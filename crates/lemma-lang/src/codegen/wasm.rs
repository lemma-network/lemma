//! WASM binary emitter — wasm-encoder backend.
//!
//! Emits a valid WASM module from a type-checked Lem contract. Expression
//! lowering (literals, checked arithmetic, comparison, local variable read)
//! was added in P3·Step 6c. Statement and control-flow lowering (let, assign,
//! if/else, while, loop, break, continue, return, assert, revert) was added
//! in P3·Step 6d. Function dispatch, storage access, and production wiring
//! were added in P3·Step 6e. Modifier inlining was added in P3·Step 6f.
//! Built-in Address constants and isZero()/isBurn() predicates were added
//! in P3·Step 6g.
//!
//! ## Backend choice
//!
//! Uses `wasm-encoder = "=0.251.0"` (bytecodealliance, decisions-log DB-A52).
//! Chosen for determinism: identical input → identical output bytes, no global
//! state, no RNG, no hash-map iteration in the emit path (AGENTS §7.1).
//!
//! ## Section ordering
//!
//! Canonical WASM section order (per WebAssembly spec §5.5.2):
//! Type → Import → Function → Table → Memory → Global → Export →
//! Start → Element → DataCount → Code → Data → Custom
//!
//! This module emits:
//! Type → Import → Function → Memory → Global → Export → DataCount → Code → Data.
//!
//! DataCount is required before Code when active data segments are present
//! (WebAssembly bulk-memory proposal). We always emit 3 active segments for
//! the Address constants (P3·Step 6g), so DataCount is always present.
//!
//! ## Address constants in linear memory (P3·Step 6g)
//!
//! Three 20-byte Address constants are placed in page 0 at fixed offsets:
//! - offset 0..20:  Address::zero   (20 zero bytes)
//! - offset 20..40: Address::burn   (BURN_BYTES from lemma-core)
//! - offset 40..60: Address::native_lem (NATIVE_LEM_BYTES from lemma-core)
//!
//! These are below the heap base (65536 = page 1 start) and never conflict
//! with the bump allocator. Bytes are sourced from `lemma_core::Address`
//! (single source of truth — AGENTS §2 DRY).
//!
//! ## Determinism guarantee (AGENTS §7.1)
//!
//! - No `HashMap`/`HashSet` — `BTreeMap`/`BTreeSet` only.
//! - No `SystemTime`, `rand`, or floating-point in the emit path.
//! - Section/function/export ordering is fully deterministic (fixed constants).
//! - `wasm-encoder` itself is a purely syntactic byte emitter with no internal
//!   non-determinism.
//!
//! ## Submodule layout
//!
//! The lowering logic is split into focused submodules under [`lower`]:
//! - `lower/mod.rs` — `LowerCtx` struct, constants, free helpers (selectors,
//!   storage keys, modifier helpers)
//! - `lower/expr.rs` — expression lowering
//! - `lower/stmt.rs` — statement + control-flow lowering
//! - `lower/storage.rs` — storage read/write lowering
//! - `lower/arithmetic.rs` — checked arithmetic + u128 comparisons
//! - `lower/xcall.rs` — cross-contract call lowering
//! - `lower/dispatch.rs` — dispatch prologue, bump allocator, function body

use lemma_core::Address;
use wasm_encoder::{
    CodeSection, ConstExpr, CustomSection, DataCountSection, DataSection, EntityType, ExportKind,
    ExportSection, FunctionSection, GlobalSection, GlobalType, ImportSection, MemorySection,
    MemoryType, Module, TypeSection, ValType,
};

use crate::codegen::abi::{self, HOST_IMPORT_COUNT, IMPORT_MODULE, IMPORT_ORDER};
use crate::codegen::metadata;
use crate::codegen::types::{local_count, wasm_valtype};
use crate::error::LangError;
use crate::parser::Visibility;
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::type_checker::types::SymbolSig;

// ─── Lowering submodules ─────────────────────────────────────────────────────

mod lower;

// Re-export public items from lower/ that are used by other codegen modules
// and tests.
pub(crate) use lower::{
    compute_selector, detect_selector_collisions, type_canonical_name, ADDR_BURN_OFFSET,
    ADDR_NATIVE_OFFSET, ADDR_ZERO_OFFSET, HOST_SIGS,
};
// Re-exports used only in test builds (test helpers + wasm/tests.rs).
#[cfg(test)]
pub(crate) use lower::{storage_key, LowerCtx};

use lower::dispatch::{emit_alloc_body, emit_contract_fn_body, emit_dispatch_prologue};
use lower::{ADDR_DATA_SEGMENT_COUNT, HEAP_BASE_ADDR, INITIAL_MEMORY_PAGES};

// ─── Public API ───────────────────────────────────────────────────────────────

/// Emit a valid WASM module for the given contract.
///
/// Builds the full section layout: Type → Import → Function → Memory →
/// Global → Export → Code. Includes:
/// - Expression lowering (P3·Step 6c): literals, checked arithmetic, comparisons
/// - Statement/control flow lowering (P3·Step 6d): let, assign, if/else, while, etc.
/// - Function dispatch + storage access (P3·Step 6e): selector-based dispatch in
///   the `call` entry point, `alloc` bump allocator, storage read/write via host
///   imports, per-function body lowering
///
/// ## Function layout
///
/// ```text
/// WASM function indices:
///   0..13  — host imports (IMPORT_ORDER)
///   14     — call (entry point, dispatch prologue)
///   15     — alloc (internal bump allocator)
///   16..N  — contract functions (one per pub/external fn with a body)
/// ```
///
/// # Returns
///
/// `Ok(Vec<u8>)` — a valid WebAssembly binary, or
/// `Err(LangError::Codegen)` if lowering or section assembly fails.
///
/// # Determinism
///
/// Calling this function twice with the same input produces byte-identical
/// output. See module-level doc for the determinism guarantee.
// consumer: codegen::compile (P3·Step 6j — wired into public pipeline)
pub(crate) fn emit_module(contract: &TypedContract<'_>) -> Result<Vec<u8>, LangError> {
    let mut module = Module::new();

    // ── Collect dispatchable functions ─────────────────────────────────────
    let all_fns = contract.functions();
    let pub_fns: Vec<&ContractFunction<'_>> = all_fns
        .iter()
        .filter(|f| matches!(f.visibility, Visibility::Pub | Visibility::External))
        .filter(|f| f.body.is_some())
        .collect();

    // Compute selectors for each dispatchable function.
    let mut selectors: Vec<(u32, usize)> = Vec::new();
    for (i, f) in pub_fns.iter().enumerate() {
        let sel = compute_selector(f, contract)?;
        selectors.push((sel, i));
    }

    // Reject selector collisions at compile time (L-2).
    let selector_names: Vec<(&str, u32)> = pub_fns
        .iter()
        .zip(selectors.iter())
        .map(|(f, (sel, _))| (f.name, *sel))
        .collect();
    detect_selector_collisions(&selector_names)?;

    let state_fields = contract.state_fields();

    // ── Function index layout ─────────────────────────────────────────────
    let call_idx = HOST_IMPORT_COUNT;
    let alloc_idx = HOST_IMPORT_COUNT + 1;
    let fn_base = HOST_IMPORT_COUNT + 2;

    // ── 1. Type section ───────────────────────────────────────────────────
    let mut types = TypeSection::new();
    for (params, results) in HOST_SIGS {
        types
            .ty()
            .function(params.iter().copied(), results.iter().copied());
    }
    types.ty().function([], []);
    types.ty().function([ValType::I32], [ValType::I32]);
    for f in &pub_fns {
        let mut param_valtypes = Vec::new();
        if let Some(sym_id) = f.symbol_id {
            if let Some(SymbolSig::Function(fn_sig)) = contract.sig(sym_id) {
                for (_, ty, _) in &fn_sig.params {
                    let vt = wasm_valtype(ty)?;
                    let count = local_count(ty);
                    for _ in 0..count {
                        param_valtypes.push(vt);
                    }
                }
            }
        }
        types.ty().function(param_valtypes.iter().copied(), []);
    }
    module.section(&types);

    // ── 2. Import section ─────────────────────────────────────────────────
    let mut imports = ImportSection::new();
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        imports.import(IMPORT_MODULE, name, EntityType::Function(i as u32));
    }
    module.section(&imports);

    // ── 3. Function section ───────────────────────────────────────────────
    let mut functions = FunctionSection::new();
    functions.function(call_idx);
    functions.function(call_idx + 1);
    for (i, _) in pub_fns.iter().enumerate() {
        functions.function(fn_base + i as u32);
    }
    module.section(&functions);

    // ── 4. Memory section ─────────────────────────────────────────────────
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: INITIAL_MEMORY_PAGES,
        maximum: None,
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    // ── 5. Global section ─────────────────────────────────────────────────
    let mut globals = GlobalSection::new();
    globals.global(
        GlobalType {
            val_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        &ConstExpr::i32_const(HEAP_BASE_ADDR),
    );
    globals.global(
        GlobalType {
            val_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        &ConstExpr::i32_const(HEAP_BASE_ADDR),
    );
    module.section(&globals);

    // ── 6. Export section ─────────────────────────────────────────────────
    let mut exports = ExportSection::new();
    exports.export(abi::ENTRY_POINT, ExportKind::Func, call_idx);
    exports.export(abi::MEMORY_EXPORT, ExportKind::Memory, 0);
    exports.export(abi::HEAP_BASE_GLOBAL, ExportKind::Global, 0);
    module.section(&exports);

    // ── 6.5 DataCount section ─────────────────────────────────────────────
    module.section(&DataCountSection {
        count: ADDR_DATA_SEGMENT_COUNT,
    });

    // ── 7. Code section ───────────────────────────────────────────────────
    let mut codes = CodeSection::new();
    let call_body = emit_dispatch_prologue(&selectors, &pub_fns, contract, alloc_idx, fn_base)?;
    codes.function(&call_body);
    let alloc_body = emit_alloc_body();
    codes.function(&alloc_body);
    for (i, f) in pub_fns.iter().enumerate() {
        let fn_body = emit_contract_fn_body(f, contract, &state_fields, alloc_idx)?;
        codes.function(&fn_body);
        let _ = i;
    }
    module.section(&codes);

    // ── 8. Data section ───────────────────────────────────────────────────
    let mut data = DataSection::new();
    data.active(
        0,
        &ConstExpr::i32_const(ADDR_ZERO_OFFSET as i32),
        [0u8; 20].iter().copied(),
    );
    let burn_bytes = *Address::burn().as_bytes();
    data.active(
        0,
        &ConstExpr::i32_const(ADDR_BURN_OFFSET as i32),
        burn_bytes.iter().copied(),
    );
    let native_bytes = *Address::native_lem().as_bytes();
    data.active(
        0,
        &ConstExpr::i32_const(ADDR_NATIVE_OFFSET as i32),
        native_bytes.iter().copied(),
    );
    module.section(&data);

    // ── Custom sections (P3·Step 6i) ─────────────────────────────────────
    let abi_bytes = abi::build_abi(contract)?;
    module.section(&CustomSection {
        name: "lemma.abi".into(),
        data: std::borrow::Cow::Owned(abi_bytes),
    });
    let meta_bytes = metadata::build_metadata(contract);
    module.section(&CustomSection {
        name: "lemma.meta".into(),
        data: std::borrow::Cow::Owned(meta_bytes),
    });

    Ok(module.finish())
}

// ─── Test-only helpers ────────────────────────────────────────────────────────

/// Build a complete WASM module containing a single test function that
/// evaluates the given expression and returns the result.
///
/// Only available in test builds.
#[cfg(test)]
pub(crate) fn emit_test_expr_module(
    contract: &TypedContract<'_>,
    expr: &crate::parser::Expr,
    params: &[(String, ValType)],
) -> Result<Vec<u8>, LangError> {
    use std::collections::BTreeMap;
    use wasm_encoder::{Function, Instruction};

    use crate::codegen::types::wasm_valtype;

    let expr_span = crate::parser::expr_span(expr);
    let result_ty = contract
        .type_of(&expr_span)
        .ok_or_else(|| LangError::Codegen {
            message: "no resolved type for test expression".into(),
        })?;
    let wasm_result = wasm_valtype(result_ty)?;

    let mut ctx = LowerCtx::new(contract, params);
    ctx.emit_expr(expr)?;
    ctx.func.instruction(&Instruction::End);

    let temp_local_count = ctx.local_types.len();
    let all_locals: Vec<(u32, ValType)> = ctx.local_types;

    let mut ctx2 = LowerCtx {
        contract,
        func: Function::new(all_locals),
        locals: {
            let mut m = BTreeMap::new();
            for (i, (name, _)) in params.iter().enumerate() {
                m.insert(name.clone(), i as u32);
            }
            m
        },
        next_local: params.len() as u32 + temp_local_count as u32,
        local_types: Vec::new(),
        loop_stack: Vec::new(),
        block_depth: 0,
        alloc_fn_idx: 0,
        state_fields: BTreeMap::new(),
    };

    ctx2.next_local = params.len() as u32;
    ctx2.emit_expr(expr)?;
    ctx2.func.instruction(&Instruction::End);

    assert_eq!(
        ctx2.next_local,
        params.len() as u32 + temp_local_count as u32,
        "BUG: pass-2 allocated {} temp locals but pass-1 allocated {} — instruction/local desync",
        ctx2.next_local - params.len() as u32,
        temp_local_count,
    );

    let mut module = Module::new();
    let mut types = TypeSection::new();
    for (p, r) in HOST_SIGS {
        types.ty().function(p.iter().copied(), r.iter().copied());
    }
    let param_valtypes: Vec<ValType> = params.iter().map(|(_, vt)| *vt).collect();
    types
        .ty()
        .function(param_valtypes.iter().copied(), [wasm_result]);
    module.section(&types);

    let mut imports = ImportSection::new();
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        imports.import(IMPORT_MODULE, name, EntityType::Function(i as u32));
    }
    module.section(&imports);

    let test_type_index = HOST_IMPORT_COUNT;
    let mut functions = FunctionSection::new();
    functions.function(test_type_index);
    module.section(&functions);

    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: INITIAL_MEMORY_PAGES,
        maximum: None,
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    let mut globals = GlobalSection::new();
    globals.global(
        GlobalType {
            val_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        &ConstExpr::i32_const(HEAP_BASE_ADDR),
    );
    module.section(&globals);

    let test_func_index = HOST_IMPORT_COUNT;
    let mut exports = ExportSection::new();
    exports.export("test", ExportKind::Func, test_func_index);
    exports.export(abi::MEMORY_EXPORT, ExportKind::Memory, 0);
    module.section(&exports);

    let mut codes = CodeSection::new();
    codes.function(&ctx2.func);
    module.section(&codes);

    Ok(module.finish())
}

/// Build a complete WASM module from a contract function body (statements).
///
/// Only available in test builds.
#[cfg(test)]
pub(crate) fn emit_test_stmt_module(
    contract: &TypedContract<'_>,
    stmts: &[crate::parser::Stmt],
    params: &[(String, ValType)],
    result_type: ValType,
) -> Result<Vec<u8>, LangError> {
    use std::collections::BTreeMap;
    use wasm_encoder::{Function, Instruction};

    let mut ctx = LowerCtx::new(contract, params);
    ctx.emit_block(stmts)?;
    ctx.func.instruction(&Instruction::End);

    let local_count = ctx.local_types.len();
    let all_locals: Vec<(u32, ValType)> = ctx.local_types;
    let discovered_locals = ctx.locals.clone();

    let mut ctx2 = LowerCtx {
        contract,
        func: Function::new(all_locals),
        locals: {
            let mut m = BTreeMap::new();
            for (i, (name, _)) in params.iter().enumerate() {
                m.insert(name.clone(), i as u32);
            }
            m
        },
        next_local: params.len() as u32,
        local_types: Vec::new(),
        loop_stack: Vec::new(),
        block_depth: 0,
        alloc_fn_idx: 0,
        state_fields: BTreeMap::new(),
    };

    ctx2.emit_block(stmts)?;
    ctx2.func.instruction(&Instruction::End);

    assert_eq!(
        ctx2.next_local,
        params.len() as u32 + local_count as u32,
        "BUG: pass-2 allocated {} locals but pass-1 allocated {} — desync",
        ctx2.next_local - params.len() as u32,
        local_count,
    );
    assert_eq!(
        ctx2.locals, discovered_locals,
        "BUG: named local map differs between pass-1 and pass-2"
    );

    let mut module = Module::new();
    let mut types = TypeSection::new();
    for (p, r) in HOST_SIGS {
        types.ty().function(p.iter().copied(), r.iter().copied());
    }
    let param_valtypes: Vec<ValType> = params.iter().map(|(_, vt)| *vt).collect();
    types
        .ty()
        .function(param_valtypes.iter().copied(), [result_type]);
    module.section(&types);

    let mut imports = ImportSection::new();
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        imports.import(IMPORT_MODULE, name, EntityType::Function(i as u32));
    }
    module.section(&imports);

    let test_type_index = HOST_IMPORT_COUNT;
    let mut functions = FunctionSection::new();
    functions.function(test_type_index);
    module.section(&functions);

    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: INITIAL_MEMORY_PAGES,
        maximum: None,
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    let mut globals = GlobalSection::new();
    globals.global(
        GlobalType {
            val_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        &ConstExpr::i32_const(HEAP_BASE_ADDR),
    );
    module.section(&globals);

    let test_func_index = HOST_IMPORT_COUNT;
    let mut exports = ExportSection::new();
    exports.export("test", ExportKind::Func, test_func_index);
    exports.export(abi::MEMORY_EXPORT, ExportKind::Memory, 0);
    module.section(&exports);

    let mut codes = CodeSection::new();
    codes.function(&ctx2.func);
    module.section(&codes);

    Ok(module.finish())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
