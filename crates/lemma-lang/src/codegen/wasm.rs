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

use std::collections::BTreeMap;

use lemma_core::{Address, DROPS_PER_DRIP, DROPS_PER_LEM};
use wasm_encoder::{
    CodeSection, ConstExpr, DataCountSection, DataSection, EntityType, ExportKind, ExportSection,
    Function, FunctionSection, GlobalSection, GlobalType, ImportSection, Instruction,
    MemorySection, MemoryType, Module, TypeSection, ValType,
};

use crate::codegen::abi::{self, HOST_IMPORT_COUNT, IMPORT_MODULE, IMPORT_ORDER};
use crate::codegen::types::{is_i64, is_signed, is_sub_word, wasm_valtype};
use crate::error::LangError;
use crate::lexer::token::Span;
use crate::parser::expr_span;
use crate::parser::{
    AssignOp, BinaryOp, Expr, Literal, ModifierDef, Pattern, Stmt, UnaryOp, UnitKind, Visibility,
};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::type_checker::types::{ResolvedType, SymbolSig};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Initial linear memory size in pages (1 page = 64 KiB).
///
/// Two pages: page 0 for static data, page 1+ for the bump heap.
/// The bump allocator starts at HEAP_BASE_ADDR (page 1 start = 65536).
const INITIAL_MEMORY_PAGES: u64 = 2;

/// Bump-heap base address — first byte past the static data segment.
///
/// Set to page 1 start (65536 = 64 KiB). The guest bump allocator starts
/// here and grows upward. See 08-EXECUTION_SPEC §4.5.
const HEAP_BASE_ADDR: i32 = 65536;

// ─── Address constant data-segment offsets (P3·Step 6g) ──────────────────────
//
// Three 20-byte Address constants are placed in page 0 at fixed offsets.
// These are compile-time constants mirroring lemma-core::Address (AGENTS §2 DRY).
// Layout (page 0, starting at offset 0):
//   offset 0..20:  Address::zero   (20 zero bytes)
//   offset 20..40: Address::burn   (BURN_BYTES from lemma-core)
//   offset 40..60: Address::native_lem (NATIVE_LEM_BYTES from lemma-core)
//
// All offsets are well below the heap base (65536), so they never conflict
// with the bump allocator.

/// Byte offset in page 0 for the `Address::zero` constant (20 zero bytes).
pub(crate) const ADDR_ZERO_OFFSET: u32 = 0;

/// Byte offset in page 0 for the `Address::burn` constant (BURN_BYTES).
pub(crate) const ADDR_BURN_OFFSET: u32 = 20;

/// Byte offset in page 0 for the `Address::native_lem` constant (NATIVE_LEM_BYTES).
pub(crate) const ADDR_NATIVE_OFFSET: u32 = 40;

/// Number of active data segments emitted for Address constants.
const ADDR_DATA_SEGMENT_COUNT: u32 = 3;

// ─── Unit-literal multipliers (P3·Step 6h) ───────────────────────────────────
//
// Time units lower to **seconds**; value units lower to **Drop** (Lemma's base
// denomination). All multipliers are named constants — no magic numbers (AGENTS
// §3.3). Value-unit constants re-use `lemma_core::amount` exports (AGENTS §2.4
// DRY — single definition, imported here). Time constants are codegen-local
// (no other crate consumes them today).
//
// Conversion table (03-LANGUAGE_SPEC §2):
//   .seconds × 1             → seconds
//   .minutes × 60            → seconds
//   .hours   × 3_600         → seconds
//   .days    × 86_400        → seconds
//   .ether   × DROPS_PER_LEM  (1e18) → Drop
//   .gwei    × DROPS_PER_DRIP (1e9)  → Drop  (1 Drip = DROPS_PER_DRIP Drops)

/// `.seconds` × 1 — explicit constant for a readable, exhaustive `unit_multiplier` match.
const SECONDS_PER_SECOND: u128 = 1;
/// `.minutes` → 60 seconds.
const SECONDS_PER_MINUTE: u128 = 60;
/// `.hours` → 3 600 seconds.
const SECONDS_PER_HOUR: u128 = 3_600;
/// `.days` → 86 400 seconds.
const SECONDS_PER_DAY: u128 = 86_400;

/// Return the fold multiplier for a [`UnitKind`] (named constants — no magic numbers).
///
/// Time units scale to **seconds**; value units scale to **Drop**.
/// `.ether`/`.gwei` multipliers are re-exported from `lemma_core::amount`
/// (AGENTS §2.4 — single source of truth). Time multipliers are defined above.
///
/// # Panics
///
/// Never panics — exhaustive match, no wildcard arm.
fn unit_multiplier(kind: &UnitKind) -> u128 {
    match kind {
        UnitKind::Seconds => SECONDS_PER_SECOND,
        UnitKind::Minutes => SECONDS_PER_MINUTE,
        UnitKind::Hours => SECONDS_PER_HOUR,
        UnitKind::Days => SECONDS_PER_DAY,
        UnitKind::Ether => DROPS_PER_LEM,
        UnitKind::Gwei => DROPS_PER_DRIP,
    }
}

// ─── Host function type signatures ───────────────────────────────────────────

/// WASM type signatures for each host function, in `IMPORT_ORDER` order.
///
/// Each entry is `(params, results)`. The type index in the TypeSection
/// matches the position in this array.
///
/// `pub(crate)` so execution tests can build a wasmtime stub linker matching
/// these signatures (M3 — CR finding).
pub(crate) const HOST_SIGS: &[(&[ValType], &[ValType])] = &[
    // 0: block_height() -> i64
    (&[], &[ValType::I64]),
    // 1: block_timestamp() -> i64
    (&[], &[ValType::I64]),
    // 2: gas_remaining() -> i64
    (&[], &[ValType::I64]),
    // 3: msg_value() -> i64
    (&[], &[ValType::I64]),
    // 4: msg_sender(register_id: i32)
    (&[ValType::I32], &[]),
    // 5: input(register_id: i32)
    (&[ValType::I32], &[]),
    // 6: register_len(register_id: i32) -> i64
    (&[ValType::I32], &[ValType::I64]),
    // 7: read_register(register_id: i32, ptr: i32)
    (&[ValType::I32, ValType::I32], &[]),
    // 8: storage_read(key_ptr: i32, key_len: i32, register_id: i32) -> i32
    (&[ValType::I32, ValType::I32, ValType::I32], &[ValType::I32]),
    // 9: storage_write(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32)
    (
        &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        &[],
    ),
    // 10: storage_delete(key_ptr: i32, key_len: i32)
    (&[ValType::I32, ValType::I32], &[]),
    // 11: emit_event(topics_ptr: i32, topics_len: i32, data_ptr: i32, data_len: i32)
    (
        &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        &[],
    ),
    // 12: transfer(to_ptr: i32, to_len: i32, amount: i64) -> i32
    (&[ValType::I32, ValType::I32, ValType::I64], &[ValType::I32]),
    // 13: value_return(ptr: i32, len: i32)
    (&[ValType::I32, ValType::I32], &[]),
];

// ─── Function selector + storage key computation ─────────────────────────────

/// Compute the 4-byte function selector for dispatch.
///
/// Selector = first 4 bytes of `blake3(fn_name + "(" + param_types + ")")`,
/// interpreted as a **little-endian** u32 (matching WASM `i32.load` native
/// endianness — AGENTS §7.1 determinism).
///
/// Example: `transfer(Address,u128)` → blake3("transfer(Address,u128)")[0..4] as LE u32.
///
/// This is Lemma-native (blake3, not keccak like Solidity). Deterministic.
pub(crate) fn compute_selector(
    func: &ContractFunction<'_>,
    contract: &TypedContract<'_>,
) -> Result<u32, LangError> {
    let mut sig = func.name.to_string();
    sig.push('(');

    // Use resolved param types from the function signature for canonical names.
    // The FnSig has (name, ResolvedType, has_default) tuples.
    // If we can't get canonical param types from the type checker, this is
    // an internal invariant violation — codegen must not emit a selector
    // from Debug output (ABI-fragile).
    let param_types: Vec<String> = if let Some(sym_id) = func.symbol_id {
        if let Some(SymbolSig::Function(fn_sig)) = contract.sig(sym_id) {
            fn_sig
                .params
                .iter()
                .map(|(_, ty, _)| type_canonical_name(ty))
                .collect()
        } else {
            return Err(LangError::Codegen {
                message: format!(
                    "cannot compute selector for function '{}': no resolved type signature",
                    func.name
                ),
            });
        }
    } else {
        return Err(LangError::Codegen {
            message: format!(
                "cannot compute selector for function '{}': no resolved type signature",
                func.name
            ),
        });
    };

    sig.push_str(&param_types.join(","));
    sig.push(')');

    let hash = blake3::hash(sig.as_bytes());
    let bytes = hash.as_bytes();
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Canonical type name for selector signature computation.
///
/// Maps `ResolvedType` to a stable string used in the blake3 hash input.
/// Must be deterministic and consistent across validators (AGENTS §7.1).
fn type_canonical_name(ty: &ResolvedType) -> String {
    match ty {
        ResolvedType::Bool => "bool".into(),
        ResolvedType::U8 => "u8".into(),
        ResolvedType::U16 => "u16".into(),
        ResolvedType::U32 => "u32".into(),
        ResolvedType::U64 => "u64".into(),
        ResolvedType::U128 => "u128".into(),
        ResolvedType::U256 => "u256".into(),
        ResolvedType::I8 => "i8".into(),
        ResolvedType::I16 => "i16".into(),
        ResolvedType::I32 => "i32".into(),
        ResolvedType::I64 => "i64".into(),
        ResolvedType::I128 => "i128".into(),
        ResolvedType::I256 => "i256".into(),
        ResolvedType::AddressTy => "Address".into(),
        ResolvedType::StringTy => "string".into(),
        ResolvedType::Bytes => "bytes".into(),
        ResolvedType::HashTy => "Hash".into(),
        // For compound types, use display_name (deterministic)
        other => other.display_name(),
    }
}

/// Derive the 32-byte storage key for a state field.
///
/// Key = blake3(field_name).as_bytes() (full 32 bytes).
/// Deterministic, consistent across validators (AGENTS §7.1).
pub(crate) fn storage_key(field_name: &str) -> [u8; 32] {
    let hash = blake3::hash(field_name.as_bytes());
    *hash.as_bytes()
}

/// Byte width of a resolved type in storage encoding.
///
/// Returns the number of bytes needed to store a value of this type in
/// linear memory for storage read/write operations.
fn storage_byte_width(ty: &ResolvedType) -> Result<u32, LangError> {
    match ty {
        ResolvedType::Bool => Ok(1),
        ResolvedType::U8 | ResolvedType::I8 => Err(LangError::Codegen {
            message: "sub-word types (u8/i8) in storage not yet implemented (M1)".into(),
        }),
        ResolvedType::U16 | ResolvedType::I16 => Err(LangError::Codegen {
            message: "sub-word types (u16/i16) in storage not yet implemented (M1)".into(),
        }),
        ResolvedType::U32 | ResolvedType::I32 => Ok(4),
        ResolvedType::U64 | ResolvedType::I64 => Ok(8),
        _ => Err(LangError::Codegen {
            message: format!(
                "storage encoding for type {} not yet implemented",
                ty.display_name()
            ),
        }),
    }
}

// ─── Modifier inlining helpers (P3·Step 6f) ──────────────────────────────────

/// Split a modifier body at the `Stmt::Placeholder` position.
///
/// Returns `(pre, post)` where `pre` is everything before `_` and `post` is
/// everything after `_`. Returns `Err` if no `_` is found (defensive; WF-006
/// should have caught this — AGENTS §7.2, no panics in codegen).
fn split_at_placeholder(stmts: &[Stmt]) -> Result<(&[Stmt], &[Stmt]), LangError> {
    for (i, stmt) in stmts.iter().enumerate() {
        if matches!(stmt, Stmt::Placeholder(_)) {
            return Ok((&stmts[..i], &stmts[i + 1..]));
        }
    }
    Err(LangError::Codegen {
        message: "modifier body has no `_` placeholder (WF-006 should have caught this)".into(),
    })
}

/// Look up a modifier definition by name from the contract's modifiers.
///
/// Returns `Err` if the modifier is not found — this indicates an annotation
/// referencing a non-existent modifier (should have been caught by the type
/// checker, but codegen handles it defensively).
fn find_modifier<'a>(
    contract: &'a TypedContract<'a>,
    name: &str,
) -> Result<&'a ModifierDef, LangError> {
    contract
        .modifiers()
        .into_iter()
        .find(|m| m.name == name)
        .ok_or_else(|| LangError::Codegen {
            message: format!("modifier '{name}' not found in contract"),
        })
}

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
// consumer: codegen::compile orchestrator (P3·Step 6a+); lib.rs pipeline (P3·Step 6j)
#[allow(dead_code)]
pub(crate) fn emit_module(contract: &TypedContract<'_>) -> Result<Vec<u8>, LangError> {
    let mut module = Module::new();

    // ── Collect dispatchable functions ─────────────────────────────────────
    // Only pub/external functions with bodies are dispatchable.
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

    // Collect state fields for storage key computation.
    let state_fields = contract.state_fields();

    // ── Function index layout ─────────────────────────────────────────────
    // call_idx  = HOST_IMPORT_COUNT     (first defined function)
    // alloc_idx = HOST_IMPORT_COUNT + 1
    // fn_base   = HOST_IMPORT_COUNT + 2 (first contract function)
    let call_idx = HOST_IMPORT_COUNT;
    let alloc_idx = HOST_IMPORT_COUNT + 1;
    let fn_base = HOST_IMPORT_COUNT + 2;

    // ── 1. Type section ───────────────────────────────────────────────────
    // Types 0..13: host function signatures
    // Type 14: call entry point [] -> []
    // Type 15: alloc (i32) -> (i32)
    // Types 16..N: one per contract function (params → [])
    let mut types = TypeSection::new();
    for (params, results) in HOST_SIGS {
        types
            .ty()
            .function(params.iter().copied(), results.iter().copied());
    }
    // call entry point: [] -> []
    types.ty().function([], []);
    // alloc: (i32) -> (i32)
    types.ty().function([ValType::I32], [ValType::I32]);
    // Contract function types: each takes its params as WASM values, returns void.
    // Return values are communicated via value_return host call, not WASM return.
    for f in &pub_fns {
        let mut param_valtypes = Vec::new();
        if let Some(sym_id) = f.symbol_id {
            if let Some(SymbolSig::Function(fn_sig)) = contract.sig(sym_id) {
                for (_, ty, _) in &fn_sig.params {
                    param_valtypes.push(wasm_valtype(ty)?);
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
    // Declare: call, alloc, then each contract function.
    let mut functions = FunctionSection::new();
    functions.function(call_idx); // call type index = HOST_IMPORT_COUNT
    functions.function(call_idx + 1); // alloc type index = HOST_IMPORT_COUNT + 1
    for (i, _) in pub_fns.iter().enumerate() {
        functions.function(fn_base + i as u32); // type index = fn_base + i
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
    // Global 0: __heap_base (exported, mutable) — base of bump heap
    // Global 1: __heap_ptr (NOT exported, mutable) — current allocation pointer
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
    // Required before the Code section when active data segments are present
    // (WebAssembly bulk-memory proposal). We always emit 3 segments for the
    // Address constants (P3·Step 6g).
    module.section(&DataCountSection {
        count: ADDR_DATA_SEGMENT_COUNT,
    });

    // ── 7. Code section ───────────────────────────────────────────────────
    let mut codes = CodeSection::new();

    // 7a. call entry point — dispatch prologue
    let call_body = emit_dispatch_prologue(&selectors, &pub_fns, contract, alloc_idx, fn_base)?;
    codes.function(&call_body);

    // 7b. alloc — bump allocator
    let alloc_body = emit_alloc_body();
    codes.function(&alloc_body);

    // 7c. Contract function bodies
    for (i, f) in pub_fns.iter().enumerate() {
        let fn_body = emit_contract_fn_body(f, contract, &state_fields, alloc_idx)?;
        codes.function(&fn_body);
        let _ = i; // suppress unused warning
    }

    module.section(&codes);

    // ── 8. Data section ───────────────────────────────────────────────────
    // Three active data segments for Address constants (P3·Step 6g).
    // Bytes sourced from lemma-core::Address — single source of truth (AGENTS §2).
    let mut data = DataSection::new();

    // Segment 0: Address::zero — 20 zero bytes at offset ADDR_ZERO_OFFSET
    data.active(
        0,
        &ConstExpr::i32_const(ADDR_ZERO_OFFSET as i32),
        [0u8; 20].iter().copied(),
    );

    // Segment 1: Address::burn — BURN_BYTES at offset ADDR_BURN_OFFSET
    let burn_bytes = *Address::burn().as_bytes();
    data.active(
        0,
        &ConstExpr::i32_const(ADDR_BURN_OFFSET as i32),
        burn_bytes.iter().copied(),
    );

    // Segment 2: Address::native_lem — NATIVE_LEM_BYTES at offset ADDR_NATIVE_OFFSET
    let native_bytes = *Address::native_lem().as_bytes();
    data.active(
        0,
        &ConstExpr::i32_const(ADDR_NATIVE_OFFSET as i32),
        native_bytes.iter().copied(),
    );

    module.section(&data);

    Ok(module.finish())
}

/// Emit the bump allocator function body.
///
/// ```wasm
/// ;; alloc(size: i32) -> ptr: i32
/// ;; ptr = global.get $heap_ptr
/// ;; global.set $heap_ptr (ptr + size)
/// ;; return ptr
/// ```
///
/// Global 1 = `__heap_ptr` (mutable, starts at HEAP_BASE_ADDR).
///
/// ## Limitations (intentional-deferred)
///
/// Bump allocator: alloc(size) -> ptr. No overflow/bounds check.
/// If __heap_ptr runs past the memory boundary, the next i32.store/i64.store
/// traps on out-of-bounds — deterministic but implicit, not a designed limit.
/// Storage key buffers (32 bytes per storage_read/write) are allocated per-op
/// and never reused — a contract with many storage ops exhausts the heap
/// faster than expected.
///
/// Intentional-deferred: memory.grow + key-buffer reuse land after 6e
/// (tracked in living-notes Technical Debt).
fn emit_alloc_body() -> Function {
    let mut f = Function::new(vec![]);
    // ptr = global.get 1 (__heap_ptr) — this is the return value
    f.instruction(&Instruction::GlobalGet(1));
    // __heap_ptr = __heap_ptr + size
    f.instruction(&Instruction::GlobalGet(1));
    f.instruction(&Instruction::LocalGet(0)); // size param
    f.instruction(&Instruction::I32Add);
    f.instruction(&Instruction::GlobalSet(1));
    // ptr is already on the stack from the first GlobalGet
    f.instruction(&Instruction::End);
    f
}

/// Emit the `call` entry point dispatch prologue.
///
/// Reads calldata via host imports, extracts the 4-byte selector, and
/// dispatches to the correct contract function. Unknown selectors trap.
///
/// ## Calldata layout
///
/// ```text
/// [selector: 4 bytes LE u32] [arg0] [arg1] ...
/// ```
fn emit_dispatch_prologue(
    selectors: &[(u32, usize)],
    pub_fns: &[&ContractFunction<'_>],
    contract: &TypedContract<'_>,
    alloc_idx: u32,
    fn_base: u32,
) -> Result<Function, LangError> {
    // Locals: cd_len_i64 (i64), cd_len (i32), cd_ptr (i32), selector (i32)
    let mut f = Function::new(vec![
        (1, ValType::I64), // local 0: cd_len_i64 (raw register_len result, for sentinel check)
        (1, ValType::I32), // local 1: cd_len
        (1, ValType::I32), // local 2: cd_ptr
        (1, ValType::I32), // local 3: selector
    ]);

    // If no dispatchable functions, just return (empty contract)
    if selectors.is_empty() {
        f.instruction(&Instruction::End);
        return Ok(f);
    }

    // input(REG_CALLDATA=0) — load calldata into register 0
    f.instruction(&Instruction::I32Const(abi::REG_CALLDATA as i32));
    f.instruction(&Instruction::Call(5)); // input = index 5

    // register_len(0) → i64
    // W3 fix: compare as i64 BEFORE wrapping to i32. register_len returns -1
    // (REGISTER_EMPTY) when the register is unset. Wrapping -1i64 to i32 gives
    // 0xFFFFFFFF which passes the `< 4` unsigned check — a 4 GB allocation.
    // Signed i64 comparison catches -1 < 4 correctly.
    f.instruction(&Instruction::I32Const(abi::REG_CALLDATA as i32));
    f.instruction(&Instruction::Call(6)); // register_len = index 6
    f.instruction(&Instruction::LocalTee(0)); // cd_len_i64 (i64)
    f.instruction(&Instruction::I64Const(4));
    f.instruction(&Instruction::I64LtS); // signed: -1 < 4 = true
    f.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
    f.instruction(&Instruction::Unreachable); // trap: calldata too short or missing
    f.instruction(&Instruction::End);

    // Now safe to truncate to i32 (we know cd_len_i64 >= 4)
    f.instruction(&Instruction::LocalGet(0)); // cd_len_i64
    f.instruction(&Instruction::I32WrapI64);
    f.instruction(&Instruction::LocalSet(1)); // cd_len (i32)

    // alloc(cd_len) → cd_ptr
    f.instruction(&Instruction::LocalGet(1));
    f.instruction(&Instruction::Call(alloc_idx));
    f.instruction(&Instruction::LocalSet(2)); // cd_ptr

    // read_register(REG_CALLDATA, cd_ptr) — copy calldata to memory
    f.instruction(&Instruction::I32Const(abi::REG_CALLDATA as i32));
    f.instruction(&Instruction::LocalGet(2));
    f.instruction(&Instruction::Call(7)); // read_register = index 7

    // selector = i32.load(cd_ptr) — first 4 bytes as LE u32
    f.instruction(&Instruction::LocalGet(2));
    f.instruction(&Instruction::I32Load(wasm_encoder::MemArg {
        offset: 0,
        align: 2, // 4-byte alignment
        memory_index: 0,
    }));
    f.instruction(&Instruction::LocalSet(3)); // selector

    // Dispatch: if/else chain comparing selector to each function's selector
    for (sel, fn_idx) in selectors {
        f.instruction(&Instruction::LocalGet(3));
        f.instruction(&Instruction::I32Const(*sel as i32));
        f.instruction(&Instruction::I32Eq);
        f.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));

        // Decode args from calldata and call the function
        let func = pub_fns[*fn_idx];
        let param_types = get_fn_param_types(func, contract)?;
        let mut offset: u32 = 4; // skip selector

        for ty in &param_types {
            f.instruction(&Instruction::LocalGet(2)); // cd_ptr
            match ty {
                ValType::I32 => {
                    f.instruction(&Instruction::I32Load(wasm_encoder::MemArg {
                        offset: offset as u64,
                        align: 2,
                        memory_index: 0,
                    }));
                    offset = offset.checked_add(4).ok_or_else(|| LangError::Codegen {
                        message: "calldata offset overflow".into(),
                    })?;
                }
                ValType::I64 => {
                    f.instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                        offset: offset as u64,
                        align: 3,
                        memory_index: 0,
                    }));
                    offset = offset.checked_add(8).ok_or_else(|| LangError::Codegen {
                        message: "calldata offset overflow".into(),
                    })?;
                }
                _ => {
                    return Err(LangError::Codegen {
                        message: format!("unsupported WASM param type in dispatch: {ty:?}"),
                    });
                }
            }
        }

        // Call the contract function
        let wasm_fn_idx = fn_base + *fn_idx as u32;
        f.instruction(&Instruction::Call(wasm_fn_idx));
        f.instruction(&Instruction::Return);
        f.instruction(&Instruction::End);
    }

    // Unknown selector → trap
    f.instruction(&Instruction::Unreachable);
    f.instruction(&Instruction::End);
    Ok(f)
}

/// Get the WASM param types for a contract function from its resolved signature.
fn get_fn_param_types(
    func: &ContractFunction<'_>,
    contract: &TypedContract<'_>,
) -> Result<Vec<ValType>, LangError> {
    let mut param_valtypes = Vec::new();
    if let Some(sym_id) = func.symbol_id {
        if let Some(SymbolSig::Function(fn_sig)) = contract.sig(sym_id) {
            for (_, ty, _) in &fn_sig.params {
                param_valtypes.push(wasm_valtype(ty)?);
            }
        }
    }
    Ok(param_valtypes)
}

/// Emit a contract function body using the two-pass approach.
///
/// Pass 1: lower the function body to discover local allocations.
/// Pass 2: rebuild with correct local declarations.
fn emit_contract_fn_body(
    func: &ContractFunction<'_>,
    contract: &TypedContract<'_>,
    state_fields: &[crate::type_checker::typed_contract::StateField<'_>],
    alloc_idx: u32,
) -> Result<Function, LangError> {
    let body = func.body.ok_or_else(|| LangError::Codegen {
        message: format!("function '{}' has no body", func.name),
    })?;

    // Build param list: (name, ValType) from the resolved signature
    let mut params: Vec<(String, ValType)> = Vec::new();
    if let Some(sym_id) = func.symbol_id {
        if let Some(SymbolSig::Function(fn_sig)) = contract.sig(sym_id) {
            for (name, ty, _) in &fn_sig.params {
                params.push((name.clone(), wasm_valtype(ty)?));
            }
        }
    }

    // Build state field map for storage access: field_name → (ResolvedType, storage_key)
    let mut field_map: BTreeMap<String, (&ResolvedType, [u8; 32])> = BTreeMap::new();
    for sf in state_fields {
        if !sf.is_immutable {
            field_map.insert(sf.name.to_string(), (sf.ty, storage_key(sf.name)));
        }
    }

    // Collect modifier annotations: annotations that reference a modifier definition.
    // Modifiers are applied outermost-first (left-to-right annotation order).
    let contract_modifiers = contract.modifiers();
    let modifier_names: Vec<&str> = func
        .annotations
        .iter()
        .filter(|a| contract_modifiers.iter().any(|m| m.name == a.name))
        .map(|a| a.name.as_str())
        .collect();

    // Pass 1: emit to discover locals
    let mut ctx1 = LowerCtx::new(contract, &params);
    ctx1.alloc_fn_idx = alloc_idx;
    ctx1.state_fields = field_map.clone();
    if modifier_names.is_empty() {
        ctx1.emit_block(body)?;
    } else {
        ctx1.emit_with_modifiers(body, &modifier_names, contract)?;
    }
    ctx1.func.instruction(&Instruction::End);

    let local_count = ctx1.local_types.len();
    let all_locals: Vec<(u32, ValType)> = ctx1.local_types;
    let discovered_locals = ctx1.locals.clone();

    // Pass 2: rebuild with correct local declarations
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
        alloc_fn_idx: alloc_idx,
        state_fields: field_map,
    };

    if modifier_names.is_empty() {
        ctx2.emit_block(body)?;
    } else {
        ctx2.emit_with_modifiers(body, &modifier_names, contract)?;
    }
    ctx2.func.instruction(&Instruction::End);

    // Verify pass consistency
    if ctx2.next_local != params.len() as u32 + local_count as u32 {
        return Err(LangError::Codegen {
            message: format!(
                "two-pass desync: pass-2 allocated {} locals but pass-1 allocated {}",
                ctx2.next_local - params.len() as u32,
                local_count,
            ),
        });
    }
    if ctx2.locals != discovered_locals {
        return Err(LangError::Codegen {
            message: "two-pass desync: named local map differs between passes".into(),
        });
    }

    Ok(ctx2.func)
}

// ─── LoopCtx — break/continue label tracking ─────────────────────────────────

/// Tracks the WASM block nesting for break/continue label resolution.
///
/// Each entry represents a loop construct (`while`/`loop`) with its
/// break and continue targets expressed as *absolute* block depths.
/// At the point of a `break`/`continue`, the relative `br` depth is
/// computed as `current_block_depth - target_depth`.
///
/// This correctly handles nested control flow (if/else inside loops):
/// the `br` depth adjusts for any intervening blocks.
struct LoopCtx {
    /// Absolute block depth of the outer `block` (break target).
    break_target_depth: u32,
    /// Absolute block depth of the inner `loop` (continue target).
    continue_target_depth: u32,
}

// ─── LowerCtx — expression + statement lowering context ──────────────────────

/// Codegen context for lowering a single function body.
///
/// Holds the contract reference (for type lookups), the WASM function body
/// being built, and the local variable table.
///
/// ## Local variable layout
///
/// WASM locals are indexed sequentially: function params first (0..N),
/// then explicit locals. The `locals` map tracks `name → index`.
/// Temp locals (for checked arithmetic) are allocated via `alloc_temp_local`.
///
/// ## Loop tracking (P3·Step 6d)
///
/// `loop_stack` tracks nested loop contexts for break/continue resolution.
/// `block_depth` tracks the current WASM block nesting depth (incremented
/// by `block`/`loop`/`if`, decremented by `end`).
///
/// ## Storage access (P3·Step 6e)
///
/// `state_fields` maps field names to their resolved type and 32-byte storage
/// key (blake3 hash of the field name). `alloc_fn_idx` is the WASM function
/// index of the internal bump allocator.
// consumer: emit_test_expr_module (P3·Step 6c tests); emit_module (P3·Step 6d/6e)
#[allow(dead_code)]
struct LowerCtx<'a> {
    /// The contract being compiled (for `type_of` lookups).
    contract: &'a TypedContract<'a>,
    /// WASM function body being built.
    func: Function,
    /// Local variable name → WASM local index mapping.
    /// BTreeMap for deterministic iteration (AGENTS §7.1).
    locals: BTreeMap<String, u32>,
    /// Next available local index.
    next_local: u32,
    /// Accumulated local type declarations (count, type) for the function.
    /// Params are not included here — only explicitly declared locals.
    local_types: Vec<(u32, ValType)>,
    /// Stack of loop contexts for break/continue resolution.
    /// Pushed on entering while/loop, popped on exit.
    loop_stack: Vec<LoopCtx>,
    /// Current WASM block nesting depth (incremented by block/loop/if).
    block_depth: u32,
    /// WASM function index of the internal bump allocator.
    /// Set to 0 for test helpers that don't use storage.
    alloc_fn_idx: u32,
    /// State field map: field_name → (resolved_type, 32-byte storage key).
    /// BTreeMap for deterministic iteration (AGENTS §7.1).
    state_fields: BTreeMap<String, (&'a ResolvedType, [u8; 32])>,
}

#[allow(dead_code)]
impl<'a> LowerCtx<'a> {
    /// Create a new lowering context for a function with the given parameters.
    ///
    /// Parameters are assigned local indices 0..N in declaration order.
    fn new(contract: &'a TypedContract<'a>, params: &[(String, ValType)]) -> Self {
        let mut locals = BTreeMap::new();
        for (i, (name, _vt)) in params.iter().enumerate() {
            locals.insert(name.clone(), i as u32);
        }
        // Function::new takes the *extra* locals (not params).
        // We'll accumulate them in local_types and build the Function at finish().
        Self {
            contract,
            func: Function::new(vec![]),
            locals,
            next_local: params.len() as u32,
            local_types: Vec::new(),
            loop_stack: Vec::new(),
            block_depth: 0,
            alloc_fn_idx: 0,
            state_fields: BTreeMap::new(),
        }
    }

    /// Allocate a temporary local of the given type. Returns its index.
    fn alloc_temp_local(&mut self, vt: ValType) -> u32 {
        let idx = self.next_local;
        self.next_local += 1;
        self.local_types.push((1, vt));
        idx
    }

    /// Resolve the type of an expression by its span.
    ///
    /// Returns `Err(LangError::Codegen)` if the type is not found — this
    /// should not happen for well-formed, type-checked ASTs.
    fn resolve_type(&self, span: &Span) -> Result<ResolvedType, LangError> {
        self.contract
            .type_of(span)
            .cloned()
            .ok_or_else(|| LangError::Codegen {
                message: format!(
                    "no resolved type for expression at line {} col {}",
                    span.line, span.col
                ),
            })
    }

    /// Resolve the type of an expression, with fallback for `self.field`.
    ///
    /// The type checker may store `Unknown` for `self.field` member access
    /// in contract context (the inference pass handles struct fields but not
    /// contract state fields). This method falls back to the state field map
    /// when the expression is `Expr::Member(self, field_name)`.
    fn resolve_expr_type(&self, expr: &Expr) -> Result<ResolvedType, LangError> {
        // Try the type checker's span-based map first
        let span = expr_span(expr);
        if let Some(ty) = self.contract.type_of(&span) {
            // If the type checker resolved it to a concrete type, use it.
            // Unknown means the type checker couldn't resolve it — fall through.
            if *ty != ResolvedType::Unknown {
                return Ok(ty.clone());
            }
        }

        // Fallback: if this is self.field, look up from state_fields
        if let Expr::Member(receiver, field, _) = expr {
            if let Expr::Ident(name, _) = receiver.as_ref() {
                if name == "self" {
                    if let Some((ty, _)) = self.state_fields.get(field.as_str()) {
                        return Ok((*ty).clone());
                    }
                }
            }
        }

        // No type found
        Err(LangError::Codegen {
            message: format!(
                "no resolved type for expression at line {} col {}",
                span.line, span.col
            ),
        })
    }

    /// Emit WASM instructions for an expression.
    ///
    /// Recursively visits the expression tree and emits the corresponding
    /// WASM instructions. The result value is left on the WASM value stack.
    ///
    /// ## Supported expressions (P3·Step 6c)
    ///
    /// - Literals: Int, IntTyped, Hex, Bool
    /// - Binary arithmetic: Add, Sub, Mul, Div, Rem (all checked)
    /// - Comparisons: Eq, NotEq, Lt, Gt, LtEq, GtEq
    /// - Logical: And, Or, Not
    /// - Unary: Neg
    /// - Local variable read (Ident)
    ///
    /// ## Deferred expressions
    ///
    /// All other expression variants return `Err(LangError::Codegen)` with
    /// an honest deferral message.
    fn emit_expr(&mut self, expr: &Expr) -> Result<(), LangError> {
        match expr {
            Expr::Literal(lit, span) => self.emit_literal(lit, span),

            Expr::Ident(name, span) => self.emit_ident(name, span),

            Expr::Binary(op, lhs, rhs, span) => self.emit_binary(op, lhs, rhs, span),

            Expr::Unary(op, inner, span) => self.emit_unary(op, inner, span),

            // Member access: self.field → storage read (P3·Step 6e)
            // Address.zero / Address.burn / Address.nativeLem → constant pointer (P3·Step 6g)
            Expr::Member(receiver, field, _span) => {
                if let Expr::Ident(name, _) = receiver.as_ref() {
                    if name == "self" {
                        return self.emit_storage_read(field);
                    }
                    if name == "Address" {
                        return self.emit_address_constant(field);
                    }
                }
                Err(LangError::Codegen {
                    message: format!(
                        "member access on receiver '{receiver:?}' not yet implemented"
                    ),
                })
            }

            // Function calls: addr.isZero() / addr.isBurn() / addr.isContract() (P3·Step 6g)
            Expr::Call { callee, args, .. } => {
                if let Expr::Member(receiver, method, _) = callee.as_ref() {
                    // Address predicate methods: isZero, isBurn, isNativeLem
                    let predicate_offset = match method.as_str() {
                        "isZero" => Some(ADDR_ZERO_OFFSET),
                        "isBurn" => Some(ADDR_BURN_OFFSET),
                        "isNativeLem" => Some(ADDR_NATIVE_OFFSET),
                        _ => None,
                    };
                    if let Some(offset) = predicate_offset {
                        if args.is_empty() {
                            return self.emit_address_predicate(receiver, offset);
                        }
                        return Err(LangError::Codegen {
                            message: format!("address predicate '{method}' takes no arguments"),
                        });
                    }
                    if method == "isContract" {
                        // isContract() requires a host call to check if an address has
                        // code deployed. The current ABI has no has_code host function.
                        // Deferred: P3·Step 6g scope (DB-A37).
                        return Err(LangError::Codegen {
                            message: "addr.isContract() not yet implemented \
                                      (requires has_code host function — deferred)"
                                .into(),
                        });
                    }
                }
                Err(LangError::Codegen {
                    message: "general function call lowering not yet implemented".into(),
                })
            }

            _ => Err(LangError::Codegen {
                message: format!(
                    "expression lowering not yet implemented for {}",
                    expr_variant_name(expr)
                ),
            }),
        }
    }

    // ── Statement + control flow lowering (P3·Step 6d) ──────────────────

    /// Emit WASM instructions for a block of statements.
    ///
    /// Simply iterates and calls `emit_stmt` on each statement.
    fn emit_block(&mut self, stmts: &[Stmt]) -> Result<(), LangError> {
        for stmt in stmts {
            self.emit_stmt(stmt)?;
        }
        Ok(())
    }

    /// Emit a function body with modifier inlining applied (P3·Step 6f).
    ///
    /// Processes modifiers outermost-first (left-to-right annotation order):
    /// `@a @b fn f()` → `a.pre → b.pre → f.body → b.post → a.post`.
    ///
    /// Each modifier body is split at `Stmt::Placeholder` (`_`) into pre/post
    /// segments. The inner body (remaining modifiers + function body) replaces
    /// the `_` position.
    ///
    /// ## Parameterized modifiers
    ///
    /// Modifiers with parameters are not yet supported in codegen — returns
    /// an honest deferral error (DB-A37 mod.2 scope).
    fn emit_with_modifiers(
        &mut self,
        inner_body: &[Stmt],
        modifiers: &[&str],
        contract: &TypedContract<'_>,
    ) -> Result<(), LangError> {
        if modifiers.is_empty() {
            // Base case: no more modifiers — emit the function body directly.
            return self.emit_block(inner_body);
        }

        let modifier_name = modifiers[0];
        let remaining = &modifiers[1..];

        let modifier_def = find_modifier(contract, modifier_name)?;

        // Reject parameterized modifiers for now (honest deferral).
        if !modifier_def.params.is_empty() {
            return Err(LangError::Codegen {
                message: format!(
                    "parameterized modifier '{modifier_name}' not yet supported in codegen"
                ),
            });
        }

        let (pre, post) = split_at_placeholder(&modifier_def.body)?;

        // Emit: pre → (inner modifiers + body) → post
        self.emit_block(pre)?;
        self.emit_with_modifiers(inner_body, remaining, contract)?;
        self.emit_block(post)?;

        Ok(())
    }

    /// Emit WASM instructions for a single statement.
    ///
    /// ## Supported statements (P3·Step 6d)
    ///
    /// - Let binding, Const binding (local variable allocation + init)
    /// - Assign (simple and compound: +=, -=, *=, /=, %=)
    /// - If/Else
    /// - While loop, Loop (infinite), Break, Continue
    /// - Return
    /// - Assert (trap on false), Revert (unconditional trap)
    /// - Expr (bare expression statement — result dropped)
    ///
    /// ## Deferred statements
    ///
    /// Match, For, Emit, Try, Unchecked, Placeholder → honest codegen error.
    fn emit_stmt(&mut self, stmt: &Stmt) -> Result<(), LangError> {
        match stmt {
            // ── Let binding ───────────────────────────────────────────
            Stmt::Let { pattern, expr, .. } => {
                // Only support Pattern::Ident for now (destructuring deferred)
                let name = match pattern {
                    Pattern::Ident(name, _) => name.clone(),
                    _ => {
                        return Err(LangError::Codegen {
                            message: "let destructuring not yet implemented in codegen".into(),
                        })
                    }
                };
                // Resolve the type from the expression
                let expr_s = expr_span(expr);
                let resolved = self.resolve_type(&expr_s)?;
                let valtype = wasm_valtype(&resolved)?;
                // Allocate a named local
                let idx = self.next_local;
                self.locals.insert(name, idx);
                self.local_types.push((1, valtype));
                self.next_local += 1;
                // Emit the initializer and store
                self.emit_expr(expr)?;
                self.func.instruction(&Instruction::LocalSet(idx));
                Ok(())
            }

            // ── Const binding (immutability is a semantic check, not codegen) ──
            Stmt::Const(c) => {
                let name = c.name.clone();
                let expr_s = expr_span(&c.value);
                let resolved = self.resolve_type(&expr_s)?;
                let valtype = wasm_valtype(&resolved)?;
                let idx = self.next_local;
                self.locals.insert(name, idx);
                self.local_types.push((1, valtype));
                self.next_local += 1;
                self.emit_expr(&c.value)?;
                self.func.instruction(&Instruction::LocalSet(idx));
                Ok(())
            }

            // ── Assignment ────────────────────────────────────────────
            Stmt::Assign {
                target,
                op,
                value,
                span,
            } => self.emit_assign(target, op, value, span),

            // ── If/Else ───────────────────────────────────────────────
            Stmt::If {
                cond, then, else_, ..
            } => {
                self.emit_expr(cond)?;
                if let Some(else_stmts) = else_ {
                    self.func
                        .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                    self.block_depth += 1;
                    self.emit_block(then)?;
                    self.func.instruction(&Instruction::Else);
                    self.emit_block(else_stmts)?;
                    self.block_depth -= 1;
                    self.func.instruction(&Instruction::End);
                } else {
                    self.func
                        .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                    self.block_depth += 1;
                    self.emit_block(then)?;
                    self.block_depth -= 1;
                    self.func.instruction(&Instruction::End);
                }
                Ok(())
            }

            // ── While loop ────────────────────────────────────────────
            // WASM pattern:
            //   block $exit        ;; break target
            //     loop $continue   ;; continue target
            //       <cond>
            //       i32.eqz
            //       br_if 1        ;; if cond is false, exit outer block
            //       <body>
            //       br 0           ;; loop back to loop head
            //     end
            //   end
            Stmt::While { cond, body, .. } => {
                self.func
                    .instruction(&Instruction::Block(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                let break_target = self.block_depth; // outer block

                self.func
                    .instruction(&Instruction::Loop(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                let continue_target = self.block_depth; // loop head

                self.loop_stack.push(LoopCtx {
                    break_target_depth: break_target,
                    continue_target_depth: continue_target,
                });

                self.emit_expr(cond)?;
                self.func.instruction(&Instruction::I32Eqz);
                // br depth to exit outer block = current_depth - break_target
                let br_exit = self.block_depth.checked_sub(break_target).ok_or_else(|| {
                    LangError::Codegen {
                        message: "block depth underflow computing while break target".into(),
                    }
                })?;
                self.func.instruction(&Instruction::BrIf(br_exit));

                self.emit_block(body)?;

                // br depth to loop head = current_depth - continue_target
                let br_cont = self
                    .block_depth
                    .checked_sub(continue_target)
                    .ok_or_else(|| LangError::Codegen {
                        message: "block depth underflow computing while continue target".into(),
                    })?;
                self.func.instruction(&Instruction::Br(br_cont));

                self.loop_stack.pop();
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End); // end loop
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End); // end block
                Ok(())
            }

            // ── Loop (infinite) ───────────────────────────────────────
            Stmt::Loop { body, .. } => {
                self.func
                    .instruction(&Instruction::Block(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                let break_target = self.block_depth;

                self.func
                    .instruction(&Instruction::Loop(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                let continue_target = self.block_depth;

                self.loop_stack.push(LoopCtx {
                    break_target_depth: break_target,
                    continue_target_depth: continue_target,
                });

                self.emit_block(body)?;
                // br depth to loop head = current_depth - continue_target
                let br_cont = self
                    .block_depth
                    .checked_sub(continue_target)
                    .ok_or_else(|| LangError::Codegen {
                        message: "block depth underflow computing loop continue target".into(),
                    })?;
                self.func.instruction(&Instruction::Br(br_cont));

                self.loop_stack.pop();
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End); // end loop
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End); // end block
                Ok(())
            }

            // ── Break ─────────────────────────────────────────────────
            Stmt::Break(_) => {
                let ctx = self.loop_stack.last().ok_or_else(|| LangError::Codegen {
                    message: "break outside of loop".into(),
                })?;
                // Relative br depth = current nesting - target nesting
                let depth = self
                    .block_depth
                    .checked_sub(ctx.break_target_depth)
                    .ok_or_else(|| LangError::Codegen {
                        message: "block depth underflow computing break target".into(),
                    })?;
                self.func.instruction(&Instruction::Br(depth));
                Ok(())
            }

            // ── Continue ──────────────────────────────────────────────
            Stmt::Continue(_) => {
                let ctx = self.loop_stack.last().ok_or_else(|| LangError::Codegen {
                    message: "continue outside of loop".into(),
                })?;
                // Relative br depth = current nesting - target nesting
                let depth = self
                    .block_depth
                    .checked_sub(ctx.continue_target_depth)
                    .ok_or_else(|| LangError::Codegen {
                        message: "block depth underflow computing continue target".into(),
                    })?;
                self.func.instruction(&Instruction::Br(depth));
                Ok(())
            }

            // ── Return ────────────────────────────────────────────────
            Stmt::Return(expr, _) => {
                if let Some(e) = expr {
                    self.emit_expr(e)?;
                }
                self.func.instruction(&Instruction::Return);
                Ok(())
            }

            // ── Assert (trap on false) ────────────────────────────────
            Stmt::Assert { cond, .. } => {
                self.emit_expr(cond)?;
                self.func.instruction(&Instruction::I32Eqz);
                self.func
                    .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                self.func.instruction(&Instruction::Unreachable);
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End);
                Ok(())
            }

            // ── Revert (unconditional trap) ───────────────────────────
            Stmt::Revert { .. } => {
                self.func.instruction(&Instruction::Unreachable);
                Ok(())
            }

            // ── Bare expression statement ─────────────────────────────
            // Drop the result from the value stack. All expressions from
            // 6c push exactly one value; void expressions (e.g. function
            // calls returning void) will need special handling in 6e.
            Stmt::Expr(expr, _) => {
                self.emit_expr(expr)?;
                self.func.instruction(&Instruction::Drop);
                Ok(())
            }

            // ── Deferred statement variants ───────────────────────────
            Stmt::Match { .. } => Err(LangError::Codegen {
                message: "match lowering not yet implemented".into(),
            }),
            Stmt::For { .. } => Err(LangError::Codegen {
                message: "for loop lowering not yet implemented".into(),
            }),
            Stmt::Emit { .. } => Err(LangError::Codegen {
                message: "emit lowering not yet implemented (6e)".into(),
            }),
            Stmt::Try { .. } => Err(LangError::Codegen {
                message: "try/catch lowering not yet implemented".into(),
            }),
            Stmt::Unchecked(..) => Err(LangError::Codegen {
                message: "unchecked block lowering not yet implemented".into(),
            }),
            Stmt::Placeholder(..) => Err(LangError::Codegen {
                message: "unexpected `_` placeholder in codegen — modifier inlining should \
                          have removed it (did split_at_placeholder miss?)"
                    .into(),
            }),
            // Forward-compatibility for #[non_exhaustive]
            #[allow(unreachable_patterns)]
            _ => Err(LangError::Codegen {
                message: "unknown statement variant in codegen".into(),
            }),
        }
    }

    /// Emit WASM instructions for an assignment statement.
    ///
    /// Handles simple assignment (`=`) and compound assignment (`+=`, `-=`,
    /// `*=`, `/=`, `%=`). Compound assignment uses checked arithmetic from
    /// 6c (AGENTS §7.4).
    fn emit_assign(
        &mut self,
        target: &Expr,
        op: &AssignOp,
        value: &Expr,
        _span: &Span,
    ) -> Result<(), LangError> {
        match target {
            Expr::Ident(name, ident_span) => {
                let idx = *self.locals.get(name).ok_or_else(|| LangError::Codegen {
                    message: format!("undefined variable in assignment: {name}"),
                })?;
                if matches!(op, AssignOp::Assign) {
                    // Simple assignment: evaluate value, store
                    self.emit_expr(value)?;
                    self.func.instruction(&Instruction::LocalSet(idx));
                } else {
                    // Compound assign: load current, evaluate value, checked op, store.
                    // Resolve type from the target identifier (not the statement span),
                    // because the type checker stores types by expression span.
                    let ty = self.resolve_type(ident_span)?;
                    // Sub-word compound assignment deferred (M1)
                    if is_sub_word(&ty) {
                        return Err(LangError::Codegen {
                            message: format!(
                                "sub-word compound assignment ({}) not yet implemented",
                                ty.display_name()
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::LocalGet(idx));
                    self.emit_expr(value)?;
                    match op {
                        AssignOp::Add => self.emit_checked_add(&ty)?,
                        AssignOp::Sub => self.emit_checked_sub(&ty)?,
                        AssignOp::Mul => self.emit_checked_mul(&ty)?,
                        AssignOp::Div => self.emit_checked_div(&ty)?,
                        AssignOp::Rem => self.emit_checked_rem(&ty)?,
                        // Forward-compatibility for #[non_exhaustive].
                        // AssignOp::Assign is handled above; remaining
                        // future variants get an honest error.
                        #[allow(unreachable_patterns)]
                        _ => {
                            return Err(LangError::Codegen {
                                message: format!(
                                    "compound assignment operator {op:?} not yet implemented"
                                ),
                            })
                        }
                    }
                    self.func.instruction(&Instruction::LocalSet(idx));
                }
                Ok(())
            }
            // self.field assignment → storage write (P3·Step 6e)
            Expr::Member(receiver, field, _) => {
                if let Expr::Ident(name, _) = receiver.as_ref() {
                    if name == "self" {
                        if !matches!(op, AssignOp::Assign) {
                            return Err(LangError::Codegen {
                                message: "compound assignment to self.field not yet implemented"
                                    .into(),
                            });
                        }
                        return self.emit_storage_write(field, value);
                    }
                }
                Err(LangError::Codegen {
                    message: "assignment to non-self member not yet implemented".into(),
                })
            }
            _ => Err(LangError::Codegen {
                message: "non-local assignment (index) not yet implemented in codegen".into(),
            }),
        }
    }

    // ── Literal emission ──────────────────────────────────────────────────

    fn emit_literal(&mut self, lit: &Literal, span: &Span) -> Result<(), LangError> {
        match lit {
            Literal::Int(n) => {
                let ty = self.resolve_type(span)?;
                if is_i64(&ty) {
                    // Range check: literal must fit in i64 (M2 — catch oversized IntLiteral)
                    if *n > i64::MAX as u128 {
                        return Err(LangError::Codegen {
                            message: format!(
                                "integer literal {n} exceeds i64 range; u128/u256 codegen not yet implemented"
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::I64Const(*n as i64));
                } else {
                    if *n > u32::MAX as u128 {
                        return Err(LangError::Codegen {
                            message: format!(
                                "integer literal {n} exceeds i32 range; larger type needed"
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::I32Const(*n as i32));
                }
                Ok(())
            }

            Literal::IntTyped { value, .. } => {
                let ty = self.resolve_type(span)?;
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Const(*value as i64));
                } else {
                    self.func.instruction(&Instruction::I32Const(*value as i32));
                }
                Ok(())
            }

            Literal::Hex(s) => {
                let hex_str = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                let value = u128::from_str_radix(hex_str, 16).map_err(|e| LangError::Codegen {
                    message: format!("invalid hex literal '{s}': {e}"),
                })?;
                let ty = self.resolve_type(span)?;
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Const(value as i64));
                } else {
                    self.func.instruction(&Instruction::I32Const(value as i32));
                }
                Ok(())
            }

            Literal::Bool(b) => {
                self.func.instruction(&Instruction::I32Const(i32::from(*b)));
                Ok(())
            }

            // ── Unit literals (P3·Step 6h) ────────────────────────────
            //
            // `<n>.<unit>` folds to `n × multiplier` at compile time (checked
            // arithmetic — AGENTS §7.4).  Emitted as I64Const for i64-context
            // types (u64/i64), I32Const otherwise.  Overflows that exceed i64
            // range produce an honest deferral error (u256 multi-word codegen
            // is not yet built).  See DB-A55 and 03-LANGUAGE_SPEC §2.
            Literal::Unit(inner, kind) => {
                // The parser only produces Literal::Unit from `<int>.<unit>`,
                // so inner is always Expr::Literal(Literal::Int(n), _).
                let n = match inner.as_ref() {
                    Expr::Literal(Literal::Int(n), _) => *n,
                    _ => {
                        return Err(LangError::Codegen {
                            message: "unit literal inner expression is not a plain integer".into(),
                        });
                    }
                };
                // Fold: n × multiplier, checked at u128 width (AGENTS §7.4).
                let multiplier = unit_multiplier(kind);
                let folded = n
                    .checked_mul(multiplier)
                    .ok_or_else(|| LangError::Codegen {
                        message: format!(
                            "unit literal {n}.{kind:?} overflows u128; \
                         u256 codegen not yet implemented"
                        ),
                    })?;
                // Emit as i64 or i32 based on context type, mirroring Literal::Int.
                let ty = self.resolve_type(span)?;
                if is_i64(&ty) {
                    if folded > i64::MAX as u128 {
                        return Err(LangError::Codegen {
                            message: format!(
                                "unit literal value {folded} exceeds i64 range; \
                                 u256 codegen not yet implemented"
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::I64Const(folded as i64));
                } else {
                    if folded > u32::MAX as u128 {
                        return Err(LangError::Codegen {
                            message: format!(
                                "unit literal value {folded} exceeds i32 range; \
                                 use a u64 or larger integer type in the context"
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::I32Const(folded as i32));
                }
                Ok(())
            }

            _ => Err(LangError::Codegen {
                message: format!("literal lowering not yet implemented for {lit:?}"),
            }),
        }
    }

    // ── Identifier (local variable read) ──────────────────────────────────

    fn emit_ident(&mut self, name: &str, _span: &Span) -> Result<(), LangError> {
        let local_idx = self.locals.get(name).ok_or_else(|| LangError::Codegen {
            message: format!("undefined local variable: {name}"),
        })?;
        self.func.instruction(&Instruction::LocalGet(*local_idx));
        Ok(())
    }

    // ── Address constants and predicates (P3·Step 6g) ────────────────────

    /// Emit an i32 pointer to a built-in Address constant in linear memory.
    ///
    /// The three constants (`zero`, `burn`, `nativeLem`) are placed in page 0
    /// at fixed offsets by the data section (see `emit_module`). This method
    /// pushes the corresponding offset as an i32 constant onto the WASM stack.
    ///
    /// The caller receives an i32 pointer into linear memory where the 20-byte
    /// address bytes reside.
    fn emit_address_constant(&mut self, field: &str) -> Result<(), LangError> {
        let offset = match field {
            "zero" => ADDR_ZERO_OFFSET,
            "burn" => ADDR_BURN_OFFSET,
            "nativeLem" => ADDR_NATIVE_OFFSET,
            other => {
                return Err(LangError::Codegen {
                    message: format!("Address has no constant '{other}'"),
                })
            }
        };
        self.func.instruction(&Instruction::I32Const(offset as i32));
        Ok(())
    }

    /// Emit a byte-comparison predicate for an address value.
    ///
    /// Compares the 20 bytes at the address pointer produced by `addr_expr`
    /// against the 20-byte constant at `constant_offset` in linear memory.
    /// Returns i32: 1 if equal, 0 if not equal.
    ///
    /// ## Comparison strategy
    ///
    /// Unrolled into 2×i64 loads (bytes 0..8, 8..16) + 1×i32 load (bytes 16..20),
    /// compared against compile-time constants derived from `lemma_core::Address`.
    /// This avoids a runtime loop and is deterministic (AGENTS §7.1).
    ///
    /// The constant bytes are embedded as i64/i32 immediates — no runtime memory
    /// access for the reference side.
    fn emit_address_predicate(
        &mut self,
        addr_expr: &Expr,
        constant_offset: u32,
    ) -> Result<(), LangError> {
        // Evaluate addr_expr → i32 pointer to the address bytes in memory
        self.emit_expr(addr_expr)?;
        let addr_ptr = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::LocalSet(addr_ptr));

        // Retrieve the 20 constant bytes from lemma-core (single source of truth).
        // AGENTS §2 DRY: bytes come from Address::burn()/native_lem(), not hardcoded.
        let const_bytes: [u8; 20] = match constant_offset {
            ADDR_ZERO_OFFSET => [0u8; 20],
            ADDR_BURN_OFFSET => *Address::burn().as_bytes(),
            ADDR_NATIVE_OFFSET => *Address::native_lem().as_bytes(),
            other => {
                return Err(LangError::Codegen {
                    message: format!("unknown address constant offset {other}"),
                })
            }
        };

        // chunk 0: bytes 0..8 — compare as i64 (little-endian)
        let chunk0 = i64::from_le_bytes([
            const_bytes[0],
            const_bytes[1],
            const_bytes[2],
            const_bytes[3],
            const_bytes[4],
            const_bytes[5],
            const_bytes[6],
            const_bytes[7],
        ]);
        self.func.instruction(&Instruction::LocalGet(addr_ptr));
        self.func
            .instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                offset: 0,
                align: 1,
                memory_index: 0,
            }));
        self.func.instruction(&Instruction::I64Const(chunk0));
        self.func.instruction(&Instruction::I64Eq);

        // chunk 1: bytes 8..16 — compare as i64 (little-endian)
        let chunk1 = i64::from_le_bytes([
            const_bytes[8],
            const_bytes[9],
            const_bytes[10],
            const_bytes[11],
            const_bytes[12],
            const_bytes[13],
            const_bytes[14],
            const_bytes[15],
        ]);
        self.func.instruction(&Instruction::LocalGet(addr_ptr));
        self.func
            .instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                offset: 8,
                align: 1,
                memory_index: 0,
            }));
        self.func.instruction(&Instruction::I64Const(chunk1));
        self.func.instruction(&Instruction::I64Eq);
        // AND the two i64 comparisons (both return i32 0/1 from I64Eq)
        self.func.instruction(&Instruction::I32And);

        // chunk 2: bytes 16..20 — compare as i32 (little-endian)
        let chunk2 = i32::from_le_bytes([
            const_bytes[16],
            const_bytes[17],
            const_bytes[18],
            const_bytes[19],
        ]);
        self.func.instruction(&Instruction::LocalGet(addr_ptr));
        self.func
            .instruction(&Instruction::I32Load(wasm_encoder::MemArg {
                offset: 16,
                align: 1,
                memory_index: 0,
            }));
        self.func.instruction(&Instruction::I32Const(chunk2));
        self.func.instruction(&Instruction::I32Eq);
        // AND with the previous result
        self.func.instruction(&Instruction::I32And);

        Ok(())
    }

    // ── Storage access (P3·Step 6e) ──────────────────────────────────────

    /// Emit WASM instructions to read a state field from storage.
    ///
    /// Sequence:
    /// 1. Allocate 32 bytes for the storage key, write key bytes to memory
    /// 2. Call `storage_read(key_ptr, 32, REG_SCRATCH)` → status (i32)
    /// 3. If status == STORAGE_NOT_FOUND: push default value (0)
    /// 4. Else: read value from register into memory, load as typed value
    fn emit_storage_read(&mut self, field_name: &str) -> Result<(), LangError> {
        let (ty, key_bytes) =
            self.state_fields
                .get(field_name)
                .ok_or_else(|| LangError::Codegen {
                    message: format!("unknown state field: {field_name}"),
                })?;
        let ty = (*ty).clone();
        let key_bytes = *key_bytes;
        let byte_width = storage_byte_width(&ty)?;

        // Allocate 32 bytes for the key and write key bytes to memory
        let key_ptr = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::I32Const(32));
        self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
        self.func.instruction(&Instruction::LocalSet(key_ptr));

        // Write key bytes to memory (8 i32.store operations = 32 bytes)
        for chunk_idx in 0..8u32 {
            self.func.instruction(&Instruction::LocalGet(key_ptr));
            let start = (chunk_idx * 4) as usize;
            let word = u32::from_le_bytes([
                key_bytes[start],
                key_bytes[start + 1],
                key_bytes[start + 2],
                key_bytes[start + 3],
            ]);
            self.func.instruction(&Instruction::I32Const(word as i32));
            self.func
                .instruction(&Instruction::I32Store(wasm_encoder::MemArg {
                    offset: (chunk_idx * 4) as u64,
                    align: 2,
                    memory_index: 0,
                }));
        }

        // Call storage_read(key_ptr, 32, REG_SCRATCH) → status
        let status = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::LocalGet(key_ptr));
        self.func.instruction(&Instruction::I32Const(32));
        self.func
            .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
        self.func.instruction(&Instruction::Call(8)); // storage_read = index 8
        self.func.instruction(&Instruction::LocalSet(status));

        // Check status: if STORAGE_NOT_FOUND → push default (0)
        self.func.instruction(&Instruction::LocalGet(status));
        self.func
            .instruction(&Instruction::I32Const(abi::STORAGE_NOT_FOUND));
        self.func.instruction(&Instruction::I32Eq);
        if is_i64(&ty) {
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Result(
                    ValType::I64,
                )));
            self.block_depth += 1;
            // Not found → default 0
            self.func.instruction(&Instruction::I64Const(0));
            self.func.instruction(&Instruction::Else);
        } else {
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Result(
                    ValType::I32,
                )));
            self.block_depth += 1;
            // Not found → default 0
            self.func.instruction(&Instruction::I32Const(0));
            self.func.instruction(&Instruction::Else);
        }

        // Found → validate register length matches expected byte width.
        // Storage value length must match the declared field type's byte width.
        // A mismatch indicates storage corruption or type migration — trap
        // deterministically (AGENTS §7.2).
        let val_len = self.alloc_temp_local(ValType::I32);
        self.func
            .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
        self.func.instruction(&Instruction::Call(6)); // register_len = index 6
        self.func.instruction(&Instruction::I32WrapI64); // truncate to i32 (storage values < 2GB)
        self.func.instruction(&Instruction::LocalTee(val_len));
        self.func
            .instruction(&Instruction::I32Const(byte_width as i32));
        self.func.instruction(&Instruction::I32Ne);
        self.func
            .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
        self.block_depth += 1;
        self.func.instruction(&Instruction::Unreachable); // trap: storage value length mismatch
        self.block_depth -= 1;
        self.func.instruction(&Instruction::End);

        // Allocate buffer for value
        let val_ptr = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::LocalGet(val_len));
        self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
        self.func.instruction(&Instruction::LocalSet(val_ptr));

        // read_register(REG_SCRATCH, val_ptr)
        self.func
            .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
        self.func.instruction(&Instruction::LocalGet(val_ptr));
        self.func.instruction(&Instruction::Call(7)); // read_register = index 7

        // Load value from memory based on type
        self.func.instruction(&Instruction::LocalGet(val_ptr));
        match &ty {
            ResolvedType::Bool => {
                self.func
                    .instruction(&Instruction::I32Load8U(wasm_encoder::MemArg {
                        offset: 0,
                        align: 0,
                        memory_index: 0,
                    }));
            }
            ResolvedType::U32 | ResolvedType::I32 => {
                self.func
                    .instruction(&Instruction::I32Load(wasm_encoder::MemArg {
                        offset: 0,
                        align: 2,
                        memory_index: 0,
                    }));
            }
            ResolvedType::U64 | ResolvedType::I64 => {
                self.func
                    .instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                        offset: 0,
                        align: 3,
                        memory_index: 0,
                    }));
            }
            _ => {
                return Err(LangError::Codegen {
                    message: format!(
                        "storage read for type {} not yet implemented",
                        ty.display_name()
                    ),
                });
            }
        }

        self.block_depth -= 1;
        self.func.instruction(&Instruction::End); // end if/else

        Ok(())
    }

    /// Emit WASM instructions to write a value to a state field in storage.
    ///
    /// Sequence:
    /// 1. Allocate 32 bytes for the storage key, write key bytes to memory
    /// 2. Emit the value expression
    /// 3. Encode value to bytes in memory
    /// 4. Call `storage_write(key_ptr, 32, val_ptr, val_len)`
    fn emit_storage_write(&mut self, field_name: &str, value: &Expr) -> Result<(), LangError> {
        let (ty, key_bytes) =
            self.state_fields
                .get(field_name)
                .ok_or_else(|| LangError::Codegen {
                    message: format!("unknown state field: {field_name}"),
                })?;
        let ty = (*ty).clone();
        let key_bytes = *key_bytes;
        let byte_width = storage_byte_width(&ty)?;

        // Allocate 32 bytes for the key and write key bytes to memory
        let key_ptr = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::I32Const(32));
        self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
        self.func.instruction(&Instruction::LocalSet(key_ptr));

        // Write key bytes to memory
        for chunk_idx in 0..8u32 {
            self.func.instruction(&Instruction::LocalGet(key_ptr));
            let start = (chunk_idx * 4) as usize;
            let word = u32::from_le_bytes([
                key_bytes[start],
                key_bytes[start + 1],
                key_bytes[start + 2],
                key_bytes[start + 3],
            ]);
            self.func.instruction(&Instruction::I32Const(word as i32));
            self.func
                .instruction(&Instruction::I32Store(wasm_encoder::MemArg {
                    offset: (chunk_idx * 4) as u64,
                    align: 2,
                    memory_index: 0,
                }));
        }

        // Emit the value expression — result on stack
        self.emit_expr(value)?;

        // Allocate buffer for value and store it
        let val_ptr = self.alloc_temp_local(ValType::I32);
        self.func
            .instruction(&Instruction::I32Const(byte_width as i32));
        self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
        self.func.instruction(&Instruction::LocalSet(val_ptr));

        // Store value to memory based on type
        // The value is on the stack from emit_expr; we need to save it to a temp
        // because we need val_ptr on the stack first for the store instruction.
        let val_tmp = if is_i64(&ty) {
            self.alloc_temp_local(ValType::I64)
        } else {
            self.alloc_temp_local(ValType::I32)
        };
        self.func.instruction(&Instruction::LocalSet(val_tmp));

        self.func.instruction(&Instruction::LocalGet(val_ptr));
        self.func.instruction(&Instruction::LocalGet(val_tmp));
        match &ty {
            ResolvedType::Bool => {
                self.func
                    .instruction(&Instruction::I32Store8(wasm_encoder::MemArg {
                        offset: 0,
                        align: 0,
                        memory_index: 0,
                    }));
            }
            ResolvedType::U32 | ResolvedType::I32 => {
                self.func
                    .instruction(&Instruction::I32Store(wasm_encoder::MemArg {
                        offset: 0,
                        align: 2,
                        memory_index: 0,
                    }));
            }
            ResolvedType::U64 | ResolvedType::I64 => {
                self.func
                    .instruction(&Instruction::I64Store(wasm_encoder::MemArg {
                        offset: 0,
                        align: 3,
                        memory_index: 0,
                    }));
            }
            _ => {
                return Err(LangError::Codegen {
                    message: format!(
                        "storage write for type {} not yet implemented",
                        ty.display_name()
                    ),
                });
            }
        }

        // Call storage_write(key_ptr, 32, val_ptr, val_len)
        self.func.instruction(&Instruction::LocalGet(key_ptr));
        self.func.instruction(&Instruction::I32Const(32));
        self.func.instruction(&Instruction::LocalGet(val_ptr));
        self.func
            .instruction(&Instruction::I32Const(byte_width as i32));
        self.func.instruction(&Instruction::Call(9)); // storage_write = index 9

        Ok(())
    }

    // ── Binary expression emission ────────────────────────────────────────

    fn emit_binary(
        &mut self,
        op: &BinaryOp,
        lhs: &Expr,
        rhs: &Expr,
        _span: &Span,
    ) -> Result<(), LangError> {
        // Resolve the operand type from the LHS. Both sides have the same type
        // after type checking (or IntLiteral which coerces to the other side's type).
        // Uses resolve_expr_type for self.field fallback (P3·Step 6e).
        let ty = self.resolve_expr_type(lhs)?;

        // M1 — sub-word types (u8/u16/i8/i16) need range-check masking after
        // arithmetic to detect overflow within the narrower type range. Until
        // that is implemented, reject arithmetic on sub-word types honestly.
        if matches!(
            op,
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem
        ) && is_sub_word(&ty)
        {
            return Err(LangError::Codegen {
                message: format!(
                    "sub-word arithmetic ({}) not yet implemented; range-check masking needed",
                    ty.display_name()
                ),
            });
        }

        // M2 (revised) — IntLiteral in arithmetic is common (untyped `10 + 20`).
        // The type checker doesn't always coerce sub-expression types to concrete.
        // Treat IntLiteral as i64 unsigned (WASM native). Checked arithmetic uses
        // i64 overflow bounds, which is safe for values ≤ i64::MAX. Literal values
        // exceeding i64::MAX are caught at emission time (emit_literal range check).
        // This is conservative: i64 overflow detection is stricter than u256.

        match op {
            // ── Checked arithmetic ────────────────────────────────────
            BinaryOp::Add => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_add(&ty)
            }
            BinaryOp::Sub => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_sub(&ty)
            }
            BinaryOp::Mul => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_mul(&ty)
            }
            BinaryOp::Div => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_div(&ty)
            }
            BinaryOp::Rem => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_rem(&ty)
            }

            // ── Comparisons ───────────────────────────────────────────
            BinaryOp::Eq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Eq);
                } else {
                    self.func.instruction(&Instruction::I32Eq);
                }
                Ok(())
            }
            BinaryOp::NotEq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Ne);
                } else {
                    self.func.instruction(&Instruction::I32Ne);
                }
                Ok(())
            }
            BinaryOp::Lt => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_lt(&ty);
                Ok(())
            }
            BinaryOp::Gt => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_gt(&ty);
                Ok(())
            }
            BinaryOp::LtEq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_le(&ty);
                Ok(())
            }
            BinaryOp::GtEq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_ge(&ty);
                Ok(())
            }

            // ── Logical ───────────────────────────────────────────────
            BinaryOp::And => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.func.instruction(&Instruction::I32And);
                Ok(())
            }
            BinaryOp::Or => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.func.instruction(&Instruction::I32Or);
                Ok(())
            }

            _ => Err(LangError::Codegen {
                message: format!("binary operator lowering not yet implemented for {op:?}"),
            }),
        }
    }

    // ── Unary expression emission ─────────────────────────────────────────

    fn emit_unary(&mut self, op: &UnaryOp, inner: &Expr, span: &Span) -> Result<(), LangError> {
        match op {
            UnaryOp::Not => {
                self.emit_expr(inner)?;
                self.func.instruction(&Instruction::I32Eqz);
                Ok(())
            }
            UnaryOp::Neg => {
                // C2 — Neg(MIN) must trap for signed types.
                // Route through checked sub: `0 - x`. For signed types, the
                // checked sub pattern `(a ^ b) & (a ^ result) < 0` catches
                // `0 - MIN` (negation overflow). For unsigned types, checked
                // sub catches `0 - x` when `x > 0` (underflow).
                let ty = self.resolve_type(span)?;

                // Sub-word negation needs range-check masking (same as M1).
                if is_sub_word(&ty) {
                    return Err(LangError::Codegen {
                        message: format!(
                            "sub-word negation ({}) not yet implemented; range-check masking needed",
                            ty.display_name()
                        ),
                    });
                }

                // Emit: [0, inner] on stack, then checked sub
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Const(0));
                } else {
                    self.func.instruction(&Instruction::I32Const(0));
                }
                self.emit_expr(inner)?;
                self.emit_checked_sub(&ty)
            }
            _ => Err(LangError::Codegen {
                message: format!("unary operator lowering not yet implemented for {op:?}"),
            }),
        }
    }

    // ── Comparison helpers ────────────────────────────────────────────────

    fn emit_lt(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if is_signed(ty) {
                self.func.instruction(&Instruction::I64LtS);
            } else {
                self.func.instruction(&Instruction::I64LtU);
            }
        } else if is_signed(ty) {
            self.func.instruction(&Instruction::I32LtS);
        } else {
            self.func.instruction(&Instruction::I32LtU);
        }
    }

    fn emit_gt(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if is_signed(ty) {
                self.func.instruction(&Instruction::I64GtS);
            } else {
                self.func.instruction(&Instruction::I64GtU);
            }
        } else if is_signed(ty) {
            self.func.instruction(&Instruction::I32GtS);
        } else {
            self.func.instruction(&Instruction::I32GtU);
        }
    }

    fn emit_le(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if is_signed(ty) {
                self.func.instruction(&Instruction::I64LeS);
            } else {
                self.func.instruction(&Instruction::I64LeU);
            }
        } else if is_signed(ty) {
            self.func.instruction(&Instruction::I32LeS);
        } else {
            self.func.instruction(&Instruction::I32LeU);
        }
    }

    fn emit_ge(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if is_signed(ty) {
                self.func.instruction(&Instruction::I64GeS);
            } else {
                self.func.instruction(&Instruction::I64GeU);
            }
        } else if is_signed(ty) {
            self.func.instruction(&Instruction::I32GeS);
        } else {
            self.func.instruction(&Instruction::I32GeU);
        }
    }

    // ── Checked arithmetic (AGENTS §7.4) ──────────────────────────────────
    //
    // Every arithmetic operation traps on overflow/underflow/division-by-zero.
    // The pattern: save operands to temp locals, perform the operation, check
    // the result, and emit `unreachable` (WASM trap) on failure.

    /// Checked addition: traps if `a + b` overflows.
    ///
    /// ## Unsigned overflow detection
    /// `result < a` implies overflow (since `b >= 0` for unsigned).
    ///
    /// ## Signed overflow detection
    ///
    /// Uses the WASM `add` instruction which wraps, then checks:
    /// - If both operands positive and result negative → overflow
    /// - If both operands negative and result positive → overflow
    ///
    /// Simplified: `(a ^ result) & (b ^ result)` has sign bit set on overflow.
    fn emit_checked_add(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        if wide {
            let tmp_a = self.alloc_temp_local(ValType::I64);
            let tmp_b = self.alloc_temp_local(ValType::I64);
            let tmp_result = self.alloc_temp_local(ValType::I64);

            // Stack: [a, b] → save both
            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            // Compute a + b
            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I64Add);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            if signed {
                // Signed overflow: (a ^ result) & (b ^ result) < 0
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I64Xor);
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I64Xor);
                self.func.instruction(&Instruction::I64And);
                self.func.instruction(&Instruction::I64Const(0));
                self.func.instruction(&Instruction::I64LtS);
            } else {
                // Unsigned overflow: result < a
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::I64LtU);
            }

            // If overflow → trap
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);

            // Push result
            self.func.instruction(&Instruction::LocalGet(tmp_result));
        } else {
            let tmp_a = self.alloc_temp_local(ValType::I32);
            let tmp_b = self.alloc_temp_local(ValType::I32);
            let tmp_result = self.alloc_temp_local(ValType::I32);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I32Add);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            if signed {
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I32Xor);
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I32Xor);
                self.func.instruction(&Instruction::I32And);
                self.func.instruction(&Instruction::I32Const(0));
                self.func.instruction(&Instruction::I32LtS);
            } else {
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::I32LtU);
            }

            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        }
        Ok(())
    }

    /// Checked subtraction: traps if `a - b` underflows.
    ///
    /// ## Unsigned underflow detection
    /// `a < b` implies underflow.
    ///
    /// ## Signed overflow detection
    /// `(a ^ b) & (a ^ result)` has sign bit set on overflow.
    fn emit_checked_sub(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        if wide {
            let tmp_a = self.alloc_temp_local(ValType::I64);
            let tmp_b = self.alloc_temp_local(ValType::I64);
            let tmp_result = self.alloc_temp_local(ValType::I64);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I64Sub);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            if signed {
                // Signed sub overflow: (a ^ b) & (a ^ result) < 0
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I64Xor);
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I64Xor);
                self.func.instruction(&Instruction::I64And);
                self.func.instruction(&Instruction::I64Const(0));
                self.func.instruction(&Instruction::I64LtS);
            } else {
                // Unsigned underflow: a < b
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I64LtU);
            }

            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        } else {
            let tmp_a = self.alloc_temp_local(ValType::I32);
            let tmp_b = self.alloc_temp_local(ValType::I32);
            let tmp_result = self.alloc_temp_local(ValType::I32);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I32Sub);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            if signed {
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I32Xor);
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I32Xor);
                self.func.instruction(&Instruction::I32And);
                self.func.instruction(&Instruction::I32Const(0));
                self.func.instruction(&Instruction::I32LtS);
            } else {
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I32LtU);
            }

            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        }
        Ok(())
    }

    /// Checked multiplication: traps if `a * b` overflows.
    ///
    /// ## Unsigned overflow detection
    /// If `a != 0 && result / a != b` → overflow.
    ///
    /// ## Signed overflow detection
    /// Same check but using signed division, plus special-case for
    /// `a == -1 && b == MIN` (which would overflow signed div).
    fn emit_checked_mul(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        if wide {
            let tmp_a = self.alloc_temp_local(ValType::I64);
            let tmp_b = self.alloc_temp_local(ValType::I64);
            let tmp_result = self.alloc_temp_local(ValType::I64);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I64Mul);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            // Check: if a != 0 && result / a != b → overflow
            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::I64Const(0));
            self.func.instruction(&Instruction::I64Ne);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            {
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                if signed {
                    self.func.instruction(&Instruction::I64DivS);
                } else {
                    self.func.instruction(&Instruction::I64DivU);
                }
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I64Ne);
                self.func
                    .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                self.func.instruction(&Instruction::Unreachable);
                self.func.instruction(&Instruction::End);
            }
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        } else {
            let tmp_a = self.alloc_temp_local(ValType::I32);
            let tmp_b = self.alloc_temp_local(ValType::I32);
            let tmp_result = self.alloc_temp_local(ValType::I32);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I32Mul);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::I32Const(0));
            self.func.instruction(&Instruction::I32Ne);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            {
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                if signed {
                    self.func.instruction(&Instruction::I32DivS);
                } else {
                    self.func.instruction(&Instruction::I32DivU);
                }
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I32Ne);
                self.func
                    .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                self.func.instruction(&Instruction::Unreachable);
                self.func.instruction(&Instruction::End);
            }
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        }
        Ok(())
    }

    /// Checked division: traps if divisor is zero.
    ///
    /// WASM `div_u` / `div_s` already trap on division by zero, but we emit
    /// an explicit check for clarity and to produce a consistent trap pattern.
    /// For signed division, WASM also traps on `INT_MIN / -1` (overflow).
    fn emit_checked_div(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        // Check divisor != 0 (top of stack is divisor, below is dividend)
        if wide {
            let tmp_b = self.alloc_temp_local(ValType::I64);
            self.func.instruction(&Instruction::LocalTee(tmp_b));
            self.func.instruction(&Instruction::I64Eqz);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);
            // Restore divisor and perform division
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            if signed {
                self.func.instruction(&Instruction::I64DivS);
            } else {
                self.func.instruction(&Instruction::I64DivU);
            }
        } else {
            let tmp_b = self.alloc_temp_local(ValType::I32);
            self.func.instruction(&Instruction::LocalTee(tmp_b));
            self.func.instruction(&Instruction::I32Eqz);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            if signed {
                self.func.instruction(&Instruction::I32DivS);
            } else {
                self.func.instruction(&Instruction::I32DivU);
            }
        }
        Ok(())
    }

    /// Checked remainder: traps if divisor is zero.
    ///
    /// Same zero-check pattern as division.
    fn emit_checked_rem(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        if wide {
            let tmp_b = self.alloc_temp_local(ValType::I64);
            self.func.instruction(&Instruction::LocalTee(tmp_b));
            self.func.instruction(&Instruction::I64Eqz);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            if signed {
                self.func.instruction(&Instruction::I64RemS);
            } else {
                self.func.instruction(&Instruction::I64RemU);
            }
        } else {
            let tmp_b = self.alloc_temp_local(ValType::I32);
            self.func.instruction(&Instruction::LocalTee(tmp_b));
            self.func.instruction(&Instruction::I32Eqz);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            if signed {
                self.func.instruction(&Instruction::I32RemS);
            } else {
                self.func.instruction(&Instruction::I32RemU);
            }
        }
        Ok(())
    }

    /// Seal the function body by appending the `End` instruction.
    ///
    /// Returns the built `Function`. Note: the caller is responsible for
    /// ensuring the function was created with the correct local declarations
    /// (see `emit_test_expr_module` for the two-pass approach).
    fn finish(mut self) -> Function {
        self.func.instruction(&Instruction::End);
        self.func
    }
}

// ─── Test-only helpers ────────────────────────────────────────────────────────

/// Build a complete WASM module containing a single test function that
/// evaluates the given expression and returns the result.
///
/// This is the primary test vehicle for P3·Step 6c expression lowering.
/// The function signature is `() -> [result_type]` so the expression result
/// can be validated.
///
/// Only available in test builds.
#[cfg(test)]
pub(crate) fn emit_test_expr_module(
    contract: &TypedContract<'_>,
    expr: &Expr,
    params: &[(String, ValType)],
) -> Result<Vec<u8>, LangError> {
    use crate::codegen::types::wasm_valtype;

    let expr_span = expr_span(expr);
    let result_ty = contract
        .type_of(&expr_span)
        .ok_or_else(|| LangError::Codegen {
            message: "no resolved type for test expression".into(),
        })?;
    let wasm_result = wasm_valtype(result_ty)?;

    // Phase 1: emit instructions into a LowerCtx to discover temp locals
    let mut ctx = LowerCtx::new(contract, params);
    ctx.emit_expr(expr)?;
    ctx.func.instruction(&Instruction::End);

    // Phase 2: rebuild the function with correct local declarations
    // We need to replay the instructions with the now-known local count.
    // Since wasm-encoder doesn't support replaying, we use a workaround:
    // build a second LowerCtx with pre-allocated locals matching the first pass.
    //
    // Actually, a simpler approach: we know the local_types from ctx.
    // We can use raw_bytes from the first function and patch the locals.
    // But that's fragile.
    //
    // Simplest correct approach: use Function::new with the right locals
    // from the start by doing a two-pass compile. But that's expensive.
    //
    // Best approach for correctness: since we know the number of temp locals
    // after the first pass, we can pre-allocate them in a second pass.
    let temp_local_count = ctx.local_types.len();
    let all_locals: Vec<(u32, ValType)> = ctx.local_types;

    // Second pass: rebuild with correct locals
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
        local_types: Vec::new(), // won't allocate more temps in second pass
        loop_stack: Vec::new(),
        block_depth: 0,
        alloc_fn_idx: 0,
        state_fields: BTreeMap::new(),
    };

    // We need to re-emit the expression. The temp local indices must match.
    // Since alloc_temp_local increments next_local, and we set it to skip
    // past the pre-allocated temps, new allocations would get wrong indices.
    // Fix: reset next_local to where temps start, so re-allocation matches.
    ctx2.next_local = params.len() as u32;

    ctx2.emit_expr(expr)?;
    ctx2.func.instruction(&Instruction::End);

    // C1 — assert that pass-2 allocated the same number of temp locals as
    // pass-1. If this fires, the two-pass approach has desynced: the
    // instruction stream references local indices that don't match the
    // declared locals, producing a silently miscompiled module.
    assert_eq!(
        ctx2.next_local,
        params.len() as u32 + temp_local_count as u32,
        "BUG: pass-2 allocated {} temp locals but pass-1 allocated {} — instruction/local desync",
        ctx2.next_local - params.len() as u32,
        temp_local_count,
    );

    // Build the module
    let mut module = Module::new();

    // Type section: host function types + test function type
    let mut types = TypeSection::new();
    for (p, r) in HOST_SIGS {
        types.ty().function(p.iter().copied(), r.iter().copied());
    }
    // Test function type: params → [result]
    let param_valtypes: Vec<ValType> = params.iter().map(|(_, vt)| *vt).collect();
    types
        .ty()
        .function(param_valtypes.iter().copied(), [wasm_result]);
    module.section(&types);

    // Import section
    let mut imports = ImportSection::new();
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        imports.import(IMPORT_MODULE, name, EntityType::Function(i as u32));
    }
    module.section(&imports);

    // Function section
    let test_type_index = HOST_IMPORT_COUNT;
    let mut functions = FunctionSection::new();
    functions.function(test_type_index);
    module.section(&functions);

    // Memory section
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: INITIAL_MEMORY_PAGES,
        maximum: None,
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    // Global section
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

    // Export section
    let test_func_index = HOST_IMPORT_COUNT;
    let mut exports = ExportSection::new();
    exports.export("test", ExportKind::Func, test_func_index);
    exports.export(abi::MEMORY_EXPORT, ExportKind::Memory, 0);
    module.section(&exports);

    // Code section
    let mut codes = CodeSection::new();
    codes.function(&ctx2.func);
    module.section(&codes);

    Ok(module.finish())
}

/// Build a complete WASM module from a contract function body (statements).
///
/// This is the primary test vehicle for P3·Step 6d statement lowering.
/// The function signature is `() -> [result_type]` so the function body
/// can include `return <expr>` and the result can be validated.
///
/// Uses the same two-pass approach as `emit_test_expr_module`: pass 1
/// discovers local allocations, pass 2 rebuilds with correct declarations.
///
/// Only available in test builds.
#[cfg(test)]
pub(crate) fn emit_test_stmt_module(
    contract: &TypedContract<'_>,
    stmts: &[Stmt],
    params: &[(String, ValType)],
    result_type: ValType,
) -> Result<Vec<u8>, LangError> {
    // Phase 1: emit instructions to discover local allocations
    let mut ctx = LowerCtx::new(contract, params);
    ctx.emit_block(stmts)?;
    ctx.func.instruction(&Instruction::End);

    let local_count = ctx.local_types.len();
    let all_locals: Vec<(u32, ValType)> = ctx.local_types;
    let discovered_locals = ctx.locals.clone();

    // Phase 2: rebuild with correct local declarations
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

    // Verify pass-2 allocated the same locals as pass-1
    assert_eq!(
        ctx2.next_local,
        params.len() as u32 + local_count as u32,
        "BUG: pass-2 allocated {} locals but pass-1 allocated {} — desync",
        ctx2.next_local - params.len() as u32,
        local_count,
    );
    // Verify named locals match between passes
    assert_eq!(
        ctx2.locals, discovered_locals,
        "BUG: named local map differs between pass-1 and pass-2"
    );

    // Build the module
    let mut module = Module::new();

    // Type section: host function types + test function type
    let mut types = TypeSection::new();
    for (p, r) in HOST_SIGS {
        types.ty().function(p.iter().copied(), r.iter().copied());
    }
    let param_valtypes: Vec<ValType> = params.iter().map(|(_, vt)| *vt).collect();
    types
        .ty()
        .function(param_valtypes.iter().copied(), [result_type]);
    module.section(&types);

    // Import section
    let mut imports = ImportSection::new();
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        imports.import(IMPORT_MODULE, name, EntityType::Function(i as u32));
    }
    module.section(&imports);

    // Function section
    let test_type_index = HOST_IMPORT_COUNT;
    let mut functions = FunctionSection::new();
    functions.function(test_type_index);
    module.section(&functions);

    // Memory section
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: INITIAL_MEMORY_PAGES,
        maximum: None,
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    // Global section
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

    // Export section
    let test_func_index = HOST_IMPORT_COUNT;
    let mut exports = ExportSection::new();
    exports.export("test", ExportKind::Func, test_func_index);
    exports.export(abi::MEMORY_EXPORT, ExportKind::Memory, 0);
    module.section(&exports);

    // Code section
    let mut codes = CodeSection::new();
    codes.function(&ctx2.func);
    module.section(&codes);

    Ok(module.finish())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Return the variant name of an `Expr` for error messages.
///
/// Avoids printing the full debug representation (which includes all inner data).
/// The `#[allow(unreachable_patterns)]` is required because `Expr` is
/// `#[non_exhaustive]` — the wildcard arm is needed for forward compatibility.
// consumer: LowerCtx::emit_expr (P3·Step 6c)
#[allow(dead_code, unreachable_patterns)]
fn expr_variant_name(expr: &Expr) -> &'static str {
    match expr {
        Expr::Literal(..) => "Literal",
        Expr::Ident(..) => "Ident",
        Expr::Tuple(..) => "Tuple",
        Expr::Array(..) => "Array",
        Expr::Struct_ { .. } => "Struct",
        Expr::Call { .. } => "Call",
        Expr::Index(..) => "Index",
        Expr::Member(..) => "Member",
        Expr::Unary(..) => "Unary",
        Expr::Binary(..) => "Binary",
        Expr::Ternary { .. } => "Ternary",
        Expr::Nullish(..) => "Nullish",
        Expr::Try_(..) => "Try",
        Expr::Cast { .. } => "Cast",
        Expr::Lambda { .. } => "Lambda",
        Expr::New { .. } => "New",
        Expr::Match_(..) => "Match",
        Expr::If_ { .. } => "If",
        Expr::Template(..) => "Template",
        Expr::Assign_(..) => "Assign",
        // Forward-compatibility for #[non_exhaustive]
        _ => "Unknown",
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
