//! Dispatch prologue, bump allocator, and contract function body emission.
//!
//! Split from `wasm.rs` (P3·Step 6e dispatch + function body lowering).

use std::collections::BTreeMap;

use wasm_encoder::{Function, Instruction, ValType};

use crate::codegen::abi;
use crate::codegen::types::{is_address, is_u128, local_count, wasm_valtype};
use crate::codegen::wasm::lower::{get_fn_resolved_params, storage_key, LowerCtx};
use crate::error::LangError;
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::type_checker::types::{ResolvedType, SymbolSig};

use super::ADDRESS_BYTE_LEN;

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
pub(crate) fn emit_alloc_body() -> Function {
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
pub(crate) fn emit_dispatch_prologue(
    selectors: &[(u32, usize)],
    pub_fns: &[&ContractFunction<'_>],
    contract: &TypedContract<'_>,
    alloc_idx: u32,
    fn_base: u32,
) -> Result<Function, LangError> {
    // Count the max number of Address params in any single dispatchable function.
    // Each Address param needs a temp i32 local during calldata decoding to hold
    // the bump-allocated pointer while copying bytes. Since dispatch branches are
    // mutually exclusive, we can reuse the same temp locals across branches.
    let mut max_addr_params: u32 = 0;
    for func in pub_fns {
        let resolved = get_fn_resolved_params(func, contract);
        let addr_count = resolved.iter().filter(|(_, ty)| is_address(ty)).count() as u32;
        if addr_count > max_addr_params {
            max_addr_params = addr_count;
        }
    }

    // Locals: cd_len_i64 (i64), cd_len (i32), cd_ptr (i32), selector (i32),
    //         then max_addr_params × i32 temps for Address pointer storage.
    let mut local_decls = vec![
        (1, ValType::I64), // local 0: cd_len_i64 (raw register_len result, for sentinel check)
        (1, ValType::I32), // local 1: cd_len
        (1, ValType::I32), // local 2: cd_ptr
        (1, ValType::I32), // local 3: selector
    ];
    if max_addr_params > 0 {
        local_decls.push((max_addr_params, ValType::I32)); // locals 4..4+N: addr temps
    }
    let mut f = Function::new(local_decls);

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

    // Dispatch: if/else chain comparing selector to each function's selector.
    // Address temp locals start at index 4 and are reused across branches
    // (only one branch executes per call).
    let addr_temp_base: u32 = 4;
    for (sel, fn_idx) in selectors {
        // Reset the Address temp local counter for each branch (reuse across branches).
        let mut dispatch_next_local = addr_temp_base;
        f.instruction(&Instruction::LocalGet(3));
        f.instruction(&Instruction::I32Const(*sel as i32));
        f.instruction(&Instruction::I32Eq);
        f.instruction(&Instruction::If(wasm_encoder::BlockType::Empty));

        // Decode args from calldata and call the function.
        // Uses resolved Lem types (not just WASM ValTypes) to distinguish
        // u128 (16 bytes → i64-pair) and Address (20 bytes → i32 pointer)
        // from plain i32/i64 params.
        let func = pub_fns[*fn_idx];
        let resolved_params = get_fn_resolved_params(func, contract);
        let mut offset: u32 = 4; // skip selector

        for (_name, ty) in &resolved_params {
            if is_u128(ty) {
                // u128: read 16 LE bytes from calldata as two i64 values (lo, hi).
                // Push lo first, then hi — matches the i64-pair local layout.
                f.instruction(&Instruction::LocalGet(2)); // cd_ptr
                f.instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                    offset: offset as u64,
                    align: 3,
                    memory_index: 0,
                }));
                offset = offset.checked_add(8).ok_or_else(|| LangError::Codegen {
                    message: "calldata offset overflow".into(),
                })?;
                f.instruction(&Instruction::LocalGet(2)); // cd_ptr
                f.instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                    offset: offset as u64,
                    align: 3,
                    memory_index: 0,
                }));
                offset = offset.checked_add(8).ok_or_else(|| LangError::Codegen {
                    message: "calldata offset overflow".into(),
                })?;
            } else if is_address(ty) {
                // Address: read 20 bytes from calldata into bump-alloc memory,
                // push the pointer (i32). Uses 5 × i32.store (20 bytes).
                f.instruction(&Instruction::I32Const(ADDRESS_BYTE_LEN as i32));
                f.instruction(&Instruction::Call(alloc_idx));
                // Stack: [addr_ptr]. Save to a dispatch-local temp.
                let addr_tmp = dispatch_next_local;
                dispatch_next_local += 1;
                f.instruction(&Instruction::LocalSet(addr_tmp));
                // Copy 20 bytes from calldata to allocated memory.
                // 4 × i32.store (16 bytes) + 1 × i32.store for last 4 bytes.
                for chunk in 0..5u32 {
                    f.instruction(&Instruction::LocalGet(addr_tmp));
                    f.instruction(&Instruction::LocalGet(2)); // cd_ptr
                    let byte_offset =
                        offset
                            .checked_add(chunk * 4)
                            .ok_or_else(|| LangError::Codegen {
                                message: "calldata offset overflow".into(),
                            })?;
                    f.instruction(&Instruction::I32Load(wasm_encoder::MemArg {
                        offset: byte_offset as u64,
                        align: 2,
                        memory_index: 0,
                    }));
                    f.instruction(&Instruction::I32Store(wasm_encoder::MemArg {
                        offset: (chunk * 4) as u64,
                        align: 2,
                        memory_index: 0,
                    }));
                }
                offset =
                    offset
                        .checked_add(ADDRESS_BYTE_LEN)
                        .ok_or_else(|| LangError::Codegen {
                            message: "calldata offset overflow".into(),
                        })?;
                // Push the pointer for the function call
                f.instruction(&Instruction::LocalGet(addr_tmp));
            } else {
                // Standard single-word types
                let vt = wasm_valtype(ty)?;
                f.instruction(&Instruction::LocalGet(2)); // cd_ptr
                match vt {
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
                            message: format!("unsupported WASM param type in dispatch: {vt:?}"),
                        });
                    }
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

/// Emit a contract function body using the two-pass approach.
///
/// Pass 1: lower the function body to discover local allocations.
/// Pass 2: rebuild with correct local declarations.
pub(crate) fn emit_contract_fn_body(
    func: &ContractFunction<'_>,
    contract: &TypedContract<'_>,
    state_fields: &[crate::type_checker::typed_contract::StateField<'_>],
    alloc_idx: u32,
) -> Result<Function, LangError> {
    let body = func.body.ok_or_else(|| LangError::Codegen {
        message: format!("function '{}' has no body", func.name),
    })?;

    // Build param list: (name, ValType) from the resolved signature.
    // u128 params expand to 2 i64 locals (lo, hi) with synthetic names.
    // Address params are i32 pointers (1 local).
    let mut params: Vec<(String, ValType)> = Vec::new();
    if let Some(sym_id) = func.symbol_id {
        if let Some(SymbolSig::Function(fn_sig)) = contract.sig(sym_id) {
            for (name, ty, _) in &fn_sig.params {
                let vt = wasm_valtype(ty)?;
                let count = local_count(ty);
                if count == 2 {
                    // u128: two i64 locals named <name>_lo and <name>_hi
                    params.push((format!("{name}_lo"), vt));
                    params.push((format!("{name}_hi"), vt));
                } else {
                    params.push((name.clone(), vt));
                }
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
