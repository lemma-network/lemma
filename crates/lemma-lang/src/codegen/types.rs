//! Lem → WASM type mapping for codegen.
//!
//! WASM has only two integer types: `i32` and `i64`. Lem's richer type system
//! (u8..u256, bool, Address, etc.) must be projected onto these two types.
//!
//! ## Supported types (P3·Step 6c + subtask_08)
//!
//! Single-word types:
//! - bool, u8, u16, u32, i8, i16, i32 → `ValType::I32`
//! - u64, i64 → `ValType::I64`
//!
//! Multi-word / reference types (subtask_08):
//! - u128 → i64-pair (lo, hi) in two consecutive WASM locals. Each half
//!   maps to `ValType::I64`. Functions that accept u128 params receive two
//!   i64 values on the WASM stack. `wasm_valtype` returns `I64` (the type
//!   of each half); callers use `local_count()` to know how many locals.
//! - Address → i32 pointer to 20 bytes in linear memory. `wasm_valtype`
//!   returns `I32` (the pointer type). Calldata decoding copies 20 bytes
//!   from calldata into bump-allocated memory and pushes the pointer.
//!
//! Deferred types:
//! - u256, i128, i256 → `Err` (multi-word, deferred to P3·Step 23)
//! - string, bytes, etc. → `Err` (reference types, deferred)
//!
//! ## `IntLiteral` handling
//!
//! Unconstrained integer literals (`IntLiteral`) default to `i32` in codegen
//! (conservative — avoids needing u256 multi-word for simple literals like `42`).
//! The type checker should have coerced most `IntLiteral`s to concrete types
//! before codegen; this fallback handles the residual unconstrained case.

use wasm_encoder::ValType;

use crate::error::LangError;
use crate::type_checker::types::ResolvedType;

/// Map a Lem [`ResolvedType`] to a WASM [`ValType`].
///
/// Returns `Err(LangError::Codegen)` for types not yet supported in codegen.
///
/// ## Mapping table
///
/// | Lem type | WASM type | Notes |
/// |----------|-----------|-------|
/// | bool, u8, u16, u32, i8, i16, i32 | `I32` | single-word |
/// | u64, i64 | `I64` | single-word |
/// | IntLiteral | `I32` | narrowest native; range-checked at emit |
/// | u128 | `I64` | i64-pair (lo, hi); use `local_count()` for 2 locals |
/// | Address | `I32` | pointer to 20 bytes in linear memory |
/// | u256, i128, i256 | `Err` | deferred to P3·Step 23 |
/// | string, bytes, etc. | `Err` | reference types, deferred |
///
/// ## u128 representation (subtask_08)
///
/// u128 is represented as an i64-pair (lo, hi) in two consecutive WASM locals.
/// `wasm_valtype` returns `I64` — the type of each half. Callers that need to
/// know the number of WASM locals per Lem value use [`local_count`].
///
/// ## Address representation (subtask_08)
///
/// Address is a 20-byte value in linear memory. `wasm_valtype` returns `I32`
/// (the pointer type). The caller is responsible for allocating 20 bytes via
/// the bump allocator and passing the pointer.
pub(crate) fn wasm_valtype(ty: &ResolvedType) -> Result<ValType, LangError> {
    match ty {
        // Single-word i32 types
        ResolvedType::Bool
        | ResolvedType::U8
        | ResolvedType::U16
        | ResolvedType::U32
        | ResolvedType::I8
        | ResolvedType::I16
        | ResolvedType::I32 => Ok(ValType::I32),

        // Single-word i64 types
        ResolvedType::U64 | ResolvedType::I64 => Ok(ValType::I64),

        // IntLiteral defaults to i32 when unconstrained. The type checker
        // coerces most literals to concrete types by context; when it doesn't,
        // we use i32 (the narrowest WASM native type) for two reasons:
        // (1) checked arithmetic on i32 is strictly tighter than i64 (catches
        //     overflows earlier), and (2) matching the common u32 context avoids
        //     type-stack mismatches with i32-typed function returns.
        // Literal values exceeding i32 range are caught by the range check in
        // emit_literal. For actual i64/u64 arithmetic, the type checker must
        // resolve the literal to a concrete I64/U64 type.
        ResolvedType::IntLiteral => Ok(ValType::I32),

        // u128: i64-pair representation. Each half is I64. The caller uses
        // local_count() to allocate 2 locals per u128 value. Calldata decoding
        // reads 16 LE bytes and splits into (lo, hi) i64 pair.
        ResolvedType::U128 => Ok(ValType::I64),

        // Address: 20-byte value in linear memory, passed as i32 pointer.
        // Calldata decoding copies 20 bytes to bump-alloc memory and pushes ptr.
        // Matches the existing Address constant data segments (P3·Step 6g).
        ResolvedType::AddressTy => Ok(ValType::I32),

        // Multi-word integers — deferred to P3·Step 23
        ResolvedType::U256 | ResolvedType::I128 | ResolvedType::I256 => Err(LangError::Codegen {
            message: format!(
                "multi-word integer type {} not yet supported in codegen (deferred P3·Step 23)",
                ty.display_name()
            ),
        }),

        // Reference/compound types — not yet implemented
        _ => Err(LangError::Codegen {
            message: format!("type {} not yet supported in codegen", ty.display_name()),
        }),
    }
}

/// Number of WASM locals needed to represent a Lem type.
///
/// Most types use 1 local. u128 uses 2 (i64-pair: lo + hi).
/// Used by calldata decoding and function type section generation
/// to allocate the correct number of WASM params/locals.
pub(crate) fn local_count(ty: &ResolvedType) -> usize {
    match ty {
        ResolvedType::U128 => 2, // i64-pair: lo + hi
        _ => 1,
    }
}

/// Returns `true` if the type is u128 (i64-pair representation).
///
/// Used by codegen to select the multi-word arithmetic path.
pub(crate) fn is_u128(ty: &ResolvedType) -> bool {
    matches!(ty, ResolvedType::U128)
}

/// Returns `true` if the type is Address (memory-pointer representation).
///
/// Used by codegen to select the memory-based comparison/storage path.
pub(crate) fn is_address(ty: &ResolvedType) -> bool {
    matches!(ty, ResolvedType::AddressTy)
}

/// Returns `true` if the WASM representation of this type is `i64` (64-bit).
///
/// Used by expression lowering to choose between `i32.xxx` and `i64.xxx`
/// instructions.
pub(crate) fn is_i64(ty: &ResolvedType) -> bool {
    matches!(ty, ResolvedType::U64 | ResolvedType::I64)
}

/// Returns `true` if the type should be treated as signed for comparison/division.
///
/// Signed types use `i32.lt_s` / `i64.lt_s` etc.; unsigned types use `_u` variants.
pub(crate) fn is_signed(ty: &ResolvedType) -> bool {
    matches!(
        ty,
        ResolvedType::I8
            | ResolvedType::I16
            | ResolvedType::I32
            | ResolvedType::I64
            | ResolvedType::I128
            | ResolvedType::I256
    )
}

/// Returns `true` if the type is a sub-word integer (u8, u16, i8, i16).
///
/// Sub-word types are stored in a 32-bit WASM container but have a narrower
/// valid range. Checked arithmetic patterns validate against the container
/// width (32-bit), not the declared Lem type width — so `u8: 200 + 100 = 300`
/// would pass the u32 overflow check but exceed the u8 range.
///
/// Until range-check masking is implemented, arithmetic on sub-word types
/// is honestly deferred with a codegen error (M1 — CR finding).
pub(crate) fn is_sub_word(ty: &ResolvedType) -> bool {
    matches!(
        ty,
        ResolvedType::U8 | ResolvedType::U16 | ResolvedType::I8 | ResolvedType::I16
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
