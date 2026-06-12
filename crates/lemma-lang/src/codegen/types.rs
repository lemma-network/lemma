//! Lem → WASM type mapping for codegen.
//!
//! WASM has only two integer types: `i32` and `i64`. Lem's richer type system
//! (u8..u256, bool, Address, etc.) must be projected onto these two types.
//!
//! ## Current scope (P3·Step 6c)
//!
//! Only types that fit in a single WASM value are supported:
//! - bool, u8, u16, u32, i8, i16, i32 → `ValType::I32`
//! - u64, i64 → `ValType::I64`
//!
//! Multi-word types (u128, u256), reference types (Address, string, bytes),
//! and compound types (Array, Map, etc.) return `Err` — honestly deferred.
//!
//! ## `IntLiteral` handling
//!
//! Unconstrained integer literals (`IntLiteral`) default to `i32` in codegen
//! (conservative — avoids needing u256 multi-word for simple literals like `42`).
//! The type checker should have coerced most `IntLiteral`s to concrete types
//! before codegen; this fallback handles the residual unconstrained case.
//!
//! ## Dead-code allow
//!
//! All functions in this module are consumed by the expression lowering
//! infrastructure (`LowerCtx` in `wasm.rs`) which is currently only exercised
//! by tests (P3·Step 6c). Production wiring (entry-point dispatch → function
//! bodies → expression lowering) lands in P3·Steps 6d/6e.

// All functions are consumed by LowerCtx (wasm.rs) which is test-only in 6c.
// Production wiring lands in 6d/6e. Removing the allow would hide the spec
// behind a compile error until every consumer is built simultaneously.
#![allow(dead_code)]

use wasm_encoder::ValType;

use crate::error::LangError;
use crate::type_checker::types::ResolvedType;

/// Map a Lem [`ResolvedType`] to a WASM [`ValType`].
///
/// Returns `Err(LangError::Codegen)` for types not yet supported in codegen.
///
/// ## Mapping table
///
/// | Lem type | WASM type |
/// |----------|-----------|
/// | bool, u8, u16, u32, i8, i16, i32 | `I32` |
/// | u64, i64 | `I64` |
/// | IntLiteral | `I32` (narrowest native; range-checked at emit) |
/// | u128, u256, i128, i256 | `Err` (multi-word, deferred) |
/// | Address, string, bytes, etc. | `Err` (reference types, deferred) |
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

        // Multi-word integers — not yet implemented
        ResolvedType::U128 | ResolvedType::U256 | ResolvedType::I128 | ResolvedType::I256 => {
            Err(LangError::Codegen {
                message: format!(
                    "multi-word integer type {} not yet supported in codegen",
                    ty.display_name()
                ),
            })
        }

        // Reference/compound types — not yet implemented
        _ => Err(LangError::Codegen {
            message: format!("type {} not yet supported in codegen", ty.display_name()),
        }),
    }
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
