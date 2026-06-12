//! Tests for `codegen::types` — Lem → WASM type mapping.
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.
//! Test naming: `{action}_{outcome}` (AGENTS §11.3).

use wasm_encoder::ValType;

use crate::type_checker::types::ResolvedType;

use super::{is_i64, is_signed, is_sub_word, wasm_valtype};

// ─── wasm_valtype — i32 types ────────────────────────────────────────────────

#[test]
fn wasm_valtype_maps_bool_to_i32() {
    assert_eq!(wasm_valtype(&ResolvedType::Bool).unwrap(), ValType::I32);
}

#[test]
fn wasm_valtype_maps_u8_to_i32() {
    assert_eq!(wasm_valtype(&ResolvedType::U8).unwrap(), ValType::I32);
}

#[test]
fn wasm_valtype_maps_u16_to_i32() {
    assert_eq!(wasm_valtype(&ResolvedType::U16).unwrap(), ValType::I32);
}

#[test]
fn wasm_valtype_maps_u32_to_i32() {
    assert_eq!(wasm_valtype(&ResolvedType::U32).unwrap(), ValType::I32);
}

#[test]
fn wasm_valtype_maps_i8_to_i32() {
    assert_eq!(wasm_valtype(&ResolvedType::I8).unwrap(), ValType::I32);
}

#[test]
fn wasm_valtype_maps_i16_to_i32() {
    assert_eq!(wasm_valtype(&ResolvedType::I16).unwrap(), ValType::I32);
}

#[test]
fn wasm_valtype_maps_i32_to_i32() {
    assert_eq!(wasm_valtype(&ResolvedType::I32).unwrap(), ValType::I32);
}

// ─── wasm_valtype — i64 types ────────────────────────────────────────────────

#[test]
fn wasm_valtype_maps_u64_to_i64() {
    assert_eq!(wasm_valtype(&ResolvedType::U64).unwrap(), ValType::I64);
}

#[test]
fn wasm_valtype_maps_i64_to_i64() {
    assert_eq!(wasm_valtype(&ResolvedType::I64).unwrap(), ValType::I64);
}

#[test]
fn wasm_valtype_maps_int_literal_to_i32() {
    assert_eq!(
        wasm_valtype(&ResolvedType::IntLiteral).unwrap(),
        ValType::I32
    );
}

// ─── wasm_valtype — unsupported types ────────────────────────────────────────

#[test]
fn wasm_valtype_rejects_u128() {
    let result = wasm_valtype(&ResolvedType::U128);
    assert!(result.is_err());
}

#[test]
fn wasm_valtype_rejects_u256() {
    let result = wasm_valtype(&ResolvedType::U256);
    assert!(result.is_err());
}

#[test]
fn wasm_valtype_rejects_i128() {
    let result = wasm_valtype(&ResolvedType::I128);
    assert!(result.is_err());
}

#[test]
fn wasm_valtype_rejects_i256() {
    let result = wasm_valtype(&ResolvedType::I256);
    assert!(result.is_err());
}

#[test]
fn wasm_valtype_rejects_string() {
    let result = wasm_valtype(&ResolvedType::StringTy);
    assert!(result.is_err());
}

#[test]
fn wasm_valtype_rejects_address() {
    let result = wasm_valtype(&ResolvedType::AddressTy);
    assert!(result.is_err());
}

#[test]
fn wasm_valtype_rejects_bytes() {
    let result = wasm_valtype(&ResolvedType::Bytes);
    assert!(result.is_err());
}

// ─── is_i64 ──────────────────────────────────────────────────────────────────

#[test]
fn is_i64_returns_true_for_u64() {
    assert!(is_i64(&ResolvedType::U64));
}

#[test]
fn is_i64_returns_true_for_i64() {
    assert!(is_i64(&ResolvedType::I64));
}

#[test]
fn is_i64_returns_false_for_int_literal() {
    // IntLiteral defaults to i32 (narrowest WASM native) — not i64.
    assert!(!is_i64(&ResolvedType::IntLiteral));
}

#[test]
fn is_i64_returns_false_for_u32() {
    assert!(!is_i64(&ResolvedType::U32));
}

#[test]
fn is_i64_returns_false_for_bool() {
    assert!(!is_i64(&ResolvedType::Bool));
}

// ─── is_signed ───────────────────────────────────────────────────────────────

#[test]
fn is_signed_returns_true_for_i8() {
    assert!(is_signed(&ResolvedType::I8));
}

#[test]
fn is_signed_returns_true_for_i32() {
    assert!(is_signed(&ResolvedType::I32));
}

#[test]
fn is_signed_returns_true_for_i64() {
    assert!(is_signed(&ResolvedType::I64));
}

#[test]
fn is_signed_returns_false_for_u32() {
    assert!(!is_signed(&ResolvedType::U32));
}

#[test]
fn is_signed_returns_false_for_bool() {
    assert!(!is_signed(&ResolvedType::Bool));
}

#[test]
fn is_signed_returns_false_for_int_literal() {
    // IntLiteral is unsigned by default (DB-A27: defaults to u256)
    assert!(!is_signed(&ResolvedType::IntLiteral));
}

// ─── is_sub_word ─────────────────────────────────────────────────────────────

#[test]
fn is_sub_word_returns_true_for_u8() {
    assert!(is_sub_word(&ResolvedType::U8));
}

#[test]
fn is_sub_word_returns_true_for_u16() {
    assert!(is_sub_word(&ResolvedType::U16));
}

#[test]
fn is_sub_word_returns_true_for_i8() {
    assert!(is_sub_word(&ResolvedType::I8));
}

#[test]
fn is_sub_word_returns_true_for_i16() {
    assert!(is_sub_word(&ResolvedType::I16));
}

#[test]
fn is_sub_word_returns_false_for_u32() {
    assert!(!is_sub_word(&ResolvedType::U32));
}

#[test]
fn is_sub_word_returns_false_for_i32() {
    assert!(!is_sub_word(&ResolvedType::I32));
}

#[test]
fn is_sub_word_returns_false_for_u64() {
    assert!(!is_sub_word(&ResolvedType::U64));
}

#[test]
fn is_sub_word_returns_false_for_bool() {
    assert!(!is_sub_word(&ResolvedType::Bool));
}

#[test]
fn is_sub_word_returns_false_for_int_literal() {
    assert!(!is_sub_word(&ResolvedType::IntLiteral));
}
