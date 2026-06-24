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

// ─── wasm_valtype — u128 (i64-pair) ──────────────────────────────────────────

#[test]
fn wasm_valtype_maps_u128_to_i64() {
    // u128 is represented as an i64-pair (lo, hi). Each half is I64.
    assert_eq!(wasm_valtype(&ResolvedType::U128).unwrap(), ValType::I64);
}

// ─── wasm_valtype — Address (i32 pointer) ────────────────────────────────────

#[test]
fn wasm_valtype_maps_address_to_i32() {
    // Address is a 20-byte value in linear memory, passed as i32 pointer.
    assert_eq!(
        wasm_valtype(&ResolvedType::AddressTy).unwrap(),
        ValType::I32
    );
}

// ─── wasm_valtype — unsupported types ────────────────────────────────────────

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
fn wasm_valtype_rejects_bytes() {
    let result = wasm_valtype(&ResolvedType::Bytes);
    assert!(result.is_err());
}

// ─── local_count ─────────────────────────────────────────────────────────────

#[test]
fn local_count_returns_2_for_u128() {
    assert_eq!(super::local_count(&ResolvedType::U128), 2);
}

#[test]
fn local_count_returns_1_for_u64() {
    assert_eq!(super::local_count(&ResolvedType::U64), 1);
}

#[test]
fn local_count_returns_1_for_address() {
    assert_eq!(super::local_count(&ResolvedType::AddressTy), 1);
}

#[test]
fn local_count_returns_1_for_i32() {
    assert_eq!(super::local_count(&ResolvedType::I32), 1);
}

// ─── is_u128 ─────────────────────────────────────────────────────────────────

#[test]
fn is_u128_returns_true_for_u128() {
    assert!(super::is_u128(&ResolvedType::U128));
}

#[test]
fn is_u128_returns_false_for_u64() {
    assert!(!super::is_u128(&ResolvedType::U64));
}

// ─── is_address ──────────────────────────────────────────────────────────────

#[test]
fn is_address_returns_true_for_address() {
    assert!(super::is_address(&ResolvedType::AddressTy));
}

#[test]
fn is_address_returns_false_for_u32() {
    assert!(!super::is_address(&ResolvedType::U32));
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
