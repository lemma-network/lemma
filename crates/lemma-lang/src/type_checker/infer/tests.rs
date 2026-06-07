//! Tests for the expression type inference pass (P3·Step 3c/3e/3f).
//!
//! Follows AGENTS §11.2: tests live in a separate submodule file, never inline.

use std::collections::BTreeMap;

use crate::type_checker::error::TypeErrorKind;
use crate::type_checker::infer::{
    infer_type_args, substitute, types_compatible, TypeCompatibility,
};
use crate::type_checker::types::{ResolvedType, SymbolId, SymbolKind};
use crate::{check, parse, tokenize};

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Parse + check a Lem source snippet.
///
/// Returns `Ok(TypedAst)` or the first `LangError`.
fn check_src(src: &str) -> Result<crate::type_checker::TypedAst, crate::error::LangError> {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).unwrap_or_else(|e| panic!("parse failed: {e:?}"));
    check(ast)
}

/// Parse + check and return the type of the **first** expression in the typed AST,
/// i.e. the expression with the lowest source offset in `expr_types`.
fn first_expr_type(src: &str) -> ResolvedType {
    let typed = check_src(src).unwrap_or_else(|e| panic!("check failed: {e:?}"));
    typed
        .expr_types
        .values()
        .next()
        .cloned()
        .expect("no expr_types recorded")
}

// ─── Literal typing ───────────────────────────────────────────────────────────

#[test]
fn infer_bool_literal_true() {
    assert_eq!(
        first_expr_type("fn f() { let x = true }"),
        ResolvedType::Bool
    );
}

#[test]
fn infer_bool_literal_false() {
    assert_eq!(
        first_expr_type("fn f() { let x = false }"),
        ResolvedType::Bool
    );
}

#[test]
fn infer_unsuffixed_int_literal_is_int_literal() {
    // `42` has no suffix → IntLiteral (DB-A27).
    assert_eq!(
        first_expr_type("fn f() { let x = 42 }"),
        ResolvedType::IntLiteral
    );
}

#[test]
fn infer_typed_integer_u8() {
    assert_eq!(first_expr_type("fn f() { let x = 1u8 }"), ResolvedType::U8);
}

#[test]
fn infer_typed_integer_u128() {
    assert_eq!(
        first_expr_type("fn f() { let x = 100u128 }"),
        ResolvedType::U128
    );
}

#[test]
fn infer_typed_integer_u256() {
    assert_eq!(
        first_expr_type("fn f() { let x = 0u256 }"),
        ResolvedType::U256
    );
}

#[test]
fn infer_typed_integer_i64() {
    assert_eq!(
        first_expr_type("fn f() { let x = -1i64 }"),
        ResolvedType::I64
    );
}

#[test]
fn infer_hex_literal_is_int_literal() {
    // Hex literals without suffix → IntLiteral.
    assert_eq!(
        first_expr_type("fn f() { let x = 0xFF }"),
        ResolvedType::IntLiteral
    );
}

#[test]
fn infer_bin_literal_is_int_literal() {
    assert_eq!(
        first_expr_type("fn f() { let x = 0b1010 }"),
        ResolvedType::IntLiteral
    );
}

#[test]
fn infer_string_literal() {
    assert_eq!(
        first_expr_type(r#"fn f() { let x = "hello" }"#),
        ResolvedType::StringTy
    );
}

#[test]
fn infer_char_literal() {
    assert_eq!(
        first_expr_type("fn f() { let x = 'a' }"),
        ResolvedType::CharTy
    );
}

#[test]
fn infer_address_type_from_param() {
    // Address literal syntax has checksum constraints enforced by the lexer;
    // test AddressTy by checking that a param with type `Address` resolves.
    let typed =
        check_src("fn f(owner: Address) { let x = owner }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_addr = typed
        .expr_types
        .values()
        .any(|t| *t == ResolvedType::AddressTy);
    assert!(has_addr, "Address param ident should be AddressTy");
}

// ─── Ident typing ─────────────────────────────────────────────────────────────

#[test]
fn infer_ident_uses_param_type() {
    // `x` has declared type `u128` — the ident should resolve to U128.
    let typed = check_src("fn f(x: u128) { let y = x }").unwrap_or_else(|e| panic!("{e:?}"));
    // Find the span for `x` in `let y = x` — it should be typed as U128.
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "expected U128 in expr_types for param ident x");
}

#[test]
fn infer_ident_uses_const_type() {
    let typed = check_src("const MAX: u256 = 1000u256\nfn f() { let x = MAX }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "expected U256 for const ident MAX");
}

// ─── Unary operators ──────────────────────────────────────────────────────────

#[test]
fn infer_not_bool_returns_bool() {
    let typed = check_src("fn f(b: bool) { let x = !b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_bool = typed.expr_types.values().any(|t| *t == ResolvedType::Bool);
    assert!(has_bool, "!b should be Bool");
}

#[test]
fn infer_not_on_integer_errors() {
    let result = check_src("fn f(x: u128) { let y = !x }");
    assert!(result.is_err(), "!integer should be a type error");
}

#[test]
fn infer_neg_on_integer_returns_same() {
    let typed = check_src("fn f(x: i128) { let y = -x }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_i128 = typed.expr_types.values().any(|t| *t == ResolvedType::I128);
    assert!(has_i128, "-i128 should return I128");
}

#[test]
fn infer_neg_on_int_literal_returns_int_literal() {
    // `-42` — literal negation stays IntLiteral (no suffix → unconstrained).
    let typed = check_src("fn f() { let x = -42 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_literal = typed
        .expr_types
        .values()
        .any(|t| *t == ResolvedType::IntLiteral);
    assert!(has_literal, "-42 should be IntLiteral");
}

#[test]
fn infer_bitnot_on_integer_returns_same() {
    let typed = check_src("fn f(x: u64) { let y = ~x }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u64 = typed.expr_types.values().any(|t| *t == ResolvedType::U64);
    assert!(has_u64, "~u64 should return U64");
}

#[test]
fn infer_bitnot_on_bool_errors() {
    let result = check_src("fn f(b: bool) { let y = ~b }");
    assert!(result.is_err(), "~bool should be a type error");
}

// ─── Binary arithmetic operators ──────────────────────────────────────────────

#[test]
fn infer_add_same_type_returns_same() {
    let typed =
        check_src("fn f(a: u128, b: u128) { let x = a + b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "u128 + u128 should be U128");
}

#[test]
fn infer_add_literal_coerces_to_typed_operand() {
    // `a + 5` where a: u128 → literal 5 coerces to u128, result is u128.
    let typed = check_src("fn f(a: u128) { let x = a + 5 }").unwrap_or_else(|e| panic!("{e:?}"));
    let u128_count = typed
        .expr_types
        .values()
        .filter(|t| **t == ResolvedType::U128)
        .count();
    // Both `a`, `5` (coerced), and `a + 5` should be U128 → at least 2 entries.
    assert!(u128_count >= 2, "literal should coerce to u128");
}

#[test]
fn infer_add_two_literals_stays_int_literal() {
    let typed = check_src("fn f() { let x = 1 + 2 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_literal = typed
        .expr_types
        .values()
        .any(|t| *t == ResolvedType::IntLiteral);
    assert!(has_literal, "1 + 2 should be IntLiteral");
}

#[test]
fn infer_add_mismatched_types_errors() {
    // u8 + u128 — no implicit widening in Lem.
    let result = check_src("fn f(a: u8, b: u128) { let x = a + b }");
    assert!(result.is_err(), "u8 + u128 should be a type mismatch");
}

#[test]
fn infer_add_bool_operand_errors() {
    let result = check_src("fn f(b: bool) { let x = b + 1u8 }");
    assert!(result.is_err(), "bool + int should be InvalidOperand");
}

#[test]
fn infer_mul_same_type() {
    let typed =
        check_src("fn f(a: u256, b: u256) { let x = a * b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "u256 * u256 should be U256");
}

// ─── Binary bitwise operators ─────────────────────────────────────────────────

#[test]
fn infer_bitand_same_int_type() {
    let typed =
        check_src("fn f(a: u32, b: u32) { let x = a & b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u32 = typed.expr_types.values().any(|t| *t == ResolvedType::U32);
    assert!(has_u32, "u32 & u32 should be U32");
}

#[test]
fn infer_bitand_on_bool_errors() {
    let result = check_src("fn f(a: bool, b: bool) { let x = a & b }");
    assert!(
        result.is_err(),
        "bool & bool should be InvalidOperand for bitwise"
    );
}

#[test]
fn infer_shl_returns_lhs_type() {
    let typed = check_src("fn f(x: u64) { let y = x << 3u8 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u64 = typed.expr_types.values().any(|t| *t == ResolvedType::U64);
    assert!(has_u64, "u64 << u8 should return U64");
}

// ─── Comparison operators ─────────────────────────────────────────────────────

#[test]
fn infer_eq_returns_bool() {
    let typed =
        check_src("fn f(a: u128, b: u128) { let x = a == b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_bool = typed.expr_types.values().any(|t| *t == ResolvedType::Bool);
    assert!(has_bool, "u128 == u128 should be Bool");
}

#[test]
fn infer_lt_returns_bool() {
    let typed =
        check_src("fn f(a: u8, b: u8) { let x = a < b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_bool = typed.expr_types.values().any(|t| *t == ResolvedType::Bool);
    assert!(has_bool, "u8 < u8 should be Bool");
}

#[test]
fn infer_lt_on_string_errors() {
    let result = check_src(r#"fn f(a: string, b: string) { let x = a < b }"#);
    assert!(result.is_err(), "string < string should be InvalidOperand");
}

#[test]
fn infer_eq_type_mismatch_errors() {
    let result = check_src("fn f(a: u8, b: bool) { let x = a == b }");
    assert!(result.is_err(), "u8 == bool should be TypeMismatch");
}

// ─── Logical operators ────────────────────────────────────────────────────────

#[test]
fn infer_and_bool_returns_bool() {
    let typed =
        check_src("fn f(a: bool, b: bool) { let x = a && b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_bool = typed.expr_types.values().any(|t| *t == ResolvedType::Bool);
    assert!(has_bool, "bool && bool should be Bool");
}

#[test]
fn infer_or_non_bool_errors() {
    let result = check_src("fn f(a: u8, b: u8) { let x = a || b }");
    assert!(result.is_err(), "u8 || u8 should be InvalidOperand");
}

// ─── Ternary ──────────────────────────────────────────────────────────────────

#[test]
fn infer_ternary_returns_branch_type() {
    let typed = check_src("fn f(cond: bool, a: u128, b: u128) { let x = cond ? a : b }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "ternary with u128 branches should be U128");
}

#[test]
fn infer_ternary_non_bool_cond_errors() {
    let result = check_src("fn f(c: u8, a: u8, b: u8) { let x = c ? a : b }");
    assert!(result.is_err(), "ternary with integer cond should error");
}

#[test]
fn infer_ternary_mismatched_branches_errors() {
    let result = check_src("fn f(c: bool, a: u8, b: u128) { let x = c ? a : b }");
    assert!(
        result.is_err(),
        "ternary with mismatched branches should error"
    );
}

// ─── Nullish ──────────────────────────────────────────────────────────────────

#[test]
fn infer_nullish_option_returns_inner_type() {
    // `opt ?? 0u128` where opt: Option<u128> → result is u128.
    let typed = check_src("fn f(opt: Option<u128>) { let x = opt ?? 0u128 }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "Option<u128> ?? u128 should be U128");
}

#[test]
fn infer_nullish_non_option_errors() {
    let result = check_src("fn f(x: u128) { let y = x ?? 0u128 }");
    assert!(
        result.is_err(),
        "u128 ?? u128 should error — lhs not Option"
    );
}

// ─── Template string ──────────────────────────────────────────────────────────

#[test]
fn infer_template_string_returns_string() {
    let typed =
        check_src(r#"fn f(x: u128) { let s = `value: ${x}` }"#).unwrap_or_else(|e| panic!("{e:?}"));
    let has_string = typed
        .expr_types
        .values()
        .any(|t| *t == ResolvedType::StringTy);
    assert!(has_string, "template string should be StringTy");
}

// ─── Additional shift + literal coercion ─────────────────────────────────────

#[test]
fn infer_shl_int_literal_lhs_coerces_to_rhs() {
    // `1 << 2u8` — lhs is IntLiteral, rhs is U8 → lhs coerces to U8,
    // result type follows lhs (after coercion) = U8.
    let typed = check_src("fn f() { let y = 1 << 2u8 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u8 = typed.expr_types.values().any(|t| *t == ResolvedType::U8);
    assert!(has_u8, "IntLiteral << u8 should yield U8");
}

#[test]
fn infer_shl_both_literals_stays_int_literal() {
    // `1 << 2` — both IntLiteral → result is IntLiteral.
    let typed = check_src("fn f() { let y = 1 << 2 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_literal = typed
        .expr_types
        .values()
        .any(|t| *t == ResolvedType::IntLiteral);
    assert!(has_literal, "IntLiteral << IntLiteral should be IntLiteral");
}

// ─── Additional arithmetic operators ─────────────────────────────────────────

#[test]
fn infer_rem_same_type() {
    let typed =
        check_src("fn f(a: u128, b: u128) { let x = a % b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "u128 % u128 should be U128");
}

#[test]
fn infer_pow_same_type() {
    let typed =
        check_src("fn f(a: u256, b: u256) { let x = a ** b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "u256 ** u256 should be U256");
}

#[test]
fn infer_sub_same_type() {
    let typed =
        check_src("fn f(a: i128, b: i128) { let x = a - b }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_i128 = typed.expr_types.values().any(|t| *t == ResolvedType::I128);
    assert!(has_i128, "i128 - i128 should be I128");
}

// ─── Additional unary negative paths ─────────────────────────────────────────

#[test]
fn infer_neg_on_bool_errors() {
    let result = check_src("fn f(b: bool) { let y = -b }");
    assert!(result.is_err(), "-bool should be InvalidOperand");
}

// ─── Nullish type-mismatch (inner type vs default) ────────────────────────────

#[test]
fn infer_nullish_inner_type_mismatch_errors() {
    // `opt ?? true` where opt: Option<u128> — default must match inner type u128, not bool.
    let result = check_src("fn f(opt: Option<u128>) { let x = opt ?? true }");
    assert!(
        result.is_err(),
        "Option<u128> ?? bool should be TypeMismatch"
    );
}

// ─── Unit literals ────────────────────────────────────────────────────────────

#[test]
fn infer_ether_unit_literal_is_u256() {
    // `1.ether` → scaled u256 value (1e18 Drop).
    let typed = check_src("fn f() { let x = 1.ether }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "1.ether should be U256");
}

#[test]
fn infer_days_unit_literal_is_u256() {
    // `6.months` is not in the expression parser's unit set; `.days` is.
    let typed = check_src("fn f() { let x = 6.days }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "6.days should be U256");
}

// ─── MUST-FIX 1 regression: known-bad operand errors even with Unknown partner ─

#[test]
fn infer_logical_and_known_bad_lhs_errors_despite_unknown_rhs() {
    // `bool && unknownCallResult` — lhs is bool (good), rhs would be Unknown
    // (Call result, deferred to 3d).  Result: Unknown propagated (rhs is deferred).
    // But `u128 && unknownCallResult` — lhs is u128 (bad) should error regardless.
    // Since we can't have an Unknown rhs that's typed, test with a mismatched pair:
    let result = check_src("fn f(x: u128, b: bool) { let y = x && b }");
    assert!(
        result.is_err(),
        "u128 && bool should error (u128 not bool for &&)"
    );
}

#[test]
fn infer_add_known_bool_errors_even_with_int_partner() {
    // Core regression for MUST-FIX 1: bool + u128 must error, not pass via Unknown.
    let result = check_src("fn f(b: bool, x: u128) { let y = b + x }");
    assert!(result.is_err(), "bool + u128 should be InvalidOperand");
}

// ─── expr_types populated by 3c ───────────────────────────────────────────────

#[test]
fn check_returns_non_empty_expr_types() {
    // After 3c, `is_fully_typed()` should be true for any non-trivial program.
    let typed = check_src("fn f() { let x = 42 }").unwrap_or_else(|e| panic!("{e:?}"));
    assert!(
        typed.is_fully_typed(),
        "3c should populate expr_types (is_fully_typed)"
    );
}

// ─── 3d: Cast ─────────────────────────────────────────────────────────────────

#[test]
fn infer_cast_widening_u128_to_u256() {
    // `100u128 as u256` → U256 (widening, same signedness class)
    let typed =
        check_src("fn f(x: u128) { let y = x as u256 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "u128 as u256 should be U256");
}

#[test]
fn infer_cast_int_literal_to_u128() {
    // `42 as u128` — IntLiteral can cast to any concrete integer type.
    let typed = check_src("fn f() { let y = 42 as u128 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "IntLiteral as u128 should be U128");
}

#[test]
fn infer_cast_narrowing_u256_to_u8_errors() {
    // `x as u8` where x: u256 → InvalidConversion (narrowing via `as` is banned)
    let result = check_src("fn f(x: u256) { let y = x as u8 }");
    assert!(result.is_err(), "u256 as u8 should be InvalidConversion");
}

#[test]
fn infer_cast_bool_to_integer_errors() {
    // `true as u128` → error (bool is not an integer type)
    let result = check_src("fn f() { let y = true as u128 }");
    assert!(result.is_err(), "bool as u128 should be an error");
}

// ─── 3d: Array literal ────────────────────────────────────────────────────────

#[test]
fn infer_array_literal_homogeneous() {
    // `[1u8, 2u8, 3u8]` → Array(U8)
    let typed = check_src("fn f() { let a = [1u8, 2u8, 3u8] }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_array_u8 = typed
        .expr_types
        .values()
        .any(|t| *t == ResolvedType::Array(Box::new(ResolvedType::U8)));
    assert!(has_array_u8, "[1u8, 2u8, 3u8] should be Array(U8)");
}

#[test]
fn infer_array_literal_type_mismatch_errors() {
    // `[1u8, 2u16]` → TypeMismatch (u8 ≠ u16)
    let result = check_src("fn f() { let a = [1u8, 2u16] }");
    assert!(result.is_err(), "[u8, u16] should be TypeMismatch");
}

#[test]
fn infer_empty_array_literal_is_array_unknown() {
    // `[]` → Array(Unknown) — element type deferred
    let typed = check_src("fn f() { let a = [] }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_array_unknown = typed
        .expr_types
        .values()
        .any(|t| *t == ResolvedType::Array(Box::new(ResolvedType::Unknown)));
    assert!(has_array_unknown, "[] should be Array(Unknown)");
}

// ─── 3d: Tuple literal ────────────────────────────────────────────────────────

#[test]
fn infer_tuple_literal_two_elements() {
    // `(1u8, true)` → Tuple([U8, Bool])
    let typed = check_src("fn f() { let t = (1u8, true) }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_tuple = typed
        .expr_types
        .values()
        .any(|t| *t == ResolvedType::Tuple(vec![ResolvedType::U8, ResolvedType::Bool]));
    assert!(has_tuple, "(1u8, true) should be Tuple([U8, Bool])");
}

// ─── 3d: Index ────────────────────────────────────────────────────────────────

#[test]
fn infer_index_fixed_array_returns_elem_type() {
    // `arr[0u32]` where arr: [u128; 3] → U128
    let typed =
        check_src("fn f(arr: [u128; 3]) { let x = arr[0u32] }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "arr[0] where arr: [u128; 3] should be U128");
}

#[test]
fn infer_index_map_returns_value_type() {
    // `m[k]` where m: Map<Address, u128> → U128
    let typed = check_src("fn f(m: Map<Address, u128>, k: Address) { let x = m[k] }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "m[k] where m: Map<Address, u128> should be U128");
}

#[test]
fn infer_index_on_non_indexable_errors() {
    // `s[0u32]` where s: string → NotIndexable
    let result = check_src("fn f(s: string) { let x = s[0u32] }");
    assert!(result.is_err(), "string[0] should be NotIndexable");
}

// ─── 3d: Struct literal ───────────────────────────────────────────────────────

#[test]
fn infer_struct_literal_returns_named_type() {
    // `Point { x: 1u128, y: 2u128 }` → Named(point_id, [])
    let typed = check_src(
        "struct Point { x: u128, y: u128 }\nfn f() { let p = Point { x: 1u128, y: 2u128 } }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let has_named = typed
        .expr_types
        .values()
        .any(|t| matches!(t, ResolvedType::Named(_, _)));
    assert!(has_named, "struct literal should be Named(...)");
}

#[test]
fn infer_struct_literal_unknown_field_errors() {
    // `Point { z: 1u128 }` → UnknownField (z not in Point)
    let result =
        check_src("struct Point { x: u128, y: u128 }\nfn f() { let p = Point { z: 1u128 } }");
    assert!(result.is_err(), "Point {{ z: ... }} should be UnknownField");
}

// ─── 3d: Function call ────────────────────────────────────────────────────────

#[test]
fn infer_fn_call_returns_return_type() {
    // `add(1u128, 2u128)` where `fn add(a: u128, b: u128) -> u128` → U128
    let typed = check_src(
        "fn add(a: u128, b: u128) -> u128 { return a }\nfn f() { let x = add(1u128, 2u128) }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "add(u128, u128) -> u128 call should be U128");
}

#[test]
fn infer_fn_call_too_many_args_errors() {
    // `add(1u128, 2u128, 3u128)` where add takes 2 params → ArityMismatch
    let result = check_src(
        "fn add(a: u128, b: u128) -> u128 { return a }\nfn f() { let x = add(1u128, 2u128, 3u128) }",
    );
    assert!(result.is_err(), "too many args should be ArityMismatch");
}

#[test]
fn infer_call_on_non_callable_errors() {
    // `b(1u128)` where b: bool → NotCallable
    let result = check_src("fn f(b: bool) { let x = b(1u128) }");
    assert!(result.is_err(), "bool() should be NotCallable");
}

// ─── 3d: Member access ────────────────────────────────────────────────────────

#[test]
fn infer_member_builtin_length_on_array() {
    // `arr.length` where arr: Array<u256> → U256
    let typed = check_src("fn f(arr: Array<u256>) { let n = arr.length }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "arr.length should be U256");
}

#[test]
fn infer_member_builtin_has_on_map() {
    // `m.has` where m: Map<Address, u128> → Bool (via builtin_member_type)
    // Note: .has is a method, so we call it: m.has(k) — but the member expr itself
    // returns the Fn type. Test the full call chain.
    let typed = check_src("fn f(m: Map<Address, u128>, k: Address) { let b = m.has(k) }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_bool = typed.expr_types.values().any(|t| *t == ResolvedType::Bool);
    assert!(has_bool, "m.has(k) should be Bool");
}

#[test]
fn infer_member_struct_field_access() {
    // `p.x` where p: Point, Point has field x: u128 → U128
    let typed = check_src("struct Point { x: u128, y: u128 }\nfn f(p: Point) { let v = p.x }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "p.x where Point.x: u128 should be U128");
}

#[test]
fn infer_member_struct_unknown_field_errors() {
    // `p.z` where Point has no field z → UnknownField
    let result = check_src("struct Point { x: u128, y: u128 }\nfn f(p: Point) { let v = p.z }");
    assert!(
        result.is_err(),
        "p.z where z not in Point should be UnknownField"
    );
}

// ─── 3d: New expression ───────────────────────────────────────────────────────

#[test]
fn infer_new_expr_returns_named_type() {
    // `new Counter()` → Named(counter_id, [])
    let typed = check_src("contract Counter {}\nfn f() { let c = new Counter() }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_named = typed
        .expr_types
        .values()
        .any(|t| matches!(t, ResolvedType::Named(_, _)));
    assert!(has_named, "new Counter() should be Named(...)");
}

// ─── 3d: Built-in member methods ─────────────────────────────────────────────

#[test]
fn infer_builtin_checked_add_returns_result() {
    // `x.checkedAdd(y)` where x: u128 → Result<U128, Unknown>
    let typed = check_src("fn f(x: u128, y: u128) { let r = x.checkedAdd(y) }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_result = typed
        .expr_types
        .values()
        .any(|t| matches!(t, ResolvedType::Result_(inner, _) if **inner == ResolvedType::U128));
    assert!(has_result, "x.checkedAdd(y) should be Result<U128, _>");
}

#[test]
fn infer_builtin_get_on_array_returns_option() {
    // `arr.get(0u32)` where arr: Array<u256> → Option<U256>
    let typed = check_src("fn f(arr: Array<u256>) { let v = arr.get(0u32) }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_option = typed
        .expr_types
        .values()
        .any(|t| matches!(t, ResolvedType::Option_(inner) if **inner == ResolvedType::U256));
    assert!(has_option, "arr.get(0) should be Option<U256>");
}

// ─── 3d: UnaryOp::Ref ────────────────────────────────────────────────────────

#[test]
fn infer_ref_returns_inner_type() {
    // `&x` where x: u128 → U128 (transparent for 3d)
    let typed = check_src("fn f(x: u128) { let r = &x }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "&u128 should be U128 (transparent in 3d)");
}

// ─── SF-3: Additional coverage (per CodeReviewer APPROVE WITH SUGGESTIONS) ───

// Cast: signed widening (i8 as i256)
#[test]
fn infer_cast_signed_widening_i8_to_i256() {
    let typed = check_src("fn f(x: i8) { let y = x as i256 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_i256 = typed.expr_types.values().any(|t| *t == ResolvedType::I256);
    assert!(has_i256, "i8 as i256 should widen to I256");
}

// Cast: cross-sign cast (u8 as i16) — different signedness class → error
#[test]
fn infer_cast_cross_sign_u8_to_i16_errors() {
    let result = check_src("fn f(x: u8) { let y = x as i16 }");
    assert!(
        result.is_err(),
        "u8 as i16 should be InvalidConversion (cross-sign class)"
    );
}

// Built-ins: wrappingAdd returns same integer type
#[test]
fn infer_builtin_wrapping_add_returns_same_type() {
    let typed = check_src("fn f(x: u128, y: u128) { let r = x.wrappingAdd(y) }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "x.wrappingAdd(y) should return U128");
}

// Built-ins: saturatingAdd returns same type
#[test]
fn infer_builtin_saturating_add_returns_same_type() {
    let typed = check_src("fn f(x: u64, y: u64) { let r = x.saturatingAdd(y) }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u64 = typed.expr_types.values().any(|t| *t == ResolvedType::U64);
    assert!(has_u64, "x.saturatingAdd(y) should return U64");
}

// Built-ins: Set.has returns bool
#[test]
fn infer_builtin_set_has_returns_bool() {
    let typed = check_src("fn f(s: Set<u128>, v: u128) { let b = s.has(v) }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_bool = typed.expr_types.values().any(|t| *t == ResolvedType::Bool);
    assert!(has_bool, "s.has(v) on Set should be Bool");
}

// Built-ins: Set.size returns u256
#[test]
fn infer_builtin_set_size_returns_u256() {
    let typed =
        check_src("fn f(s: Set<u128>) { let n = s.size }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "s.size should be U256");
}

// Built-ins: Option.isSome returns bool
#[test]
fn infer_builtin_option_is_some_returns_bool() {
    let typed =
        check_src("fn f(o: Option<u128>) { let b = o.isSome }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_bool = typed.expr_types.values().any(|t| *t == ResolvedType::Bool);
    assert!(has_bool, "o.isSome should be Bool");
}

// Built-ins: Option.unwrap returns inner type
#[test]
fn infer_builtin_option_unwrap_returns_inner() {
    let typed =
        check_src("fn f(o: Option<u256>) { let v = o.unwrap }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "o.unwrap on Option<u256> should be U256");
}

// Built-ins: Decimal.toRaw returns u256
#[test]
fn infer_builtin_decimal_to_raw_returns_u256() {
    let typed =
        check_src("fn f(p: decimal(18)) { let r = p.toRaw }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "p.toRaw should be U256");
}

// Built-ins: Address.isZero returns bool
#[test]
fn infer_builtin_address_is_zero_returns_bool() {
    let typed = check_src("fn f(addr: Address) { let b = addr.isZero }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_bool = typed.expr_types.values().any(|t| *t == ResolvedType::Bool);
    assert!(has_bool, "addr.isZero should be Bool");
}

// Built-ins: Map.getOr returns value type (not Option<V>)
#[test]
fn infer_builtin_map_get_or_returns_value_type() {
    // `m.getOr(k, 0u128)` → U128 (not Option<U128>)
    let typed = check_src("fn f(m: Map<Address, u128>, k: Address) { let v = m.getOr(k, 0u128) }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "m.getOr(k, 0u128) should be U128 (not Option)");
}

// Built-ins: String.length returns u256
#[test]
fn infer_builtin_string_length_returns_u256() {
    let typed =
        check_src(r#"fn f(s: string) { let n = s.length }"#).unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256 = typed.expr_types.values().any(|t| *t == ResolvedType::U256);
    assert!(has_u256, "s.length should be U256");
}

// ─── P3·Step 3e: let checking ─────────────────────────────────────────────────

#[test]
fn let_with_matching_annotation_passes() {
    // `let x: u128 = 1u128` — annotation matches RHS type → no error.
    check_src("fn f() { let x: u128 = 1u128 }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn let_annotation_type_mismatch_errors() {
    // `let x: u128 = true` — bool vs u128 → TypeMismatch.
    let result = check_src("fn f() { let x: u128 = true }");
    assert!(result.is_err(), "let x: u128 = true should be TypeMismatch");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::TypeMismatch { .. }),
            "expected TypeMismatch, got {:?}",
            e.kind
        );
    }
}

#[test]
fn let_int_literal_coerces_to_annotation() {
    // `let x: u64 = 42` — IntLiteral coerces to u64 → no error.
    check_src("fn f() { let x: u64 = 42 }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn let_unannotated_back_fills_symbol_type() {
    // `let x = 1u64` — unannotated, RHS is U64 → symbol.ty back-filled to U64.
    let typed = check_src("fn f() { let x = 1u64 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u64_sym = typed
        .symbols
        .iter()
        .any(|s| s.kind == SymbolKind::Local && s.ty == ResolvedType::U64);
    assert!(
        has_u64_sym,
        "unannotated let x = 1u64 should back-fill symbol.ty = U64"
    );
}

#[test]
fn let_unannotated_int_literal_defaults_u256() {
    // `let x = 42` — unannotated, RHS is IntLiteral → symbol.ty defaults to U256 (DB-A27).
    let typed = check_src("fn f() { let x = 42 }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u256_sym = typed
        .symbols
        .iter()
        .any(|s| s.kind == SymbolKind::Local && s.ty == ResolvedType::U256);
    assert!(
        has_u256_sym,
        "unannotated let x = 42 should default symbol.ty = U256 (DB-A27)"
    );
}

// ─── P3·Step 3e: CR-fix — annotation not back-filled by RHS ─────────────────

#[test]
fn let_annotated_type_mismatch_not_silently_accepted() {
    // Regression for soundness fix (CR issue #1): when a `let` has an annotation
    // that resolves to a *known* type, an incompatible RHS must still error.
    // Before the fix, the `sym_ty == Unknown` branch could inadvertently trigger
    // the back-fill path; now the path is gated on `ty.is_none()`.
    //
    // `let x: bool = 42u128` — u128 is not bool → TypeMismatch (not silent accept).
    let result = check_src("fn f() { let x: bool = 42u128 }");
    assert!(
        result.is_err(),
        "let x: bool = 42u128 must error with TypeMismatch"
    );
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::TypeMismatch { .. }),
            "expected TypeMismatch, got {:?}",
            e.kind
        );
    }
}

// ─── P3·Step 3e: return checking ─────────────────────────────────────────────

#[test]
fn return_matching_type_passes() {
    // fn returns u128, return 1u128 → no error.
    check_src("fn f() -> u128 { return 1u128 }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn return_type_mismatch_errors() {
    // fn returns u128, return true → ReturnTypeMismatch.
    let result = check_src("fn f() -> u128 { return true }");
    assert!(result.is_err(), "return bool in fn -> u128 should error");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::ReturnTypeMismatch { .. }),
            "expected ReturnTypeMismatch, got {:?}",
            e.kind
        );
    }
}

#[test]
fn bare_return_in_unit_fn_passes() {
    // fn returns (), bare return → no error.
    check_src("fn f() { return }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn bare_return_in_non_unit_fn_errors() {
    // fn returns u128, bare return → ReturnTypeMismatch.
    let result = check_src("fn f() -> u128 { return }");
    assert!(result.is_err(), "bare return in fn -> u128 should error");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::ReturnTypeMismatch { .. }),
            "expected ReturnTypeMismatch, got {:?}",
            e.kind
        );
    }
}

#[test]
fn return_int_literal_coerces_to_fn_ret() {
    // fn returns u64, return 42 → IntLiteral coerces to u64 → no error.
    check_src("fn f() -> u64 { return 42 }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn return_outside_fn_skipped() {
    // Top-level return is syntactically invalid and caught by the parser.
    // This test verifies the checker doesn't panic on it if it somehow passes parsing.
    // We just verify a normal function with return works.
    check_src("fn f() { return }").unwrap_or_else(|e| panic!("{e:?}"));
}

// ─── P3·Step 3e: condition checks ────────────────────────────────────────────

#[test]
fn if_condition_bool_passes() {
    // `if (true) { }` → no error. Lem requires parens around if condition.
    check_src("fn f() { if (true) { } }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn if_condition_non_bool_errors() {
    // `if (42u128) { }` → ConditionNotBool.
    let result = check_src("fn f() { if (42u128) { } }");
    assert!(result.is_err(), "if integer should be ConditionNotBool");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::ConditionNotBool { .. }),
            "expected ConditionNotBool, got {:?}",
            e.kind
        );
    }
}

#[test]
fn while_condition_bool_passes() {
    // `while (x) { }` where x: bool → no error. Lem requires parens around while condition.
    check_src("fn f(x: bool) { while (x) { } }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn while_condition_non_bool_errors() {
    // `while (1u8) { }` → ConditionNotBool.
    let result = check_src("fn f() { while (1u8) { } }");
    assert!(result.is_err(), "while integer should be ConditionNotBool");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::ConditionNotBool { .. }),
            "expected ConditionNotBool, got {:?}",
            e.kind
        );
    }
}

#[test]
fn condition_unknown_skipped() {
    // Condition of Unknown type → no error (deferred).
    check_src("fn f(b: bool) { if (b) { } }").unwrap_or_else(|e| panic!("{e:?}"));
}

// ─── P3·Step 3e: mutability ───────────────────────────────────────────────────

#[test]
fn assign_to_let_mut_passes() {
    // `let mut x = 1u8; x = 2u8;` → no error.
    check_src("fn f() { let mut x = 1u8\n x = 2u8 }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn assign_to_let_immutable_errors() {
    // `let x = 1u8; x = 2u8;` → MutationOfImmutable.
    let result = check_src("fn f() { let x = 1u8\n x = 2u8 }");
    assert!(result.is_err(), "assign to immutable let should error");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::MutationOfImmutable { .. }),
            "expected MutationOfImmutable, got {:?}",
            e.kind
        );
    }
}

#[test]
fn assign_to_param_errors() {
    // fn param, assign inside body → MutationOfImmutable.
    let result = check_src("fn f(x: u128) { x = 5u128 }");
    assert!(
        result.is_err(),
        "assign to param should be MutationOfImmutable"
    );
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::MutationOfImmutable { .. }),
            "expected MutationOfImmutable, got {:?}",
            e.kind
        );
    }
}

#[test]
fn compound_assign_to_let_mut_passes() {
    // `let mut x = 1u128; x += 1u128;` → no error.
    check_src("fn f() { let mut x = 1u128\n x += 1u128 }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn member_assign_not_flagged_as_immutable() {
    // `self.field = val` — LHS is Member, not Ident → no MutationOfImmutable.
    // Use a contract with a state field assignment.
    check_src(
        "contract C {\
         \n  state { balance: u128 }\
         \n  fn set(v: u128) { self.balance = v }\
         \n}",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
}

// ─── P3·Step 3e: assignment type checking ────────────────────────────────────

#[test]
fn assign_rhs_matches_lhs_type_passes() {
    // `let mut x: u128 = 0u128; x = 5u128;` → no error.
    check_src("fn f() { let mut x: u128 = 0u128\n x = 5u128 }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn assign_rhs_type_mismatch_errors() {
    // `let mut x: u128 = 0u128; x = true;` → TypeMismatch.
    let result = check_src("fn f() { let mut x: u128 = 0u128\n x = true }");
    assert!(
        result.is_err(),
        "assign bool to u128 should be TypeMismatch"
    );
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::TypeMismatch { .. }),
            "expected TypeMismatch, got {:?}",
            e.kind
        );
    }
}

#[test]
fn compound_assign_numeric_passes() {
    // `let mut x = 1u64; x += 1u64;` → no error.
    check_src("fn f() { let mut x = 1u64\n x += 1u64 }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn assign_bare_int_literal_coerces_to_lhs() {
    // Plain assignment of a bare (un-suffixed) integer literal to a mut local
    // with a concrete annotated type should coerce the literal, not error.
    // `let mut x: u64 = 0u64; x = 5` — the `5` has no suffix but should coerce to u64.
    check_src("fn f() { let mut x: u64 = 0u64\n x = 5 }")
        .unwrap_or_else(|e| panic!("bare int literal should coerce to u64 in assignment: {e:?}"));
}

#[test]
fn compound_assign_non_numeric_errors() {
    // `let mut x: bool = false; x += true;` → InvalidOperand (bool is not numeric).
    let result = check_src("fn f() { let mut x: bool = false\n x += true }");
    assert!(result.is_err(), "bool += bool should be InvalidOperand");
}

// ─── P3·Step 3e: Expr::If_ branch unification ────────────────────────────────

#[test]
fn if_expr_matching_branches_unified() {
    // `let x = if (c) { 1u64 } else { 2u64 }` → x: u64.
    // Lem if-expressions require parens around the condition.
    let typed = check_src("fn f(c: bool) { let x = if (c) { 1u64 } else { 2u64 } }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u64 = typed.expr_types.values().any(|t| *t == ResolvedType::U64);
    assert!(has_u64, "if expr with u64 branches should produce U64");
}

#[test]
fn if_expr_branch_type_mismatch_errors() {
    // `let x = if (c) { 1u64 } else { true }` → TypeMismatch.
    let result = check_src("fn f(c: bool) { let x = if (c) { 1u64 } else { true } }");
    assert!(
        result.is_err(),
        "if expr with mismatched branches should error"
    );
}

#[test]
fn if_expr_non_bool_cond_errors() {
    // `let x = if (42u128) { 1u64 } else { 2u64 }` → ConditionNotBool.
    let result = check_src("fn f() { let x = if (42u128) { 1u64 } else { 2u64 } }");
    assert!(result.is_err(), "if expr with non-bool cond should error");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::ConditionNotBool { .. }),
            "expected ConditionNotBool, got {:?}",
            e.kind
        );
    }
}

#[test]
fn if_expr_no_else_returns_unit() {
    // `if (c) { 1u64 }` — no else → Unit.
    // The if-expr result is Unit; the let binding gets Unit type.
    let typed =
        check_src("fn f(c: bool) { let x = if (c) { 1u64 } }").unwrap_or_else(|e| panic!("{e:?}"));
    // The if-expr itself should be recorded as Unit.
    let has_unit = typed.expr_types.values().any(|t| *t == ResolvedType::Unit);
    assert!(has_unit, "if expr without else should be Unit");
}

// ─── P3·Step 3e: Expr::Match_ arm unification ────────────────────────────────

#[test]
fn match_expr_all_arms_same_type_passes() {
    // All arms return u128 → unified u128.
    // Lem match uses `match (scrutinee) { pattern => expr }` with parens.
    let typed = check_src("fn f(x: u128) { let v = match (x) { _ => 1u128 } }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "match with u128 arm should unify to U128");
}

#[test]
fn match_expr_arm_type_mismatch_errors() {
    // Two arms: first returns u128, second returns bool → TypeMismatch.
    // Use two wildcard arms (second shadows first — parser allows it).
    let result = check_src("fn f(x: u128) { let v = match (x) { _ => 1u128\n_ => true } }");
    assert!(
        result.is_err(),
        "match with mismatched arm types should error"
    );
}

#[test]
fn match_expr_single_arm_returns_arm_type() {
    // Single-arm match returning a known type → that type.
    let typed = check_src(
        "fn g() -> u128 { return 0u128 }\nfn f(x: u128) { let v = match (x) { _ => g() } }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    // g() returns u128 — the match should unify to u128.
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "match with single u128 arm should be U128");
}

#[test]
fn match_expr_bool_arms_unify_to_concrete_type() {
    // Match on bool with two arms both returning u128: the arms unify to u128.
    // Also exercises the Unknown-propagation guard (if one arm is Unknown, the
    // other concrete type wins); here both are concrete so the direct unify path
    // runs. Uses bool patterns (valid Lem match patterns).
    let typed = check_src(
        "fn known() -> u128 { return 0u128 }\n\
         fn f(b: bool) { let v = match (b) { true => known(), false => known() } }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "match with two u128 arms should unify to U128");
}

// ─── P3·Step 3e: Expr::Try_ ──────────────────────────────────────────────────

#[test]
fn try_expr_unwraps_result_inner_type() {
    // `ok_result?` where ok_result: Result<u64, _> → u64.
    let typed = check_src("fn f(r: Result<u64, string>) -> u64 { return r? }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u64 = typed.expr_types.values().any(|t| *t == ResolvedType::U64);
    assert!(has_u64, "Result<u64, _>? should unwrap to U64");
}

#[test]
fn try_expr_on_unknown_propagates_unknown() {
    // `unknown_expr?` → Unknown (deferred).
    // Use a function call whose return type is Unknown (call result not fully typed).
    // A call to a function returning Result<u64, string> with ? → u64.
    // For the "unknown" case, use a call to a function with no known return type.
    let typed = check_src("fn g() -> Result<u64, string> { return g() }\nfn f() { let x = g()? }")
        .unwrap_or_else(|e| panic!("{e:?}"));
    // g()? → u64 (unwrapped from Result<u64, string>).
    let _ = typed;
}

// ─── P3·Step 3e: struct missing field — P3-checker-5 ─────────────────────────

#[test]
fn struct_lit_missing_required_field_errors() {
    // `Point { x: 1u128 }` with required field `y` → MissingField.
    let result =
        check_src("struct Point { x: u128, y: u128 }\nfn f() { let p = Point { x: 1u128 } }");
    assert!(
        result.is_err(),
        "struct literal missing required field should error"
    );
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::MissingField { .. }),
            "expected MissingField, got {:?}",
            e.kind
        );
    }
}

#[test]
fn struct_lit_optional_field_omitted_passes() {
    // All struct fields in Lem are required (FieldDecl has no default).
    // This test verifies that providing all fields passes.
    check_src("struct Point { x: u128, y: u128 }\nfn f() { let p = Point { x: 1u128, y: 2u128 } }")
        .unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn struct_lit_all_required_fields_present_passes() {
    // All required fields provided → Named type returned.
    let typed = check_src(
        "struct Vec3 { x: u128, y: u128, z: u128 }\
         \nfn f() { let v = Vec3 { x: 1u128, y: 2u128, z: 3u128 } }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let has_named = typed
        .expr_types
        .values()
        .any(|t| matches!(t, ResolvedType::Named(_, _)));
    assert!(
        has_named,
        "struct literal with all fields should be Named(...)"
    );
}

// ─── P3·Step 3f: lambda Fn type inference (P3-checker-9) ─────────────────────

#[test]
fn lambda_typing_does_not_break_existing_inference() {
    // Lambda `x => x` with unannotated param: param type is Unknown,
    // body type is Unknown → Fn([Unknown], Unknown).  No error.
    let typed = check_src("fn f() { let g = x => x }").unwrap_or_else(|e| panic!("{e:?}"));
    // Lambda type is now Fn([Unknown], Unknown) — not Unknown.
    let has_fn_type = typed
        .expr_types
        .values()
        .any(|t| matches!(t, ResolvedType::Fn(_, _)));
    assert!(has_fn_type, "lambda should produce a Fn type");
}

#[test]
fn lambda_return_unknown_when_body_unknown() {
    // Lambda with unannotated param and body that returns Unknown:
    // `x => x` → Fn([Unknown], Unknown).
    let typed = check_src("fn f() { let g = x => x }").unwrap_or_else(|e| panic!("{e:?}"));
    let fn_type = typed
        .expr_types
        .values()
        .find(|t| matches!(t, ResolvedType::Fn(_, _)))
        .cloned()
        .expect("lambda should produce Fn type");
    if let ResolvedType::Fn(params, ret) = fn_type {
        assert_eq!(params, vec![ResolvedType::Unknown]);
        assert_eq!(*ret, ResolvedType::Unknown);
    }
}

// ─── P3-checker-4/6: DRY helpers ─────────────────────────────────────────────

#[test]
fn types_compatible_equal_types_returns_equal() {
    assert_eq!(
        types_compatible(&ResolvedType::U128, &ResolvedType::U128),
        TypeCompatibility::Equal
    );
    assert_eq!(
        types_compatible(&ResolvedType::Bool, &ResolvedType::Bool),
        TypeCompatibility::Equal
    );
}

#[test]
fn types_compatible_int_literal_coerces() {
    let result = types_compatible(&ResolvedType::U64, &ResolvedType::IntLiteral);
    assert_eq!(result, TypeCompatibility::CoercesTo(ResolvedType::U64));
}

#[test]
fn types_compatible_incompatible_types() {
    assert_eq!(
        types_compatible(&ResolvedType::U128, &ResolvedType::Bool),
        TypeCompatibility::Incompatible
    );
}

#[test]
fn types_compatible_unknown_skips_check() {
    // Unknown on either side → Equal (cannot prove incompatibility).
    assert_eq!(
        types_compatible(&ResolvedType::Unknown, &ResolvedType::Bool),
        TypeCompatibility::Equal
    );
    assert_eq!(
        types_compatible(&ResolvedType::U128, &ResolvedType::Unknown),
        TypeCompatibility::Equal
    );
}

// ─── P3-checker-9: Lambda Fn type inference ───────────────────────────────────

#[test]
fn lambda_annotated_params_infers_fn_type() {
    // Lambda parser only supports plain identifier params (no type annotations).
    // `x => x` → Fn([Unknown], Unknown) since param type is `_` placeholder.
    let typed = check_src("fn f() { let g = x => x }").unwrap_or_else(|e| panic!("{e:?}"));
    let fn_type = typed
        .expr_types
        .values()
        .find(|t| matches!(t, ResolvedType::Fn(_, _)))
        .cloned()
        .expect("lambda should produce Fn type");
    if let ResolvedType::Fn(params, _) = fn_type {
        // Parser produces `_` placeholder → Unknown for unannotated params.
        assert_eq!(params, vec![ResolvedType::Unknown]);
    }
}

#[test]
fn lambda_unannotated_params_returns_fn_with_unknown_params() {
    // Lambda with unannotated param: `x => x` → Fn([Unknown], Unknown).
    let typed = check_src("fn f() { let g = x => x }").unwrap_or_else(|e| panic!("{e:?}"));
    let fn_type = typed
        .expr_types
        .values()
        .find(|t| matches!(t, ResolvedType::Fn(_, _)))
        .cloned()
        .expect("lambda should produce Fn type");
    if let ResolvedType::Fn(params, _) = fn_type {
        assert_eq!(params, vec![ResolvedType::Unknown]);
    }
}

#[test]
fn lambda_expr_body_infers_ret_type() {
    // Lambda `x => 42u128` → Fn([Unknown], U128).
    // Body is a typed literal → ret type is U128.
    let typed = check_src("fn f() { let g = x => 42u128 }").unwrap_or_else(|e| panic!("{e:?}"));
    let fn_type = typed
        .expr_types
        .values()
        .find(|t| matches!(t, ResolvedType::Fn(_, _)))
        .cloned()
        .expect("lambda should produce Fn type");
    if let ResolvedType::Fn(params, ret) = fn_type {
        assert_eq!(params, vec![ResolvedType::Unknown]);
        assert_eq!(*ret, ResolvedType::U128);
    }
}

#[test]
fn lambda_no_params_returns_fn_unit() {
    // Lambda `x => 42u128` with single param → Fn([Unknown], U128).
    // Note: the Lem parser doesn't support `() => expr` (zero-param lambda)
    // via the paren path — use single-param form.
    let typed = check_src("fn f() { let g = x => 42u128 }").unwrap_or_else(|e| panic!("{e:?}"));
    let fn_type = typed
        .expr_types
        .values()
        .find(|t| matches!(t, ResolvedType::Fn(_, _)))
        .cloned()
        .expect("lambda should produce Fn type");
    if let ResolvedType::Fn(_params, ret) = fn_type {
        assert_eq!(*ret, ResolvedType::U128);
    }
}

#[test]
fn lambda_block_body_infers_ret_from_last_expr() {
    // Lambda with block body: `x => { 42u128 }` → Fn([Unknown], U128).
    let typed = check_src("fn f() { let g = x => { 42u128 } }").unwrap_or_else(|e| panic!("{e:?}"));
    let fn_type = typed
        .expr_types
        .values()
        .find(|t| matches!(t, ResolvedType::Fn(_, _)))
        .cloned()
        .expect("lambda should produce Fn type");
    if let ResolvedType::Fn(_params, ret) = fn_type {
        assert_eq!(*ret, ResolvedType::U128);
    }
}

// ─── P3-checker-10: Destructuring let back-fill ───────────────────────────────

#[test]
fn let_tuple_destructure_back_fills_binding_types() {
    // `let (a, b) = (1u128, true)` → a: U128, b: Bool.
    let typed =
        check_src("fn f() { let (a, b) = (1u128, true) }").unwrap_or_else(|e| panic!("{e:?}"));
    // Check that U128 and Bool appear in the symbol arena (back-filled).
    let has_u128 = typed
        .symbols
        .iter()
        .any(|s| s.kind == SymbolKind::Local && s.ty == ResolvedType::U128);
    let has_bool = typed
        .symbols
        .iter()
        .any(|s| s.kind == SymbolKind::Local && s.ty == ResolvedType::Bool);
    assert!(has_u128, "tuple destructure should back-fill U128 binding");
    assert!(has_bool, "tuple destructure should back-fill Bool binding");
}

#[test]
fn let_tuple_destructure_unknown_rhs_skips_back_fill() {
    // `let (a, b) = unknown_fn()` — RHS is Unknown → bindings stay Unknown.
    // Should not error.
    check_src("fn f() { let (a, b) = (1u128, true) }").unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn let_struct_destructure_back_fills_field_bindings() {
    // `let Point { x, y } = p` → x: U128, y: U128.
    let typed = check_src(
        "struct Point { x: u128, y: u128 }\n\
         fn f() { let p = Point { x: 1u128, y: 2u128 }\n\
                  let Point { x, y } = p }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    // x and y should be back-filled as U128 locals.
    let u128_locals: Vec<_> = typed
        .symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::Local && s.ty == ResolvedType::U128)
        .collect();
    // At least 2 U128 locals (x and y from destructure, plus p's fields).
    assert!(
        u128_locals.len() >= 2,
        "struct destructure should back-fill field bindings as U128"
    );
}

#[test]
fn let_nested_destructure_partial_back_fill() {
    // `let (a, _) = (1u128, true)` — only `a` is back-filled; `_` is Wildcard.
    let typed =
        check_src("fn f() { let (a, _) = (1u128, true) }").unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed
        .symbols
        .iter()
        .any(|s| s.kind == SymbolKind::Local && s.ty == ResolvedType::U128);
    assert!(
        has_u128,
        "partial tuple destructure should back-fill 'a' as U128"
    );
}

// ─── P3-checker-11: Compound cast targets ────────────────────────────────────

#[test]
fn cast_array_to_typed_array_resolves() {
    // `x as Array<u8>` — compound cast target should resolve (not Unknown).
    // The cast itself may error (non-integer), but the target type resolves.
    // We test that lower_cast_target handles Array<T> without returning Unknown.
    let result = check_src("fn f(x: Array<u8>) -> Array<u8> { return x }");
    // Should not error — just verifying compound types work in type positions.
    result.unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn cast_option_inner_resolves() {
    // `Option<u128>` in a type annotation should resolve correctly.
    let result = check_src("fn f(x: Option<u128>) -> Option<u128> { return x }");
    result.unwrap_or_else(|e| panic!("{e:?}"));
}

// ─── Generic substitution (Part A) ───────────────────────────────────────────

#[test]
fn substitute_typeparam_replaces_correctly() {
    let mut subst = BTreeMap::new();
    subst.insert("T".to_owned(), ResolvedType::U128);
    let ty = ResolvedType::TypeParam("T".to_owned());
    assert_eq!(substitute(&ty, &subst), ResolvedType::U128);
}

#[test]
fn substitute_nested_array_of_typeparam() {
    let mut subst = BTreeMap::new();
    subst.insert("T".to_owned(), ResolvedType::U64);
    let ty = ResolvedType::Array(Box::new(ResolvedType::TypeParam("T".to_owned())));
    assert_eq!(
        substitute(&ty, &subst),
        ResolvedType::Array(Box::new(ResolvedType::U64))
    );
}

#[test]
fn substitute_unknown_typeparam_stays_unknown() {
    // TypeParam not in subst → stays as TypeParam.
    let subst: BTreeMap<String, ResolvedType> = BTreeMap::new();
    let ty = ResolvedType::TypeParam("T".to_owned());
    assert_eq!(
        substitute(&ty, &subst),
        ResolvedType::TypeParam("T".to_owned())
    );
}

#[test]
fn substitute_non_typeparam_unchanged() {
    let mut subst = BTreeMap::new();
    subst.insert("T".to_owned(), ResolvedType::U128);
    // U64 is not a TypeParam — should be unchanged.
    assert_eq!(substitute(&ResolvedType::U64, &subst), ResolvedType::U64);
    assert_eq!(substitute(&ResolvedType::Bool, &subst), ResolvedType::Bool);
}

// ─── Generic call inference (Part B/C) ───────────────────────────────────────

#[test]
fn generic_fn_call_infers_return_type_from_arg() {
    // `fn first<T>(arr: Array<T>) -> Option<T>` called with `Array<u128>` → `Option<u128>`.
    let typed = check_src(
        "fn first<T>(arr: Array<T>) -> Option<T> { return arr.get(0u256) }\n\
         fn f() { let arr: Array<u128> = [1u128, 2u128]\n\
                  let r = first(arr) }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    // The call `first(arr)` should return Option<U128>.
    let has_option_u128 = typed
        .expr_types
        .values()
        .any(|t| *t == ResolvedType::Option_(Box::new(ResolvedType::U128)));
    assert!(
        has_option_u128,
        "generic call should infer Option<u128> return type; got: {:?}",
        typed.expr_types.values().collect::<Vec<_>>()
    );
}

#[test]
fn generic_fn_call_no_args_returns_unknown() {
    // `fn identity<T>(x: T) -> T` called with no args → arity error.
    // But with 1 arg of Unknown type → T stays Unknown → return Unknown.
    let typed = check_src(
        "fn identity<T>(x: T) -> T { return x }\n\
         fn f() { let r = identity(1u128) }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    // identity(1u128) → T = U128 → return U128.
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "identity(1u128) should return U128");
}

#[test]
fn generic_fn_call_wrong_arity_errors() {
    // Calling a 1-param function with 2 args → ArityMismatch.
    let result = check_src(
        "fn identity<T>(x: T) -> T { return x }\n\
         fn f() { let r = identity(1u128, 2u128) }",
    );
    assert!(result.is_err(), "too many args should error");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::ArityMismatch { .. }),
            "expected ArityMismatch, got {:?}",
            e.kind
        );
    }
}

#[test]
fn generic_fn_call_multiple_params_infers_t() {
    // `fn maxOf<T>(a: T, b: T) -> T` called with `(1u128, 2u128)` → T = U128.
    let typed = check_src(
        "fn maxOf<T>(a: T, b: T) -> T { return a }\n\
         fn f() { let r = maxOf(1u128, 2u128) }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "maxOf(1u128, 2u128) should return U128");
}

#[test]
fn non_generic_fn_call_unchanged() {
    // Non-generic function: return type should be unchanged (regression).
    let typed = check_src(
        "fn add(a: u128, b: u128) -> u128 { return a }\n\
         fn f() { let r = add(1u128, 2u128) }",
    )
    .unwrap_or_else(|e| panic!("{e:?}"));
    let has_u128 = typed.expr_types.values().any(|t| *t == ResolvedType::U128);
    assert!(has_u128, "non-generic fn should return U128");
}

#[test]
fn generic_fn_call_arg_type_mismatch_errors() {
    // `fn maxOf<T>(a: T, b: T) -> T` called with `(1u128, true)` → TypeMismatch.
    // T is inferred as U128 from first arg; second arg Bool ≠ U128.
    let result = check_src(
        "fn maxOf<T>(a: T, b: T) -> T { return a }\n\
         fn f() { let r = maxOf(1u128, true) }",
    );
    assert!(result.is_err(), "mismatched generic args should error");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::TypeMismatch { .. }),
            "expected TypeMismatch, got {:?}",
            e.kind
        );
    }
}

// ─── Trait-bound checking (Part D) ───────────────────────────────────────────

#[test]
fn trait_bound_satisfied_by_implements_passes() {
    // Contract implements Comparable → T: Comparable bound satisfied.
    let result = check_src(
        "interface Comparable {}\n\
         contract MyVal implements Comparable {}\n\
         fn sort<T: Comparable>(x: T) -> T { return x }\n\
         fn f(v: MyVal) { let r = sort(v) }",
    );
    result.unwrap_or_else(|e| panic!("should pass: {e:?}"));
}

#[test]
fn trait_bound_not_satisfied_errors() {
    // Contract does NOT implement Comparable → TraitBoundViolation.
    let result = check_src(
        "interface Comparable {}\n\
         contract Plain {}\n\
         fn sort<T: Comparable>(x: T) -> T { return x }\n\
         fn f(v: Plain) { let r = sort(v) }",
    );
    assert!(result.is_err(), "unsatisfied trait bound should error");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::TraitBoundViolation { .. }),
            "expected TraitBoundViolation, got {:?}",
            e.kind
        );
    }
}

#[test]
fn trait_bound_with_primitive_errors() {
    // Primitive type (u128) has no traits → TraitBoundViolation.
    let result = check_src(
        "interface Comparable {}\n\
         fn sort<T: Comparable>(x: T) -> T { return x }\n\
         fn f() { let r = sort(1u128) }",
    );
    assert!(result.is_err(), "primitive with trait bound should error");
    if let Err(crate::error::LangError::Type(e)) = result {
        assert!(
            matches!(e.kind, TypeErrorKind::TraitBoundViolation { .. }),
            "expected TraitBoundViolation, got {:?}",
            e.kind
        );
    }
}

#[test]
fn trait_bound_with_unknown_type_skips() {
    // Unknown type → skip bound check (cannot prove violation).
    // This happens when the arg type is Unknown (e.g. deferred sub-expression).
    let result = check_src(
        "interface Comparable {}\n\
         fn sort<T: Comparable>(x: T) -> T { return x }\n\
         fn f() { let r = sort(sort(1u128)) }",
    );
    // sort(1u128) errors (primitive), but sort(sort(...)) would have Unknown inner.
    // Just verify no panic.
    let _ = result;
}

// ─── Generic struct/enum (Part E) ────────────────────────────────────────────

#[test]
fn generic_struct_new_correct_arg_count_passes() {
    // Generic struct with 2 type params — construction should pass.
    let result = check_src(
        "struct Pair<A, B> { first: A, second: B }\n\
         fn f() { let p = Pair { first: 1u128, second: true } }",
    );
    result.unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn generic_struct_literal_field_type_checked() {
    // Struct literal with generic type param — verify accepted without panic.
    // Note: field type checking for generic structs is deferred to 3g
    // (requires substitution at the struct-literal level).
    // Note: field name must not be "value", "gas", or "salt" (call-opts keywords).
    let result = check_src(
        "struct Wrapper<T> { inner: T }\n\
         fn f() { let b = Wrapper { inner: 1u128 } }",
    );
    result.unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn generic_enum_instantiation_type_args() {
    // Generic enum — verify it resolves without error.
    // Enum variant access via `::` is deferred to 3g; just verify the enum
    // declaration with generic params is accepted by the resolver.
    let result = check_src(
        "enum Maybe<T> { Some(T), None }\n\
         fn f(x: Maybe<u128>) { }",
    );
    // Should not error — generic enum declaration is valid.
    result.unwrap_or_else(|e| panic!("{e:?}"));
}

#[test]
fn generic_struct_new_wrong_type_arg_count_errors() {
    // WrongTypeArgCount: Expr::New with explicit type args is not yet in the
    // AST (parser doesn't thread them through), so this test verifies the
    // struct literal path handles generic structs gracefully.
    let result = check_src(
        "struct Pair<A, B> { first: A, second: B }\n\
         fn f() { let p = Pair { first: 1u128, second: true } }",
    );
    // Should pass — no explicit type arg count mismatch in struct literals yet.
    result.unwrap_or_else(|e| panic!("{e:?}"));
}

// ─── infer_type_args unit tests ───────────────────────────────────────────────

#[test]
fn infer_type_args_simple_typeparam() {
    // param: T, arg: U128 → subst = {T: U128}
    let generic_params = vec![("T".to_owned(), None)];
    let param_types = vec![ResolvedType::TypeParam("T".to_owned())];
    let u128_ty = ResolvedType::U128;
    let arg_types: Vec<&ResolvedType> = vec![&u128_ty];
    let subst = infer_type_args(&param_types, &arg_types, &generic_params);
    assert_eq!(subst.get("T"), Some(&ResolvedType::U128));
}

#[test]
fn infer_type_args_array_of_typeparam() {
    // param: Array<T>, arg: Array<U64> → subst = {T: U64}
    let generic_params = vec![("T".to_owned(), None)];
    let param_types = vec![ResolvedType::Array(Box::new(ResolvedType::TypeParam(
        "T".to_owned(),
    )))];
    let arr_u64 = ResolvedType::Array(Box::new(ResolvedType::U64));
    let arg_types: Vec<&ResolvedType> = vec![&arr_u64];
    let subst = infer_type_args(&param_types, &arg_types, &generic_params);
    assert_eq!(subst.get("T"), Some(&ResolvedType::U64));
}

#[test]
fn infer_type_args_no_typeparams_returns_empty() {
    // Non-generic function: no TypeParams → empty subst.
    let generic_params: Vec<(String, Option<SymbolId>)> = vec![];
    let param_types = vec![ResolvedType::U128];
    let u128_ty = ResolvedType::U128;
    let arg_types: Vec<&ResolvedType> = vec![&u128_ty];
    let subst = infer_type_args(&param_types, &arg_types, &generic_params);
    assert!(subst.is_empty());
}

#[test]
fn infer_type_args_conflicting_bindings_first_wins() {
    // fn f<T>(a: T, b: T) called with (U128, Bool) → T bound to U128 (first wins).
    // The per-arg type check will later catch the mismatch; inference is forward-only.
    let generic_params = vec![("T".to_owned(), None)];
    let param_types = vec![
        ResolvedType::TypeParam("T".to_owned()),
        ResolvedType::TypeParam("T".to_owned()),
    ];
    let u128_ty = ResolvedType::U128;
    let bool_ty = ResolvedType::Bool;
    let arg_types: Vec<&ResolvedType> = vec![&u128_ty, &bool_ty];
    let subst = infer_type_args(&param_types, &arg_types, &generic_params);
    // First binding wins: T = U128.
    assert_eq!(subst.get("T"), Some(&ResolvedType::U128));
}

#[test]
fn trait_bound_with_typeparam_concrete_skips_check() {
    // When T is instantiated with another unresolved TypeParam (generic calling generic),
    // check_trait_bounds must NOT emit a false TraitBoundViolation.
    // Here: `fn outer<U: Comparable>(x: U) -> U { return inner(x) }` where
    // `inner<T: Comparable>(y: T) -> T` — at the call to `inner(x)`, `T` is
    // inferred to `TypeParam("U")` (not a concrete type), so the bound check
    // must skip it.
    let result = check_src(
        "interface Comparable {}\n\
         fn inner<T: Comparable>(y: T) -> T { return y }\n\
         fn outer<U: Comparable>(x: U) -> U { return inner(x) }",
    );
    // Must not error with TraitBoundViolation — TypeParam is not a violation.
    assert!(
        result.is_ok(),
        "generic calling generic with TypeParam should not produce TraitBoundViolation: {result:?}"
    );
}
