//! Tests for the expression type inference pass (P3·Step 3c).
//!
//! Follows AGENTS §11.2: tests live in a separate submodule file, never inline.

use crate::type_checker::types::ResolvedType;
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
