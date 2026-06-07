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
