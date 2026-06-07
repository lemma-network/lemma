//! Tests for SAFETY-012 — Integer Safety rule.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as integer_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn integer_no_unchecked_block_passes() {
    // No unchecked block at all — no violation possible.
    let ast = typed_ast(
        r#"contract C {
state { balance: u128 }
pub fn deposit(amount: u128) {
self.balance = self.balance + amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "arithmetic outside unchecked must pass SAFETY-012; got {violations:?}"
    );
}

#[test]
fn integer_unchecked_local_only_passes() {
    // unchecked block with arithmetic that only touches a local variable — safe.
    let ast = typed_ast(
        r#"contract C {
state { balance: u128 }
pub fn compute(a: u128, b: u128) -> u128 {
let mut result: u128 = 0
unchecked {
result = a + b
}
return result
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "unchecked arithmetic on local var must pass SAFETY-012; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn integer_unchecked_add_to_state_field_rejected() {
    // unchecked { self.balance = self.balance + amount } — must be rejected.
    let ast = typed_ast(
        r#"contract C {
state { balance: u128 }
pub fn badDeposit(amount: u128) {
unchecked {
self.balance = self.balance + amount
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "unchecked + to state field must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UncheckedArithmetic { op, .. } if op == "+"),
        "violation must be UncheckedArithmetic with op '+'; got {:?}",
        violations[0]
    );
}

#[test]
fn integer_unchecked_sub_to_state_field_rejected() {
    // unchecked { self.total_supply = self.total_supply - amount } — must be rejected.
    let ast = typed_ast(
        r#"contract C {
state { total_supply: u128 }
pub fn badBurn(amount: u128) {
unchecked {
self.total_supply = self.total_supply - amount
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "unchecked - to state field must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UncheckedArithmetic { op, .. } if op == "-"),
        "violation must be UncheckedArithmetic with op '-'; got {:?}",
        violations[0]
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn integer_unchecked_local_var_not_state_write_passes() {
    // unchecked block that only computes a local variable (not self.*) — safe.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn localOnly(a: u128, b: u128) {
let mut tmp: u128 = 0
unchecked {
tmp = a * b
}
self.x = tmp
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "unchecked arithmetic on local var only must pass SAFETY-012; got {violations:?}"
    );
}

#[test]
fn integer_empty_unchecked_block_passes() {
    // Empty unchecked block — no violation.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn noop() {
unchecked {
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "empty unchecked block must pass SAFETY-012; got {violations:?}"
    );
}
