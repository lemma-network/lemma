//! Tests for SAFETY-004 — Reentrancy rule.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as reentrancy_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn reentrancy_cei_order_write_then_call_passes() {
    // CEI pattern: state write BEFORE external call — no violation.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 }
pub fn goodWithdraw(target: Address, amount: u128) {
self.bal = self.bal - amount
let _ = target.transfer(amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "CEI-ordered function must pass SAFETY-004; got {violations:?}"
    );
}

#[test]
fn reentrancy_no_external_call_passes() {
    // Function with only state writes and no external calls — safe.
    let ast = typed_ast(
        r#"contract C {
state { count: u128 }
pub fn increment() {
self.count = self.count + 1
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "function with no external calls must pass SAFETY-004; got {violations:?}"
    );
}

#[test]
fn reentrancy_no_state_write_passes() {
    // Function that only makes external calls but never writes state — safe.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn notify(target: Address, amount: u128) {
let _ = target.transfer(amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "function with no state writes must pass SAFETY-004; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn reentrancy_state_write_after_ext_call_rejected() {
    // Classic reentrancy: external call THEN state write — must be rejected.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 }
pub fn badWithdraw(target: Address, amount: u128) {
let _ = target.transfer(amount)
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "exactly one SAFETY-004 violation expected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::StateAfterCall { func, .. } if func == "badWithdraw"),
        "violation must be StateAfterCall for badWithdraw; got {:?}",
        violations[0]
    );
}

#[test]
fn reentrancy_non_reentrant_annotation_does_not_exempt() {
    // @nonReentrant does NOT exempt from SAFETY-004 — CEI is required unconditionally.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 }
@nonReentrant
pub fn annotatedWithdraw(target: Address, amount: u128) {
let _ = target.transfer(amount)
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "@nonReentrant must NOT exempt from SAFETY-004; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::StateAfterCall { func, .. } if func == "annotatedWithdraw"),
        "violation must be StateAfterCall for annotatedWithdraw; got {:?}",
        violations[0]
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn reentrancy_write_call_write_reports_one_violation() {
    // Write → call → write: first write is safe (before call), second write
    // after call is a violation. Only one violation per function is reported.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128, flag: u128 }
pub fn mixed(target: Address, amount: u128) {
self.flag = 1
let _ = target.transfer(amount)
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "write-call-write must produce exactly one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::StateAfterCall { func, .. } if func == "mixed"),
        "violation must be StateAfterCall for mixed; got {:?}",
        violations[0]
    );
}

#[test]
fn reentrancy_empty_contract_passes() {
    // Contract with no functions — no violations possible.
    let ast = typed_ast("contract Empty {}");
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "empty contract must pass SAFETY-004; got {violations:?}"
    );
}
