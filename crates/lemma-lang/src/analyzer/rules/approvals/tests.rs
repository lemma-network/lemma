//! Tests for SAFETY-006 — Approval Bounds rule.
//!
//! ## Inconclusive coverage (spec §5.2)
//!
//! SAFETY-006 is **decidable-exact** for the 4e scope: the presence or absence
//! of an expiry parameter is a syntactic check with no ambiguous cases.
//! No `Inconclusive` path exists in 4e.
//!
//! ## Scoping note
//!
//! MAX-sentinel check (`approve(spender, Amount::MAX)`) is deferred to 4f.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as approvals_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn approvals_no_approve_function_passes() {
    // Contract with no `approve` function — rule does not apply.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn transfer(to: Address, amount: u128) {
self.x = self.x - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = approvals_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "contract with no approve function must pass SAFETY-006; got {violations:?}"
    );
}

#[test]
fn approvals_approve_with_expiry_param_passes() {
    // approve(spender, amount, expiry) → passes.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn approve(spender: Address, amount: u128, expiry: u64) {
self.x = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = approvals_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "approve with expiry param must pass SAFETY-006; got {violations:?}"
    );
}

#[test]
fn approvals_approve_with_deadline_param_passes() {
    // approve with `deadline` param (synonym for expiry) → passes.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn approve(spender: Address, amount: u128, deadline: u64) {
self.x = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = approvals_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "approve with deadline param must pass SAFETY-006; got {violations:?}"
    );
}

#[test]
fn approvals_approve_with_expires_param_passes() {
    // approve with `expires` param (synonym for expiry) → passes.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn approve(spender: Address, amount: u128, expires: u64) {
self.x = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = approvals_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "approve with expires param must pass SAFETY-006; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn approvals_approve_without_expiry_rejected() {
    // approve(spender, amount) — no expiry → UnboundedApproval.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn approve(spender: Address, amount: u128) {
self.x = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = approvals_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "approve without expiry must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UnboundedApproval { .. }),
        "violation must be UnboundedApproval; got {:?}",
        violations[0]
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn approvals_approve_with_only_spender_param_rejected() {
    // approve(spender) — no amount, no expiry → UnboundedApproval.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn approve(spender: Address) {
self.x = 0
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = approvals_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "approve with only spender param must produce one violation; got {violations:?}"
    );
}

#[test]
fn approvals_non_approve_function_not_checked() {
    // A function named `setApproval` (not exactly `approve`) — not checked.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn setApproval(spender: Address, amount: u128) {
self.x = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = approvals_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "setApproval (not exactly 'approve') must not be checked by SAFETY-006; got {violations:?}"
    );
}

#[test]
fn approvals_empty_contract_passes() {
    // Empty contract — no violations possible.
    let ast = typed_ast("contract Empty {}");
    let contracts = ast.contracts();
    let violations = approvals_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "empty contract must pass SAFETY-006; got {violations:?}"
    );
}
