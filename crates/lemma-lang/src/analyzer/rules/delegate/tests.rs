//! Tests for SAFETY-011 — Delegate Restriction rule.
//!
//! ## Inconclusive coverage (spec §5.2)
//!
//! SAFETY-011 is **decidable-exact** (sound over-approximation for the
//! `@std` allow-list). The `self.<field>.<method>()` pattern is either present
//! or absent. There is no `Inconclusive` path. No `Inconclusive→reject` needed.
//!
//! ## Cross-rule interaction tests (P3·Step 4g)
//!
//! Cross-rule tests call `analyze_safety` directly to verify that multiple
//! rules fire simultaneously on a single contract.

use crate::analyzer::error::SafetyError;
use crate::{analyze_safety, parse, tokenize};

use super::check as delegate_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn delegate_self_method_call_passes() {
    // self.transfer(to, amount) — direct self-method call, internal, not a delegate.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
pub fn transfer(to: Address, amount: u128) {
self.bal = self.bal - amount
}
pub fn doTransfer(to: Address, amount: u128) {
let _ = self.transfer(to, amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "self.method() internal call must pass SAFETY-011; got {violations:?}"
    );
}

#[test]
fn delegate_local_var_external_call_passes() {
    // oracle.getPrice() — external call through a local variable, not self.field.
    let ast = typed_ast(
        r#"contract C {
state { price: u128 = 0 }
pub fn updatePrice(oracle: Address) {
let p = oracle.getPrice()
self.price = p
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "external call through local var must pass SAFETY-011; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn delegate_self_field_method_call_rejected() {
    // self.implementation.execute(data) — call through a state field, must be rejected.
    let ast = typed_ast(
        r#"contract C {
state { implementation: Address }
init(implementation: Address) {
self.implementation = implementation
}
pub fn execute(data: u128) {
let _ = self.implementation.execute(data)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        !violations.is_empty(),
        "self.<field>.<method>() must produce SAFETY-011 violation; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .all(|v| matches!(v, SafetyError::UnsafeDelegate { .. })),
        "all violations must be UnsafeDelegate; got {violations:?}"
    );
}

#[test]
fn delegate_self_impl_addr_call_rejected() {
    // self.impl_addr.call(selector) — another delegate pattern, must be rejected.
    let ast = typed_ast(
        r#"contract C {
state { impl_addr: Address }
init(impl_addr: Address) {
self.impl_addr = impl_addr
}
pub fn proxyCall(selector: u128) {
let _ = self.impl_addr.call(selector)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        !violations.is_empty(),
        "self.impl_addr.call() must produce SAFETY-011 violation; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .all(|v| matches!(v, SafetyError::UnsafeDelegate { .. })),
        "all violations must be UnsafeDelegate; got {violations:?}"
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn delegate_self_field_read_only_passes() {
    // self.implementation is only READ (not called) — no violation.
    let ast = typed_ast(
        r#"contract C {
state { implementation: Address }
init(implementation: Address) {
self.implementation = implementation
}
pub view fn getImpl() -> Address {
return self.implementation
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "reading self.field without calling it must pass SAFETY-011; got {violations:?}"
    );
}

#[test]
fn delegate_empty_contract_passes() {
    // Contract with no functions — no violations possible.
    let ast = typed_ast("contract Empty {}");
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "empty contract must pass SAFETY-011; got {violations:?}"
    );
}

// ─── Cross-rule interaction tests (P3·Step 4g) ────────────────────────────────

#[test]
fn cross_rule_safety_011_and_004_combined() {
    // Contract with a dynamic delegate call (SAFETY-011) AND state written
    // after an external call (SAFETY-004) in the same function → both detected.
    let tokens = tokenize(
        r#"contract C {
state { implementation: Address bal: u128 = 0 }
init(implementation: Address) {
self.implementation = implementation
}
pub fn execute(data: u128) {
let _ = self.implementation.execute(data)
self.bal = self.bal + 1
}
}"#,
    )
    .expect("tokenize");
    let ast = parse(tokens).expect("parse");
    let typed = crate::type_checker::check_skip_wf(ast).expect("type check");
    let contracts = typed.contracts();
    let result = analyze_safety(&contracts[0]);
    let violations = result.unwrap_err();
    assert!(
        violations
            .iter()
            .any(|e| matches!(e, SafetyError::UnsafeDelegate { .. })),
        "SAFETY-011 UnsafeDelegate must be present; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|e| matches!(e, SafetyError::StateAfterCall { .. })),
        "SAFETY-004 StateAfterCall must be present; got {violations:?}"
    );
}
