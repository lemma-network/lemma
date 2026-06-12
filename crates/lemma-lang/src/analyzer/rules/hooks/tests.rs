//! Tests for SAFETY-008 — Hook Sandboxing rule.
//!
//! ## Inconclusive coverage (spec §5.2)
//!
//! SAFETY-008 is **decidable-exact** — `Ext(f)` is either empty or non-empty.
//! There is no `Inconclusive` path. No `Inconclusive→reject` case needed.
//!
//! ## Cross-rule interaction tests (P3·Step 4g)
//!
//! Cross-rule tests call `analyze_safety` directly to verify that multiple
//! rules fire simultaneously on a single contract.

use crate::analyzer::error::SafetyError;
use crate::{analyze_safety, parse, tokenize};

use super::check as hooks_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn hooks_on_transfer_pure_state_access_passes() {
    // #[onTransfer] hook that only reads/writes own state — no violation.
    let ast = typed_ast(
        r#"contract C {
state { count: u128 = 0 }
#[onTransfer]
pub fn onTransfer() {
self.count = self.count + 1
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = hooks_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "#[onTransfer] hook with only own-state access must pass SAFETY-008; got {violations:?}"
    );
}

#[test]
fn hooks_no_on_transfer_annotation_passes() {
    // Function without #[onTransfer] that makes external calls — not a hook, safe.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn notAHook(target: Address, amount: u128) {
let _ = target.transfer(amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = hooks_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "non-hook function with external calls must pass SAFETY-008; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn hooks_on_transfer_with_external_call_rejected() {
    // #[onTransfer] hook that calls an external contract — must be rejected.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
#[onTransfer]
pub fn onTransfer(target: Address, amount: u128) {
let _ = target.transfer(amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = hooks_check(&contracts[0]);
    assert!(
        !violations.is_empty(),
        "#[onTransfer] hook with external call must produce SAFETY-008 violation; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .all(|v| matches!(v, SafetyError::HookEscape { hook, .. } if hook == "onTransfer")),
        "all violations must be HookEscape for onTransfer; got {violations:?}"
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn hooks_other_annotation_with_external_call_passes() {
    // Function with a different annotation (not onTransfer) that makes external
    // calls — not a hook, so SAFETY-008 does not apply.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
@onlyOwner
pub fn adminAction(target: Address, amount: u128) {
let _ = target.transfer(amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = hooks_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "non-onTransfer annotated function must pass SAFETY-008; got {violations:?}"
    );
}

#[test]
fn hooks_empty_on_transfer_body_passes() {
    // #[onTransfer] hook with an empty body — no external calls, safe.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
#[onTransfer]
pub fn onTransfer() {
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = hooks_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "#[onTransfer] hook with empty body must pass SAFETY-008; got {violations:?}"
    );
}

#[test]
fn hooks_on_transfer_collection_write_own_state_passes() {
    // P3-cfg-1 regression: a hook writing its OWN collection state via a
    // collection mutator (self.balances.set(...)) must NOT be a HookEscape.
    // Before the cfg fix, self.balances.set() was mis-recorded as an EXTERNAL
    // call → false-positive HookEscape. The fix records it as a StateWrite to
    // own state → no violation.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
#[onTransfer]
pub fn onTransfer(to: Address, amount: u128) {
self.balances.set(to, amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = hooks_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "hook writing own collection state must pass SAFETY-008 (P3-cfg-1); got {violations:?}"
    );
}

// ─── Cross-rule interaction tests (P3·Step 4g) ────────────────────────────────

#[test]
fn cross_rule_safety_008_and_004_combined() {
    // #[onTransfer] hook that makes an external call (SAFETY-008) AND writes
    // state after it (SAFETY-004) → both violations must appear.
    let tokens = tokenize(
        r#"contract C {
state { count: u128 = 0 }
#[onTransfer]
pub fn onTransfer(target: Address, amount: u128) {
let _ = target.transfer(amount)
self.count = self.count + 1
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
            .any(|e| matches!(e, SafetyError::HookEscape { .. })),
        "SAFETY-008 HookEscape must be present; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|e| matches!(e, SafetyError::StateAfterCall { .. })),
        "SAFETY-004 StateAfterCall must be present; got {violations:?}"
    );
}
