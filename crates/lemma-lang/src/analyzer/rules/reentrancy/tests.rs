//! Tests for SAFETY-004 — Reentrancy rule.
//!
//! ## Inconclusive coverage (spec §5.2)
//!
//! SAFETY-004 is **decidable-exact** — the CFG-node sequence is a sound
//! over-approximation (all branch paths merged) that never produces an
//! inconclusive result. There is no `Inconclusive` path; all contracts either
//! pass (empty `Vec`) or fail (one `StateAfterCall` per function). No
//! `Inconclusive→reject` test case exists or is needed.
//!
//! ## Cross-rule interaction and fuzz tests (spec §5.2)
//!
//! Deferred to **P3·Step 4g** (integration + fuzz + full pipeline wiring), as
//! stated in `analyzer/mod.rs`. Intentional deferral; tracked in living-notes.

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
state { bal: u128 = 0 }
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
state { count: u128 = 0 }
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
state { x: u128 = 0 }
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
state { bal: u128 = 0 }
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
state { bal: u128 = 0 }
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

// ─── Transitive write via internal callee ─────────────────────────────────────

#[test]
fn reentrancy_state_write_via_helper_callee_after_ext_call_rejected() {
    // The canonical one-hop evasion: external call in pub fn, then delegate to
    // an internal helper that writes state — still a CEI violation.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
pub fn withdraw(target: Address, amount: u128) {
let _ = target.transfer(amount)
self.applyDebit(amount)
}
fn applyDebit(amount: u128) {
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "helper-via-indirection after ext call must be SAFETY-004 violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::StateAfterCall { func, .. } if func == "withdraw"),
        "violation must be on withdraw; got {:?}",
        violations[0]
    );
}

#[test]
fn reentrancy_helper_called_before_ext_call_passes() {
    // Safe: state-writing helper called BEFORE the external call (correct CEI).
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
pub fn safeWithdraw(target: Address, amount: u128) {
self.applyDebit(amount)
let _ = target.transfer(amount)
}
fn applyDebit(amount: u128) {
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "state-writing helper called before ext call must pass SAFETY-004; got {violations:?}"
    );
}

#[test]
fn reentrancy_internal_helper_with_no_state_write_after_ext_call_passes() {
    // Safe: calling a helper that does NOT write state after an external call is fine.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
pub fn notify(target: Address, amount: u128) {
let _ = target.transfer(amount)
self.logEvent(amount)
}
view fn logEvent(amount: u128) -> u128 {
return amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "calling a non-state-writing helper after ext call must pass SAFETY-004; got {violations:?}"
    );
}

// ─── Loop back-edge tests ─────────────────────────────────────────────────────

#[test]
fn reentrancy_loop_write_before_call_back_edge_rejected() {
    // Write precedes call within one iteration, but the back-edge of the loop
    // means iteration N's call is followed by iteration N+1's write — violation.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
pub fn badLoop(target: Address, amount: u128) {
loop {
self.bal = self.bal - amount
let _ = target.transfer(amount)
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "loop with write-before-call must be flagged (back-edge); got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::StateAfterCall { func, .. } if func == "badLoop"),
        "violation must be on badLoop; got {:?}",
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
state { bal: u128 = 0, flag: u128 = 0 }
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

// ─── P3-cfg-1 regression: collection-method write after external call ──────────

#[test]
fn reentrancy_collection_set_after_call_rejected() {
    // CEI violation via a COLLECTION mutator: external call THEN
    // self.balances.set(...). Before the P3-cfg-1 cfg fix, state_write_key was
    // blind to `.set()` so this CEI violation was a FALSE NEGATIVE. Now the
    // collection-method write is a StateWrite after the ExternalCall → rejected.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
init() {}
pub fn badWithdraw(target: Address, amount: u128) {
let _ = target.transfer(amount)
self.balances.set(target, amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::StateAfterCall { func, .. } if func == "badWithdraw")),
        "collection-mutator write after external call must be a SAFETY-004 violation; got {violations:?}"
    );
}

#[test]
fn reentrancy_array_sort_after_call_rejected() {
    // CEI violation via an in-place Array reordering after an external call.
    // self.queue.sort() is conservatively a StateWrite → CEI violation when it
    // follows an external call.
    let ast = typed_ast(
        r#"contract C {
state { queue: Array<u128> }
init() { self.queue = [] }
pub fn badReorder(target: Address, amount: u128) {
let _ = target.transfer(amount)
self.queue.sort()
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = reentrancy_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::StateAfterCall { func, .. } if func == "badReorder")),
        "in-place sort after external call must be a SAFETY-004 violation; got {violations:?}"
    );
}
