//! Tests for SAFETY-011 — Delegate Restriction rule.
//!
//! ## Inconclusive coverage (spec §5.2)
//!
//! SAFETY-011 is **decidable-exact**. The `self.<field>.<method>()` pattern is
//! either present or absent, and known collection methods are whitelisted.
//! There is no `Inconclusive` path. No `Inconclusive→reject` needed.
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

// ─── Collection method allow-list tests (P3-rule-2) ───────────────────────────

#[test]
fn collection_get_on_state_field_is_not_delegate() {
    // self.balances.get(addr) — Map read, not a delegate call.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
pub view fn balance(addr: Address) -> u128 {
let b = self.balances.get(addr)
return b
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "self.balances.get() is a collection read, not a delegate; got {violations:?}"
    );
}

#[test]
fn collection_set_on_state_field_is_not_delegate() {
    // self.balances.set(addr, val) — Map write, not a delegate call.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
pub fn deposit(addr: Address, amount: u128) {
self.balances.set(addr, amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "self.balances.set() is a collection write, not a delegate; got {violations:?}"
    );
}

#[test]
fn collection_add_on_state_field_is_not_delegate() {
    // self.walletExempt.add(addr) — Set add, not a delegate call.
    let ast = typed_ast(
        r#"contract C {
state { walletExempt: Set<Address> }
pub fn exempt(addr: Address) {
self.walletExempt.add(addr)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "self.walletExempt.add() is a Set operation, not a delegate; got {violations:?}"
    );
}

#[test]
fn collection_has_on_state_field_is_not_delegate() {
    // self.pairs.has(addr) — Set membership check, not a delegate call.
    let ast = typed_ast(
        r#"contract C {
state { pairs: Set<Address> }
pub view fn isPair(addr: Address) -> bool {
return self.pairs.has(addr)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "self.pairs.has() is a Set membership check, not a delegate; got {violations:?}"
    );
}

#[test]
fn non_collection_method_on_state_field_is_delegate() {
    // self.externalContract.execute() — NOT a collection method, IS a delegate.
    let ast = typed_ast(
        r#"contract C {
state { externalContract: Address }
init(externalContract: Address) {
self.externalContract = externalContract
}
pub fn run(data: u128) {
let _ = self.externalContract.execute(data)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        !violations.is_empty(),
        "self.externalContract.execute() is a delegate call; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .all(|v| matches!(v, SafetyError::UnsafeDelegate { .. })),
        "all violations must be UnsafeDelegate; got {violations:?}"
    );
}

// ─── SAFETY-011b — delegateCall built-in #[allowDelegate] gate ────────────────

#[test]
fn delegate_call_builtin_without_annotation_rejected() {
    // addr.delegateCall(data) on a local param WITHOUT #[allowDelegate] → reject.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn run(lib: Address, data: bytes) {
let _ = lib.delegateCall(data)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::UngatedDelegateCall { func, .. } if func == "run")),
        "addr.delegateCall without #[allowDelegate] must produce UngatedDelegateCall for `run`; got {violations:?}"
    );
}

#[test]
fn delegate_call_builtin_with_annotation_passes() {
    // addr.delegateCall(data) WITH #[allowDelegate] → pass.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
#[allowDelegate]
pub fn run(lib: Address, data: bytes) {
let _ = lib.delegateCall(data)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "addr.delegateCall WITH #[allowDelegate] must pass SAFETY-011b; got {violations:?}"
    );
}

#[test]
fn delegate_call_builtin_with_at_annotation_passes() {
    // @allowDelegate (the @-form) is the same annotation name → also opts in.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
@allowDelegate
pub fn run(lib: Address, data: bytes) {
let _ = lib.delegateCall(data)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "addr.delegateCall WITH @allowDelegate must pass SAFETY-011b; got {violations:?}"
    );
}

#[test]
fn allow_delegate_is_scoped_to_its_function() {
    // #[allowDelegate] on `safe` must NOT exempt `unsafe_fn` — the gate is
    // per-function. `unsafe_fn` still rejects.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
#[allowDelegate]
pub fn safe(lib: Address, data: bytes) {
let _ = lib.delegateCall(data)
}
pub fn unsafe_fn(lib: Address, data: bytes) {
let _ = lib.delegateCall(data)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "exactly one UngatedDelegateCall expected (only `unsafe_fn`); got {violations:?}"
    );
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::UngatedDelegateCall { func, .. } if func == "unsafe_fn")
        ),
        "the violation must name `unsafe_fn`; got {violations:?}"
    );
}

#[test]
fn self_field_delegate_call_reported_once_as_safety_011() {
    // self.lib.delegateCall(data) — receiver IS self.<field>, so this is the
    // proxy pattern (SAFETY-011 UnsafeDelegate), reported ONCE — not also as
    // SAFETY-011b. No #[allowDelegate], to prove the arms don't double-fire.
    let ast = typed_ast(
        r#"contract C {
state { lib: Address }
init(lib: Address) {
self.lib = lib
}
pub fn run(data: bytes) {
let _ = self.lib.delegateCall(data)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = delegate_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "self.<field>.delegateCall must be reported exactly once; got {violations:?}"
    );
    assert!(
        matches!(violations[0], SafetyError::UnsafeDelegate { .. }),
        "self.<field>.delegateCall must be SAFETY-011 UnsafeDelegate (not 011b); got {violations:?}"
    );
}

#[test]
fn non_delegate_local_call_with_annotation_still_clean() {
    // A function carrying #[allowDelegate] that makes a NON-delegate external
    // call (oracle.getPrice()) must not spuriously fire either arm.
    let ast = typed_ast(
        r#"contract C {
state { price: u128 = 0 }
#[allowDelegate]
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
        "non-delegate call under #[allowDelegate] must stay clean; got {violations:?}"
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
