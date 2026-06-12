//! Tests for SAFETY-025 — Sell-Path External Veto rule.
//!
//! ## Rule summary
//!
//! Any external call on the sell/transfer path that is NOT wrapped in
//! `try { … } catch { … }` is rejected with `SellPathExternalVeto`.
//! A try-wrapped call cannot propagate a revert from the callee.
//!
//! ## Inconclusive coverage
//!
//! SAFETY-025 is decidable-exact for the try-wrapping check: an external call
//! is either inside a `Stmt::Try` body or it is not.  No `Inconclusive` path.

use crate::analyzer::error::SafetyError;
use crate::{parse, tokenize};

use super::check as sell_path_veto_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
///
/// Uses `check_skip_wf` so that contracts with intentional safety violations
/// (e.g. unwrapped external calls) can be type-checked without the pipeline
/// safety gate rejecting them before the rule under test can run.
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn sell_path_with_try_wrapped_external_call_passes() {
    // External call in transfer but inside try/catch → safe (revert cannot propagate).
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 externalChecker: "lem1qchecker" }
state { balances: Map<Address, u128> checker: Address }
init(c: Address) { self.checker = c }
pub fn transfer(to: Address, amount: u128) {
try {
let _ = self.checker.canTransfer(to, amount)
} catch (err) {
}
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = sell_path_veto_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "try-wrapped external call on transfer path must pass SAFETY-025; got {violations:?}"
    );
}

#[test]
fn non_transfer_function_with_external_call_not_flagged() {
    // External call in distributeTaxes (off transfer path) → not flagged.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> oracle: Address }
init(o: Address) { self.oracle = o }
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
pub fn refreshOracle() {
let _ = self.oracle.update()
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = sell_path_veto_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "external call off transfer path must not be flagged by SAFETY-025; got {violations:?}"
    );
}

#[test]
fn contract_without_external_calls_passes() {
    // No external calls anywhere → clean.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
init() {}
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = sell_path_veto_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "contract with no external calls must pass SAFETY-025; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn sell_path_with_unwrapped_external_call_rejected() {
    // self.checker.canTransfer(from, to) without try → SellPathExternalVeto.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 externalChecker: "lem1qchecker" }
state { balances: Map<Address, u128> checker: Address }
init(c: Address) { self.checker = c }
pub fn transfer(to: Address, amount: u128) {
let _ = self.checker.canTransfer(to, amount)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = sell_path_veto_check(&contracts[0]);
    assert!(
        !violations.is_empty(),
        "unwrapped external call on transfer path must produce SAFETY-025 violation; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::SellPathExternalVeto { func } if func == "transfer")),
        "violation must be SellPathExternalVeto for transfer; got {violations:?}"
    );
}

// ─── Cross-rule interaction test ──────────────────────────────────────────────

#[test]
fn cross_rule_025_and_010_combined() {
    // External call on transfer path, undeclared (no externalChecker in config)
    // → both SAFETY-025 (unwrapped) and SAFETY-010 (undeclared) triggered.
    //
    // Note: analyze_safety is called directly to collect violations from both rules.
    use crate::analyzer::analyze_safety;

    let tokens = tokenize(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> checker: Address }
init(c: Address) { self.checker = c }
pub fn transfer(to: Address, amount: u128) {
let _ = self.checker.canTransfer(to, amount)
self.balances[to] = amount
}
}"#,
    )
    .expect("tokenize");
    let ast = parse(tokens).expect("parse");
    // Use check_skip_wf to bypass pipeline safety gate and call analyze_safety directly.
    let typed = crate::type_checker::check_skip_wf(ast).expect("type check");
    let contracts = typed.contracts();
    let result = analyze_safety(&contracts[0]);
    let violations = result.unwrap_err();
    assert!(
        violations
            .iter()
            .any(|e| matches!(e, SafetyError::SellPathExternalVeto { .. })),
        "SAFETY-025 SellPathExternalVeto must be present; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|e| matches!(e, SafetyError::UndeclaredRestriction { .. })),
        "SAFETY-010 UndeclaredRestriction must be present; got {violations:?}"
    );
}
