//! Tests for the analyze_safety driver.
//!
//! 4a tests: stub returns Ok(()) for any well-typed contract.
//! 4g tests: end-to-end driver tests — plain token passes all rules,
//!   TaxToken passes all rules, collect-all behavior verified.

use crate::{check, parse, tokenize};

/// Run the full pipeline and return a TypedAst (panics if tokenize/parse/check fail).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize failed in test");
    let ast = parse(tokens).expect("parse failed in test");
    check(ast).expect("check failed in test")
}

// ─── 4a stub tests ────────────────────────────────────────────────────────────

#[test]
fn empty_contract_passes() {
    // Any well-typed plain contract must pass analyze_safety while no rules
    // are active (4a stub).
    let ast = typed_ast("contract Empty {}");
    let contracts = ast.contracts();
    assert_eq!(contracts.len(), 1);
    let result = super::analyze_safety(&contracts[0]);
    assert!(
        result.is_ok(),
        "empty contract should pass analyze_safety stub: {result:?}"
    );
}

#[test]
fn non_token_contract_passes() {
    // A plain contract (not a token) with state + functions must pass the stub.
    let ast = typed_ast(
        r#"contract SimpleVault {
state {
pub balance: u128 = 0
pub owner: Address
}
init(owner: Address) {
self.owner = owner
}
pub view fn getBalance() -> u128 {
return self.balance
}
}"#,
    );
    let contracts = ast.contracts();
    assert_eq!(contracts.len(), 1);
    assert!(!contracts[0].is_token());
    let result = super::analyze_safety(&contracts[0]);
    assert!(
        result.is_ok(),
        "non-token contract should pass analyze_safety stub: {result:?}"
    );
}

#[test]
fn minimal_token_passes() {
    // A minimal token must pass analyze_safety.
    // SAFETY-003 (4e) requires a cap assert before totalSupply writes when maxSupply is set.
    // Uses a complete Token config (name, symbol, decimals, maxSupply) per WF-014.
    let ast = typed_ast(
        r#"token MinimalToken extends Token {
config {
name: "Minimal"
symbol: "MIN"
decimals: 18
maxSupply: 1000000
}
state { totalSupply: u128 = 0 }
init() {}
}"#,
    );
    let contracts = ast.contracts();
    assert_eq!(contracts.len(), 1);
    assert!(contracts[0].is_token());
    let result = super::analyze_safety(&contracts[0]);
    assert!(
        result.is_ok(),
        "minimal token should pass analyze_safety: {result:?}"
    );
}

#[test]
fn analyze_safety_returns_ok_not_err_in_stub_phase() {
    // Prove the stub never returns Err (no rules yet = no violations possible).
    let ast = typed_ast("contract AnyContract {}");
    let contracts = ast.contracts();
    let result = super::analyze_safety(&contracts[0]);
    assert_eq!(
        result,
        Ok(()),
        "stub must return Ok(()) for any input: {result:?}"
    );
}

// ─── P3·Step 4g driver tests ──────────────────────────────────────────────────

#[test]
fn analyze_safety_plain_token_passes_all_rules() {
    // A valid minimal Token contract with a transfer function must pass all
    // SAFETY-001…025 rules (Ok(())).
    let ast = typed_ast(
        r#"token MinimalToken extends Token {
config {
name: "Minimal"
symbol: "MIN"
decimals: 18
maxSupply: 1000000
}
state { totalSupply: u128 = 0 balances: Map<Address, u128> }
init() {}
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    assert_eq!(contracts.len(), 1);
    let result = super::analyze_safety(&contracts[0]);
    assert!(
        result.is_ok(),
        "valid minimal Token must pass all SAFETY rules; got {result:?}"
    );
}

#[test]
fn analyze_safety_tax_token_passes_all_rules() {
    // A valid minimal TaxToken with no distributeTaxes, no isTaxable, no fees
    // setter must pass all SAFETY-001…025 rules (Ok(())).
    // Uses fees.others = 0 to avoid WF-014 distributeTaxes requirement.
    let ast = typed_ast(
        r#"token MinimalTax extends TaxToken {
config {
name: "MinimalTax"
symbol: "MTAX"
decimals: 18
maxSupply: 1000000
fees: { burn: 0 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0 balances: Map<Address, u128> }
init() {}
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    assert_eq!(contracts.len(), 1);
    let result = super::analyze_safety(&contracts[0]);
    assert!(
        result.is_ok(),
        "valid minimal TaxToken must pass all SAFETY rules; got {result:?}"
    );
}

#[test]
fn analyze_safety_contract_with_multiple_violations_collects_all() {
    // A contract with 2 distinct violations must return Err with both in the Vec
    // (collect-all behavior — never fail-fast).
    //
    // Violations triggered:
    // - SAFETY-004: state written after external call (CEI violation)
    // - SAFETY-011: dynamic delegate call via self.implementation.execute()
    let tokens = tokenize(
        r#"contract MultiViolation {
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
    let result = super::analyze_safety(&contracts[0]);
    let violations = result.unwrap_err();
    assert!(
        violations.len() >= 2,
        "at least 2 violations expected (collect-all); got {violations:?}"
    );
    assert!(
        violations.iter().any(|e| matches!(
            e,
            crate::analyzer::error::SafetyError::StateAfterCall { .. }
        )),
        "SAFETY-004 StateAfterCall must be present; got {violations:?}"
    );
    assert!(
        violations.iter().any(|e| matches!(
            e,
            crate::analyzer::error::SafetyError::UnsafeDelegate { .. }
        )),
        "SAFETY-011 UnsafeDelegate must be present; got {violations:?}"
    );
}
