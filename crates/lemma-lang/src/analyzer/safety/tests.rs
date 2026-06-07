//! Tests for the analyze_safety driver.
//!
//! 4a tests: stub returns Ok(()) for any well-typed contract.
//! 4d–4f tests: per-rule positive + negative + boundary + cross-rule tests
//! will be added here as each rule batch is implemented.

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
pub balance: u128
pub owner: Address
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
    // A minimal config-only token must pass the stub.
    let ast = typed_ast(
        r#"token MinimalToken extends Token {
config {
name: "Minimal"
symbol: "MIN"
decimals: 18
maxSupply: 1000000
}
}"#,
    );
    let contracts = ast.contracts();
    assert_eq!(contracts.len(), 1);
    assert!(contracts[0].is_token());
    let result = super::analyze_safety(&contracts[0]);
    assert!(
        result.is_ok(),
        "minimal token should pass analyze_safety stub: {result:?}"
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
