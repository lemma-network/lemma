//! Tests for SAFETY-013 — Ticker Registration rule.
//!
//! ## Inconclusive coverage (spec §5.2)
//!
//! SAFETY-013 is **decidable-exact**: the presence or absence of an
//! unconditional `registry.register` call at the top level of `init` is a
//! syntactic check with no ambiguous cases.  No `Inconclusive` path exists.
//!
//! ## Scoping note
//!
//! 4e checks `is_token()` only.  Plain contracts implementing `IToken` via
//! `implements IToken` are a 4f extension.
//!
//! ## Lem syntax notes
//!
//! - Token declarations: `token T extends Token { ... }`
//! - Constructor: `init(params) { body }` (keyword, not `fn init`)
//! - `if` requires parentheses: `if (cond) { ... }`
//! - `registry` must be in scope — pass as a parameter to `init` in tests.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as ticker_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn ticker_token_with_unconditional_register_in_init_passes() {
    // Token with `init { registry.register(self.ticker, self) }` at top level → passes.
    // Pass `registry` as a parameter so the type checker accepts the identifier.
    let ast = typed_ast(
        r#"token T extends Token {
state { totalSupply: u128, ticker: u128 }
init(registry: Address) {
registry.register(self.ticker, self)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = ticker_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "token with unconditional registry.register in init must pass SAFETY-013; got {violations:?}"
    );
}

#[test]
fn ticker_token_register_as_last_statement_passes() {
    // register call as the LAST statement in a multi-statement init → passes (still top-level).
    let ast = typed_ast(
        r#"token T extends Token {
state { totalSupply: u128, ticker: u128 }
init(supply: u128, registry: Address) {
self.totalSupply = supply
registry.register(self.ticker, self)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = ticker_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "register as last top-level statement must pass SAFETY-013; got {violations:?}"
    );
}

#[test]
fn ticker_plain_contract_not_checked() {
    // Plain contract (not a token) — rule does not apply.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn setup() {
self.x = 0
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = ticker_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "plain contract must not be checked by SAFETY-013; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn ticker_token_with_no_init_rejected() {
    // Token with no `init` function → MissingTickerRegistration.
    let ast = typed_ast(
        r#"token T extends Token {
state { totalSupply: u128 }
pub fn transfer(to: Address, amount: u128) {
self.totalSupply = self.totalSupply - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = ticker_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "token with no init must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::MissingTickerRegistration),
        "violation must be MissingTickerRegistration; got {:?}",
        violations[0]
    );
}

#[test]
fn ticker_token_init_without_register_call_rejected() {
    // Token with `init` but no registry.register call → MissingTickerRegistration.
    let ast = typed_ast(
        r#"token T extends Token {
state { totalSupply: u128 }
init(supply: u128) {
self.totalSupply = supply
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = ticker_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "token with init but no register call must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::MissingTickerRegistration),
        "violation must be MissingTickerRegistration; got {:?}",
        violations[0]
    );
}

#[test]
fn ticker_token_register_inside_if_block_rejected() {
    // Token with register inside an `if` block in init → MissingTickerRegistration (conditional).
    // Note: Lem `if` requires parentheses around the condition.
    let ast = typed_ast(
        r#"token T extends Token {
state { totalSupply: u128, ticker: u128 }
init(supply: u128, registry: Address) {
self.totalSupply = supply
if (supply > 0) {
registry.register(self.ticker, self)
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = ticker_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "register inside if block must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::MissingTickerRegistration),
        "violation must be MissingTickerRegistration; got {:?}",
        violations[0]
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn ticker_token_register_as_first_statement_passes() {
    // register call as the FIRST statement in init → passes.
    let ast = typed_ast(
        r#"token T extends Token {
state { totalSupply: u128, ticker: u128 }
init(supply: u128, registry: Address) {
registry.register(self.ticker, self)
self.totalSupply = supply
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = ticker_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "register as first top-level statement must pass SAFETY-013; got {violations:?}"
    );
}

#[test]
fn ticker_empty_token_no_init_rejected() {
    // Minimal token with no functions at all → MissingTickerRegistration.
    let ast = typed_ast(
        r#"token T extends Token {
state { totalSupply: u128 }
}"#,
    );
    let contracts = ast.contracts();
    let violations = ticker_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "token with no functions must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::MissingTickerRegistration),
        "violation must be MissingTickerRegistration; got {:?}",
        violations[0]
    );
}
