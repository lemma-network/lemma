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
use crate::type_checker::check_skip_wf;
use crate::{check, parse, tokenize};

use super::check as ticker_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

/// Run the pipeline WITHOUT the well-formedness pass.
///
/// Used for negative SAFETY-013 tests where the contract intentionally
/// violates WF-003 (no init / no registry.register) — the WF pass would
/// fire before the safety rule can be exercised.
fn typed_ast_skip_wf(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check_skip_wf(ast).expect("check_skip_wf")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn ticker_token_with_unconditional_register_in_init_passes() {
    // Token with `init { registry.register(self.ticker, self) }` at top level → passes.
    // Pass `registry` as a parameter so the type checker accepts the identifier.
    // Uses a complete Token config per WF-014.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { totalSupply: u128 = 0, ticker: u128 = 0 }
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
    // Uses a complete Token config per WF-014.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { totalSupply: u128 = 0, ticker: u128 = 0 }
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
state { x: u128 = 0 }
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
    // Uses skip-WF helper: WF-003 would fire before SAFETY-013 otherwise.
    let ast = typed_ast_skip_wf(
        r#"token T extends Token {
state { totalSupply: u128 = 0 }
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
    // Uses skip-WF helper: WF-003 would fire before SAFETY-013 otherwise.
    let ast = typed_ast_skip_wf(
        r#"token T extends Token {
state { totalSupply: u128 = 0 }
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
    // Uses skip-WF helper: WF-003 would fire before SAFETY-013 otherwise.
    let ast = typed_ast_skip_wf(
        r#"token T extends Token {
state { totalSupply: u128 = 0, ticker: u128 = 0 }
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
    // Uses a complete Token config per WF-014.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { totalSupply: u128 = 0, ticker: u128 = 0 }
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
    // Uses skip-WF helper: WF-003 would fire before SAFETY-013 otherwise.
    let ast = typed_ast_skip_wf(
        r#"token T extends Token {
state { totalSupply: u128 = 0 }
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
