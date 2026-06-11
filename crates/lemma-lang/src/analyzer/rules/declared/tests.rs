//! Tests for SAFETY-010 — Declared Restrictions (option A: external-call clause).
//!
//! An external call on the transfer path (`transfer`/`transferFrom`/`#[onTransfer]`)
//! requires `externalChecker: "<addr>"` declared in `config {}`. Undeclared ⇒
//! `UndeclaredRestriction`.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as declared_check;

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn declared_no_external_call_passes() {
    // transfer makes no external call → nothing to declare.
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
    let violations = declared_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "transfer with no external call must pass SAFETY-010; got {violations:?}"
    );
}

#[test]
fn declared_external_call_with_checker_passes() {
    // transfer calls an external checker AND declares externalChecker → surfaced.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 externalChecker: "lem1qchecker" }
state { balances: Map<Address, u128> }
state { checker: Address }
init(c: Address) { self.checker = c }
pub fn transfer(to: Address, amount: u128) {
let ok = self.checker.canTransfer(to, amount)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = declared_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "declared externalChecker must pass SAFETY-010; got {violations:?}"
    );
}

#[test]
fn declared_external_call_off_transfer_path_passes() {
    // An external call in a NON-transfer function does not require externalChecker.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { oracle: Address }
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
    let violations = declared_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "external call off the transfer path must not require externalChecker; got {violations:?}"
    );
}

// ─── Negative tests (violations → UndeclaredRestriction) ─────────────────────

#[test]
fn declared_undeclared_external_call_in_transfer_rejected() {
    // transfer calls an external contract but config has NO externalChecker.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { checker: Address }
init(c: Address) { self.checker = c }
pub fn transfer(to: Address, amount: u128) {
let ok = self.checker.canTransfer(to, amount)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = declared_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "undeclared external call on transfer must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UndeclaredRestriction { func } if func == "transfer"),
        "expected UndeclaredRestriction naming transfer; got {:?}",
        violations[0]
    );
}

#[test]
fn declared_undeclared_external_call_in_transfer_from_rejected() {
    // transferFrom calls an external contract with no externalChecker declared.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { gate: Address }
init(g: Address) { self.gate = g }
pub fn transferFrom(from: Address, to: Address, amount: u128) {
let ok = self.gate.check(from, to)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = declared_check(&contracts[0]);
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::UndeclaredRestriction { func } if func == "transferFrom")
        ),
        "undeclared external call on transferFrom must be rejected; got {violations:?}"
    );
}

#[test]
fn declared_transitive_ext_call_known_gap_not_flagged() {
    // KNOWN GAP (living-notes P3-rule-7): ext_calls is DIRECT-only. A transfer
    // that delegates the external call to an internal helper evades the static
    // check — the hidden dependence slips to the Tier-2 runtime score by design.
    // This test PINS the current limitation so a future transitive-closure fix
    // changes behaviour deliberately (the assertion will flip to len()==1 then).
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { checker: Address }
init(c: Address) { self.checker = c }
pub fn transfer(to: Address, amount: u128) {
let _ = self.doCheck(to)
self.balances[to] = amount
}
fn doCheck(to: Address) {
let _ = self.checker.canTransfer(to)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = declared_check(&contracts[0]);
    // Direct-only detection: the external call hidden in `doCheck` is NOT seen
    // from `transfer`'s body. Pinned as the known gap (P3-rule-7).
    assert!(
        violations.is_empty(),
        "KNOWN GAP P3-rule-7: transitive ext-call is direct-only (slips to Tier-2); got {violations:?}"
    );
}

#[test]
fn declared_empty_external_checker_string_rejected() {
    // externalChecker declared but EMPTY → not a real declaration; the external
    // call is still undeclared.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 externalChecker: "" }
state { balances: Map<Address, u128> }
state { checker: Address }
init(c: Address) { self.checker = c }
pub fn transfer(to: Address, amount: u128) {
let ok = self.checker.canTransfer(to, amount)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = declared_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "empty externalChecker must not count as declared; got {violations:?}"
    );
}
