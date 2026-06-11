//! Tests for SAFETY-005 — Blacklist Governance.
//!
//! A function that writes a transfer-deny restriction field keyed by a function
//! parameter (a per-address blacklist) must be `@onlyRole("GOVERNANCE")`.
//! `@onlyOwner` / unguarded ⇒ `UngovernedBlacklist`.
//!
//! Distinction from SAFETY-009: 005 is per-address (param-keyed write); 009 is a
//! global boolean gate. A non-param-keyed bool flag does NOT trigger 005.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as blacklist_check;

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn blacklist_governance_gated_map_passes() {
    // frozen[addr] is read to deny on transfer; setter is GOVERNANCE-gated → safe.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { frozen: Map<Address, bool> }
init() {}
@onlyRole("GOVERNANCE") pub fn setFrozen(addr: Address, val: bool) {
self.frozen[addr] = val
}
pub fn transfer(to: Address, amount: u128) {
assert (!self.frozen[to])
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = blacklist_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "governance-gated blacklist must pass SAFETY-005; got {violations:?}"
    );
}

#[test]
fn blacklist_no_restriction_field_passes() {
    // No deny-gating field on the transfer path → no restriction functions.
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
    let violations = blacklist_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "contract with no blacklist must pass SAFETY-005; got {violations:?}"
    );
}

#[test]
fn blacklist_global_bool_flag_not_param_keyed_passes() {
    // A GLOBAL bool gate (paused) written WITHOUT a param key is SAFETY-009's
    // concern, not 005 — 005 only fires on param-keyed (per-address) writes.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { paused: bool = false }
init() {}
@onlyOwner pub fn pause() {
self.paused = true
}
pub fn transfer(to: Address, amount: u128) {
assert (!self.paused)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = blacklist_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "global bool flag (non-param-keyed) is not a SAFETY-005 blacklist; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn blacklist_owner_only_map_write_rejected() {
    // @onlyOwner setFrozen(addr) writing frozen[addr] (read-to-deny) → violation.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { frozen: Map<Address, bool> }
init() {}
@onlyOwner pub fn setFrozen(addr: Address, val: bool) {
self.frozen[addr] = val
}
pub fn transfer(to: Address, amount: u128) {
assert (!self.frozen[to])
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = blacklist_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "owner-only blacklist setter must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UngovernedBlacklist { func } if func == "setFrozen"),
        "expected UngovernedBlacklist naming setFrozen; got {:?}",
        violations[0]
    );
}

#[test]
fn blacklist_owner_only_set_add_rejected() {
    // @onlyOwner blacklist(addr) via Set.add(addr) where blacklisted is read on
    // transfer via .contains() → violation.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { blacklisted: Set<Address> }
init() {}
@onlyOwner pub fn blacklist(addr: Address) {
self.blacklisted.add(addr)
}
pub fn transfer(to: Address, amount: u128) {
assert (!self.blacklisted.contains(to))
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = blacklist_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "owner-only Set.add blacklist must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UngovernedBlacklist { func } if func == "blacklist"),
        "expected UngovernedBlacklist naming blacklist; got {:?}",
        violations[0]
    );
}

#[test]
fn blacklist_unguarded_write_rejected() {
    // Unguarded (no annotation) blacklist setter → violation (weaker than owner).
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { frozen: Map<Address, bool> }
init() {}
pub fn setFrozen(addr: Address, val: bool) {
self.frozen[addr] = val
}
pub fn transfer(to: Address, amount: u128) {
assert (!self.frozen[to])
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = blacklist_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "unguarded blacklist setter must be rejected; got {violations:?}"
    );
}

#[test]
fn blacklist_non_governance_role_rejected() {
    // @onlyRole("ADMIN") (non-governance) blacklist setter → violation.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { frozen: Map<Address, bool> }
init() {}
@onlyRole("ADMIN") pub fn setFrozen(addr: Address, val: bool) {
self.frozen[addr] = val
}
pub fn transfer(to: Address, amount: u128) {
assert (!self.frozen[to])
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = blacklist_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "@onlyRole(\"ADMIN\") blacklist setter (non-governance) must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UngovernedBlacklist { .. }),
        "expected UngovernedBlacklist; got {:?}",
        violations[0]
    );
}

#[test]
fn blacklist_non_param_key_not_flagged() {
    // A write to a restriction field with a NON-param key (a hardcoded address
    // or self-derived key) is not a per-address blacklist keyed by a caller
    // parameter — it must NOT trigger 005 (only param-keyed writes do).
    // Here `setFrozen` writes frozen[msg.sender]-style via a local, not a param.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { frozen: Map<Address, bool> }
init() {}
@onlyOwner pub fn freezeSelf() {
let me = self.address
self.frozen[me] = true
}
pub fn transfer(to: Address, amount: u128) {
assert (!self.frozen[to])
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = blacklist_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "non-param-keyed restriction write must NOT trigger SAFETY-005; got {violations:?}"
    );
}
