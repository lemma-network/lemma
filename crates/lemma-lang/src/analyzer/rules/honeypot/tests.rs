//! Tests for SAFETY-001 — Anti-Honeypot (disposal-path existence).
//!
//! Fires unconditionally for all token contracts (DB-A57).  Enforces
//! disposal-path accessibility: a public `transfer` (and `transferFrom` if
//! present) must exist and be access-unrestricted.

use crate::analyzer::error::SafetyError;
use crate::{parse, tokenize};

use super::check as honeypot_check;

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn honeypot_public_transfer_passes() {
    // Public unrestricted transfer → safe (SAFETY-001 fires for all tokens).
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
    let violations = honeypot_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "public unrestricted transfer must pass SAFETY-001; got {violations:?}"
    );
}

#[test]
fn honeypot_public_transfer_and_transfer_from_passes() {
    // Both transfer and transferFrom public → safe.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
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
    let violations = honeypot_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "public transfer + transferFrom must pass; got {violations:?}"
    );
}

// ─── Negative tests (violations → Honeypot) ──────────────────────────────────

#[test]
fn honeypot_missing_transfer_rejected() {
    // Token with NO transfer function → holders cannot sell.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
init() {}
@onlyOwner pub fn mint(to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = honeypot_check(&contracts[0]);
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::Honeypot { reason } if reason.contains("no `transfer`"))
        ),
        "missing transfer must be a honeypot; got {violations:?}"
    );
}

#[test]
fn honeypot_owner_gated_transfer_rejected() {
    // transfer exists but is @onlyOwner — holders cannot freely sell.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
init() {}
@onlyOwner pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = honeypot_check(&contracts[0]);
    assert!(
        violations.iter().any(|v| matches!(v, SafetyError::Honeypot { reason } if reason.contains("`transfer` is access-restricted"))),
        "@onlyOwner transfer must be a honeypot; got {violations:?}"
    );
}

#[test]
fn honeypot_role_gated_transfer_rejected() {
    // transfer gated by @onlyRole — also blocks free disposal.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
init() {}
@onlyRole("ADMIN") pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = honeypot_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::Honeypot { .. })),
        "@onlyRole transfer must be a honeypot; got {violations:?}"
    );
}

#[test]
fn honeypot_owner_gated_transfer_from_rejected() {
    // transfer is public but transferFrom is @onlyOwner — gated delegated sell.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
init() {}
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
@onlyOwner pub fn transferFrom(from: Address, to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = honeypot_check(&contracts[0]);
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::Honeypot { reason } if reason.contains("transferFrom"))
        ),
        "@onlyOwner transferFrom must be a honeypot; got {violations:?}"
    );
}

#[test]
fn honeypot_restricted_mint_with_public_transfer_passes() {
    // CRITICAL false-positive guard (CR finding): a legitimate @onlyOwner mint
    // (acquisition-side, restricting is normal) alongside a public transfer must
    // NOT be flagged. Restricting acquisition never blocks a sell (spec §3-001
    // step 1 vs step 2). A direction-blind "restricted balance-mutator" check
    // would wrongly reject every mintable token — this test pins that the rule
    // does NOT do that.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 mintable: true }
state { balances: Map<Address, u128> }
init() {}
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
@onlyOwner pub fn mint(to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = honeypot_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "@onlyOwner mint (acquisition-side) with public transfer must NOT be a honeypot; got {violations:?}"
    );
}

#[test]
fn honeypot_extra_public_mutator_passes() {
    // Public transfer + a public (unrestricted) extra balance-mutator → safe.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
init() {}
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
pub fn burn(holder: Address, amount: u128) {
self.balances[holder] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = honeypot_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "extra public balance-mutator must pass; got {violations:?}"
    );
}

#[test]
fn check_fires_for_token_without_flag() {
    // DB-A57: SAFETY-001 fires unconditionally — a token with NO antiHoneypot
    // config key and no transfer function must still produce a violation.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
init() {}
@onlyOwner pub fn adminMove(to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = honeypot_check(&contracts[0]);
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::Honeypot { reason } if reason.contains("no `transfer`"))
        ),
        "token without antiHoneypot flag must still fire SAFETY-001; got {violations:?}"
    );
}
