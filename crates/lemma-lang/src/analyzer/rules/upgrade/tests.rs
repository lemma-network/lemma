//! Tests for SAFETY-007 — Upgrade Safety.
//!
//! ## Scope (spec §3-007, §13)
//!
//! Compile-time decidable core: when `config.upgradeable == true`, any function
//! that mutates the `upgradeable` capability state must be GOVERNANCE-gated.
//! `@onlyOwner` / unguarded ⇒ `UnsafeUpgrade`.
//!
//! Tier-2 / runtime (NOT tested here — not compile-time decidable, per spec):
//! storage-layout prefix-compat (needs prior version), timelock magnitude
//! (VM-enforced), RATCHET-OFF flag enforcement (runtime).
//!
//! ## Config note (WF-014)
//!
//! All token configs include the mandatory Token keys (name, symbol, decimals,
//! maxSupply); `upgradeable` is an optional capability flag added on top.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as upgrade_check;

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn upgrade_not_upgradeable_passes() {
    // upgradeable: false — rule does not fire regardless of owner-only setters.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 upgradeable: false }
state { upgradeable: bool = false }
init() {}
@onlyOwner pub fn lockUpgrade() {
self.upgradeable = false
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = upgrade_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "upgradeable:false must not trigger SAFETY-007; got {violations:?}"
    );
}

#[test]
fn upgrade_governance_gated_lever_passes() {
    // upgradeable: true with the upgrade lever gated by GOVERNANCE → safe.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 upgradeable: true }
state { upgradeable: bool = true }
init() {}
@onlyRole("GOVERNANCE") pub fn disableUpgrade() {
self.upgradeable = false
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = upgrade_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "GOVERNANCE-gated upgrade lever must pass SAFETY-007; got {violations:?}"
    );
}

#[test]
fn upgrade_upgradeable_true_no_lever_passes() {
    // upgradeable: true but no function writes the upgrade capability → nothing
    // to gate, so no violation (the capability is immutable from contract code).
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 upgradeable: true }
state { upgradeable: bool = true }
init() {}
pub fn transfer(to: Address, amount: u128) {
let x = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = upgrade_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "upgradeable:true with no lever must pass SAFETY-007; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn upgrade_owner_only_lever_rejected() {
    // upgradeable: true with an @onlyOwner upgrade lever → UnsafeUpgrade.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 upgradeable: true }
state { upgradeable: bool = true }
init() {}
@onlyOwner pub fn disableUpgrade() {
self.upgradeable = false
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = upgrade_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "owner-only upgrade lever must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UnsafeUpgrade { reason } if reason.contains("disableUpgrade")),
        "expected UnsafeUpgrade naming the lever; got {:?}",
        violations[0]
    );
}

#[test]
fn upgrade_unguarded_lever_rejected() {
    // upgradeable: true with an UNGUARDED (no annotation) upgrade lever →
    // UnsafeUpgrade (unguarded is even weaker than @onlyOwner).
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 upgradeable: true }
state { upgradeable: bool = true }
init() {}
pub fn disableUpgrade() {
self.upgradeable = false
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = upgrade_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "unguarded upgrade lever must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UnsafeUpgrade { .. }),
        "expected UnsafeUpgrade; got {:?}",
        violations[0]
    );
}

#[test]
fn upgrade_non_governance_role_lever_rejected() {
    // @onlyRole("ADMIN") is a role but NOT the GOVERNANCE role → UnsafeUpgrade.
    // (requires_governance is proven to reject non-GOVERNANCE roles in
    // authset/tests.rs; this pins the behavior at the SAFETY-007 rule path.)
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 upgradeable: true }
state { upgradeable: bool = true }
init() {}
@onlyRole("ADMIN") pub fn disableUpgrade() {
self.upgradeable = false
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = upgrade_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "@onlyRole(\"ADMIN\") lever (non-governance) must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UnsafeUpgrade { .. }),
        "expected UnsafeUpgrade for non-governance role; got {:?}",
        violations[0]
    );
}

#[test]
fn upgrade_transitive_owner_only_lever_rejected() {
    // The lever is reached transitively: @onlyOwner outer() calls inner() which
    // writes the capability. state_write_reachability marks outer as a writer,
    // so outer's @onlyOwner gate is the violation.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 upgradeable: true }
state { upgradeable: bool = true }
init() {}
@onlyOwner pub fn adminDisable() {
let _ = self.doDisable()
}
fn doDisable() {
self.upgradeable = false
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = upgrade_check(&contracts[0]);
    // Both adminDisable (transitive writer, @onlyOwner) and doDisable (direct
    // writer, unguarded) are levers — each lacking GOVERNANCE is a violation.
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::UnsafeUpgrade { reason } if reason.contains("adminDisable"))),
        "transitive @onlyOwner lever `adminDisable` must be rejected; got {violations:?}"
    );
}
