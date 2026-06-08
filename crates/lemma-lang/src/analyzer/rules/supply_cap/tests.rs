//! Tests for SAFETY-003 — Supply Cap rule.
//!
//! ## Inconclusive coverage (spec §5.2)
//!
//! SAFETY-003 is **decidable-exact** for the 4e scope: `mintable: false` +
//! increasing write is a definite violation; `maxSupply` + no preceding assert
//! is a definite violation.  No `Inconclusive` path exists in 4e.
//!
//! ## Scoping note
//!
//! Cap-assert detection is conservative (linear scan, any `<=`/`<` assert
//! before the write).  Full dominator tree analysis is 4g work.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as supply_cap_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn supply_cap_mintable_false_no_writes_passes() {
    // mintable: false token with no totalSupply writes → passes.
    let ast = typed_ast(
        r#"token T extends Token {
config { mintable: false }
state { totalSupply: u128 }
pub fn transfer(to: Address, amount: u128) {
let x = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "mintable:false with no writes must pass SAFETY-003; got {violations:?}"
    );
}

#[test]
fn supply_cap_mintable_false_burn_only_passes() {
    // mintable: false with only totalSupply -= (burn, no +=) → passes.
    let ast = typed_ast(
        r#"token T extends Token {
config { mintable: false }
state { totalSupply: u128 }
pub fn burn(amount: u128) {
self.totalSupply = self.totalSupply - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "mintable:false with burn-only must pass SAFETY-003; got {violations:?}"
    );
}

#[test]
fn supply_cap_max_supply_with_preceding_assert_passes() {
    // maxSupply declared + assert before totalSupply += → passes.
    let ast = typed_ast(
        r#"token T extends Token {
config { maxSupply: 1000000 }
state { totalSupply: u128 }
pub fn mint(amount: u128) {
assert(self.totalSupply + amount <= 1000000)
self.totalSupply += amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "maxSupply with preceding assert must pass SAFETY-003; got {violations:?}"
    );
}

#[test]
fn supply_cap_no_config_block_passes() {
    // Plain contract with no config block — rule does not apply.
    let ast = typed_ast(
        r#"contract C {
state { totalSupply: u128 }
pub fn mint(amount: u128) {
self.totalSupply += amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "contract with no config block must pass SAFETY-003; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn supply_cap_mintable_false_with_add_assign_rejected() {
    // mintable: false + self.totalSupply += amount → SupplyCapViolation.
    let ast = typed_ast(
        r#"token T extends Token {
config { mintable: false }
state { totalSupply: u128 }
pub fn mint(amount: u128) {
self.totalSupply += amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "mintable:false + += must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::SupplyCapViolation { reason } if reason.contains("mintable: false")),
        "violation must be SupplyCapViolation mentioning mintable:false; got {:?}",
        violations[0]
    );
}

#[test]
fn supply_cap_mintable_false_with_plain_add_rejected() {
    // mintable: false + self.totalSupply = self.totalSupply + amount → SupplyCapViolation.
    let ast = typed_ast(
        r#"token T extends Token {
config { mintable: false }
state { totalSupply: u128 }
pub fn mint(amount: u128) {
self.totalSupply = self.totalSupply + amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "mintable:false + plain add must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::SupplyCapViolation { .. }),
        "violation must be SupplyCapViolation; got {:?}",
        violations[0]
    );
}

#[test]
fn supply_cap_max_supply_without_assert_rejected() {
    // maxSupply declared + totalSupply += without preceding assert → SupplyCapViolation.
    let ast = typed_ast(
        r#"token T extends Token {
config { maxSupply: 1000000 }
state { totalSupply: u128 }
pub fn mint(amount: u128) {
self.totalSupply += amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "maxSupply without preceding assert must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::SupplyCapViolation { reason } if reason.contains("not dominated")),
        "violation must be SupplyCapViolation mentioning cap check; got {:?}",
        violations[0]
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn supply_cap_max_supply_assert_after_write_rejected() {
    // Assert AFTER the write (not before) → not a cap guard → violation.
    let ast = typed_ast(
        r#"token T extends Token {
config { maxSupply: 1000000 }
state { totalSupply: u128 }
pub fn mint(amount: u128) {
self.totalSupply += amount
assert(self.totalSupply <= 1000000)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "assert after write must not count as cap guard; got {violations:?}"
    );
}

#[test]
fn supply_cap_mintable_true_no_max_supply_passes() {
    // mintable: true (default) with no maxSupply — rule does not apply.
    let ast = typed_ast(
        r#"token T extends Token {
config { mintable: true }
state { totalSupply: u128 }
pub fn mint(amount: u128) {
self.totalSupply += amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "mintable:true with no maxSupply must pass SAFETY-003; got {violations:?}"
    );
}
