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
//!
//! ## Config note (WF-014)
//!
//! All token configs include the mandatory Token keys (name, symbol, decimals,
//! maxSupply) per WF-014.  Supply-cap-specific keys (mintable, maxSupply) are
//! added on top.  When testing `mintable: false` without a `maxSupply` cap,
//! `maxSupply` is still present as a mandatory key (the supply_cap rule reads
//! `mintable` and `maxSupply` independently).

use crate::analyzer::error::SafetyError;
use crate::{parse, tokenize};

use super::check as supply_cap_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn supply_cap_mintable_false_no_writes_passes() {
    // mintable: false token with no totalSupply writes → passes.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 mintable: false }
state { totalSupply: u128 = 0 }
init() {}
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
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 mintable: false }
state { totalSupply: u128 = 0 }
init() {}
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
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { totalSupply: u128 = 0 }
init() {}
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
state { totalSupply: u128 = 0 }
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
    // Note: maxSupply is also set (mandatory per WF-014), so the supply_cap rule
    // fires twice: once for mintable:false and once for the missing cap assert.
    // We verify at least one violation mentions mintable:false.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 mintable: false }
state { totalSupply: u128 = 0 }
init() {}
pub fn mint(amount: u128) {
self.totalSupply += amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert!(
        !violations.is_empty(),
        "mintable:false + += must produce violations; got {violations:?}"
    );
    assert!(
        violations.iter().any(|v| matches!(v, SafetyError::SupplyCapViolation { reason } if reason.contains("mintable: false"))),
        "at least one violation must mention mintable:false; got {violations:?}"
    );
}

#[test]
fn supply_cap_mintable_false_with_plain_add_rejected() {
    // mintable: false + self.totalSupply = self.totalSupply + amount → SupplyCapViolation.
    // Note: maxSupply is also set (mandatory per WF-014), so multiple violations may fire.
    // We verify at least one SupplyCapViolation is produced.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 mintable: false }
state { totalSupply: u128 = 0 }
init() {}
pub fn mint(amount: u128) {
self.totalSupply = self.totalSupply + amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert!(
        !violations.is_empty(),
        "mintable:false + plain add must produce violations; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::SupplyCapViolation { .. })),
        "at least one violation must be SupplyCapViolation; got {violations:?}"
    );
}

#[test]
fn supply_cap_max_supply_without_assert_rejected() {
    // maxSupply declared + totalSupply += without preceding assert → SupplyCapViolation.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { totalSupply: u128 = 0 }
init() {}
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

// ─── Nested-write tests (BLOCKER 1 regression — CR 2026-06-08) ───────────────

#[test]
fn supply_cap_max_supply_nested_write_without_assert_rejected() {
    // Mint hidden inside an if block with no preceding cap assert → must be
    // caught (this was the BLOCKER: has_cap_assert_before_write returned
    // true for nested writes before the fix).
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { totalSupply: u128 = 0, enabled: bool = false }
init() {}
pub fn mint(amount: u128) {
if (self.enabled) {
self.totalSupply += amount
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "nested mint inside if with no cap assert must be SAFETY-003 violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::SupplyCapViolation { reason } if reason.contains("not dominated")),
        "violation must mention missing cap check; got {:?}",
        violations[0]
    );
}

#[test]
fn supply_cap_max_supply_nested_write_with_enclosing_assert_passes() {
    // Enclosing assert (before the if) covers nested write — must pass.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { totalSupply: u128 = 0, enabled: bool = false }
init() {}
pub fn mint(amount: u128) {
assert(self.totalSupply + amount <= 1000000)
if (self.enabled) {
self.totalSupply += amount
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = supply_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "enclosing assert before if covers nested write — must pass; got {violations:?}"
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn supply_cap_max_supply_assert_after_write_rejected() {
    // Assert AFTER the write (not before) → not a cap guard → violation.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { totalSupply: u128 = 0 }
init() {}
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
    // mintable: true (default) with a cap assert before the write → passes.
    // Note: maxSupply is present as a mandatory Token config key (WF-014), so
    // the supply_cap rule requires a cap assert before totalSupply writes.
    // We add the assert to satisfy SAFETY-003 while testing mintable:true behavior.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 mintable: true }
state { totalSupply: u128 = 0 }
init() {}
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
        "mintable:true with cap assert must pass SAFETY-003; got {violations:?}"
    );
}
