//! Tests for SAFETY-009 — One-Way Gates.
//!
//! Covers the four gating-condition shapes (assert positive/negated, if-revert
//! positive/negated) for blocking-polarity inference, plus the legitimate
//! one-way `enableTrading()` (permitting write → no violation) and the
//! governance-gated disable (allowed).

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as one_way_gate_check;

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn one_way_gate_enable_only_passes() {
    // `enableTrading()` sets tradingEnabled = true (the PERMITTING value).
    // transfer asserts self.tradingEnabled (blocking value = false).
    // No function writes the blocking value → safe one-way gate.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { tradingEnabled: bool = false }
init() {}
@onlyOwner pub fn enableTrading() {
self.tradingEnabled = true
}
pub fn transfer(to: Address, amount: u128) {
assert (self.tradingEnabled)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "enable-only one-way gate must pass SAFETY-009; got {violations:?}"
    );
}

#[test]
fn one_way_gate_governance_disable_passes() {
    // A function CAN set the blocking value, but it is GOVERNANCE-gated → allowed.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { tradingEnabled: bool = false }
init() {}
@onlyRole("GOVERNANCE") pub fn disableTrading() {
self.tradingEnabled = false
}
pub fn transfer(to: Address, amount: u128) {
assert (self.tradingEnabled)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "governance-gated disable must pass SAFETY-009; got {violations:?}"
    );
}

#[test]
fn one_way_gate_non_gating_bool_flag_passes() {
    // A boolean field that is NOT read on the transfer path is not a gating flag;
    // owner writing it freely is fine.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { featureOn: bool = false }
init() {}
@onlyOwner pub fn toggle() {
self.featureOn = false
}
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "non-gating bool flag must not trigger SAFETY-009; got {violations:?}"
    );
}

// ─── Negative tests — assert-positive gate (blocking = false) ────────────────

#[test]
fn one_way_gate_owner_disable_assert_positive_rejected() {
    // transfer asserts self.tradingEnabled (blocking = false).
    // @onlyOwner disableTrading sets it to false (blocking) → OneWayGate.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { tradingEnabled: bool = false }
init() {}
@onlyOwner pub fn disableTrading() {
self.tradingEnabled = false
}
pub fn transfer(to: Address, amount: u128) {
assert (self.tradingEnabled)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "owner-flippable trading gate must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::OneWayGate { func } if func == "disableTrading"),
        "expected OneWayGate naming disableTrading; got {:?}",
        violations[0]
    );
}

// ─── Negative tests — assert-negated gate (blocking = true) ──────────────────

#[test]
fn one_way_gate_owner_pause_assert_negated_rejected() {
    // transfer asserts !self.paused (blocking value = true).
    // @onlyOwner pause() sets paused = true (blocking) → OneWayGate.
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
    let violations = one_way_gate_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "owner-flippable pause gate must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::OneWayGate { func } if func == "pause"),
        "expected OneWayGate naming pause; got {:?}",
        violations[0]
    );
}

// ─── Negative tests — if-revert gate (blocking = true) ───────────────────────

#[test]
fn one_way_gate_owner_block_if_revert_rejected() {
    // transfer: if (self.blocked) { revert } (blocking value = true).
    // @onlyOwner setBlocked sets blocked = true (blocking) → OneWayGate.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { blocked: bool = false }
init() {}
@onlyOwner pub fn setBlocked() {
self.blocked = true
}
pub fn transfer(to: Address, amount: u128) {
if (self.blocked) {
revert "blocked"
}
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "owner if-revert gate must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::OneWayGate { func } if func == "setBlocked"),
        "expected OneWayGate naming setBlocked; got {:?}",
        violations[0]
    );
}

// ─── Negative tests — permitting write NOT flagged (polarity correctness) ────

#[test]
fn one_way_gate_permitting_write_not_flagged() {
    // The CRITICAL polarity test: with assert(self.tradingEnabled) (blocking =
    // false), an @onlyOwner function that writes the PERMITTING value (true)
    // must NOT be flagged — only blocking-value writers are violations.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { tradingEnabled: bool = false }
init() {}
@onlyOwner pub fn enableTrading() {
self.tradingEnabled = true
}
@onlyOwner pub fn reEnable() {
self.tradingEnabled = true
}
pub fn transfer(to: Address, amount: u128) {
assert (self.tradingEnabled)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "owner functions that only ENABLE (permitting value) must not be flagged; got {violations:?}"
    );
}

// ─── Soundness regression: comparison-to-literal gating (CR BLOCKER fix) ─────

#[test]
fn one_way_gate_comparison_eq_false_honeypot_rejected() {
    // CR-found honeypot: `assert(self.paused == false)` is semantically
    // `assert(!self.paused)` (blocking value = true). An @onlyOwner pause()
    // that sets paused = true is a re-blocking honeypot.
    //
    // The naive parity scan would infer blocking=false from the `==` and MISS
    // the pause() writer (false-negative). The opaque-read fix treats the
    // comparison read as Both → rejects on doubt.
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
assert (self.paused == false)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "comparison-to-literal gate honeypot must be rejected (opaque-read fix); got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::OneWayGate { func } if func == "pause"),
        "expected OneWayGate naming pause; got {:?}",
        violations[0]
    );
}

#[test]
fn one_way_gate_comparison_if_revert_honeypot_rejected() {
    // `if (self.tradingEnabled == false) { revert }` — comparison gate.
    // @onlyOwner disable sets tradingEnabled = false. Opaque read → reject.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { tradingEnabled: bool = false }
init() {}
@onlyOwner pub fn disable() {
self.tradingEnabled = false
}
pub fn transfer(to: Address, amount: u128) {
if (self.tradingEnabled == false) {
revert "disabled"
}
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "comparison if-revert gate honeypot must be rejected; got {violations:?}"
    );
}

#[test]
fn one_way_gate_non_literal_flip_write_rejected() {
    // CR-found: `self.tradingEnabled = !self.tradingEnabled` (non-literal) can
    // set the blocking value. transfer asserts self.tradingEnabled (blocking =
    // false). An @onlyOwner flip() that writes a non-literal must be rejected
    // (reject on doubt — value can't be statically pinned).
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { tradingEnabled: bool = true }
init() {}
@onlyOwner pub fn flip() {
self.tradingEnabled = !self.tradingEnabled
}
pub fn transfer(to: Address, amount: u128) {
assert (self.tradingEnabled)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "non-literal flip write to a gating flag must be rejected; got {violations:?}"
    );
}

#[test]
fn one_way_gate_and_combinator_gate_rejected() {
    // `&&` combinator keeps clean polarity: assert(self.tradingEnabled && cond).
    // blocking value = false; @onlyOwner disable sets false → rejected.
    // Confirms the &&/|| clean-path still works after the opaque-read fix.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { tradingEnabled: bool = false }
state { setupDone: bool = false }
init() {}
@onlyOwner pub fn disableTrading() {
self.tradingEnabled = false
}
pub fn transfer(to: Address, amount: u128) {
assert (self.tradingEnabled && self.setupDone)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::OneWayGate { func } if func == "disableTrading")),
        "&& clean-polarity gate must still reject the disable writer; got {violations:?}"
    );
}

#[test]
fn one_way_gate_non_governance_role_rejected() {
    // @onlyRole("ADMIN") (non-governance) disabling trading → OneWayGate.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { tradingEnabled: bool = false }
init() {}
@onlyRole("ADMIN") pub fn disableTrading() {
self.tradingEnabled = false
}
pub fn transfer(to: Address, amount: u128) {
assert (self.tradingEnabled)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "@onlyRole(\"ADMIN\") disable (non-governance) must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::OneWayGate { .. }),
        "expected OneWayGate; got {:?}",
        violations[0]
    );
}

// ─── BUG-C2 — spec §2.1: renounce-aware does NOT skip SAFETY-009 ─────────────

#[test]
fn fake_renounce_does_not_disable_safety_009() {
    // (neg) C2: `renounce(){ self.owner = self.owner }` (no-op write) does NOT disable SAFETY-009.
    // Spec §2.1: "static rule remains conservative — owner-settable restriction is a
    // violation regardless of whether the deployer later renounces."
    // The renounce-aware skip was reverted; SAFETY-009 must flag unconditionally.
    let ast = typed_ast(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }
state { balances: Map<Address, u128> }
state { tradingEnabled: bool = false }
init() {}
pub fn renounce() {
    self.owner = self.owner
}
@onlyOwner pub fn disableTrading() {
self.tradingEnabled = false
}
pub fn transfer(to: Address, amount: u128) {
assert (self.tradingEnabled)
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = one_way_gate_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::OneWayGate { func } if func == "disableTrading")),
        "Renounce-aware contract with @onlyOwner gate lever must still fail SAFETY-009 (spec §2.1); got {violations:?}"
    );
}
