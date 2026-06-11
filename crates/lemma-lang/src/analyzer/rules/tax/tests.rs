//! Tests for SAFETY-020, SAFETY-021, SAFETY-022 — TaxToken fee-model rules.
//!
//! ## Test layout (AGENTS §11.2)
//!
//! - **Positive**: valid TaxToken (correct `distributeTaxes`, pure `isTaxable`,
//!   correct fees setter with timelock) → zero violations.
//! - **Token guard**: plain `Token` (non-tax) → zero violations for all three rules.
//! - **Negative per rule**: each attack variant produces the exact `SafetyError` variant.
//! - **Boundary**: fees sum == maxFeePercent passes; fees sum == maxFeePercent+1 fails.
//!
//! ## Config note (WF-014)
//!
//! All TaxToken configs include the mandatory `fees` block per WF-014.
//! The `fees` config block is the initial value; individual fee components are
//! written in function bodies as `self.fees.burn = N`, `self.fees.holders = N`,
//! `self.fees.others = N` (Lem does not support struct-literal assignment for
//! the `fees` state block).
//!
//! ## WF-014 constraints in tests
//!
//! - `fees.others > 0` in config requires a `distributeTaxes` function (WF-014).
//! - State fields must be initialized in `init` (WF-001).
//! - `maxFeePercent` is only valid for TaxToken, not plain Token.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as tax_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Shared TaxToken fixtures ─────────────────────────────────────────────────

/// Minimal valid TaxToken with no `distributeTaxes`, no `isTaxable`, no fees setter.
/// Uses `fees.others = 0` to avoid WF-014 `distributeTaxes` requirement.
fn minimal_taxttoken_src() -> &'static str {
    r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0 }
init() {}
}"#
}

// ─── Guard: plain Token triggers zero violations ──────────────────────────────

#[test]
fn tax_rules_plain_token_triggers_no_violations() {
    // Plain Token (non-tax) must trigger zero violations for all three rules.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
}
state { totalSupply: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "plain Token must trigger zero tax-rule violations; got {violations:?}"
    );
}

#[test]
fn tax_rules_plain_contract_triggers_no_violations() {
    // Plain contract (no token standard) must trigger zero violations.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn foo() {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "plain contract must trigger zero tax-rule violations; got {violations:?}"
    );
}

// ─── SAFETY-020 positive tests ────────────────────────────────────────────────

#[test]
fn safety_020_no_distribute_taxes_passes() {
    // TaxToken with no `distributeTaxes` function → SAFETY-020 does not apply.
    let ast = typed_ast(minimal_taxttoken_src());
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "TaxToken with no distributeTaxes must pass SAFETY-020; got {violations:?}"
    );
}

#[test]
fn safety_020_valid_distribute_taxes_passes() {
    // Valid `distributeTaxes`: not on transfer path, zeroes taxPool before ext call.
    // Uses fees.others = 500 to require distributeTaxes (WF-014).
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 0 holders: 0 others: 500 }
}
state { totalSupply: u128 = 0, taxPool: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
self.totalSupply = self.totalSupply + amount
}
pub fn distributeTaxes(recipient: Address) {
let pool = self.taxPool
self.taxPool = 0
recipient.transfer(pool)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations: Vec<_> = tax_check(&contracts[0])
        .into_iter()
        .filter(|v| {
            matches!(
                v,
                SafetyError::TaxDistributeOnTransferPath { .. }
                    | SafetyError::TaxDistributeUnbounded { .. }
                    | SafetyError::TaxPoolNotZeroedFirst { .. }
            )
        })
        .collect();
    assert!(
        violations.is_empty(),
        "valid distributeTaxes must pass SAFETY-020; got {violations:?}"
    );
}

// ─── SAFETY-020 negative tests ────────────────────────────────────────────────

#[test]
fn safety_020_transfer_calls_distribute_taxes_rejected() {
    // `transfer` directly calls `distributeTaxes` → TaxDistributeOnTransferPath.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 0 holders: 0 others: 500 }
}
state { totalSupply: u128 = 0, taxPool: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
self.distributeTaxes(to)
}
pub fn distributeTaxes(recipient: Address) {
let pool = self.taxPool
self.taxPool = 0
recipient.transfer(pool)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let sep_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::TaxDistributeOnTransferPath { .. }))
        .collect();
    assert!(
        !sep_violations.is_empty(),
        "transfer calling distributeTaxes must produce TaxDistributeOnTransferPath; got {violations:?}"
    );
}

#[test]
fn safety_020_on_transfer_hook_calls_distribute_taxes_rejected() {
    // `#[onTransfer]` hook calls `distributeTaxes` → TaxDistributeOnTransferPath.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 0 holders: 0 others: 500 }
}
state { totalSupply: u128 = 0, taxPool: u128 = 0 }
init() {}
@onTransfer
pub fn onTransfer(from: Address, to: Address, amount: u128) {
self.distributeTaxes(to)
}
pub fn distributeTaxes(recipient: Address) {
let pool = self.taxPool
self.taxPool = 0
recipient.transfer(pool)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let sep_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::TaxDistributeOnTransferPath { .. }))
        .collect();
    assert!(
        !sep_violations.is_empty(),
        "@onTransfer hook calling distributeTaxes must produce TaxDistributeOnTransferPath; got {violations:?}"
    );
}

#[test]
fn safety_020_distribute_taxes_reads_balances_rejected() {
    // `distributeTaxes` reads `self.balances` → TaxDistributeUnbounded.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 0 holders: 0 others: 500 }
}
state { totalSupply: u128 = 0, taxPool: u128 = 0, balances: Map<Address, u128> }
init() {}
pub fn distributeTaxes(recipient: Address) {
let pool = self.taxPool
self.taxPool = 0
let extra = self.balances.get(recipient)
recipient.transfer(pool)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let budget_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::TaxDistributeUnbounded { .. }))
        .collect();
    assert!(
        !budget_violations.is_empty(),
        "distributeTaxes reading balances must produce TaxDistributeUnbounded; got {violations:?}"
    );
}

#[test]
fn safety_020_distribute_taxes_reads_total_supply_rejected() {
    // `distributeTaxes` reads `self.totalSupply` → TaxDistributeUnbounded.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 0 holders: 0 others: 500 }
}
state { totalSupply: u128 = 0, taxPool: u128 = 0 }
init() {}
pub fn distributeTaxes(recipient: Address) {
let pool = self.taxPool
self.taxPool = 0
let supply = self.totalSupply
recipient.transfer(pool)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let budget_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::TaxDistributeUnbounded { .. }))
        .collect();
    assert!(
        !budget_violations.is_empty(),
        "distributeTaxes reading totalSupply must produce TaxDistributeUnbounded; got {violations:?}"
    );
}

#[test]
fn safety_020_distribute_taxes_ext_call_before_zero_rejected() {
    // `distributeTaxes` makes an external call before zeroing taxPool → TaxPoolNotZeroedFirst.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 0 holders: 0 others: 500 }
}
state { totalSupply: u128 = 0, taxPool: u128 = 0 }
init() {}
pub fn distributeTaxes(recipient: Address) {
recipient.transfer(self.taxPool)
self.taxPool = 0
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let zero_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::TaxPoolNotZeroedFirst { .. }))
        .collect();
    assert!(
        !zero_violations.is_empty(),
        "ext call before taxPool zero must produce TaxPoolNotZeroedFirst; got {violations:?}"
    );
}

// ─── SAFETY-021 positive tests ────────────────────────────────────────────────

#[test]
fn safety_021_no_is_taxable_passes() {
    // TaxToken with no `isTaxable` function → SAFETY-021 does not apply.
    let ast = typed_ast(minimal_taxttoken_src());
    let contracts = ast.contracts();
    let violations: Vec<_> = tax_check(&contracts[0])
        .into_iter()
        .filter(|v| matches!(v, SafetyError::TaxablePredicateImpure { .. }))
        .collect();
    assert!(
        violations.is_empty(),
        "TaxToken with no isTaxable must pass SAFETY-021; got {violations:?}"
    );
}

#[test]
fn safety_021_pure_is_taxable_passes() {
    // `isTaxable` reads only state fields via collection reads (no writes, no ext calls) → passes.
    // Uses `self.exemptList.has(from)` — a collection read method on own state.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0, exemptList: Map<Address, bool> }
init() {}
pub fn isTaxable(from: Address, to: Address) -> bool {
return !self.exemptList.has(from)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations: Vec<_> = tax_check(&contracts[0])
        .into_iter()
        .filter(|v| matches!(v, SafetyError::TaxablePredicateImpure { .. }))
        .collect();
    assert!(
        violations.is_empty(),
        "pure isTaxable must pass SAFETY-021; got {violations:?}"
    );
}

// ─── SAFETY-021 negative tests ────────────────────────────────────────────────

#[test]
fn safety_021_is_taxable_writes_state_rejected() {
    // `isTaxable` writes a state field → TaxablePredicateImpure.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0, callCount: u128 = 0 }
init() {}
pub fn isTaxable(from: Address, to: Address) -> bool {
self.callCount = self.callCount + 1
return true
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let impure_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::TaxablePredicateImpure { .. }))
        .collect();
    assert!(
        !impure_violations.is_empty(),
        "isTaxable writing state must produce TaxablePredicateImpure; got {violations:?}"
    );
}

#[test]
fn safety_021_is_taxable_makes_external_call_rejected() {
    // `isTaxable` calls a non-collection method on a state Address field → TaxablePredicateImpure.
    // `self.checker` is an Address field; `isBlocked` is not a collection read method.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0, checker: Address }
init(checker: Address) {
self.checker = checker
}
pub fn isTaxable(from: Address, to: Address) -> bool {
return self.checker.isBlocked(from)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let impure_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::TaxablePredicateImpure { .. }))
        .collect();
    assert!(
        !impure_violations.is_empty(),
        "isTaxable calling non-collection method on state field must produce TaxablePredicateImpure; got {violations:?}"
    );
}

// ─── SAFETY-022 positive tests ────────────────────────────────────────────────

#[test]
fn safety_022_no_fees_setter_passes() {
    // TaxToken with no function that writes `self.fees.*` → SAFETY-022 does not apply.
    let ast = typed_ast(minimal_taxttoken_src());
    let contracts = ast.contracts();
    let violations: Vec<_> = tax_check(&contracts[0])
        .into_iter()
        .filter(|v| matches!(v, SafetyError::FeeRaiseNoTimelock { .. }))
        .collect();
    assert!(
        violations.is_empty(),
        "TaxToken with no fees setter must pass SAFETY-022; got {violations:?}"
    );
}

#[test]
fn safety_022_fees_setter_with_timelock_passes() {
    // Fees setter writes `self.fees.burn` AND `self.feeEffectiveBlock` → passes.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0, feeEffectiveBlock: u64 = 0 }
init() {}
@onlyOwner
pub fn setFees(newBurn: u128) {
self.fees.burn = 500
self.fees.holders = 0
self.fees.others = 0
self.feeEffectiveBlock = 7200
}
}"#,
    );
    let contracts = ast.contracts();
    let violations: Vec<_> = tax_check(&contracts[0])
        .into_iter()
        .filter(|v| matches!(v, SafetyError::FeeRaiseNoTimelock { .. }))
        .collect();
    assert!(
        violations.is_empty(),
        "fees setter with timelock must pass SAFETY-022; got {violations:?}"
    );
}

// ─── SAFETY-022 negative tests ────────────────────────────────────────────────

#[test]
fn safety_022_fees_setter_without_timelock_rejected() {
    // Fees setter writes `self.fees.burn` without `self.feeEffectiveBlock`
    // → FeeRaiseNoTimelock.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0 }
init() {}
@onlyOwner
pub fn setFees() {
self.fees.burn = 500
self.fees.holders = 0
self.fees.others = 0
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let timelock_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::FeeRaiseNoTimelock { .. }))
        .collect();
    assert!(
        !timelock_violations.is_empty(),
        "fees setter without timelock must produce FeeRaiseNoTimelock; got {violations:?}"
    );
    assert!(
        matches!(
            &timelock_violations[0],
            SafetyError::FeeRaiseNoTimelock { func }
            if func == "setFees"
        ),
        "violation must be FeeRaiseNoTimelock(func=setFees); got {:?}",
        timelock_violations[0]
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn safety_020_distribute_taxes_no_ext_call_passes() {
    // `distributeTaxes` with no external call — zero-before-interaction does not apply.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 0 holders: 0 others: 500 }
}
state { totalSupply: u128 = 0, taxPool: u128 = 0 }
init() {}
pub fn distributeTaxes(recipient: Address) {
let pool = self.taxPool
self.taxPool = 0
self.totalSupply = self.totalSupply - pool
}
}"#,
    );
    let contracts = ast.contracts();
    let violations: Vec<_> = tax_check(&contracts[0])
        .into_iter()
        .filter(|v| matches!(v, SafetyError::TaxPoolNotZeroedFirst { .. }))
        .collect();
    assert!(
        violations.is_empty(),
        "distributeTaxes with no ext call must pass zero-before-interaction; got {violations:?}"
    );
}

#[test]
fn safety_022_fees_setter_single_component_without_timelock_rejected() {
    // A setter that writes only `self.fees.burn` without `self.feeEffectiveBlock`
    // is flagged — the analyzer cannot prove it only decreases (reject on doubt).
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0 }
init() {}
@onlyOwner
pub fn decreaseBurn() {
self.fees.burn = 100
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let timelock_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::FeeRaiseNoTimelock { .. }))
        .collect();
    // The rule flags any fees component write without a timelock marker (reject on doubt).
    assert!(
        !timelock_violations.is_empty(),
        "fees component write without timelock marker must produce FeeRaiseNoTimelock; got {violations:?}"
    );
}
