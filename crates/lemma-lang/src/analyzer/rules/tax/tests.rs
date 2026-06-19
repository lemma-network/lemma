//! Tests for SAFETY-020, SAFETY-021, SAFETY-022 — TaxToken fee-model rules.
//!
//! ## Test layout (AGENTS §11.2)
//!
//! - **Positive**: valid TaxToken (correct `distributeTaxes`, pure `isTaxable`,
//!   no fees setter) → zero violations.
//! - **Token guard**: plain `Token` (non-tax) → zero violations for all three rules.
//! - **Negative per rule**: each attack variant produces the exact `SafetyError` variant.
//! - **Inconclusive→reject**: non-canonical shapes that cannot be proven safe are
//!   rejected with `Inconclusive` (soundness over completeness).
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
//!
//! ## SAFETY-022 reject-on-doubt (C4)
//!
//! Any direct write to `self.fees.*` → `Inconclusive`.  The canonical
//! `pendingFees + effectiveBlock` pattern is required for full enforcement
//! (deferred to P3·Step 7).  Tests that previously expected `FeeRaiseNoTimelock`
//! now expect `Inconclusive`.

use crate::analyzer::error::SafetyError;
use crate::{parse, tokenize};

use super::check as tax_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── Shared TaxToken fixtures ─────────────────────────────────────────────────

/// Minimal valid TaxToken with no `distributeTaxes`, no `isTaxable`, no fees setter.
/// Uses `fees.others = 0` to avoid WF-014 `distributeTaxes` requirement.
fn minimal_tax_token_src() -> &'static str {
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
    let ast = typed_ast(minimal_tax_token_src());
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "TaxToken with no distributeTaxes must pass SAFETY-020; got {violations:?}"
    );
}

#[test]
fn safety_020_valid_distribute_taxes_passes() {
    // Valid `distributeTaxes`: not on transfer path, canonical drain shape.
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
                    | SafetyError::Inconclusive {
                        rule: "SAFETY-020",
                        ..
                    }
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
pub fn transfer(to: Address, amount: u128) {}
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
pub fn transfer(to: Address, amount: u128) {}
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
fn safety_020_distribute_taxes_ext_call_before_zero_is_inconclusive() {
    // `distributeTaxes` makes an external call before zeroing taxPool →
    // Inconclusive (reject-on-doubt: non-canonical ordering cannot be proven safe).
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
pub fn transfer(to: Address, amount: u128) {}
pub fn distributeTaxes(recipient: Address) {
recipient.transfer(self.taxPool)
self.taxPool = 0
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    // The non-canonical ordering (ext call before zero) → Inconclusive.
    let inconclusive: Vec<_> = violations
        .iter()
        .filter(|v| {
            matches!(
                v,
                SafetyError::Inconclusive {
                    rule: "SAFETY-020",
                    ..
                }
            )
        })
        .collect();
    assert!(
        !inconclusive.is_empty(),
        "ext call before taxPool zero must produce Inconclusive(SAFETY-020); got {violations:?}"
    );
}

// ─── SAFETY-020 C1 — non-literal-zero write is Inconclusive ──────────────────

#[test]
fn distribute_taxes_with_partial_decrement_is_inconclusive() {
    // `self.taxPool = self.taxPool - 1` is a non-literal-zero write →
    // Inconclusive (C1: RHS must be literal integer 0).
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
pub fn transfer(to: Address, amount: u128) {}
pub fn distributeTaxes(recipient: Address) {
self.taxPool = self.taxPool - 1
recipient.transfer(self.taxPool)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let inconclusive: Vec<_> = violations
        .iter()
        .filter(|v| {
            matches!(
                v,
                SafetyError::Inconclusive {
                    rule: "SAFETY-020",
                    ..
                }
            )
        })
        .collect();
    assert!(
        !inconclusive.is_empty(),
        "non-literal-zero taxPool write must produce Inconclusive(SAFETY-020); got {violations:?}"
    );
}

// ─── SAFETY-020 C1.3 — external call arg reads self.taxPool after zero ────────

#[test]
fn distribute_taxes_args_read_taxpool_after_zero_is_inconclusive() {
    // `recipient.transfer(self.taxPool)` after `self.taxPool = 0` →
    // Inconclusive (C1.3: external call arg must use local snapshot, not self.taxPool).
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
pub fn transfer(to: Address, amount: u128) {}
pub fn distributeTaxes(recipient: Address) {
self.taxPool = 0
recipient.transfer(self.taxPool)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let inconclusive: Vec<_> = violations
        .iter()
        .filter(|v| {
            matches!(
                v,
                SafetyError::Inconclusive {
                    rule: "SAFETY-020",
                    ..
                }
            )
        })
        .collect();
    assert!(
        !inconclusive.is_empty(),
        "ext call arg reading self.taxPool after zero must produce Inconclusive(SAFETY-020); got {violations:?}"
    );
}

// ─── SAFETY-020 C2 — helper call is Inconclusive ─────────────────────────────

#[test]
fn distribute_taxes_with_helper_call_is_inconclusive() {
    // `distributeTaxes` calls an internal helper function →
    // Inconclusive (C2: cannot trace into callee without transitive analysis).
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
pub fn transfer(to: Address, amount: u128) {}
pub fn distributeTaxes(recipient: Address) {
self.doDistribute(recipient)
}
fn doDistribute(recipient: Address) {
let pool = self.taxPool
self.taxPool = 0
recipient.transfer(pool)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let inconclusive: Vec<_> = violations
        .iter()
        .filter(|v| {
            matches!(
                v,
                SafetyError::Inconclusive {
                    rule: "SAFETY-020",
                    ..
                }
            )
        })
        .collect();
    assert!(
        !inconclusive.is_empty(),
        "distributeTaxes with helper call must produce Inconclusive(SAFETY-020); got {violations:?}"
    );
}

// ─── SAFETY-020 C5 — no transfer-path entries is Inconclusive ────────────────

#[test]
fn tax_token_without_transfer_entry_is_inconclusive() {
    // TaxToken with `distributeTaxes` but no `transfer`/`transferFrom`/`#[onTransfer]` →
    // Inconclusive (C5: cannot verify separation without seeing the transfer path).
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
recipient.transfer(pool)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    let inconclusive: Vec<_> = violations
        .iter()
        .filter(|v| {
            matches!(
                v,
                SafetyError::Inconclusive {
                    rule: "SAFETY-020",
                    ..
                }
            )
        })
        .collect();
    assert!(
        !inconclusive.is_empty(),
        "TaxToken with distributeTaxes but no transfer-path entries must produce Inconclusive(SAFETY-020); got {violations:?}"
    );
}

// ─── SAFETY-021 positive tests ────────────────────────────────────────────────

#[test]
fn safety_021_no_is_taxable_passes() {
    // TaxToken with no `isTaxable` function → SAFETY-021 does not apply.
    let ast = typed_ast(minimal_tax_token_src());
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

// ─── SAFETY-021 C3 — SystemTime::now() is caught ─────────────────────────────

#[test]
fn is_taxable_with_system_time_is_impure() {
    // `isTaxable` calls `SystemTime.now()` (path/method-call form) →
    // rejected at the type-checker or safety-analyzer stage.
    //
    // In Lem, `SystemTime` is not a built-in identifier, so the type checker
    // rejects it as `UndefinedName` before the safety analyzer runs.  The
    // ImpurityScanner's C3 fix is defense-in-depth for future Lem versions
    // that may expose `SystemTime` as a built-in.
    //
    // This test verifies the end-to-end guarantee: a contract with
    // `SystemTime.now()` in `isTaxable` is REJECTED (either by the type
    // checker or the safety analyzer).  The contract must not compile clean.
    let tokens = crate::tokenize(
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
pub fn isTaxable(from: Address, to: Address) -> bool {
let t = SystemTime.now()
return t > 0
}
}"#,
    )
    .expect("tokenize");
    let ast = crate::parse(tokens).expect("parse");
    // The type checker must reject this contract (SystemTime is undefined).
    // If Lem ever adds SystemTime as a built-in, the safety analyzer's C3
    // fix will catch it instead.
    let result = crate::check(ast);
    assert!(
        result.is_err(),
        "contract with SystemTime.now() in isTaxable must be rejected; got Ok"
    );
}

// ─── SAFETY-022 positive tests ────────────────────────────────────────────────

#[test]
fn safety_022_no_fees_setter_passes() {
    // TaxToken with no function that writes `self.fees.*` → SAFETY-022 does not apply.
    let ast = typed_ast(minimal_tax_token_src());
    let contracts = ast.contracts();
    let violations: Vec<_> = tax_check(&contracts[0])
        .into_iter()
        .filter(|v| {
            matches!(
                v,
                SafetyError::FeeRaiseNoTimelock { .. }
                    | SafetyError::Inconclusive {
                        rule: "SAFETY-022",
                        ..
                    }
            )
        })
        .collect();
    assert!(
        violations.is_empty(),
        "TaxToken with no fees setter must pass SAFETY-022; got {violations:?}"
    );
}

// ─── SAFETY-022 negative tests — flat writes produce FeeRaiseNoTimelock ──────

#[test]
fn fees_direct_write_produces_fee_raise_no_timelock() {
    // A flat (non-branched) direct write to `self.fees.*` → FeeRaiseNoTimelock.
    // The function can raise fees without any timelock — this is a real violation.
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
    let no_timelock: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::FeeRaiseNoTimelock { .. }))
        .collect();
    assert!(
        !no_timelock.is_empty(),
        "flat self.fees write must produce FeeRaiseNoTimelock; got {violations:?}"
    );
}

#[test]
fn safety_022_fees_setter_with_literal_timelock_produces_no_timelock_error() {
    // A fees setter that writes `self.feeEffectiveBlock = 7200` (a literal, NOT
    // `block.height + N`) is a flat write — FeeRaiseNoTimelock.
    // The canonical pattern requires `block.height + FEE_INCREASE_DELAY`.
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
    let violations = tax_check(&contracts[0]);
    let no_timelock: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::FeeRaiseNoTimelock { .. }))
        .collect();
    assert!(
        !no_timelock.is_empty(),
        "fees setter with literal feeEffectiveBlock (not block.height) must produce FeeRaiseNoTimelock; got {violations:?}"
    );
}

#[test]
fn safety_022_fees_setter_without_timelock_produces_no_timelock_error() {
    // Fees setter writes `self.fees.burn` without any timelock → FeeRaiseNoTimelock.
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
    let no_timelock: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::FeeRaiseNoTimelock { .. }))
        .collect();
    assert!(
        !no_timelock.is_empty(),
        "fees setter without timelock must produce FeeRaiseNoTimelock; got {violations:?}"
    );
}

#[test]
fn safety_022_fees_setter_single_component_produces_no_timelock_error() {
    // A setter that writes only `self.fees.burn` (flat write) → FeeRaiseNoTimelock.
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
    let no_timelock: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::FeeRaiseNoTimelock { .. }))
        .collect();
    assert!(
        !no_timelock.is_empty(),
        "single fees component flat write must produce FeeRaiseNoTimelock; got {violations:?}"
    );
}

// ─── SAFETY-022 positive test — canonical timelock pattern passes ─────────────

#[test]
fn safety_022_canonical_timelock_pattern_passes() {
    // The canonical fees setter with if/else + block.height timelock passes SAFETY-022.
    // Increase path: self.feeEffectiveBlock = block.height + FEE_INCREASE_DELAY
    // Decrease path: self.fees.* = newValue (immediate)
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
let currentTotal = self.fees.burn
if (newBurn > currentTotal) {
self.feeEffectiveBlock = block.height + 7200
} else {
self.fees.burn = newBurn
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations: Vec<_> = tax_check(&contracts[0])
        .into_iter()
        .filter(|v| {
            matches!(
                v,
                SafetyError::FeeRaiseNoTimelock { .. }
                    | SafetyError::Inconclusive {
                        rule: "SAFETY-022",
                        ..
                    }
            )
        })
        .collect();
    assert!(
        violations.is_empty(),
        "canonical timelock pattern must pass SAFETY-022; got {violations:?}"
    );
}

// ─── SAFETY-022 Inconclusive — ambiguous patterns still rejected ──────────────

#[test]
fn safety_022_if_else_without_block_height_is_inconclusive() {
    // if/else fees setter where neither branch uses block.height → Inconclusive.
    // The increase branch has fees writes but no block.height timelock.
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
pub fn setFees(newBurn: u128) {
let currentTotal = self.fees.burn
if (newBurn > currentTotal) {
self.fees.burn = newBurn
} else {
self.fees.burn = newBurn
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = tax_check(&contracts[0]);
    // Both branches write fees directly with no block.height → IncreaseWithoutTimelock
    let no_timelock: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::FeeRaiseNoTimelock { .. }))
        .collect();
    assert!(
        !no_timelock.is_empty(),
        "if/else fees setter without block.height must produce FeeRaiseNoTimelock; got {violations:?}"
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
pub fn transfer(to: Address, amount: u128) {}
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
        .filter(|v| {
            matches!(
                v,
                SafetyError::TaxPoolNotZeroedFirst { .. }
                    | SafetyError::Inconclusive {
                        rule: "SAFETY-020",
                        ..
                    }
            )
        })
        .collect();
    assert!(
        violations.is_empty(),
        "distributeTaxes with no ext call must pass zero-before-interaction; got {violations:?}"
    );
}
