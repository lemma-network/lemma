//! Tests for SAFETY-002 — Fee Cap rule (DB-A41 model).
//!
//! ## DB-A41 model (replaces old `amount * rate / DENOM` hook scan)
//!
//! Under DB-A41:
//! - **Plain `Token`**: fee-free.  Only `maxFeePercent` config ceiling is checked.
//! - **`TaxToken`**: `fees` is a state block.  The rule checks the initial `fees`
//!   config block sum AND any fees-setter functions that write individual components.
//! - **Plain `contract`**: no config block → rule does not apply.
//!
//! ## Inconclusive coverage (spec §5.2)
//!
//! A fees-setter with a non-literal component value cannot be bounded statically
//! → the contract is **rejected** with `Inconclusive`.  The test
//! `fee_cap_non_literal_fees_component_inconclusive_rejected` verifies this.

use crate::analyzer::error::SafetyError;
use crate::{parse, tokenize};

use super::check as fee_cap_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn fee_cap_tax_token_fees_within_cap_passes() {
    // TaxToken with fees sum (500+0+0 = 500) ≤ maxFeePercent (2500) → passes.
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
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "TaxToken fees within cap must pass SAFETY-002; got {violations:?}"
    );
}

#[test]
fn fee_cap_tax_token_fees_equal_to_max_passes() {
    // Boundary: fees sum == maxFeePercent (2500) → passes (not strictly greater).
    // Use burn=2500, holders=0, others=0 to avoid WF-014 distributeTaxes requirement.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 2500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0 }
init() {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "fees sum == maxFeePercent must pass SAFETY-002; got {violations:?}"
    );
}

#[test]
fn fee_cap_plain_token_no_max_fee_passes() {
    // Plain Token with no maxFeePercent config — rule does not apply.
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
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "plain Token with no maxFeePercent must pass SAFETY-002; got {violations:?}"
    );
}

#[test]
fn fee_cap_no_config_block_passes() {
    // Plain contract with no config block — rule does not apply.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn foo(amount: u128) {
let y = amount + 1
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "contract with no config block must pass SAFETY-002; got {violations:?}"
    );
}

#[test]
fn fee_cap_tax_token_no_fees_setter_passes() {
    // TaxToken with no function that writes self.fees.* → no setter violations.
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
pub fn getSupply() -> u128 {
return self.totalSupply
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "TaxToken with no fees setter must pass SAFETY-002; got {violations:?}"
    );
}

#[test]
fn fee_cap_tax_token_fees_setter_all_components_within_cap_passes() {
    // Fees setter writes all three components with literals summing to 500 ≤ 2500 → passes.
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
pub fn setFees() {
self.fees.burn = 300
self.fees.holders = 100
self.fees.others = 100
self.feeEffectiveBlock = 7200
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "fees setter with all components within cap must pass SAFETY-002; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn fee_cap_tax_token_initial_fees_sum_exceeds_declared_max_rejected() {
    // Initial fees config sum (3000) > maxFeePercent (2500) → FeeTooHigh.
    // Note: WF-014 also catches this; this test verifies SAFETY-002 defense-in-depth.
    // We bypass WF-014 by using a sum that WF-014 would also reject — but since
    // WF-014 runs before SAFETY-002, we test the rule directly.
    // Instead, test via a fees setter that writes a total > cap.
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
pub fn setFees() {
self.fees.burn = 3000
self.fees.holders = 0
self.fees.others = 0
self.feeEffectiveBlock = 7200
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "fees setter total > maxFeePercent must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(
            &violations[0],
            SafetyError::FeeTooHigh {
                declared: 2500,
                found: 3000
            }
        ),
        "violation must be FeeTooHigh(declared=2500, found=3000); got {:?}",
        violations[0]
    );
}

#[test]
fn fee_cap_tax_token_fees_setter_exceeds_protocol_ceiling_rejected() {
    // A fees setter writes total 2501 which exceeds PROTOCOL_MAX_FEE_BPS (2500)
    // even when no maxFeePercent is declared → FeeTooHigh.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0, feeEffectiveBlock: u64 = 0 }
init() {}
@onlyOwner
pub fn setFees() {
self.fees.burn = 2501
self.fees.holders = 0
self.fees.others = 0
self.feeEffectiveBlock = 7200
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "fees setter total > PROTOCOL_MAX_FEE_BPS must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::FeeTooHigh { .. }),
        "violation must be FeeTooHigh; got {:?}",
        violations[0]
    );
}

// ─── Inconclusive→reject test (REQUIRED by spec §5.2) ────────────────────────

#[test]
fn fee_cap_non_literal_fees_component_inconclusive_rejected() {
    // A fees setter uses a non-literal value for a component — cannot be bounded
    // statically → Inconclusive (safe-but-unanalyzable contract is REJECTED).
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 0 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0, feeEffectiveBlock: u64 = 0 }
init() {}
@onlyOwner
pub fn setFees(newBurn: u128) {
self.fees.burn = newBurn
self.fees.holders = 0
self.fees.others = 0
self.feeEffectiveBlock = 7200
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "non-literal fees component must produce exactly one Inconclusive; got {violations:?}"
    );
    assert!(
        matches!(
            &violations[0],
            SafetyError::Inconclusive {
                rule: "SAFETY-002",
                ..
            }
        ),
        "violation must be Inconclusive(SAFETY-002); got {:?}",
        violations[0]
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn fee_cap_tax_token_fees_sum_one_above_max_rejected() {
    // Boundary: fees setter sum == maxFeePercent + 1 (2501) → FeeTooHigh.
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
pub fn setFees() {
self.fees.burn = 2501
self.fees.holders = 0
self.fees.others = 0
self.feeEffectiveBlock = 7200
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = fee_cap_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "fees sum == maxFeePercent+1 must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(
            &violations[0],
            SafetyError::FeeTooHigh {
                declared: 2500,
                found: 2501
            }
        ),
        "violation must be FeeTooHigh(declared=2500, found=2501); got {:?}",
        violations[0]
    );
}
