//! Tests for `express.rs` — Express fast-path eligibility classifier.
//!
//! Coverage target: 100% (consensus-adjacent safety boundary).
//! Structure: AGENTS.md §11.2 — separate tests.rs submodule, shared helpers,
//! `{action}_{expected_outcome}` test names.

use super::*;
use lemma_core::transaction::TxType;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// A fully-eligible hint: `is_express_eligible=true`, no shared reads, not private.
fn eligible_hint() -> ExpressHint {
    ExpressHint::eligible()
}

/// A hint with `is_express_eligible=false` (compiler disqualified).
fn not_eligible_hint() -> ExpressHint {
    ExpressHint::new(false, false, false)
}

/// A hint with shared-state read flag set.
fn shared_read_hint() -> ExpressHint {
    ExpressHint::new(true, true, false)
}

/// A hint with private/Veil flag set.
fn private_hint() -> ExpressHint {
    ExpressHint::new(true, false, true)
}

// ── ExpressHint constructors ──────────────────────────────────────────────────

#[test]
fn hint_new_stores_all_fields() {
    let h = ExpressHint::new(true, false, true);
    assert!(h.is_express_eligible);
    assert!(!h.reads_shared_state);
    assert!(h.is_private);
}

#[test]
fn hint_eligible_produces_fully_eligible_hint() {
    let h = ExpressHint::eligible();
    assert!(h.is_express_eligible);
    assert!(!h.reads_shared_state);
    assert!(!h.is_private);
}

#[test]
fn hint_eligible_equals_new_with_matching_args() {
    assert_eq!(
        ExpressHint::eligible(),
        ExpressHint::new(true, false, false)
    );
}

// ── ExpressEligibility predicates ─────────────────────────────────────────────

#[test]
fn is_eligible_returns_true_for_eligible_variant() {
    assert!(ExpressEligibility::Eligible.is_eligible());
}

#[test]
fn is_eligible_returns_false_for_fallback_variant() {
    let fb = ExpressEligibility::Fallback(FallbackReason::MissingHint);
    assert!(!fb.is_eligible());
}

#[test]
fn fallback_reason_returns_none_for_eligible() {
    assert_eq!(ExpressEligibility::Eligible.fallback_reason(), None);
}

#[test]
fn fallback_reason_returns_some_for_fallback() {
    let fb = ExpressEligibility::Fallback(FallbackReason::SharedStateRead);
    assert_eq!(fb.fallback_reason(), Some(FallbackReason::SharedStateRead));
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[test]
fn classify_returns_eligible_for_transfer_with_full_proof() {
    // Arrange: Transfer + fully eligible hint (the canonical Express case)
    let hint = eligible_hint();
    // Act
    let result = classify(TxType::Transfer, Some(&hint));
    // Assert
    assert_eq!(result, ExpressEligibility::Eligible);
    assert!(result.is_eligible());
    assert_eq!(result.fallback_reason(), None);
}

// ── TxType allow-list (IneligibleTxType) ─────────────────────────────────────

#[test]
fn classify_rejects_contract_call_regardless_of_hint() {
    // ContractCall may read/write shared contract storage — always Fallback.
    let result = classify(TxType::ContractCall, Some(&eligible_hint()));
    assert_eq!(
        result,
        ExpressEligibility::Fallback(FallbackReason::IneligibleTxType)
    );
}

#[test]
fn classify_rejects_contract_deploy_regardless_of_hint() {
    // ContractDeploy creates a new shared account — always Fallback.
    let result = classify(TxType::ContractDeploy, Some(&eligible_hint()));
    assert_eq!(
        result,
        ExpressEligibility::Fallback(FallbackReason::IneligibleTxType)
    );
}

#[test]
fn classify_rejects_stake_regardless_of_hint() {
    // Stake writes shared validator-set state — always Fallback.
    let result = classify(TxType::Stake, Some(&eligible_hint()));
    assert_eq!(
        result,
        ExpressEligibility::Fallback(FallbackReason::IneligibleTxType)
    );
}

#[test]
fn classify_rejects_unstake_regardless_of_hint() {
    // Unstake writes shared validator-set state — always Fallback.
    let result = classify(TxType::Unstake, Some(&eligible_hint()));
    assert_eq!(
        result,
        ExpressEligibility::Fallback(FallbackReason::IneligibleTxType)
    );
}

#[test]
fn classify_rejects_governance_vote_regardless_of_hint() {
    // GovernanceVote writes shared governance system-contract state — always Fallback.
    let result = classify(TxType::GovernanceVote, Some(&eligible_hint()));
    assert_eq!(
        result,
        ExpressEligibility::Fallback(FallbackReason::IneligibleTxType)
    );
}

// ── Missing hint (conservative default) ──────────────────────────────────────

#[test]
fn classify_returns_missing_hint_when_hint_is_none() {
    // No compiler hint → conservative fallback (08-EXECUTION_SPEC §1.7).
    let result = classify(TxType::Transfer, None);
    assert_eq!(
        result,
        ExpressEligibility::Fallback(FallbackReason::MissingHint)
    );
}

#[test]
fn classify_returns_missing_hint_not_ineligible_type_when_transfer_and_no_hint() {
    // Type-check is first; hint-check is second.
    // Transfer passes the type check → the reported reason is MissingHint, not
    // IneligibleTxType. This validates check ordering.
    let result = classify(TxType::Transfer, None);
    assert_eq!(result.fallback_reason(), Some(FallbackReason::MissingHint));
}

#[test]
fn classify_ineligible_type_reported_before_missing_hint() {
    // IneligibleTxType is checked BEFORE hint presence — so even with no hint,
    // ContractCall returns IneligibleTxType (not MissingHint). Check ordering matters.
    let result = classify(TxType::ContractCall, None);
    assert_eq!(
        result.fallback_reason(),
        Some(FallbackReason::IneligibleTxType)
    );
}

// ── Compiler disqualifier (NotCompilerEligible) ───────────────────────────────

#[test]
fn classify_returns_not_compiler_eligible_when_hint_says_false() {
    let hint = not_eligible_hint();
    let result = classify(TxType::Transfer, Some(&hint));
    assert_eq!(
        result,
        ExpressEligibility::Fallback(FallbackReason::NotCompilerEligible)
    );
}

// ── Shared-state read disqualifier ────────────────────────────────────────────

#[test]
fn classify_returns_shared_state_read_when_hint_reads_shared() {
    let hint = shared_read_hint();
    let result = classify(TxType::Transfer, Some(&hint));
    assert_eq!(
        result,
        ExpressEligibility::Fallback(FallbackReason::SharedStateRead)
    );
}

// ── Private / Veil disqualifier ───────────────────────────────────────────────

#[test]
fn classify_returns_private_tx_when_hint_is_private() {
    let hint = private_hint();
    let result = classify(TxType::Transfer, Some(&hint));
    assert_eq!(
        result,
        ExpressEligibility::Fallback(FallbackReason::PrivateTx)
    );
}

// ── Check ordering ────────────────────────────────────────────────────────────

#[test]
fn classify_reports_not_compiler_eligible_before_shared_state_read() {
    // When both is_express_eligible=false AND reads_shared_state=true,
    // NotCompilerEligible is returned (checked first).
    let hint = ExpressHint::new(false, true, false);
    let result = classify(TxType::Transfer, Some(&hint));
    assert_eq!(
        result.fallback_reason(),
        Some(FallbackReason::NotCompilerEligible)
    );
}

#[test]
fn classify_reports_not_compiler_eligible_before_private_tx() {
    // When both is_express_eligible=false AND is_private=true,
    // NotCompilerEligible is returned (checked first).
    let hint = ExpressHint::new(false, false, true);
    let result = classify(TxType::Transfer, Some(&hint));
    assert_eq!(
        result.fallback_reason(),
        Some(FallbackReason::NotCompilerEligible)
    );
}

#[test]
fn classify_reports_shared_state_read_before_private_tx() {
    // When reads_shared_state=true AND is_private=true (but is_express_eligible=true),
    // SharedStateRead is returned (checked before PrivateTx).
    let hint = ExpressHint::new(true, true, true);
    let result = classify(TxType::Transfer, Some(&hint));
    assert_eq!(
        result.fallback_reason(),
        Some(FallbackReason::SharedStateRead)
    );
}

// ── All TxType variants produce Fallback except Transfer ─────────────────────

#[test]
fn only_transfer_is_eligible_in_phase_1_allow_list() {
    // Exhaustive check: every non-Transfer variant with the best possible hint
    // still returns Fallback(IneligibleTxType).
    let hint = eligible_hint();
    let ineligible_types = [
        TxType::ContractCall,
        TxType::ContractDeploy,
        TxType::Stake,
        TxType::Unstake,
        TxType::GovernanceVote,
    ];
    for tx_type in ineligible_types {
        let result = classify(tx_type, Some(&hint));
        assert_eq!(
            result,
            ExpressEligibility::Fallback(FallbackReason::IneligibleTxType),
            "TxType::{tx_type:?} should be IneligibleTxType with best hint"
        );
    }
}

// ── Safety boundary: disqualifiers each independently prevent Eligible ────────

#[test]
fn all_three_disqualifiers_each_prevent_eligibility_independently() {
    // Verify each flag, in isolation (other two clear), causes Fallback.

    // is_express_eligible=false only
    let r1 = classify(TxType::Transfer, Some(&ExpressHint::new(false, false, false)));
    assert_eq!(r1.fallback_reason(), Some(FallbackReason::NotCompilerEligible));

    // reads_shared_state=true only
    let r2 = classify(TxType::Transfer, Some(&ExpressHint::new(true, true, false)));
    assert_eq!(r2.fallback_reason(), Some(FallbackReason::SharedStateRead));

    // is_private=true only
    let r3 = classify(TxType::Transfer, Some(&ExpressHint::new(true, false, true)));
    assert_eq!(r3.fallback_reason(), Some(FallbackReason::PrivateTx));
}

// ── is_allowed_tx_type (internal, tested via classify) ───────────────────────

#[test]
fn transfer_is_the_only_allowed_type_confirmed_via_classify() {
    // Transfer + eligible hint → Eligible (allow-listed).
    let eligible_result = classify(TxType::Transfer, Some(&eligible_hint()));
    assert!(eligible_result.is_eligible());

    // Every other current variant + eligible hint → IneligibleTxType (not allow-listed).
    // This test documents the Phase 1 boundary and will fail if a new TxType is
    // added to the allow-list without updating this assertion.
    let non_transfer = [
        TxType::ContractCall,
        TxType::ContractDeploy,
        TxType::Stake,
        TxType::Unstake,
        TxType::GovernanceVote,
    ];
    for t in non_transfer {
        assert!(
            !classify(t, Some(&eligible_hint())).is_eligible(),
            "TxType::{t:?} should not be eligible in Phase 1"
        );
    }
}
