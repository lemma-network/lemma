//! Tests for `lemma_mempool::circuit_breaker`.
//!
//! Covers:
//! - Tier boundaries at each threshold (inclusive/exclusive).
//! - capacity == 0 guard.
//! - admits() for every TxType at every tier.
//! - NetworkTier ordering (Normal < Busy < Critical < Emergency).
//! - Monotonic restriction: higher tiers never admit more tx types.
//! - is_admitted() integration.

use lemma_core::transaction::TxType;

use crate::circuit_breaker::{
    is_admitted, NetworkTier,
    BUSY_THRESHOLD_PCT, CRITICAL_THRESHOLD_PCT, EMERGENCY_THRESHOLD_PCT,
};

// ── Test helpers ──────────────────────────────────────────────────────────────

const CAPACITY: usize = 1000;

/// All 6 TxType variants.
fn all_tx_types() -> [TxType; 6] {
    [
        TxType::Transfer,
        TxType::ContractCall,
        TxType::ContractDeploy,
        TxType::Stake,
        TxType::Unstake,
        TxType::GovernanceVote,
    ]
}

/// pending count that yields exactly `pct` percent of `CAPACITY`.
fn pending_at(pct: u64) -> usize {
    (CAPACITY as u64 * pct / 100) as usize
}

// ── from_load — tier boundaries ───────────────────────────────────────────────

#[test]
fn from_load_zero_pending_is_normal() {
    assert_eq!(NetworkTier::from_load(0, CAPACITY), NetworkTier::Normal);
}

#[test]
fn from_load_69pct_is_normal() {
    assert_eq!(NetworkTier::from_load(pending_at(69), CAPACITY), NetworkTier::Normal);
}

#[test]
fn from_load_at_busy_threshold_is_busy() {
    // 70% → Busy (load_pct == BUSY_THRESHOLD_PCT)
    assert_eq!(NetworkTier::from_load(pending_at(70), CAPACITY), NetworkTier::Busy);
}

#[test]
fn from_load_89pct_is_busy() {
    assert_eq!(NetworkTier::from_load(pending_at(89), CAPACITY), NetworkTier::Busy);
}

#[test]
fn from_load_at_critical_threshold_is_critical() {
    // 90% → Critical (load_pct == CRITICAL_THRESHOLD_PCT)
    assert_eq!(NetworkTier::from_load(pending_at(90), CAPACITY), NetworkTier::Critical);
}

#[test]
fn from_load_99pct_is_critical() {
    assert_eq!(NetworkTier::from_load(pending_at(99), CAPACITY), NetworkTier::Critical);
}

#[test]
fn from_load_at_emergency_threshold_is_emergency() {
    // 100% → Emergency (load_pct == EMERGENCY_THRESHOLD_PCT)
    assert_eq!(NetworkTier::from_load(CAPACITY, CAPACITY), NetworkTier::Emergency);
}

#[test]
fn from_load_over_capacity_is_emergency() {
    // 150% — over capacity
    assert_eq!(
        NetworkTier::from_load(pending_at(150), CAPACITY),
        NetworkTier::Emergency
    );
}

// ── from_load — capacity == 0 guard ──────────────────────────────────────────

#[test]
fn from_load_zero_capacity_is_emergency() {
    // capacity == 0 → Emergency (no division by zero, safest default)
    assert_eq!(NetworkTier::from_load(0, 0), NetworkTier::Emergency);
}

#[test]
fn from_load_nonzero_pending_zero_capacity_is_emergency() {
    assert_eq!(NetworkTier::from_load(100, 0), NetworkTier::Emergency);
}

// ── from_load — threshold constants correct ───────────────────────────────────

#[test]
fn busy_threshold_constant_matches_from_load_behavior() {
    let just_below = pending_at(BUSY_THRESHOLD_PCT - 1);
    let at = pending_at(BUSY_THRESHOLD_PCT);
    assert_eq!(NetworkTier::from_load(just_below, CAPACITY), NetworkTier::Normal);
    assert_eq!(NetworkTier::from_load(at, CAPACITY), NetworkTier::Busy);
}

#[test]
fn critical_threshold_constant_matches_from_load_behavior() {
    let just_below = pending_at(CRITICAL_THRESHOLD_PCT - 1);
    let at = pending_at(CRITICAL_THRESHOLD_PCT);
    assert_eq!(NetworkTier::from_load(just_below, CAPACITY), NetworkTier::Busy);
    assert_eq!(NetworkTier::from_load(at, CAPACITY), NetworkTier::Critical);
}

#[test]
fn emergency_threshold_constant_matches_from_load_behavior() {
    let just_below = pending_at(EMERGENCY_THRESHOLD_PCT - 1);
    let at = pending_at(EMERGENCY_THRESHOLD_PCT);
    assert_eq!(NetworkTier::from_load(just_below, CAPACITY), NetworkTier::Critical);
    assert_eq!(NetworkTier::from_load(at, CAPACITY), NetworkTier::Emergency);
}

// ── admits — Normal: all types ────────────────────────────────────────────────

#[test]
fn normal_admits_all_tx_types() {
    for tx_type in all_tx_types() {
        assert!(
            NetworkTier::Normal.admits(tx_type),
            "Normal must admit {tx_type:?}"
        );
    }
}

// ── admits — Busy: no ContractDeploy ─────────────────────────────────────────

#[test]
fn busy_admits_transfer() {
    assert!(NetworkTier::Busy.admits(TxType::Transfer));
}

#[test]
fn busy_admits_contract_call() {
    assert!(NetworkTier::Busy.admits(TxType::ContractCall));
}

#[test]
fn busy_rejects_contract_deploy() {
    assert!(!NetworkTier::Busy.admits(TxType::ContractDeploy));
}

#[test]
fn busy_admits_stake() {
    assert!(NetworkTier::Busy.admits(TxType::Stake));
}

#[test]
fn busy_admits_unstake() {
    assert!(NetworkTier::Busy.admits(TxType::Unstake));
}

#[test]
fn busy_admits_governance_vote() {
    assert!(NetworkTier::Busy.admits(TxType::GovernanceVote));
}

// ── admits — Critical: Transfer + Stake + Unstake + GovernanceVote ───────────

#[test]
fn critical_admits_transfer() {
    assert!(NetworkTier::Critical.admits(TxType::Transfer));
}

#[test]
fn critical_rejects_contract_call() {
    assert!(!NetworkTier::Critical.admits(TxType::ContractCall));
}

#[test]
fn critical_rejects_contract_deploy() {
    assert!(!NetworkTier::Critical.admits(TxType::ContractDeploy));
}

#[test]
fn critical_admits_stake() {
    assert!(NetworkTier::Critical.admits(TxType::Stake));
}

#[test]
fn critical_admits_unstake() {
    assert!(NetworkTier::Critical.admits(TxType::Unstake));
}

#[test]
fn critical_admits_governance_vote() {
    // WHITEPAPER: Critical allows governance transactions.
    assert!(NetworkTier::Critical.admits(TxType::GovernanceVote));
}

// ── admits — Emergency: Stake + Unstake only ──────────────────────────────────

#[test]
fn emergency_rejects_transfer() {
    assert!(!NetworkTier::Emergency.admits(TxType::Transfer));
}

#[test]
fn emergency_rejects_contract_call() {
    assert!(!NetworkTier::Emergency.admits(TxType::ContractCall));
}

#[test]
fn emergency_rejects_contract_deploy() {
    assert!(!NetworkTier::Emergency.admits(TxType::ContractDeploy));
}

#[test]
fn emergency_admits_stake() {
    assert!(NetworkTier::Emergency.admits(TxType::Stake));
}

#[test]
fn emergency_admits_unstake() {
    assert!(NetworkTier::Emergency.admits(TxType::Unstake));
}

#[test]
fn emergency_rejects_governance_vote() {
    // During Emergency only validator-set ops; governance is queued.
    assert!(!NetworkTier::Emergency.admits(TxType::GovernanceVote));
}

// ── Ordering (Normal < Busy < Critical < Emergency) ───────────────────────────

#[test]
fn tier_ordering_normal_less_than_busy() {
    assert!(NetworkTier::Normal < NetworkTier::Busy);
}

#[test]
fn tier_ordering_busy_less_than_critical() {
    assert!(NetworkTier::Busy < NetworkTier::Critical);
}

#[test]
fn tier_ordering_critical_less_than_emergency() {
    assert!(NetworkTier::Critical < NetworkTier::Emergency);
}

#[test]
fn tier_ordering_normal_less_than_emergency() {
    assert!(NetworkTier::Normal < NetworkTier::Emergency);
}

// ── Monotonic restriction ─────────────────────────────────────────────────────

#[test]
fn higher_tier_never_admits_more_types_than_lower() {
    // For every pair of tiers (lower, higher) and every TxType:
    // if lower rejects it, higher must also reject it.
    let tiers = [
        NetworkTier::Normal,
        NetworkTier::Busy,
        NetworkTier::Critical,
        NetworkTier::Emergency,
    ];
    for (i, lower) in tiers.iter().enumerate() {
        for higher in tiers.iter().skip(i + 1) {
            for tx_type in all_tx_types() {
                if !lower.admits(tx_type) {
                    assert!(
                        !higher.admits(tx_type),
                        "{higher:?} admits {tx_type:?} but {lower:?} does not — \
                         stricter tier must not admit more types"
                    );
                }
            }
        }
    }
}

// ── is_admitted integration ───────────────────────────────────────────────────

#[test]
fn is_admitted_transfer_at_50pct_load_is_true() {
    assert!(is_admitted(TxType::Transfer, pending_at(50), CAPACITY));
}

#[test]
fn is_admitted_contract_deploy_at_95pct_load_is_false() {
    // 95% → Critical tier → ContractDeploy rejected.
    assert!(!is_admitted(TxType::ContractDeploy, pending_at(95), CAPACITY));
}

#[test]
fn is_admitted_stake_at_emergency_load_is_true() {
    // Over capacity → Emergency → Stake still admitted.
    assert!(is_admitted(TxType::Stake, CAPACITY + 1, CAPACITY));
}

#[test]
fn is_admitted_governance_vote_at_critical_load_is_true() {
    // WHITEPAPER: governance admitted at Critical.
    assert!(is_admitted(TxType::GovernanceVote, pending_at(95), CAPACITY));
}

#[test]
fn is_admitted_governance_vote_at_emergency_load_is_false() {
    // Emergency: only Stake/Unstake.
    assert!(!is_admitted(TxType::GovernanceVote, CAPACITY, CAPACITY));
}
