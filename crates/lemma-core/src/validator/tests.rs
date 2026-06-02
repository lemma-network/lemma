//! Tests for `lemma_core::validator`.
//!
//! Covers `ConsensusKey`, `VotingPower`, `ValidatorStatus`, `Stake`,
//! `UnbondingEntry`, and `Validator`: construction, accessors, predicates,
//! arithmetic, and serde round-trips.
//! 100% public API coverage per AGENTS.md §11.1.

use super::*;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn test_consensus_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952])
}

fn test_validator() -> Validator {
    Validator {
        address: Address::zero(),
        consensus_pubkey: test_consensus_key(),
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active: Amount::from_drop(1_000_000_000_000_000_000), // 1 LEM
            pending_active: Amount::zero(),
            pending_inactive: Vec::new(),
            inactive: Amount::zero(),
        },
        delegated: Amount::zero(),
        commission_bps: 500,
        jailed_until: None,
    }
}

// ── ConsensusKey ──────────────────────────────────────────────────────────────

#[test]
fn consensus_key_from_bytes_stores_correct_lengths() {
    let key = ConsensusKey::from_bytes(vec![1u8; 32], vec![2u8; 1952]);
    assert_eq!(key.classical.len(), 32);
    assert_eq!(key.quantum.len(), 1952);
    assert!(key.classical.iter().all(|&b| b == 1));
    assert!(key.quantum.iter().all(|&b| b == 2));
}

// ── VotingPower ──────────────────────────────────────────────────────────────

#[test]
fn voting_power_zero_is_zero_amount() {
    let vp = VotingPower::zero();
    assert_eq!(vp.as_amount(), Amount::zero());
}

// ── ValidatorStatus ──────────────────────────────────────────────────────────

#[test]
fn validator_status_variants_are_distinct() {
    assert_ne!(ValidatorStatus::Bonded, ValidatorStatus::Unbonded);
    assert_ne!(ValidatorStatus::Bonded, ValidatorStatus::Unbonding);
    assert_ne!(ValidatorStatus::Unbonded, ValidatorStatus::Unbonding);
}

// ── Stake ────────────────────────────────────────────────────────────────────

#[test]
fn stake_zero_has_all_zero_buckets() {
    let s = Stake::zero();
    assert_eq!(s.active, Amount::zero());
    assert_eq!(s.pending_active, Amount::zero());
    assert!(s.pending_inactive.is_empty());
    assert_eq!(s.inactive, Amount::zero());
}

#[test]
fn stake_total_bonded_sums_correctly() {
    let stake = Stake {
        active: Amount::from_drop(100),
        pending_active: Amount::from_drop(50),
        pending_inactive: vec![
            UnbondingEntry {
                initial_balance: Amount::from_drop(25),
                start_height: 10,
                complete_time: 1_000_000,
                on_hold: false,
            },
            UnbondingEntry {
                initial_balance: Amount::from_drop(10),
                start_height: 15,
                complete_time: 2_000_000,
                on_hold: true,
            },
        ],
        inactive: Amount::from_drop(999), // NOT included in total_bonded
    };
    // active(100) + pending_active(50) + pending_inactive(25 + 10) = 185
    assert_eq!(stake.total_bonded().unwrap(), Amount::from_drop(185));
}

// ── Validator — voting_power ─────────────────────────────────────────────────

#[test]
fn validator_voting_power_sums_self_stake_and_delegated() {
    let val = Validator {
        self_stake: Stake {
            active: Amount::from_drop(1000),
            pending_active: Amount::zero(),
            pending_inactive: Vec::new(),
            inactive: Amount::zero(),
        },
        delegated: Amount::from_drop(500),
        ..test_validator()
    };
    // voting_power = active self_stake + delegated = 1000 + 500 = 1500
    assert_eq!(
        val.voting_power().unwrap(),
        VotingPower(Amount::from_drop(1500))
    );
}

// ── Validator — is_active ────────────────────────────────────────────────────

#[test]
fn validator_is_active_when_bonded_not_tombstoned_not_jailed() {
    let val = test_validator();
    assert_eq!(val.status, ValidatorStatus::Bonded);
    assert!(!val.tombstoned);
    assert!(val.jailed_until.is_none());
    assert!(val.is_active());
}

#[test]
fn validator_is_not_active_when_unbonding() {
    let val = Validator {
        status: ValidatorStatus::Unbonding,
        ..test_validator()
    };
    assert!(!val.is_active());
}

#[test]
fn validator_is_not_active_when_tombstoned() {
    let val = Validator {
        tombstoned: true,
        ..test_validator()
    };
    assert!(!val.is_active());
}

#[test]
fn validator_is_not_active_when_jailed() {
    let val = Validator {
        jailed_until: Some(9_999_999),
        ..test_validator()
    };
    assert!(!val.is_active());
}

// ── UnbondingEntry ───────────────────────────────────────────────────────────

#[test]
fn unbonding_entry_stores_all_fields() {
    let entry = UnbondingEntry {
        initial_balance: Amount::from_drop(42),
        start_height: 100,
        complete_time: 1_700_000_000,
        on_hold: true,
    };
    assert_eq!(entry.initial_balance, Amount::from_drop(42));
    assert_eq!(entry.start_height, 100);
    assert_eq!(entry.complete_time, 1_700_000_000);
    assert!(entry.on_hold);
}

// ── Serde round-trips ────────────────────────────────────────────────────────

#[test]
fn consensus_key_serde_roundtrip() {
    let original = test_consensus_key();
    let json = serde_json::to_string(&original).expect("ConsensusKey should serialize");
    let decoded: ConsensusKey =
        serde_json::from_str(&json).expect("ConsensusKey should deserialize");
    assert_eq!(decoded, original);
}

#[test]
fn voting_power_serde_roundtrip() {
    let original = VotingPower(Amount::from_drop(42_000));
    let json = serde_json::to_string(&original).expect("VotingPower should serialize");
    let decoded: VotingPower = serde_json::from_str(&json).expect("VotingPower should deserialize");
    assert_eq!(decoded, original);
}

#[test]
fn validator_serde_roundtrip() {
    let original = test_validator();
    let json = serde_json::to_string(&original).expect("Validator should serialize");
    let decoded: Validator = serde_json::from_str(&json).expect("Validator should deserialize");
    assert_eq!(decoded, original);
}
