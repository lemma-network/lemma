//! Tests for `lemma_core::validator_set`.
//!
//! Covers `ValidatorSet` and `Member`: hash determinism, accessors,
//! and serde round-trips.
//! 100% public API coverage per AGENTS.md §11.1.

use std::collections::BTreeMap;

use super::*;
use crate::amount::Amount;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn test_consensus_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952])
}

fn single_member_set() -> ValidatorSet {
    let mut members = BTreeMap::new();
    let power = VotingPower(Amount::from_drop(1_000));
    members.insert(
        Address::zero(),
        Member {
            consensus_pubkey: test_consensus_key(),
            power,
        },
    );
    ValidatorSet {
        epoch: 0,
        members,
        total_power: Amount::from_drop(1_000),
    }
}

// ── hash ─────────────────────────────────────────────────────────────────────

#[test]
fn validator_set_hash_is_deterministic() {
    let set = single_member_set();
    let h1 = set.hash();
    let h2 = set.hash();
    assert_eq!(h1, h2);
}

#[test]
fn validator_set_hash_differs_for_different_members() {
    let set1 = single_member_set();

    let mut members2 = BTreeMap::new();
    members2.insert(
        Address::burn(), // different address
        Member {
            consensus_pubkey: test_consensus_key(),
            power: VotingPower(Amount::from_drop(1_000)),
        },
    );
    let set2 = ValidatorSet {
        epoch: 0,
        members: members2,
        total_power: Amount::from_drop(1_000),
    };

    assert_ne!(set1.hash(), set2.hash());
}

#[test]
fn validator_set_hash_differs_for_different_power() {
    let set1 = single_member_set();

    let mut members2 = BTreeMap::new();
    members2.insert(
        Address::zero(), // same address
        Member {
            consensus_pubkey: test_consensus_key(),
            power: VotingPower(Amount::from_drop(2_000)), // different power
        },
    );
    let set2 = ValidatorSet {
        epoch: 0,
        members: members2,
        total_power: Amount::from_drop(2_000),
    };

    assert_ne!(set1.hash(), set2.hash());
}

// ── len / is_empty ───────────────────────────────────────────────────────────

#[test]
fn validator_set_len_and_is_empty() {
    let empty = ValidatorSet {
        epoch: 0,
        members: BTreeMap::new(),
        total_power: Amount::zero(),
    };
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());

    let non_empty = single_member_set();
    assert_eq!(non_empty.len(), 1);
    assert!(!non_empty.is_empty());
}

// ── Serde ────────────────────────────────────────────────────────────────────

#[test]
fn validator_set_serde_roundtrip() {
    let original = single_member_set();
    let json = serde_json::to_string(&original).expect("ValidatorSet should serialize");
    let decoded: ValidatorSet =
        serde_json::from_str(&json).expect("ValidatorSet should deserialize");
    assert_eq!(decoded, original);
}

// ── from_active_validators ────────────────────────────────────────────────────

// Shared helper: a minimal Bonded Validator for use in from_active_validators tests.
fn bonded_validator(byte: u8, active_drop: u128) -> crate::validator::Validator {
    use crate::validator::{Stake, Validator, ValidatorStatus};
    Validator {
        address: Address::from_public_key(&[byte; 32]),
        consensus_pubkey: ConsensusKey::from_bytes(vec![byte; 32], vec![byte; 32]),
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active:           Amount::from_drop(active_drop),
            pending_active:   Amount::zero(),
            pending_inactive: vec![],
            inactive:         Amount::zero(),
        },
        delegated:      Amount::zero(),
        commission_bps: 0,
        jailed_until:   None,
    }
}

#[test]
fn from_active_validators_builds_set_from_bonded_validators() {
    let mut validators = BTreeMap::new();
    validators.insert(
        Address::from_public_key(&[0x01; 32]),
        bonded_validator(0x01, 1_000),
    );
    validators.insert(
        Address::from_public_key(&[0x02; 32]),
        bonded_validator(0x02, 2_000),
    );

    let vset = ValidatorSet::from_active_validators(5, &validators)
        .expect("bonded validators must succeed");

    assert_eq!(vset.epoch, 5);
    assert_eq!(vset.members.len(), 2);
    assert_eq!(vset.total_power, Amount::from_drop(3_000));
}

#[test]
fn from_active_validators_excludes_unbonded() {
    use crate::validator::ValidatorStatus;
    let mut validators = BTreeMap::new();
    validators.insert(Address::from_public_key(&[0x01; 32]), bonded_validator(0x01, 1_000));
    let mut unbonded = bonded_validator(0x02, 2_000);
    unbonded.status = ValidatorStatus::Unbonded;
    validators.insert(Address::from_public_key(&[0x02; 32]), unbonded);

    let vset = ValidatorSet::from_active_validators(0, &validators)
        .expect("at least one active member");

    assert_eq!(vset.members.len(), 1, "only the Bonded validator is included");
    assert_eq!(vset.total_power, Amount::from_drop(1_000));
}

#[test]
fn from_active_validators_excludes_tombstoned() {
    let mut validators = BTreeMap::new();
    validators.insert(Address::from_public_key(&[0x01; 32]), bonded_validator(0x01, 1_000));
    let mut tombstoned = bonded_validator(0x02, 2_000);
    tombstoned.tombstoned = true;
    validators.insert(Address::from_public_key(&[0x02; 32]), tombstoned);

    let vset = ValidatorSet::from_active_validators(0, &validators)
        .expect("at least one active member");

    assert_eq!(vset.members.len(), 1);
}

#[test]
fn from_active_validators_excludes_jailed() {
    let mut validators = BTreeMap::new();
    validators.insert(Address::from_public_key(&[0x01; 32]), bonded_validator(0x01, 1_000));
    let mut jailed = bonded_validator(0x02, 2_000);
    jailed.jailed_until = Some(u64::MAX);
    validators.insert(Address::from_public_key(&[0x02; 32]), jailed);

    let vset = ValidatorSet::from_active_validators(0, &validators)
        .expect("at least one active member");

    assert_eq!(vset.members.len(), 1);
}

#[test]
fn from_active_validators_errors_on_all_inactive() {
    use crate::error::{CoreError, ValidatorError};
    use crate::validator::ValidatorStatus;
    let mut validators = BTreeMap::new();
    let mut v = bonded_validator(0x01, 1_000);
    v.status = ValidatorStatus::Unbonded;
    validators.insert(Address::from_public_key(&[0x01; 32]), v);

    let err = ValidatorSet::from_active_validators(7, &validators)
        .expect_err("all inactive must error");

    assert!(
        matches!(err, CoreError::Validator(ValidatorError::EmptyValidatorSet { epoch: 7 })),
        "got: {err:?}",
    );
}

#[test]
fn from_active_validators_is_deterministic_regardless_of_btreemap_construction_order() {
    // BTreeMap sorts by Address — same result regardless of insertion order.
    let mut v1 = BTreeMap::new();
    v1.insert(Address::from_public_key(&[0x02; 32]), bonded_validator(0x02, 200));
    v1.insert(Address::from_public_key(&[0x01; 32]), bonded_validator(0x01, 100));

    let mut v2 = BTreeMap::new();
    v2.insert(Address::from_public_key(&[0x01; 32]), bonded_validator(0x01, 100));
    v2.insert(Address::from_public_key(&[0x02; 32]), bonded_validator(0x02, 200));

    let s1 = ValidatorSet::from_active_validators(0, &v1).expect("v1");
    let s2 = ValidatorSet::from_active_validators(0, &v2).expect("v2");

    assert_eq!(s1.hash(), s2.hash());
}
