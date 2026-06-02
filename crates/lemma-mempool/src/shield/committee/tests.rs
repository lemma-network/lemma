//! Tests for `shield::committee`.
//!
//! Covers: partition completeness, determinism, weight proportionality,
//! threshold derivation, and all error cases.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};

use super::ShieldCommittee;
use crate::shield::{params::WEIGHT_GRANULARITY_DROP, ShieldError};

// ── Test fixtures ─────────────────────────────────────────────────────────────

/// A dummy `ConsensusKey` using zero bytes (valid for structural tests).
fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952])
}

/// Derive a unique `Address` from a single distinguishing byte.
///
/// Uses `Address::from_public_key` which hashes a 32-byte key to 20 bytes.
/// The resulting address is deterministic for a given `byte`.
fn addr(byte: u8) -> Address {
    Address::from_public_key(&[byte; 32])
}

/// Build a `ValidatorSet` from a list of `(distinguishing_byte, shares)` pairs.
///
/// Each validator's voting power = `shares * WEIGHT_GRANULARITY_DROP` drops,
/// giving exactly `shares` slots in the Ω_i partition.
fn vset_with_shares(epoch: u64, validators: &[(u8, u64)]) -> ValidatorSet {
    let mut members = BTreeMap::new();
    let mut total_power = Amount::from_drop(0);
    for &(byte, shares) in validators {
        let power_drop = u128::from(shares) * WEIGHT_GRANULARITY_DROP;
        let power = VotingPower(Amount::from_drop(power_drop));
        total_power = total_power
            .checked_add(Amount::from_drop(power_drop))
            .unwrap();
        members.insert(
            addr(byte),
            Member { consensus_pubkey: dummy_key(), power },
        );
    }
    ValidatorSet { epoch, members, total_power }
}

// ── Partition completeness ─────────────────────────────────────────────────────

#[test]
fn partition_covers_all_share_ids_exactly_once() {
    // 3 validators with weights 5, 3, 2 → W=10, ShareIds [1..=10]
    let vset = vset_with_shares(1, &[(1, 5), (2, 3), (3, 2)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();

    let mut all_ids: Vec<u16> = committee
        .iter()
        .flat_map(|(_, ids)| ids.iter().copied())
        .collect();
    all_ids.sort_unstable();

    let expected: Vec<u16> = (1..=10).collect();
    assert_eq!(all_ids, expected, "ShareIds must cover 1..=W with no gaps or duplicates");
}

#[test]
fn partition_starts_at_one_not_zero() {
    let vset = vset_with_shares(1, &[(1, 4), (2, 3)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();

    for (_, ids) in committee.iter() {
        assert!(!ids.contains(&0), "ShareId 0 is forbidden (Lagrange rejects x=0)");
    }
}

#[test]
fn partition_blocks_are_contiguous_per_validator() {
    let vset = vset_with_shares(1, &[(10, 6), (20, 4), (30, 3)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();

    for (_, ids) in committee.iter() {
        for window in ids.windows(2) {
            assert_eq!(
                window[1],
                window[0] + 1,
                "ShareId block is not contiguous: {ids:?}"
            );
        }
    }
}

// ── Weight proportionality ────────────────────────────────────────────────────

#[test]
fn weight_proportional_to_stake() {
    // Validator A: 3 shares, Validator B: 6 shares (2× stake of A).
    let vset = vset_with_shares(1, &[(1, 3), (2, 6)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();

    assert_eq!(committee.weight_of(&addr(1)), 3);
    assert_eq!(committee.weight_of(&addr(2)), 6);
    assert_eq!(committee.total_weight(), 9);
}

#[test]
fn stake_below_granularity_rounds_to_zero_and_is_rejected() {
    // Validator A: exactly 1 share (= WEIGHT_GRANULARITY_DROP drops).
    // Validator B: just below 1 share (WEIGHT_GRANULARITY_DROP - 1 drops) → 0 shares → error.
    let mut members = BTreeMap::new();
    let key = dummy_key();

    members.insert(
        addr(1),
        Member {
            consensus_pubkey: key.clone(),
            power: VotingPower(Amount::from_drop(WEIGHT_GRANULARITY_DROP)),
        },
    );
    members.insert(
        addr(2),
        Member {
            consensus_pubkey: key,
            power: VotingPower(Amount::from_drop(WEIGHT_GRANULARITY_DROP - 1)),
        },
    );
    let total = Amount::from_drop(2 * WEIGHT_GRANULARITY_DROP - 1);
    let vset = ValidatorSet { epoch: 0, members, total_power: total };

    let err = ShieldCommittee::from_validator_set(&vset).unwrap_err();
    assert!(
        matches!(err, ShieldError::ZeroWeightValidator(_)),
        "expected ZeroWeightValidator, got: {err:?}"
    );
}

// ── Threshold parameters ──────────────────────────────────────────────────────

#[test]
fn params_match_total_weight() {
    // W=10: t=⌊10/3⌋−1=2, p=⌊20/3⌋=6
    let vset = vset_with_shares(1, &[(1, 5), (2, 3), (3, 2)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let params = committee.params();
    assert_eq!(params.w, 10);
    assert_eq!(params.t, 2);
    assert_eq!(params.p, 6);
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn same_validator_set_produces_identical_committee() {
    let vset = vset_with_shares(5, &[(10, 4), (20, 7), (30, 3)]);
    let c1 = ShieldCommittee::from_validator_set(&vset).unwrap();
    let c2 = ShieldCommittee::from_validator_set(&vset).unwrap();

    let ids1: Vec<_> = c1.iter().map(|(a, ids)| (*a, ids.to_vec())).collect();
    let ids2: Vec<_> = c2.iter().map(|(a, ids)| (*a, ids.to_vec())).collect();
    assert_eq!(ids1, ids2, "committee must be deterministic for identical inputs");
}

// ── Edge cases ────────────────────────────────────────────────────────────────

#[test]
fn single_validator_gets_all_shares() {
    let vset = vset_with_shares(1, &[(1, 10)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();

    assert_eq!(committee.weight_of(&addr(1)), 10);
    assert_eq!(committee.total_weight(), 10);
    assert_eq!(committee.validator_count(), 1);

    let ids = committee.share_ids_of(&addr(1)).unwrap();
    assert_eq!(ids, &(1u16..=10).collect::<Vec<_>>());
}

#[test]
fn skewed_stake_one_validator_dominates() {
    let vset = vset_with_shares(1, &[(1, 90), (2, 10)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    assert_eq!(committee.weight_of(&addr(1)), 90);
    assert_eq!(committee.weight_of(&addr(2)), 10);
    assert_eq!(committee.total_weight(), 100);
}

#[test]
fn unknown_address_has_zero_weight_and_no_ids() {
    let vset = vset_with_shares(1, &[(1, 5), (2, 5)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let stranger = Address::zero();
    assert_eq!(committee.weight_of(&stranger), 0);
    assert!(committee.share_ids_of(&stranger).is_none());
}

// ── Error cases ───────────────────────────────────────────────────────────────

#[test]
fn empty_validator_set_is_too_small() {
    let vset = ValidatorSet {
        epoch: 0,
        members: BTreeMap::new(),
        total_power: Amount::from_drop(0),
    };
    assert_eq!(
        ShieldCommittee::from_validator_set(&vset).unwrap_err(),
        ShieldError::CommitteeTooSmall { have: 0 }
    );
}

#[test]
fn w_below_4_is_too_small() {
    // 3 validators × 1 share each = W=3 → CommitteeTooSmall.
    let vset = vset_with_shares(1, &[(1, 1), (2, 1), (3, 1)]);
    assert_eq!(
        ShieldCommittee::from_validator_set(&vset).unwrap_err(),
        ShieldError::CommitteeTooSmall { have: 3 }
    );
}

#[test]
fn w_4_is_accepted_minimum() {
    let vset = vset_with_shares(1, &[(1, 1), (2, 1), (3, 1), (4, 1)]);
    assert!(ShieldCommittee::from_validator_set(&vset).is_ok());
}

#[test]
fn total_w_above_u16_max_is_domain_too_large() {
    // Two validators with 33 000 shares each → W = 66 000 > 65 535.
    let vset = vset_with_shares(1, &[(1, 33_000), (2, 33_000)]);
    assert_eq!(
        ShieldCommittee::from_validator_set(&vset).unwrap_err(),
        ShieldError::DomainTooLarge { size: 66_000 }
    );
}

#[test]
fn total_w_at_u16_max_is_accepted() {
    // W = 65 535 = u16::MAX. 21845 + 21845 + 21845 = 65535.
    let vset = vset_with_shares(1, &[(1, 21_845), (2, 21_845), (3, 21_845)]);
    assert!(
        ShieldCommittee::from_validator_set(&vset).is_ok(),
        "W=65535 should be accepted"
    );
}
