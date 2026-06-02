//! Tests for `lemma_consensus::dag::validity`.
//!
//! Tests each check function in isolation — no full `Dag` state needed.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    signature::Signature,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};

use crate::{
    dag::block::{DagBlock, DagBlockBody, DagBlockRef},
    dag::validity::{
        check_author_and_signature, check_gc_boundary, check_no_equivocation,
        check_strong_link_quorum, collect_missing_ancestors,
    },
    error::ConsensusError,
};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn hash(n: u8) -> Hash {
    Hash::from_bytes([n; 32])
}

fn block_ref(round: u64, n: u8) -> DagBlockRef {
    DagBlockRef::new(round, addr(n), hash(n))
}

fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32])
}

/// 4-validator equal-stake committee. Total power = 40 Drop. Quorum = 3 of 4.
fn vset_4() -> ValidatorSet {
    let power = VotingPower(Amount::from_drop(10));
    let mut members = BTreeMap::new();
    for n in 1u8..=4 {
        members.insert(
            addr(n),
            Member {
                consensus_pubkey: dummy_key(),
                power,
            },
        );
    }
    ValidatorSet {
        epoch: 1,
        members,
        total_power: Amount::from_drop(40),
    }
}

fn make_block(round: u64, author_n: u8, ancestors: Vec<DagBlockRef>) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round,
            author: addr(author_n),
            timestamp_ms: 0,
            ancestors,
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    )
}

// ── check_author_and_signature ────────────────────────────────────────────────

#[test]
fn check_author_and_signature_known_author_and_sig_ok_passes() {
    let vset = vset_4();
    let block = make_block(1, 1, vec![]);
    assert!(check_author_and_signature(&block, &vset, true).is_ok());
}

#[test]
fn check_author_and_signature_unknown_author_returns_error() {
    let vset = vset_4();
    let block = make_block(1, 9, vec![]); // addr(9) not in vset
    let err = check_author_and_signature(&block, &vset, true).unwrap_err();
    assert!(matches!(err, ConsensusError::UnknownAuthor { .. }));
}

#[test]
fn check_author_and_signature_sig_fail_returns_error() {
    let vset = vset_4();
    let block = make_block(1, 1, vec![]);
    let err = check_author_and_signature(&block, &vset, false).unwrap_err();
    assert!(matches!(err, ConsensusError::InvalidSignature { .. }));
}

#[test]
fn check_author_and_signature_unknown_author_takes_precedence_over_bad_sig() {
    // Unknown author is checked first (membership before sig).
    let vset = vset_4();
    let block = make_block(1, 9, vec![]);
    let err = check_author_and_signature(&block, &vset, false).unwrap_err();
    assert!(matches!(err, ConsensusError::UnknownAuthor { .. }));
}

// ── check_gc_boundary ─────────────────────────────────────────────────────────

#[test]
fn check_gc_boundary_round_above_gc_passes() {
    assert!(check_gc_boundary(10, 5).is_ok());
}

#[test]
fn check_gc_boundary_round_exactly_at_gc_rejected() {
    // Strict >: round must be ABOVE gc_round, not equal.
    let err = check_gc_boundary(5, 5).unwrap_err();
    assert!(matches!(
        err,
        ConsensusError::BelowGcBoundary {
            round: 5,
            gc_round: 5
        }
    ));
}

#[test]
fn check_gc_boundary_round_below_gc_rejected() {
    let err = check_gc_boundary(3, 10).unwrap_err();
    assert!(matches!(
        err,
        ConsensusError::BelowGcBoundary {
            round: 3,
            gc_round: 10
        }
    ));
}

#[test]
fn check_gc_boundary_genesis_round_zero_exempt() {
    // Genesis round (0) is always exempt, even when gc_round = 0.
    assert!(check_gc_boundary(0, 0).is_ok());
}

// ── check_strong_link_quorum ──────────────────────────────────────────────────

#[test]
fn check_strong_link_quorum_genesis_round_exempt() {
    let vset = vset_4();
    // Round 0: no prev round → no strong links needed.
    let block = make_block(0, 1, vec![]);
    assert!(check_strong_link_quorum(&block, &vset).is_ok());
}

#[test]
fn check_strong_link_quorum_sufficient_quorum_passes() {
    // 3 of 4 validators at round 0 → quorum. Block is at round 1.
    let vset = vset_4();
    let ancestors = vec![block_ref(0, 1), block_ref(0, 2), block_ref(0, 3)];
    let block = make_block(1, 4, ancestors);
    assert!(check_strong_link_quorum(&block, &vset).is_ok());
}

#[test]
fn check_strong_link_quorum_exact_two_thirds_not_sufficient() {
    // 2 of 4 validators at round 0 → 20 * 3 = 60, total * 2 = 80. 60 > 80 is false.
    let vset = vset_4();
    let ancestors = vec![block_ref(0, 1), block_ref(0, 2)];
    let block = make_block(1, 3, ancestors);
    let err = check_strong_link_quorum(&block, &vset).unwrap_err();
    assert!(matches!(
        err,
        ConsensusError::InsufficientStrongLinks { .. }
    ));
}

#[test]
fn check_strong_link_quorum_non_member_ancestors_do_not_count() {
    // 2 known members + 1 unknown at round 0 → still only 20 stake → not quorum.
    let vset = vset_4();
    let ancestors = vec![
        block_ref(0, 1),
        block_ref(0, 2),
        block_ref(0, 9), // addr(9) not in vset
    ];
    let block = make_block(1, 3, ancestors);
    let err = check_strong_link_quorum(&block, &vset).unwrap_err();
    assert!(matches!(
        err,
        ConsensusError::InsufficientStrongLinks { .. }
    ));
}

#[test]
fn check_strong_link_quorum_weak_links_do_not_count_toward_quorum() {
    // Weak links at round < prev do NOT count toward strong-link quorum.
    // Only ancestors at exactly round-1 are strong links.
    let vset = vset_4();
    // Block at round 2: strong links must be at round 1.
    // We give 3 ancestors at round 0 (weak, won't count for round 1 strong links)
    // and only 2 at round 1 → insufficient.
    let ancestors = vec![
        block_ref(1, 1),
        block_ref(1, 2),
        block_ref(0, 1), // weak link (round < round-1=1)
        block_ref(0, 2),
        block_ref(0, 3),
    ];
    let block = make_block(2, 4, ancestors);
    let err = check_strong_link_quorum(&block, &vset).unwrap_err();
    assert!(matches!(
        err,
        ConsensusError::InsufficientStrongLinks { .. }
    ));
}

// ── check_no_equivocation ─────────────────────────────────────────────────────

#[test]
fn check_no_equivocation_no_prior_block_passes() {
    let block = make_block(1, 1, vec![]);
    assert!(check_no_equivocation(&block, None).is_ok());
}

#[test]
fn check_no_equivocation_same_block_resubmitted_passes() {
    // Identical block (same digest) = idempotent re-delivery, not equivocation.
    let block = make_block(1, 1, vec![]);
    let existing = Some(block.reference());
    assert!(check_no_equivocation(&block, existing).is_ok());
}

#[test]
fn check_no_equivocation_different_block_same_slot_returns_error() {
    let block_a = make_block(1, 1, vec![]);
    let block_b = make_block(1, 1, vec![block_ref(0, 2)]); // different body → different digest
    let existing = Some(block_a.reference());
    let err = check_no_equivocation(&block_b, existing).unwrap_err();
    assert!(matches!(err, ConsensusError::Equivocation { .. }));
    assert!(err.is_equivocation());
}

#[test]
fn check_no_equivocation_error_contains_both_digests() {
    let block_a = make_block(1, 1, vec![]);
    let block_b = make_block(1, 1, vec![block_ref(0, 2)]);
    let existing = Some(block_a.reference());
    let err = check_no_equivocation(&block_b, existing).unwrap_err();
    if let ConsensusError::Equivocation { first, second, .. } = err {
        assert_eq!(first, block_a.digest);
        assert_eq!(second, block_b.digest);
        assert_ne!(first, second);
    } else {
        panic!("expected Equivocation error");
    }
}

// ── collect_missing_ancestors ─────────────────────────────────────────────────

#[test]
fn collect_missing_ancestors_empty_when_all_present() {
    let block = make_block(1, 1, vec![block_ref(0, 2), block_ref(0, 3)]);
    let present = |r: &DagBlockRef| r.round == 0; // all round-0 refs "present"
    assert!(collect_missing_ancestors(&block, present).is_empty());
}

#[test]
fn collect_missing_ancestors_returns_all_missing() {
    let ref_a = block_ref(0, 2);
    let ref_b = block_ref(0, 3);
    let block = make_block(1, 1, vec![ref_a, ref_b]);
    let present = |_: &DagBlockRef| false; // nothing present
    let missing = collect_missing_ancestors(&block, present);
    assert_eq!(missing.len(), 2);
    assert!(missing.contains(&ref_a));
    assert!(missing.contains(&ref_b));
}
