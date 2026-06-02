//! Tests for `lemma_consensus::pulse::leader`.
//!
//! Covers: round-robin cycle, offset shift, committee ordering (determinism),
//! swap-table integration, leader_fn adapter, integration with try_decide,
//! single-validator edge case, and proptest safety invariants.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    signature::Signature,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};
use proptest::prelude::*;

use crate::{
    dag::{
        block::{DagBlock, DagBlockBody, DagBlockRef, Slot},
        graph::{Dag, InsertOutcome},
    },
    pulse::{committer::try_decide, leader::LeaderSchedule},
    reputation::LeaderSwapTable,
    LEADER_OFFSET,
};

// ── Fixtures ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32])
}

/// Build a ValidatorSet with `n` validators (authors 1..=n), equal power.
fn vset(n: u8) -> ValidatorSet {
    let power = VotingPower(Amount::from_drop(10));
    let total = Amount::from_drop(n as u128 * 10);
    let mut members = BTreeMap::new();
    for i in 1u8..=n {
        members.insert(
            addr(i),
            Member {
                consensus_pubkey: dummy_key(),
                power,
            },
        );
    }
    ValidatorSet {
        epoch: 1,
        members,
        total_power: total,
    }
}

// ── Construction — empty committee (W1) ──────────────────────────────────────

#[test]
fn new_returns_error_on_empty_committee() {
    // Empty ValidatorSet must return Err(EmptyCommittee), never panic (W1, AGENTS §7.2).
    use std::collections::BTreeMap;
    let empty_vset = ValidatorSet {
        epoch: 5,
        members: BTreeMap::new(),
        total_power: Amount::from_drop(0),
    };
    let err = LeaderSchedule::new(&empty_vset).unwrap_err();
    assert!(
        err.is_empty_committee(),
        "empty committee must return EmptyCommittee error, got: {err:?}"
    );
}

#[test]
fn with_offset_returns_error_on_empty_committee() {
    use std::collections::BTreeMap;
    let empty_vset = ValidatorSet {
        epoch: 1,
        members: BTreeMap::new(),
        total_power: Amount::from_drop(0),
    };
    assert!(LeaderSchedule::with_offset(&empty_vset, 0).is_err());
    assert!(LeaderSchedule::with_swap(&empty_vset, 0, LeaderSwapTable::identity()).is_err());
}

// ── Basic construction ─────────────────────────────────────────────────────────

#[test]
fn new_has_correct_committee_size() {
    let schedule = LeaderSchedule::new(&vset(4)).unwrap();
    assert_eq!(schedule.committee_size(), 4);
}

#[test]
fn new_uses_leader_offset_zero() {
    assert_eq!(LEADER_OFFSET, 0);
    let schedule = LeaderSchedule::new(&vset(4)).unwrap();
    assert_eq!(schedule.offset(), 0);
}

#[test]
fn with_offset_stores_offset() {
    let schedule = LeaderSchedule::with_offset(&vset(4), 2).unwrap();
    assert_eq!(schedule.offset(), 2);
}

// ── Round-robin cycle ─────────────────────────────────────────────────────────

#[test]
fn elect_leader_cycles_through_committee() {
    // 4 validators. Leaders at rounds 0..3 must be all 4 distinct authors.
    let v = vset(4);
    let schedule = LeaderSchedule::new(&v).unwrap();
    let leaders: Vec<Address> = (0u64..4).map(|r| schedule.elect_leader(r).author).collect();
    let mut unique = leaders.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        4,
        "4 rounds must cover all 4 distinct authors"
    );
}

#[test]
fn elect_leader_wraps_at_committee_size() {
    // Round 4 must equal round 0 (modulo 4).
    let v = vset(4);
    let schedule = LeaderSchedule::new(&v).unwrap();
    assert_eq!(
        schedule.elect_leader(4).author,
        schedule.elect_leader(0).author,
        "round 4 must wrap to same leader as round 0"
    );
}

#[test]
fn elect_leader_returns_correct_slot_round() {
    // elect_leader(r) must return Slot { round: r, author: _ }.
    let v = vset(4);
    let schedule = LeaderSchedule::new(&v).unwrap();
    for r in 0u64..10 {
        assert_eq!(
            schedule.elect_leader(r).round,
            r,
            "slot round must equal input round"
        );
    }
}

#[test]
fn elect_leader_deterministic_same_round_same_leader() {
    // Two calls with same round must return identical result.
    let v = vset(4);
    let s1 = LeaderSchedule::new(&v).unwrap();
    let s2 = LeaderSchedule::new(&v).unwrap();
    for r in 0u64..20 {
        assert_eq!(
            s1.elect_leader(r),
            s2.elect_leader(r),
            "same round must always elect same leader"
        );
    }
}

// ── Committee ordering (determinism) ──────────────────────────────────────────

#[test]
fn committee_order_matches_btreemap_sorted_address_order() {
    // committee_order must be sorted by Address (BTreeMap key order).
    let v = vset(4);
    let schedule = LeaderSchedule::new(&v).unwrap();
    // Extract all 4 leaders at rounds 0..3 (one per committee slot).
    let leaders: Vec<Address> = (0u64..4).map(|r| schedule.elect_leader(r).author).collect();
    // BTreeMap keys are sorted by Address bytes.
    let btree_order: Vec<Address> = v.members.keys().copied().collect();
    assert_eq!(
        leaders, btree_order,
        "round 0..4 leaders must match BTreeMap sorted key order"
    );
}

#[test]
fn committee_order_is_stable_across_vset_constructions() {
    // Two ValidatorSets with same members must produce identical committee order.
    let v1 = vset(4);
    let v2 = vset(4);
    let s1 = LeaderSchedule::new(&v1).unwrap();
    let s2 = LeaderSchedule::new(&v2).unwrap();
    for r in 0u64..8 {
        assert_eq!(s1.elect_leader(r), s2.elect_leader(r));
    }
}

// ── Overflow safety (S2) ──────────────────────────────────────────────────────

#[test]
fn elect_leader_at_max_round_does_not_panic_and_wraps() {
    // u64::MAX.wrapping_add(offset=1) == 0, so result must equal round 0
    // with offset=0 (since wrapping_add(0) at u64::MAX stays at u64::MAX,
    // which is MAX % 4 = 3).
    let v = vset(4);
    let s_off0 = LeaderSchedule::with_offset(&v, 0).unwrap();
    let s_off1 = LeaderSchedule::with_offset(&v, 1).unwrap();

    // Must not panic — wrapping_add is the hardening.
    let slot_max = s_off0.elect_leader(u64::MAX);
    assert_eq!(
        slot_max.round,
        u64::MAX,
        "slot.round must always equal the input round"
    );
    assert!(
        v.members.contains_key(&slot_max.author),
        "elected leader at u64::MAX must be a committee member"
    );

    // offset=1 at u64::MAX: wrapping_add(1) == 0; same as offset=0 at round 0.
    let slot_wrap = s_off1.elect_leader(u64::MAX);
    assert_eq!(
        slot_wrap.author,
        s_off0.elect_leader(0).author,
        "offset=1 at u64::MAX wraps to same author as offset=0 at round 0"
    );
}

// ── Insertion-order independence (S3) ──────────────────────────────────────────

#[test]
fn committee_order_independent_of_insertion_order() {
    // Two ValidatorSets with the same members but inserted in reverse order
    // must produce identical LeaderSchedule outputs (BTreeMap sorts by Address).
    let power = VotingPower(Amount::from_drop(10));
    let mut fwd: BTreeMap<Address, Member> = BTreeMap::new();
    let mut rev: BTreeMap<Address, Member> = BTreeMap::new();
    for i in 1u8..=4 {
        fwd.insert(
            addr(i),
            Member {
                consensus_pubkey: dummy_key(),
                power,
            },
        );
    }
    for i in (1u8..=4).rev() {
        rev.insert(
            addr(i),
            Member {
                consensus_pubkey: dummy_key(),
                power,
            },
        );
    }
    let total = Amount::from_drop(40);
    let v_fwd = ValidatorSet {
        epoch: 1,
        members: fwd,
        total_power: total,
    };
    let v_rev = ValidatorSet {
        epoch: 1,
        members: rev,
        total_power: total,
    };
    let s_fwd = LeaderSchedule::new(&v_fwd).unwrap();
    let s_rev = LeaderSchedule::new(&v_rev).unwrap();

    for r in 0u64..8 {
        assert_eq!(
            s_fwd.elect_leader(r),
            s_rev.elect_leader(r),
            "insertion order must not affect leader election (round {r})"
        );
    }
}

// ── Offset ────────────────────────────────────────────────────────────────────

#[test]
fn elect_leader_respects_offset() {
    // With offset=1, round 0 leader == round 1 leader of offset-0 schedule.
    let v = vset(4);
    let s0 = LeaderSchedule::with_offset(&v, 0).unwrap();
    let s1 = LeaderSchedule::with_offset(&v, 1).unwrap();
    assert_eq!(
        s1.elect_leader(0).author,
        s0.elect_leader(1).author,
        "offset-1 schedule at round 0 must equal offset-0 at round 1"
    );
}

#[test]
fn offset_shifts_cycle_by_n_positions() {
    // For offset k: elect_leader_offset_k(r).author == elect_leader_offset_0(r+k).author
    let v = vset(4);
    let s0 = LeaderSchedule::with_offset(&v, 0).unwrap();
    for offset in 1u64..=4 {
        let sk = LeaderSchedule::with_offset(&v, offset).unwrap();
        for r in 0u64..4 {
            assert_eq!(
                sk.elect_leader(r).author,
                s0.elect_leader(r + offset).author,
                "offset {offset} at round {r} must match offset-0 at round {}",
                r + offset
            );
        }
    }
}

// ── Single validator ──────────────────────────────────────────────────────────

#[test]
fn single_validator_committee_always_same_leader() {
    let v = vset(1);
    let schedule = LeaderSchedule::new(&v).unwrap();
    let leader = schedule.elect_leader(0).author;
    for r in 0u64..20 {
        assert_eq!(
            schedule.elect_leader(r).author,
            leader,
            "single-validator committee must always elect same leader"
        );
    }
}

// ── Swap table ────────────────────────────────────────────────────────────────

#[test]
fn with_swap_identity_equals_new() {
    let v = vset(4);
    let s_new = LeaderSchedule::new(&v).unwrap();
    let s_swap = LeaderSchedule::with_swap(&v, LEADER_OFFSET, LeaderSwapTable::identity()).unwrap();
    for r in 0u64..8 {
        assert_eq!(
            s_new.elect_leader(r),
            s_swap.elect_leader(r),
            "identity swap must produce same result as new()"
        );
    }
}

// ── leader_fn adapter ─────────────────────────────────────────────────────────

#[test]
fn leader_fn_produces_same_results_as_elect_leader() {
    let v = vset(4);
    let schedule = LeaderSchedule::new(&v).unwrap();
    let f = schedule.leader_fn();
    for r in 0u64..12 {
        assert_eq!(
            f(r),
            schedule.elect_leader(r),
            "leader_fn must produce same result as elect_leader"
        );
    }
}

// ── Integration: leader_fn + try_decide ───────────────────────────────────────

#[test]
fn leader_fn_works_with_try_decide() {
    // Build a complete wave in the DAG and verify try_decide produces a
    // Commit using the real LeaderSchedule as the leader_of function.
    let v = vset(4);
    let schedule = LeaderSchedule::new(&v).unwrap();
    let mut dag = Dag::new(1);
    // addr(0): genesis sentinel, not a committee member (1..=4). Only .round is read.
    let last = Slot {
        round: 0,
        author: addr(0),
    };

    // Determine who leads round 3 (first wave-aligned round > 0).
    let leader3 = schedule.elect_leader(3);

    // Helper: insert and panic if not Accepted.
    let mut insert = |b: DagBlock| -> DagBlockRef {
        let r = b.reference();
        match dag.insert(b, &v, true) {
            Ok(InsertOutcome::Accepted) => r,
            other => panic!("expected Accepted, got {other:?}"),
        }
    };

    // Foundation wave at round 0 (genesis).
    let r0: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert(dag_block(0, a, vec![], 1)))
        .collect();
    let r1: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert(dag_block(1, a, r0.clone(), 1)))
        .collect();
    let r2: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert(dag_block(2, a, r1.clone(), 1)))
        .collect();

    // Wave at round 3 (first wave-aligned round the driver will scan).
    let r3: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert(dag_block(3, a, r2.clone(), 1)))
        .collect();
    let r4: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert(dag_block(4, a, r3.clone(), 1)))
        .collect();
    let _: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert(dag_block(5, a, r4.clone(), 1)))
        .collect();

    // try_decide with the real schedule as leader_of.
    let result = try_decide(last, &dag, &v, schedule.leader_fn()).unwrap();

    assert!(!result.is_empty(), "should decide at least one leader");
    assert_eq!(
        result[0].round(),
        3,
        "first decided leader must be at round 3"
    );

    // W2 fix: use match so the test fails loudly if the wave didn't Commit.
    // An `if let` would silently pass if result[0] is Skip instead of Commit.
    match &result[0] {
        crate::pulse::committer::LeaderStatus::Commit(lref) => {
            assert_eq!(
                lref.author, leader3.author,
                "committed leader must match elect_leader output"
            );
        }
        other => panic!(
            "expected round-3 leader to Commit, got {other:?}; \
             the wave may not have enough blocks or the leader schedule is wrong"
        ),
    }
}

// Helper for integration test: build a DagBlock.
fn dag_block(round: u64, author_n: u8, ancestors: Vec<DagBlockRef>, epoch: u64) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch,
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

// ── Proptest ───────────────────────────────────────────────────────────────────

proptest! {
    /// elect_leader must never panic for any round and committee size.
    #[test]
    fn elect_leader_never_panics(
        n_validators in 1u8..=20,
        round in 0u64..10_000,
        offset in 0u64..100,
    ) {
        let v = vset(n_validators);
        let schedule = LeaderSchedule::with_offset(&v, offset).unwrap();
        // Must not panic.
        let _ = schedule.elect_leader(round);
    }

    /// elect_leader always returns an author that is in the committee.
    #[test]
    fn elect_leader_always_returns_committee_member(
        n_validators in 1u8..=10,
        round in 0u64..1_000,
    ) {
        let v = vset(n_validators);
        let schedule = LeaderSchedule::new(&v).unwrap();
        let slot = schedule.elect_leader(round);
        prop_assert!(
            v.members.contains_key(&slot.author),
            "elected leader {slot:?} must be a committee member"
        );
    }

    /// elect_leader is deterministic: same inputs → same output.
    #[test]
    fn elect_leader_deterministic(
        n_validators in 1u8..=10,
        round in 0u64..1_000,
        offset in 0u64..50,
    ) {
        let v = vset(n_validators);
        let s1 = LeaderSchedule::with_offset(&v, offset).unwrap();
        let s2 = LeaderSchedule::with_offset(&v, offset).unwrap();
        prop_assert_eq!(s1.elect_leader(round), s2.elect_leader(round));
    }
}
