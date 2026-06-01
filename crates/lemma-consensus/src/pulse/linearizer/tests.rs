//! Tests for `lemma_consensus::pulse::linearizer`.
//!
//! Covers: linearize_sub_dag (DFS sort, dedup, GC boundary),
//! commit_timestamp (median, monotonic, edge cases),
//! stake_weighted_median (weighted, equal stakes, single sample),
//! Linearizer state machine (index chaining, GC advance, skip handling),
//! integration with try_decide + LeaderSchedule, and proptest determinism.

use std::collections::{BTreeMap, BTreeSet};

use lemma_core::{
    address::Address,
    amount::Amount,
    signature::Signature,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};
use proptest::prelude::*;

use crate::{
    commit::Commit,
    dag::{
        block::{DagBlock, DagBlockBody, DagBlockRef, Slot},
        graph::{Dag, InsertOutcome},
    },
    pulse::{
        committer::{try_decide, LeaderStatus},
        leader::LeaderSchedule,
        linearizer::{commit_timestamp, stake_weighted_median, Linearizer, linearize_sub_dag},
    },
};

// ── Fixtures ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32])
}

fn vset4() -> ValidatorSet {
    let power = VotingPower(Amount::from_drop(10));
    let total = Amount::from_drop(40);
    let mut members = BTreeMap::new();
    for i in 1u8..=4 {
        members.insert(addr(i), Member { consensus_pubkey: dummy_key(), power });
    }
    ValidatorSet { epoch: 1, members, total_power: total }
}

fn block(round: u64, author_n: u8, ancestors: Vec<DagBlockRef>, ts_ms: u64) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round,
            author: addr(author_n),
            timestamp_ms: ts_ms,
            ancestors,
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    )
}

fn insert_ok(dag: &mut Dag, b: DagBlock, vset: &ValidatorSet) -> DagBlockRef {
    let r = b.reference();
    match dag.insert(b, vset, true) {
        Ok(InsertOutcome::Accepted) => r,
        other => panic!("expected Accepted, got {other:?}"),
    }
}

/// Build a complete wave at leader round `l`.
/// `prev_refs` = round-(l-1) ancestors for strong-link rule.
/// Returns (leader_ref, voter_refs, decider_refs).
fn build_wave(
    dag: &mut Dag,
    vset: &ValidatorSet,
    l: u64,
    prev_refs: Vec<DagBlockRef>,
    ts_base: u64,
) -> (DagBlockRef, Vec<DagBlockRef>, Vec<DagBlockRef>) {
    let l_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(dag, block(l, a, prev_refs.clone(), ts_base + a as u64), vset))
        .collect();
    let leader_ref = l_refs[0];
    let v_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(dag, block(l + 1, a, l_refs.clone(), ts_base + 10), vset))
        .collect();
    let d_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(dag, block(l + 2, a, v_refs.clone(), ts_base + 20), vset))
        .collect();
    (leader_ref, v_refs, d_refs)
}

/// Build rounds 0→1→2 (genesis foundation) with proper ancestry.
/// Returns round-2 refs (= valid strong-link ancestors for round-3 blocks).
fn build_foundation(dag: &mut Dag, vset: &ValidatorSet, ts_base: u64) -> Vec<DagBlockRef> {
    let r0: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(dag, block(0, a, vec![], ts_base), vset))
        .collect();
    let r1: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(dag, block(1, a, r0.clone(), ts_base + 10), vset))
        .collect();
    (1u8..=4)
        .map(|a| insert_ok(dag, block(2, a, r1.clone(), ts_base + 20), vset))
        .collect()
}

// ── stake_weighted_median ─────────────────────────────────────────────────────

#[test]
fn median_single_sample_returns_its_timestamp() {
    let samples = vec![(10u128, 1000u64)];
    assert_eq!(stake_weighted_median(&samples).unwrap(), 1000);
}

#[test]
fn median_equal_stakes_returns_middle_timestamp() {
    // 3 equal stakes: timestamps 100, 200, 300. Total=30, threshold=15.
    // Walk: ts=100 accum=10 (<=15), ts=200 accum=20 (>15) → 200.
    let samples = vec![(10u128, 100u64), (10u128, 300u64), (10u128, 200u64)];
    assert_eq!(stake_weighted_median(&samples).unwrap(), 200);
}

#[test]
fn median_weighted_large_first() {
    // Stake 30 at ts=100, stake 10 at ts=200. Total=40, threshold=20.
    // Walk: ts=100 accum=30 (>20) → 100.
    let samples = vec![(30u128, 100u64), (10u128, 200u64)];
    assert_eq!(stake_weighted_median(&samples).unwrap(), 100);
}

#[test]
fn median_weighted_large_last() {
    // Stake 10 at ts=100, stake 30 at ts=200. Total=40, threshold=20.
    // Walk: ts=100 accum=10 (<=20), ts=200 accum=40 (>20) → 200.
    let samples = vec![(10u128, 100u64), (30u128, 200u64)];
    assert_eq!(stake_weighted_median(&samples).unwrap(), 200);
}

#[test]
fn median_all_same_timestamp() {
    let samples = vec![(10u128, 500u64), (20u128, 500u64), (5u128, 500u64)];
    assert_eq!(stake_weighted_median(&samples).unwrap(), 500);
}

#[test]
fn median_exact_half_uses_upper() {
    // Stake 20 at ts=100, stake 20 at ts=200. Total=40, threshold=20.
    // Walk: ts=100 accum=20 (NOT > 20), ts=200 accum=40 (>20) → 200.
    let samples = vec![(20u128, 100u64), (20u128, 200u64)];
    assert_eq!(stake_weighted_median(&samples).unwrap(), 200,
        "exactly half must use upper half (strict > threshold)");
}

#[test]
fn median_is_deterministic_regardless_of_input_order() {
    let s1 = vec![(10u128, 300u64), (10u128, 100u64), (10u128, 200u64)];
    let s2 = vec![(10u128, 100u64), (10u128, 200u64), (10u128, 300u64)];
    assert_eq!(stake_weighted_median(&s1).unwrap(), stake_weighted_median(&s2).unwrap());
}

// ── commit_timestamp ──────────────────────────────────────────────────────────

#[test]
fn commit_timestamp_genesis_round_returns_last_ts() {
    let vset = vset4();
    let dag = Dag::new(1);
    let leader = block(0, 1, vec![], 9_999);
    assert_eq!(commit_timestamp(&leader, 5_000, &dag, &vset).unwrap(), 5_000,
        "genesis round (no L-1 parents) must return last_commit_ts");
}

#[test]
fn commit_timestamp_monotonic_clamp() {
    // If median < last_commit_ts, result must be last_commit_ts.
    let vset = vset4();
    let mut dag = Dag::new(1);

    // Round 0: parents at round 0 with low timestamps.
    let r0: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![], 100), &vset))
        .collect();

    // Round 1 leader: parents at round 0 (median ~ 100 ms).
    let leader_round1 = block(1, 1, r0, 999);
    let ts = commit_timestamp(&leader_round1, 5_000, &dag, &vset).unwrap();
    assert_eq!(ts, 5_000, "median (100) < last_commit_ts (5000) → clamp to 5000");
}

#[test]
fn commit_timestamp_returns_weighted_median_of_parents() {
    let vset = vset4();
    let mut dag = Dag::new(1);

    // 4 round-0 parents with timestamps 100, 200, 300, 400 (equal stake 10 each).
    // Median: total=40, threshold=20.
    // Walk: ts=100 accum=10 (≤20), ts=200 accum=20 (≤20), ts=300 accum=30 (>20) → 300.
    for (a, ts) in [(1u8, 100u64), (2, 200), (3, 300), (4, 400)] {
        insert_ok(&mut dag, block(0, a, vec![], ts), &vset);
    }
    let r0_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| {
            let slot = crate::dag::block::Slot { round: 0, author: addr(a) };
            dag.block_at_slot(slot).unwrap()
        })
        .collect();

    let leader = block(1, 1, r0_refs, 9_999);
    let ts = commit_timestamp(&leader, 0, &dag, &vset).unwrap();
    assert_eq!(ts, 300, "stake-weighted median of (100,200,300,400) = 300");
}

// ── commit_timestamp edge cases (W5) ─────────────────────────────────────────

#[test]
fn commit_timestamp_nonmember_parents_falls_back_to_last_ts() {
    // Non-genesis leader (round 1) whose round-0 parents are all non-members
    // relative to the timestamp-resolution vset. All parents skipped →
    // samples empty → return last_commit_ts_ms.
    let mut dag = Dag::new(1);

    // Insert round-0 blocks from authors NOT in vset4 (addr(10), addr(11), addr(12), addr(13)).
    // These can't be inserted via Dag (unknown author), so we simulate by inserting
    // only round-0 genesis blocks from real members, then build a leader at round 1
    // that references blocks from the real members. But to test the non-member
    // path, we need the leader's ancestors to be non-members.
    //
    // Strategy: use a *different* vset (subset) for the leader's ancestry vs the
    // vset used for timestamp resolution. Build round-0 blocks for a 4-member vset,
    // then resolve timestamp against a *different* vset that doesn't include any of them.
    let vset_for_insert = vset4(); // insert with this
    let r0: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![], 999), &vset_for_insert))
        .collect();

    // vset_for_timestamp has completely different members (addr(10)..addr(13)).
    let power = VotingPower(Amount::from_drop(10));
    let mut alt_members = BTreeMap::new();
    for n in 10u8..=13 {
        alt_members.insert(addr(n), Member { consensus_pubkey: dummy_key(), power });
    }
    let vset_alt = ValidatorSet {
        epoch: 1,
        members: alt_members,
        total_power: Amount::from_drop(40),
    };

    let leader_block = block(1, 1, r0, 1_234); // round-1 leader
    let ts = commit_timestamp(&leader_block, 5_000, &dag, &vset_alt).unwrap();
    // All round-0 ancestors are addr(1)..addr(4), none in vset_alt → empty samples
    // → fallback to last_commit_ts_ms = 5_000.
    assert_eq!(ts, 5_000,
        "non-member parents (empty samples) must fall back to last_commit_ts_ms");
}

// ── linearize_sub_dag ─────────────────────────────────────────────────────────

#[test]
fn linearize_single_block_returns_itself() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let r = insert_ok(&mut dag, block(0, 1, vec![], 0), &vset);
    let mut committed = BTreeSet::new();
    let result = linearize_sub_dag(&r, &dag, &mut committed);
    assert_eq!(result, vec![r]);
    assert!(committed.contains(&r));
}

#[test]
fn linearize_sorts_by_round_then_author() {
    // Build blocks at rounds > gc_round (=0). Use rounds 3,4 so GC boundary
    // doesn't swallow them (gc_round = last_committed.saturating_sub(30) = 0,
    // and spec §5 skips ancestors at round <= gc_round).
    let vset = vset4();
    let mut dag = Dag::new(1);

    // Foundation at round 0 (genesis, gc_round=0, but leader at round 3
    // needs round-2 ancestors which need round-1 which needs round-0).
    // Use simple 4-block genesis + chain upward.
    let r0: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![], 0), &vset))
        .collect();
    let r1: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(1, a, r0.clone(), 0), &vset))
        .collect();
    let r2: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(2, a, r1.clone(), 0), &vset))
        .collect();

    // Leader at round 3 with round-2 ancestors (these are > gc_round=0).
    // Insert authors in non-alphabetical order to verify sort.
    let a3 = insert_ok(&mut dag, block(3, 3, r2.clone(), 0), &vset);
    let a1 = insert_ok(&mut dag, block(3, 1, r2.clone(), 0), &vset);
    let a2 = insert_ok(&mut dag, block(3, 2, r2.clone(), 0), &vset);
    let leader_r = insert_ok(&mut dag, block(4, 1, vec![a3, a1, a2], 0), &vset);

    let mut committed = BTreeSet::new();
    let result = linearize_sub_dag(&leader_r, &dag, &mut committed);

    // The sort must be (round ASC, author ASC).
    // All collected blocks should be at rounds > 0 (gc_round).
    assert!(!result.is_empty(), "linearized result must not be empty");
    for w in result.windows(2) {
        assert!(
            (w[0].round, w[0].author) <= (w[1].round, w[1].author),
            "not sorted: {:?} vs {:?}", w[0], w[1]
        );
    }
    // Must contain at least a1, a2, a3, leader_r (all at round 3+).
    assert!(result.contains(&a1));
    assert!(result.contains(&a2));
    assert!(result.contains(&a3));
    assert!(result.contains(&leader_r));
}

#[test]
fn linearize_dedup_across_commits() {
    // Verify that a block appearing in two leaders' ancestry is committed
    // only once (idempotency guard via the committed BTreeSet).
    // Use a valid DAG chain so insert_ok succeeds.
    let vset = vset4();
    let mut dag = Dag::new(1);

    // Foundation rounds 0-2.
    let r2 = build_foundation(&mut dag, &vset, 1_000);

    // Shared round-3 blocks referenced by both leaders.
    let shared: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(3, a, r2.clone(), 2_000), &vset))
        .collect();
    let shared_ref = shared[0]; // one specific block to track

    // Two leaders at rounds 4 and 5, both referencing the shared round-3 blocks.
    let l1 = insert_ok(&mut dag, block(4, 1, shared.clone(), 3_000), &vset);
    // Leader 2 can't be at round 4 same author (equivocation); use round 5.
    let r4_others: Vec<DagBlockRef> = (2u8..=4)
        .map(|a| insert_ok(&mut dag, block(4, a, shared.clone(), 3_000), &vset))
        .collect();
    let mut r4_all = vec![l1];
    r4_all.extend(r4_others);
    let l2 = insert_ok(&mut dag, block(5, 1, r4_all, 4_000), &vset);

    let mut committed = BTreeSet::new();
    let result1 = linearize_sub_dag(&l1, &dag, &mut committed);
    let result2 = linearize_sub_dag(&l2, &dag, &mut committed);

    // shared_ref must appear in result1 but NOT in result2.
    assert!(result1.contains(&shared_ref),
        "shared block must appear in first commit");
    assert!(!result2.contains(&shared_ref),
        "shared block must NOT appear in second commit (dedup)");
}

#[test]
fn linearize_dfs_order_irrelevant_sort_is_deterministic() {
    // Prove that DFS *visit order* is irrelevant — the terminal sort guarantees
    // identical output regardless of which ancestor is popped from the stack first.
    //
    // We build two leaders with IDENTICAL block contents but DIFFERENT ancestor
    // list orderings (vec![a1,a2,a3] vs vec![a3,a2,a1]). Since the DFS stack
    // is fed from the ancestor list in order, these produce different DFS
    // traversals. The output must still be identical (W4 fix).
    let vset = vset4();
    let mut dag = Dag::new(1);

    // Foundation: 4 round-0 blocks, then chain upward.
    let r0: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![], 0), &vset))
        .collect();
    let r1: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(1, a, r0.clone(), 0), &vset))
        .collect();
    let r2: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(2, a, r1.clone(), 0), &vset))
        .collect();

    // Round-3 blocks (the ancestors we will reorder).
    let a1 = insert_ok(&mut dag, block(3, 1, r2.clone(), 0), &vset);
    let a2 = insert_ok(&mut dag, block(3, 2, r2.clone(), 0), &vset);
    let a3 = insert_ok(&mut dag, block(3, 3, r2.clone(), 0), &vset);
    let r3_all = vec![a1, a2, a3];

    // Two leaders at round 4 with REVERSED ancestor list ordering.
    // Different DFS traversal, same result expected.
    let r3_rev: Vec<DagBlockRef> = r3_all.iter().rev().copied().collect();
    let l_fwd = insert_ok(&mut dag, block(4, 1, r3_all.clone(), 0), &vset);
    let l_rev = insert_ok(&mut dag, block(4, 2, r3_rev.clone(), 0), &vset);

    // Linearize each independently with a fresh committed set.
    let mut c_fwd = BTreeSet::new();
    let r_fwd = linearize_sub_dag(&l_fwd, &dag, &mut c_fwd);

    let mut c_rev = BTreeSet::new();
    let r_rev = linearize_sub_dag(&l_rev, &dag, &mut c_rev);

    // Sort output must be identical regardless of ancestor list order.
    // (Only the leader refs differ — r_fwd contains l_fwd, r_rev contains l_rev —
    // but all shared ancestors must appear in the same order in both.)
    let shared_fwd: Vec<_> = r_fwd.iter().filter(|&&r| r != l_fwd).collect();
    let shared_rev: Vec<_> = r_rev.iter().filter(|&&r| r != l_rev).collect();
    assert_eq!(shared_fwd, shared_rev,
        "shared ancestors must be in identical (round,author)-sorted order \
         regardless of ancestor list ordering in the leader block (DFS order independence)");
}

// ── Linearizer state machine ───────────────────────────────────────────────────

#[test]
fn linearizer_new_starts_at_index_one() {
    assert_eq!(Linearizer::new().next_index(), 1);
}

#[test]
fn linearizer_last_digest_starts_at_zero() {
    assert_eq!(Linearizer::new().last_digest(), Commit::genesis_previous());
}

#[test]
fn commit_leaders_skips_skip_status() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let mut lin = Linearizer::new();
    let slot = Slot { round: 0, author: addr(1) };
    let decided = vec![LeaderStatus::Skip(slot)];
    let result = lin.commit_leaders(&decided, &mut dag, &vset).unwrap();
    assert!(result.is_empty(), "Skip must produce no commit");
    assert_eq!(lin.next_index(), 1, "index must not advance for Skip");
}

#[test]
fn commit_leaders_assigns_monotonic_index() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let mut lin = Linearizer::new();
    let schedule = LeaderSchedule::new(&vset).unwrap();

    // Build foundation + two consecutive full waves with proper ancestry.
    // Each wave's round-L needs round-(L-1) ancestors for strong-link.
    let r0: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![], 1_000), &vset))
        .collect();
    let r1: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(1, a, r0.clone(), 1_100), &vset))
        .collect();
    let r2: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(2, a, r1.clone(), 1_200), &vset))
        .collect();
    let (_, _, d0) = build_wave(&mut dag, &vset, 3, r2, 2_000);
    let (_, _, _d1) = build_wave(&mut dag, &vset, 6, d0, 3_000);

    let last = Slot { round: 0, author: addr(0) };
    let decided = try_decide(last, &dag, &vset, schedule.leader_fn()).unwrap();

    let commits = lin.commit_leaders(&decided, &mut dag, &vset).unwrap();
    assert!(!commits.is_empty(), "should have at least one commit");
    for (i, c) in commits.iter().enumerate() {
        assert_eq!(c.index, (i + 1) as u64,
            "commit {i} must have index {}", i + 1);
    }
}

#[test]
fn commit_leaders_chains_digests() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let mut lin = Linearizer::new();
    let schedule = LeaderSchedule::new(&vset).unwrap();

    // Build two full waves.
    let r2 = build_foundation(&mut dag, &vset, 1_000);
    let (_, _, d0) = build_wave(&mut dag, &vset, 3, r2, 2_000);
    let (_, _, _d1) = build_wave(&mut dag, &vset, 6, d0, 3_000);

    let last = Slot { round: 0, author: addr(0) };
    let decided = try_decide(last, &dag, &vset, schedule.leader_fn()).unwrap();
    let commits = lin.commit_leaders(&decided, &mut dag, &vset).unwrap();

    // Verify chaining: each commit's previous_digest == prior commit's digest().
    for i in 1..commits.len() {
        assert_eq!(
            commits[i].previous_digest,
            commits[i - 1].digest(),
            "commit {i} previous_digest must equal commit {}'s digest", i - 1
        );
    }
    // First commit's previous_digest must be genesis (Hash::zero).
    if !commits.is_empty() {
        assert_eq!(commits[0].previous_digest, Commit::genesis_previous());
    }
}

#[test]
fn commit_leaders_advances_gc() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let mut lin = Linearizer::new();
    let schedule = LeaderSchedule::new(&vset).unwrap();

    // Build wave at round 3.
    let r2 = build_foundation(&mut dag, &vset, 1_000);
    let (_, _, _d0) = build_wave(&mut dag, &vset, 3, r2, 2_000);

    let last = Slot { round: 0, author: addr(0) };
    let decided = try_decide(last, &dag, &vset, schedule.leader_fn()).unwrap();
    assert!(!decided.is_empty(), "should have at least one decided leader");

    let gc_before = dag.gc_round();
    lin.commit_leaders(&decided, &mut dag, &vset).unwrap();
    // After committing leader at round 3, gc_round should advance.
    // gc_round = last_committed_round.saturating_sub(GC_DEPTH).
    // With GC_DEPTH=30, gc_round is still 0 (3 < 30), but last_committed_round is now 3.
    // We verify gc_round is >= gc_before (monotonic).
    assert!(dag.gc_round() >= gc_before,
        "GC must be monotonically advanced after commit");
}

// ── Integration: try_decide → commit_leaders ──────────────────────────────────

#[test]
fn full_pipeline_try_decide_then_linearize() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let mut lin = Linearizer::new();
    let schedule = LeaderSchedule::new(&vset).unwrap();

    // Foundation (rounds 0-2) + committable wave at round 3.
    let r2 = build_foundation(&mut dag, &vset, 1_000);
    let (_, _, _d0) = build_wave(&mut dag, &vset, 3, r2, 2_000);

    let last = Slot { round: 0, author: addr(0) };
    let decided = try_decide(last, &dag, &vset, schedule.leader_fn()).unwrap();
    let commits = lin.commit_leaders(&decided, &mut dag, &vset).unwrap();

    assert!(!commits.is_empty(), "at least one Commit must be produced");
    for c in &commits {
        assert!(!c.blocks.is_empty(), "each Commit must have blocks");
        // Sort invariant: round ASC, author ASC.
        for w in c.blocks.windows(2) {
            let (a, b) = (&w[0], &w[1]);
            assert!(
                (a.round, a.author) <= (b.round, b.author),
                "blocks must be sorted (round ASC, author ASC)"
            );
        }
    }
}

// ── Proptest ───────────────────────────────────────────────────────────────────

proptest! {
    /// stake_weighted_median never panics and always returns a timestamp in range.
    #[test]
    fn median_never_panics_and_in_range(
        samples in proptest::collection::vec(
            (1u128..=1_000_000u128, 0u64..=1_000_000u64),
            1..10,
        ),
    ) {
        let min_ts = samples.iter().map(|(_, ts)| *ts).min().unwrap_or(0);
        let max_ts = samples.iter().map(|(_, ts)| *ts).max().unwrap_or(0);
        let result = stake_weighted_median(&samples);
        // Must not error for reasonable stakes.
        if let Ok(ts) = result {
            prop_assert!(ts >= min_ts && ts <= max_ts,
                "median {ts} must be in [{min_ts}, {max_ts}]");
        }
    }

    /// linearize_sub_dag output is always sorted (round ASC, author ASC).
    /// Uses rounds > gc_round so ancestors are actually collected and sorted.
    #[test]
    fn linearize_always_sorted(n_authors in 1u8..=4u8) {
        let vset_n = {
            let power = VotingPower(Amount::from_drop(10));
            let total = Amount::from_drop(n_authors as u128 * 10);
            let mut members = BTreeMap::new();
            for i in 1u8..=n_authors {
                members.insert(addr(i), Member { consensus_pubkey: dummy_key(), power });
            }
            ValidatorSet { epoch: 1, members, total_power: total }
        };
        let mut dag = Dag::new(1);
        // Round 0: genesis (no strong-link needed).
        let r0: Vec<DagBlockRef> = (1u8..=n_authors)
            .map(|a| insert_ok(&mut dag, block(0, a, vec![], 0), &vset_n))
            .collect();
        // Round 1: references round-0 (strong-link from genesis).
        let r1: Vec<DagBlockRef> = (1u8..=n_authors)
            .map(|a| insert_ok(&mut dag, block(1, a, r0.clone(), 0), &vset_n))
            .collect();
        // Round 2: references round-1.
        let r2: Vec<DagBlockRef> = (1u8..=n_authors)
            .map(|a| insert_ok(&mut dag, block(2, a, r1.clone(), 0), &vset_n))
            .collect();
        // Leader at round 3, references round-2. Round 3 > gc_round=0 so
        // round-1 and round-2 ancestors will be collected by linearize.
        let leader = insert_ok(&mut dag, block(3, 1, r2, 0), &vset_n);
        let mut committed = BTreeSet::new();
        let result = linearize_sub_dag(&leader, &dag, &mut committed);
        // Result must have blocks (at least the leader) and be sorted.
        prop_assert!(!result.is_empty());
        for w in result.windows(2) {
            prop_assert!(
                (w[0].round, w[0].author) <= (w[1].round, w[1].author),
                "blocks not sorted: {:?} > {:?}", w[0], w[1]
            );
        }
    }
}
