//! Tests for `lemma_consensus::reputation` (Step 9 full implementation).
//!
//! ## Coverage strategy
//!
//! - `ReputationScores`: scoring, accumulation, empty/absent cases, backward compat.
//! - `LeaderSwapTable`: swap policy (D9c), equal-score guard, no-self-swap,
//!   tie-break by address, determinism.
//! - Safety invariant: every swap target is a committee member (liveness-only).
//! - Integration: `LeaderSchedule::with_swap` + real swap table → correct leader.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};

use crate::{
    commit::Commit,
    dag::block::DagBlockRef,
    pulse::leader::LeaderSchedule,
    reputation::{LeaderSwapTable, ReputationScores},
};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Create an `Address` from a single discriminator byte (test fixture only).
fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

/// Create a `DagBlockRef` with the given author and a zero digest.
fn bref(round: u64, author: Address) -> DagBlockRef {
    DagBlockRef::new(round, author, Hash::zero())
}

/// Build a `Commit` from an explicit list of block refs.
///
/// `leader` is set to the first block in `blocks`; if `blocks` is empty the
/// commit is structurally valid but has no blocks to score.
fn make_commit(index: u64, blocks: Vec<DagBlockRef>) -> Commit {
    let leader = blocks
        .first()
        .copied()
        .unwrap_or_else(|| DagBlockRef::new(1, Address::zero(), Hash::zero()));
    Commit {
        index,
        previous_digest: Hash::zero(),
        timestamp_ms: 0,
        leader,
        blocks,
    }
}

/// Build a `ValidatorSet` from discriminator bytes (each → distinct address).
///
/// All members get equal voting power (1 LEM). Addresses are BTreeMap-sorted.
/// Do not pass duplicate bytes — the second insert would overwrite the first.
fn make_vset(addr_bytes: &[u8]) -> ValidatorSet {
    let one_lem = Amount::from_drop(1_000_000_000_000_000_000);
    let mut members = BTreeMap::new();
    for &b in addr_bytes {
        members.insert(
            addr(b),
            Member {
                consensus_pubkey: ConsensusKey::from_bytes(vec![b; 32], vec![b; 32]),
                power: VotingPower(one_lem),
            },
        );
    }
    let total = Amount::from_drop(addr_bytes.len() as u128 * 1_000_000_000_000_000_000);
    ValidatorSet {
        epoch: 1,
        members,
        total_power: total,
    }
}

/// Return committee addresses in BTreeMap sorted order (Address Ord).
fn sorted_addrs(vset: &ValidatorSet) -> Vec<Address> {
    vset.members.keys().copied().collect()
}

// ── ReputationScores — backward-compat (Step 7 stubs still pass) ──────────────

#[test]
fn reputation_scores_empty_constructs() {
    let scores = ReputationScores::empty();
    assert_eq!(scores, ReputationScores::default());
}

#[test]
fn reputation_scores_default_equals_empty() {
    assert_eq!(ReputationScores::default(), ReputationScores::empty());
}

// ── ReputationScores — Step 9 ─────────────────────────────────────────────────

#[test]
fn from_commits_empty_slice_produces_empty_scores() {
    let scores = ReputationScores::from_commits(&[]);
    assert!(scores.is_empty());
}

#[test]
fn from_commits_counts_each_block_ref_once() {
    // 3 distinct authors, one block each in a single commit.
    let a0 = addr(0);
    let a1 = addr(1);
    let a2 = addr(2);
    let commit = make_commit(1, vec![bref(1, a0), bref(2, a1), bref(3, a2)]);
    let scores = ReputationScores::from_commits(&[commit]);
    assert_eq!(scores.score(&a0), 1);
    assert_eq!(scores.score(&a1), 1);
    assert_eq!(scores.score(&a2), 1);
}

#[test]
fn from_commits_accumulates_across_multiple_commits() {
    let a = addr(7);
    let c1 = make_commit(1, vec![bref(1, a)]);
    let c2 = make_commit(2, vec![bref(2, a), bref(3, a)]);
    let scores = ReputationScores::from_commits(&[c1, c2]);
    // 3 blocks total for author `a`.
    assert_eq!(scores.score(&a), 3);
}

#[test]
fn from_commits_same_author_multiple_blocks_in_one_commit() {
    let a = addr(5);
    let commit = make_commit(1, vec![bref(1, a), bref(2, a), bref(3, a)]);
    let scores = ReputationScores::from_commits(&[commit]);
    assert_eq!(scores.score(&a), 3);
}

#[test]
fn from_commits_multiple_authors_scored_independently() {
    let a0 = addr(0);
    let a1 = addr(1);
    let commits = vec![
        make_commit(1, vec![bref(1, a0), bref(2, a0)]), // a0 gets 2
        make_commit(2, vec![bref(3, a1)]),              // a1 gets 1
    ];
    let scores = ReputationScores::from_commits(&commits);
    assert_eq!(scores.score(&a0), 2);
    assert_eq!(scores.score(&a1), 1);
}

#[test]
fn score_absent_author_returns_zero() {
    let scores = ReputationScores::from_commits(&[make_commit(1, vec![bref(1, addr(0))])]);
    assert_eq!(scores.score(&addr(99)), 0, "absent author must return 0");
}

#[test]
fn score_returns_accumulated_count() {
    let a = addr(3);
    let scores = ReputationScores::from_commits(&[make_commit(1, vec![bref(1, a), bref(2, a)])]);
    assert_eq!(scores.score(&a), 2);
}

#[test]
fn is_empty_true_on_empty_scores() {
    assert!(ReputationScores::empty().is_empty());
}

#[test]
fn is_empty_false_after_accumulation() {
    let scores = ReputationScores::from_commits(&[make_commit(1, vec![bref(1, addr(0))])]);
    assert!(!scores.is_empty());
}

#[test]
fn from_commits_is_deterministic() {
    // Pure function: identical input → identical BTreeMap output.
    let commits = vec![
        make_commit(1, vec![bref(1, addr(0)), bref(2, addr(1))]),
        make_commit(2, vec![bref(3, addr(0))]),
    ];
    assert_eq!(
        ReputationScores::from_commits(&commits),
        ReputationScores::from_commits(&commits),
    );
}

// ── LeaderSwapTable — backward-compat (Step 7 stubs still pass) ───────────────

#[test]
fn swap_table_identity_returns_candidate_unchanged() {
    let table = LeaderSwapTable::identity();
    let candidate = addr(1);
    assert_eq!(table.swap(candidate, 0), candidate);
    assert_eq!(table.swap(candidate, 42), candidate);
    assert_eq!(table.swap(candidate, u64::MAX), candidate);
}

#[test]
fn swap_table_identity_works_for_any_author() {
    let table = LeaderSwapTable::identity();
    for n in 0u8..=10 {
        let a = addr(n);
        assert_eq!(
            table.swap(a, n as u64),
            a,
            "identity swap must return candidate unchanged for author {n}"
        );
    }
}

#[test]
fn swap_table_default_is_identity() {
    assert_eq!(LeaderSwapTable::default(), LeaderSwapTable::identity());
}

#[test]
fn swap_table_is_round_independent() {
    let table = LeaderSwapTable::identity();
    let candidate = addr(3);
    let first = table.swap(candidate, 0);
    for round in 1..=100 {
        assert_eq!(
            table.swap(candidate, round),
            first,
            "identity swap must be round-independent"
        );
    }
}

// ── LeaderSwapTable — Step 9 ──────────────────────────────────────────────────

#[test]
fn from_scores_swap_count_zero_returns_identity() {
    let vset = make_vset(&[0, 1, 2, 3]);
    let scores = ReputationScores::from_commits(&[make_commit(1, vec![bref(1, addr(0))])]);
    let table = LeaderSwapTable::from_scores(&scores, &vset, 0);
    assert!(table.is_identity());
}

#[test]
fn from_scores_empty_committee_returns_identity() {
    let vset = ValidatorSet {
        epoch: 1,
        members: BTreeMap::new(),
        total_power: Amount::zero(),
    };
    let table = LeaderSwapTable::from_scores(&ReputationScores::empty(), &vset, 1);
    assert!(table.is_identity());
}

#[test]
fn from_scores_single_member_committee_returns_identity() {
    // n=1, n/2=0 → actual=0 → identity (cannot swap the only member with itself).
    let vset = make_vset(&[0]);
    let table = LeaderSwapTable::from_scores(&ReputationScores::empty(), &vset, 1);
    assert!(
        table.is_identity(),
        "single-member committee must produce identity swap"
    );
}

#[test]
fn from_scores_no_swap_when_all_scores_equal() {
    // All scores 0 (empty ReputationScores) → no evidence of failure → no swaps.
    let vset = make_vset(&[0, 1, 2, 3]);
    let table = LeaderSwapTable::from_scores(&ReputationScores::empty(), &vset, 1);
    assert!(
        table.is_identity(),
        "equal scores must not produce any swap"
    );
}

#[test]
fn from_scores_swaps_worst_for_best() {
    // 4-member committee; addrs[0] (sorted first) gets 0 blocks, addrs[3] gets 3.
    let vset = make_vset(&[0, 1, 2, 3]);
    let addrs = sorted_addrs(&vset);

    // Give the highest-address member the most blocks; others get 0 or 1.
    let commits = vec![make_commit(
        1,
        vec![
            bref(1, addrs[3]),
            bref(2, addrs[3]),
            bref(3, addrs[3]),
            bref(4, addrs[1]), // middle performers
            bref(5, addrs[2]),
        ],
    )];
    let scores = ReputationScores::from_commits(&commits);
    // scores: addrs[0]=0, addrs[1]=1, addrs[2]=1, addrs[3]=3
    // sort(score,addr): [addrs[0], addrs[1], addrs[2], addrs[3]]
    // swap_count=1: bad=[addrs[0]], good=[addrs[3]]; 0 < 3 → swap.

    let f = (vset.len() - 1) / 3; // f=1 for n=4
    let table = LeaderSwapTable::from_scores(&scores, &vset, f);

    assert_eq!(table.swap(addrs[0], 0), addrs[3], "worst replaced by best");
    assert_eq!(table.swap(addrs[1], 0), addrs[1], "mid member unchanged");
    assert_eq!(table.swap(addrs[2], 0), addrs[2], "mid member unchanged");
    assert_eq!(
        table.swap(addrs[3], 0),
        addrs[3],
        "good member not swapped out"
    );
    assert!(!table.is_identity());
}

#[test]
fn from_scores_tie_break_by_address_in_equal_bad_tier() {
    // addrs[0] and addrs[1] both score 0 (bad tier);
    // addrs[2] and addrs[3] both score 5 (good tier).
    // With swap_count=1, tie-break selects addrs[0] (lower address) as bad
    // and addrs[3] (higher address) as good.
    let vset = make_vset(&[0, 1, 2, 3]);
    let addrs = sorted_addrs(&vset);

    // Only give blocks to addrs[2] and addrs[3].
    let blocks: Vec<DagBlockRef> = (1..=5)
        .map(|r| bref(r, addrs[2]))
        .chain((6..=10).map(|r| bref(r, addrs[3])))
        .collect();
    let scores = ReputationScores::from_commits(&[make_commit(1, blocks)]);
    // addrs[0]=0, addrs[1]=0, addrs[2]=5, addrs[3]=5
    // sort(score,addr): [addrs[0], addrs[1], addrs[2], addrs[3]]
    // swap_count=1: bad=[addrs[0]], good=[addrs[3]]; 0 < 5 → swap.

    let table = LeaderSwapTable::from_scores(&scores, &vset, 1);

    assert_eq!(
        table.swap(addrs[0], 0),
        addrs[3],
        "lower-address bad candidate swapped for higher-address good"
    );
    // addrs[1] also has 0 score but is not the bad candidate (swap_count=1).
    assert_eq!(table.swap(addrs[1], 0), addrs[1]);
}

#[test]
fn from_scores_is_deterministic() {
    let vset = make_vset(&[0, 1, 2, 3]);
    let addrs = sorted_addrs(&vset);
    let commits = vec![make_commit(1, vec![bref(1, addrs[3]), bref(2, addrs[3])])];
    let scores = ReputationScores::from_commits(&commits);

    let t1 = LeaderSwapTable::from_scores(&scores, &vset, 1);
    let t2 = LeaderSwapTable::from_scores(&scores, &vset, 1);
    assert_eq!(t1, t2, "from_scores must be a pure function");
}

#[test]
fn swap_returns_replacement_for_bad_authority_across_rounds() {
    let vset = make_vset(&[0, 1, 2, 3]);
    let addrs = sorted_addrs(&vset);
    let commits = vec![make_commit(1, vec![bref(1, addrs[3]), bref(2, addrs[3])])];
    let scores = ReputationScores::from_commits(&commits);
    let table = LeaderSwapTable::from_scores(&scores, &vset, 1);

    // Swap is epoch-fixed: same replacement regardless of round.
    assert_eq!(table.swap(addrs[0], 0), addrs[3]);
    assert_eq!(
        table.swap(addrs[0], 42),
        addrs[3],
        "round must not affect swap result"
    );
    assert_eq!(table.swap(addrs[0], u64::MAX), addrs[3]);
}

#[test]
fn swap_returns_candidate_unchanged_for_non_swapped_authority() {
    let vset = make_vset(&[0, 1, 2, 3]);
    let addrs = sorted_addrs(&vset);
    let commits = vec![make_commit(1, vec![bref(1, addrs[3]), bref(2, addrs[3])])];
    let scores = ReputationScores::from_commits(&commits);
    let table = LeaderSwapTable::from_scores(&scores, &vset, 1);

    // addrs[1] and addrs[2] are neither bad nor good source — returned unchanged.
    assert_eq!(table.swap(addrs[1], 0), addrs[1]);
    assert_eq!(table.swap(addrs[2], 0), addrs[2]);
    // addrs[3] is the replacement target, not the source — also unchanged.
    assert_eq!(table.swap(addrs[3], 0), addrs[3]);
}

/// Safety invariant: every leader returned by `swap` is a committee member.
///
/// The swap table must never produce a leader outside the committee — that would
/// violate the "liveness-only, never safety" requirement (spec 13 §4.3).
#[test]
fn swapped_target_is_always_a_committee_member() {
    let vset = make_vset(&[0, 1, 2, 3]);
    let addrs = sorted_addrs(&vset);
    let committee: std::collections::BTreeSet<Address> = addrs.iter().copied().collect();

    let commits = vec![make_commit(
        1,
        vec![bref(1, addrs[3]), bref(2, addrs[3]), bref(3, addrs[3])],
    )];
    let scores = ReputationScores::from_commits(&commits);
    let f = (vset.len() - 1) / 3;
    let table = LeaderSwapTable::from_scores(&scores, &vset, f);

    for &candidate in &addrs {
        let leader = table.swap(candidate, 0);
        assert!(
            committee.contains(&leader),
            "swap({candidate:?}) = {leader:?} is not a committee member — safety violation"
        );
    }
}

#[test]
fn is_identity_true_when_no_swaps_exist() {
    assert!(LeaderSwapTable::identity().is_identity());
}

#[test]
fn is_identity_false_when_swaps_exist() {
    let vset = make_vset(&[0, 1, 2, 3]);
    let addrs = sorted_addrs(&vset);
    let commits = vec![make_commit(
        1,
        vec![bref(1, addrs[3]), bref(2, addrs[3]), bref(3, addrs[3])],
    )];
    let scores = ReputationScores::from_commits(&commits);
    let table = LeaderSwapTable::from_scores(&scores, &vset, 1);
    assert!(!table.is_identity());
}

/// S2: cap path — `swap_count` larger than `n/2` is truncated; cross-pairing
/// means the worst bad gets the best good, second-worst gets second-best (D9f).
#[test]
fn from_scores_caps_swap_count_at_half_committee() {
    // n=4, swap_count=3 → capped to n/2=2.
    // Score gradient: addrs[0]=0, addrs[1]=1, addrs[2]=2, addrs[3]=3.
    let vset = make_vset(&[0, 1, 2, 3]);
    let addrs = sorted_addrs(&vset);

    let mut blocks = vec![bref(1, addrs[1])]; // a1 = 1 block
    blocks.extend((2..=3).map(|r| bref(r, addrs[2]))); // a2 = 2 blocks
    blocks.extend((4..=6).map(|r| bref(r, addrs[3]))); // a3 = 3 blocks
    let scores = ReputationScores::from_commits(&[make_commit(1, blocks)]);

    let table = LeaderSwapTable::from_scores(&scores, &vset, 3); // capped to 2
                                                                 // Cross-pairing (D9f): bad=[addrs[0],addrs[1]], good-reversed=[addrs[3],addrs[2]]
                                                                 //   addrs[0] (score 0) → addrs[3] (score 3): 0 < 3 → swap
                                                                 //   addrs[1] (score 1) → addrs[2] (score 2): 1 < 2 → swap
    assert_eq!(table.swap(addrs[0], 0), addrs[3], "worst bad → best good");
    assert_eq!(
        table.swap(addrs[1], 0),
        addrs[2],
        "second-worst bad → second-best good"
    );
    assert_eq!(
        table.swap(addrs[2], 0),
        addrs[2],
        "good source not swapped out"
    );
    assert_eq!(
        table.swap(addrs[3], 0),
        addrs[3],
        "good source not swapped out"
    );
}

/// Integration: `LeaderSchedule::with_swap` + real swap table
/// → `elect_leader` returns the swapped (high-reputation) leader for the bad round.
#[test]
fn integration_leader_schedule_uses_reputation_swap() {
    // 4-member committee; addrs[0] gets 0 blocks, addrs[3] gets 3.
    let vset = make_vset(&[0, 1, 2, 3]);
    let addrs = sorted_addrs(&vset);

    let commits = vec![make_commit(
        1,
        vec![bref(1, addrs[3]), bref(2, addrs[3]), bref(3, addrs[3])],
    )];
    let scores = ReputationScores::from_commits(&commits);
    let f = (vset.len() - 1) / 3; // f=1 for n=4
    let table = LeaderSwapTable::from_scores(&scores, &vset, f);

    let schedule =
        LeaderSchedule::with_swap(&vset, 0, table).expect("non-empty vset must not fail");

    // committee_order = [addrs[0], addrs[1], addrs[2], addrs[3]] (Address-sorted).
    // Round 0 → idx 0 → candidate=addrs[0] → swap → addrs[3]  ← reputation upgrade!
    assert_eq!(
        schedule.elect_leader(0).author,
        addrs[3],
        "round 0 leader (worst author) must be replaced by the high-reputation member"
    );
    // Rounds 1, 2, 3 elect addrs[1], addrs[2], addrs[3] — none are swapped out.
    assert_eq!(schedule.elect_leader(1).author, addrs[1]);
    assert_eq!(schedule.elect_leader(2).author, addrs[2]);
    assert_eq!(schedule.elect_leader(3).author, addrs[3]);
}
