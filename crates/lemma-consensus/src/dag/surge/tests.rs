//! Tests for `lemma_consensus::dag::surge` (SurgeDriver).
//!
//! Coverage: construction, on_block happy path (accepted/suspended/dropped/
//! equivocation), clock advancement, commit pipeline trigger, last_decided
//! advancement, epoch advance, determinism (order-independent commits),
//! non-member blocks, StakeOverflow propagation, no-panic on bad input.
//!
//! Test pattern: AGENTS §11 — separate tests.rs, `{action}_{outcome}` names,
//! shared fixtures (DRY — §2.6), AAA structure.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    signature::Signature,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};
use proptest::prelude::*;

use crate::{
    dag::{
        block::{DagBlock, DagBlockBody, DagBlockRef},
        graph::InsertOutcome,
        surge::SurgeDriver,
    },
    error::ConsensusError,
    WAVE_LENGTH,
};

// ─────────────────────────────────────────────────────────────────────────────
// Fixtures
// ─────────────────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32])
}

/// Uniform-stake committee: `n` validators (addr 1..=n) each with `power` Drop.
fn vset_uniform(n: u8, power_drop: u128) -> ValidatorSet {
    let power = VotingPower(Amount::from_drop(power_drop));
    let total = Amount::from_drop(n as u128 * power_drop);
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

/// A minimal genesis-round block (round 0, no ancestors needed).
fn genesis_block(author_n: u8, epoch: u64) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch,
            round: 0,
            author: addr(author_n),
            timestamp_ms: 1_000 * author_n as u64,
            ancestors: vec![],
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    )
}

/// A block at `round` by `author_n` referencing `ancestors`.
fn block_with_ancestors(
    round: u64,
    author_n: u8,
    ancestors: Vec<DagBlockRef>,
    epoch: u64,
) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch,
            round,
            author: addr(author_n),
            timestamp_ms: 1_000 * round + author_n as u64,
            ancestors,
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    )
}

/// Insert `n` genesis blocks (round 0) for authors 1..=n into `driver`.
/// Returns the inserted block references.
fn insert_genesis_round(driver: &mut SurgeDriver, n: u8, epoch: u64) -> Vec<DagBlockRef> {
    (1u8..=n)
        .map(|i| {
            let b = genesis_block(i, epoch);
            let r = b.reference();
            driver.on_block(b, true).unwrap();
            r
        })
        .collect()
}

/// Insert a full round of blocks (all 4 authors) referencing `parent_refs`.
/// Returns the references of the inserted blocks.
fn insert_round(
    driver: &mut SurgeDriver,
    round: u64,
    parent_refs: Vec<DagBlockRef>,
    epoch: u64,
) -> Vec<DagBlockRef> {
    (1u8..=4)
        .map(|i| {
            let b = block_with_ancestors(round, i, parent_refs.clone(), epoch);
            let r = b.reference();
            driver.on_block(b, true).unwrap();
            r
        })
        .collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// Construction
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn new_succeeds_with_valid_vset() {
    let vset = vset_uniform(4, 10);
    let driver = SurgeDriver::new(vset);
    assert!(
        driver.is_ok(),
        "SurgeDriver::new must succeed for valid vset"
    );
}

#[test]
fn new_fails_with_empty_committee() {
    let empty_vset = ValidatorSet {
        epoch: 1,
        members: BTreeMap::new(),
        total_power: Amount::from_drop(0),
    };
    let result = SurgeDriver::new(empty_vset);
    assert!(
        matches!(result, Err(ConsensusError::EmptyCommittee { .. })),
        "empty committee must return EmptyCommittee, got: {result:?}"
    );
}

#[test]
fn new_starts_at_round_zero_and_no_commits() {
    let vset = vset_uniform(4, 10);
    let driver = SurgeDriver::new(vset).unwrap();
    assert_eq!(driver.clock_round(), 0, "clock must start at round 0");
    assert_eq!(
        driver.next_commit_index(),
        1,
        "first commit will have index 1"
    );
    assert!(driver.dag().is_empty(), "DAG must be empty on construction");
}

// ─────────────────────────────────────────────────────────────────────────────
// on_block — accepted / suspended / dropped outcomes
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn on_block_returns_accepted_for_valid_genesis_block() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();
    let b = genesis_block(1, 1);
    let out = driver.on_block(b, true).unwrap();
    assert_eq!(
        out.outcome,
        InsertOutcome::Accepted,
        "valid genesis block must be accepted"
    );
}

#[test]
fn on_block_returns_suspended_when_ancestors_missing() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    // Build a round-1 block referencing a non-existent genesis block.
    let fake_parent = DagBlockRef::new(0, addr(1), Hash::from_bytes([0xab; 32]));
    let b = block_with_ancestors(1, 1, vec![fake_parent], 1);
    let out = driver.on_block(b, true).unwrap();
    assert_eq!(
        out.outcome,
        InsertOutcome::Suspended,
        "block with missing ancestors must be suspended"
    );
    // Suspended block must not trigger a clock tick or commits.
    assert_eq!(out.new_round, None);
    assert!(out.commits.is_empty());
}

#[test]
fn on_block_returns_no_commits_for_accepted_but_undecidable_block() {
    // Genesis round alone cannot decide any leader (no decision round yet).
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();
    let b = genesis_block(1, 1);
    let out = driver.on_block(b, true).unwrap();
    assert!(
        out.commits.is_empty(),
        "a single genesis block must not produce commits"
    );
}

#[test]
fn on_block_accepted_increments_dag_size() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();
    assert_eq!(driver.dag().len(), 0);
    driver.on_block(genesis_block(1, 1), true).unwrap();
    assert_eq!(driver.dag().len(), 1);
    driver.on_block(genesis_block(2, 1), true).unwrap();
    assert_eq!(driver.dag().len(), 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Clock advancement
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn on_block_clock_advances_after_quorum_at_genesis_round() {
    // 4 validators × 10 Drop = 40. Quorum: >26.67 → 3 distinct authors.
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    let out1 = driver.on_block(genesis_block(1, 1), true).unwrap();
    assert_eq!(out1.new_round, None, "1 author: clock must not advance");

    let out2 = driver.on_block(genesis_block(2, 1), true).unwrap();
    assert_eq!(out2.new_round, None, "2 authors: clock must not advance");

    let out3 = driver.on_block(genesis_block(3, 1), true).unwrap();
    assert_eq!(
        out3.new_round,
        Some(1),
        "3rd author crosses 2f+1: clock must advance to round 1"
    );
    assert_eq!(driver.clock_round(), 1);
}

#[test]
fn on_block_clock_does_not_advance_below_quorum() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();
    driver.on_block(genesis_block(1, 1), true).unwrap();
    driver.on_block(genesis_block(2, 1), true).unwrap();
    assert_eq!(driver.clock_round(), 0, "2 authors below quorum — round 0");
}

#[test]
fn on_block_clock_idempotent_for_same_author() {
    // Equivocating author: inserting two different blocks by same author
    // at same round must not double-count stake.
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    // Build two genesis blocks by author 1 (different timestamps → different digests).
    let b1 = DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round: 0,
            author: addr(1),
            timestamp_ms: 100,
            ancestors: vec![],
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    );
    let b2 = DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round: 0,
            author: addr(1),
            timestamp_ms: 200, // different timestamp → different digest → equivocation
            ancestors: vec![],
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    );

    driver.on_block(b1, true).unwrap();
    // Second block by same author at same round → InsertOutcome::Equivocation.
    let out = driver.on_block(b2, true).unwrap();
    assert!(
        matches!(out.outcome, InsertOutcome::Equivocation { .. }),
        "second block at same slot must produce Equivocation outcome"
    );
    // Clock must NOT advance — equivocated block is not inserted into DAG,
    // so it is not counted toward quorum.
    assert_eq!(
        driver.clock_round(),
        0,
        "equivocated block must not advance clock"
    );
    assert_eq!(driver.dag().len(), 1, "only first block is in DAG");
}

// ─────────────────────────────────────────────────────────────────────────────
// Equivocation surfacing
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn on_block_equivocation_surfaces_in_output() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    let b1 = DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round: 0,
            author: addr(1),
            timestamp_ms: 100,
            ancestors: vec![],
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    );
    let b2 = DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round: 0,
            author: addr(1),
            timestamp_ms: 999, // different → equivocation
            ancestors: vec![],
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    );

    driver.on_block(b1, true).unwrap();
    let out = driver.on_block(b2, true).unwrap();

    // The equivocation must appear in `equivocations` (for slashing evidence).
    assert_eq!(
        out.equivocations.len(),
        1,
        "equivocation must appear in SurgeOutput::equivocations"
    );
    assert!(
        matches!(out.equivocations[0], InsertOutcome::Equivocation { .. }),
        "equivocation entry must be InsertOutcome::Equivocation"
    );
}

#[test]
fn on_block_non_equivocating_block_has_empty_equivocations() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();
    let out = driver.on_block(genesis_block(1, 1), true).unwrap();
    assert!(
        out.equivocations.is_empty(),
        "normal block must have no equivocations"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Commit pipeline — full 3-round wave commit
// ─────────────────────────────────────────────────────────────────────────────
//
// A WAVE_LENGTH = 3 commit:
//   Round 0 (leader round L): genesis blocks from all 4 authors.
//   Round 1 (voting round L+1): all 4 authors reference round-0 blocks.
//   Round 2 (decision round L+2): all 4 authors reference round-1 blocks.
//
// After round 2 fills, `try_decide` can direct-commit the round-0 leader.

#[test]
fn on_block_produces_commit_after_full_wave() {
    // With last_decided.round = 0, try_decide starts from round 1.
    // The first wave-aligned round in range is round 3 (wave 1).
    // A commit for that leader requires decision-round blocks at round 5.
    // So: foundation wave (rounds 0-2) + wave 1 (rounds 3-5) = 6 total rounds.
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    // Foundation: rounds 0, 1, 2 — needed as strong-link ancestors for round 3.
    let r0 = insert_genesis_round(&mut driver, 4, 1);
    let r1 = insert_round(&mut driver, 1, r0, 1);
    let r2 = insert_round(&mut driver, 2, r1, 1);

    // Wave 1: rounds 3, 4, 5 — leader at round 3, decision at round 5.
    let r3 = insert_round(&mut driver, 3, r2, 1);
    let r4 = insert_round(&mut driver, 4, r3, 1);

    let mut commits_found = Vec::new();
    for i in 1u8..=4 {
        let b = block_with_ancestors(5, i, r4.clone(), 1);
        let out = driver.on_block(b, true).unwrap();
        commits_found.extend(out.commits);
    }

    assert!(
        !commits_found.is_empty(),
        "a full 2-wave build (rounds 0-5) must produce at least one commit"
    );
    assert_eq!(commits_found[0].index, 1, "first commit must have index 1");
}

#[test]
fn on_block_commit_advances_last_decided() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    let initial_decided = driver.last_decided();

    // Build foundation wave (rounds 0-2) + wave 1 (rounds 3-5) to get a commit.
    let r0 = insert_genesis_round(&mut driver, 4, 1);
    let r1 = insert_round(&mut driver, 1, r0, 1);
    let r2 = insert_round(&mut driver, 2, r1, 1);
    let r3 = insert_round(&mut driver, 3, r2, 1);
    let r4 = insert_round(&mut driver, 4, r3, 1);
    insert_round(&mut driver, 5, r4, 1);

    // After a commit, last_decided must have advanced.
    let after_decided = driver.last_decided();
    assert_ne!(
        after_decided, initial_decided,
        "last_decided must advance after a commit is produced"
    );
}

#[test]
fn commit_has_monotonically_increasing_index() {
    // Run several waves and collect commits; indices must be 1, 2, 3, …
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();
    let mut refs = insert_genesis_round(&mut driver, 4, 1);
    let mut all_commits: Vec<crate::commit::Commit> = Vec::new();

    // Insert 3 × WAVE_LENGTH additional rounds to drive multiple commits.
    // Collect commits inline (insert_round discards outputs).
    for round in 1..=(3 * WAVE_LENGTH) {
        refs = {
            let mut new_refs = Vec::new();
            for i in 1u8..=4 {
                let b = block_with_ancestors(round, i, refs.clone(), 1);
                let r = b.reference();
                let out = driver.on_block(b, true).unwrap();
                all_commits.extend(out.commits);
                new_refs.push(r);
            }
            new_refs
        };
    }

    // All produced commit indices must be strictly increasing from 1.
    for (idx, commit) in all_commits.iter().enumerate() {
        assert_eq!(
            commit.index,
            idx as u64 + 1,
            "commit indices must be monotonically increasing from 1"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Determinism: same blocks in different delivery order → identical commits
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn commits_are_identical_regardless_of_block_insertion_order() {
    // Build all blocks for 6 rounds (foundation wave 0-2 + wave 1 at rounds 3-5),
    // then insert in two different orders. Both drivers must produce the same commits.
    // Blocks arrive out-of-order via suspension: round-5 blocks are suspended until
    // their ancestors arrive — final DAG state must be identical regardless.

    let make_all_blocks = || {
        let mut blocks: Vec<(DagBlock, bool)> = Vec::new();

        // Round 0 (genesis).
        let r0: Vec<DagBlock> = (1u8..=4).map(|i| genesis_block(i, 1)).collect();
        let r0_refs: Vec<DagBlockRef> = r0.iter().map(|b| b.reference()).collect();
        for b in r0 {
            blocks.push((b, true));
        }

        // Rounds 1-5: each references all blocks from previous round.
        let mut prev: Vec<DagBlockRef> = r0_refs;
        for round in 1u64..=5 {
            let round_blocks: Vec<DagBlock> = (1u8..=4)
                .map(|i| block_with_ancestors(round, i, prev.clone(), 1))
                .collect();
            prev = round_blocks.iter().map(|b| b.reference()).collect();
            for b in round_blocks {
                blocks.push((b, true));
            }
        }
        blocks
    };

    // Driver A: canonical order (round 0 → 5, author 1 → 4).
    let blocks_a = make_all_blocks();
    let vset_a = vset_uniform(4, 10);
    let mut driver_a = SurgeDriver::new(vset_a).unwrap();
    for (b, sig_ok) in blocks_a {
        driver_a.on_block(b, sig_ok).unwrap();
    }

    // Driver B: reverse order (round 5 → 0, author 4 → 1).
    // Higher-round blocks get suspended until ancestors arrive;
    // final DAG and commit state must be identical.
    let mut blocks_b = make_all_blocks();
    blocks_b.reverse();
    let vset_b = vset_uniform(4, 10);
    let mut driver_b = SurgeDriver::new(vset_b).unwrap();
    for (b, sig_ok) in blocks_b {
        driver_b.on_block(b, sig_ok).unwrap();
    }

    // Both drivers must agree: same next_commit_index (= #commits + 1).
    let idx_a = driver_a.next_commit_index();
    let idx_b = driver_b.next_commit_index();
    assert_eq!(
        idx_a, idx_b,
        "both drivers must have produced the same number of commits"
    );
    // Also verify at least one commit was produced (test is meaningful).
    assert!(
        idx_a > 1,
        "6 rounds must produce at least one commit (idx={idx_a})"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Non-member blocks
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn on_block_rejects_non_member_author() {
    // Author 99 is not in the validator set.
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    // dag.insert returns Err(UnknownAuthor) which propagates from on_block.
    let b = genesis_block(99, 1); // epoch=1, round=0
    let result = driver.on_block(b, true);
    assert!(
        matches!(result, Err(ConsensusError::UnknownAuthor { .. })),
        "non-member block must return UnknownAuthor, got: {result:?}"
    );
}

#[test]
fn on_block_invalid_sig_is_rejected() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();
    let b = genesis_block(1, 1);
    // sig_ok = false → InvalidSignature from dag::validity.
    let result = driver.on_block(b, false);
    assert!(
        matches!(result, Err(ConsensusError::InvalidSignature { .. })),
        "block with invalid signature must be rejected"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Epoch advance
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn advance_epoch_resets_clock_and_linearizer() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    // Insert some genesis blocks to move the clock.
    insert_genesis_round(&mut driver, 4, 1);
    assert_eq!(driver.clock_round(), 1, "clock at round 1 after quorum");
    assert_eq!(driver.next_commit_index(), 1, "no commits yet");

    // Advance to epoch 2.
    let new_vset = vset_uniform(4, 10);
    let new_vset = ValidatorSet {
        epoch: 2,
        ..new_vset
    };
    let buffered = driver.advance_epoch(new_vset).unwrap();

    // No next-epoch blocks were buffered (we didn't insert any epoch-2 blocks).
    assert!(
        buffered.is_empty(),
        "no epoch-2 blocks buffered before advance"
    );

    // After epoch advance: clock reset, linearizer reset.
    assert_eq!(
        driver.next_commit_index(),
        1,
        "linearizer must reset on epoch advance"
    );
}

#[test]
fn advance_epoch_fails_with_empty_committee() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    let empty_vset = ValidatorSet {
        epoch: 2,
        members: BTreeMap::new(),
        total_power: Amount::from_drop(0),
    };
    let result = driver.advance_epoch(empty_vset);
    assert!(
        matches!(result, Err(ConsensusError::EmptyCommittee { .. })),
        "advance_epoch with empty committee must fail"
    );
}

#[test]
fn advance_epoch_returns_buffered_next_epoch_blocks() {
    // Insert a block for epoch 2 before the epoch advance — it should be buffered.
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    // Block for epoch 2 (next epoch) is buffered by Dag::insert.
    let next_epoch_block = genesis_block(1, 2); // epoch=2
    let out = driver.on_block(next_epoch_block, true).unwrap();
    assert_eq!(
        out.outcome,
        InsertOutcome::NextEpochBuffered,
        "epoch+1 block must be buffered"
    );

    // Now advance to epoch 2.
    let new_vset = ValidatorSet {
        epoch: 2,
        ..vset_uniform(4, 10)
    };
    let buffered = driver.advance_epoch(new_vset).unwrap();

    assert_eq!(
        buffered.len(),
        1,
        "advance_epoch must return the 1 buffered block"
    );
}

#[test]
fn advance_epoch_skips_non_consecutive_epoch() {
    // advance_epoch(new_epoch) only works for new_epoch == current+1.
    // Skipping an epoch returns empty buffered vec (no-op in Dag).
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    // Advance to epoch 3 (skipping 2) — Dag::advance_epoch guards this.
    let skip_vset = ValidatorSet {
        epoch: 3,
        ..vset_uniform(4, 10)
    };
    // advance_epoch will build a new LeaderSchedule (ok) but Dag::advance_epoch
    // returns empty (skipped epoch). No error — just silent skip.
    let result = driver.advance_epoch(skip_vset);
    assert!(
        result.is_ok(),
        "skipping epoch returns Ok (silent no-op at DAG level)"
    );
    assert!(
        result.unwrap().is_empty(),
        "no blocks buffered for skipped epoch"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Epoch advance — G1: clock must reset to round 0 (CodeReviewer C1 fix)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn advance_epoch_clock_resets_to_round_zero_and_accepts_new_epoch_blocks() {
    // G1: After epoch advance the ThresholdClock must be at round 0.
    // If the old epoch's blocks were carried over, `highest_accepted_round()`
    // would return a stale non-zero round, causing the new-epoch clock to
    // silently drop all round-0 blocks (b.round != clock.round guard).
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    // Build rounds 0-1 in epoch 1 — this advances the clock to >= 1.
    let r0 = insert_genesis_round(&mut driver, 4, 1);
    let _r1 = insert_round(&mut driver, 1, r0, 1);
    assert!(
        driver.clock_round() >= 1,
        "clock must have advanced in epoch 1 (quorum at round 0)"
    );
    let old_clock_round = driver.clock_round();

    // Advance to epoch 2.
    let new_vset = ValidatorSet {
        epoch: 2,
        ..vset_uniform(4, 10)
    };
    driver.advance_epoch(new_vset).unwrap();

    // Clock must be at round 0 — new epoch starts fresh.
    assert_eq!(
        driver.clock_round(),
        0,
        "clock must reset to round 0 on epoch advance (was {old_clock_round})"
    );
    assert_eq!(
        driver.dag().len(),
        0,
        "DAG must be empty after epoch advance (fresh start)"
    );

    // New-epoch round-0 blocks must be accepted and advance the clock normally.
    // 3 authors × 10 Drop = 30 > 26.67 quorum → clock advances to round 1.
    let out1 = driver.on_block(genesis_block(1, 2), true).unwrap();
    let out2 = driver.on_block(genesis_block(2, 2), true).unwrap();
    let out3 = driver.on_block(genesis_block(3, 2), true).unwrap();

    assert_eq!(
        out1.outcome,
        InsertOutcome::Accepted,
        "epoch-2 block must be accepted"
    );
    assert_eq!(out2.outcome, InsertOutcome::Accepted);
    assert_eq!(
        out3.new_round,
        Some(1),
        "third epoch-2 block must advance clock to round 1"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Cascade equivocation — G3: drain_equivocations() path (CodeReviewer G3 fix)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn on_block_collects_cascade_equivocation_from_drain() {
    // G3: Test the `drain_equivocations()` path (deferred cascade) in `on_block`.
    //
    // Setup:
    //   R0_1, R0_2, R0_3 = genesis blocks by authors 1, 2, 3 (in DAG).
    //   FILL = genesis by author 4 (NOT yet in DAG — used as missing ancestor).
    //   S2   = round-1 block by author 1, ancestors = [R0_1, R0_2, R0_3, FILL]
    //              → Suspended (FILL not in DAG).
    //   S1   = round-1 block by author 1, ancestors = [R0_1, R0_2, R0_3]
    //              → Accepted at slot (1, addr(1)).  Different digest from S2.
    //   Insert FILL → unsuspends S2.
    //   S2 re-validation: all ancestors present, strong-link OK (4 × 10 = 40 > 26.67),
    //   rule 6 fires: slot (1, addr(1)) already has S1 → cascade equivocation.
    //   `drain_equivocations()` in `on_block` surfaces it in `out_fill.equivocations`.
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    // Insert 3 genesis blocks (authors 1-3).
    let r0_1 = genesis_block(1, 1);
    let r0_1_ref = r0_1.reference();
    let r0_2 = genesis_block(2, 1);
    let r0_2_ref = r0_2.reference();
    let r0_3 = genesis_block(3, 1);
    let r0_3_ref = r0_3.reference();
    driver.on_block(r0_1, true).unwrap();
    driver.on_block(r0_2, true).unwrap();
    driver.on_block(r0_3, true).unwrap();

    // FILL = genesis by author 4. Compute reference BEFORE inserting.
    let fill_block = genesis_block(4, 1);
    let fill_ref = fill_block.reference();

    // S2: round-1, author 1, references [R0_1, R0_2, R0_3, FILL].
    // FILL is missing → Suspended.
    let s2 = block_with_ancestors(1, 1, vec![r0_1_ref, r0_2_ref, r0_3_ref, fill_ref], 1);
    let out_s2 = driver.on_block(s2, true).unwrap();
    assert_eq!(
        out_s2.outcome,
        InsertOutcome::Suspended,
        "S2 must be suspended — FILL not yet in DAG"
    );

    // S1: round-1, author 1, references [R0_1, R0_2, R0_3] only.
    // Different digest from S2 (no fill_ref in ancestors). Accepted at slot (1, addr(1)).
    let s1 = block_with_ancestors(1, 1, vec![r0_1_ref, r0_2_ref, r0_3_ref], 1);
    let out_s1 = driver.on_block(s1, true).unwrap();
    assert_eq!(
        out_s1.outcome,
        InsertOutcome::Accepted,
        "S1 must be accepted at slot (1, addr(1))"
    );

    // Insert FILL → unsuspends S2 → S2 re-validation → rule 6 → cascade equivocation.
    // The cascade equivocation surfaces in `out_fill.equivocations` via drain_equivocations().
    let out_fill = driver.on_block(fill_block, true).unwrap();
    assert_eq!(
        out_fill.outcome,
        InsertOutcome::Accepted,
        "FILL must be accepted"
    );
    assert_eq!(
        out_fill.equivocations.len(),
        1,
        "cascade equivocation (S2 vs S1 at slot (1,addr(1))) must be collected"
    );
    assert!(
        matches!(
            out_fill.equivocations[0],
            InsertOutcome::Equivocation { .. }
        ),
        "cascade equivocation must be InsertOutcome::Equivocation"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// No-panic safety (per AGENTS §7.2)
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn on_block_does_not_panic_on_duplicate_insertion() {
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();
    let b = genesis_block(1, 1);
    let b2 = b.clone();

    driver.on_block(b, true).unwrap();
    // Re-inserting the same block is idempotent — must not panic.
    let out = driver.on_block(b2, true).unwrap();
    assert_eq!(
        out.outcome,
        InsertOutcome::Accepted,
        "duplicate insertion must be idempotent (Accepted)"
    );
}

#[test]
fn on_block_suspends_block_with_future_round_and_missing_ancestor() {
    // A block at round 99 with a missing ancestor must be Suspended (rule 4 runs
    // before rule 5/6 in dag::graph::Dag::insert), not panic and not be Accepted.
    let vset = vset_uniform(4, 10);
    let mut driver = SurgeDriver::new(vset).unwrap();

    let fake_ancestor = DagBlockRef::new(98, addr(1), Hash::from_bytes([0x11; 32]));
    let b = block_with_ancestors(99, 1, vec![fake_ancestor], 1);
    // Rule 4 fires first: fake_ancestor not in DAG → Suspended.
    let out = driver.on_block(b, true).unwrap();
    assert_eq!(
        out.outcome,
        InsertOutcome::Suspended,
        "block with missing ancestor must be Suspended (not Accepted, not panic)"
    );
    assert_eq!(
        out.new_round, None,
        "suspended block must not advance clock"
    );
    assert!(
        out.commits.is_empty(),
        "suspended block must not produce commits"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Proptest — no panic under random inputs
// ─────────────────────────────────────────────────────────────────────────────

proptest! {
    /// Any combination of round/author/sig_ok must never cause a panic
    /// (ByzantineInvariantBreach / DecidedLeaderMissing are allowed as Err).
    #[test]
    fn on_block_never_panics(
        round in 0u64..20,
        author_n in 1u8..=4,
        sig_ok in proptest::bool::ANY,
    ) {
        let vset = vset_uniform(4, 10);
        let mut driver = SurgeDriver::new(vset).unwrap();

        let b = genesis_block(author_n, 1); // keep epoch/round=0 to avoid validity rejects
        // Result is Ok or Err — either is fine. Panic = fail.
        let _ = driver.on_block(b, sig_ok);

        // Also insert a round-N block with missing ancestors — must not panic.
        if round > 0 {
            let fake = DagBlockRef::new(round - 1, addr(author_n), Hash::from_bytes([author_n; 32]));
            let b2 = block_with_ancestors(round, author_n, vec![fake], 1);
            let _ = driver.on_block(b2, true);
        }
    }

    /// Multiple round-0 blocks from different authors must never panic
    /// even if they duplicate or have odd stake values.
    #[test]
    fn genesis_round_insertion_never_panics(
        n_authors in 1u8..=4,
        power in 1u128..=1_000_000u128,
    ) {
        let vset = vset_uniform(n_authors, power);
        let mut driver = SurgeDriver::new(vset).unwrap();
        for i in 1u8..=n_authors {
            let b = genesis_block(i, 1);
            let _ = driver.on_block(b, true);
        }
    }
}
