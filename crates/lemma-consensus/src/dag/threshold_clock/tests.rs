//! Tests for `lemma_consensus::dag::threshold_clock`.
//!
//! Covers: round advancement, quorum threshold (strict >2/3), idempotensi,
//! non-member skip (D5b), round mismatch (past + future), weighted stake,
//! StakeOverflow propagation, catch-up via `at_round`, proptest safety.

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
    dag::block::{DagBlock, DagBlockBody},
    dag::threshold_clock::ThresholdClock,
    error::ConsensusError,
};

// ── Fixtures ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32])
}

/// Uniform-stake committee: `n` validators each with `power` Drop.
/// Total = `n as u128 * power`.
fn vset_uniform(n: u8, power_drop: u128) -> ValidatorSet {
    let power = VotingPower(Amount::from_drop(power_drop));
    let total = Amount::from_drop(n as u128 * power_drop);
    let mut members = BTreeMap::new();
    for i in 1u8..=n {
        members.insert(addr(i), Member { consensus_pubkey: dummy_key(), power });
    }
    ValidatorSet { epoch: 1, members, total_power: total }
}

/// Minimal DagBlock at given round by given author.
fn block_at(round: u64, author_n: u8) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round,
            author: addr(author_n),
            timestamp_ms: 0,
            ancestors: vec![],
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    )
}

// ── Construction ───────────────────────────────────────────────────────────────

#[test]
fn new_starts_at_round_zero() {
    let clock = ThresholdClock::new(Amount::from_drop(40));
    assert_eq!(clock.round(), 0);
}

#[test]
fn at_round_starts_at_given_round() {
    let clock = ThresholdClock::at_round(7, Amount::from_drop(40));
    assert_eq!(clock.round(), 7);
}

// ── Round advancement ──────────────────────────────────────────────────────────

#[test]
fn add_block_advances_on_quorum() {
    // 4 validators × 10 Drop = 40 total. Quorum: > 2/3 × 40 = 26.67 → need 30
    // (3 validators). Adding authors 1, 2, 3 crosses quorum at the 3rd block.
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(40));

    assert_eq!(clock.add_block(&block_at(0, 1), &vset).unwrap(), None);
    assert_eq!(clock.add_block(&block_at(0, 2), &vset).unwrap(), None);
    let result = clock.add_block(&block_at(0, 3), &vset).unwrap();
    assert_eq!(result, Some(1), "clock should advance to round 1 on quorum");
    assert_eq!(clock.round(), 1);
}

#[test]
fn add_block_below_quorum_does_not_advance() {
    // 4 validators × 10 Drop. 2 authors = 20 Drop, NOT > 26.67.
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(40));

    assert_eq!(clock.add_block(&block_at(0, 1), &vset).unwrap(), None);
    assert_eq!(clock.add_block(&block_at(0, 2), &vset).unwrap(), None);
    assert_eq!(clock.round(), 0, "should still be round 0");
}

#[test]
fn add_block_exact_two_thirds_does_not_advance() {
    // 3 validators × 10 Drop = 30 total. Exact 2/3 = 20 Drop (2 validators).
    // Check: 20 × 3 = 60, 30 × 2 = 60. 60 > 60 is FALSE — strict > required.
    let vset = vset_uniform(3, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(30));

    assert_eq!(clock.add_block(&block_at(0, 1), &vset).unwrap(), None);
    assert_eq!(clock.add_block(&block_at(0, 2), &vset).unwrap(), None);
    assert_eq!(clock.round(), 0, "exact 2/3 must NOT advance (strict >)");

    // All 3 → crosses strict threshold (30×3=90 > 30×2=60 ✓).
    let result = clock.add_block(&block_at(0, 3), &vset).unwrap();
    assert_eq!(result, Some(1));
}

// ── Round mismatch ─────────────────────────────────────────────────────────────

#[test]
fn add_block_ignores_past_round() {
    // Advance clock to round 1 first.
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(40));
    clock.add_block(&block_at(0, 1), &vset).unwrap();
    clock.add_block(&block_at(0, 2), &vset).unwrap();
    clock.add_block(&block_at(0, 3), &vset).unwrap();
    assert_eq!(clock.round(), 1);

    // Past-round block (round 0) must be ignored.
    assert_eq!(
        clock.add_block(&block_at(0, 4), &vset).unwrap(),
        None,
        "past-round block must not affect clock"
    );
    assert_eq!(clock.round(), 1);
}

#[test]
fn add_block_ignores_future_round() {
    // Future-round block is handled by Dag suspended buffer (spec §3 rule 4).
    // Clock must silently ignore it — no second buffer here (D5e).
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(40)); // round 0

    assert_eq!(
        clock.add_block(&block_at(5, 1), &vset).unwrap(),
        None,
        "future-round block must not advance clock"
    );
    assert_eq!(clock.round(), 0);
}

// ── Idempotency ────────────────────────────────────────────────────────────────

#[test]
fn add_block_idempotent_author_no_inflation() {
    // Equivocating author submits two blocks at same round. Second add must be
    // idempotent — cannot count the same author twice to fake a quorum.
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(40));

    clock.add_block(&block_at(0, 1), &vset).unwrap();
    clock.add_block(&block_at(0, 2), &vset).unwrap();

    // Author 1 again (equivocation simulation) — must be no-op.
    assert_eq!(
        clock.add_block(&block_at(0, 1), &vset).unwrap(),
        None,
        "re-adding same author must not advance clock"
    );
    assert_eq!(clock.round(), 0, "2 distinct authors still below quorum");
}

// ── Non-member skip (D5b) ──────────────────────────────────────────────────────

#[test]
fn add_block_skips_non_member() {
    // Author 99 is not in the validator set. Block must be silently ignored.
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(40));

    assert_eq!(
        clock.add_block(&block_at(0, 99), &vset).unwrap(),
        None,
        "non-member block must be silently skipped (D5b)"
    );
    assert_eq!(clock.round(), 0);
}

#[test]
fn multiple_non_member_blocks_cannot_advance_clock() {
    // Safety-neutrality: any number of non-member blocks must never advance
    // the clock (D5b). Non-members have 0 stake by definition.
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(40));

    for i in 100u8..=200 {
        let result = clock.add_block(&block_at(0, i), &vset).unwrap();
        assert_eq!(result, None);
    }
    assert_eq!(clock.round(), 0, "non-members must never advance the clock");
}

// ── Multi-round advancement ────────────────────────────────────────────────────

#[test]
fn advance_clears_for_next_round() {
    // After advancing to round 1, accumulator must be cleared so that
    // quorum at round 1 can independently advance to round 2.
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(40));

    // Advance round 0 → 1.
    clock.add_block(&block_at(0, 1), &vset).unwrap();
    clock.add_block(&block_at(0, 2), &vset).unwrap();
    clock.add_block(&block_at(0, 3), &vset).unwrap();
    assert_eq!(clock.round(), 1);

    // Accumulate quorum at round 1.
    assert_eq!(clock.add_block(&block_at(1, 1), &vset).unwrap(), None);
    assert_eq!(clock.add_block(&block_at(1, 2), &vset).unwrap(), None);
    let result = clock.add_block(&block_at(1, 3), &vset).unwrap();
    assert_eq!(result, Some(2), "clock must advance to round 2");
    assert_eq!(clock.round(), 2);
}

#[test]
fn add_block_returns_some_only_on_crossing_call() {
    // Some(new_round) is returned exactly once — on the crossing call.
    // Subsequent blocks at the now-past round return None (round mismatch).
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::new(Amount::from_drop(40));

    clock.add_block(&block_at(0, 1), &vset).unwrap();
    clock.add_block(&block_at(0, 2), &vset).unwrap();
    let crossing = clock.add_block(&block_at(0, 3), &vset).unwrap();
    assert_eq!(crossing, Some(1));

    // Round 0 block after advancement — past-round, ignored.
    assert_eq!(
        clock.add_block(&block_at(0, 4), &vset).unwrap(),
        None,
        "blocks at now-past round must return None after advancement"
    );
}

// ── Weighted stake ─────────────────────────────────────────────────────────────

#[test]
fn add_block_weighted_stake_single_large_author() {
    // Heterogeneous power: author 1 holds > 2/3 of total stake alone.
    // Clock must advance on that single block.
    //   author 1: 70 Drop
    //   authors 2-4: 10 Drop each
    //   total: 100 Drop
    //   quorum: > 66.67 Drop → need > 66.67 → 70 > 66.67 ✓
    let power_large = VotingPower(Amount::from_drop(70));
    let power_small = VotingPower(Amount::from_drop(10));
    let mut members = BTreeMap::new();
    members.insert(addr(1), Member { consensus_pubkey: dummy_key(), power: power_large });
    for i in 2u8..=4 {
        members.insert(addr(i), Member { consensus_pubkey: dummy_key(), power: power_small });
    }
    let vset = ValidatorSet { epoch: 1, members, total_power: Amount::from_drop(100) };
    let mut clock = ThresholdClock::new(Amount::from_drop(100));

    let result = clock.add_block(&block_at(0, 1), &vset).unwrap();
    assert_eq!(result, Some(1), "single large-stake author must advance clock");
}

// ── catch-up / at_round ────────────────────────────────────────────────────────

#[test]
fn at_round_clock_ignores_lower_rounds() {
    // Clock rehydrated at round 5 must ignore blocks at rounds 0-4.
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::at_round(5, Amount::from_drop(40));

    for r in 0u64..5 {
        for a in 1u8..=4 {
            assert_eq!(clock.add_block(&block_at(r, a), &vset).unwrap(), None);
        }
    }
    assert_eq!(clock.round(), 5, "past-round blocks must not affect catch-up clock");
}

#[test]
fn at_round_clock_advances_at_its_round() {
    let vset = vset_uniform(4, 10);
    let mut clock = ThresholdClock::at_round(5, Amount::from_drop(40));

    clock.add_block(&block_at(5, 1), &vset).unwrap();
    clock.add_block(&block_at(5, 2), &vset).unwrap();
    let result = clock.add_block(&block_at(5, 3), &vset).unwrap();
    assert_eq!(result, Some(6), "at_round clock must advance normally at its round");
}

// ── Error path ─────────────────────────────────────────────────────────────────

#[test]
fn stake_overflow_propagates() {
    // Craft a vset where adding a block causes StakeOverflow: author power
    // is u128::MAX, ensuring checked_add overflows on second distinct author.
    // First author: u128::MAX. Second author: 1.
    // After first add: accumulated = u128::MAX.
    // Second add: u128::MAX + 1 overflows.
    let max_power = VotingPower(Amount::from_drop(u128::MAX));
    let small_power = VotingPower(Amount::from_drop(1));
    let mut members = BTreeMap::new();
    members.insert(addr(1), Member { consensus_pubkey: dummy_key(), power: max_power });
    members.insert(addr(2), Member { consensus_pubkey: dummy_key(), power: small_power });
    // total_power itself would overflow, but StakeAggregator uses the stored
    // total_power u128 from construction. We set it to u128::MAX to avoid
    // quorum being reached on the first add (accumulated = MAX, MAX×3 wraps,
    // we need the add to overflow first).
    let vset = ValidatorSet {
        epoch: 1,
        members,
        total_power: Amount::from_drop(u128::MAX),
    };
    let mut clock = ThresholdClock::new(Amount::from_drop(u128::MAX));

    // First add: accumulated = u128::MAX.
    // Quorum check: MAX×3 saturates = u128::MAX; MAX×2 saturates = u128::MAX.
    // u128::MAX > u128::MAX is FALSE → no quorum reached. Returns Ok(None).
    let first = clock.add_block(&block_at(0, 1), &vset);
    assert_eq!(first.unwrap(), None, "first add must not advance (saturating mul: MAX > MAX is false)");

    // Second add: checked_add(u128::MAX, 1) → None (overflow) → StakeOverflow.
    // This pins the overflow propagation contract: if StakeAggregator ever stops
    // returning the error, this test will fail (not silently pass).
    let second = clock.add_block(&block_at(0, 2), &vset);
    assert!(
        matches!(second, Err(ConsensusError::StakeOverflow { .. })),
        "second add must propagate StakeOverflow (D5c), got: {second:?}"
    );
}

// ── Proptest ───────────────────────────────────────────────────────────────────

proptest! {
    /// For any random round and author, add_block must never panic.
    #[test]
    fn add_block_never_panics(
        clock_round in 0u64..100,
        block_round in 0u64..100,
        author_n in 1u8..=4,
        power in 1u128..=1_000_000u128,
    ) {
        let vset = vset_uniform(4, power);
        let mut clock = ThresholdClock::at_round(clock_round, Amount::from_drop(4 * power));
        // Should not panic regardless of input. Error is acceptable (StakeOverflow).
        let _ = clock.add_block(&block_at(block_round, author_n), &vset);
    }

    /// Non-member blocks must never advance the clock, regardless of quantity.
    /// D5b safety-neutrality: non-members have 0 stake, cannot reach 2f+1.
    #[test]
    fn non_member_blocks_never_advance_clock(
        author_n in 100u8..=254,  // not in 1..=4 (vset members)
        round in 0u64..50,
        n_blocks in 1usize..=50,
    ) {
        let vset = vset_uniform(4, 10);
        let mut clock = ThresholdClock::at_round(round, Amount::from_drop(40));
        let initial_round = clock.round();
        for _ in 0..n_blocks {
            let result = clock.add_block(&block_at(round, author_n), &vset).unwrap();
            prop_assert_eq!(result, None, "non-member must never advance clock");
        }
        prop_assert_eq!(clock.round(), initial_round, "clock round must be unchanged");
    }
}
