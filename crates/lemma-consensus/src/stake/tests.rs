//! Tests for `lemma_consensus::stake`.
//!
//! Covers:
//! - Quorum / validity threshold math including exact-boundary (strict >) cases.
//! - Idempotency: same author added twice counts once.
//! - `add` returns `true` on the crossing call and every call after.
//! - Overflow on accumulation returns `StakeOverflow`.
//! - `clear` resets state; `total_power` and `threshold` preserved.
//! - `count` reflects distinct authors only.
//! - `wave_of` round-to-wave mapping.

use lemma_core::{address::Address, amount::Amount, validator::VotingPower};

use crate::{error::ConsensusError, stake::StakeAggregator, wave_of};

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Total voting power helper.
fn tp(drop: u128) -> Amount {
    Amount::from_drop(drop)
}

/// VotingPower helper.
fn vp(drop: u128) -> VotingPower {
    VotingPower(Amount::from_drop(drop))
}

/// Distinct address for validator `n`. Uses `from_public_key([n; 32])`.
fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

// ── Quorum threshold (> 2/3) ──────────────────────────────────────────────────

#[test]
fn quorum_not_reached_below_two_thirds() {
    // 3 equal validators, total = 30. Need > 20 (strictly) to reach quorum.
    // Adding 2 of 3 gives accumulated = 20; 20 * 3 = 60, total * 2 = 60 → 60 > 60 is false.
    let mut agg = StakeAggregator::quorum(tp(30));
    assert!(!agg.add(addr(1), vp(10)).unwrap());
    assert!(!agg.add(addr(2), vp(10)).unwrap());
    assert!(!agg.is_reached());
}

#[test]
fn quorum_reached_above_two_thirds() {
    // 4 validators, total = 40. 3 of 4 gives accumulated = 30; 30 * 3 = 90 > 40 * 2 = 80. ✓
    let mut agg = StakeAggregator::quorum(tp(40));
    assert!(!agg.add(addr(1), vp(10)).unwrap());
    assert!(!agg.add(addr(2), vp(10)).unwrap());
    let crossed = agg.add(addr(3), vp(10)).unwrap();
    assert!(crossed);
    assert!(agg.is_reached());
}

#[test]
fn quorum_boundary_exactly_two_thirds_is_not_reached() {
    // accumulated = 20, total = 30 → 20 * 3 = 60 = 30 * 2 = 60 → NOT > 60. Strict > required.
    let mut agg = StakeAggregator::quorum(tp(30));
    agg.add(addr(1), vp(20)).unwrap();
    assert!(
        !agg.is_reached(),
        "exact 2/3 must NOT satisfy strict quorum (spec §1)"
    );
}

// ── Validity threshold (> 1/3) ────────────────────────────────────────────────

#[test]
fn validity_reached_above_one_third() {
    // total = 30. accumulated = 11 → 11 * 3 = 33 > 30 * 1 = 30. ✓
    let mut agg = StakeAggregator::validity(tp(30));
    let crossed = agg.add(addr(1), vp(11)).unwrap();
    assert!(crossed);
}

#[test]
fn validity_boundary_exactly_one_third_is_not_reached() {
    // accumulated = 10, total = 30 → 10 * 3 = 30 = 30 * 1 = 30 → NOT > 30. Strict > required.
    let mut agg = StakeAggregator::validity(tp(30));
    agg.add(addr(1), vp(10)).unwrap();
    assert!(
        !agg.is_reached(),
        "exact 1/3 must NOT satisfy strict validity (spec §1)"
    );
}

// ── Idempotency (safety invariant) ───────────────────────────────────────────

#[test]
fn add_is_idempotent_same_author_does_not_double_count() {
    let mut agg = StakeAggregator::quorum(tp(30));

    // Add author 1 twice.
    agg.add(addr(1), vp(10)).unwrap();
    agg.add(addr(1), vp(10)).unwrap(); // no-op

    // Accumulated must equal exactly one addition (10), not two (20).
    assert_eq!(
        agg.accumulated(),
        10,
        "duplicate add must not increase accumulated"
    );
    assert_eq!(agg.count(), 1, "duplicate add must not increase count");
}

#[test]
fn add_idempotent_cannot_forge_quorum_with_single_author() {
    // Byzantine scenario: one author added 100 times.
    // With total = 30, single-author power = 10, even 100 adds must not forge quorum.
    let mut agg = StakeAggregator::quorum(tp(30));
    for _ in 0..100 {
        agg.add(addr(1), vp(10)).unwrap();
    }
    assert!(!agg.is_reached(), "idempotency must prevent forged quorum");
    assert_eq!(agg.accumulated(), 10);
}

// ── Crossing and staying true ─────────────────────────────────────────────────

#[test]
fn add_returns_true_on_crossing_call_and_all_subsequent_calls() {
    let mut agg = StakeAggregator::quorum(tp(40));
    assert!(!agg.add(addr(1), vp(10)).unwrap());
    assert!(!agg.add(addr(2), vp(10)).unwrap());
    // Third add crosses the threshold.
    assert!(agg.add(addr(3), vp(10)).unwrap());
    // Fourth add (new author, already reached) also returns true.
    assert!(agg.add(addr(4), vp(10)).unwrap());
    assert!(agg.is_reached());
}

// ── Overflow protection (AGENTS.md §7.4) ─────────────────────────────────────

#[test]
fn add_overflow_returns_stake_overflow_error() {
    // Set total_power to MAX so the aggregator doesn't reject on construction.
    let mut agg = StakeAggregator::quorum(tp(u128::MAX));

    // First add: accumulated = MAX/2 + 1. No overflow yet.
    let half_plus_one = u128::MAX / 2 + 1;
    agg.add(addr(1), vp(half_plus_one)).unwrap();

    // Second add: (MAX/2 + 1) + (MAX/2 + 1) overflows u128.
    let result = agg.add(addr(2), vp(half_plus_one));
    assert!(
        matches!(result, Err(ConsensusError::StakeOverflow { .. })),
        "accumulation overflow must return StakeOverflow, got: {result:?}"
    );
}

// ── clear ─────────────────────────────────────────────────────────────────────

#[test]
fn clear_resets_accumulated_counted_and_reached() {
    let mut agg = StakeAggregator::quorum(tp(40));
    agg.add(addr(1), vp(10)).unwrap();
    agg.add(addr(2), vp(10)).unwrap();
    agg.add(addr(3), vp(10)).unwrap(); // crosses threshold
    assert!(agg.is_reached());

    agg.clear();

    assert_eq!(agg.accumulated(), 0, "accumulated must be 0 after clear");
    assert_eq!(agg.count(), 0, "count must be 0 after clear");
    assert!(!agg.is_reached(), "reached must be false after clear");
}

#[test]
fn clear_preserves_threshold_and_total_power() {
    // After clear, re-adding enough stake reaches threshold again.
    let mut agg = StakeAggregator::quorum(tp(40));
    agg.add(addr(1), vp(10)).unwrap();
    agg.add(addr(2), vp(10)).unwrap();
    agg.add(addr(3), vp(10)).unwrap();
    assert!(agg.is_reached());

    agg.clear();

    // New round: add fresh quorum with different authors.
    agg.add(addr(4), vp(10)).unwrap();
    agg.add(addr(5), vp(10)).unwrap();
    assert!(
        agg.add(addr(6), vp(10)).unwrap(),
        "re-adding quorum after clear must reach threshold"
    );
}

// ── count ─────────────────────────────────────────────────────────────────────

#[test]
fn count_reflects_distinct_authors_only() {
    let mut agg = StakeAggregator::quorum(tp(100));
    agg.add(addr(1), vp(10)).unwrap();
    agg.add(addr(2), vp(10)).unwrap();
    agg.add(addr(1), vp(10)).unwrap(); // duplicate — ignored
    assert_eq!(agg.count(), 2);
}

// ── wave_of ───────────────────────────────────────────────────────────────────

#[test]
fn wave_of_maps_rounds_to_correct_waves() {
    // Wave 0: rounds 0, 1, 2.
    assert_eq!(wave_of(0), 0);
    assert_eq!(wave_of(1), 0);
    assert_eq!(wave_of(2), 0);
    // Wave 1: rounds 3, 4, 5.
    assert_eq!(wave_of(3), 1);
    assert_eq!(wave_of(4), 1);
    assert_eq!(wave_of(5), 1);
    // Wave 2: rounds 6, 7, 8.
    assert_eq!(wave_of(6), 2);
    assert_eq!(wave_of(9), 3);
}

// ── Threshold comparison ──────────────────────────────────────────────────────

#[test]
fn quorum_threshold_is_stricter_than_validity_for_same_stake() {
    // With total = 30, accumulated = 11:
    //   validity: 11 * 3 = 33 > 30 * 1 = 30 → reached ✓
    //   quorum:   11 * 3 = 33 > 30 * 2 = 60 → NOT reached ✓
    let mut q = StakeAggregator::quorum(tp(30));
    let mut v = StakeAggregator::validity(tp(30));

    q.add(addr(1), vp(11)).unwrap();
    v.add(addr(1), vp(11)).unwrap();

    assert!(!q.is_reached(), "quorum must not be reached at 11/30");
    assert!(v.is_reached(), "validity must be reached at 11/30");
}
