//! Tests for `lemma_consensus::reputation` (Step 7 minimal stubs).

use lemma_core::address::Address;

use crate::reputation::{LeaderSwapTable, ReputationScores};

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

// ── ReputationScores ──────────────────────────────────────────────────────────

#[test]
fn reputation_scores_empty_constructs() {
    let scores = ReputationScores::empty();
    assert_eq!(scores, ReputationScores::default());
}

#[test]
fn reputation_scores_default_equals_empty() {
    assert_eq!(ReputationScores::default(), ReputationScores::empty());
}

// ── LeaderSwapTable ───────────────────────────────────────────────────────────

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
        assert_eq!(table.swap(a, n as u64), a,
            "identity swap must return candidate unchanged for author {n}");
    }
}

#[test]
fn swap_table_default_is_identity() {
    let default = LeaderSwapTable::default();
    let identity = LeaderSwapTable::identity();
    assert_eq!(default, identity);
}

#[test]
fn swap_table_is_round_independent() {
    // Identity table must return the same candidate regardless of round.
    let table = LeaderSwapTable::identity();
    let candidate = addr(3);
    let first = table.swap(candidate, 0);
    for round in 1..=100 {
        assert_eq!(table.swap(candidate, round), first,
            "identity swap must be round-independent");
    }
}
