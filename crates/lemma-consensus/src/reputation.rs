//! # Reputation scores and leader swap table (spec §6, §13)
//!
//! ## Step 7 (current): minimal stubs
//!
//! This module provides the types needed by [`LeaderSchedule`] to compile:
//! - [`LeaderSwapTable`] — identity map (every candidate leads its own round).
//! - [`ReputationScores`] — placeholder; no data yet.
//!
//! ## Step 9 (upcoming): full implementation
//!
//! `ReputationScores` will be recomputed after every committed sub-DAG,
//! counting how many certificates and votes each authority's blocks earned.
//! `LeaderSwapTable` will use those scores to swap persistently-failing leaders
//! out for high-reputation alternates, improving liveness without affecting
//! safety (`docs/07-CONSENSUS_SPEC.md §6`,
//! `docs/13-VALIDATOR_EPOCH_SPEC.md §4.7`).
//!
//! ## Separation of concerns
//!
//! The swap table is consumed by `pulse::leader::LeaderSchedule`. Keeping it
//! in `reputation.rs` (not `leader.rs`) follows spec §11 layout and lets
//! Step 9 add the full recompute logic without touching the leader module
//! (Decision 7b).
//!
//! [`LeaderSchedule`]: crate::pulse::leader::LeaderSchedule

use lemma_core::address::Address;

// ── ReputationScores ──────────────────────────────────────────────────────────

/// Per-authority reputation scores accumulated from committed sub-DAGs (§6).
///
/// **Step 7 stub.** Step 9 will add certificate/vote counting and the
/// recompute logic called at epoch boundaries
/// (`docs/13-VALIDATOR_EPOCH_SPEC.md §4.7`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReputationScores {
    // Step 9: BTreeMap<Address, u64> scores per authority.
    // Placeholder: unit struct semantics (no data yet).
    _placeholder: (),
}

impl ReputationScores {
    /// Create an empty (zero) reputation scores set.
    #[must_use]
    pub fn empty() -> Self {
        Self { _placeholder: () }
    }
}

// ── LeaderSwapTable ───────────────────────────────────────────────────────────

/// Maps a base round-robin leader candidate to the actual leader for that round.
///
/// **Step 7**: identity map — every candidate is returned unchanged.
///
/// **Step 9** will build the real swap table from [`ReputationScores`]:
/// authorities with persistently low scores are swapped out for
/// high-reputation alternates, improving liveness without affecting safety
/// (the swap is deterministic and epoch-fixed, so every node agrees).
///
/// ## Determinism
///
/// The swap table is recomputed at epoch boundaries from committed sub-DAG
/// data — a pure function of the committed history. Every honest node
/// computes the identical table for the same epoch
/// (`docs/07-CONSENSUS_SPEC.md §12`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaderSwapTable {
    // Step 9: BTreeMap<Address, Address> swap pairs.
    // Step 7: no data — identity swap.
    _placeholder: (),
}

impl LeaderSwapTable {
    /// Create an identity swap table (no authority is swapped).
    ///
    /// Used in Step 7 (no reputation data yet) and as the default for
    /// the first epoch before any committed sub-DAGs have been processed.
    #[must_use]
    pub fn identity() -> Self {
        Self { _placeholder: () }
    }

    /// Map `candidate` to the actual leader for `round`.
    ///
    /// **Step 7**: returns `candidate` unchanged (identity map).
    ///
    /// **Step 9**: will look up whether `candidate` is swapped out for a
    /// high-reputation alternate. The swap is per-round to allow future
    /// pipelining variants where different rounds may swap different leaders.
    #[must_use]
    pub fn swap(&self, candidate: Address, _round: u64) -> Address {
        // Step 7: identity — no swap.
        // Step 9: self.pairs.get(&candidate).copied().unwrap_or(candidate)
        candidate
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
