//! # lemma-consensus
//!
//! DAG-based BFT consensus for the Lemma blockchain:
//! **Surge** (data-availability / dissemination layer) +
//! **Pulse** (deterministic ordering / commit rule).
//!
//! ## Protocol
//!
//! Lemma adopts the **Mysticeti uncertified-DAG** model
//! (`docs/07-CONSENSUS_SPEC.md §0`):
//! - One unified DAG carries both data availability (Surge) and ordering (Pulse).
//! - Blocks are signed by their author only — no separate certification round.
//! - Common-case finality: **3 rounds** (~0.5 s WAN).
//! - Fault threshold: Byzantine stake `< S/3` (`2f+1` quorum throughout).
//!
//! ## Module layout
//!
//! | Module | Role |
//! |--------|------|
//! | `error` | Typed errors for all consensus failure paths |
//! | `stake` | `StakeAggregator` — stake-weighted quorum/validity checks (§1.1) |
//! | `dag`   | DAG types, store, validity rules, threshold clock (§2–3) |
//! | `pulse` | Commit rule, leader schedule, linearizer (§4–6) |
//! | `commit`| `Commit` / `CommittedSubDag`, commit-chain digest (§5) |
//! | `reputation` | `ReputationScores` / `LeaderSwapTable` (§6) |
//! | `fee`   | Burn Fee Model: base-fee calc + distribution (§fee) |
//!
//! Validator-set management, epoch transitions, slashing, and rewards live in
//! later steps of this crate (`docs/13-VALIDATOR_EPOCH_SPEC.md`), reusing
//! `stake` and `reputation` from above.
//!
//! ## Determinism invariants
//!
//! Every node MUST produce identical results from identical inputs
//! (`docs/07-CONSENSUS_SPEC.md §12`):
//! - All ordered maps are `BTreeMap` / `BTreeSet` — never `HashMap`.
//! - Commit timestamp = stake-weighted median of leader parents; never `SystemTime`.
//! - All token / stake arithmetic uses `checked_*` (AGENTS.md §7.4).
//! - No `f64` / `f32` anywhere in the commit path.

// ── Protocol constants ────────────────────────────────────────────────────────

/// A wave is exactly 3 rounds: leader round, voting round, decision round.
///
/// Verified against Mysticeti `commit.rs` (AGENTS.md §9.2).
/// Used by the commit rule (§4.1) and leader-schedule (§6).
pub const WAVE_LENGTH: u64 = 3;

/// Rounds retained before garbage collection.
///
/// Blocks at `round <= last_committed_round - GC_DEPTH` are dropped from DAG
/// state. Default chosen conservatively; tunable per-network in genesis
/// (`docs/07-CONSENSUS_SPEC.md §1`, §9).
pub const GC_DEPTH: u64 = 30;

// ── Wave helpers ──────────────────────────────────────────────────────────────

/// Map a DAG round to its wave number (`round / WAVE_LENGTH`).
///
/// Used throughout the commit rule (§4.1) and leader-schedule (§6).
/// `const fn` so it can be used in constant expressions.
#[must_use]
pub const fn wave_of(round: u64) -> u64 {
    round / WAVE_LENGTH
}

// ── Modules ───────────────────────────────────────────────────────────────────

pub mod dag;
pub mod error;
pub mod pulse;
pub mod stake;

// ── Re-exports ────────────────────────────────────────────────────────────────

pub use dag::block::{CommitVote, DagBlock, DagBlockBody, DagBlockRef, Slot, TxBatchRef};
pub use dag::graph::{Dag, InsertOutcome};
pub use dag::threshold_clock::ThresholdClock;
pub use error::ConsensusError;
pub use pulse::committer::{LeaderStatus, try_decide};
pub use stake::{StakeAggregator, Threshold};
