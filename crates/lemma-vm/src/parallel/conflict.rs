//! # Captured Reads + Validation (08-EXECUTION_SPEC §1.3)
//!
//! Each speculative execution records the set of reads it performed. After the
//! suffix of higher-indexed work settles, those reads are re-resolved against
//! the current [`MvState`]. If any read would now resolve to a different
//! version/value, the execution is stale: its incarnation is aborted and
//! re-run (08-EXECUTION_SPEC §1.2, §1.6).
//!
//! ## B5 scope (value-equality validation)
//!
//! B5 validates by *value equality*: a captured read stores the [`StateKey`]
//! and the [`ObservedRead`] it saw (a specific MVCC version+value, or a
//! base-storage fall-through). Re-validation re-resolves the key and compares.
//! The fine-grained `Exists`/`Size`/`Metadata` read-kind optimization of §1.3
//! is deferred (recorded as Technical Debt) — it only *reduces* aborts; it does
//! not affect correctness.

use crate::parallel::mvstate::{MvReadResult, MvState, StateKey, StateValue, Version};

// ── ObservedRead ────────────────────────────────────────────────────────────

/// What a single read observed, captured for later re-validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObservedRead {
    /// Read resolved to a specific MVCC write.
    Versioned {
        /// The version that produced the observed value.
        version: Version,
        /// The observed value.
        value: StateValue,
    },
    /// Read fell through to committed base storage (no MVCC write below it).
    BaseFallthrough,
}

// ── CapturedReads ───────────────────────────────────────────────────────────

/// The ordered set of reads performed by one incarnation.
///
/// Stored as a `Vec<(StateKey, ObservedRead)>`. Duplicate reads of the same key
/// are retained as recorded; re-validation re-checks each entry independently,
/// which is sound (a key that re-resolves identically passes for every entry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapturedReads {
    reads: Vec<(StateKey, ObservedRead)>,
}

impl CapturedReads {
    /// Create an empty read set.
    pub fn new() -> Self {
        Self { reads: Vec::new() }
    }

    /// Record that `key` resolved to `observed`.
    pub fn record(&mut self, key: StateKey, observed: ObservedRead) {
        self.reads.push((key, observed));
    }

    /// Number of recorded reads.
    pub fn len(&self) -> usize {
        self.reads.len()
    }

    /// Returns `true` if no reads were recorded.
    pub fn is_empty(&self) -> bool {
        self.reads.is_empty()
    }
}

// ── Validation ──────────────────────────────────────────────────────────────

/// Re-validate `reads` for transaction `txn_idx` against the current `mv`.
///
/// Returns `true` iff every captured read still resolves to the same outcome.
/// A read that now lands on an [`MvReadResult::Estimate`] is treated as
/// *invalid* (the underlying value is in flux), forcing a re-execution — the
/// conservative, always-correct choice (08-EXECUTION_SPEC §1.3).
///
/// # Arguments
///
/// * `reads` — the read set captured during the incarnation under validation.
/// * `mv` — the current multi-version store.
/// * `txn_idx` — the validating transaction's block index.
pub fn validate(reads: &CapturedReads, mv: &MvState, txn_idx: u32) -> bool {
    reads
        .reads
        .iter()
        .all(|(key, observed)| read_still_matches(mv, txn_idx, key, observed))
}

/// Check that re-resolving `key` for `txn_idx` matches the original `observed`.
fn read_still_matches(mv: &MvState, txn_idx: u32, key: &StateKey, observed: &ObservedRead) -> bool {
    match (mv.read(key, txn_idx), observed) {
        (
            MvReadResult::Value { version, value },
            ObservedRead::Versioned {
                version: ov,
                value: oval,
            },
        ) => version == *ov && value == *oval,
        (MvReadResult::NotFound, ObservedRead::BaseFallthrough) => true,
        // Estimate now in flux, or a version/fallthrough mismatch → stale.
        _ => false,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
