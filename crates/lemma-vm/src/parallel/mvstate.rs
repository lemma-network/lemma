//! # Multi-Version State (08-EXECUTION_SPEC §1.1)
//!
//! [`MvState`] is the multi-version concurrency-control (MVCC) store at the
//! heart of Flux parallel execution. It records, per state key, every
//! speculative write stamped with the [`Version`] (`txn_idx`, `incarnation`)
//! that produced it. A read by transaction `j` resolves to the highest-indexed
//! write *strictly below* `j`, falling through to committed base storage when
//! no such write exists.
//!
//! ## Determinism (AGENTS.md §7.1)
//!
//! [`MvState`] is the SOLE place [`DashMap`] is used — it is a pure concurrency
//! container. **Its iteration order NEVER escapes.** Final committed writes are
//! collected into a sorted [`BTreeMap`] keyed by [`StateKey`] (which derives
//! `Ord`) before any hashing or comparison
//! ([`MvState::snapshot_committed_into_btreemap`]). No thread schedule, timing,
//! or `DashMap` shard ordering influences any consensus-visible result.
//!
//! ## Shifted index convention
//!
//! Versions are stored in a per-key `BTreeMap<u32, Entry>` keyed by a *shifted*
//! transaction index:
//!
//! - slot `0` = the pre-block committed storage base (never materialized as an
//!   [`Entry`]; it is the implicit fall-through).
//! - slot `i + 1` = the write produced by transaction `i`.
//!
//! A read by transaction `j` therefore inspects shifted slots `[0, j]`, i.e.
//! base plus txns `[0, j - 1]` — never `j`'s own speculative write. See
//! [`shifted`] and the pinning tests in `mvstate/tests.rs`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use lemma_core::{address::Address, amount::Amount};

// ── Version ─────────────────────────────────────────────────────────────────

/// A write is stamped with the (`txn_idx`, `incarnation`) that produced it.
///
/// Incarnation never regresses for a given `txn_idx` (08-EXECUTION_SPEC §1.2):
/// each re-execution bumps it, so a stale read can be detected by comparing the
/// version it observed against the version currently resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Version {
    /// Position of the producing transaction in block order.
    pub txn_idx: u32,
    /// Re-execution counter for that transaction (0 = first execution).
    pub incarnation: u32,
}

impl Version {
    /// Create a new [`Version`].
    pub fn new(txn_idx: u32, incarnation: u32) -> Self {
        Self {
            txn_idx,
            incarnation,
        }
    }
}

// ── StateKey ────────────────────────────────────────────────────────────────

/// Unified key for all versioned state in [`MvState`].
///
/// [`crate::state::ContractStateView`] exposes four kinds of state; MVCC needs
/// ONE key type to version them uniformly. `Storage` uses `(contract, key)`;
/// `Balance`/`Nonce`/`Code` use the account address.
///
/// Derives `Ord` (via lexicographic field order) so committed writes collect
/// into a deterministic sorted [`BTreeMap`] for the state root (AGENTS.md §7.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateKey {
    /// Contract storage slot: `(contract address, slot key bytes)`.
    Storage {
        /// The contract whose storage namespace this slot belongs to.
        contract: Address,
        /// The arbitrary-bytes storage key.
        key: Vec<u8>,
    },
    /// Native LEM balance of an account.
    Balance(Address),
    /// Transaction nonce of an account.
    Nonce(Address),
    /// Deployed bytecode at a contract address.
    Code(Address),
}

// ── StateValue ──────────────────────────────────────────────────────────────

/// The versioned value mirroring the four [`StateKey`] kinds.
///
/// `Storage` and `Code` carry `Option<Vec<u8>>` where `None` denotes deletion /
/// absence; `Balance` and `Nonce` carry their concrete value types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateValue {
    /// Storage slot value; `None` = deleted.
    Storage(Option<Vec<u8>>),
    /// Account balance in Drop.
    Balance(Amount),
    /// Account nonce.
    Nonce(u64),
    /// Contract bytecode; `None` = absent.
    Code(Option<Vec<u8>>),
}

// ── Entry ───────────────────────────────────────────────────────────────────

/// A single versioned write held at one shifted slot for one key.
///
/// `is_estimate` is set while the producing incarnation is being re-executed
/// (08-EXECUTION_SPEC §1.2): a read landing on an estimate must treat the
/// producer as a dependency rather than trusting a stale value.
#[derive(Debug)]
pub struct Entry {
    /// Incarnation of the producing transaction at write time.
    pub incarnation: u32,
    /// The written value.
    pub value: StateValue,
    /// `true` while the producer is mid-re-execution (stale-write marker).
    pub is_estimate: AtomicBool,
}

impl Entry {
    /// Create a non-estimate entry for `incarnation` holding `value`.
    fn new(incarnation: u32, value: StateValue) -> Self {
        Self {
            incarnation,
            value,
            is_estimate: AtomicBool::new(false),
        }
    }
}

// ── MvReadResult ────────────────────────────────────────────────────────────

/// Outcome of an [`MvState::read`] resolution for transaction `txn_idx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MvReadResult {
    /// Resolved to a versioned write below `txn_idx`.
    Value {
        /// The version that produced the resolved value.
        version: Version,
        /// The resolved value.
        value: StateValue,
    },
    /// Resolved entry is flagged estimate — producer is re-executing.
    Estimate {
        /// The transaction index the reader must wait on.
        blocking_txn: u32,
    },
    /// No write below `txn_idx`; caller falls through to base storage.
    NotFound,
}

// ── Shift helper ────────────────────────────────────────────────────────────

/// Map a transaction index to its shifted slot (`txn_idx + 1`).
///
/// Slot `0` is reserved for the committed base; transaction `i` writes at
/// slot `i + 1`. Saturating add keeps the unreachable `u32::MAX` case total.
fn shifted(txn_idx: u32) -> u32 {
    txn_idx.saturating_add(1)
}

// ── MvState ─────────────────────────────────────────────────────────────────

/// Multi-version store mapping each [`StateKey`] to its versioned writes.
///
/// Backed by [`DashMap`] for lock-striped concurrent access (the AGENTS.md
/// §7.1 concurrency-container exception). Per key, a `BTreeMap<u32, Entry>`
/// holds writes keyed by shifted index, giving ordered highest-below-`j`
/// resolution via `range`.
#[derive(Debug, Default)]
pub struct MvState {
    /// `key → (shifted_txn_idx → entry)`. DashMap order never escapes.
    inner: DashMap<StateKey, BTreeMap<u32, Entry>>,
}

impl MvState {
    /// Create an empty multi-version store.
    pub fn new() -> Self {
        Self {
            inner: DashMap::new(),
        }
    }

    /// Resolve a read of `key` by transaction `txn_idx`.
    ///
    /// Returns the highest versioned write strictly below `txn_idx`
    /// ([`MvReadResult::Value`]), an [`MvReadResult::Estimate`] if that write is
    /// flagged in-flight, or [`MvReadResult::NotFound`] when no write exists
    /// below `txn_idx` (caller falls through to base storage).
    pub fn read(&self, key: &StateKey, txn_idx: u32) -> MvReadResult {
        let Some(versions) = self.inner.get(key) else {
            return MvReadResult::NotFound;
        };
        // Shifted range [0, txn_idx] covers base(0) + txns [0, txn_idx - 1].
        // The reader's own slot (txn_idx + 1) is excluded by construction.
        let Some((&slot, entry)) = versions.range(0..=txn_idx).next_back() else {
            return MvReadResult::NotFound;
        };
        if entry.is_estimate.load(Ordering::SeqCst) {
            // slot is txn_idx_of_producer + 1; recover the producer index.
            return MvReadResult::Estimate {
                blocking_txn: slot.saturating_sub(1),
            };
        }
        MvReadResult::Value {
            version: Version::new(slot.saturating_sub(1), entry.incarnation),
            value: entry.value.clone(),
        }
    }

    /// Insert or replace the write produced by `version` for `key`.
    ///
    /// Stored at shifted slot `version.txn_idx + 1`. A fresh write always
    /// clears the estimate flag (it is the current, trustworthy value).
    pub fn write(&self, key: StateKey, version: Version, value: StateValue) {
        let slot = shifted(version.txn_idx);
        let mut versions = self.inner.entry(key).or_default();
        versions.insert(slot, Entry::new(version.incarnation, value));
    }

    /// Flag every entry written by `txn_idx` as an estimate (on abort).
    ///
    /// Marks the prior incarnation's writes stale so concurrent readers treat
    /// `txn_idx` as a dependency until the re-execution republishes
    /// (08-EXECUTION_SPEC §1.2).
    pub fn mark_estimate(&self, txn_idx: u32, keys: &[StateKey]) {
        let slot = shifted(txn_idx);
        for key in keys {
            if let Some(versions) = self.inner.get(key) {
                if let Some(entry) = versions.get(&slot) {
                    entry.is_estimate.store(true, Ordering::SeqCst);
                }
            }
        }
    }

    /// Remove `txn_idx`'s write for every key in `keys`.
    ///
    /// Used when a re-execution no longer writes a key it wrote previously, so
    /// the stale slot does not shadow lower writes (08-EXECUTION_SPEC §1.2).
    pub fn remove_writes(&self, txn_idx: u32, keys: &[StateKey]) {
        let slot = shifted(txn_idx);
        for key in keys {
            if let Some(mut versions) = self.inner.get_mut(key) {
                versions.remove(&slot);
            }
        }
    }

    /// Collect the highest write per key into a sorted [`BTreeMap`].
    ///
    /// This is the determinism escape barrier (AGENTS.md §7.1): the
    /// `DashMap`'s nondeterministic iteration order is funneled into a
    /// `StateKey`-sorted `BTreeMap` before any state-root hashing or
    /// equivalence comparison. The highest shifted slot per key is the final
    /// committed value (commits are strictly in-order, §1.6).
    pub fn snapshot_committed_into_btreemap(&self) -> BTreeMap<StateKey, StateValue> {
        let mut out = BTreeMap::new();
        for shard in self.inner.iter() {
            if let Some((_, entry)) = shard.value().iter().next_back() {
                out.insert(shard.key().clone(), entry.value.clone());
            }
        }
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
