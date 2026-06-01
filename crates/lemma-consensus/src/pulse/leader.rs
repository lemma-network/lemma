//! # Leader schedule — spec §6
//!
//! Implements `elect_leader(round) -> Slot`: the deterministic function that
//! maps a DAG round to its leader slot. Every honest validator computes the
//! identical result from the identical inputs — no communication needed.
//!
//! ## Algorithm (spec §6)
//!
//! 1. **Base round-robin**: `idx = (round + offset) % committee_size`.
//!    The committee is ordered by `Address` (BTreeMap key order) — canonical
//!    and deterministic across all nodes (AGENTS §7.1).
//! 2. **Reputation swap** (Step 9): `candidate = swap_table.swap(candidate, round)`.
//!    Persistently-failing leaders are swapped out for high-reputation alternates.
//!    Step 7 uses an identity swap table (no-op).
//!
//! ## Integration with the commit rule (Decision 6a)
//!
//! [`try_decide`] accepts `leader_of: impl Fn(u64) -> Slot`. Use
//! [`LeaderSchedule::leader_fn`] to produce the closure:
//!
//! ```rust,ignore
//! let schedule = LeaderSchedule::new(&vset);
//! let decided = try_decide(last_decided, &dag, &vset, schedule.leader_fn())?;
//! ```
//!
//! ## Multi-leader pipelining (v1: single-leader)
//!
//! `LEADER_OFFSET = 0` for v1 (single-leader per wave). The `with_offset`
//! constructor enables multi-leader pipelining: N `LeaderSchedule`s each
//! with a distinct `leader_offset` run N parallel commit pipelines, one
//! decided leader per round (spec §6, "Pipelining").
//!
//! ## Forward-compat hook for Step 9
//!
//! [`LeaderSchedule::with_swap`] accepts a [`LeaderSwapTable`]. Step 9 will
//! replace the identity table with a reputation-driven one recomputed at
//! epoch boundaries — no change to `leader.rs` needed (Decision 7b).
//!
//! [`try_decide`]: crate::pulse::committer::try_decide
//! [`LeaderSwapTable`]: crate::reputation::LeaderSwapTable

use lemma_core::{address::Address, validator_set::ValidatorSet};

use crate::{
    dag::block::Slot,
    error::ConsensusError,
    reputation::LeaderSwapTable,
    LEADER_OFFSET,
};

// ── LeaderSchedule ────────────────────────────────────────────────────────────

/// Deterministic leader schedule for a single epoch.
///
/// Constructed once per epoch from the validator set. Caches the
/// committee ordering as a `Vec<Address>` (sorted by address = BTreeMap key
/// order) for O(1) `elect_leader` calls (Decision 7c).
///
/// ## Precondition
///
/// The validator set must be non-empty. An empty committee is a protocol
/// violation (genesis always has ≥ 1 validator). The constructors return
/// `Err(ConsensusError::EmptyCommittee)` rather than panicking, consistent
/// with Decision 6c (no panics in consensus path, AGENTS §7.2).
#[derive(Debug, Clone)]
pub struct LeaderSchedule {
    /// Committee members in canonical order (sorted by `Address` = BTreeMap
    /// iteration order). Cached for O(1) index lookup. Deterministic because
    /// `BTreeMap<Address, _>` is sorted by the canonical address bytes
    /// (AGENTS §7.1).
    committee_order: Vec<Address>,
    /// Leader offset for multi-leader pipelining (spec §6 "Pipelining").
    /// v1 single-leader: always 0. Each pipelined committer uses a distinct
    /// offset (0, 1, 2, …) to spread leadership across rounds.
    offset: u64,
    /// Reputation-based leader swap table. Step 7: identity (no swap).
    /// Step 9: swaps persistently-failing leaders for high-reputation ones.
    swap: LeaderSwapTable,
}

impl LeaderSchedule {
    /// Create a schedule for `vset` with `LEADER_OFFSET = 0` and identity swap.
    ///
    /// This is the standard v1 single-leader constructor.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::EmptyCommittee`] if `vset` has no members.
    /// This is a protocol invariant violation — valid epochs always have ≥ 1
    /// validator. Returning an error (not panicking) follows Decision 6c/W1
    /// (AGENTS §7.2).
    pub fn new(vset: &ValidatorSet) -> Result<Self, ConsensusError> {
        Self::with_swap(vset, LEADER_OFFSET, LeaderSwapTable::identity())
    }

    /// Create a schedule with a specific `offset` for multi-leader pipelining.
    ///
    /// `offset` shifts the round-robin cycle: `idx = (round + offset) % len`.
    /// Two committers with offsets 0 and 1 elect different leaders for the
    /// same round, enabling parallel commit pipelines (spec §6 "Pipelining").
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::EmptyCommittee`] if `vset` has no members.
    pub fn with_offset(
        vset: &ValidatorSet,
        offset: u64,
    ) -> Result<Self, ConsensusError> {
        Self::with_swap(vset, offset, LeaderSwapTable::identity())
    }

    /// Create a schedule with an explicit swap table (Step 9 hook).
    ///
    /// Step 9 calls this at epoch boundaries after recomputing
    /// [`LeaderSwapTable`] from [`ReputationScores`].
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::EmptyCommittee`] if `vset` has no members.
    ///
    /// [`ReputationScores`]: crate::reputation::ReputationScores
    pub fn with_swap(
        vset: &ValidatorSet,
        offset: u64,
        swap: LeaderSwapTable,
    ) -> Result<Self, ConsensusError> {
        if vset.members.is_empty() {
            // Never panic in the consensus path (AGENTS §7.2, Decision 6c/W1).
            // An empty committee is a fatal configuration error — the node
            // binary should treat this as unrecoverable.
            return Err(ConsensusError::EmptyCommittee { epoch: vset.epoch });
        }
        // Collect keys in BTreeMap iteration order (sorted by Address).
        // This is the canonical committee ordering — identical on every node
        // given the same validator set (AGENTS §7.1 determinism).
        let committee_order: Vec<Address> = vset.members.keys().copied().collect();
        Ok(Self { committee_order, offset, swap })
    }

    /// Elect the leader for `round`.
    ///
    /// Returns `Slot { round, author }` where `author` is determined by:
    /// 1. Base round-robin: `idx = (round + offset) % committee_size`
    /// 2. Reputation swap (Step 9 no-op in Step 7): `swap.swap(candidate, round)`
    ///
    /// # Determinism
    ///
    /// Produces the identical result on every node for the same `round` and
    /// the same validator set — no floats, no `SystemTime`, no `HashMap`
    /// (AGENTS §7.1, spec §12).
    #[must_use]
    pub fn elect_leader(&self, round: u64) -> Slot {
        // len > 0 guaranteed by with_swap returning Err on empty committee (W1 fix).
        // Cast is lossless: committee_order.len() originates from a usize, so
        // len <= usize::MAX <= u64::MAX on all supported 64-bit targets (S1).
        let len = self.committee_order.len() as u64;
        // wrapping_add (not `+`): hardens the literal spec §6 formula against
        // overflow at rounds near u64::MAX. Every node wraps identically —
        // determinism is preserved (S2, AGENTS §7.1).
        let idx = (round.wrapping_add(self.offset)) % len;
        // idx < len by construction; committee_order is non-empty (S1 lossless cast).
        let candidate = self.committee_order[idx as usize];
        // Apply reputation swap (Step 7: identity; Step 9: real swap).
        let author = self.swap.swap(candidate, round);
        Slot { round, author }
    }

    /// Return a closure suitable for passing to [`try_decide`].
    ///
    /// The closure borrows `self` for its lifetime — the schedule must outlive
    /// any call to `try_decide` that uses it.
    ///
    /// ```rust,ignore
    /// let schedule = LeaderSchedule::new(&vset);
    /// let decided = try_decide(last_decided, &dag, &vset, schedule.leader_fn())?;
    /// ```
    ///
    /// [`try_decide`]: crate::pulse::committer::try_decide
    pub fn leader_fn(&self) -> impl Fn(u64) -> Slot + '_ {
        |round| self.elect_leader(round)
    }

    /// Number of validators in the committee.
    #[must_use]
    pub fn committee_size(&self) -> usize {
        self.committee_order.len()
    }

    /// The leader offset for this schedule instance.
    #[must_use]
    pub fn offset(&self) -> u64 {
        self.offset
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
