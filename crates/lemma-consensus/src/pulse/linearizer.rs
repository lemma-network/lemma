//! # Linearizer — sub-DAG flattening and Commit production (spec §5)
//!
//! Converts [`LeaderStatus::Commit`] entries from [`try_decide`] into
//! deterministically-ordered [`Commit`] records with chained digests.
//!
//! ## Algorithm (spec §5)
//!
//! For each committed leader:
//! 1. **Linearize sub-DAG**: DFS from the leader block over `ancestors`,
//!    skipping blocks below the GC boundary or already committed. Sort
//!    the result by `(round ASC, author ASC)` — the sole determinism
//!    guarantee (DFS visit order is irrelevant).
//! 2. **Commit timestamp**: stake-weighted median of the leader's round-(L-1)
//!    parents, clamped monotonically (`spec §5.1`).
//! 3. **Commit record**: `{ index, previous_digest, timestamp_ms, leader, blocks }`.
//!    `index` is monotonic; `previous_digest` chains to the prior commit.
//!
//! ## State (Decision 8c)
//!
//! [`Linearizer`] is stateful — it tracks `next_index`, `last_digest`,
//! `last_timestamp_ms`, and the `committed` dedup set across calls.
//! This mirrors [`ThresholdClock`] (owned by the driver, advanced per event).
//! The surge/pulse driver owns the `Linearizer` and calls
//! [`commit_leaders`] after each [`try_decide`] result.
//!
//! ## Downstream (§5.2 mapping)
//!
//! [`Commit`] is the cross-crate contract between `lemma-consensus` and
//! `lemma-vm`. The §5.2 `Commit → BlockHeader` mapping (dag_round, dag_anchor,
//! timestamp in seconds, height) is performed by `lemma-vm`/Flux when forming
//! the chain Block — not here. See `commit.rs` module doc for details.
//!
//! [`ThresholdClock`]: crate::dag::threshold_clock::ThresholdClock
//! [`commit_leaders`]: Linearizer::commit_leaders
//! [`try_decide`]: crate::pulse::committer::try_decide

use std::collections::BTreeSet;

use lemma_core::{hash::Hash, validator_set::ValidatorSet};

use crate::{
    commit::Commit,
    dag::{block::DagBlockRef, graph::Dag},
    error::ConsensusError,
    pulse::committer::LeaderStatus,
};

// ── Linearizer ────────────────────────────────────────────────────────────────

/// Stateful commit producer: converts decided leaders into chained [`Commit`]s.
///
/// Constructed once per epoch. Feed decided leaders via [`commit_leaders`];
/// the linearizer advances its internal index and digest state each call.
///
/// ## Idempotency
///
/// The `committed` set tracks every block ref added to any commit.
/// Blocks already committed are skipped in subsequent sub-DAG traversals —
/// no block appears in more than one `Commit.blocks` list (spec §5: the
/// `committed` set is the sole idempotency guard).
///
/// [`commit_leaders`]: Linearizer::commit_leaders
#[derive(Debug)]
pub struct Linearizer {
    /// Next commit index (1-based; genesis = 0 implicit).
    next_index: u64,
    /// Digest of the most recent commit (`previous_digest` for the next one).
    /// Starts as [`Commit::genesis_previous`] = `Hash::zero()`.
    last_digest: Hash,
    /// Set of all block refs ever committed. BTreeSet for deterministic
    /// membership (AGENTS §7.1).
    committed: BTreeSet<DagBlockRef>,
    /// Monotonic commit timestamp (ms). Each new timestamp is clamped to
    /// `>= last_timestamp_ms` (spec §5.1).
    last_timestamp_ms: u64,
}

impl Linearizer {
    /// Create a fresh linearizer (genesis state: index 0, zero digest).
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_index: 1, // first real commit gets index 1
            last_digest: Commit::genesis_previous(),
            committed: BTreeSet::new(),
            last_timestamp_ms: 0,
        }
    }

    /// Process a slice of leader decisions and produce [`Commit`] records.
    ///
    /// Only [`LeaderStatus::Commit`] entries produce a `Commit`; `Skip`
    /// entries are silently ignored (no commit record — the leader was not
    /// certified).
    ///
    /// Advances internal state (`next_index`, `last_digest`,
    /// `last_timestamp_ms`, `committed` set) for each produced commit.
    /// Also calls [`Dag::set_last_committed_round`] for the highest
    /// committed leader round, advancing GC.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::StakeOverflow`] if stake accumulation
    /// overflows `u128` during timestamp median computation (AGENTS §7.4).
    pub fn commit_leaders(
        &mut self,
        decided: &[LeaderStatus],
        dag: &mut Dag,
        vset: &ValidatorSet,
    ) -> Result<Vec<Commit>, ConsensusError> {
        let mut commits = Vec::new();

        for status in decided {
            let LeaderStatus::Commit(leader_ref) = status else {
                continue; // Skip: no commit record
            };

            let Some(leader_block) = dag.block(leader_ref).cloned() else {
                // Provably unreachable in normal operation: `try_decide` returns
                // `Commit` only for a leader block that was *accepted* into the DAG
                // (certified — cert check uses `dag.block()`). GC cannot have dropped
                // it yet because `set_last_committed_round` is called *after* we
                // process this batch (end of this function) — so the leader's round
                // is always > gc_round at this point.
                //
                // If we ever reach here it means either the DAG state was mutated
                // outside the normal flow, or a programming error in the driver.
                // We surface this as a dedicated error (not a silent skip — that
                // would corrupt the commit chain by dropping a decided leader,
                // breaking the gapless-prefix invariant — and not a misleading
                // ByzantineInvariantBreach — this is an internal invariant, not a
                // detected equivocation; CodeReviewer W3 refinement).
                debug_assert!(false,
                    "decided leader block {leader_ref:?} not in DAG — invariant violated");
                return Err(ConsensusError::DecidedLeaderMissing {
                    round: leader_ref.round,
                    author: leader_ref.author,
                });
            };

            // 1. Linearize sub-DAG (DFS, dedup via self.committed).
            let blocks = linearize_sub_dag(&leader_block.reference(), dag, &mut self.committed);

            // 2. Deterministic commit timestamp (spec §5.1).
            let timestamp_ms = commit_timestamp(
                &leader_block,
                self.last_timestamp_ms,
                dag,
                vset,
            )?;

            // 3. Build Commit record.
            let commit = Commit {
                index: self.next_index,
                previous_digest: self.last_digest,
                timestamp_ms,
                leader: *leader_ref,
                blocks,
            };

            // Advance chain state.
            self.last_digest = commit.digest();
            self.last_timestamp_ms = timestamp_ms;
            self.next_index += 1;

            commits.push(commit);
        }

        // Advance GC to the highest committed leader round (spec §9).
        if let Some(highest) = commits.iter().map(|c| c.leader.round).max() {
            dag.set_last_committed_round(highest);
        }

        Ok(commits)
    }

    /// The index that will be assigned to the next commit.
    #[must_use]
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// The digest of the most recently produced commit.
    ///
    /// Returns [`Hash::zero`] before the first commit (genesis sentinel).
    #[must_use]
    pub fn last_digest(&self) -> Hash {
        self.last_digest
    }
}

impl Default for Linearizer {
    fn default() -> Self {
        Self::new()
    }
}

// ── linearize_sub_dag (spec §5) ───────────────────────────────────────────────

/// DFS from `leader_ref` over accepted ancestors, collecting unrecommitted
/// blocks above the GC boundary.
///
/// **Sort**: terminal `(round ASC, author ASC)` is the SOLE determinism
/// guarantee — DFS visit order is irrelevant (spec §5 note). We sort
/// explicitly by `(round, author)` rather than relying on `DagBlockRef::Ord`
/// (which also includes `digest`) to match the spec exactly.
///
/// `committed` is updated in-place: every collected ref is inserted before
/// the DFS continues, acting as the idempotency dedup guard.
fn linearize_sub_dag(
    leader_ref: &DagBlockRef,
    dag: &Dag,
    committed: &mut BTreeSet<DagBlockRef>,
) -> Vec<DagBlockRef> {
    let gc_round = dag.gc_round();

    // Idempotency guard: mark leader as committed before DFS.
    committed.insert(*leader_ref);

    let mut stack = vec![*leader_ref];
    let mut to_commit: Vec<DagBlockRef> = Vec::new();

    while let Some(r) = stack.pop() {
        to_commit.push(r);

        let Some(block) = dag.block(&r) else {
            continue; // block not locally present — skip its ancestors
        };

        for ancestor in &block.ancestors {
            // Skip: below GC boundary (permanently gone) or already committed.
            if ancestor.round <= gc_round || committed.contains(ancestor) {
                continue;
            }
            committed.insert(*ancestor);
            stack.push(*ancestor);
        }
    }

    // Deterministic sort: (round ASC, author ASC) — spec §5 exact requirement.
    // Explicit key rather than DagBlockRef::Ord (which includes digest) to
    // match the spec and make the sort criteria self-documenting.
    to_commit.sort_by(|a, b| a.round.cmp(&b.round).then_with(|| a.author.cmp(&b.author)));
    to_commit
}

// ── commit_timestamp (spec §5.1) ──────────────────────────────────────────────

/// Compute the consensus timestamp for a commit (spec §5.1).
///
/// The timestamp is the **stake-weighted median** of the `timestamp_ms`
/// values of the leader's round-`(L-1)` member ancestors. Spec §5.1 names
/// these "strong parents"; because the leader passed DAG validity rule 5
/// (strong-link quorum), its round-`(L-1)` ancestors collectively satisfy
/// the 2f+1 quorum — so "all round-(L-1) member ancestors" and
/// "strong-link quorum parents" are the same set given an accepted leader.
/// Non-member ancestors (stake 0) are skipped (AGENTS §2, consistent with
/// `ThresholdClock` and `check_strong_link_quorum`).
/// The result is clamped to be ≥ `last_commit_ts_ms` (monotonic).
///
/// **Not** the leader's own `timestamp_ms` (that is advisory only).
///
/// **Genesis / round-0 leaders**: have no round-`L-1` parents → return
/// `last_commit_ts_ms` (the clamp produces the right sentinel: 0 for
/// the very first commit).
///
/// # Errors
///
/// [`ConsensusError::StakeOverflow`] if stake accumulation overflows
/// (AGENTS §7.4 — all token arithmetic uses `checked_*`).
pub(crate) fn commit_timestamp(
    leader: &crate::dag::block::DagBlock,
    last_commit_ts_ms: u64,
    dag: &Dag,
    vset: &ValidatorSet,
) -> Result<u64, ConsensusError> {
    // Genesis round has no L-1 parents; return the monotonic clamp.
    if leader.round == 0 {
        return Ok(last_commit_ts_ms);
    }

    let prev_round = leader.round - 1;

    // Collect (stake, timestamp_ms) for each round-(L-1) parent.
    // Non-member ancestors: stake 0 by definition → skip (consistent
    // with ThresholdClock and check_strong_link_quorum, AGENTS §2).
    let mut samples: Vec<(u128, u64)> = Vec::new(); // (stake_drop, timestamp_ms)
    for ancestor_ref in leader.ancestors_at_round(prev_round) {
        if let Some(member) = vset.members.get(&ancestor_ref.author) {
            if let Some(block) = dag.block(ancestor_ref) {
                let stake = member.power.as_amount().as_drop();
                samples.push((stake, block.timestamp_ms));
            }
        }
    }

    // No eligible parents (all non-member or locally absent): clamp.
    if samples.is_empty() {
        return Ok(last_commit_ts_ms);
    }

    let median = stake_weighted_median(&samples)?;
    // Monotonic clamp: never go backwards (spec §5.1).
    Ok(median.max(last_commit_ts_ms))
}

// ── stake_weighted_median ─────────────────────────────────────────────────────

/// Stake-weighted median of `(stake_drop, timestamp_ms)` pairs.
///
/// **Algorithm** (integer-only, no floats — AGENTS §7.1):
/// 1. Compute `total_stake` = sum of all stakes (checked arithmetic).
/// 2. Sort pairs by `timestamp_ms ASC` (tie-break: smaller timestamp first —
///    deterministic because timestamps are `u64` with a total order).
/// 3. Walk the sorted list, accumulating stake.
/// 4. The median is the `timestamp_ms` where accumulated stake **first
///    exceeds** `total_stake / 2` (integer division = floor).
///
/// **Why `> total/2` not `>= total/2`**: the median point is the value
/// where more than half the weight is at or below it. Integer floor division
/// is conservative (if total is odd, floor gives the lower bound), so
/// `> floor(total/2)` correctly identifies the crossing point.
///
/// **Edge cases**:
/// - Single element: returns its timestamp.
/// - All same timestamp: returns that timestamp.
///
/// # Errors
///
/// [`ConsensusError::StakeOverflow`] if `total_stake` overflows `u128`.
fn stake_weighted_median(
    samples: &[(u128, u64)], // (stake_drop, timestamp_ms)
) -> Result<u64, ConsensusError> {
    debug_assert!(!samples.is_empty(), "caller must ensure non-empty samples");

    // Total stake — checked (AGENTS §7.4). Single checked_add per iteration —
    // canonical pattern per stake.rs:147, threshold_clock.rs:165 (W1 fix, C1 fix).
    // Note: StakeAggregator is not reused here because we need a raw u128 sum
    // for the median threshold computation, not a quorum-threshold predicate.
    // A zero-address sentinel is used for StakeOverflow.author because this is
    // an aggregate sum with no single offending author — an internal invariant
    // violation if it occurs (the validator set's total_power is already bounded).
    let sentinel = lemma_core::address::Address::from_public_key(&[0u8; 32]);
    let total = samples
        .iter()
        .try_fold(0u128, |acc, (stake, _)| {
            acc.checked_add(*stake)
                .ok_or(ConsensusError::StakeOverflow { author: sentinel })
        })?;

    // Sort by timestamp ASC — tie-break by timestamp value (total order on u64).
    let mut sorted = samples.to_vec();
    sorted.sort_by_key(|(_, ts)| *ts);

    // Walk to find the crossing point (> total / 2).
    // `accumulated` cannot overflow: it is bounded by `total` which was proven
    // not to overflow above. Plain `+` is therefore safe (S1 fix).
    let threshold = total / 2;
    let mut accumulated: u128 = 0;
    for (stake, ts) in &sorted {
        accumulated += stake;
        if accumulated > threshold {
            return Ok(*ts);
        }
    }

    // Fallback: return the last timestamp (only reachable if total == 0,
    // which cannot happen in a valid validator set, but is safe).
    Ok(sorted.last().map(|(_, ts)| *ts).unwrap_or(0))
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
