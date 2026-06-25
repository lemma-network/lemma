//! DAG store — accepts, indexes, suspends, and garbage-collects [`DagBlock`]s.
//!
//! [`Dag`] is the single source of truth for the local DAG state. It enforces
//! validity rules §3 (via `dag::validity`) and manages:
//! - **Primary store**: accepted blocks keyed by [`DagBlockRef`].
//! - **Slot index**: `(round, author) → DagBlockRef` for `block_at_slot` and equivocation detection.
//! - **Round index**: `round → BTreeSet<DagBlockRef>` for `blocks_at_round`.
//! - **Suspended buffer** (rule 4): blocks waiting for missing ancestors.
//! - **Next-epoch buffer** (§4.6): blocks for `epoch+1`, admitted on `advance_epoch`.
//! - **GC** (§9): drops blocks at `round <= gc_round` when `set_last_committed_round` advances.
//!
//! # Insertion flow
//!
//! [`Dag::insert`] applies rules in spec §3 order:
//! 1. Epoch check → next-epoch buffer OR hard reject (rule 1 / §4.6)
//! 2. Author membership + sig (rule 2, sig injected as `sig_ok: bool`)
//! 3. GC boundary (rule 3)
//! 4. Ancestors present (rule 4) → suspension with wakeup index
//! 5. Strong-link quorum (rule 5) → complete "strong link" definition
//! 6. Equivocation (rule 6) → `InsertOutcome::Equivocation`
//!
//! See `docs/07-CONSENSUS_SPEC.md §3` for the full rule set and §9 for GC.

use std::collections::{BTreeMap, BTreeSet};

use lemma_core::{address::Address, hash::Hash, validator_set::ValidatorSet};

use crate::{
    dag::block::{DagBlock, DagBlockRef, Slot},
    dag::validity,
    error::ConsensusError,
    GC_DEPTH,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum suspended blocks (rule 4 buffer, DoS bound — AGENTS.md §15.2).
///
/// Derived from `GC_DEPTH × typical_committee_size`: 30 rounds × ~100 validators
/// = 3 000 max honest pending blocks; we cap at 1 000 to leave headroom against
/// a spam attacker who submits out-of-order blocks before their ancestors arrive.
/// Blocks exceeding this cap return `InsertOutcome::Dropped`.
pub(crate) const MAX_SUSPENDED: usize = 1_000;

/// Maximum next-epoch buffered blocks (spec §4.6, DoS bound — AGENTS.md §15.2).
///
/// One next-epoch block per validator per wave ≈ committee_size × waves_per_epoch.
/// 200 is generous for a 100-validator committee with short epochs.
/// Blocks exceeding this cap return `InsertOutcome::Dropped`.
pub(crate) const MAX_NEXT_EPOCH_BUFFER: usize = 200;

// ── InsertOutcome ─────────────────────────────────────────────────────────────

/// The result of a successful [`Dag::insert`] call.
///
/// `Err(ConsensusError)` is returned for hard rejections (rules 2, 3, 5).
/// `Ok(InsertOutcome)` covers the non-error resolution paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertOutcome {
    /// Block accepted and inserted into the DAG.
    Accepted,
    /// Block suspended: one or more ancestors not yet present in the DAG.
    ///
    /// The block is held in the pending buffer and will be re-validated
    /// automatically when its ancestors arrive (rule 4).
    Suspended,
    /// Block buffered: belongs to the next epoch (`block.epoch == dag.epoch + 1`).
    ///
    /// Call [`Dag::advance_epoch`] to promote buffered blocks once the epoch
    /// boundary commits (`docs/13-VALIDATOR_EPOCH_SPEC.md §4.6`).
    NextEpochBuffered,
    /// Block silently dropped because a bounded buffer was full (DoS protection).
    ///
    /// Distinct from [`Suspended`] (which guarantees the block is held and will
    /// be re-validated) and [`NextEpochBuffered`]. The caller must re-submit
    /// the block later or rely on re-broadcast from peers.
    ///
    /// [`Suspended`]: InsertOutcome::Suspended
    Dropped,
    /// Block revealed an equivocation — block NOT inserted.
    ///
    /// The caller MUST construct and broadcast `DoubleSignEvidence`
    /// (`docs/13-VALIDATOR_EPOCH_SPEC.md §5.2`). Both conflicting digests
    /// are provided to seed the evidence record.
    Equivocation {
        author: Address,
        round: u64,
        /// Digest of the existing block already in the DAG at this slot.
        first: Hash,
        /// Digest of the incoming conflicting block.
        second: Hash,
    },
}

// ── Dag ───────────────────────────────────────────────────────────────────────

/// The local DAG state for one epoch.
///
/// All ordered collections use `BTreeMap`/`BTreeSet` for deterministic
/// iteration across all nodes (AGENTS.md §7.1).
/// Fields are `pub(super)` where the maintenance submodule (`graph::maintenance`,
/// which carries the GC + unsuspend lifecycle) needs them. They remain private
/// to the rest of the crate.
#[derive(Debug)]
pub struct Dag {
    // ── Accepted blocks ───────────────────────────────────────────────────────
    /// Primary store: accepted blocks keyed by their content-addressing ref.
    pub(super) blocks: BTreeMap<DagBlockRef, DagBlock>,
    /// Slot → ref index (O(log n) `block_at_slot` + equivocation detection).
    pub(super) by_slot: BTreeMap<Slot, DagBlockRef>,
    /// Round → ref set (O(log n) `blocks_at_round` + quorum scan by callers).
    pub(super) by_round: BTreeMap<u64, BTreeSet<DagBlockRef>>,

    // ── Suspension buffer (rule 4) ────────────────────────────────────────────
    /// Pending blocks: all ancestors declared but not yet present in DAG.
    pub(super) suspended: BTreeMap<DagBlockRef, DagBlock>,
    /// Reverse index: missing_ref → {suspended block refs waiting for it}.
    /// Used to wake up suspended blocks in O(log n) when a missing block arrives.
    pub(super) waiting_for: BTreeMap<DagBlockRef, BTreeSet<DagBlockRef>>,

    // ── Next-epoch buffer (§4.6) ──────────────────────────────────────────────
    /// Blocks for `epoch + 1`, held until `advance_epoch()`.
    next_epoch_buffer: BTreeMap<DagBlockRef, DagBlock>,

    // ── Consensus state ───────────────────────────────────────────────────────
    /// Highest committed DAG round. Drives `gc_round()`.
    last_committed_round: u64,
    /// Current validator-set epoch. Validated against every incoming block.
    epoch: u64,

    // ── Pending notifications ─────────────────────────────────────────────────
    /// Equivocations detected during `try_unsuspend` cascade (C2 fix).
    ///
    /// When a suspended block's ancestors finally arrive and re-validation
    /// discovers equivocation (rule 6), the evidence cannot be returned from
    /// `insert` inline (the cascade is async relative to the triggering insert).
    /// Callers drain this buffer after each `insert` via [`drain_equivocations`].
    ///
    /// [`drain_equivocations`]: Dag::drain_equivocations
    pub(super) pending_equivocations: Vec<InsertOutcome>,
}

impl Dag {
    /// Create a new empty DAG for the given epoch.
    #[must_use]
    pub fn new(epoch: u64) -> Self {
        Self {
            blocks: BTreeMap::new(),
            by_slot: BTreeMap::new(),
            by_round: BTreeMap::new(),
            suspended: BTreeMap::new(),
            waiting_for: BTreeMap::new(),
            next_epoch_buffer: BTreeMap::new(),
            last_committed_round: 0,
            epoch,
            pending_equivocations: Vec::new(),
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// GC round: all blocks at `round <= gc_round` have been dropped.
    ///
    /// `gc_round = last_committed_round.saturating_sub(GC_DEPTH)` (spec §9).
    #[must_use]
    pub fn gc_round(&self) -> u64 {
        self.last_committed_round.saturating_sub(GC_DEPTH)
    }

    /// Highest round of any accepted block. Returns 0 if the DAG is empty.
    #[must_use]
    pub fn highest_accepted_round(&self) -> u64 {
        self.by_round.keys().next_back().copied().unwrap_or(0)
    }

    /// Look up an accepted block by its reference.
    #[must_use]
    pub fn block(&self, r: &DagBlockRef) -> Option<&DagBlock> {
        self.blocks.get(r)
    }

    /// Look up the ref of the accepted block at `slot`, if any.
    #[must_use]
    pub fn block_at_slot(&self, slot: Slot) -> Option<DagBlockRef> {
        self.by_slot.get(&slot).copied()
    }

    /// Iterate over all accepted blocks at `round`.
    pub fn blocks_at_round(&self, round: u64) -> impl Iterator<Item = &DagBlock> {
        self.by_round
            .get(&round)
            .into_iter()
            .flat_map(|refs| refs.iter().filter_map(|r| self.blocks.get(r)))
    }

    /// Returns `true` if `r` is an accepted block in the DAG.
    #[must_use]
    pub fn contains(&self, r: &DagBlockRef) -> bool {
        self.blocks.contains_key(r)
    }

    /// Compute the total stake of all accepted blocks at `round`.
    ///
    /// Used by the commit rule (§4.3) as an early-exit guard: if the total
    /// stake of blocks at the decision round is below quorum, there can be no
    /// certificate yet — no need to scan individual blocks.
    ///
    /// Returns `Err(ConsensusError::StakeOverflow)` if accumulation overflows
    /// `u128` (AGENTS §7.4). Non-member authors (stake 0 by definition) are
    /// silently skipped — consistent with `validate_strong_link_quorum` and
    /// `ThresholdClock::add_block` (AGENTS §2 one canonical way).
    ///
    /// # Errors
    /// `ConsensusError::StakeOverflow` if the sum of voting powers overflows.
    pub fn total_stake_at(
        &self,
        round: u64,
        vset: &lemma_core::validator_set::ValidatorSet,
    ) -> Result<crate::stake::StakeAggregator, crate::error::ConsensusError> {
        let mut agg = crate::stake::StakeAggregator::quorum(vset.total_power);
        for block in self.blocks_at_round(round) {
            if let Some(member) = vset.members.get(&block.author) {
                agg.add(block.author, member.power)?;
            }
        }
        Ok(agg)
    }

    /// Current epoch of this DAG.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Number of accepted blocks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// `true` if no blocks have been accepted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Number of blocks currently in the suspension buffer (test-only accessor).
    #[cfg(test)]
    pub(crate) fn suspended_count(&self) -> usize {
        self.suspended.len()
    }

    /// Drain equivocations surfaced during `try_unsuspend` cascade.
    ///
    /// When a suspended block's ancestors arrive and re-validation detects
    /// equivocation, the evidence is queued here (the cascade cannot return
    /// inline from `insert`). Callers MUST drain this after every `insert`
    /// and emit `DoubleSignEvidence` for each
    /// (`docs/13-VALIDATOR_EPOCH_SPEC.md §5.2`).
    pub fn drain_equivocations(&mut self) -> Vec<InsertOutcome> {
        std::mem::take(&mut self.pending_equivocations)
    }

    // ── Insertion ─────────────────────────────────────────────────────────────

    /// Insert a block into the DAG, applying validity rules §3.
    ///
    /// `sig_ok` = result of hybrid Ed25519+ML-DSA verification performed by
    /// the **network layer** (decisions-log "Decision 4a"). The graph does not
    /// import `lemma-crypto`.
    ///
    /// # Returns
    ///
    /// `Ok(InsertOutcome)` on non-error paths (accepted / suspended /
    /// buffered / equivocation). `Err(ConsensusError)` on hard rejection
    /// (rules 2, 3, or 5).
    pub fn insert(
        &mut self,
        block: DagBlock,
        vset: &ValidatorSet,
        sig_ok: bool,
    ) -> Result<InsertOutcome, ConsensusError> {
        let block_ref = block.reference();

        // Idempotency: already accepted → report as accepted without re-validation.
        if self.blocks.contains_key(&block_ref) {
            return Ok(InsertOutcome::Accepted);
        }

        // ── Rule 1: epoch (spec §3 rule 1, §4.6) ────────────────────────────
        match block.epoch.cmp(&self.epoch) {
            std::cmp::Ordering::Equal => { /* proceed */ }
            std::cmp::Ordering::Greater => {
                // Next epoch (epoch+1): buffer. Far future: hard reject.
                if block.epoch == self.epoch + 1 {
                    if self.next_epoch_buffer.len() < MAX_NEXT_EPOCH_BUFFER {
                        self.next_epoch_buffer.insert(block_ref, block);
                        return Ok(InsertOutcome::NextEpochBuffered);
                    }
                    // Buffer full: drop (DoS §15.2). Distinct from NextEpochBuffered.
                    return Ok(InsertOutcome::Dropped);
                }
                return Err(ConsensusError::EpochMismatch {
                    expected: self.epoch,
                    got: block.epoch,
                });
            }
            std::cmp::Ordering::Less => {
                return Err(ConsensusError::EpochMismatch {
                    expected: self.epoch,
                    got: block.epoch,
                });
            }
        }

        // ── Rule 1.5: digest integrity (pre-sig check) ──────────────────────
        // Verify block.digest == compute_digest(body) BEFORE sig check.
        // A forged digest makes sig_ok meaningless: "signed this forged hash"
        // ≠ "block body is authentic". Closes peer content-integrity gap (D·15b-1).
        validity::validate_digest_integrity(&block)?;

        // ── Rule 2: author + sig (spec §3 rule 2) ───────────────────────────
        validity::validate_author_and_signature(&block, vset, sig_ok)?;

        // ── Rule 3: GC boundary (spec §3 rule 3) ────────────────────────────
        validity::validate_gc_boundary(block.round, self.gc_round())?;

        // ── Rule 4: ancestors present (spec §3 rule 4) ──────────────────────
        let missing = validity::collect_missing_ancestors(&block, |r| self.blocks.contains_key(r));
        if !missing.is_empty() {
            // Bounded suspension buffer (AGENTS §15.2).
            if self.suspended.len() < MAX_SUSPENDED {
                for m in &missing {
                    self.waiting_for.entry(*m).or_default().insert(block_ref);
                }
                self.suspended.insert(block_ref, block);
                return Ok(InsertOutcome::Suspended);
            }
            // Buffer full: drop. Distinct from Suspended (no wakeup registered).
            return Ok(InsertOutcome::Dropped);
        }

        // ── Rule 5: strong-link quorum (spec §3 rule 5) ─────────────────────
        validity::validate_strong_link_quorum(&block, vset)?;

        // ── Rule 6: equivocation (spec §3 rule 6) ───────────────────────────
        let existing = self.block_at_slot(block.slot());
        match validity::validate_no_equivocation(&block, existing) {
            Ok(()) => {}
            Err(ConsensusError::Equivocation {
                author,
                round,
                first,
                second,
            }) => {
                // Block NOT inserted — caller emits DoubleSignEvidence.
                return Ok(InsertOutcome::Equivocation {
                    author,
                    round,
                    first,
                    second,
                });
            }
            Err(e) => return Err(e),
        }

        // ── Accept ───────────────────────────────────────────────────────────
        self.accept_block(block_ref, block);
        // Cascade: unsuspend blocks that were waiting for this one.
        // Any equivocations detected during cascade are queued in
        // `pending_equivocations` — caller drains via `drain_equivocations()`.
        self.try_unsuspend(block_ref, vset);

        Ok(InsertOutcome::Accepted)
    }

    // ── Committed-round advance + GC ──────────────────────────────────────────

    /// Advance the last committed round and garbage-collect old blocks (spec §9).
    ///
    /// Blocks at `round <= new_gc_round` are dropped from all indexes.
    /// `last_committed_round` can only increase (monotonic).
    pub fn set_last_committed_round(&mut self, round: u64) {
        if round <= self.last_committed_round {
            return; // monotonic — never go backwards
        }
        self.last_committed_round = round;
        self.collect_garbage();
    }

    // ── Epoch advance (§4.6) ──────────────────────────────────────────────────

    /// Advance to `new_epoch`, returning next-epoch buffered blocks for
    /// re-insertion by the caller.
    ///
    /// The caller re-inserts each returned block via [`insert`] with the new
    /// epoch's [`ValidatorSet`] and re-verified signatures. Blocks that fail
    /// re-validation (e.g. author not in new committee) are simply dropped.
    ///
    /// Only advances by exactly one epoch (no skipping). Returns an empty
    /// `Vec` if `new_epoch != self.epoch + 1`.
    ///
    /// [`insert`]: Dag::insert
    pub fn advance_epoch(&mut self, new_epoch: u64) -> Vec<DagBlock> {
        if new_epoch != self.epoch + 1 {
            return vec![];
        }
        self.epoch = new_epoch;
        let buffered: Vec<DagBlock> = self.next_epoch_buffer.values().cloned().collect();
        self.next_epoch_buffer.clear();
        buffered
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Unconditionally insert into the accepted-block indexes.
    ///
    /// Crate-internal: used by `insert` and the maintenance module
    /// (`graph::maintenance`) which carries the GC + unsuspend lifecycle.
    pub(super) fn accept_block(&mut self, block_ref: DagBlockRef, block: DagBlock) {
        let slot = block.slot();
        let round = block_ref.round;
        self.by_slot.insert(slot, block_ref);
        self.by_round.entry(round).or_default().insert(block_ref);
        self.blocks.insert(block_ref, block);
    }
}

// ── Submodules ────────────────────────────────────────────────────────────────

/// GC + suspended-block cascade lifecycle (second `impl Dag` block).
mod maintenance;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
