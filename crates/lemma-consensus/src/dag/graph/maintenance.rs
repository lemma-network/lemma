//! DAG maintenance lifecycle: garbage collection (§9) and suspended-block
//! cascade unsuspension (rule 4).
//!
//! Split from `graph.rs` to keep each file within the AGENTS §3.1 size limit.
//! These are `impl Dag` methods operating on the same store; they live here
//! because they form a distinct concern (background lifecycle) from the
//! synchronous insert/query path.

use std::collections::BTreeSet;

use lemma_core::validator_set::ValidatorSet;

use crate::dag::{
    block::DagBlockRef,
    graph::{Dag, InsertOutcome},
    validity,
};

impl Dag {
    /// Promote suspended blocks that were waiting for `newly_accepted`.
    ///
    /// Recursively promotes cascading dependencies. Equivocations discovered
    /// during the cascade are queued in `pending_equivocations` (C2 fix) for
    /// the caller to drain via `drain_equivocations`.
    pub(super) fn try_unsuspend(&mut self, newly_accepted: DagBlockRef, vset: &ValidatorSet) {
        let waiting = match self.waiting_for.remove(&newly_accepted) {
            Some(set) => set,
            None => return,
        };

        for suspended_ref in waiting {
            // Check if ALL ancestors are now present.
            let all_present = self
                .suspended
                .get(&suspended_ref)
                .map(|b| b.ancestors.iter().all(|a| self.blocks.contains_key(a)))
                .unwrap_or(false);

            if !all_present {
                continue; // still missing other ancestors
            }

            let Some(block) = self.suspended.remove(&suspended_ref) else {
                continue;
            };

            // Clean up other waiting_for entries for this block's ancestors.
            for ancestor in &block.ancestors {
                if let Some(waiters) = self.waiting_for.get_mut(ancestor) {
                    waiters.remove(&suspended_ref);
                }
            }

            // Re-run rules 5–6 (rules 1–4 already passed at original submission).
            let strong_ok = validity::check_strong_link_quorum(&block, vset).is_ok();
            let existing = self.block_at_slot(block.slot());
            let no_equiv = validity::check_no_equivocation(&block, existing).is_ok();

            if strong_ok && no_equiv {
                self.accept_block(suspended_ref, block);
                self.try_unsuspend(suspended_ref, vset); // recurse for cascade
            } else if !no_equiv {
                // Equivocation detected during cascade — cannot return inline from
                // insert. Queue for caller to drain via drain_equivocations().
                // The block is not inserted, but slashing evidence must be emitted.
                if let Some(existing_ref) = existing {
                    if existing_ref.digest != block.digest {
                        self.pending_equivocations
                            .push(InsertOutcome::Equivocation {
                                author: block.author,
                                round: block.round,
                                first: existing_ref.digest,
                                second: block.digest,
                            });
                    }
                }
            }
            // If only rule 5 fails (InsufficientStrongLinks): block is dropped.
            // No slashing evidence — the block simply doesn't qualify.
        }
    }

    /// Drop all blocks at `round <= gc_round` from every index (spec §9).
    ///
    /// Also evicts suspended blocks whose ancestors are permanently unreachable
    /// (below the GC frontier) to prevent stranding (C1 fix).
    pub(super) fn collect_garbage(&mut self) {
        let gc = self.gc_round();

        // Drop from round index and collect refs to remove.
        let gc_rounds: Vec<u64> = self.by_round.keys().copied().filter(|&r| r <= gc).collect();
        let mut gc_refs: BTreeSet<DagBlockRef> = BTreeSet::new();
        for round in gc_rounds {
            if let Some(refs) = self.by_round.remove(&round) {
                gc_refs.extend(refs);
            }
        }

        // Drop from primary store and slot index.
        for r in &gc_refs {
            self.blocks.remove(r);
            self.by_slot.remove(&r.slot()); // DRY: DagBlockRef::slot() (AGENTS §2)
        }

        // Drop suspended blocks below GC boundary OR whose ancestors are below it.
        //
        // A block suspended because ancestor A is missing can never unsuspend if
        // A's round <= gc_round — A can never be inserted (rule 3 rejects it).
        // We must evict such blocks to prevent permanent stranding (C1 fix).
        let suspended_to_drop: Vec<DagBlockRef> = self
            .suspended
            .iter()
            .filter(|(r, b)| {
                // Drop if block itself is below GC boundary...
                r.round <= gc
                // ...or if any declared ancestor can never arrive (below GC).
                || b.ancestors.iter().any(|a| a.round <= gc && !self.blocks.contains_key(a))
            })
            .map(|(r, _)| *r)
            .collect();
        for r in suspended_to_drop {
            if let Some(b) = self.suspended.remove(&r) {
                // Clean up waiting_for entries for every ancestor of the dropped block.
                for ancestor in &b.ancestors {
                    if let Some(waiters) = self.waiting_for.get_mut(ancestor) {
                        waiters.remove(&r);
                    }
                }
            }
        }
        // Prune waiting_for keys below the GC frontier (ancestors that can never
        // arrive) and empty sets.
        self.waiting_for
            .retain(|k, waiters| k.round > gc && !waiters.is_empty());
    }
}
