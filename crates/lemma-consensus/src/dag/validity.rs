//! Pure validity-check functions for DAG block acceptance (spec §3 rules 1–6).
//!
//! Each function checks exactly one rule and returns `Ok(())` on success or a
//! typed [`ConsensusError`] on failure. **No state mutation** — these are pure
//! predicates callable independently of the [`Dag`] store, making them easy to
//! unit-test and reason about.
//!
//! # Caller contract
//!
//! These functions are called by [`Dag::insert`] in rule order. Rules must be
//! checked in sequence (1 → 2 → 3 → [4 inline] → 5 → 6) because:
//! - Rule 4 (ancestors present) is handled **inline in `insert`** (requires
//!   state mutation — suspension buffer update).
//! - Rule 5 (strong-link quorum) implicitly assumes rule 4 has passed: all
//!   ancestors are present, so we can trust `block.ancestors` to be the
//!   complete parent set.
//!
//! # `lemma-crypto` independence
//!
//! Rule 2 crypto part (signature bytes verification) is performed by the
//! **network layer** before forwarding to consensus. `check_author_and_signature`
//! accepts the result as `sig_ok: bool` (injected). See decisions-log
//! "Decision 4a" and `docs/07-CONSENSUS_SPEC.md §3` implementation note.
//!
//! See `docs/07-CONSENSUS_SPEC.md §3`.

use lemma_core::validator_set::ValidatorSet;

use crate::{
    dag::block::{DagBlock, DagBlockRef},
    error::ConsensusError,
    stake::StakeAggregator,
};

// ── Rule 2: author membership + signature ────────────────────────────────────

/// Rule 2: `author` is in the active validator set; signature is valid.
///
/// Membership is checked directly against [`ValidatorSet::members`].
/// `sig_ok` is the result of hybrid Ed25519+ML-DSA signature verification
/// performed by the network layer (decision-log "Decision 4a").
pub(crate) fn check_author_and_signature(
    block: &DagBlock,
    vset: &ValidatorSet,
    sig_ok: bool,
) -> Result<(), ConsensusError> {
    if !vset.members.contains_key(&block.author) {
        return Err(ConsensusError::UnknownAuthor {
            author: block.author,
            epoch: block.epoch,
        });
    }
    if !sig_ok {
        return Err(ConsensusError::InvalidSignature {
            author: block.author,
            round: block.round,
        });
    }
    Ok(())
}

// ── Rule 3: GC boundary ───────────────────────────────────────────────────────

/// Rule 3: `block.round > gc_round`.
///
/// Genesis round (round 0) is explicitly exempt: at startup `gc_round = 0`
/// (from `last_committed_round.saturating_sub(GC_DEPTH)` with no commits yet),
/// and `0 > 0` is false — but round-0 blocks are valid DAG starting points.
/// The spec's genesis-round exemption (explicit for rule 5) is implicitly
/// required for rule 3 too.
pub(crate) fn check_gc_boundary(block_round: u64, gc_round: u64) -> Result<(), ConsensusError> {
    if block_round == 0 || block_round > gc_round {
        Ok(())
    } else {
        Err(ConsensusError::BelowGcBoundary {
            round: block_round,
            gc_round,
        })
    }
}

// ── Rule 5: strong-link quorum ───────────────────────────────────────────────

/// Rule 5: strong-link ancestors form a 2f+1 stake quorum at `round - 1`.
///
/// This is the **complete definition of "strong link"** per spec §2.2 —
/// not merely "ancestor at round-1" but "ancestor at round-1 that
/// participates in a 2f+1 quorum." Not in `dag::block` (see decisions-log
/// "Decision 3c").
///
/// Genesis round (round 0) is exempt (spec §3 rule 5): there is no prior
/// round from which to draw strong links.
///
/// Assumes rule 4 has already passed (all ancestors are in the DAG).
pub(crate) fn check_strong_link_quorum(
    block: &DagBlock,
    vset: &ValidatorSet,
) -> Result<(), ConsensusError> {
    if block.is_genesis_round() {
        return Ok(());
    }

    let prev_round = block.round - 1;
    let mut agg = StakeAggregator::quorum(vset.total_power);

    for ancestor in block.ancestors.iter().filter(|a| a.round == prev_round) {
        // Only count ancestors whose author is in the current validator set.
        // An ancestor from a non-member is a valid parent edge but contributes
        // zero stake toward the quorum (it cannot satisfy the 2f+1 requirement).
        if let Some(member) = vset.members.get(&ancestor.author) {
            agg.add(ancestor.author, member.power)?; // StakeOverflow → propagate
        }
    }

    if agg.is_reached() {
        Ok(())
    } else {
        Err(ConsensusError::InsufficientStrongLinks {
            author: block.author,
            round: block.round,
        })
    }
}

// ── Rule 6: equivocation ──────────────────────────────────────────────────────

/// Rule 6: the author has not produced a *different* block at this slot.
///
/// `existing_at_slot` is the result of `dag.block_at_slot(block.slot())`,
/// pre-fetched by the caller to keep this function free of a `Dag` reference
/// (see module doc — no cross-module coupling).
///
/// Returns `Err(ConsensusError::Equivocation)` if a conflicting block already
/// exists. The same block submitted twice (idempotent re-delivery) is **not**
/// equivocation: digests match, no error.
pub(crate) fn check_no_equivocation(
    block: &DagBlock,
    existing_at_slot: Option<DagBlockRef>,
) -> Result<(), ConsensusError> {
    if let Some(existing) = existing_at_slot {
        if existing.digest != block.digest {
            return Err(ConsensusError::Equivocation {
                author: block.author,
                round: block.round,
                first: existing.digest,
                second: block.digest,
            });
        }
    }
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Collect all ancestor refs that are missing from the given `contains` predicate.
///
/// Used by `Dag::insert` to build the `waiting_for` reverse index for
/// suspended blocks (rule 4). Separate from `check_*` because rule 4 requires
/// ALL missing ancestors (not just the first) to build the wakeup index.
pub(crate) fn collect_missing_ancestors<F>(block: &DagBlock, contains: F) -> Vec<DagBlockRef>
where
    F: Fn(&DagBlockRef) -> bool,
{
    block
        .ancestors
        .iter()
        .filter(|a| !contains(a))
        .copied()
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
