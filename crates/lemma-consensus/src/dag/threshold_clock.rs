//! # ThresholdClock — Surge round advancement (spec §2.3)
//!
//! The threshold clock is the **heartbeat of the Surge dissemination loop**.
//! A validator advances its local round when it has observed a **2f+1 stake
//! quorum** of distinct-author blocks at the current round — no separate
//! certificate is needed. This single-round-trip design is Mysticeti's core
//! latency advantage over Narwhal.
//!
//! ## Surge loop
//!
//! ```text
//! propose block at round R
//!   → broadcast to peers
//!   → receive 2f+1 blocks at round R
//!   → clock.add_block(...) returns Some(R+1)
//!   → propose block at round R+1 (referencing the 2f+1 quorum as strong links)
//! ```
//!
//! ## Integration (Arsitektur Y — spec §11)
//!
//! `ThresholdClock` is a **self-contained type** owned by the surge driver
//! (`dag::surge`, Step 11). It is NOT called from [`Dag::insert`] — round
//! advancement and DAG validity are separate concerns with separate timing:
//!
//! - `Dag::insert` answers: "is this block structurally valid for the DAG?"
//! - `ThresholdClock` answers: "have I seen enough blocks to advance my round?"
//!
//! The surge driver wires them: `insert → if Accepted → clock.add_block →
//! if Some(new_round) → trigger propose`.
//!
//! ## Future-round blocks
//!
//! [`add_block`] returns `None` for any block whose round differs from the
//! current clock round (past **or** future). Future-round blocks are not
//! buffered here — they are handled by [`Dag`]'s suspended-block buffer
//! (spec §3 rule 4, Step 4). When the clock eventually catches up to their
//! round, the surge driver re-presents the by-then-accepted blocks. A single
//! buffer is sufficient (AGENTS.md §2 — one canonical way).
//!
//! ## Non-member authors
//!
//! [`add_block`] skips blocks whose author is not in the current validator set,
//! returning `Ok(None)` silently. This is safety-neutral: a non-member has
//! 0 stake by definition and cannot contribute to a 2f+1 quorum. The skip is
//! a defensive measure — the surge driver (which calls `add_block` after
//! `Dag::insert`) will normally only present accepted blocks, and `insert`
//! already rejects non-member authors (spec §3 rule 2). Consistency with
//! [`validate_strong_link_quorum`]'s treatment of non-member ancestors (AGENTS §2).
//!
//! [`Dag`]: crate::dag::graph::Dag
//! [`Dag::insert`]: crate::dag::graph::Dag::insert
//! [`add_block`]: ThresholdClock::add_block
//! [`validate_strong_link_quorum`]: crate::dag::validity::validate_strong_link_quorum

use lemma_core::{amount::Amount, validator_set::ValidatorSet};

use crate::{dag::block::DagBlock, error::ConsensusError, stake::StakeAggregator};

// ── ThresholdClock ─────────────────────────────────────────────────────────────

/// Advances the local DAG round when a 2f+1 stake quorum of blocks is seen
/// at the current round.
///
/// Constructed once per epoch with the committee's total voting power.
/// Feed accepted blocks via [`add_block`]; the clock notifies the surge driver
/// when a new round opens by returning `Some(new_round)`.
///
/// ## Idempotency
///
/// Re-adding the same author at the same round is a no-op — the underlying
/// [`StakeAggregator`] de-duplicates by author address. An equivocating author
/// cannot inflate the clock past a genuine 2f+1 quorum.
///
/// [`add_block`]: ThresholdClock::add_block
#[derive(Debug, Clone)]
pub struct ThresholdClock {
    /// Current local round. Advances to `b.round + 1` once 2f+1 stake is seen
    /// at `b.round`.
    round: u64,
    /// Stake accumulator for the current round. Uses [`Threshold::Quorum`]
    /// (strict > 2/3 S). Reset via `clear()` each time the round advances;
    /// `clear()` preserves `total_power` and `threshold` for the next round.
    stake_at_round: StakeAggregator,
}

impl ThresholdClock {
    /// Create a new clock starting at round 0 with the given committee power.
    ///
    /// `total_power` is [`ValidatorSet::total_power`] for the current epoch.
    #[must_use]
    pub fn new(total_power: Amount) -> Self {
        Self {
            round: 0,
            stake_at_round: StakeAggregator::quorum(total_power),
        }
    }

    /// Create a clock starting at a specific round.
    ///
    /// Used for catch-up / epoch-restart: the surge driver may need to
    /// rehydrate the clock to the last known DAG round without replaying
    /// every historical block.
    #[must_use]
    pub fn at_round(round: u64, total_power: Amount) -> Self {
        Self {
            round,
            stake_at_round: StakeAggregator::quorum(total_power),
        }
    }

    /// The current local round.
    #[must_use]
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Present a block to the clock; returns `Some(new_round)` on advancement.
    ///
    /// # Round mismatch
    ///
    /// - `b.round < self.round` (past) — ignored: stake already counted.
    /// - `b.round > self.round` (future) — ignored: block is in [`Dag`]'s
    ///   suspended-block buffer (spec §3 rule 4) and will be re-presented when
    ///   the clock reaches that round. No second buffer here.
    ///
    /// # Non-member author
    ///
    /// Skipped silently (see module-level doc). Does not return an error.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::StakeOverflow`] if accumulating the author's
    /// power overflows `u128`. This indicates a misconfigured or Byzantine
    /// validator set (AGENTS.md §7.4) — the surge driver should treat this as
    /// a fatal error for the current epoch.
    ///
    /// [`Dag`]: crate::dag::graph::Dag
    pub fn add_block(
        &mut self,
        b: &DagBlock,
        vset: &ValidatorSet,
    ) -> Result<Option<u64>, ConsensusError> {
        // Rule: only count blocks at the current round (spec §2.3).
        // Past blocks: stake already settled. Future blocks: buffered by Dag
        // suspended buffer (spec §3 rule 4) — no second buffer here (D5e).
        if b.round != self.round {
            return Ok(None);
        }

        // Resolve voting power. Non-member = 0 stake by definition → skip
        // silently. Consistent with validate_strong_link_quorum (AGENTS §2 —
        // one canonical way for non-member handling). Defensive: Dag::insert
        // (rule 2, see validity::validate_author_and_signature) normally filters
        // non-members before blocks reach the clock, but the clock does not
        // assume that contract holds (D5b).
        let Some(member) = vset.members.get(&b.author) else {
            return Ok(None);
        };

        // Accumulate stake. Idempotent per author (BTreeSet in StakeAggregator).
        // Propagate StakeOverflow — no panic in consensus path (AGENTS §7.2/§7.4).
        let reached = self.stake_at_round.add(b.author, member.power)?;

        if reached {
            // 2f+1 stake quorum observed. Clear accumulator for next round
            // (clear() preserves total_power + threshold — stake.rs §190-194).
            self.stake_at_round.clear();
            // `+= 1` not `checked_add`: u64 rounds at ~0.5 s/round would take
            // > 10^11 years to overflow — deliberate exemption from §7.4
            // checked-arithmetic rule (unlike token amounts, rounds are not an
            // attack surface for overflow). If this assumption ever changes,
            // add `checked_add` here and make `add_block` return `Result`.
            self.round += 1;
            Ok(Some(self.round))
        } else {
            Ok(None)
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
