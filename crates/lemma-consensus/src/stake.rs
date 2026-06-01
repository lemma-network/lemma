//! Stake-weighted quorum and validity threshold aggregation.
//!
//! [`StakeAggregator`] is the **single entry point** for every 2f+1 / f+1 check
//! in this crate — round advancement, certificate detection, blame, and commit/
//! skip decisions all route through here
//! (`docs/07-CONSENSUS_SPEC.md §1.1`).
//!
//! # Safety-critical invariant — idempotency
//!
//! [`StakeAggregator::add`] is **idempotent per author**: adding the same author
//! twice counts their stake exactly once. Without this, a Byzantine block that
//! pads its ancestor list with duplicate references from one author could inflate
//! the accumulated stake past a genuine 2f+1 quorum. The invariant is enforced
//! by a [`BTreeSet`] of counted authors (deterministic — AGENTS.md §7.1).
//!
//! # Reuse contract (spec 13)
//!
//! `StakeAggregator` is also consumed by the validator/epoch/slashing modules
//! (`docs/13-VALIDATOR_EPOCH_SPEC.md §8.2`). The caller supplies `VotingPower`
//! directly so the aggregator remains independent of [`ValidatorSet`] — it can
//! therefore accumulate historical-epoch power for slashing without holding a
//! reference to the current epoch's set.
//!
//! [`ValidatorSet`]: lemma_core::ValidatorSet

use std::collections::BTreeSet;

use lemma_core::{address::Address, amount::Amount, validator::VotingPower};

use crate::error::ConsensusError;

// ── Threshold ─────────────────────────────────────────────────────────────────

/// Which stake fraction the aggregator is measuring against.
///
/// Per `docs/07-CONSENSUS_SPEC.md §0` (decision) and §1: **all** commit-path
/// checks (round advance, certificates, blame, skip) use [`Threshold::Quorum`].
/// [`Threshold::Validity`] is reserved for availability / "at least one honest
/// node" reasoning — it is **never** used as a commit gate. Do not mix them
/// (spec §1: "do not mix thresholds").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Threshold {
    /// Strict majority: accumulated stake **> 2/3** of total (`2f+1` nodes with
    /// equal stake). Governs round advancement, certificates, blame, and skip.
    ///
    /// Check: `accumulated * 3 > total * 2`.
    Quorum,

    /// Availability threshold: accumulated stake **> 1/3** of total (`f+1`).
    ///
    /// Use only for equivocation / availability arguments.
    /// Check: `accumulated * 3 > total * 1`.
    Validity,
}

// ── StakeAggregator ───────────────────────────────────────────────────────────

/// Accumulates stake over a **set** of distinct authors against a fixed threshold.
///
/// Constructed once per check site (one per round, one per certificate scan)
/// with the committee's total voting power, then fed `(author, power)` pairs.
/// Returns `true` from [`add`] once the threshold is first crossed.
///
/// # Idempotency
///
/// Re-adding an already-counted author is a **no-op** — their stake is never
/// double-counted. See module-level doc for the safety argument.
///
/// # Design choice — caller supplies `VotingPower`
///
/// The aggregator does not hold a reference to [`ValidatorSet`]. Callers resolve
/// `author → VotingPower` from their own epoch context before calling `add`.
/// This keeps the aggregator pure (single responsibility: accumulate stake
/// against a threshold), testable without a full `ValidatorSet`, and reusable
/// with historical power values for slashing (spec 13 §5.1).
///
/// [`add`]: StakeAggregator::add
/// [`ValidatorSet`]: lemma_core::ValidatorSet
#[derive(Debug, Clone)]
pub struct StakeAggregator {
    threshold: Threshold,
    /// Total voting power of the committee, raw Drop. Fixed at construction.
    total_power: u128,
    /// Accumulated stake so far, raw Drop. Built with `checked_add`.
    accumulated: u128,
    /// Set of distinct authors whose stake has been counted. `BTreeSet` for
    /// deterministic membership (AGENTS.md §7.1).
    counted: BTreeSet<Address>,
    /// Cached threshold result. Set to `true` once crossed; never reset to
    /// `false` except by `clear`.
    reached: bool,
}

impl StakeAggregator {
    /// Create a new aggregator for the given `threshold` and committee
    /// `total_power` (`ValidatorSet::total_power` for the current epoch).
    #[must_use]
    pub fn new(threshold: Threshold, total_power: Amount) -> Self {
        Self {
            threshold,
            total_power: total_power.as_drop(),
            accumulated: 0,
            counted: BTreeSet::new(),
            reached: false,
        }
    }

    /// Convenience: quorum (> 2/3, `2f+1`) aggregator.
    #[must_use]
    pub fn quorum(total_power: Amount) -> Self {
        Self::new(Threshold::Quorum, total_power)
    }

    /// Convenience: validity (> 1/3, `f+1`) aggregator.
    #[must_use]
    pub fn validity(total_power: Amount) -> Self {
        Self::new(Threshold::Validity, total_power)
    }

    /// Add an author's voting power to the accumulation.
    ///
    /// **Idempotent per author**: if `author` was already counted this is a
    /// no-op and the current threshold state is returned unchanged.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` — threshold is now reached (on the crossing call and every
    ///   subsequent call).
    /// - `Ok(false)` — threshold not yet reached.
    /// - `Err(ConsensusError::StakeOverflow)` — `checked_add` overflowed
    ///   `u128`. Indicates a misconfigured or Byzantine validator set
    ///   (AGENTS.md §7.4).
    pub fn add(
        &mut self,
        author: Address,
        power: VotingPower,
    ) -> Result<bool, ConsensusError> {
        // Idempotency guard: already counted → return current state, no change.
        if self.counted.contains(&author) {
            return Ok(self.reached);
        }

        // Accumulate with overflow check (AGENTS.md §7.4).
        self.accumulated = self
            .accumulated
            .checked_add(power.as_amount().as_drop())
            .ok_or(ConsensusError::StakeOverflow { author })?;

        self.counted.insert(author);

        // Cache once reached. Safe because accumulated is monotonically
        // non-decreasing within a round — only `clear` can reset it. A threshold
        // crossed once stays crossed until the next `clear` (spec §1.1).
        if !self.reached {
            self.reached =
                exceeds_threshold(self.accumulated, self.total_power, self.threshold);
        }

        Ok(self.reached)
    }

    /// Returns `true` if the threshold has been reached.
    #[must_use]
    pub fn is_reached(&self) -> bool {
        self.reached
    }

    /// The accumulated stake in raw Drop units.
    #[must_use]
    pub fn accumulated(&self) -> u128 {
        self.accumulated
    }

    /// The number of **distinct** authors counted so far.
    ///
    /// **Diagnostic / test accessor only.** Quorum is stake-weighted — this
    /// count carries no quorum semantics. A validator set with heterogeneous
    /// voting power may reach quorum with fewer authors than a naive count
    /// would suggest.
    #[must_use]
    pub fn count(&self) -> usize {
        self.counted.len()
    }

    /// Reset accumulated stake and counted-author set for reuse.
    ///
    /// Preserves `total_power` and `threshold` — a cleared aggregator can be
    /// used for the next check site without re-construction
    /// (`docs/07-CONSENSUS_SPEC.md §1.1` `clear` contract).
    pub fn clear(&mut self) {
        self.accumulated = 0;
        self.counted.clear();
        self.reached = false;
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `accumulated` stake **strictly exceeds** the threshold
/// fraction of `total` stake.
///
/// Quorum (2f+1):   `accumulated * 3 > total * 2`
/// Validity (f+1):  `accumulated * 3 > total * 1`
///
/// Uses `saturating_mul` to guard against overflow. In practice both values are
/// bounded by the total LEM supply in Drop (< 10^28 at any realistic supply),
/// far below `u128::MAX / 3` (~1.13 × 10^38), so saturation never occurs on a
/// correctly configured network.
///
/// The strict `>` is intentional: spec §1 defines quorum as "stake **> 2/3 S**"
/// and validity as "stake **> 1/3 S**" — exact two-thirds / one-third does NOT
/// qualify.
fn exceeds_threshold(accumulated: u128, total: u128, threshold: Threshold) -> bool {
    let factor: u128 = match threshold {
        Threshold::Quorum => 2,
        Threshold::Validity => 1,
    };
    accumulated.saturating_mul(3) > total.saturating_mul(factor)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
