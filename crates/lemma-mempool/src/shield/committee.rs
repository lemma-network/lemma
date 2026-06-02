//! `ShieldCommittee` — stake-weighted share partition (Ω_i) for one epoch.
//!
//! Derives each committee member's share indices from the `ValidatorSet`'s
//! voting powers (15-SHIELD_SPEC §4.0, §4.2). The partition is **deterministic**:
//! same `ValidatorSet` → same `Ω_i` assignment on every node (§7.7, §7.8).
//!
//! # Partition algorithm
//!
//! 1. Iterate `ValidatorSet.members` in `BTreeMap<Address, _>` order (canonical
//!    address sort — deterministic across all nodes, AGENTS.md §7.1).
//! 2. For each member, compute `weight_i = ⌊stake_drop / WEIGHT_GRANULARITY_DROP⌋`.
//!    Members with zero weight are rejected (`ShieldError::ZeroWeightValidator`).
//! 3. Assign a contiguous block of `ShareId`s: `Ω_i = [next..next+weight_i)`.
//!    ShareIds are 1-indexed (`ShareId = u16 ≥ 1`) as required by
//!    `lagrange_basis_at_0_for_all` (docknetwork rejects x=0).
//! 4. `W = Σ weight_i`. Validated through `ShieldParams::for_weight`.
//!
//! # Determinism
//!
//! All arithmetic is integer-only (no floats). Uses `BTreeMap` throughout.
//! Two nodes given identical `ValidatorSet` inputs produce byte-identical
//! `Ω_i` assignments (15-SHIELD_SPEC §7.7, §7.8, AGENTS.md §7.1).

use std::collections::BTreeMap;

use secret_sharing_and_dkg::common::ShareId;

use lemma_core::{address::Address, validator_set::ValidatorSet};

use crate::shield::{
    params::{ShieldParams, WEIGHT_GRANULARITY_DROP},
    ShieldError,
};

// ── ShieldCommittee ───────────────────────────────────────────────────────────

/// Stake-weighted Ω_i share partition for one Shield epoch.
///
/// Contains the threshold parameters `(W, t, p)` and the per-validator
/// contiguous blocks of `ShareId`s. Consumed by the PVSS deal/verify steps
/// (S5–S6) and the resharing step (S7).
///
/// # Construction
///
/// Use [`ShieldCommittee::from_validator_set`]. The struct is immutable after
/// construction — the partition is frozen for the epoch's duration.
#[derive(Debug, Clone)]
pub struct ShieldCommittee {
    /// Epoch this partition is active for.
    epoch: u64,
    /// Threshold parameters derived from total weight `W`.
    params: ShieldParams,
    /// Per-validator share blocks: `address → [start_id, …, start_id+weight−1]`.
    ///
    /// `BTreeMap` guarantees deterministic iteration across all nodes.
    /// ShareIds are 1-indexed contiguous integers (never 0).
    shares: BTreeMap<Address, Vec<ShareId>>,
}

impl ShieldCommittee {
    /// Derive the Ω_i partition from a `ValidatorSet`.
    ///
    /// Iterates members in canonical address order, assigns contiguous
    /// `ShareId` blocks proportional to stake, and validates the total
    /// weight `W` through [`ShieldParams::for_weight`].
    ///
    /// # Errors
    ///
    /// - [`ShieldError::ZeroWeightValidator`] — member's stake is below
    ///   `WEIGHT_GRANULARITY_DROP` (rounds to 0 shares).
    /// - [`ShieldError::DomainTooLarge`] — total `W > u16::MAX` (65 535)
    ///   or individual weight overflows `u64`.
    /// - [`ShieldError::CommitteeTooSmall`] — total `W < 4`.
    pub fn from_validator_set(vset: &ValidatorSet) -> Result<Self, ShieldError> {
        if vset.members.is_empty() {
            return Err(ShieldError::CommitteeTooSmall { have: 0 });
        }

        // Pass 1: compute per-validator weights + accumulate W.
        // Iterate in BTreeMap<Address, _> order → deterministic across nodes.
        let mut weights: BTreeMap<Address, u64> = BTreeMap::new();
        let mut total_w: u64 = 0;

        for (addr, member) in &vset.members {
            let stake_drop: u128 = member.power.as_amount().as_drop();
            let weight_u128: u128 = stake_drop / WEIGHT_GRANULARITY_DROP;

            if weight_u128 == 0 {
                return Err(ShieldError::ZeroWeightValidator(*addr));
            }

            // Cast u128 → u64: safe because max individual weight =
            // (total_supply_drop / WEIGHT_GRANULARITY_DROP) ≪ u64::MAX.
            // With 1B LEM total supply: max_weight = 10^27 / 10^24 = 1_000.
            // We guard the general case defensively with try_from.
            let weight = u64::try_from(weight_u128)
                .map_err(|_| ShieldError::DomainTooLarge { size: u64::MAX })?;

            total_w = total_w
                .checked_add(weight)
                .ok_or(ShieldError::DomainTooLarge { size: total_w })?;

            weights.insert(*addr, weight);
        }

        // Validate total W through ShieldParams (checks W ≥ 4) and the
        // ShareId ceiling (ShareId = u16 → W ≤ u16::MAX = 65_535).
        if total_w > u64::from(u16::MAX) {
            return Err(ShieldError::DomainTooLarge { size: total_w });
        }
        let params = ShieldParams::for_weight(total_w)?;

        // Pass 2: assign contiguous ShareId blocks.
        // Use u32 for next_id to avoid u16 overflow arithmetic during the loop
        // (next_id reaches up to 1 + total_w ≤ 1 + 65_535 = 65_536 = u16::MAX+1).
        let mut next_id: u32 = 1; // ShareId is 1-indexed (never 0)
        let mut shares: BTreeMap<Address, Vec<ShareId>> = BTreeMap::new();

        for (addr, &weight) in &weights {
            // The two `as` casts below are safety-load-bearing on the `total_w ≤ u16::MAX`
            // invariant enforced on line 108. Both are safe: `weight ≤ total_w ≤ 65535`
            // and all produced IDs `≤ total_w ≤ u16::MAX`.
            // TODO(shield): replace inner `i as u16` with `u16::try_from(i)` if refactored
            // to remove the total_w ceiling check — CodeReviewer W2.
            let weight_u32 = weight as u32; // weight ≤ total_w ≤ u16::MAX ✓
            let block: Vec<ShareId> = (next_id..next_id + weight_u32)
                .map(|i| i as u16) // i ≤ total_w ≤ u16::MAX ✓
                .collect();
            next_id += weight_u32;
            shares.insert(*addr, block);
        }

        // Postcondition: all W ShareIds assigned, none skipped or doubled.
        debug_assert_eq!(next_id, 1 + total_w as u32, "ShareId assignment gap");

        Ok(Self {
            epoch: vset.epoch,
            params,
            shares,
        })
    }

    /// The epoch this committee is active for.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Threshold parameters `(W, t, p)` for this committee.
    #[must_use]
    pub fn params(&self) -> &ShieldParams {
        &self.params
    }

    /// Total share count `W = Σ weight_i`.
    #[must_use]
    pub fn total_weight(&self) -> u64 {
        self.params.w
    }

    /// Share-ID block assigned to `addr`, or `None` if not in this committee.
    #[must_use]
    pub fn share_ids_of(&self, addr: &Address) -> Option<&[ShareId]> {
        self.shares.get(addr).map(Vec::as_slice)
    }

    /// Number of shares assigned to `addr` (0 if not a member).
    #[must_use]
    pub fn weight_of(&self, addr: &Address) -> u64 {
        self.shares.get(addr).map(|v| v.len() as u64).unwrap_or(0)
    }

    /// Iterator over `(address, share_ids)` in canonical address order.
    pub fn iter(&self) -> impl Iterator<Item = (&Address, &[ShareId])> {
        self.shares.iter().map(|(a, v)| (a, v.as_slice()))
    }

    /// Number of distinct validators in this committee.
    #[must_use]
    pub fn validator_count(&self) -> usize {
        self.shares.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
