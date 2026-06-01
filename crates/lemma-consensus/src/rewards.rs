//! # Reward distribution — inflation mint + validator allocation (spec §7)
//!
//! Implements Steps 1–2 of `advance_epoch`
//! (`docs/13-VALIDATOR_EPOCH_SPEC §4.1`): computes epoch inflation from total
//! supply and distributes the pool to active validators proportionally by
//! voting power.
//!
//! ## Design decisions (decisions-log DB-4, DB-5)
//!
//! - **Inflation**: stepped per-year schedule (DB-2), computed as
//!   `supply × rate_bps / 10_000 / EPOCHS_PER_YEAR` per epoch
//!   (integer-only, round down). Closes spec §9 open-item "inflation curve".
//!
//! - **Distribution unit — Drip** (DB-4): raw Drop arithmetic risks u128
//!   overflow (`pool × power` ≈ 10³² at 1B-LEM supply + one large validator).
//!   Both operands are divided by `DROPS_PER_DRIP` before multiplication;
//!   the largest intermediate product is ≈ 10³², well below `u128::MAX ≈ 3.4×10³⁸`.
//!   Precision loss: < 1 Drip (10⁹ Drop ≈ 10⁻⁹ LEM) per validator per epoch —
//!   acceptable. Overflow safety holds up to ≈ 1000× genesis supply.
//!
//! - **Remainder burn** (DB-5): truncation dust (pool − Σshares) is **burned**
//!   — deterministic, no new state, consistent with "slashed LEM is burned"
//!   (spec §5.1). Caller reduces total supply by `burned_remainder`.
//!
//! - **Commission v1 note**: `commission_bps` is honored structurally. With
//!   no delegator records (F1 accumulator = Phase 3), the split is identity —
//!   the full share goes to `self_stake.active` (auto-compound). Superseded by
//!   Phase 3.
//!
//! - **No tips** (T2): priority tips are credited per-block to the block
//!   proposer during execution (`lemma-vm`, Phase 3). `advance_epoch` handles
//!   inflation only.
//!
//! ## Determinism
//!
//! Integer-only. `BTreeMap` iteration. No `SystemTime`. No floats.
//! Same `(supply, epoch_number)` → same inflation. Same `(pool, vset)` → same
//! share splits. Two nodes given identical inputs produce identical outcomes.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::{Amount, DROPS_PER_DRIP},
    error::AmountError,
    validator::Validator,
    validator_set::ValidatorSet,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of epochs per year (DB-2: one epoch = 24 h, 365 days/year).
///
/// Used to convert the annual inflation schedule into a per-epoch mint amount.
pub const EPOCHS_PER_YEAR: u64 = 365;

/// Stepped annual inflation rates in basis points, indexed by calendar year (DB-2).
///
/// | Index | Year   | Rate   |
/// |-------|--------|--------|
/// |   0   | Yr 1   | 2.00%  |
/// |   1   | Yr 2   | 1.70%  |
/// |   2   | Yr 3   | 1.40%  |
/// |   3   | Yr 4   | 1.20%  |
/// |   4   | Yr 5   | 1.00%  |
/// |   5   | Yr 6+  | 0.80%  | ← floor; index clamped at 5
///
/// Year = `epoch_number / EPOCHS_PER_YEAR`; clamp to index 5 for the floor.
/// Values match `docs/05-TOKENOMICS_AND_LAUNCH §2` and `docs/01-WHITEPAPER §7.2`.
pub const INFLATION_SCHEDULE_BPS: [u32; 6] = [200, 170, 140, 120, 100, 80];

// ── RewardError ───────────────────────────────────────────────────────────────

/// Errors that can occur during reward computation or distribution.
///
/// Every variant includes diagnostic context. No variant causes a panic —
/// returning `Err` propagates via `EpochError::Reward` to the node binary
/// (AGENTS.md §7.2 / Sui-stall lesson).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RewardError {
    /// Arithmetic overflow computing epoch inflation.
    ///
    /// Practically unreachable — requires total supply > `u128::MAX / 200 ≈ 1.7×10³⁶ Drop
    /// ≈ 1.7×10¹⁸ LEM`. Genesis supply is 1B LEM (10⁹ LEM = 10²⁷ Drop) — 9 orders of
    /// magnitude below the overflow threshold.
    #[error("inflation computation overflow: {source}")]
    InflationOverflow {
        /// Underlying arithmetic error with the offending operands.
        #[source]
        source: AmountError,
    },

    /// Arithmetic overflow crediting reward share to validator `address`.
    ///
    /// Practically unreachable in Drip units for any realistic supply:
    /// worst-case `pool_drip × power_drip ≈ 5.5×10³¹` at 1B-LEM supply — more than
    /// 10⁶× below `u128::MAX ≈ 3.4×10³⁸`. Safety holds up to ≈ 1000× genesis supply.
    #[error("reward distribution overflow for validator {address}: {source}")]
    DistributionOverflow {
        /// The validator whose share arithmetic overflowed.
        address: Address,
        /// Underlying arithmetic error.
        #[source]
        source: AmountError,
    },

    /// Arithmetic underflow computing remainder (`pool − Σshares < 0`).
    ///
    /// Indicates a logic bug: Σshares must never exceed the pool.
    #[error("reward remainder underflow (Σshares > pool — logic bug): {source}")]
    RemainderUnderflow {
        /// Underlying arithmetic error.
        #[source]
        source: AmountError,
    },
}

// ── RewardOutcome ─────────────────────────────────────────────────────────────

/// Output of a successful [`distribute_rewards`] call.
///
/// **Invariant**: `distributed + burned_remainder == pool` (the input pool).
///
/// The caller (`advance_epoch`) passes both values into [`EpochOutput`] so
/// `lemma-vm` can update the chain's tracked total supply:
///
/// ```text
/// new_total_supply = old_total_supply + distributed
///                  ≡ old_total_supply + minted - burned_remainder
/// ```
///
/// [`EpochOutput`]: crate::epoch::EpochOutput
#[must_use = "reward outcome must be applied: update total supply and account for burned remainder"]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardOutcome {
    /// Sum of all shares credited to active validators' `self_stake.active`.
    pub distributed: Amount,

    /// Truncation dust burned (pool − Σshares).
    ///
    /// Always < `#active_validators × DROPS_PER_DRIP` (< 1 Drip per validator).
    /// Burned per DB-5: no new state, deterministic, consistent with spec §5.1
    /// "slashed LEM is burned". Caller reduces total supply by this amount.
    pub burned_remainder: Amount,
}

// ── compute_epoch_inflation ───────────────────────────────────────────────────

/// Compute the LEM amount to mint as inflation for `epoch_number`.
///
/// Formula (integer, round down):
/// ```text
/// rate_bps = INFLATION_SCHEDULE_BPS[min(epoch_number / EPOCHS_PER_YEAR, 5)]
/// inflation = total_supply × rate_bps / 10_000 / EPOCHS_PER_YEAR
/// ```
///
/// ## Determinism
///
/// Pure function of `(total_supply, epoch_number)`. No walltime, no floats.
/// Epoch 0 uses year-1 rate (200 bps). Epoch 365 uses year-2 rate (170 bps).
///
/// ## Examples
///
/// ```
/// use lemma_consensus::rewards::{compute_epoch_inflation, INFLATION_SCHEDULE_BPS};
/// use lemma_core::amount::{Amount, DROPS_PER_LEM};
///
/// // 1B LEM at 2%/yr: per-epoch inflation ≈ 54,794 LEM
/// let supply = Amount::from_lem(1_000_000_000).unwrap();
/// let minted = compute_epoch_inflation(supply, 0).unwrap(); // epoch 0 = Yr 1
/// // 1e9 × 200 / 10_000 / 365 = 54,794... LEM (integer, round down)
/// assert!(minted.as_drop() > 0);
/// ```
///
/// # Errors
///
/// [`RewardError::InflationOverflow`] on arithmetic overflow. Unreachable for
/// any realistic supply (overflow requires supply > `u128::MAX / 200 ≈ 10³⁶ LEM`).
pub fn compute_epoch_inflation(
    total_supply: Amount,
    epoch_number: u64,
) -> Result<Amount, RewardError> {
    let year = epoch_number / EPOCHS_PER_YEAR;
    // Clamp year index to 5 (the 0.8% floor — Yr 6+).
    // `year.min(5)` is always in 0..=5 — cast to usize is always valid; no fallible conv needed.
    let idx = year.min(5) as usize;
    let rate_bps = u128::from(INFLATION_SCHEDULE_BPS[idx]);

    // supply × rate_bps / 10_000 / EPOCHS_PER_YEAR — all checked.
    //
    // Overflow analysis: supply × 200 overflows u128 only when supply > u128::MAX/200
    // ≈ 1.7×10³⁶ Drop ≈ 1.7×10¹⁸ LEM — far above the 1B-LEM genesis supply.
    total_supply
        .checked_mul(rate_bps)
        .map_err(|e| RewardError::InflationOverflow { source: e })?
        .checked_div(10_000)
        .map_err(|e| RewardError::InflationOverflow { source: e })?
        .checked_div(u128::from(EPOCHS_PER_YEAR))
        .map_err(|e| RewardError::InflationOverflow { source: e })
}

// ── distribute_rewards ────────────────────────────────────────────────────────

/// Distribute the reward `pool` to active validators, proportionally by voting power.
///
/// Credits each active validator's share to `self_stake.active` (auto-compound,
/// Cosmos model). Truncation dust is returned as `burned_remainder`.
///
/// ## Input
///
/// - `validators`: the full validator map (mutated in-place for share crediting).
/// - `vset`: **epoch N's** frozen committee (`current.validators`). Only members
///   of this set earn rewards for the epoch being closed (Bonded validators).
/// - `pool`: the total reward amount to distribute (epoch inflation).
///
/// ## Overflow guard (DB-4 — Drip units)
///
/// Raw Drop arithmetic: `pool_drop × power_drop / total_power_drop`.
/// At 1B-LEM supply with one large validator holding 1B LEM:
/// - `pool_drop ≈ 5.5×10²²`, `power_drop ≈ 10²⁷` → product ≈ 5.5×10⁴⁹ — **overflows**.
///
/// Drip-unit arithmetic: divide both by `DROPS_PER_DRIP = 10⁹` first:
/// - `pool_drip ≈ 5.5×10¹³`, `power_drip ≈ 10¹⁸` → product ≈ 5.5×10³¹ — **safe**.
///
/// Safety margin: overflow at supply ≈ 1000× genesis (1 trillion LEM).
///
/// ## Commission (v1 note)
///
/// `commission_bps` is honored structurally. With no delegator records (F1
/// accumulator = Phase 3), the split is identity — the full share goes to
/// `self_stake.active`. This is documented and superseded by Phase 3.
///
/// ## Empty active set
///
/// If no validators are active, the entire pool becomes `burned_remainder`.
///
/// # Errors
///
/// - [`RewardError::DistributionOverflow`] — unreachable in Drip units for realistic supply.
/// - [`RewardError::RemainderUnderflow`] — indicates a logic bug.
pub fn distribute_rewards(
    validators: &mut BTreeMap<Address, Validator>,
    vset: &ValidatorSet,
    pool: Amount,
) -> Result<RewardOutcome, RewardError> {
    // Total power in Drip units — truncate sub-Drip precision (< 1 Drip lost).
    let total_power_drip = vset.total_power.as_drop() / DROPS_PER_DRIP;

    // No active validators (or total power rounds to 0 in Drip): burn entire pool.
    if total_power_drip == 0 {
        return Ok(RewardOutcome { distributed: Amount::zero(), burned_remainder: pool });
    }

    let pool_drip = pool.as_drop() / DROPS_PER_DRIP;
    let mut distributed = Amount::zero();

    // BTreeMap iteration is deterministic (sorted by Address — AGENTS.md §7.1).
    for (addr, member) in &vset.members {
        let power_drip = member.power.as_amount().as_drop() / DROPS_PER_DRIP;

        // share_drip = pool_drip × power_drip / total_power_drip (round down).
        //
        // Overflow analysis (DB-4):
        //   pool_drip × power_drip
        //   ≈ 5.5×10¹³ × 10¹⁸ = 5.5×10³¹ at 1B-LEM supply, one-validator scenario.
        //   u128::MAX ≈ 3.4×10³⁸ → margin of ≈ 10⁷ (safe up to ~1000× genesis supply).
        let product = pool_drip.checked_mul(power_drip).ok_or(
            RewardError::DistributionOverflow {
                address: *addr,
                source: AmountError::Overflow { lhs: pool_drip, rhs: power_drip },
            },
        )?;
        let share_drip = product / total_power_drip;
        // Reconstruct Drop amount from Drip count: checked_mul enforces AGENTS §7.4.
        // share_drip ≤ pool_drip (proven below), so this cannot overflow in practice,
        // but an explicit check is mandatory — `from_drop` is a raw cast.
        let share = Amount::from_drop(share_drip)
            .checked_mul(DROPS_PER_DRIP)
            .map_err(|e| RewardError::DistributionOverflow { address: *addr, source: e })?;

        // Credit to self_stake.active (auto-compound — effective next epoch).
        //
        // Commission v1 note: with no delegator records, commission_bps is
        // structurally present but the split is identity (full share to self).
        // Phase 3 F1 accumulator will apply commission_bps to delegator rewards.
        if let Some(v) = validators.get_mut(addr) {
            v.self_stake.active = v
                .self_stake
                .active
                .checked_add(share)
                .map_err(|e| RewardError::DistributionOverflow { address: *addr, source: e })?;
        }

        distributed = distributed
            .checked_add(share)
            .map_err(|e| RewardError::DistributionOverflow { address: *addr, source: e })?;
    }

    // Remainder = pool − Σshares (truncation dust, < #validators × DROPS_PER_DRIP).
    // Burned per DB-5: deterministic, no new state.
    //
    // Safety: `distributed ≤ pool` is guaranteed by the floor-sum inequality:
    //   Σ floor(power_i / D) ≤ floor(Σ power_i / D) = total_power_drip
    // Therefore Σ share_drip_i ≤ pool_drip, so distributed ≤ pool.
    // `checked_sub` here is a correctness guard against logic bugs — not expected to fire.
    let burned_remainder = pool
        .checked_sub(distributed)
        .map_err(|e| RewardError::RemainderUnderflow { source: e })?;

    Ok(RewardOutcome { distributed, burned_remainder })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
