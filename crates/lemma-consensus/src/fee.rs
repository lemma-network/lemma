//! # Burn Fee Model — base-fee calculation and fee distribution
//!
//! Implements the global per-block base fee and per-transaction fee distribution.
//!
//! ## Protocol (Burn Fee Model ≡ EIP-1559)
//!
//! The **base fee** adjusts each block to target 50% gas utilization:
//! - Above 50% → fee increases by up to `base_fee / 8` (+12.5% max).
//! - Below 50% → fee decreases by up to `base_fee / 8` (−12.5% max).
//! - Base fee is **100% burned** (sent to `Address::burn()`).
//! - Priority tip = `(gas_price − base_fee) × gas_used` → **100% to proposer**.
//!
//! ## Anti-spam floor (D10g)
//!
//! The base fee never falls below [`MIN_BASE_FEE_DROP`] (1 Drip = 10⁹ Drop).
//! Grounding: mirrors Ethereum's `INITIAL_BASE_FEE = 1 Gwei`; Lemma's Drip
//! is the gas unit (1 Drip = 1e9 Drop ≡ 1 Gwei). Identical floor on
//! devnet / testnet / mainnet — production-ready by design.
//! Genesis may set `initial_base_fee = 0`; this clamp takes effect from block 1.
//!
//! ## Determinism (AGENTS.md §7.1)
//!
//! - Integer-only arithmetic — no floats.
//! - `checked_mul` guards the one multiplication that can theoretically overflow.
//! - Integer division truncates toward zero — identical on every node.
//! - No `SystemTime`, no `HashMap`.
//!
//! ## Usage (lemma-vm / Flux)
//!
//! ```text
//! // Block N+1 header construction:
//! let next_base = calculate_base_fee(&parent_header)?;
//!
//! // Per-transaction after execution (gas_used from receipt):
//! let fees = distribute_fee(receipt.gas_used, header.base_fee, tx.gas_price)?;
//! // → fees.burned sent to Address::burn()
//! // → fees.to_proposer credited to block proposer
//! ```

use lemma_core::{amount::Amount, error::AmountError, header::BlockHeader};

// ── Protocol constants ────────────────────────────────────────────────────────

/// Gas utilization target: 50% of `gas_limit` (`target = gas_limit / 2`).
const GAS_TARGET_DENOMINATOR: u64 = 2;

/// Maximum base-fee change per block: ±12.5% (i.e. `÷ 8`). Mirrors EIP-1559
/// `BASE_FEE_MAX_CHANGE_DENOMINATOR`.
const BASE_FEE_CHANGE_DENOMINATOR: u128 = 8;

/// Minimum base-fee increase when the block is above target: 1 Drop.
///
/// When `base_fee × delta / target / 8` truncates to zero (very low base fee),
/// this floor guarantees at least 1 Drop increase so the fee can recover.
/// Mirrors EIP-1559 `max(base_fee_per_gas_delta, 1)`.
const MIN_BASE_FEE_DELTA_DROP: u128 = 1;

/// Anti-spam floor: the base fee never falls below **1 Drip = 1,000,000,000 Drop**.
///
/// Grounding (D10g): mirrors Ethereum's `INITIAL_BASE_FEE = 1 Gwei`; the Lemma
/// Drip unit is the gas-price unit (1 Drip = 1e9 Drop ≡ 1 Gwei = 1e9 wei).
/// Prevents spam attacks that exploit a near-zero base fee.
/// Identical across devnet / testnet / mainnet — production-ready.
pub const MIN_BASE_FEE_DROP: u128 = 1_000_000_000; // 1 Drip

// ── FeeDistribution ───────────────────────────────────────────────────────────

/// The distribution of a single transaction's fee.
///
/// `burned + to_proposer == gas_price × gas_used` exactly (no rounding loss).
/// The burned portion is sent to [`Address::burn()`];
/// `to_proposer` is credited to the block proposer.
///
/// [`Address::burn()`]: lemma_core::address::Address::burn
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "fee distribution must be applied: burned → Address::burn(), to_proposer → block proposer"]
pub struct FeeDistribution {
    /// Amount burned (100% of `base_fee × gas_used`). → `Address::burn()`.
    pub burned: Amount,
    /// Amount to the block proposer (100% of `(gas_price − base_fee) × gas_used`).
    pub to_proposer: Amount,
}

// ── calculate_base_fee ────────────────────────────────────────────────────────

/// Compute the base fee for the next block using the Burn Fee Model.
///
/// ## Formula
///
/// ```text
/// target  = parent.gas_limit / 2
/// delta   = parent.base_fee × |gas_used − target| / target / 8
/// if gas_used > target: next = parent.base_fee + max(delta, 1 Drop)
/// if gas_used < target: next = parent.base_fee − delta
/// if gas_used == target: next = parent.base_fee
/// result  = max(next, MIN_BASE_FEE_DROP)          ← anti-spam clamp
/// ```
///
/// ## Determinism
///
/// Pure function of `parent` — integer-only, no clock, no `HashMap`.
/// Produces identical results on every node for identical input.
///
/// ## Precondition
///
/// `parent` must satisfy [`BlockHeader::validate`] (`gas_used ≤ gas_limit`).
/// The consensus path guarantees this. An unvalidated header with
/// `gas_used > gas_limit` may produce a delta exceeding the ±12.5% cap.
///
/// ## Errors
///
/// Returns [`AmountError::Overflow`] if `parent.base_fee × |gas_used − target|`
/// overflows `u128`. Unreachable with physically plausible gas parameters
/// (base_fee ≤ 10^36 Drop and gas_diff ≤ 10^9 would still not overflow u128),
/// but the check is mandatory per AGENTS.md §7.4.
#[must_use = "the calculated base fee must be used to build the next block header"]
pub fn calculate_base_fee(parent: &BlockHeader) -> Result<Amount, AmountError> {
    let base_fee = parent.base_fee.as_drop();
    let target_u64 = parent.gas_limit / GAS_TARGET_DENOMINATOR;

    // Guard: gas_limit = 0 is already rejected by BlockHeader::validate,
    // but gas_limit = 1 → target = 0 → division-by-zero in the formula.
    // Return the clamped parent fee rather than failing with a confusing error.
    if target_u64 == 0 {
        return Ok(parent.base_fee.max(Amount::from_drop(MIN_BASE_FEE_DROP)));
    }

    let target = target_u64 as u128;
    let gas_used = parent.gas_used as u128;

    let new_fee_drop = match gas_used.cmp(&target) {
        std::cmp::Ordering::Equal => {
            // Exactly at target: no change.
            base_fee
        }
        std::cmp::Ordering::Greater => {
            // Above target: fee increases.
            let delta = compute_fee_delta(base_fee, gas_used - target, target)?;
            // Always increase by at least MIN_BASE_FEE_DELTA_DROP even when
            // integer division truncates delta to 0 (mirrors EIP-1559 max(Δ, 1)).
            let delta = delta.max(MIN_BASE_FEE_DELTA_DROP);
            base_fee.checked_add(delta).ok_or(AmountError::Overflow {
                lhs: base_fee,
                rhs: delta,
            })?
        }
        std::cmp::Ordering::Less => {
            // Below target: fee decreases.
            //
            // Proof that subtraction cannot underflow:
            //   delta = base_fee × (target − gas_used) / target / 8
            //         ≤ base_fee × target / target / 8
            //         = base_fee / 8  ≤  base_fee
            // Therefore base_fee − delta ≥ 0 always.
            let delta = compute_fee_delta(base_fee, target - gas_used, target)?;
            debug_assert!(
                delta <= base_fee,
                "decrease delta must not exceed base_fee (proof in doc)"
            );
            base_fee.saturating_sub(delta) // safe per proof above; saturating = defence-in-depth
        }
    };

    // Clamp: base fee never falls below the anti-spam floor (D10g).
    Ok(Amount::from_drop(new_fee_drop.max(MIN_BASE_FEE_DROP)))
}

/// `base_fee × gas_diff / target / BASE_FEE_CHANGE_DENOMINATOR` (Drop units).
///
/// `target > 0` is guaranteed by `calculate_base_fee` (early-return guard).
/// `BASE_FEE_CHANGE_DENOMINATOR = 8 ≠ 0` — no division-by-zero.
/// Only `checked_mul` can fail; the two subsequent divisions are infallible.
fn compute_fee_delta(base_fee: u128, gas_diff: u128, target: u128) -> Result<u128, AmountError> {
    debug_assert!(
        target > 0,
        "compute_fee_delta requires target > 0 (caller invariant)"
    );
    base_fee
        .checked_mul(gas_diff)
        .map(|n| n / target / BASE_FEE_CHANGE_DENOMINATOR)
        .ok_or(AmountError::Overflow {
            lhs: base_fee,
            rhs: gas_diff,
        })
}

// ── distribute_fee ────────────────────────────────────────────────────────────

/// Distribute a transaction's fee into burned and proposer portions.
///
/// ## Distribution
///
/// - `burned      = base_fee × gas_used` — 100% burned (Burn Fee Model).
/// - `to_proposer = (gas_price − base_fee) × gas_used` — 100% to proposer.
///
/// `burned + to_proposer == gas_price × gas_used` exactly.
///
/// ## Parameters
///
/// - `gas_used`   — actual gas consumed (from execution receipt, **not** `Transaction.gas_limit`).
///   Injected by the caller (lemma-vm / Flux) after execution.
/// - `base_fee`   — the block's base fee per gas (`BlockHeader.base_fee`).
/// - `gas_price`  — the transaction's gas price (`Transaction.gas_price`).
///
/// ## Errors
///
/// - [`AmountError::Underflow`] if `gas_price < base_fee` (D10d defence-in-depth;
///   the mempool already enforces `gas_price ≥ base_fee` at admission).
/// - [`AmountError::Overflow`] if `base_fee × gas_used` or `tip × gas_used` overflows.
pub fn distribute_fee(
    gas_used: u64,
    base_fee: Amount,
    gas_price: Amount,
) -> Result<FeeDistribution, AmountError> {
    // Err if gas_price < base_fee (AmountError::Underflow, D10d).
    let tip_per_gas = gas_price.checked_sub(base_fee)?;
    let burned = base_fee.checked_mul(gas_used as u128)?;
    let to_proposer = tip_per_gas.checked_mul(gas_used as u128)?;
    Ok(FeeDistribution {
        burned,
        to_proposer,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
