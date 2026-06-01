//! Stake-weighted Quality of Service (QoS) for `lemma-mempool`.
//!
//! Computes a **local admission priority** for each transaction: a `u64` sort
//! key that determines which transactions are admitted and kept when the pool
//! is under load.
//!
//! # Design: hybrid Ethereum + Solana
//!
//! ```text
//! priority = gas_component + stake_bonus
//! ```
//!
//! - **`gas_component`** (Ethereum price-auction model): higher gas price →
//!   higher priority. Users that want inclusion urgently pay more.
//! - **`stake_bonus`** (Solana swQoS model): accounts that hold stake get a
//!   bandwidth advantage under congestion. Attackers spamming the mempool
//!   typically have no stake (stake is expensive and slashable), so honest
//!   staked participants retain admission bandwidth even during spam floods.
//!   This is **anti-DoS, not censorship** — it only reorders admission under
//!   congestion, it never permanently excludes a transaction.
//!
//! # Determinism boundary (spec §1.1)
//!
//! `Priority` is a **local sort key**, NOT a token amount and NOT part of the
//! committed transaction order. Consensus (07-CONSENSUS_SPEC) owns the final
//! order; the mempool's priority only affects which transactions this node
//! admits and gossips. Because of this:
//!
//! - This module uses **saturating arithmetic** (not `checked_*`). An overflow
//!   clamps to the maximum priority, which is the correct behavior for a sort
//!   key (an "infinitely expensive" tx should have max priority, not wrap to 0).
//! - This is intentionally different from `validation.rs` and `pool.rs` where
//!   token arithmetic uses `checked_*` (AGENTS.md §7.4). The distinction is
//!   documented here so future maintainers don't "fix" the saturation.
//!
//! # Stake bonus cap (anti-plutocracy)
//!
//! Without a cap, a whale with 10M LEM staked would get a +10M bonus, making
//! every gas-price difference irrelevant. [`MAX_STAKE_BONUS`] limits the bonus
//! so stake provides spam-resistance without concentrating ordering power in
//! the largest stakers. This is the primary critique of Solana's raw swQoS
//! (no cap) that we address here.
//!
//! # References
//!
//! - `docs/11-MEMPOOL_SHIELD_SPEC.md §1` — base mempool spec
//! - `docs/11-MEMPOOL_SHIELD_SPEC.md §1.1` — determinism note
//! - Solana swQoS: stake-weighted connection allocation (SIMDs 0022/0116)
//! - Ethereum EIP-1559: priority_fee price auction

use lemma_core::{amount::DROPS_PER_LEM, Amount};

// ── Types ─────────────────────────────────────────────────────────────────────

/// Local admission priority for a pending transaction.
///
/// Higher value = admitted and retained first under congestion.
///
/// This is a **sort key** — it is never serialized, never committed to a block,
/// and has no meaning outside this node's local pool ordering.
pub type Priority = u64;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Drop of self-stake that earns one unit of [`Priority`] bonus.
///
/// Set to 1 LEM (10¹⁸ Drop): staking 1 LEM earns +1 priority bonus.
///
/// # ⚠️ Placeholder
///
/// The final value depends on the **minimum validator stake** threshold, which
/// is a tracked open question in `living-notes.md`. Once that threshold is
/// decided, `STAKE_UNIT` should be re-evaluated to ensure the bonus curve
/// feels right relative to real stake distributions on the network.
pub const STAKE_UNIT: u128 = DROPS_PER_LEM;

/// Maximum stake-derived priority bonus per transaction.
///
/// Caps the bonus at 1,000,000 priority units regardless of stake size.
/// This prevents the largest stakers from making gas-price differences
/// irrelevant (anti-plutocracy — learned from Solana swQoS critique).
///
/// A staker needs `MAX_STAKE_BONUS × STAKE_UNIT` Drop staked to hit the cap.
/// With `STAKE_UNIT = 1 LEM`, the cap is reached at 1,000,000 LEM staked —
/// well above typical delegator amounts, so the cap only affects whales.
pub const MAX_STAKE_BONUS: u64 = 1_000_000;

// ── Public API ────────────────────────────────────────────────────────────────

/// Compute the local admission [`Priority`] for a transaction.
///
/// ```text
/// priority = gas_component + stake_bonus
///
/// gas_component  = min(gas_price_in_drop, u64::MAX)       // saturating clamp
/// stake_bonus    = min(sender_stake_drop / STAKE_UNIT, MAX_STAKE_BONUS)
/// ```
///
/// Both additions saturate at `u64::MAX` — overflow clamps to maximum priority,
/// which is the correct behavior for a sort key (see module-level docs).
///
/// # Parameters
///
/// - `gas_price`   — the transaction's gas price (in Drop per gas unit).
/// - `sender_stake` — the sender's active self-stake (in Drop).
///   Pass `Amount::zero()` for non-staked accounts; they still get prioritized
///   by their gas price, just without the stake bonus.
///
/// # Examples
///
/// ```
/// use lemma_core::Amount;
/// use lemma_mempool::qos::{priority_score, STAKE_UNIT};
///
/// // Zero stake → priority is purely the gas price component.
/// let p = priority_score(Amount::from_drop(1_000), Amount::zero());
/// assert_eq!(p, 1_000);
///
/// // 1 LEM staked → +1 bonus on top of gas component.
/// let p_staked = priority_score(Amount::from_drop(1_000), Amount::from_drop(STAKE_UNIT));
/// assert_eq!(p_staked, 1_001);
/// ```
#[must_use]
pub fn priority_score(gas_price: Amount, sender_stake: Amount) -> Priority {
    let gas_component = saturating_u128_to_u64(gas_price.as_drop());
    let bonus = stake_bonus(sender_stake);
    gas_component.saturating_add(bonus)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Compute the stake-derived priority bonus.
///
/// `bonus = min(sender_stake / STAKE_UNIT, MAX_STAKE_BONUS)`
///
/// Integer division intentionally truncates — sub-unit stake earns no bonus.
/// This avoids giving tiny stakes a disproportionate advantage and keeps the
/// bonus curve predictable and step-wise.
pub(crate) fn stake_bonus(sender_stake: Amount) -> u64 {
    let raw_bonus = sender_stake.as_drop() / STAKE_UNIT;
    // Saturating clamp to u64 before applying the MAX_STAKE_BONUS cap,
    // so a u128::MAX stake doesn't overflow the min() comparison.
    let clamped = saturating_u128_to_u64(raw_bonus);
    clamped.min(MAX_STAKE_BONUS)
}

/// Saturating cast from `u128` to `u64`.
///
/// Values that exceed `u64::MAX` clamp to `u64::MAX` rather than wrapping or
/// panicking. Safe for priority sort-key arithmetic (see module-level docs).
pub(crate) fn saturating_u128_to_u64(v: u128) -> u64 {
    v.min(u64::MAX as u128) as u64
}

#[cfg(test)]
mod tests;
