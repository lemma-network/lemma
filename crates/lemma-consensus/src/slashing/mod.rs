//! # Slashing — common mechanics, evidence, liveness, jail (spec §5)
//!
//! Implements `docs/13-VALIDATOR_EPOCH_SPEC §5.1–§5.5`:
//! - **This module**: common `slash()` function, `SlashError`, penalty constants.
//! - **`evidence.rs`** (B3b): `DoubleSignEvidence` + verification + double-sign §5.2.
//! - **`jail.rs`** (B3b): `tombstone` / `jail` state transitions §5.2/§5.5.
//! - **`liveness.rs`** (B3c): downtime sliding-window bit-array §5.5.
//!
//! Shield share-withholding (§5.4) is **deferred** — `ferveo` is GPL-3.0
//! (decisions-log), blocking the DKG dependency. `SHARE_WITHHOLDING_SLASH_BPS`
//! is defined for completeness; the caller-side implementation is not yet built.
//!
//! ## Design decisions (B3)
//!
//! - **B3-1 (inline evidence power)**: `slash()` takes `validator_power: Amount`
//!   injected from the evidence payload (CometBFT model). Historical ValidatorSet
//!   store = Phase 3; v1 trusts evidence-supplied power.
//! - **B3-2 (sig injection)**: signature verification is injected as `bool` flags
//!   (`sig_a_ok`, `sig_b_ok`) — same pattern as `dag::graph` (no `lemma-crypto`
//!   dep in `lemma-consensus`).
//! - **B3-3 (bit-array window)**: downtime uses a Cosmos-style sliding-window
//!   bit-array — O(1) per block, deterministic.
//!
//! ## Determinism
//!
//! All functions are pure over their inputs. No `SystemTime`. No floats.
//! `pending_inactive` entries are iterated in `Vec` insertion order (deterministic
//! across all nodes given identical validator state). Two nodes given identical
//! inputs produce identical slashed amounts.

use lemma_core::{address::Address, amount::Amount, error::AmountError, validator::Validator};

use crate::epoch::UNBONDING_PERIOD_SECONDS;

// ── Sub-modules (B3b / B3c) ───────────────────────────────────────────────────

pub mod evidence; // B3b: DoubleSignEvidence + verify + apply_double_sign
pub mod jail; // B3b: tombstone / jail state transitions
pub mod liveness; // B3c: SignedBlocksWindow + downtime breach detection

// ── Penalty constants ─────────────────────────────────────────────────────────

/// Slash fraction for double-signing / equivocation (spec §5.2, §0).
///
/// **5%** of infraction-height voting power. Results in permanent tombstone —
/// the consensus key can never re-bond.
pub const DOUBLE_SIGN_SLASH_BPS: u16 = 500;

/// Slash fraction for extended downtime (spec §5.5, §0).
///
/// **1%** of infraction-height voting power. Results in a finite jail sentence
/// (not tombstone — a liveness fault, recoverable).
pub const DOWNTIME_SLASH_BPS: u16 = 100;

/// Slash fraction for Shield share-withholding (spec §5.4, §0).
///
/// **10%** of infraction-epoch voting power. Results in finite jail.
///
/// ⚠️ **Currently unreachable** — Shield DKG (`ferveo`) is GPL-3.0
/// (decisions-log), blocking §5.4. Constant defined for completeness;
/// the evidence-handling caller is not yet built.
pub const SHARE_WITHHOLDING_SLASH_BPS: u16 = 1_000;

/// Maximum valid slash fraction in basis points (100% = full stake).
///
/// `fraction_bps > MAX_FRACTION_BPS` is rejected by [`slash`] with
/// [`SlashError::InvalidFraction`]. A 100% slash (full seizure) is valid.
pub const MAX_FRACTION_BPS: u16 = 10_000;

/// Maximum age for slashing evidence to be valid (spec §5.3).
///
/// **`EVIDENCE_MAX_AGE_SECONDS = UNBONDING_PERIOD_SECONDS` (14 days).**
///
/// Unbonding stake remains slashable for the full window an offense can be
/// reported — the long-range / nothing-at-stake guard. Evidence older than
/// this is rejected without applying any slash (the offender's stake may
/// already be in `inactive` and untouchable).
pub const EVIDENCE_MAX_AGE_SECONDS: u64 = UNBONDING_PERIOD_SECONDS; // 1_209_600 s

// ── SlashError ────────────────────────────────────────────────────────────────

/// Errors that can occur during slash computation or application.
///
/// Every variant includes diagnostic context. No variant causes a panic —
/// returning `Err` lets the node binary handle the failure (AGENTS.md §7.2).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SlashError {
    /// `fraction_bps` exceeds [`MAX_FRACTION_BPS`] (10,000 = 100%).
    ///
    /// A fraction above 100% would underflow `entry.initial_balance` for
    /// `pending_inactive` entries. Rejected at function entry before any
    /// state mutation.
    #[error(
        "slash fraction {fraction_bps} bps exceeds maximum {MAX_FRACTION_BPS} bps (100%)"
    )]
    InvalidFraction {
        /// The offending fraction value.
        fraction_bps: u16,
    },

    /// Arithmetic overflow computing the slash amount from `validator_power`.
    ///
    /// Practically unreachable: `validator_power × 10_000` overflows `u128`
    /// only when `validator_power > u128::MAX / 10_000 ≈ 3.4×10³⁴ Drop`.
    #[error("overflow computing slash amount for validator {address}: {source}")]
    ComputeOverflow {
        /// The validator whose power computation overflowed.
        address: Address,
        /// Underlying arithmetic error.
        #[source]
        source: AmountError,
    },

    /// Arithmetic overflow or underflow applying the slash to stake buckets.
    ///
    /// Indicates a logic bug — the `checked_sub` guards and `fraction_bps`
    /// validation should prevent this in correct code.
    #[error("overflow applying slash to validator {address} stake: {source}")]
    ApplyOverflow {
        /// The validator whose stake application overflowed.
        address: Address,
        /// Underlying arithmetic error.
        #[source]
        source: AmountError,
    },
}

// ── slash ─────────────────────────────────────────────────────────────────────

/// Apply a proportional slash to a validator's stake (spec §5.1).
///
/// Implements the common slash mechanics:
///
/// 1. Compute the slash amount: `validator_power × fraction_bps / 10_000` (integer, round down).
/// 2. Deduct from `self_stake.active` first — **capped at zero** (never negative).
/// 3. Apply the same fraction to each `pending_inactive` entry with
///    `start_height > infraction_height` (post-infraction unbondings — slashable).
///    Pre-infraction entries (`start_height ≤ infraction_height`) are **untouched**.
/// 4. `self_stake.inactive` (fully matured) is **always untouched** (spec §5.1).
///
/// Returns the **total amount actually deducted** across all stake buckets.
/// The caller must reduce total supply by this amount (`burn` — spec §5.1).
///
/// ## Capping semantics
///
/// `active` may be less than `intended` (e.g. if the validator unstaked since
/// the infraction). We take `min(active, intended)` rather than failing — a
/// partial slash is correct; the offender receives less reward but the chain
/// does not halt. `pending_inactive` entries cannot underflow because
/// `fraction_bps ≤ MAX_FRACTION_BPS` (validated at entry), so
/// `entry_slash ≤ initial_balance`.
///
/// ## Power injection (B3-1)
///
/// `validator_power` comes from the evidence payload (CometBFT model —
/// evidence carries an inline power snapshot). Full historical-ValidatorSet
/// cross-check is Phase 3.
///
/// ## Does NOT set jail or tombstone
///
/// After calling `slash`, the caller must separately call [`jail::tombstone`]
/// (double-sign) or [`jail::jail`] (downtime/share-withholding) as appropriate.
/// Separating state transitions from arithmetic keeps each function focused
/// (AGENTS.md §3.1 single responsibility).
///
/// # Errors
///
/// - [`SlashError::InvalidFraction`] if `fraction_bps > MAX_FRACTION_BPS`.
/// - [`SlashError::ComputeOverflow`] on overflow computing the slash amount.
/// - [`SlashError::ApplyOverflow`] on overflow applying to buckets (logic bug guard).
pub fn slash(
    validator: &mut Validator,
    infraction_height: u64,
    validator_power: Amount,
    fraction_bps: u16,
) -> Result<Amount, SlashError> {
    // Validate fraction before any computation or mutation.
    if fraction_bps > MAX_FRACTION_BPS {
        return Err(SlashError::InvalidFraction { fraction_bps });
    }

    let addr = validator.address;

    // ── COMPUTE-THEN-COMMIT (S4 atomicity guarantee) ──────────────────────────
    //
    // All arithmetic is computed into local variables first. The `&mut Validator`
    // is only modified after all fallible operations succeed. If any `Err` is
    // returned, `validator` is left byte-for-byte unchanged.
    //
    // This is required for consensus safety: a partial slash that returns `Err`
    // but leaves dirty state would corrupt the validator set deterministically
    // on some nodes and not others (AGENTS.md §7.2 / Sui-stall lesson).

    // ── Step 1: Compute intended slash amount ─────────────────────────────────
    //
    // Uses injected power (B3-1). Overflow: power × 10_000 overflows u128 only
    // when power > u128::MAX / 10_000 ≈ 3.4×10³⁴ Drop — far above any realistic
    // total supply (~10²⁷ Drop at genesis).
    let intended = validator_power
        .checked_mul(u128::from(fraction_bps))
        .map_err(|e| SlashError::ComputeOverflow { address: addr, source: e })?
        .checked_div(u128::from(MAX_FRACTION_BPS))
        .map_err(|e| SlashError::ComputeOverflow { address: addr, source: e })?;

    // ── Step 2: Compute active-stake deduction (local, no mutation yet) ───────
    //
    // Take min(active, intended) — active may be less than intended if the
    // validator reduced stake after the infraction. A partial deduction is
    // correct; the offender receives less burn but the chain does not halt.
    let new_active;
    let from_active;
    if validator.self_stake.active < intended {
        // Active exhausted: deduct all of it.
        from_active = validator.self_stake.active;
        new_active = Amount::zero();
    } else {
        // Normal case: sufficient active stake.
        from_active = intended;
        new_active = validator
            .self_stake
            .active
            .checked_sub(intended)
            .map_err(|e| SlashError::ApplyOverflow { address: addr, source: e })?;
    }

    // ── Step 3: Compute per-entry deductions (local, no mutation yet) ─────────
    //
    // Apply the SAME fraction to each `pending_inactive` entry with
    // `start_height > infraction_height` (post-infraction unbondings — slashable).
    // Pre-infraction entries (`≤ infraction_height`) are untouched.
    // `inactive` stake (fully matured) is never touched (spec §5.1).
    //
    // Safety: fraction_bps ≤ MAX_FRACTION_BPS (validated above) ⟹
    //   entry_slash = initial_balance × fraction_bps / 10_000 ≤ initial_balance.
    // `checked_sub` therefore cannot underflow; it is a correctness guard only.
    //
    // `initial_balance` is the live slashable balance (intentionally reduced
    // by prior slashes). Reducing it here reflects the remaining amount that
    // will be returned at unbonding completion.
    let mut entry_deltas: Vec<(usize, Amount)> = Vec::new(); // (index, new_balance)
    let mut from_pending = Amount::zero();

    for (i, entry) in validator.self_stake.pending_inactive.iter().enumerate() {
        if entry.start_height <= infraction_height {
            continue; // Pre-infraction — untouched.
        }
        let entry_slash = entry
            .initial_balance
            .checked_mul(u128::from(fraction_bps))
            .map_err(|e| SlashError::ApplyOverflow { address: addr, source: e })?
            .checked_div(u128::from(MAX_FRACTION_BPS))
            .map_err(|e| SlashError::ApplyOverflow { address: addr, source: e })?;
        let new_balance = entry
            .initial_balance
            .checked_sub(entry_slash)
            .map_err(|e| SlashError::ApplyOverflow { address: addr, source: e })?;
        from_pending = from_pending
            .checked_add(entry_slash)
            .map_err(|e| SlashError::ApplyOverflow { address: addr, source: e })?;
        entry_deltas.push((i, new_balance));
    }

    // ── Compute total burned (last fallible op before commit) ─────────────────
    let total_burned = from_active
        .checked_add(from_pending)
        .map_err(|e| SlashError::ApplyOverflow { address: addr, source: e })?;

    // ── COMMIT: all computation succeeded — apply mutations ───────────────────
    //
    // From this point on: no fallible operations, no early returns.
    // `validator` is modified atomically (all-or-nothing guaranteed above).
    validator.self_stake.active = new_active;
    for (i, new_balance) in entry_deltas {
        validator.self_stake.pending_inactive[i].initial_balance = new_balance;
    }

    Ok(total_burned)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
