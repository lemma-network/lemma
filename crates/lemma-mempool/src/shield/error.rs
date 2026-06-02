//! `ShieldError` — all error variants for the Shield subsystem.
//!
//! Single home for every `ShieldError` variant, grown per sub-step (S1–S8).
//! All variants carry enough context to diagnose failures (AGENTS.md §12.2).
//!
//! **Settlement-path invariant**: every Shield function in the post-order
//! settlement path returns `Result<_, ShieldError>` — it **never panics**
//! (15-SHIELD_SPEC §6, AGENTS.md §7.2, Sui-stall lesson).

use lemma_core::Address;

/// All errors produced by the Shield subsystem (15-SHIELD_SPEC §8.2).
///
/// `#[non_exhaustive]` allows adding variants in future sub-steps (S2–S8)
/// without breaking downstream `match` arms (AGENTS.md §4.3).
#[derive(Debug, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum ShieldError {
    // ── S1: foundation — params / committee / domain ──────────────────────────

    /// Committee total weight `W` is too small for viable threshold parameters.
    ///
    /// Minimum viable `W = 4` yields `t = 0` (secrecy threshold) and `p = 2`
    /// (privacy threshold; decryption needs ≥ 3 of 4 shares). Smaller values
    /// produce degenerate thresholds (t underflows below 0 for W < 3; W = 3
    /// gives t = 0 with no corruption tolerance for secrecy).
    ///
    /// In practice the genesis minimum stake (20M LEM) and 1M-LEM-per-share
    /// granularity give each validator ≥ 20 shares, so this error only fires
    /// on an empty or near-empty committee.
    #[error("committee weight W={have} is too small (minimum W=4 for viable thresholds)")]
    CommitteeTooSmall { have: u64 },

    /// A committee member's stake rounds down to zero shares under the current
    /// weight granularity and cannot be assigned a share in the Ω_i partition.
    ///
    /// Validators with active stake below `WEIGHT_GRANULARITY_DROP`
    /// (1 000 000 LEM, currently) receive zero shares and are rejected.
    /// The `ValidatorSet` passed to `ShieldCommittee::from_validator_set`
    /// should only contain bonded validators with sufficient stake.
    #[error("validator {0} has zero share weight — stake below weight granularity threshold")]
    ZeroWeightValidator(Address),

    /// Total share count `W` exceeds the maximum `ShareId` range.
    ///
    /// `ShareId` (from `secret_sharing_and_dkg`) is `u16`, capping `W` at
    /// 65 535. With 1M-LEM-per-share granularity and a 1B-LEM total supply,
    /// `W ≤ 1 000` in practice — this error is unreachable under normal
    /// operating conditions and guards against misconfiguration.
    #[error("domain size W={size} exceeds maximum ShareId range (u16::MAX = 65535)")]
    DomainTooLarge { size: u64 },

    /// The fixed radix-2 FFT evaluation domain could not be constructed.
    ///
    /// Fires when `Radix2EvaluationDomain::<Fr>::new(w)` returns `None`,
    /// which occurs when the rounded-up power-of-two size exceeds the scalar
    /// field's two-adicity (`Fr::TWO_ADICITY` for BLS12-381 = 32). With
    /// `W ≤ u16::MAX = 65 535`, the required domain size is at most 65 536 =
    /// 2^16, which is well within BLS12-381's two-adicity. Guards against
    /// future misuse with a different field or extreme W values.
    #[error("FFT evaluation domain construction failed for W={size} (exceeds field two-adicity?)")]
    FftDomainFailed { size: u64 },

    /// Lagrange basis computation returned an error from `secret_sharing_and_dkg`.
    ///
    /// In Shield's usage (ShareIds = 1..=W, never 0), this error is
    /// unreachable — the docknetwork library errors only when an x-coordinate
    /// is 0. Included for defensive error handling.
    #[error("Lagrange basis computation failed: {0}")]
    Lagrange(String),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
