//! # Epoch management — transition, proof, and recovery
//!
//! This module implements the `advance_epoch` settlement routine
//! (`docs/13-VALIDATOR_EPOCH_SPEC §4`) and will house the epoch-change proof
//! (`§4.4`, B4) and `force_epoch_close` recovery lever (`§6`, B4).
//!
//! ## Protocol
//!
//! At the **end-of-epoch boundary block**, every honest node runs the same
//! deterministic `advance_epoch` routine. It produces an identical
//! `ValidatorSet(N+1)` and `next_validators_hash` on every node — the quorum
//! commit on the boundary block IS the epoch-change proof (§4.4).
//!
//! ## Safety invariant
//!
//! **Never panics.** A panic in epoch settlement wedges the epoch — this is
//! exactly the Sui stall lesson (2026-05-28/29). Every fallible operation
//! returns `Result`; the node binary handles the error and may trigger
//! `force_epoch_close` (§6, B4) as a last resort.
//!
//! ## B4 sub-steps
//!
//! - `proof.rs` ✅ — `verify_full` + `EpochChangeProof` + `verify_epoch_change` (§4.4, B4a).
//! - `recovery.rs` ✅ — `force_epoch_close` deterministic recovery (§6, B4b).

use lemma_core::{address::Address, error::AmountError};

pub mod proof;
pub mod recovery;
pub(crate) mod transition;

pub use proof::{verify_epoch_change, verify_full, EpochChangeProof, ProofError};
pub use recovery::{force_epoch_close, RecoveryError, RecoveryOutput};
pub use transition::advance_epoch;

#[cfg(test)]
mod tests;

// ── Protocol constants ────────────────────────────────────────────────────────

/// Duration of one epoch in consensus seconds (DB-2: 24 hours, Sui/Mysticeti model).
///
/// At ~0.4 s/block: ~216,000 blocks/epoch.
/// Unbonding period = 14 epochs = 14 days.
/// Inflation year = 365 epochs.
/// **Governance-adjustable** (Phase 3) via buffered protocol-config changes
/// (spec §4.1 step 7); until then, used as the canonical value when computing
/// `UnbondingEntry.complete_time = start_time + UNBONDING_PERIOD_SECONDS`.
pub const EPOCH_DURATION_SECONDS: u64 = 86_400; // 24 hours

/// Unbonding period in consensus seconds (spec §0: 14 days).
///
/// Stake in `pending_inactive` remains slashable for this entire window.
/// `EVIDENCE_MAX_AGE = UNBONDING_PERIOD_SECONDS` (spec §5.3): the evidence
/// window ≤ the unbonding window guarantees the stake is still present to slash
/// for the full period an offense can be reported (long-range / nothing-at-stake
/// guard). `UnbondingEntry.complete_time = start_block_time + this constant`.
pub const UNBONDING_PERIOD_SECONDS: u64 = 14 * 24 * 60 * 60; // 1_209_600 s

/// Genesis seed for the minimum validator self-stake governance parameter (DB-1).
///
/// **2% of total supply (1B LEM) = 20,000,000 LEM.**
///
/// Strategy (Opsi A): start restrictive (≈ 20–50 validators at genesis), lower
/// via governance as the network matures toward the 100+ validator target.
/// At 40% staking ratio (400M LEM staked), 2% min → max ≈ 20 validators.
/// At 60% (600M staked) → max ≈ 30 validators. Target 100+ requires lowering
/// the parameter via governance as supply and staking ratio grow.
///
/// **This is a governance parameter, not a constant.** `advance_epoch` receives
/// it as an injectable `min_stake: Amount` argument so governance proposals can
/// change it (spec §4.1 step 7 "Apply buffered protocol/config changes").
/// Seed from `GenesisConfig` at chain startup.
pub const GENESIS_MIN_VALIDATOR_STAKE_DROP: u128 = 20_000_000 * lemma_core::DROPS_PER_LEM; // 20 M LEM (2% of 1B supply, DB-1)

// ── EpochOutput ───────────────────────────────────────────────────────────────

/// Output produced by a successful [`advance_epoch`] call.
///
/// The caller (`lemma-vm` / Flux) uses this to:
/// - Write `next_validators_hash` into the boundary block's
///   `BlockHeader.next_validators_hash` (spec §4.4, closes 12 §3.3).
/// - Replace the consensus driver's `LeaderSchedule` for epoch N+1.
/// - Persist the new `Epoch` to chain state.
/// - Update total supply accounting: `new_supply = old_supply + minted - burned_remainder`.
#[must_use = "epoch output must be applied: hash into block header, schedule into driver, update supply"]
#[derive(Debug, Clone)]
pub struct EpochOutput {
    /// The new epoch (N+1) with its frozen committee.
    pub epoch: lemma_core::Epoch,

    /// Blake3 hash of `ValidatorSet(N+1)`.
    ///
    /// Write into the boundary block's `BlockHeader.next_validators_hash`
    /// (spec §4.4, closes 12 §3.3). Authorises the next committee; light
    /// clients walk this hash-chain to trust epoch N+1.
    pub next_validators_hash: lemma_core::hash::Hash,

    /// Pre-built leader schedule for epoch N+1.
    ///
    /// Recomputed from `ReputationScores` over epoch N's commits (spec §4.3,
    /// closes 07 §6). Replace the running driver's schedule after applying
    /// this epoch output.
    pub leader_schedule: crate::pulse::leader::LeaderSchedule,

    /// Total LEM minted as inflation for epoch N (spec §7).
    ///
    /// Invariant: `minted = distributed_to_validators + burned_remainder`.
    /// Caller updates total supply: `new_supply = old_supply + minted - burned_remainder`,
    /// equivalently `new_supply = old_supply + distributed`.
    pub minted: lemma_core::amount::Amount,

    /// Truncation dust burned from the reward pool (DB-5, spec §7).
    ///
    /// Sub-Drip remainder from integer distribution — always
    /// `< #active_validators × 10⁹ Drop` (< 1 Drip per validator per epoch).
    /// Caller reduces total supply by this amount.
    pub burned_remainder: lemma_core::amount::Amount,
}

// ── EpochError ────────────────────────────────────────────────────────────────

/// Errors that can occur during an epoch transition.
///
/// Every variant includes context for structured logging. No variant causes a
/// panic — returning `Err` lets the node binary handle the failure gracefully
/// and optionally trigger `force_epoch_close` (spec §6, B4).
///
/// **AGENTS §7.2 / Sui-stall lesson**: a panic in `advance_epoch` wedges the
/// epoch. This type is the primary defence.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EpochError {
    /// Arithmetic overflow during stake-bucket settlement for `address`.
    ///
    /// Practically unreachable (would require total staked ≈ u128::MAX Drop),
    /// but `checked_add` is mandatory for all money operations (AGENTS §7.4).
    #[error("stake settlement overflow for validator {address}: {source}")]
    SettlementOverflow {
        /// The validator whose stake arithmetic overflowed.
        address: Address,
        /// Underlying arithmetic error.
        #[source]
        source: AmountError,
    },

    /// Arithmetic overflow accumulating total voting power.
    #[error("voting-power overflow for validator {address}: {source}")]
    PowerOverflow {
        /// The validator whose power contribution caused the overflow.
        address: Address,
        /// Underlying arithmetic error.
        #[source]
        source: AmountError,
    },

    /// No eligible validators remain after settlement for the next epoch.
    ///
    /// The committee would be empty — the chain cannot progress. The node
    /// should trigger `force_epoch_close` (spec §6, B4) or halt and alert
    /// operators.
    #[error("no eligible validators for epoch {next_epoch}: committee would be empty")]
    EmptyNextCommittee {
        /// The epoch number that would have no committee.
        next_epoch: u64,
    },

    /// Epoch number arithmetic overflow (u64 wrapped — practically unreachable).
    #[error("epoch number overflow at epoch {current}")]
    EpochNumberOverflow {
        /// The epoch number that overflowed when incremented.
        current: u64,
    },

    /// Building the leader schedule for the next epoch failed.
    ///
    /// Typically only surfaces if `EmptyNextCommittee` was not caught first.
    #[error("leader schedule construction failed: {0}")]
    ScheduleError(#[from] crate::ConsensusError),

    /// Reward computation or distribution failed (spec §7, B2).
    ///
    /// Wraps [`crate::rewards::RewardError`]. Practically unreachable in
    /// production for realistic supply levels; returned rather than panicked
    /// per AGENTS.md §7.2 / Sui-stall lesson.
    #[error("reward error: {0}")]
    Reward(#[from] crate::rewards::RewardError),

    /// An unexpected internal error during epoch settlement (S-2).
    ///
    /// Catch-all for cross-crate invariant violations that would otherwise
    /// `unreachable!()` and panic the settlement path. Returning `Err` lets
    /// the node binary handle the failure gracefully (AGENTS §7.2 / §9.3).
    #[error("internal epoch error: {reason}")]
    Internal {
        /// Human-readable description of the unexpected condition.
        reason: String,
    },
}
