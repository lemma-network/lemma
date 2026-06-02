//! # Shield Epoch Orchestrator (N8)
//!
//! Drives the Shield DKG / resharing lifecycle at epoch boundaries and applies
//! share-withholding slashes to the validator set.
//!
//! ## Scope
//!
//! | Primitive | Role |
//! |-----------|------|
//! | [`run_epoch_shield`] | Drive DKG (genesis) or reshare (N→N+1); return epoch key or transparent fallback |
//! | [`apply_withholding_slashes`] | Slash + jail each withholder; return total burned |
//! | [`EpochShieldOutcome`] | Result of one epoch shield round |
//! | [`TransparentReason`] | Why the epoch fell back to transparent (no Shield) |
//! | [`ShieldOrchestratorError`] | Errors from slash/jail application |
//! | [`WithholdingSlashOutcome`] | Summary of a withholding slash batch |
//!
//! ## Dependency note (DB-12)
//!
//! Shield crypto is **pure** (`lemma-mempool::shield`). This module is the
//! orchestration layer: it decides *when* to run DKG vs reshare, maps
//! [`ShieldError`] variants to [`TransparentReason`] (never panics), and feeds
//! the withholder set into `lemma-consensus::slashing`. Consensus stays
//! crypto-free (AGENTS §8).
//!
//! ## Determinism (AGENTS §7.1)
//!
//! All collections use `BTreeMap`/`BTreeSet`. No `HashMap`/`HashSet`.
//! No `SystemTime`. No floats. Same inputs → same output on every node.
//!
//! ## Never panics
//!
//! [`run_epoch_shield`] returns [`EpochShieldOutcome`] (not `Result`) — any
//! crypto failure maps to `Transparent { reason }` with a `tracing::warn!`.
//! The chain continues in transparent mode rather than halting.

use std::collections::{BTreeMap, BTreeSet};

use ark_bls12_381::{G1Affine, G2Affine};
use tracing::warn;

use lemma_consensus::slashing::liveness::SHARE_WITHHOLDING_JAIL_DURATION_SECONDS;
use lemma_consensus::slashing::{jail::jail, slash, SlashError, SHARE_WITHHOLDING_SLASH_BPS};
use lemma_core::{
    address::Address, amount::Amount, validator::Validator, validator_set::ValidatorSet,
};
use lemma_mempool::shield::{
    committee::ShieldCommittee, facade::withholding_set, pvss::PvssTranscript, DkgOutput, Shield,
    ShieldError,
};

// ── EpochShieldOutcome ────────────────────────────────────────────────────────

/// Outcome of one epoch Shield round (DKG or reshare).
///
/// The node layer uses this to decide whether to publish an epoch key
/// (Active) or proceed without Shield encryption (Transparent).
///
/// `#[must_use]` — ignoring the outcome silently drops the epoch key or the
/// transparent-fallback reason, both of which must be acted on.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochShieldOutcome {
    /// DKG or reshare succeeded. The epoch threshold public key `Y` is ready.
    ///
    /// `withholders` is the set of committee members that failed to post a
    /// valid transcript — feed into [`apply_withholding_slashes`].
    Active {
        /// Epoch threshold public key `Y = F_0 ∈ 𝔾₁`.
        epoch_key: G1Affine,
        /// Committee members that failed to contribute a valid transcript.
        ///
        /// Empty when all members posted valid transcripts. Feed into
        /// [`apply_withholding_slashes`] to slash and jail non-contributors.
        withholders: BTreeSet<Address>,
    },

    /// DKG or reshare failed; the epoch proceeds without Shield encryption.
    ///
    /// Clients must fall back to plaintext submission for this epoch.
    Transparent {
        /// Why the epoch fell back to transparent mode.
        reason: TransparentReason,
    },
}

// ── TransparentReason ─────────────────────────────────────────────────────────

/// Why a Shield epoch fell back to transparent (no encryption) mode.
///
/// `#[non_exhaustive]` — future spec revisions may add new failure modes
/// without breaking existing match arms.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransparentReason {
    /// Valid transcripts did not reach the ⌈2/3·W⌉ quorum threshold.
    QuorumNotReached {
        /// Weight of valid transcripts received.
        have: u64,
        /// Quorum weight required (⌈2/3·W⌉).
        need: u64,
    },

    /// The validator set is too small to form a valid Shield committee (W < 4).
    CommitteeTooSmall {
        /// Total weight of the committee (< 4).
        have: u64,
    },

    /// A validator has zero weight (stake below `WEIGHT_GRANULARITY_DROP`).
    ZeroWeightValidator {
        /// The address of the zero-weight validator.
        address: Address,
    },

    /// The total committee weight exceeds the maximum domain size (W > u16::MAX).
    DomainTooLarge {
        /// The total weight that exceeded the limit.
        size: u64,
    },
}

// ── ShieldOrchestratorError ───────────────────────────────────────────────────

/// Errors from [`apply_withholding_slashes`].
///
/// `#[non_exhaustive]` — future variants may be added without breaking callers.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ShieldOrchestratorError {
    /// A slash or jail operation failed (arithmetic overflow or invalid fraction).
    #[error("slash failed: {0}")]
    Slash(#[from] SlashError),

    /// A withholder address was not found in the validators map.
    ///
    /// Indicates a caller bug: the withholder set must be a subset of the
    /// validators map. The address is included for diagnostic logging.
    #[error("withholder not found in validators map: {address}")]
    ValidatorNotFound {
        /// The withholder address that was missing.
        address: Address,
    },
}

// ── WithholdingSlashOutcome ───────────────────────────────────────────────────

/// Summary of a [`apply_withholding_slashes`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithholdingSlashOutcome {
    /// Total LEM burned across all slashed validators (sum of per-validator burns).
    ///
    /// The caller must reduce total supply by this amount (spec §5.1).
    pub total_burned: Amount,

    /// Number of validators that were slashed and jailed.
    pub slashed_count: usize,
}

// ── run_epoch_shield ──────────────────────────────────────────────────────────

/// Drive the Shield DKG (genesis) or reshare (N→N+1) for one epoch boundary.
///
/// ## Behaviour
///
/// - `prev_epoch_key.is_none()` → genesis / epoch-0: runs [`Shield::run_dkg`].
/// - `prev_epoch_key.is_some()` → epoch N→N+1: runs [`Shield::reshare`] with
///   the new committee, preserving `Y` invariant.
///
/// On success, computes the withholder set via [`withholding_set`] and returns
/// [`EpochShieldOutcome::Active`].
///
/// On any [`ShieldError`], maps to the appropriate [`TransparentReason`] and
/// returns [`EpochShieldOutcome::Transparent`] — **never panics, never returns
/// `Result`**. The chain continues in transparent mode.
///
/// ## Arguments
///
/// * `prev_epoch_key` — `None` for genesis DKG; `Some(Y)` for reshare.
/// * `next_vset` — the new epoch's validator set (used to build the committee).
/// * `posted` — dealer address → `(PvssTranscript, sig_ok)` (DB-7 injection).
/// * `eks` — validator-index → epoch public key `ek_i ∈ 𝔾₂`.
/// * `tau` — epoch label bytes (e.g. `b"epoch:1:dkg"`).
///
/// ## Determinism
///
/// Pure function of its inputs. No `SystemTime`. No randomness. Same inputs
/// → same output on every honest node (AGENTS §7.1).
pub fn run_epoch_shield(
    prev_epoch_key: Option<G1Affine>,
    next_vset: &ValidatorSet,
    posted: &BTreeMap<Address, (PvssTranscript, bool)>,
    eks: &BTreeMap<u16, G2Affine>,
    tau: &[u8],
) -> EpochShieldOutcome {
    // ── Build the new committee ───────────────────────────────────────────────
    let committee = match ShieldCommittee::from_validator_set(next_vset) {
        Ok(c) => c,
        Err(e) => {
            let reason = map_shield_error_to_transparent(e);
            warn!(
                ?reason,
                "Shield committee construction failed — epoch proceeds transparent"
            );
            return EpochShieldOutcome::Transparent { reason };
        }
    };

    // ── Build the Shield handle ───────────────────────────────────────────────
    let shield = match Shield::new(committee.clone()) {
        Ok(s) => s,
        Err(e) => {
            let reason = map_shield_error_to_transparent(e);
            warn!(
                ?reason,
                "Shield handle construction failed — epoch proceeds transparent"
            );
            return EpochShieldOutcome::Transparent { reason };
        }
    };

    // ── Run DKG or reshare ────────────────────────────────────────────────────
    let dkg_out: DkgOutput = match prev_epoch_key {
        None => {
            // Genesis / epoch-0: fresh DKG.
            match shield.run_dkg(posted, eks, tau) {
                Ok(out) => out,
                Err(e) => {
                    let reason = map_shield_error_to_transparent(e);
                    warn!(?reason, "Shield DKG failed — epoch proceeds transparent");
                    return EpochShieldOutcome::Transparent { reason };
                }
            }
        }
        Some(_prev_y) => {
            // Epoch N→N+1: reshare.
            //
            // Phase-1 simplification: there is no validator rotation in Phase 1, so
            // the old committee (dealers) == the new committee (targets). We build
            // `shield` from `next_vset` (the new committee) and pass the same
            // `committee` as the `new_committee` arg. `Shield::reshare` only reads
            // `new_committee.weight_of` / `eks_new` for quorum + transcript
            // verification — it never consults `self.committee` for reshare math
            // (facade.rs §5) — so old == new is functionally correct in Phase 1.
            //
            // TODO(shield/phase2): when validators rotate, the OLD epoch's Shield
            // handle (carrying the old committee's share context) must be threaded
            // in. The current `prev_epoch_key: Option<G1Affine>` parameter is the
            // key `Y` only — insufficient for a cross-committee reshare. The
            // signature must be extended to pass the old `ShieldCommittee` (or the
            // full old `Shield` handle) from the previous epoch's outcome.
            // Deferred: no validator rotation until Phase 2 DAG consensus.
            // See living-notes Technical Debt: "Phase-2 reshare old-committee threading".
            match shield.reshare(&committee, posted, eks, tau) {
                Ok(out) => out,
                Err(e) => {
                    let reason = map_shield_error_to_transparent(e);
                    warn!(
                        ?reason,
                        "Shield reshare failed — epoch proceeds transparent"
                    );
                    return EpochShieldOutcome::Transparent { reason };
                }
            }
        }
    };

    // ── Compute withholder set (Duty A — §4.6 dealer duty) ───────────────────
    let withholders = withholding_set(&committee, posted, &dkg_out);

    EpochShieldOutcome::Active {
        epoch_key: dkg_out.y,
        withholders,
    }
}

// ── apply_withholding_slashes ─────────────────────────────────────────────────

/// Slash and jail each validator in `withholders` for share-withholding (spec §5.4).
///
/// For each withholder:
/// 1. Looks up the validator in `validators` — returns
///    [`ShieldOrchestratorError::ValidatorNotFound`] if missing.
/// 2. Calls [`slash`] with [`SHARE_WITHHOLDING_SLASH_BPS`] (10%) and the
///    injected `powers[addr]` as the infraction-height voting power.
/// 3. Calls [`jail`] with `until_time = block_time + DOWNTIME_JAIL_DURATION_SECONDS`
///    (finite jail — NOT tombstone; share-withholding is a liveness fault).
///
/// Returns the total LEM burned and the count of slashed validators.
///
/// ## Power injection (B3-1)
///
/// `powers` carries the infraction-epoch voting power snapshot (CometBFT model).
/// If a withholder is absent from `powers`, its power defaults to `Amount::zero()`
/// (zero slash, still jailed — conservative: jail without burn rather than error).
///
/// ## Atomicity
///
/// Each validator is slashed and jailed independently. A `SlashError` on one
/// validator propagates immediately — validators processed before the error
/// retain their mutations. The caller should treat this as a fatal node error
/// and halt rather than continue with a partially-applied slash batch.
///
/// The partial `total_burned` accrued before the error is **discarded** (the
/// `?` operator returns `Err` without the partial sum). The caller must NOT
/// apply any supply reduction from this call unless it returns `Ok` — supply
/// reduction is all-or-nothing (applied only on the returned `total_burned`).
///
/// # Errors
///
/// - [`ShieldOrchestratorError::ValidatorNotFound`] — withholder not in `validators`.
/// - [`ShieldOrchestratorError::Slash`] — arithmetic overflow in [`slash`].
pub fn apply_withholding_slashes(
    validators: &mut BTreeMap<Address, Validator>,
    withholders: &BTreeSet<Address>,
    powers: &BTreeMap<Address, Amount>,
    infraction_height: u64,
    block_time: u64,
) -> Result<WithholdingSlashOutcome, ShieldOrchestratorError> {
    let mut total_burned = Amount::zero();
    let mut slashed_count: usize = 0;

    // Iterate in canonical BTreeSet order (deterministic — AGENTS §7.1).
    for addr in withholders {
        let validator = validators
            .get_mut(addr)
            .ok_or(ShieldOrchestratorError::ValidatorNotFound { address: *addr })?;

        // Injected power (B3-1): use provided power or zero if absent.
        let power = powers.get(addr).copied().unwrap_or_else(Amount::zero);

        // Step 1: slash (10% of infraction-epoch voting power).
        let burned = slash(
            validator,
            infraction_height,
            power,
            SHARE_WITHHOLDING_SLASH_BPS,
        )?;

        // Step 2: jail (finite — NOT tombstone; share-withholding is liveness, not safety).
        // `until_time` is an absolute consensus timestamp (AGENTS §7.1 — never SystemTime).
        // Uses SHARE_WITHHOLDING_JAIL_DURATION_SECONDS (13 §5.4 "finite jail, one epoch").
        let until_time = block_time.saturating_add(SHARE_WITHHOLDING_JAIL_DURATION_SECONDS);
        jail(validator, until_time);

        // Accumulate total burned (checked — AGENTS §7.4).
        total_burned = total_burned
            .checked_add(burned)
            .map_err(|e| SlashError::ApplyOverflow {
                address: *addr,
                source: e,
            })?;

        slashed_count = slashed_count.saturating_add(1);
    }

    Ok(WithholdingSlashOutcome {
        total_burned,
        slashed_count,
    })
}

// ── map_shield_error_to_transparent ──────────────────────────────────────────

/// Map a [`ShieldError`] to the appropriate [`TransparentReason`].
///
/// Called on any crypto failure in [`run_epoch_shield`] to produce a
/// `Transparent` outcome without panicking. Unmapped variants (e.g. AEAD
/// failures, which cannot occur in DKG/reshare paths) fall through to
/// `QuorumNotReached { have: 0, need: 1 }` as a safe conservative default.
fn map_shield_error_to_transparent(e: ShieldError) -> TransparentReason {
    match e {
        ShieldError::DkgQuorumNotReached { have, need } => {
            TransparentReason::QuorumNotReached { have, need }
        }
        ShieldError::CommitteeTooSmall { have } => TransparentReason::CommitteeTooSmall { have },
        ShieldError::ZeroWeightValidator(address) => {
            TransparentReason::ZeroWeightValidator { address }
        }
        ShieldError::DomainTooLarge { size } => TransparentReason::DomainTooLarge { size },
        // All other ShieldError variants (AEAD, pairing, etc.) are unreachable
        // on the DKG/reshare path. Map conservatively to QuorumNotReached(0,1)
        // so the epoch proceeds transparent rather than panicking.
        other => {
            warn!(error = ?other, "unexpected ShieldError on DKG/reshare path — transparent fallback");
            TransparentReason::QuorumNotReached { have: 0, need: 1 }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
