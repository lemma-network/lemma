//! # Double-sign evidence + verification (spec §5.2)
//!
//! Implements `docs/13-VALIDATOR_EPOCH_SPEC §5.2`:
//! `DoubleSignEvidence` (CometBFT `DuplicateVoteEvidence` shape) + five-step
//! verification + `apply_double_sign` which calls `slash` + `tombstone`.
//!
//! ## Signature injection (B3-2)
//!
//! Signature verification is injected as `sig_a_ok: bool` / `sig_b_ok: bool`
//! — the same pattern as `dag::graph` (decisions-log "Decision 4a"). This
//! keeps `lemma-consensus` free of a `lemma-crypto` dependency. The node
//! binary performs the hybrid Ed25519+ML-DSA verification and passes the
//! result; tests can probe both the valid and invalid paths.
//!
//! ## Deduplication
//!
//! The caller maintains a committed-evidence dedup set (any ordered or hash
//! set of `(validator, infraction_height)` pairs). `verify_double_sign`
//! checks membership; the caller adds the key after `apply_double_sign`
//! succeeds. This module does not own the dedup set — it is external state
//! managed by the node's evidence processor.
//!
//! ## Atomicity
//!
//! `apply_double_sign` first calls `slash` (compute-then-commit atomic), then
//! `tombstone`. If `slash` returns `Err`, `tombstone` is NOT called and the
//! validator is unchanged. If `slash` succeeds, `tombstone` is infallible.
//!
//! ## Determinism
//!
//! All verification predicates are pure functions of their inputs: digest
//! comparison, slot equality, age check, set-membership. No `SystemTime`.
//! No floats. Two nodes given identical evidence + identical state produce
//! identical outcomes.

use serde::{Deserialize, Serialize};

use lemma_core::{
    address::Address, amount::Amount, validator::Validator, validator_set::ValidatorSet,
};

use super::{jail::tombstone, slash, SlashError, DOUBLE_SIGN_SLASH_BPS, EVIDENCE_MAX_AGE_SECONDS};
use crate::dag::block::DagBlockRef;

// ── DoubleSignEvidence ────────────────────────────────────────────────────────

/// Evidence of a double-sign (equivocation) offense (spec §5.2).
///
/// Shaped after CometBFT `DuplicateVoteEvidence`: two conflicting signed
/// references to the same slot `(round, author)` but with different digests.
///
/// ## Field notes
///
/// - `vote_a` and `vote_b` MUST share the same `(round, author)` slot.
/// - `vote_a.digest ≠ vote_b.digest` — two different blocks at the same slot.
/// - `validator_power` and `total_power` are inline snapshots of the committee
///   state at `infraction_height` (B3-1: inline evidence power, no historical
///   store required in v1). Phase 3 cross-validates against a historical
///   ValidatorSet store.
/// - `infraction_time` is `block.time` (consensus seconds) — never walltime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoubleSignEvidence {
    /// First conflicting block reference at the equivocated slot.
    pub vote_a: DagBlockRef,
    /// Second conflicting block reference — same slot, different digest.
    pub vote_b: DagBlockRef,
    /// Block height at which the equivocation occurred.
    ///
    /// `vote_a.round == vote_b.round` and both map to this height.
    pub infraction_height: u64,
    /// Consensus `block.time` (seconds) at the infraction height.
    ///
    /// Used for evidence-age checking (spec §5.3). Never set from `SystemTime`.
    pub infraction_time: u64,
    /// The validator accused of equivocation.
    pub validator: Address,
    /// The accused validator's voting power **at `infraction_height`** (inline snapshot, B3-1).
    pub validator_power: Amount,
    /// Total committee voting power at `infraction_height` (inline snapshot).
    ///
    /// Retained for future committee-level checks; not used by v1 verify logic.
    pub total_power: Amount,
}

// ── EvidenceError ─────────────────────────────────────────────────────────────

/// Errors that cause evidence to be **rejected** (no slash applied).
///
/// All rejection paths return `Err` without mutating validator state.
/// Never panics on adversarial inputs (AGENTS.md §7.2).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvidenceError {
    /// `vote_a` and `vote_b` are at different slots (different round or author).
    ///
    /// Both votes must be from the SAME `(round, author)` to constitute
    /// equivocation. Mismatched slots indicate malformed evidence.
    #[error(
        "evidence votes are at different slots: \
         vote_a=(round={}, author={}), vote_b=(round={}, author={})",
        .vote_a_round, .vote_a_author, .vote_b_round, .vote_b_author
    )]
    SlotMismatch {
        vote_a_round: u64,
        vote_a_author: Address,
        vote_b_round: u64,
        vote_b_author: Address,
    },

    /// `vote_a` and `vote_b` have identical digests — not an equivocation.
    ///
    /// Two identical blocks are gossip duplicates, not conflicting proposals.
    #[error("evidence votes have the same digest — not an equivocation")]
    IdenticalDigests,

    /// One or both signatures failed verification (hybrid Ed25519 + ML-DSA).
    ///
    /// `sig_a_ok` / `sig_b_ok` are injected by the caller (B3-2). If either
    /// is `false`, the evidence is unsigned or forged — rejected.
    #[error("evidence signature verification failed: sig_a_ok={sig_a_ok}, sig_b_ok={sig_b_ok}")]
    InvalidSignature { sig_a_ok: bool, sig_b_ok: bool },

    /// The accused validator was not in the committee at `infraction_height`.
    ///
    /// In v1, this checks the **current** `vset` (passed by the caller). A
    /// non-member cannot have committed equivocation within that committee.
    #[error(
        "validator {validator} not found in committee at infraction height {infraction_height}"
    )]
    NotInCommittee {
        validator: Address,
        infraction_height: u64,
    },

    /// Evidence is older than [`EVIDENCE_MAX_AGE_SECONDS`] (14 days, spec §5.3).
    ///
    /// Stale evidence is rejected to prevent slashing after unbonding stake
    /// has matured into `inactive` (which is untouchable).
    #[error(
        "evidence expired: infraction_time={infraction_time}, current_time={current_time}, \
         max_age={EVIDENCE_MAX_AGE_SECONDS}s"
    )]
    Expired {
        infraction_time: u64,
        current_time: u64,
    },

    /// Evidence has already been processed (dedup check, spec §5.2 check 5).
    ///
    /// Prevents double-jeopardy: the same equivocation cannot be slashed twice
    /// even if submitted again.
    #[error("evidence already processed for validator {validator} at height {infraction_height}")]
    Duplicate {
        validator: Address,
        infraction_height: u64,
    },

    /// Slashing arithmetic failed (wraps [`SlashError`]).
    #[error("slash failed: {0}")]
    SlashFailed(#[from] SlashError),
}

// ── verify_double_sign ────────────────────────────────────────────────────────

/// Verify a [`DoubleSignEvidence`] against the five spec §5.2 predicates.
///
/// All five checks must pass; the first failure returns `Err` without applying
/// any slash. Never panics on crafted/adversarial evidence (AGENTS.md §7.2).
///
/// ## Checks (spec §5.2)
///
/// 1. `vote_a` and `vote_b` are at the **same slot** (round + author) but
///    **different digests** (two distinct conflicting proposals).
/// 2. Both signatures are valid (`sig_a_ok && sig_b_ok`, injected by caller — B3-2).
/// 3. The accused validator is **in the current committee** (`vset`).
/// 4. Evidence age: `current_time - infraction_time < EVIDENCE_MAX_AGE_SECONDS`.
/// 5. Evidence is **not already in `dedup`** (uniqueness by `(validator, infraction_height)`).
///
/// ## Parameters
///
/// - `evidence` — the evidence to verify.
/// - `vset` — the current (or relevant epoch's) validator set for committee membership.
/// - `sig_a_ok`, `sig_b_ok` — results of hybrid Ed25519+ML-DSA verification
///   performed by the caller (B3-2: signature injection pattern).
/// - `current_time` — consensus `block.time` of the block that includes the evidence.
/// - `dedup` — already-processed `(validator, infraction_height)` pairs;
///   checked but not modified here (caller adds the key after `apply_double_sign`).
pub fn verify_double_sign(
    evidence: &DoubleSignEvidence,
    vset: &ValidatorSet,
    sig_a_ok: bool,
    sig_b_ok: bool,
    current_time: u64,
    dedup: &std::collections::BTreeSet<(Address, u64)>,
) -> Result<(), EvidenceError> {
    // ── Check 1: Same slot (round + author), different digest ─────────────────
    if evidence.vote_a.round != evidence.vote_b.round
        || evidence.vote_a.author != evidence.vote_b.author
    {
        return Err(EvidenceError::SlotMismatch {
            vote_a_round: evidence.vote_a.round,
            vote_a_author: evidence.vote_a.author,
            vote_b_round: evidence.vote_b.round,
            vote_b_author: evidence.vote_b.author,
        });
    }
    if evidence.vote_a.digest == evidence.vote_b.digest {
        return Err(EvidenceError::IdenticalDigests);
    }

    // ── Check 2: Both signatures valid ────────────────────────────────────────
    if !sig_a_ok || !sig_b_ok {
        return Err(EvidenceError::InvalidSignature { sig_a_ok, sig_b_ok });
    }

    // ── Check 3: Validator in committee ───────────────────────────────────────
    if !vset.members.contains_key(&evidence.validator) {
        return Err(EvidenceError::NotInCommittee {
            validator: evidence.validator,
            infraction_height: evidence.infraction_height,
        });
    }

    // ── Check 4: Evidence age (spec §5.3) ────────────────────────────────────
    //
    // `current_time.saturating_sub` avoids underflow if current_time < infraction_time
    // (clock skew / adversarial input). Saturating to 0 means age = 0 → passes.
    let age = current_time.saturating_sub(evidence.infraction_time);
    if age >= EVIDENCE_MAX_AGE_SECONDS {
        return Err(EvidenceError::Expired {
            infraction_time: evidence.infraction_time,
            current_time,
        });
    }

    // ── Check 5: Not already processed (dedup) ────────────────────────────────
    let key = (evidence.validator, evidence.infraction_height);
    if dedup.contains(&key) {
        return Err(EvidenceError::Duplicate {
            validator: evidence.validator,
            infraction_height: evidence.infraction_height,
        });
    }

    Ok(())
}

// ── apply_double_sign ─────────────────────────────────────────────────────────

/// Apply a verified [`DoubleSignEvidence`]: slash 5% and tombstone the validator.
///
/// Call [`verify_double_sign`] first. This function does NOT re-verify —
/// it assumes evidence has passed all five checks.
///
/// ## Effects (spec §5.2)
///
/// 1. Slash **5%** of `evidence.validator_power` from `validator.self_stake`
///    (active first, then post-infraction `pending_inactive` entries).
/// 2. **Tombstone** the validator — permanently banned from re-bonding.
///
/// Returns the total amount burned (caller reduces total supply).
///
/// ## Atomicity
///
/// `slash` uses compute-then-commit internally — if it fails, `validator` is
/// unchanged and `tombstone` is NOT called. Once `slash` succeeds, `tombstone`
/// is infallible.
///
/// # Errors
///
/// [`EvidenceError::SlashFailed`] if the underlying `slash()` fails
/// (practically unreachable for valid evidence; see [`SlashError`] variants).
pub fn apply_double_sign(
    validator: &mut Validator,
    evidence: &DoubleSignEvidence,
) -> Result<Amount, EvidenceError> {
    // Slash 5% of infraction-height power (injected from evidence, B3-1).
    let burned = slash(
        validator,
        evidence.infraction_height,
        evidence.validator_power,
        DOUBLE_SIGN_SLASH_BPS,
    )?;
    // Tombstone: permanent ban. Infallible after successful slash.
    tombstone(validator);
    Ok(burned)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
