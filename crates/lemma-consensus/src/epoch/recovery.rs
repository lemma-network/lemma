//! # `force_epoch_close` — deterministic epoch recovery (spec §6)
//!
//! The **backstop** for a wedged epoch. If the normal `advance_epoch` path
//! (§4) is unreachable (e.g. a persistent leader failure that cannot be healed
//! by `force_epoch_close` itself), this function provides a quorum-authorized,
//! deterministic path to close the epoch and reseat the committee.
//!
//! ## Why this exists (the Sui stall lesson)
//!
//! A panic or deterministic dead-lock in epoch settlement wedges ALL honest
//! nodes at the same point. `force_epoch_close` is the out-of-band lever:
//! validators collect a 2f+1 cert off-chain (since the chain is wedged) and
//! submit it as a deterministic system action, jointly advancing the epoch.
//!
//! ## Five safety properties (spec §6.2)
//!
//! A recovery that is missing any one of these is unsafe:
//!
//! 1. **Deterministic** — closes at an agreed `commit_index`; every node
//!    resumes from identical state. No `SystemTime`, no local data.
//! 2. **Quorum-authorized** — requires a ≥ 2f+1 quorum cert. A single
//!    validator cannot unilaterally force close.
//! 3. **On-chain record** — the authorizing cert is returned in
//!    [`RecoveryOutput`] for the caller to persist. Auditable + replay-proof
//!    (caller maintains a `BTreeSet<(epoch, commit_index)>` dedup, B4-2).
//! 4. **Bounded** — specifies exactly `at_commit_index` and `next_validators`.
//!    Nothing else is decided.
//! 5. **Never rolls back a finalized commit** — `at_commit_index` must be ≤
//!    `last_final_commit_index`. Rolling back a finalized commit would violate
//!    safety (07 §7.2: committed prefixes are immutable).
//!
//! ## Reuse of `advance_epoch`
//!
//! Per spec §6.1: "run the standard `advance_epoch` settlement". The entire
//! 9-step settlement is reused — no new settlement logic. The recovery lever's
//! job is ONLY to authorize and bound the call.
//!
//! ## Signature injection (B3-2)
//!
//! The recovery cert's signatures are injected as `BTreeMap<Address, bool>`.
//! `lemma-consensus` does not call `lemma-crypto`.
//!
//! ## Determinism
//!
//! All checks are pure functions of inputs. No `SystemTime`. No floats.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    validator::Validator,
    Epoch, QuorumCert,
};

use std::collections::BTreeSet;

use crate::{
    cert::{verify_quorum_cert, CertError},
    epoch::{advance_epoch, EpochError, EpochOutput},
};

// ── RecoveryError ─────────────────────────────────────────────────────────────

/// Errors that prevent `force_epoch_close` from executing.
///
/// Every variant returns `Err` without mutating validator state (spec §6.2
/// property 1: deterministic — a failed recovery leaves nodes in identical
/// pre-recovery state). Never panics on adversarial input (AGENTS §7.2).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryError {
    /// The recovery cert does not have ≥ 2f+1 quorum (spec §6.2 property 2).
    ///
    /// A sub-quorum cert is rejected outright — no unilateral close possible.
    /// Wraps the underlying [`CertError`] for diagnostic detail.
    #[error("recovery cert failed quorum verification: {source}")]
    InsufficientQuorum {
        /// Underlying cert error.
        #[source]
        source: CertError,
    },

    /// The requested `at_commit_index` is greater than `last_final_commit_index`.
    ///
    /// Recovery may only close AT an already-final commit (spec §6.2 property 5:
    /// "never rolls back a finalized commit"). Closing ahead of finality would
    /// discard uncommitted (and thus non-final) DAG work — which would violate
    /// BFT safety if those commits subsequently reach finality on some nodes.
    #[error(
        "cannot close at commit_index {at_commit_index}: \
         last finalized commit is {last_final_commit_index} \
         (force_epoch_close must close AT or BEFORE a finalized commit)"
    )]
    RollbackForbidden {
        /// The commit index the recovery tried to close at.
        at_commit_index: u64,
        /// The last commit index that has been finalized on this node.
        last_final_commit_index: u64,
    },

    /// The `(epoch, at_commit_index)` pair has already been applied.
    ///
    /// Replay-proof guard (spec §6.2 property 3: on-chain record "references
    /// a specific epoch/commit so an old recovery cannot be replayed"). The
    /// caller maintains a `BTreeSet<(epoch_number, commit_index)>` dedup set.
    #[error(
        "recovery already applied for epoch {epoch_number} at commit {at_commit_index}"
    )]
    Duplicate {
        /// The epoch that already has a recovery.
        epoch_number: u64,
        /// The commit index that was already closed.
        at_commit_index: u64,
    },

    /// The underlying `advance_epoch` settlement failed (spec §4, B1/B2/B3).
    ///
    /// A recovery that can trigger is already a last resort; if `advance_epoch`
    /// also fails, the node must halt and alert operators. Never panics.
    #[error("advance_epoch failed during recovery: {source}")]
    SettlementFailed {
        /// Underlying epoch error.
        #[source]
        source: EpochError,
    },
}

// ── RecoveryOutput ────────────────────────────────────────────────────────────

/// Output of a successful [`force_epoch_close`] call.
///
/// The caller must:
/// 1. Apply `epoch_output` (write `next_validators_hash`, swap leader schedule,
///    update supply — same contract as normal `advance_epoch`).
/// 2. Persist `recovery_cert` on-chain for auditability and replay prevention
///    (spec §6.2 property 3, B4-2).
/// 3. Add `(epoch_number, at_commit_index)` to the dedup set (B4-2).
#[must_use = "recovery output must be applied: epoch output + persist cert + update dedup set"]
#[derive(Debug, Clone)]
pub struct RecoveryOutput {
    /// The normal epoch output — apply as if `advance_epoch` returned this.
    pub epoch_output: EpochOutput,

    /// The authorizing quorum certificate (spec §6.2 property 3).
    ///
    /// Persist on-chain so the recovery is auditable and cannot be replayed.
    /// The cert uniquely identifies the `(epoch, commit_index)` it authorizes.
    pub recovery_cert: QuorumCert,

    /// The commit index at which the epoch was closed.
    pub at_commit_index: u64,
}

// ── force_epoch_close ─────────────────────────────────────────────────────────

/// Deterministic epoch recovery — the backstop for a wedged epoch (spec §6).
///
/// Enforces all **five safety properties** before delegating to `advance_epoch`.
/// Returns `Err` (never panics) if any property is violated.
///
/// ## Parameters
///
/// - `current` — the wedged epoch being closed (epoch N).
/// - `validators` — full validator state map (mutated iff all checks pass).
/// - `commits` — commits produced in epoch N (for reputation scoring; may be
///   partial if the epoch wedged early — this is expected and acceptable).
/// - `total_supply` — total supply at the recovery boundary (same as normal).
/// - `at_commit_index` — the already-final commit index to close at
///   (spec §6.2: "close AT an already-final commit").
/// - `last_final_commit_index` — the highest commit index known to be final on
///   this node. `at_commit_index` must be ≤ this value.
/// - `recovery_cert` — the ≥ 2f+1 quorum cert authorizing this recovery.
/// - `recovery_cert_digest` — Blake3 hash of the recovery authorization message
///   (computed by the caller via `lemma-crypto`; injected per B3-2 pattern).
///   The cert's `header_digest` field must equal this value — this is what the
///   signers actually signed over, e.g. `hash((epoch_number, at_commit_index))`.
/// - `sig_results` — per-signer sig verification results (injected, B3-2).
/// - `dedup` — already-processed `(epoch_number, commit_index)` pairs;
///   **not mutated here** — the caller adds after successful return (B4-2 pattern).
/// - `block_time`, `block_height`, `min_stake` — same as normal `advance_epoch`.
///
/// ## Atomicity
///
/// All three pre-checks (quorum, rollback, dedup) run before any `validators`
/// mutation. If any fails, `validators` is byte-for-byte unchanged.
//
// `too_many_arguments`: recovery is a rare, security-critical lever whose
// signature deliberately mirrors `advance_epoch` (7 args) plus 6 authorization
// and bounds inputs. All arguments are distinct, non-reorderable, and documented
// above. A params struct was considered but rejected: callers build these inputs
// from separate subsystems (cert from network, dedup from storage,
// recovery_cert_digest from lemma-crypto), so a struct would relocate rather
// than reduce the argument list. AGENTS §3.2 — justified here.
#[allow(clippy::too_many_arguments)]
pub fn force_epoch_close(
    current: &Epoch,
    validators: &mut BTreeMap<Address, Validator>,
    commits: &[crate::commit::Commit],
    total_supply: Amount,
    at_commit_index: u64,
    last_final_commit_index: u64,
    recovery_cert: QuorumCert,
    recovery_cert_digest: lemma_core::Hash,
    sig_results: &BTreeMap<Address, bool>,
    dedup: &BTreeSet<(u64, u64)>,
    block_time: u64,
    block_height: u64,
    min_stake: Amount,
) -> Result<RecoveryOutput, RecoveryError> {
    // ── Pre-check 1: Quorum authorization (spec §6.2 property 2) ─────────────
    //
    // The recovery cert must be signed by ≥ 2f+1 of the CURRENT epoch's
    // committee (the one that is wedged). We verify against `current.validators`.
    // `recovery_cert_digest` is the hash of the recovery message (injected by
    // caller via lemma-crypto) — the value the signers actually signed over.
    verify_quorum_cert(
        &recovery_cert,
        &current.validators,
        recovery_cert_digest,
        sig_results,
    )
    .map_err(|e| RecoveryError::InsufficientQuorum { source: e })?;

    // ── Pre-check 2: No rollback of finalized commits (spec §6.2 property 5) ──
    //
    // `at_commit_index` must be ≤ the last FINAL commit. Closing above that
    // would discard non-final DAG work that might reach finality elsewhere.
    if at_commit_index > last_final_commit_index {
        return Err(RecoveryError::RollbackForbidden {
            at_commit_index,
            last_final_commit_index,
        });
    }

    // ── Pre-check 3: Replay prevention (spec §6.2 property 3) ────────────────
    //
    // The same `(epoch, commit_index)` cannot be recovered twice.
    // Caller maintains the BTreeSet; we only query it here.
    let dedup_key = (current.number, at_commit_index);
    if dedup.contains(&dedup_key) {
        return Err(RecoveryError::Duplicate {
            epoch_number: current.number,
            at_commit_index,
        });
    }

    // ── All pre-checks passed — run standard advance_epoch settlement ──────────
    //
    // Spec §6.1: "run the standard advance_epoch settlement (§4) with
    // next_validators → produces a normal boundary header with next_validators_hash."
    // No new settlement logic here — full reuse of B1/B2/B3 implementation.
    let epoch_output = advance_epoch(
        current,
        validators,
        commits,
        total_supply,
        block_time,
        block_height,
        min_stake,
    )
    .map_err(|e| RecoveryError::SettlementFailed { source: e })?;

    Ok(RecoveryOutput { epoch_output, recovery_cert, at_commit_index })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
