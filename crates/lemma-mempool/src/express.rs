//! Express fast-path eligibility for `lemma-mempool`.
//!
//! Lemma's **Express** layer maps to Mysticeti-FPC (07-CONSENSUS_SPEC §10):
//! transactions proven by the Lem compiler to touch **owned state only**
//! (writes keyed by `msg.sender`, no shared-state reads, not `#[private]`)
//! can be fast-finalized via 2f+1 quorum votes, skipping the full three-round
//! Pulse commit.
//!
//! # This module's scope
//!
//! `express.rs` answers one question: **is this transaction eligible for the
//! Express path?** It classifies, it does not route or vote. The pool (`pool.rs`)
//! and the consensus layer (`lemma-consensus`) act on the classification.
//!
//! # Phase 1 design — injected hint
//!
//! The Lem compiler and SAFETY analyzer (09-SAFETY_ANALYZER_SPEC) are Phase 3
//! deliverables. In Phase 1, the per-function state-access hint is **injected
//! by the caller** as an [`ExpressHint`] rather than derived from compiled
//! contract metadata. This follows the dependency-injection pattern used across
//! all mempool modules for testability.
//!
//! When the compiler ships in Phase 3, it will construct and pass `ExpressHint`
//! values — the `classify` API is unchanged. The call-site changes, not the
//! eligibility logic.
//!
//! # Conservative default — assume conflict
//!
//! Per 08-EXECUTION_SPEC §1.7: *"hints are an optimization, never a correctness
//! input — a wrong/missing hint only costs re-execution; the MV validation still
//! guarantees the serial result. Conservative default: assume conflict."*
//!
//! `classify` therefore returns [`ExpressEligibility::Fallback`] on any doubt:
//! - `hint` is `None` → [`FallbackReason::MissingHint`]
//! - hint says `is_express_eligible: false` → [`FallbackReason::NotCompilerEligible`]
//! - hint says `reads_shared_state: true` → [`FallbackReason::SharedStateRead`]
//! - hint says `is_private: true` → [`FallbackReason::PrivateTx`]
//! - `TxType` not on the owned-state allow-list → [`FallbackReason::IneligibleTxType`]
//!
//! # v1 sequencing note
//!
//! v1 mainnet MAY ship with Express disabled (base Pulse only) pending an
//! independent audit of the owned-state proof and FPC vote-tracking
//! (07-CONSENSUS_SPEC §10). The classification logic is exercised by the test
//! suite from day one so that enabling Express later requires only a pool-level
//! flag change, not a code change here.
//!
//! # References
//!
//! - `docs/07-CONSENSUS_SPEC.md §10` — Express ↔ Mysticeti-FPC safety boundary
//! - `docs/08-EXECUTION_SPEC.md §1.7` — compiler-assisted scheduling, hint contract
//! - `docs/09-SAFETY_ANALYZER_SPEC.md` — where `is_express_eligible` originates
//! - `docs/11-MEMPOOL_SHIELD_SPEC.md` line 195 — express.rs mandate

use lemma_core::transaction::TxType;

// ── ExpressHint ───────────────────────────────────────────────────────────────

/// Compiler-provided state-access metadata for a transaction.
///
/// In Phase 3, the Lem compiler emits this per-function (09-SAFETY_ANALYZER_SPEC).
/// In Phase 1, callers construct it manually; the API is identical so the pool
/// and tests exercise the full eligibility logic from day one.
///
/// # Conservative construction
///
/// When metadata is unavailable or uncertain, pass `None` to [`classify`] rather
/// than constructing an optimistic `ExpressHint`. The `None` path returns
/// [`FallbackReason::MissingHint`] — the conservative-default path defined in
/// 08-EXECUTION_SPEC §1.7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpressHint {
    /// The Lem compiler's own Express eligibility flag.
    ///
    /// `true` iff the compiler proved that all state writes in this function are
    /// keyed by `msg.sender` and no shared-state reads occur. The disqualifier
    /// fields below are also checked independently for defence-in-depth.
    pub is_express_eligible: bool,

    /// `true` if the function reads from any shared (non-owned) storage slot.
    ///
    /// Shared reads create potential conflicts with other senders and disqualify
    /// the transaction from the Express path (07-CONSENSUS_SPEC §10).
    pub reads_shared_state: bool,

    /// `true` if the function is annotated `#[private]` (Veil shielded).
    ///
    /// Private transactions must flow through the Shield threshold-encryption
    /// path, not the Express fast path.
    pub is_private: bool,
}

impl ExpressHint {
    /// Construct an `ExpressHint` from its constituent parts.
    ///
    /// # Arguments
    ///
    /// * `is_express_eligible` — compiler-proven owned-state-only flag.
    /// * `reads_shared_state` — `true` if the function reads shared storage.
    /// * `is_private` — `true` if the function is `#[private]`/Veil shielded.
    #[must_use]
    pub fn new(is_express_eligible: bool, reads_shared_state: bool, is_private: bool) -> Self {
        Self {
            is_express_eligible,
            reads_shared_state,
            is_private,
        }
    }

    /// Convenience constructor for a fully-eligible hint.
    ///
    /// Produces `ExpressHint { is_express_eligible: true, reads_shared_state: false,
    /// is_private: false }`. Useful in tests and as a starting point.
    #[must_use]
    pub fn eligible() -> Self {
        Self::new(true, false, false)
    }
}

// ── FallbackReason ────────────────────────────────────────────────────────────

/// The reason a transaction was classified as ineligible for the Express path.
///
/// Ineligible is not an error — the transaction is simply routed to the base
/// Pulse ordering. `FallbackReason` is diagnostic information for logging and
/// metrics.
///
/// # `#[non_exhaustive]`
///
/// Future disqualifiers (e.g. cross-shard reads, MEV-sensitive patterns) will
/// add variants without breaking existing `match` arms.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackReason {
    /// No compiler hint was supplied.
    ///
    /// Conservative default: without proof, assume conflict and fall back to
    /// base Pulse ordering (08-EXECUTION_SPEC §1.7).
    MissingHint,

    /// The compiler did not mark this function Express-eligible
    /// (`is_express_eligible: false`).
    ///
    /// The compiler's own analysis found shared-state access, non-owned writes,
    /// or another disqualifying pattern not captured by the other fields.
    NotCompilerEligible,

    /// The function reads from shared (non-owned) storage.
    ///
    /// Shared reads create potential conflicts with other senders and violate
    /// the safety boundary of 07-CONSENSUS_SPEC §10.
    SharedStateRead,

    /// The function is annotated `#[private]` (Veil shielded).
    ///
    /// Private transactions travel via the Shield threshold-encryption path.
    PrivateTx,

    /// The `TxType` is structurally incapable of being owned-state-only.
    ///
    /// Only [`TxType::Transfer`] is on the Phase 1 allow-list. All other types
    /// either touch shared state (validator set, contract storage, governance
    /// contract) or have a structural reason that precludes owned-state proof.
    ///
    /// # Phase 1 allow-list rationale
    ///
    /// | TxType          | Why ineligible                                                    |
    /// |-----------------|-------------------------------------------------------------------|
    /// | `ContractCall`  | May read/write shared contract storage (unknown at mempool time). |
    /// | `ContractDeploy`| Creates a new shared contract account.                            |
    /// | `Stake`         | Writes the shared validator-set state.                            |
    /// | `Unstake`       | Writes the shared validator-set state.                            |
    /// | `GovernanceVote`| Writes the shared governance system-contract state.               |
    ///
    /// When the Lem compiler ships (Phase 3) with proven owned-state analysis,
    /// `ContractCall` can graduate to the allow-list for eligible functions.
    IneligibleTxType,
}

// ── ExpressEligibility ────────────────────────────────────────────────────────

/// Result of classifying a transaction for the Express fast path.
///
/// `Eligible` means the transaction *may* be submitted to the Express path
/// if the pool has Express enabled. `Fallback` means it must be routed to the
/// base Pulse ordering.
///
/// Ineligibility is not an error. The distinction affects latency only:
/// Express-eligible transactions may finalize faster.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpressEligibility {
    /// The transaction is eligible for the Express fast path.
    ///
    /// All conditions are satisfied: the `TxType` is on the allow-list, the
    /// compiler hint confirms owned-state-only access, no shared reads, and no
    /// `#[private]` annotation.
    Eligible,

    /// The transaction must use the base Pulse ordering.
    ///
    /// The inner [`FallbackReason`] is diagnostic — it identifies which
    /// condition caused the fallback.
    Fallback(FallbackReason),
}

impl ExpressEligibility {
    /// Returns `true` if this is [`ExpressEligibility::Eligible`].
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible)
    }

    /// Returns the fallback reason, or `None` if `Eligible`.
    #[must_use]
    pub fn fallback_reason(&self) -> Option<FallbackReason> {
        match self {
            Self::Eligible => None,
            Self::Fallback(reason) => Some(*reason),
        }
    }
}

// ── Classification ────────────────────────────────────────────────────────────

/// Classify whether a transaction is eligible for the Express fast path.
///
/// This is a **pure function**: same inputs always produce the same output.
/// No network calls, no timer, no randomness (AGENTS.md §7.1).
///
/// # Arguments
///
/// * `tx_type` — the transaction's type discriminant.
/// * `hint` — compiler-provided state-access metadata. Pass `None` if the
///   compiler has not yet analysed this transaction (conservative fallback).
///
/// # Returns
///
/// [`ExpressEligibility::Eligible`] iff all of the following hold:
/// 1. `tx_type` is on the Phase-1 owned-state allow-list (currently `Transfer`).
/// 2. `hint` is `Some`.
/// 3. `hint.is_express_eligible` is `true`.
/// 4. `hint.reads_shared_state` is `false`.
/// 5. `hint.is_private` is `false`.
///
/// Otherwise [`ExpressEligibility::Fallback`] with the first disqualifier found
/// (checked in the order above, most structural first).
///
/// # Conservative default
///
/// When `hint` is `None`, returns `Fallback(MissingHint)`.
/// This is the correct behaviour when the compiler has not yet proven
/// eligibility — assume conflict (08-EXECUTION_SPEC §1.7).
///
/// # Examples
///
/// ```
/// use lemma_mempool::express::{classify, ExpressHint, ExpressEligibility};
/// use lemma_core::transaction::TxType;
///
/// // Transfer with compiler proof → eligible
/// let result = classify(TxType::Transfer, Some(&ExpressHint::eligible()));
/// assert!(result.is_eligible());
///
/// // No hint → conservative fallback
/// let result = classify(TxType::Transfer, None);
/// assert!(!result.is_eligible());
///
/// // ContractCall → always fallback in Phase 1
/// let result = classify(TxType::ContractCall, Some(&ExpressHint::eligible()));
/// assert!(!result.is_eligible());
/// ```
pub fn classify(tx_type: TxType, hint: Option<&ExpressHint>) -> ExpressEligibility {
    // 1. TxType allow-list (most structural check first).
    //    Only Transfer is structurally owned-state-only in Phase 1.
    //    See FallbackReason::IneligibleTxType doc table.
    if !is_allowed_tx_type(tx_type) {
        return ExpressEligibility::Fallback(FallbackReason::IneligibleTxType);
    }

    // 2. Hint must be present — absence means "unknown", which maps to the
    //    conservative "assume conflict" default (08-EXECUTION_SPEC §1.7).
    let hint = match hint {
        Some(h) => h,
        None => return ExpressEligibility::Fallback(FallbackReason::MissingHint),
    };

    // 3. Compiler's own eligibility flag.
    if !hint.is_express_eligible {
        return ExpressEligibility::Fallback(FallbackReason::NotCompilerEligible);
    }

    // 4. Shared-state read disqualifier (07-CONSENSUS_SPEC §10).
    if hint.reads_shared_state {
        return ExpressEligibility::Fallback(FallbackReason::SharedStateRead);
    }

    // 5. Private / Veil-shielded transaction disqualifier.
    if hint.is_private {
        return ExpressEligibility::Fallback(FallbackReason::PrivateTx);
    }

    ExpressEligibility::Eligible
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Returns `true` iff `tx_type` is on the Phase-1 Express allow-list.
///
/// Uses a positive allow-list (not `!matches!(...)`) so that newly added
/// `#[non_exhaustive]` `TxType` variants default to **not allowed** — fail-
/// closed (AGENTS.md §7 "no non-determinism in consensus path"; consistent with
/// circuit_breaker.rs positive-allow-list convention).
fn is_allowed_tx_type(tx_type: TxType) -> bool {
    matches!(tx_type, TxType::Transfer)
}

#[cfg(test)]
mod tests;
