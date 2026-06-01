//! Error types for `lemma-consensus`.
//!
//! Every failure path in this crate returns a typed [`ConsensusError`] variant —
//! no `unwrap()`, no `panic!()`, no error-swallowing (AGENTS.md §12).
//!
//! # Design
//!
//! - **`#[non_exhaustive]`**: adding variants as new modules land is not a
//!   breaking change for downstream crates (AGENTS.md §4.3).
//! - **No forward references**: all variant fields use `lemma-core` types or
//!   primitives only. Internal types (`DagBlockRef`, `Slot`) that do not exist
//!   yet are represented by their constituent fields (`round: u64`,
//!   `author: Address`, `digest: Hash`), so this module compiles ahead of any
//!   internal module that defines them.
//! - **Structured fields** carry diagnostic context: callers see *what* failed,
//!   not just *that* something failed (AGENTS.md §12.2 rule 2).
//! - **Predicate helpers** let callers make policy decisions (suspend vs reject,
//!   emit slashing evidence) without exhaustive matching.
//!
//! See `docs/07-CONSENSUS_SPEC.md §3` (validity rules) and
//! `docs/13-VALIDATOR_EPOCH_SPEC.md §5.2` (slashing evidence).

use lemma_core::{address::Address, hash::Hash};
use serde::{Deserialize, Serialize};

// ── ConsensusError ────────────────────────────────────────────────────────────

/// Errors produced by the `lemma-consensus` crate.
///
/// Covers DAG validity rejections, equivocation detection, and stake arithmetic
/// failures. Future commit-path and fee variants are added via `#[non_exhaustive]`
/// as those modules land.
///
/// # Variant groups
///
/// - **`EpochMismatch` / `UnknownAuthor` / `InvalidSignature` / `BelowGcBoundary`
///   / `MissingAncestor` / `InsufficientStrongLinks`** — DAG validity rules
///   (`docs/07-CONSENSUS_SPEC.md §3`). Produced by `dag::graph` when accepting
///   an incoming `DagBlock`.
/// - **`Equivocation`** — a validator signed two conflicting blocks at the same
///   `(round, author)` slot. The caller MUST emit slashing evidence
///   (`docs/13-VALIDATOR_EPOCH_SPEC.md §5.2`).
/// - **`StakeOverflow`** — checked-arithmetic overflow in `StakeAggregator`
///   (`docs/07-CONSENSUS_SPEC.md §1.1`).
/// - **`EmptyCommittee`** — validator set has no members; fatal configuration
///   error at epoch boundary or genesis (spec §6, Decision 7a/W1).
/// - **`ByzantineInvariantBreach`** — two certified leaders at the same slot;
///   BFT assumption (`Byzantine < S/3`) violated. Node must halt + slash
///   (`docs/07-CONSENSUS_SPEC.md §4`, Decision 6c).
/// - **`DecidedLeaderMissing`** — a decided leader's block vanished from the DAG
///   before linearization; unrecoverable internal invariant (not slashable).
///   Node must halt (`docs/07-CONSENSUS_SPEC.md §5`, CodeReviewer W3).
///
/// # Coverage of spec §3 acceptance rules
///
/// Rules 1–6 map to the variants above. **Rule 7** (`payload` batch refs are
/// available/fetchable) is **not** represented here: availability is Surge's
/// responsibility and is surfaced by the dissemination layer (`dag` Step 4+),
/// not by block-validity rejection. This omission is deliberate.
///
/// # Derived traits
///
/// `Clone` + `Serialize`/`Deserialize` are required because the `Equivocation`
/// variant carries the digests that seed `DoubleSignEvidence`, which is cloned
/// while propagating and serialized for network broadcast + persistence
/// (`docs/13-VALIDATOR_EPOCH_SPEC.md §5.2`). `PartialEq`/`Eq` let tests assert
/// exact error identity. All field types (`Address`, `Hash`, `u64`) already
/// provide these (the former two via manual Bech32m/hex serde impls in
/// `lemma-core`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[non_exhaustive]
pub enum ConsensusError {
    // ── DAG validity — §3 ────────────────────────────────────────────────────

    /// The block's epoch does not match the receiver's current validator-set epoch.
    ///
    /// This variant only *reports* the mismatch — it does **not** decide whether
    /// the block is buffered or dropped. Per `docs/13-VALIDATOR_EPOCH_SPEC.md §4.6`
    /// that decision is three-way and **stateful**: an immediately-next-epoch
    /// block with an imminent boundary is *buffered*, while stale (past) or
    /// far-future blocks are *dropped*. Resolving it requires live consensus
    /// state (boundary imminence) and DAG-store state (bounded buffer capacity),
    /// neither of which an error value holds. The buffer-vs-drop logic therefore
    /// lives in `dag::graph` (Step 4), which matches on `{ expected, got }`.
    /// Consequently this variant is **not** reported as
    /// [`ConsensusError::is_pending_data`] — see that method's docs
    /// (`docs/07-CONSENSUS_SPEC.md §3 rule 1`).
    #[error("block epoch mismatch: expected {expected}, got {got}")]
    EpochMismatch { expected: u64, got: u64 },

    /// The block's `author` is not in the active validator set for `epoch`.
    ///
    /// Either the local view is stale or the block is Byzantine. The block is
    /// rejected — the author's key cannot be found for signature verification
    /// (`docs/07-CONSENSUS_SPEC.md §3 rule 2`).
    #[error("block author {author} not in validator set for epoch {epoch}")]
    UnknownAuthor { author: Address, epoch: u64 },

    /// The author's signature on the block body failed hybrid verification.
    ///
    /// Requires both Ed25519 (classical) and ML-DSA-65 (post-quantum) components
    /// to be present and valid (AGENTS.md §15.3). A bad signature is a hard
    /// reject — no buffering (`docs/07-CONSENSUS_SPEC.md §3 rule 2`).
    #[error("invalid signature on block from {author} at round {round}")]
    InvalidSignature { author: Address, round: u64 },

    /// The block's round is at or below the current GC boundary.
    ///
    /// `gc_round = last_committed_round − GC_DEPTH`. Blocks this old are dropped,
    /// not buffered; a node that far behind must state-sync instead
    /// (`docs/07-CONSENSUS_SPEC.md §3 rule 3`, §9).
    #[error("block at round {round} is below GC boundary (gc_round={gc_round})")]
    BelowGcBoundary { round: u64, gc_round: u64 },

    /// A declared ancestor of the block is not yet present in the local DAG.
    ///
    /// The block is *suspended* — parked in the pending buffer — until the
    /// missing ancestor arrives via sync. `ancestor_digest` is the Blake3 digest
    /// uniquely identifying the missing parent
    /// (`docs/07-CONSENSUS_SPEC.md §3 rule 4`, `12-NETWORK_SYNC_SPEC.md`).
    ///
    /// # Field choice
    ///
    /// `DagBlockRef = { round, author, digest }` is defined in `dag::block`
    /// (Step 3). Using `Hash` here avoids a forward reference: callers that hold
    /// a full `DagBlockRef` pass `ref.digest`; the `author` and `round` fields
    /// give context about the *receiving* block, not the missing ancestor.
    #[error("missing ancestor {ancestor_digest} for block from {author} at round {round}")]
    MissingAncestor {
        ancestor_digest: Hash,
        author: Address,
        round: u64,
    },

    /// The block's strong-link ancestors do not form a 2f+1 stake quorum at
    /// `round − 1`.
    ///
    /// Every non-genesis block must include strong links to a 2f+1 quorum of
    /// distinct stake from the previous round. Without it the block cannot
    /// advance the threshold clock
    /// (`docs/07-CONSENSUS_SPEC.md §2.2`, §3 rule 5).
    #[error("insufficient strong-link quorum for block from {author} at round {round}")]
    InsufficientStrongLinks { author: Address, round: u64 },

    // ── Equivocation — §3 rule 6, §7.1 ──────────────────────────────────────

    /// A validator produced two distinct blocks at the same `(round, author)` slot.
    ///
    /// This is a **slashable offence** (`docs/13-VALIDATOR_EPOCH_SPEC.md §5.2`).
    /// The caller MUST construct and broadcast `DoubleSignEvidence` when this
    /// variant is returned. Neither conflicting block is committed: quorum
    /// intersection guarantees at most one block per slot can gather 2f+1
    /// support (`docs/07-CONSENSUS_SPEC.md §7.1`).
    ///
    /// `first` and `second` are the Blake3 digests of the two conflicting blocks.
    #[error(
        "equivocation by {author} at round {round}: conflicting blocks {first} vs {second}"
    )]
    Equivocation {
        author: Address,
        round: u64,
        first: Hash,
        second: Hash,
    },

    // ── StakeAggregator — §1.1 ───────────────────────────────────────────────

    /// Stake accumulation overflowed a `u128`.
    ///
    /// In a correctly-configured validator set, total stake fits well within
    /// `u128::MAX`. An overflow here signals a misconfigured genesis or a
    /// Byzantine validator set with implausible stake values. The accumulation
    /// is aborted rather than wrapping (AGENTS.md §7.4 — always `checked_*`).
    #[error("stake overflow accumulating stake for author {author}")]
    StakeOverflow { author: Address },

    // ── Leader schedule — §6 ─────────────────────────────────────────────────

    /// The validator set passed to [`LeaderSchedule`] has no members.
    ///
    /// This is a protocol invariant violation — all valid epochs have at least
    /// one validator (genesis enforces this). Returning an error (not panicking)
    /// follows Decision 6c: no panics in the consensus path (AGENTS §7.2).
    /// The node binary should treat this as a fatal configuration error.
    ///
    /// [`LeaderSchedule`]: crate::pulse::leader::LeaderSchedule
    #[error("leader schedule requires a non-empty validator set (epoch {epoch})")]
    EmptyCommittee { epoch: u64 },

    // ── Commit rule — §4 ─────────────────────────────────────────────────────

    /// The BFT safety assumption (`Byzantine < S/3`) has been violated.
    ///
    /// This occurs when the commit rule detects **more than one certified leader
    /// block** at the same slot — which is mathematically impossible unless
    /// Byzantine stake ≥ S/3 (quorum intersection no longer holds). This is
    /// **not** a recoverable consensus error: the committed order would be
    /// ambiguous and unsafe. The node must halt and emit slashing evidence.
    ///
    /// `docs/07-CONSENSUS_SPEC.md §4` explicitly documents this as the one
    /// exception to the no-panic rule (AGENTS.md §7.2: "only when mathematically
    /// provable"). We surface it as a `Result` variant rather than `panic!`
    /// so the node binary can emit slashing evidence and shut down gracefully
    /// instead of crashing with an unhandled panic (Decision 6c).
    ///
    /// `slot_round` and `slot_author` identify the contested leader slot.
    /// `first` and `second` are digests of the two conflicting certified blocks.
    #[error(
        "BFT invariant breach: two certified leaders at round {slot_round} \
         author {slot_author}: {first} vs {second}"
    )]
    ByzantineInvariantBreach {
        slot_round: u64,
        slot_author: Address,
        first: Hash,
        second: Hash,
    },

    // ── Linearization — §5 ───────────────────────────────────────────────────

    /// A leader decided by `try_decide` was absent from the DAG when the
    /// linearizer went to flatten its sub-DAG.
    ///
    /// **Provably unreachable in normal operation**: GC (`set_last_committed_round`)
    /// runs *after* a commit batch, so a decided leader's block cannot be dropped
    /// mid-batch. Reaching this indicates state corruption or a driver bug.
    /// The node must halt — but this is **not** a slashable peer offence (unlike
    /// [`ConsensusError::ByzantineInvariantBreach`]), so it has its own variant
    /// rather than a misleading zero-digest `ByzantineInvariantBreach`
    /// (spec §5, CodeReviewer W3 refinement).
    #[error("decided leader block absent from DAG at round {round} author {author}")]
    DecidedLeaderMissing { round: u64, author: Address },
}

// ── Predicates ────────────────────────────────────────────────────────────────

impl ConsensusError {
    /// Returns `true` if this error represents a slashable equivocation event.
    ///
    /// When `true`, the caller MUST construct and broadcast `DoubleSignEvidence`
    /// (`docs/13-VALIDATOR_EPOCH_SPEC.md §5.2`). Only the `Equivocation` variant
    /// qualifies; all others return `false`.
    #[must_use]
    pub fn is_equivocation(&self) -> bool {
        matches!(self, Self::Equivocation { .. })
    }

    /// Returns `true` if this error is a fatal configuration error: the
    /// validator set is empty. Only `EmptyCommittee` qualifies.
    #[must_use]
    pub fn is_empty_committee(&self) -> bool {
        matches!(self, Self::EmptyCommittee { .. })
    }

    /// Returns `true` if this error represents a fatal BFT invariant breach.
    ///
    /// When `true`, the node MUST halt and emit slashing evidence — the committed
    /// order would be unsafe if execution were to continue. Only the
    /// `ByzantineInvariantBreach` variant qualifies (Decision 6c).
    #[must_use]
    pub fn is_byzantine_breach(&self) -> bool {
        matches!(self, Self::ByzantineInvariantBreach { .. })
    }

    /// Returns `true` if this error requires the node to **halt** (unrecoverable
    /// state corruption or BFT-invariant breach), as opposed to rejecting a
    /// single block.
    ///
    /// Covers `ByzantineInvariantBreach` (slashable) and `DecidedLeaderMissing`
    /// (non-slashable internal invariant). Both mean the node cannot safely
    /// continue producing commits. Only `ByzantineInvariantBreach` warrants
    /// slashing evidence — use [`is_byzantine_breach`] to distinguish.
    ///
    /// [`is_byzantine_breach`]: ConsensusError::is_byzantine_breach
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::ByzantineInvariantBreach { .. } | Self::DecidedLeaderMissing { .. }
        )
    }

    /// Returns `true` if this rejection is caused by data that has not arrived
    /// locally yet, as opposed to a definitive rejection of the block's content.
    ///
    /// This is an **intrinsic** property of the error variant — it does *not*
    /// itself decide that the caller should buffer the block. Only
    /// [`ConsensusError::MissingAncestor`] qualifies: the referenced ancestor
    /// may still arrive via sync, after which re-validation can succeed
    /// (`docs/07-CONSENSUS_SPEC.md §3 rule 4`).
    ///
    /// # Why `EpochMismatch` is excluded
    ///
    /// Epoch-mismatch recoverability is *conditional and stateful* (next-epoch +
    /// imminent boundary ⇒ buffer; stale or far-future ⇒ drop —
    /// `docs/13-VALIDATOR_EPOCH_SPEC.md §4.6`). Evaluating it needs live
    /// consensus + DAG-store state that an error value cannot carry, so that
    /// decision is owned by `dag::graph` (Step 4), not by this predicate. A
    /// predicate that returned `true` for all `EpochMismatch` would wrongly
    /// buffer far-future blocks (an unbounded-buffer DoS, AGENTS.md §15.2).
    #[must_use]
    pub fn is_pending_data(&self) -> bool {
        matches!(self, Self::MissingAncestor { .. })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
