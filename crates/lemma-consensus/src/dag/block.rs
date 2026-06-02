//! DAG vertex types for the Surge dissemination layer.
//!
//! Defines the core type vocabulary of the DAG:
//! - [`DagBlock`] — a vertex in the Surge DAG, signed by its author.
//! - [`DagBlockRef`] — lightweight identity reference `(round, author, digest)`.
//! - [`Slot`] — `(round, author)` pair; at most one honest block per slot.
//! - [`TxBatchRef`] — reference to a transaction batch (not inline transactions).
//! - [`CommitVote`] — piggybacked commit hint inside a DagBlock.
//!
//! # Canonical digest
//!
//! Every [`DagBlock`] carries a [`Hash`] digest computed by [`DagBlock::new`]
//! over the **body** (all fields except `signature` and `digest` itself).
//! The digest is the block's **content address** and the root of all
//! integrity checks. See [`DagBlock::compute_digest`].
//!
//! # What is NOT here
//!
//! - DAG store, ancestor queries, `block_at_slot`, `blocks_at_round` → `dag::graph` (Step 4).
//! - Strong/weak link validation (requires `StakeAggregator` + quorum) → `dag::graph` (Step 4).
//!   See decisions-log "Decision 3c" for why partial definitions are not exposed here.
//! - `ThresholdClock` → `dag::threshold_clock` (Step 5).
//! - Validity rules §3 (epoch/author/quorum) → `dag::graph` (Step 4).
//!
//! See `docs/07-CONSENSUS_SPEC.md §2`.

use serde::{Deserialize, Serialize};

use lemma_core::{address::Address, hash::Hash, signature::Signature};

// ── Slot ──────────────────────────────────────────────────────────────────────

/// A `(round, author)` slot in the DAG.
///
/// At most one honest block exists per slot. Two blocks at the same slot by
/// the same author constitute **equivocation** — a slashable offence
/// (`docs/07-CONSENSUS_SPEC.md §3 rule 6`, `13-VALIDATOR_EPOCH_SPEC.md §5.2`).
///
/// `Ord` enables `BTreeMap<Slot, _>` keying in the DAG store (Step 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Slot {
    /// The DAG round. Monotonically increasing across the epoch.
    pub round: u64,
    /// The validator that owns this slot.
    pub author: Address,
}

impl Slot {
    /// Create a slot from `(round, author)`.
    #[must_use]
    pub fn new(round: u64, author: Address) -> Self {
        Self { round, author }
    }
}

// ── DagBlockRef ───────────────────────────────────────────────────────────────

/// Lightweight identity reference for a DAG block: `(round, author, digest)`.
///
/// Embeds as an ancestor edge in [`DagBlock::ancestors`] and as the `leader`
/// field in [`CommitVote`] and `Commit`. The `digest` is the Blake3 content
/// hash of the referenced block's body, enabling integrity verification
/// without fetching the full block.
///
/// `Ord` enables deterministic sorting in committed sub-DAG linearization
/// (spec §5: sort by `(round ASC, author ASC)`) and `BTreeSet` membership
/// (`docs/07-CONSENSUS_SPEC.md §5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DagBlockRef {
    /// The DAG round of the referenced block.
    pub round: u64,
    /// The author of the referenced block.
    pub author: Address,
    /// Blake3 digest of the referenced block's canonical body.
    pub digest: Hash,
}

impl DagBlockRef {
    /// Create a block reference.
    #[must_use]
    pub fn new(round: u64, author: Address, digest: Hash) -> Self {
        Self {
            round,
            author,
            digest,
        }
    }

    /// The slot `(round, author)` this reference points to.
    #[must_use]
    pub fn slot(&self) -> Slot {
        Slot {
            round: self.round,
            author: self.author,
        }
    }
}

// ── TxBatchRef ────────────────────────────────────────────────────────────────

/// Reference to a transaction batch in the Surge dissemination layer.
///
/// `DagBlock` payload carries batch *references*, not inline transactions.
/// Surge separates dissemination of transaction batches from block headers so
/// that a `DagBlock` stays small and propagates in one round-trip. The actual
/// transactions live in batches fetched and pinned by availability; execution
/// (Flux, `docs/08-EXECUTION_SPEC.md`) resolves refs → transactions after
/// ordering (`docs/07-CONSENSUS_SPEC.md §2.1`).
///
/// # `size` field type
///
/// `size` is the byte length of the batch, used for availability accounting and
/// DoS bounding. It is typed as `u32` (max ~4.3 GB) because any batch exceeding
/// this is categorically an attack — representing >4 GB at the type level would
/// require explicit rejection rather than rejecting invalid state at encoding time.
/// `u32` closes that class of invalid state at the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TxBatchRef {
    /// Blake3 digest of the batch contents.
    pub digest: Hash,
    /// The validator that produced this batch.
    pub author: Address,
    /// Byte size of the batch (max ~4.3 GB; batches claiming more are invalid).
    pub size: u32,
}

// ── CommitVote ────────────────────────────────────────────────────────────────

/// Piggybacked commit hint inside a [`DagBlock`].
///
/// A validator includes commit votes in its blocks to signal to peers which
/// leader rounds it has already committed, enabling peers to skip
/// re-computation for those rounds
/// (`docs/07-CONSENSUS_SPEC.md §2.1`, "see §4.4").
///
/// # ⚠️ Interim design
///
/// This struct carries the minimal identity of a commit (`commit_index` +
/// `leader` ref), derived from [`Commit`] in spec §5. The commit rule (§4)
/// is a **pure function of the DAG** and does not read `commit_votes` —
/// this field is a piggyback optimisation that has no reader yet in the
/// current implementation. The struct is `#[non_exhaustive]` to allow
/// field additions when the fast-forward optimization is implemented
/// at Step 6/8 without breaking existing construction sites.
///
/// See decisions-log "Decision 3a" for the full rationale.
///
/// [`Commit`]: crate::commit::Commit
///
/// # `Copy` + `#[non_exhaustive]` caveat
///
/// This struct currently derives `Copy` (all fields are fixed-size). If Step 6/8
/// adds a non-`Copy` field (e.g. a `Vec<_>` for vote evidence), that addition
/// will **silently drop the `Copy` bound** — a breaking change despite
/// `#[non_exhaustive]`. The Step 6/8 implementer must update all `Copy`-dependent
/// call sites when that happens.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CommitVote {
    /// Monotonic index of the commit being voted on (`Commit::index`).
    pub commit_index: u64,
    /// The leader block of the commit (`Commit::leader`).
    pub leader: DagBlockRef,
}

impl CommitVote {
    /// Create a commit vote.
    #[must_use]
    pub fn new(commit_index: u64, leader: DagBlockRef) -> Self {
        Self {
            commit_index,
            leader,
        }
    }
}

// ── DagBlockBody ─────────────────────────────────────────────────────────────

/// The signable body of a [`DagBlock`] — all fields that enter the canonical digest.
///
/// Grouping the body separately from `signature` makes the signing boundary
/// explicit: the author signs the body digest; `signature` and `digest` itself
/// are excluded from the hash.
///
/// `DagBlock::new` accepts `(body, signature)` and computes `digest` internally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagBlockBody {
    /// Validator-set epoch.
    pub epoch: u64,
    /// Monotonically increasing DAG round.
    pub round: u64,
    /// The validator that created this block.
    pub author: Address,
    /// Author's wall clock at creation in milliseconds (advisory only).
    pub timestamp_ms: u64,
    /// Parent edges: causal history of this block.
    pub ancestors: Vec<DagBlockRef>,
    /// References to transaction batches (not inline transactions).
    pub payload: Vec<TxBatchRef>,
    /// Piggybacked commit hints (⚠️ interim — no reader yet).
    pub commit_votes: Vec<CommitVote>,
}

// ── DagBlock ──────────────────────────────────────────────────────────────────

/// A vertex in the Surge DAG. Signed by its author only (uncertified).
///
/// The pair `(round, author)` is the block's *slot*; an honest validator
/// produces exactly one block per slot. Two blocks at the same slot constitute
/// equivocation (`docs/07-CONSENSUS_SPEC.md §3 rule 6`).
///
/// # Digest
///
/// `digest` is a Blake3 hash over the [`DagBlockBody`] fields (all fields
/// except `signature` and `digest` itself). Computed by [`DagBlock::new`];
/// verified by [`DagBlock::verify_digest`]. The digest is the content address
/// used in [`DagBlockRef`] edges and determines block identity across the network.
///
/// # Ancestors
///
/// `ancestors` is a flat `Vec<DagBlockRef>` carrying all parent edges. Strong
/// vs weak link classification (spec §2.2) requires a 2f+1 quorum check and
/// is owned by `dag::graph` (Step 4), not by this type — see decisions-log
/// "Decision 3c".
///
/// See `docs/07-CONSENSUS_SPEC.md §2.1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagBlock {
    /// Validator-set epoch (`docs/13-VALIDATOR_EPOCH_SPEC.md`).
    pub epoch: u64,
    /// Monotonically increasing DAG round.
    pub round: u64,
    /// The validator that created this block.
    pub author: Address,
    /// Author's wall clock at creation, in milliseconds (advisory only —
    /// consensus timestamps use the stake-weighted median, spec §5.1).
    pub timestamp_ms: u64,
    /// Parent edges: causal history of this block.
    ///
    /// Strong vs weak link classification is owned by `dag::graph` (Step 4).
    pub ancestors: Vec<DagBlockRef>,
    /// References to transaction batches (not inline transactions — spec §2.1).
    pub payload: Vec<TxBatchRef>,
    /// Piggybacked commit hints (⚠️ interim — no reader yet; spec §2.1/§4.4).
    pub commit_votes: Vec<CommitVote>,
    /// Author signature over [`DagBlock::digest`]. Hybrid Ed25519 + ML-DSA-65.
    ///
    /// Cryptographic verification (`lemma-crypto`) is the caller's responsibility;
    /// this crate stores raw bytes only (same pattern as `lemma-core::Signature`).
    pub signature: Signature,
    /// Blake3 digest of the [`DagBlockBody`] (excludes `signature` and `digest`
    /// itself). Set by [`DagBlock::new`].
    pub digest: Hash,
}

impl DagBlock {
    /// Create a new `DagBlock` from a `body` and `signature`, computing the
    /// canonical digest.
    ///
    /// The `body` is the signable part — the author signs the body digest.
    /// `signature` is stored as-is; cryptographic verification is
    /// `lemma-crypto`'s responsibility (same pattern as `lemma-core::Signature`).
    ///
    /// Digest field order: `epoch` → `round` → `author` → `timestamp_ms` →
    /// `ancestors` → `payload` → `commit_votes`. See [`compute_digest`].
    #[must_use]
    pub fn new(body: DagBlockBody, signature: Signature) -> Self {
        let digest = compute_digest(
            body.epoch,
            body.round,
            &body.author,
            body.timestamp_ms,
            &body.ancestors,
            &body.payload,
            &body.commit_votes,
        );
        Self {
            epoch: body.epoch,
            round: body.round,
            author: body.author,
            timestamp_ms: body.timestamp_ms,
            ancestors: body.ancestors,
            payload: body.payload,
            commit_votes: body.commit_votes,
            signature,
            digest,
        }
    }

    /// The identity reference for this block: `(round, author, digest)`.
    #[must_use]
    pub fn reference(&self) -> DagBlockRef {
        DagBlockRef {
            round: self.round,
            author: self.author,
            digest: self.digest,
        }
    }

    /// The slot `(round, author)` of this block.
    #[must_use]
    pub fn slot(&self) -> Slot {
        Slot {
            round: self.round,
            author: self.author,
        }
    }

    /// Verify that the stored `digest` matches a fresh recomputation of the body.
    ///
    /// Returns `false` if the block has been tampered with after construction.
    /// This is a **content-integrity** check, not a signature check — call
    /// `lemma-crypto` to verify the author's signature over the digest.
    #[must_use]
    pub fn verify_digest(&self) -> bool {
        let expected = compute_digest(
            self.epoch,
            self.round,
            &self.author,
            self.timestamp_ms,
            &self.ancestors,
            &self.payload,
            &self.commit_votes,
        );
        self.digest == expected
    }

    /// Returns `true` if this block is at round 0 (genesis DAG round).
    #[must_use]
    pub fn is_genesis_round(&self) -> bool {
        self.round == 0
    }

    /// Iterate over ancestors whose round equals `round`.
    ///
    /// Used by the commit rule (§4.2–§4.4) to scan voting-round and
    /// decision-round ancestors without allocating a filtered collection.
    /// The iterator borrows `self` and yields `&DagBlockRef`.
    pub fn ancestors_at_round(&self, round: u64) -> impl Iterator<Item = &DagBlockRef> {
        self.ancestors.iter().filter(move |a| a.round == round)
    }
}

// ── Canonical digest ──────────────────────────────────────────────────────────

/// Compute the canonical Blake3 digest over a DagBlock body.
///
/// Hashes fields in a deterministic, canonical order using big-endian encoding
/// for all integer fields (same pattern as `ValidatorSet::hash` in `lemma-core`).
/// Lengths of variable-length fields are hashed before the field contents to
/// prevent length-extension ambiguity.
///
/// **Excluded**: `signature` (signs the digest) and `digest` itself (circular).
///
/// Field order: `epoch` → `round` → `author` → `timestamp_ms` →
/// `ancestors.len` → each ancestor `(round, author, digest)` →
/// `payload.len` → each batch ref `(digest, author, size)` →
/// `commit_votes.len` → each vote `(commit_index, leader.round, leader.author, leader.digest)`.
fn compute_digest(
    epoch: u64,
    round: u64,
    author: &Address,
    timestamp_ms: u64,
    ancestors: &[DagBlockRef],
    payload: &[TxBatchRef],
    commit_votes: &[CommitVote],
) -> Hash {
    let mut h = blake3::Hasher::new();

    // Scalar fields — big-endian for cross-platform determinism (AGENTS.md §7.1).
    h.update(&epoch.to_be_bytes());
    h.update(&round.to_be_bytes());
    h.update(author.as_bytes());
    h.update(&timestamp_ms.to_be_bytes());

    // ancestors — length prefix prevents ambiguity between e.g. [] + [a,b] vs [a] + [b].
    h.update(&(ancestors.len() as u64).to_be_bytes());
    for a in ancestors {
        h.update(&a.round.to_be_bytes());
        h.update(a.author.as_bytes());
        h.update(a.digest.as_bytes());
    }

    // payload
    h.update(&(payload.len() as u64).to_be_bytes());
    for p in payload {
        h.update(p.digest.as_bytes());
        h.update(p.author.as_bytes());
        h.update(&p.size.to_be_bytes());
    }

    // commit_votes
    h.update(&(commit_votes.len() as u64).to_be_bytes());
    for v in commit_votes {
        h.update(&v.commit_index.to_be_bytes());
        h.update(&v.leader.round.to_be_bytes());
        h.update(v.leader.author.as_bytes());
        h.update(v.leader.digest.as_bytes());
    }

    Hash::from_bytes(*h.finalize().as_bytes())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
