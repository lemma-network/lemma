//! # Commit record (spec §5)
//!
//! A [`Commit`] is the final output of Pulse: a deterministically ordered,
//! content-addressed record that chains one committed sub-DAG to the next.
//!
//! ## Commit chain integrity
//!
//! Each `Commit` carries the digest of its predecessor (`previous_digest`),
//! forming an append-only chain. Any tampering with an earlier commit breaks
//! every subsequent digest — detectable by any node. The genesis sentinel
//! uses [`Hash::zero`] as its predecessor (Decision 8a).
//!
//! ## Single type (Decision 8b)
//!
//! We use one `Commit` type rather than splitting into
//! `CommittedSubDag` (linearized blocks) + `Commit` (with index/chaining).
//! No consumer of this crate needs an intermediate sub-DAG type — the spec
//! §11 reference to `CommittedSubDag` is a Sui artefact, not a protocol
//! requirement. AGENTS §2 bans near-duplicate types.
//!
//! ## Downstream consumer
//!
//! `Commit` is the cross-crate contract between `lemma-consensus` and
//! `lemma-vm` (Flux). Flux consumes `Commit.blocks` to resolve transaction
//! batches, executes them in order, and produces receipts + a state root.
//! The §5.2 mapping (`Commit → BlockHeader`) is performed by `lemma-vm`
//! when forming the chain Block:
//!
//! - `header.dag_round  = Commit.leader.round`
//! - `header.dag_anchor = Commit.leader.digest`
//! - `header.timestamp  = Commit.timestamp_ms / 1000` (ms → seconds)
//! - `header.height     = Commit.index`
//!
//! `lemma-core::BlockHeader` fields `dag_round`/`dag_anchor` are already
//! implemented and waiting for this consumer.

use serde::{Deserialize, Serialize};

use lemma_core::hash::Hash;

use crate::dag::block::DagBlockRef;

// ── Commit ────────────────────────────────────────────────────────────────────

/// The output record of one Pulse commit: a committed sub-DAG, chained to
/// its predecessors via cryptographic digest.
///
/// Produced by [`Linearizer::commit_leaders`] for every `Commit` entry in
/// the output of [`try_decide`]. Consumed by `lemma-vm`/Flux to resolve
/// transaction batches, execute them, and form the chain `Block`.
///
/// ## Fields
///
/// - `index` — monotonically increasing commit counter (genesis = 0,
///   so the first real commit has `index = 1`). Maps to `BlockHeader.height`.
/// - `previous_digest` — Blake3 digest of the preceding `Commit`, forming
///   an append-only integrity chain. Genesis predecessor = [`Hash::zero()`].
/// - `timestamp_ms` — deterministic consensus timestamp in **milliseconds**
///   (stake-weighted median of the leader's round-`L-1` parents, clamped
///   monotonic — spec §5.1). `lemma-vm` divides by 1_000 for
///   `BlockHeader.timestamp` (Unix seconds).
/// - `leader` — the committed leader's [`DagBlockRef`]. Maps to
///   `BlockHeader.dag_round` and `BlockHeader.dag_anchor`.
/// - `blocks` — the linearized sub-DAG in deterministic `(round ASC,
///   author ASC)` order. Handed to Flux for execution.
///
/// [`Linearizer::commit_leaders`]: crate::pulse::linearizer::Linearizer::commit_leaders
/// [`try_decide`]: crate::pulse::committer::try_decide
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commit {
    /// Monotonic commit index. 1-based; genesis anchor = 0 (implicit).
    pub index: u64,
    /// Digest of the previous `Commit`, or [`Hash::zero`] for the first commit.
    pub previous_digest: Hash,
    /// Consensus timestamp in milliseconds (spec §5.1, deterministic).
    pub timestamp_ms: u64,
    /// The leader's block reference for this commit.
    pub leader: DagBlockRef,
    /// Linearized sub-DAG blocks in `(round ASC, author ASC)` order.
    pub blocks: Vec<DagBlockRef>,
}

impl Commit {
    /// Compute the Blake3 digest of this commit.
    ///
    /// Hashes fields in canonical order using big-endian integer encoding
    /// (same pattern as `DagBlock::compute_digest` and
    /// `ValidatorSet::hash`). Length-prefixed variable-length fields prevent
    /// length-extension ambiguity.
    ///
    /// **Digest input** (in order):
    /// `index` → `previous_digest` → `timestamp_ms` →
    /// `leader.(round, author, digest)` →
    /// `blocks.len` → each block `(round, author, digest)`.
    ///
    /// This value becomes `previous_digest` of the next `Commit`.
    #[must_use]
    pub fn digest(&self) -> Hash {
        let mut hasher = blake3::Hasher::new();

        // Scalars — big-endian (deterministic, cross-platform).
        hasher.update(&self.index.to_be_bytes());
        hasher.update(self.previous_digest.as_bytes());
        hasher.update(&self.timestamp_ms.to_be_bytes());

        // Leader ref.
        hasher.update(&self.leader.round.to_be_bytes());
        hasher.update(self.leader.author.as_bytes());
        hasher.update(self.leader.digest.as_bytes());

        // Blocks — length-prefix then each ref.
        hasher.update(&(self.blocks.len() as u64).to_be_bytes());
        for block in &self.blocks {
            hasher.update(&block.round.to_be_bytes());
            hasher.update(block.author.as_bytes());
            hasher.update(block.digest.as_bytes());
        }

        Hash::from_bytes(*hasher.finalize().as_bytes())
    }

    /// The digest used as `previous_digest` for the very first commit.
    ///
    /// Returns [`Hash::zero`] — a 32-byte all-zero sentinel that signals
    /// "no predecessor". Symmetric with `BlockHeader.parent_hash` for the
    /// genesis block in `lemma-core`.
    #[must_use]
    pub fn genesis_previous() -> Hash {
        Hash::zero()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
