//! Surge transaction batch — data availability layer (C·Step 14).
//!
//! ## Overview
//!
//! Surge (the Lemma DAG dissemination layer) separates *batch headers* from
//! *transaction data*. A [`DagBlock`] carries only lightweight
//! [`TxBatchRef`]s (`digest + author + size`); the actual transactions live in
//! [`Batch`]es that validators broadcast on `lemma/batch/1` **before** the
//! referencing `DagBlock` is gossiped.
//!
//! This module provides:
//!
//! | Type / fn | Role |
//! |-----------|------|
//! | [`Batch`] | A named, serializable bundle of transactions with a Blake3 digest. |
//! | [`BatchStore`] | In-memory pin store: `Arc<RwLock<HashMap<Hash, Batch>>>`. |
//! | [`new_batch_store`] | Construct a fresh, empty `BatchStore`. |
//! | [`resolve_committed_txs`] | Walk `Commit.blocks`, look up each `DagBlock`, resolve its `payload` refs → `Vec<Transaction>` (deduped, deterministic order). |
//!
//! ## Flow (per DAG round)
//!
//! ```text
//! 1. dag_driver: drain mempool → build Batch
//! 2. dag_driver: pin Batch in BatchStore
//! 3. dag_driver: JSON-encode Batch → broadcast on lemma/batch/1
//! 4. dag_driver: build DagBlock with payload = [batch.to_ref()]
//! 5. At commit: resolve_committed_txs(commit, dag, store) → Vec<Transaction>
//! 6. Flux executes the ordered, deduped tx list
//! ```
//!
//! ## Dedup guarantee
//!
//! A transaction can appear in multiple batches across the committed sub-DAG
//! (different validators may have included the same pending tx in their
//! concurrent batches). [`resolve_committed_txs`] deduplicates by tx hash,
//! keeping only the **first occurrence** in the deterministic
//! `(round ASC, author ASC)` sub-DAG order — satisfying the spec requirement
//! that every tx is executed at most once per commit.
//!
//! ## Trust model for inbound batches (security scope)
//!
//! The inbound path (`network_runner::handle_batch_received`) enforces:
//! - **Envelope integrity**: the JSON-serialized batch round-trips through
//!   [`Batch::to_ref`]'s digest, so the batch was not mutated in transit.
//! - **Per-tx hash integrity**: each `Transaction.hash` is recomputed from
//!   the transaction body and compared against the wire value. A mismatch
//!   causes the whole batch to be rejected. This makes `tx.hash` a trustworthy
//!   dedup key and prevents the consensus-divergence vector where two honest
//!   nodes resolve the same committed sub-DAG to different tx lists because a
//!   malicious peer forged `tx.hash` fields.
//! - **Signature verification**: ✅ **SECURITY GATE CLOSED (D·Step 15d)**.
//!   `handle_batch_received` in `network_runner.rs` now:
//!   (a) rejects any `Signature::Unsigned` tx in the batch (whole batch dropped),
//!   (b) for vset senders: full Ed25519+ML-DSA-65 sig verify via ConsensusKey→PublicKey,
//!   (c) for non-vset senders: hash integrity sufficient (Phase 2 documented limitation).
//!   See `network_runner.rs:handle_batch_received` + D·Step 15d commit.
//!
//! ## Batch availability (Rule 7, spec §2.1)
//!
//! In Phase 2 (single-node) the proposer owns every batch, so resolution
//! always succeeds. In Phase 3+ (multi-node), a missing batch ref is logged
//! and **skipped** — the block is still produced with the available txs. A
//! dedicated fetch-on-miss path (request-response pull when a ref is not
//! locally pinned) is deferred to D·Step 15 alongside the 4-node testnet
//! (intentional deferral — only testable with real peers, AGENTS §1 Rule 7).
//!
//! ## In-memory store (Phase 2)
//!
//! `BatchStore` is a plain `HashMap` protected by a `RwLock`. Batches are
//! never evicted in Phase 2 — the working set is bounded by the test duration.
//! Phase 3 adds a GC pass keyed on the committed `gc_round` from `SurgeDriver`
//! (TODO(batch): GC on `Dag::gc_round()` advance, deferred to D·Step 15).

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use lemma_consensus::{
    dag::block::{DagBlock, TxBatchRef},
    Commit,
};
use lemma_core::{address::Address, hash::Hash, transaction::Transaction};
use lemma_crypto::hash_bytes;

// ── BatchError ────────────────────────────────────────────────────────────────

/// Errors produced by [`Batch`] operations.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum BatchError {
    /// JSON serialization of the batch failed (programming error — well-formed
    /// Rust types should always be serializable; indicates a type-system issue).
    #[error("batch serialization failed: {0}")]
    Serialization(String),

    /// The serialized batch exceeds [`u32::MAX`] bytes (≈ 4.3 GiB).
    ///
    /// A batch this large is categorically an attack — `TxBatchRef.size` is a
    /// `u32` to close this invalid state at the type level (spec §2.1 note,
    /// DB decisions-log "TxBatchRef.size u32").
    #[error("batch too large: {0} bytes exceeds u32::MAX (attack vector — reject)")]
    TooLarge(usize),
}

// ── Batch ─────────────────────────────────────────────────────────────────────

/// A Surge transaction batch: a named bundle of transactions with a Blake3 digest.
///
/// The digest is computed lazily (or eagerly via [`Batch::to_ref`]) over the
/// JSON-serialized form — same encoding used for gossip wire transmission —
/// so digest stability is guaranteed when the same batch is encoded multiple
/// times.
///
/// # Invariants
///
/// - `author` identifies the validator that produced this batch.
/// - `txs` may be empty (an empty batch advances the clock with no execution).
/// - The same `(author, txs)` tuple always produces the same `digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// The validator that produced this batch.
    pub author: Address,
    /// The transactions included in this batch.
    pub txs: Vec<Transaction>,
}

impl Batch {
    /// Construct a new batch.
    #[must_use]
    pub fn new(author: Address, txs: Vec<Transaction>) -> Self {
        Self { author, txs }
    }

    /// Compute the Blake3 digest of this batch.
    ///
    /// The digest is computed over the JSON-encoded batch bytes — the same
    /// encoding used on the gossip wire — so any peer that receives and
    /// re-encodes the batch will produce the same digest.
    ///
    /// # Errors
    ///
    /// Returns [`BatchError::Serialization`] if JSON encoding fails (should
    /// never occur for well-formed Rust types).
    pub fn digest(&self) -> Result<Hash, BatchError> {
        let bytes =
            serde_json::to_vec(self).map_err(|e| BatchError::Serialization(e.to_string()))?;
        Ok(hash_bytes(&bytes))
    }

    /// Serialized byte length of this batch (for [`TxBatchRef::size`]).
    ///
    /// `TxBatchRef.size` is a `u32` — batches claiming > 4.3 GiB are
    /// categorically an attack and are rejected at this boundary.
    ///
    /// # Errors
    ///
    /// - [`BatchError::Serialization`] — JSON encoding failed.
    /// - [`BatchError::TooLarge`] — serialized size exceeds `u32::MAX`.
    pub fn serialized_size(&self) -> Result<u32, BatchError> {
        let bytes =
            serde_json::to_vec(self).map_err(|e| BatchError::Serialization(e.to_string()))?;
        u32::try_from(bytes.len()).map_err(|_| BatchError::TooLarge(bytes.len()))
    }

    /// Build a [`TxBatchRef`] that points to this batch.
    ///
    /// The ref carries `{ digest, author, size }` — lightweight enough to
    /// include in a `DagBlock.payload` without bloating the block.
    ///
    /// Serializes the batch **once** and derives both `digest` and `size`
    /// from the same bytes (avoids the double-serialize that calling
    /// [`Self::digest`] + [`Self::serialized_size`] separately would incur in
    /// the hot round-proposal path).
    ///
    /// # Errors
    ///
    /// - [`BatchError::Serialization`] — JSON encoding failed.
    /// - [`BatchError::TooLarge`] — serialized size exceeds `u32::MAX`.
    pub fn to_ref(&self) -> Result<TxBatchRef, BatchError> {
        // Serialize once — derive digest + size from the same bytes.
        let bytes =
            serde_json::to_vec(self).map_err(|e| BatchError::Serialization(e.to_string()))?;
        let digest = hash_bytes(&bytes);
        let size = u32::try_from(bytes.len()).map_err(|_| BatchError::TooLarge(bytes.len()))?;
        Ok(TxBatchRef {
            digest,
            author: self.author,
            size,
        })
    }
}

// ── BatchStore ────────────────────────────────────────────────────────────────

/// In-memory batch pin store: `Hash → Batch`.
///
/// Shared via `Arc<RwLock<...>>` between the DAG driver (writer, pins own
/// batches) and the network runner (writer, pins batches received from peers).
/// [`resolve_committed_txs`] takes a read-lock snapshot.
///
/// Phase 2: no eviction. Phase 3: GC on `Dag::gc_round()` advance
/// (TODO(batch): D·Step 15 — deferred; only meaningful with real peers).
pub type BatchStore = Arc<RwLock<HashMap<Hash, Batch>>>;

/// Construct a fresh, empty [`BatchStore`].
#[must_use]
pub fn new_batch_store() -> BatchStore {
    Arc::new(RwLock::new(HashMap::new()))
}

// ── resolve_committed_txs ─────────────────────────────────────────────────────

/// Resolve a [`Commit`]'s ordered sub-DAG into a deduplicated transaction list.
///
/// ## Algorithm
///
/// 1. Walk `commit.blocks` in `(round ASC, author ASC)` order — the
///    deterministic sub-DAG linearization produced by [`Linearizer`].
/// 2. For each [`DagBlockRef`], look up the full [`DagBlock`] in `dag`.
///    - If not found (GC'ed or suspended): log a warning and skip.
/// 3. For each [`TxBatchRef`] in `block.payload`:
///    - Look up the [`Batch`] by `ref.digest` in `store`.
///    - If not found (availability miss): log a warning, record the miss in
///      `missing`, and skip. The block is still produced with available txs.
/// 4. Extend the output with the batch's `txs`, deduplicating by tx hash
///    (first occurrence wins — deterministic because the sub-DAG order is
///    deterministic).
///
/// ## Determinism
///
/// `commit.blocks` is already sorted `(round ASC, author ASC)` by
/// [`Linearizer`]. Within a batch, tx order is insertion order (also
/// deterministic — the same mempool snapshot). The output is therefore
/// fully deterministic for a given commit across all honest nodes.
///
/// ## Parameters
///
/// - `commit` — the committed sub-DAG (from `SurgeOutput::commits`).
/// - `dag` — the local DAG state (from `SurgeDriver::dag()`).
/// - `store` — the current batch pin store snapshot (caller holds read-lock).
///
/// ## Returns
///
/// `(txs, missing)` where:
/// - `txs` — the deduplicated, ordered transaction list.
/// - `missing` — `(batch_digest, batch_author)` pairs for batches not found
///   in the local store. The caller may use these to trigger fetch-on-miss
///   requests to peers (D·Step 15e). Best-effort: the block is produced with
///   the available txs regardless.
///
/// [`Linearizer`]: lemma_consensus::pulse::linearizer::Linearizer
/// [`DagBlockRef`]: lemma_consensus::dag::block::DagBlockRef
pub fn resolve_committed_txs(
    commit: &Commit,
    dag: &lemma_consensus::dag::graph::Dag,
    store: &HashMap<Hash, Batch>,
) -> (Vec<Transaction>, Vec<(Hash, Address)>) {
    let mut seen: HashSet<Hash> = HashSet::new();
    let mut txs: Vec<Transaction> = Vec::new();
    let mut missing: Vec<(Hash, Address)> = Vec::new();

    for block_ref in &commit.blocks {
        // Look up the full DagBlock — may be missing if GC'ed (rare in Phase 2).
        let Some(dag_block) = dag.block(block_ref) else {
            tracing::warn!(
                round  = block_ref.round,
                author = %block_ref.author,
                digest = %block_ref.digest.to_hex(),
                "resolve_committed_txs: DagBlock not found in local DAG — skipping \
                 (GC'ed or not yet received)"
            );
            continue;
        };

        resolve_block_payload(dag_block, store, &mut seen, &mut txs, &mut missing);
    }

    (txs, missing)
}

/// Resolve one [`DagBlock`]'s payload refs into the output transaction list.
///
/// Extracted as a helper so [`resolve_committed_txs`] stays readable and this
/// path is independently testable.
///
/// `missing` accumulates `(batch_digest, batch_author)` pairs for batches not
/// found in the local store. The caller may use these to trigger fetch-on-miss
/// requests to peers (D·Step 15e). Best-effort: the block is produced with the
/// available txs regardless.
pub(crate) fn resolve_block_payload(
    block: &DagBlock,
    store: &HashMap<Hash, Batch>,
    seen: &mut HashSet<Hash>,
    out: &mut Vec<Transaction>,
    missing: &mut Vec<(Hash, Address)>,
) {
    for batch_ref in &block.payload {
        let Some(batch) = store.get(&batch_ref.digest) else {
            tracing::warn!(
                digest = %batch_ref.digest.to_hex(),
                author = %batch_ref.author,
                size   = batch_ref.size,
                "resolve_committed_txs: batch not in store — availability miss \
                 (fetch-on-miss: D·Step 15e)"
            );
            // Record the miss so the caller can trigger a fetch-on-miss request.
            missing.push((batch_ref.digest, batch_ref.author));
            continue;
        };

        for tx in &batch.txs {
            // Dedup by tx hash — first occurrence in sub-DAG order wins.
            if seen.insert(tx.hash) {
                out.push(tx.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests;
