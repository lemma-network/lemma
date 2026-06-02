//! Range-sync consumer primitives (Phase 1 — structural verification).
//!
//! ## Scope
//!
//! This module provides the building blocks for a lagging node to catch up
//! to the network tip by pulling and applying a range of missing blocks:
//!
//! | Primitive | Role |
//! |-----------|------|
//! | [`BlockVerifier`] | Trait — one impl per phase. Seam for Phase 2 QC verify. |
//! | [`StructuralVerifier`] | Phase 1 impl — real structural integrity checks |
//! | [`SyncTracker`] | Detects gaps; decides when/what to request |
//! | [`apply_synced_block`] | Verify + write under shared write-lock |
//! | [`compute_block_hash`] | Canonical hash convention (same as producer) |
//! | [`ApplyOutcome`] | Result of one apply attempt |
//!
//! ## Phase 1 verification scope
//!
//! [`StructuralVerifier`] performs **real verification** — it catches data
//! corruption, truncation, reordering, and byte-flips from a malicious
//! transport peer. It does NOT verify the QuorumCert (which doesn't exist on
//! Phase-1 blocks). This matches the Phase-1 threat model: one producer, no
//! forks, no Byzantine proposer yet. Real structural integrity protects against
//! a dishonest *transport*.
//!
//! ## Phase 2 hook (QC verification)
//!
//! In Phase 2 (DAG consensus), blocks carry a `QuorumCert` (2f+1 validator
//! signatures). The QC check is added as a second impl of `BlockVerifier`
//! (`CertifiedVerifier`) — the `apply_synced_block` call-site receives a
//! different impl, no other code changes.
//!
//! Per AGENTS.md §1.7: this is a deliberate, recorded gap — not dead code.
//! See `living-notes.md` Technical Debt: "QC verification — blocked on
//! Phase-2 certified blocks."
//!
//! **Why NOT a no-op QC stub**: a stub that returns `Ok(())` while claiming
//! to "verify" is misleading code (AGENTS.md §17). The QC verifier is simply
//! absent in Phase 1; the trait seam makes it additive in Phase 2.
//!
//! ## Write-lock contract
//!
//! `apply_synced_block` is a second `put_block` writer alongside the producer.
//! Both acquire `write_lock: &Mutex<()>` before calling `put_block`
//! (per `chain.rs` §Tip race under concurrent writers).
//! The lock is held only for the duration of one RocksDB write batch — fast.

use std::sync::Arc;

use tokio::sync::Mutex;
use tracing::warn;

use lemma_core::{
    block::Block,
    error::BlockError,
    hash::Hash,
};
use lemma_storage::{chain::ChainStore, db::LemmaDb};

use crate::error::NodeError;

// ── VerifyError ───────────────────────────────────────────────────────────────

/// Typed errors from [`BlockVerifier::verify`].
///
/// Each variant corresponds to exactly one structural check so callers can
/// report precisely which invariant a peer violated. Used for peer demotions
/// and debug logging.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// Intra-block invariants failed (gas, receipts, header constraints).
    ///
    /// Indicates the block itself is internally inconsistent — could be
    /// corruption or a malicious peer assembling an invalid block.
    #[error("intra-block validation failed: {0}")]
    BlockInvalid(#[from] BlockError),

    /// The block's `parent_hash` does not link to our current tip.
    ///
    /// For a sequential sync range, this is either out-of-order delivery
    /// or a peer serving the wrong chain.
    #[error("parent_hash mismatch: expected {expected}, got {got}")]
    ParentHashMismatch { expected: Hash, got: Hash },

    /// The block's height is not exactly `prev_height + 1`.
    ///
    /// Catches a peer that skips heights or serves a block for the wrong slot.
    #[error("height mismatch: expected {expected}, got {got}")]
    HeightMismatch { expected: u64, got: u64 },

    /// The block's serialized hash does not match the expected hash.
    ///
    /// Catches byte-level corruption or tampering during transport.
    #[error("hash mismatch: computed {computed}, got {got}")]
    HashMismatch { computed: Hash, got: Hash },

    /// `prev_height + 1` overflowed `u64`.
    ///
    /// Unreachable in any realistic chain, but must not panic.
    #[error("block height overflowed u64 (prev_height = {prev_height})")]
    HeightOverflow { prev_height: u64 },

    /// `bincode::serialize` failed on a well-formed block.
    ///
    /// Indicates a programming error (a valid Rust `Block` should always
    /// serialize). Logged as an internal error, not peer misbehaviour.
    #[error("block serialization failed during hash verification: {reason}")]
    Serialization { reason: String },
}

// ── BlockVerifier trait ───────────────────────────────────────────────────────

/// Verify a block before applying it to the local chain.
///
/// The trait is the seam between Phase-1 structural verification and Phase-2
/// QC certificate verification. The apply path ([`apply_synced_block`]) is
/// generic over this trait — Phase 2 swaps the impl, no other changes needed.
///
/// ## Implementors
///
/// | Impl | Phase | Checks |
/// |------|-------|--------|
/// | [`StructuralVerifier`] | Phase 1 | intra-block, parent_hash, height, hash |
/// | `CertifiedVerifier` (Phase 2) | Phase 2 | above + QuorumCert 2f+1 signatures |
///
/// ## Contract
///
/// - Returns the **computed block hash** on success — the hash the caller must
///   pass to `ChainStore::put_block`. Computing it here (as part of the hash
///   self-consistency check) avoids a second serialization in the write path.
/// - `prev_hash` and `prev_height` are the **current local tip** values,
///   verified outside the write-lock. Callers double-check the tip under the
///   lock before writing (see [`apply_synced_block`]).
pub trait BlockVerifier: Send + Sync {
    /// Verify `block` against the current tip (`prev_hash`, `prev_height`).
    ///
    /// # Returns
    ///
    /// The computed `Hash` of `block` (for use in `put_block`) on success.
    ///
    /// # Errors
    ///
    /// Returns a [`VerifyError`] variant describing the first failed check.
    fn verify(
        &self,
        block: &Block,
        prev_hash: Hash,
        prev_height: u64,
    ) -> Result<Hash, VerifyError>;
}

// ── StructuralVerifier ────────────────────────────────────────────────────────

/// Phase-1 block verifier — structural integrity only, no QC.
///
/// Performs four checks in order (cheap → more expensive):
///
/// 1. **Height continuity** — `block.height() == prev_height + 1`.
/// 2. **Parent linkage** — `block.header.parent_hash == prev_hash`.
/// 3. **Intra-block consistency** — delegates to [`Block::validate`]
///    (gas accounting, receipt count, header constraints).
/// 4. **Hash self-consistency** — recomputes `hash_bytes(serialize(block))`
///    and checks it matches the claimed hash.
///
/// These checks have real teeth: they catch corruption, truncation,
/// reordering, and byte-flipping by a malicious transport peer. They do NOT
/// check a QuorumCert — that check is absent (not no-op) until Phase 2.
///
/// ## Why the order matters
///
/// Height and parent checks are O(1) and detect the most common peer errors
/// (serving the wrong range, wrong chain) early. Intra-block validation runs
/// before hash recomputation to avoid paying the serialization cost on an
/// obviously invalid block.
pub struct StructuralVerifier;

impl BlockVerifier for StructuralVerifier {
    fn verify(
        &self,
        block: &Block,
        prev_hash: Hash,
        prev_height: u64,
    ) -> Result<Hash, VerifyError> {
        // ── Check 1: height continuity ────────────────────────────────────────
        let expected_height = prev_height
            .checked_add(1)
            .ok_or(VerifyError::HeightOverflow { prev_height })?;
        if block.height() != expected_height {
            return Err(VerifyError::HeightMismatch {
                expected: expected_height,
                got: block.height(),
            });
        }

        // ── Check 2: parent linkage ───────────────────────────────────────────
        if block.header.parent_hash != prev_hash {
            return Err(VerifyError::ParentHashMismatch {
                expected: prev_hash,
                got: block.header.parent_hash,
            });
        }

        // ── Check 3: intra-block consistency ──────────────────────────────────
        block.validate()?;

        // ── Check 4: hash self-consistency ────────────────────────────────────
        let computed = compute_block_hash(block)?;

        // Note: we return the computed hash so the caller doesn't serialize
        // twice. There is no "expected hash" parameter here — the hash IS
        // the identity of the block (content-addressed), so computing it IS
        // the check. The caller uses it as the key for put_block.
        Ok(computed)
    }
}

// ── SyncTracker ───────────────────────────────────────────────────────────────

/// Tracks the highest-seen peer height and controls range-request issuance.
///
/// Owned by the `run_network_dispatch` loop (single task, no locking needed).
/// Updated on every `BlockReceived` event regardless of whether the block is
/// applied. Prevents duplicate range requests via `requested_up_to` watermark.
#[derive(Debug)]
pub struct SyncTracker {
    /// The highest block height seen from any peer (gossip or range response).
    pub highest_seen: u64,

    /// The highest height included in the most recent `RequestRange` issued.
    ///
    /// Used to prevent re-requesting a range that's already in flight.
    /// Reset to `local_tip` when a gap is closed (all requested blocks applied).
    requested_up_to: u64,

    /// The peer that announced the most recently observed height.
    ///
    /// Used by the sync-retry tick to re-issue a range request when no new
    /// `BlockReceived` event arrives (handles partial responses and stalls).
    /// Phase 2 will replace this with a scored peer selector.
    last_peer: Option<libp2p::PeerId>,
}

impl SyncTracker {
    /// Create a new tracker with no peers seen.
    pub fn new() -> Self {
        SyncTracker { highest_seen: 0, requested_up_to: 0, last_peer: None }
    }

    /// Record a new observation from a peer.
    ///
    /// Updates `highest_seen` if `height` is greater than the current value.
    /// Also records `peer` as the `last_seen_peer` for retry use.
    pub fn observe(&mut self, height: u64, peer: libp2p::PeerId) {
        if height > self.highest_seen {
            self.highest_seen = height;
            self.last_peer = Some(peer);
        } else if self.last_peer.is_none() {
            self.last_peer = Some(peer);
        }
    }

    /// Returns the peer that last announced a new high-water height, if any.
    ///
    /// Used by the sync-retry tick to direct follow-up range requests.
    pub fn last_seen_peer(&self) -> Option<libp2p::PeerId> {
        self.last_peer
    }

    /// Compute the next range to request, if a gap exists.
    ///
    /// Returns `Some((from, to))` when `highest_seen > local_tip + 1` AND the
    /// range hasn't already been requested (`highest_seen > requested_up_to`).
    /// Chunks the request to `max_range` blocks at most (per-request bound).
    ///
    /// `max_range` should be `lemma_network::config::DEFAULT_MAX_RANGE`.
    ///
    /// Advances `requested_up_to` to `to` so the same range isn't re-issued.
    ///
    /// Returns `None` when already up-to-date or when the gap was already
    /// requested and is in flight.
    pub fn next_request(
        &mut self,
        local_tip: u64,
        max_range: u64,
    ) -> Option<(u64, u64)> {
        // Nothing to do if we're at or ahead of the network tip.
        // saturating_add: tip overflow is unreachable but AGENTS §7.4 bans bare + 1.
        if self.highest_seen <= local_tip.saturating_add(1) {
            return None;
        }
        // Don't re-request a range already issued.
        if self.highest_seen <= self.requested_up_to {
            return None;
        }
        let from = local_tip.saturating_add(1);
        // Clamp to max_range and to highest_seen.
        let to = self.highest_seen.min(local_tip.saturating_add(max_range));
        self.requested_up_to = to;
        Some((from, to))
    }

    /// Reset the `requested_up_to` watermark to `local_tip`.
    ///
    /// Call when the local tip advances past `requested_up_to` so the next
    /// gap (if any) can issue a fresh request. This prevents the tracker from
    /// permanently suppressing requests after a successful sync.
    pub fn on_tip_advanced(&mut self, local_tip: u64) {
        if local_tip >= self.requested_up_to {
            self.requested_up_to = local_tip;
        }
    }
}

impl Default for SyncTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ── apply_synced_block ────────────────────────────────────────────────────────

/// Outcome of a single [`apply_synced_block`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Block verified and written; tip advanced to `height`.
    Applied { height: u64, hash: Hash },

    /// The local tip advanced (producer wrote a block) between the structural
    /// verify and the write. The block is not applied; the caller should
    /// re-check whether the block is still needed.
    Stale,

    /// The local chain has no tip yet (genesis not written). Should not
    /// occur in normal Phase-1 operation but is handled gracefully.
    NoTip,
}

/// Verify `block` against the local tip and write it to the chain store.
///
/// ## Steps
///
/// 1. Read the local tip (outside the write-lock — read-only).
/// 2. Call `verifier.verify(block, prev_hash, prev_height)` — structural checks.
/// 3. Acquire `write_lock` (serializes with the producer's `commit_block`).
/// 4. **Double-check**: re-read the tip under the lock to detect concurrent
///    advancement by the producer. Return [`ApplyOutcome::Stale`] if the tip
///    moved while we were verifying.
/// 5. Write via `ChainStore::put_block`.
///
/// ## Error policy
///
/// `VerifyError` is returned as `NodeError::Verify` — the caller logs and
/// discards the block; it can re-request from a different peer.
/// Storage errors (`NodeError::Storage`, `NodeError::Block`) propagate as
/// fatal — a failed write means chain integrity is compromised.
///
/// ## Write-lock contract
///
/// Both this function and `producer::commit_block` must acquire the same
/// `write_lock` before calling `put_block`. See `chain.rs` §Tip race.
pub async fn apply_synced_block(
    block: &Block,
    db: &Arc<LemmaDb>,
    write_lock: &Arc<Mutex<()>>,
    verifier: &dyn BlockVerifier,
) -> Result<ApplyOutcome, NodeError> {
    // ── Step 1: read tip (outside lock) ──────────────────────────────────────
    let tip = ChainStore::new(db).tip()?;
    let (prev_height, prev_hash) = match tip {
        Some((h, hash)) => (h, hash),
        None => return Ok(ApplyOutcome::NoTip),
    };

    // ── Step 2: structural verify (outside lock — no writes) ─────────────────
    let computed_hash = match verifier.verify(block, prev_hash, prev_height) {
        Ok(hash) => hash,
        Err(e) => {
            // Structural failure — not a fatal node error; log at warn, let
            // the caller discard and potentially demote the peer.
            warn!(
                height = block.height(),
                error  = %e,
                "structural verify failed — block discarded"
            );
            return Err(NodeError::Verify(e.to_string()));
        }
    };

    // ── Step 3: acquire write-lock ────────────────────────────────────────────
    let _guard = write_lock.lock().await;

    // ── Step 4: double-check tip under lock ───────────────────────────────────
    // The producer may have advanced the tip while we were verifying.
    // If so, bail — the block is stale (or already written).
    let tip_now = ChainStore::new(db).tip()?;
    if tip_now.map(|(h, _)| h) != Some(prev_height) {
        return Ok(ApplyOutcome::Stale);
    }

    // ── Step 5: write ─────────────────────────────────────────────────────────
    ChainStore::new(db).put_block(block, computed_hash)?;
    Ok(ApplyOutcome::Applied { height: block.height(), hash: computed_hash })
}

// ── compute_block_hash ────────────────────────────────────────────────────────

/// Compute the canonical hash of `block`.
///
/// Uses `bincode::serialize` + `lemma_crypto::hash_bytes` — the same
/// convention as the block producer (`producer.rs:168`). This is the only
/// canonical hash path; all block-hash derivations must use this function
/// (AGENTS.md §2.2: one canonical hash function).
///
/// # Errors
///
/// Returns [`VerifyError::Serialization`] if `bincode::serialize` fails. In
/// practice this should never happen for a well-formed `Block`.
pub fn compute_block_hash(block: &Block) -> Result<Hash, VerifyError> {
    bincode::serialize(block)
        .map(|bytes| lemma_crypto::hash_bytes(&bytes))
        .map_err(|e| VerifyError::Serialization { reason: e.to_string() })
}

#[cfg(test)]
mod tests;
