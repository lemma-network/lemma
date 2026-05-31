//! NetworkError — typed errors for the `lemma-network` crate.
//!
//! All message handlers, decoders, and sync steps return `Result<_, NetworkError>`
//! and **never** `unwrap()` / `panic!()` on peer-supplied input
//! (12-NETWORK_SYNC_SPEC §1.2, AGENTS.md §7.2). A malformed packet, an oversized
//! response, or an invalid block drops the message and demotes the peer — it
//! never crashes the process.
//!
//! ## Special variant: `Equivocation`
//!
//! `Equivocation` is not merely an error — it is an **attack signal**. Under
//! Lemma's deterministic absolute finality two valid quorum certificates at the
//! same height is impossible in an honest network. Callers MUST treat this as a
//! trigger to:
//! 1. Emit slashable evidence (13-VALIDATOR_EPOCH_SPEC).
//! 2. Cross-check secondary peers and replace the primary on conflict
//!    (12-NETWORK_SYNC_SPEC §3.5).
//!
//! Note: the `Equivocation` variant will gain a `conflicting_cert` field once
//! `lemma-consensus` defines `QuorumCert` (blocked on 13-VALIDATOR_EPOCH_SPEC).
//! See the variant doc comment below.
//!
//! See `12-NETWORK_SYNC_SPEC.md §6` for the authoritative variant specification.

use libp2p::PeerId;
use thiserror::Error;

use lemma_core::Hash;

/// Typed errors for `lemma-network`.
///
/// Every variant carries structured context (peer identity, height, size) so
/// callers can log, demote peers, and retry without re-parsing a string
/// (AGENTS.md §12.2: errors must be informative and actionable).
///
/// `#[non_exhaustive]` allows adding new variants in future minor releases
/// without breaking downstream `match` arms (AGENTS.md §4.3).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NetworkError {
    // ── Block / sync validation ───────────────────────────────────────────

    /// A peer served a block that failed internal validation (bad signature,
    /// structural invariant violation, or hash mismatch). The peer MUST be
    /// demoted via the app-specific gossipsub score (12-NETWORK_SYNC_SPEC §5).
    #[error("peer {peer} served an invalid block at height {height}")]
    InvalidBlock { peer: PeerId, height: u64 },

    /// A quorum certificate failed the 2f+1 voting-power threshold check at
    /// the given height. The serving peer is demoted; the block is discarded.
    #[error("quorum certificate failed verification at height {height}")]
    InvalidQuorumCert { height: u64 },

    /// A state chunk failed its Blake3 Merkle range proof against the anchored
    /// `state_root`. The serving peer is demoted and the chunk is re-requested
    /// from a different peer (12-NETWORK_SYNC_SPEC §4.2).
    ///
    /// `root` is the anchored state root the chunk was verified against — the
    /// one committed in a 2f+1-certified header (not the peer's claimed root).
    ///
    /// # Cosmos pitfall (explicit negative test)
    ///
    /// A tampered chunk MUST be caught immediately on arrival, not after a full
    /// download. The per-chunk Blake3 range proof is the structural guard.
    #[error("state chunk failed range proof against root {root}")]
    InvalidStateChunk { root: Hash },

    // ── Bounds / DoS hardening ────────────────────────────────────────────

    /// A peer's response body exceeded the configured byte limit. The response
    /// is dropped without processing to prevent memory exhaustion
    /// (12-NETWORK_SYNC_SPEC §2.2, AGENTS.md §15.2).
    #[error("response exceeded size limit: {got} > {max} bytes")]
    ResponseTooLarge { got: usize, max: usize },

    /// A range request spans more blocks than the configured maximum. Rejected
    /// before dispatch to prevent O(n) memory allocation on the responder
    /// (12-NETWORK_SYNC_SPEC §2.2).
    #[error("range request too wide: {got} > {max} blocks")]
    RangeTooWide { got: u64, max: u64 },

    // ── Light client errors ───────────────────────────────────────────────

    /// A light block falls outside the configured trusting period. Expired
    /// headers are rejected to bound long-range attacks where exited validators
    /// sign a fork with retired keys (12-NETWORK_SYNC_SPEC §3.5).
    #[error("light block outside trusting period (height {height})")]
    Expired { height: u64 },

    /// Two valid quorum certificates exist for the same finalized height.
    ///
    /// Under Lemma's absolute finality this is an **attack, not a reorg**
    /// (12-NETWORK_SYNC_SPEC §0, §3.5). Callers MUST:
    /// 1. Emit slashable evidence (13-VALIDATOR_EPOCH_SPEC).
    /// 2. Cross-check secondary peers and replace the primary on conflict.
    ///
    /// Use [`NetworkError::is_attack_signal`] to distinguish this from routine
    /// demotion cases before deciding how to handle the error.
    ///
    /// # Pending field
    ///
    /// `conflicting_cert` (the second QC — the slashing evidence payload) will
    /// be added here once `lemma-consensus` defines `QuorumCert`.
    /// TODO(network): attach `conflicting_cert: Box<QuorumCert>` — blocked on
    /// 13-VALIDATOR_EPOCH_SPEC landing and `QuorumCert` being defined.
    #[error("equivocation detected at height {height}")]
    Equivocation { height: u64 },

    // ── Connection / transport ────────────────────────────────────────────

    /// A request-response call to a specific peer timed out before a response
    /// arrived. The sync layer retries against a different peer.
    #[error("request to peer {peer} timed out")]
    Timeout { peer: PeerId },

    /// A low-level transport error from the libp2p stack (TCP, Noise, Yamux,
    /// or libp2p-internal protocol errors).
    ///
    /// The inner `Box<dyn Error>` preserves the full source chain so structured
    /// logging and `anyhow` context propagation can inspect the root cause.
    /// `#[source]` delegates `.source()` to the inner error for chain traversal.
    #[error("transport error: {0}")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    // ── Gossipsub errors ──────────────────────────────────────────────────

    /// Failed to subscribe to a gossipsub topic. This is a configuration or
    /// behaviour-lifecycle error, not peer misbehaviour.
    #[error("failed to subscribe to gossipsub topic '{topic}'")]
    Subscribe { topic: String },

    /// Failed to publish a message to a gossipsub topic (e.g. no peers on the
    /// mesh, or the behaviour rejected the message).
    #[error("failed to publish to topic '{topic}': {reason}")]
    Publish { topic: String, reason: String },

    // ── Generic peer input validation ─────────────────────────────────────

    /// A wire message from a peer failed to deserialize or violated a
    /// structural invariant. The message is dropped; the peer is demoted.
    ///
    /// This variant exists specifically to avoid `unwrap()` / `panic!()` on
    /// crafted wire input — a panic triggered by a malformed packet is a remote
    /// crash (12-NETWORK_SYNC_SPEC §1.2, AGENTS.md §7.2).
    #[error("invalid message from peer {peer}: {reason}")]
    InvalidMessage { peer: PeerId, reason: String },
}

impl NetworkError {
    /// Construct a [`NetworkError::Transport`] from any error type.
    ///
    /// Convenience constructor since `Transport` holds a boxed trait object
    /// (preserving the source chain) rather than a plain `String`.
    pub fn transport(e: impl std::error::Error + Send + Sync + 'static) -> Self {
        NetworkError::Transport(Box::new(e))
    }

    /// Returns `true` if this error represents an **attack signal** requiring
    /// slashable evidence emission rather than routine peer demotion.
    ///
    /// Currently only [`NetworkError::Equivocation`] qualifies. Callers MUST
    /// check this before logging the error as a routine demotion event.
    pub fn is_attack_signal(&self) -> bool {
        matches!(self, NetworkError::Equivocation { .. })
    }

    /// Returns `true` if this error indicates **peer misbehaviour** — i.e. the
    /// peer served data that failed cryptographic or structural verification.
    ///
    /// Callers use this to decide whether to feed a negative score into the
    /// gossipsub app-specific peer scorer (12-NETWORK_SYNC_SPEC §5).
    pub fn is_peer_misbehaviour(&self) -> bool {
        matches!(
            self,
            NetworkError::InvalidBlock { .. }
                | NetworkError::InvalidQuorumCert { .. }
                | NetworkError::InvalidStateChunk { .. }
                | NetworkError::InvalidMessage { .. }
                | NetworkError::Equivocation { .. }
        )
    }

    /// Returns `true` if this error is a **bounds / resource-exhaustion**
    /// guard. These are dropped silently (no peer score penalty) unless the
    /// peer repeatedly triggers them (DoS pattern).
    pub fn is_bounds_violation(&self) -> bool {
        matches!(
            self,
            NetworkError::ResponseTooLarge { .. } | NetworkError::RangeTooWide { .. }
        )
    }
}

#[cfg(test)]
mod tests;
