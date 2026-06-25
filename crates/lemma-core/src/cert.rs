//! Quorum certificate — the 2f+1 voting-power commit record.
//!
//! A [`QuorumCert`] serves two roles in Lemma. Both use the same type and the
//! same `verify_quorum_cert` function (signers all signed the same digest):
//!
//! ## Role 1 — Commit-certificate (DB-A15b, `docs/12-NETWORK_SYNC_SPEC §3`)
//!
//! After Pulse decides a leader and the chain [`Block`](crate::block::Block) is
//! produced, ≥ 2f+1 validators sign the chain `BlockHeader.digest()` at commit
//! time. This is the **commit-certificate** — a post-decision signing step,
//! entirely separate from DAG block propagation (which is uncertified per
//! `docs/07-CONSENSUS_SPEC §1`). The assembled cert is stored as
//! `Block.quorum_cert: Option<QuorumCert>`.
//!
//! In Phase 2 (single-node), the QC has one signer (the local proposer with
//! 100% stake — satisfies 2f+1 trivially). Phase 3+: accumulate 2f+1 signers
//! from commit-acknowledgment gossip.
//!
//! ## Role 2 — Recovery authorization (`lemma-consensus::epoch::recovery`)
//!
//! `force_epoch_close` uses a `QuorumCert` to authorize a governance-driven
//! epoch recovery. Signers explicitly sign a recovery message digest. The same
//! `verify_quorum_cert` function applies (signers sign `recovery_cert_digest`).
//!
//! ## Shared infrastructure
//!
//! - `lemma-consensus` — verify epoch-change proofs (§4.4, B4) + recovery.
//! - `lemma-network` — propagate finality evidence (`NetworkError::InvalidQuorumCert`).
//!
//! # Why in `lemma-core`
//!
//! `lemma-network` depends only on `lemma-core` (build order: network comes
//! before consensus — see `docs/04-BUILD_GUIDE §7`). Shared blockchain types
//! belong in `lemma-core` (AGENTS.md §2.4). Verification logic (requiring
//! `StakeAggregator` from `lemma-consensus`) stays in `lemma-consensus`.
//!
//! # Determinism
//!
//! `signers` is a `BTreeMap<Address, Signature>` — deterministic iteration
//! order (AGENTS.md §7.1). No `HashMap`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{address::Address, hash::Hash, signature::Signature};

// ─── QuorumCert ───────────────────────────────────────────────────────────────

/// A 2f+1 voting-power quorum certificate over a block header.
///
/// Produced by the Pulse commit rule when a leader block accumulates ≥ 2/3
/// voting-power in valid signatures. This is the finality anchor that:
/// - Proves a block is final (no forks possible under BFT with < f Byzantine).
/// - Enables light-client verification (`docs/12-NETWORK_SYNC_SPEC §3.2`).
/// - Forms the epoch-change proof chain (`docs/13-VALIDATOR_EPOCH_SPEC §4.4`).
///
/// Equivalent to CometBFT `Commit`, Sui `CertifiedCheckpointSummary`,
/// Aptos `LedgerInfoWithSignatures`.
///
/// ## Verification
///
/// Call `lemma_consensus::cert::verify_quorum_cert` to verify the cert
/// against a [`ValidatorSet`](crate::ValidatorSet). Signature verification
/// uses the hybrid Ed25519+ML-DSA scheme (`lemma-crypto`) and is injected
/// as a `BTreeMap<Address, bool>` per the B3-2 pattern.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCert {
    /// Block height this certificate covers.
    pub height: u64,

    /// Blake3 canonical digest of the certified
    /// [`BlockHeader`](crate::BlockHeader), computed via
    /// [`BlockHeader::digest`](crate::BlockHeader::digest).
    ///
    /// This is the hand-framed canonical digest (explicit field order,
    /// big-endian integers, length-prefixed `extra_data`) — NOT a serde/bincode
    /// hash. It is the value validators sign at commit time
    /// (`docs/12-NETWORK_SYNC_SPEC §3.2`, contract `qc.header_digest ==
    /// header.digest()`). `lemma-consensus` does not compute it directly
    /// (sig injection pattern, B3-2).
    pub header_digest: Hash,

    /// Per-signer signatures, keyed by validator operator address.
    ///
    /// `BTreeMap` for deterministic iteration (AGENTS.md §7.1). In a
    /// valid cert, all entries satisfy:
    /// - The signer is a member of the committee for this epoch.
    /// - The signature is valid over the domain-separated message
    ///   `blake3(b"commit-ack" || height_le_u64 || header_digest)`,
    ///   computed by `lemma_consensus::commit_ack::commit_ack_message`.
    ///   This is the canonical signed message for ALL QC signers — both
    ///   the initial single-signer QC and multi-signer QCs from gossip
    ///   (P4·Step 9, AGENTS §7.3 domain separation).
    ///
    /// The verification of both conditions is performed by
    /// `lemma_consensus::cert::verify_quorum_cert` with injected results.
    pub signers: BTreeMap<Address, Signature>,
}

impl QuorumCert {
    /// Create a new quorum certificate.
    ///
    /// No validation is performed here — use
    /// `lemma_consensus::cert::verify_quorum_cert` to verify the cert
    /// against a validator set.
    #[must_use]
    pub fn new(height: u64, header_digest: Hash, signers: BTreeMap<Address, Signature>) -> Self {
        Self {
            height,
            header_digest,
            signers,
        }
    }

    /// Return the number of distinct signers in this certificate.
    ///
    /// **Note:** signer count carries no quorum semantics — quorum is
    /// stake-weighted, not count-based. Use
    /// `lemma_consensus::cert::verify_quorum_cert` for authoritative
    /// quorum checks.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
