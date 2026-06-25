//! Commit-acknowledgement gossip payload and accumulator (P4·Step 9).
//!
//! ## Protocol
//!
//! After a validator commits a chain block, it:
//! 1. Signs the canonical `BlockHeader::digest()` with domain separation:
//!    `blake3(b"commit-ack" || height_le_u64 || header_digest)`.
//! 2. Broadcasts a [`CommitAckPayload`] on `lemma/commit-ack/1`.
//!
//! Peers accumulate acks in a [`CommitAckAccumulator`]. When ≥ 2f+1 stake is
//! reached, the accumulator produces a [`QuorumCert`] with all signers.
//!
//! ## Domain separation (AGENTS §7.3)
//!
//! The signed message is `blake3(b"commit-ack" || height_le_u64 || header_digest)`.
//! The `b"commit-ack"` prefix prevents cross-message replay — a signature over
//! a `CommitAckPayload` cannot be replayed as a `DagBlock` signature or a
//! `BlockHeader` signature (which signs `header_digest` directly without the
//! prefix).
//!
//! ## Signature injection (B3-2 pattern)
//!
//! [`CommitAckAccumulator::add`] accepts a pre-verified `sig_ok: bool` rather
//! than calling `lemma-crypto` directly. The node layer (`lemma-node`) performs
//! the hybrid Ed25519+ML-DSA-65 verification and injects the result. This keeps
//! `lemma-consensus` crypto-free (AGENTS §8 build-order).
//!
//! ## Single-validator fast-path
//!
//! In single-validator mode (1 validator = 100% stake), the validator's own
//! `CommitAck` immediately satisfies 2f+1 (100% > 2/3). No special case is
//! needed — the stake math handles it.
//!
//! ## Determinism (AGENTS §7.1)
//!
//! [`CommitAckAccumulator`] wraps [`StakeAggregator`] (which uses `BTreeSet`
//! for counted authors). The resulting [`QuorumCert`] uses `BTreeMap<Address,
//! Signature>` for deterministic signer ordering.

use std::collections::BTreeMap;

use blake3::Hasher;
use serde::{Deserialize, Serialize};

use lemma_core::{
    address::Address, amount::Amount, cert::QuorumCert, hash::Hash, signature::Signature,
    validator_set::ValidatorSet,
};

use crate::{error::ConsensusError, stake::StakeAggregator};

// ── Domain-separation constant ────────────────────────────────────────────────

/// Domain-separation prefix for commit-ack signatures.
///
/// Signed message: `blake3(COMMIT_ACK_DOMAIN || height_le_u64 || header_digest)`.
/// Prevents cross-message replay (AGENTS §7.3).
const COMMIT_ACK_DOMAIN: &[u8] = b"commit-ack";

// ── CommitAckPayload ──────────────────────────────────────────────────────────

/// A validator's signed acknowledgement that it has observed and verified a
/// committed block.
///
/// ## Wire format
///
/// JSON-encoded, wrapped in `GossipMessage::CommitAck(Vec<u8>)` for gossip
/// transport. The network layer treats the bytes as opaque (AGENTS §8
/// build-order: `lemma-network` does not depend on `lemma-consensus`).
///
/// ## Signature
///
/// The signer signs the domain-separated message:
/// `blake3(b"commit-ack" || height.to_le_bytes() || header_digest.as_bytes())`
///
/// This prevents cross-message replay (AGENTS §7.3). The signature is a
/// hybrid Ed25519+ML-DSA-65 [`Signature::Hybrid`] produced by
/// `KeyPair::sign_to_lemma(commit_ack_message(height, header_digest))`.
///
/// ## Verification
///
/// The node layer verifies the signature via `lemma_crypto::verify` and injects
/// `sig_ok: bool` into [`CommitAckAccumulator::add`] (B3-2 pattern).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitAckPayload {
    /// Block height this ack applies to.
    pub height: u64,

    /// Canonical `BlockHeader::digest()` of the committed block.
    ///
    /// This is the hand-framed Blake3 digest (explicit field order, big-endian
    /// integers, length-prefixed `extra_data`) — NOT a serde/bincode hash.
    /// `docs/12-NETWORK_SYNC_SPEC §3.2`, contract `qc.header_digest == header.digest()`.
    pub header_digest: Hash,

    /// Signing validator's operator address.
    pub signer: Address,

    /// Hybrid Ed25519+ML-DSA-65 signature over the domain-separated message:
    /// `blake3(b"commit-ack" || height.to_le_bytes() || header_digest.as_bytes())`.
    pub signature: Signature,
}

// ── commit_ack_message ────────────────────────────────────────────────────────

/// Compute the domain-separated message that validators sign for a commit-ack.
///
/// Message: `blake3(b"commit-ack" || height.to_le_bytes() || header_digest.as_bytes())`
///
/// ## Why domain separation?
///
/// Without the `b"commit-ack"` prefix, a signature over `header_digest` could
/// be replayed as a `CommitAck` for a block at any height that happens to have
/// the same digest — a cross-message replay attack (AGENTS §7.3).
///
/// ## Why blake3 over the concatenation?
///
/// The raw concatenation `height_le_u64 || header_digest` is 40 bytes with a
/// fixed-length prefix, so length-extension attacks do not apply. However,
/// hashing the domain-separated message is the canonical pattern in this
/// codebase (consistent with `BlockHeader::digest()` and `DagBlock` signing).
#[must_use]
pub fn commit_ack_message(height: u64, header_digest: &Hash) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(COMMIT_ACK_DOMAIN);
    hasher.update(&height.to_le_bytes());
    hasher.update(header_digest.as_bytes());
    *hasher.finalize().as_bytes()
}

// ── CommitAckError ────────────────────────────────────────────────────────────

/// Errors produced by [`CommitAckAccumulator`].
///
/// All variants are non-fatal from the node's perspective — invalid acks are
/// logged and dropped; the accumulator continues accepting valid acks.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitAckError {
    /// The ack covers a different height than this accumulator.
    ///
    /// Each accumulator is keyed to a specific `(height, header_digest)` pair.
    /// An ack for a different height is either stale or from a future block.
    #[error(
        "commit-ack height mismatch: accumulator is for height {expected}, \
         ack is for height {got}"
    )]
    HeightMismatch {
        /// The height this accumulator is tracking.
        expected: u64,
        /// The height in the received ack.
        got: u64,
    },

    /// The ack covers a different header digest than this accumulator.
    ///
    /// This may indicate a fork attempt or a stale ack from a previous epoch.
    #[error(
        "commit-ack digest mismatch: accumulator covers {expected}, \
         ack covers {got}"
    )]
    DigestMismatch {
        /// The header digest this accumulator is tracking.
        expected: Hash,
        /// The header digest in the received ack.
        got: Hash,
    },

    /// The signer is not a member of the current validator set.
    ///
    /// Non-member acks cannot contribute to quorum. This may indicate a stale
    /// ack from a previous epoch or a forged ack.
    #[error("commit-ack signer {signer} is not in the validator set")]
    UnknownSigner {
        /// The address that is not in the committee.
        signer: Address,
    },

    /// The ack's signature failed verification (injected as `sig_ok = false`).
    ///
    /// The node layer verified the hybrid Ed25519+ML-DSA-65 signature and
    /// reported failure. The ack is dropped.
    #[error("commit-ack signature invalid for signer {signer}")]
    InvalidSignature {
        /// The address whose signature failed.
        signer: Address,
    },

    /// The signer already submitted a valid ack for this block.
    ///
    /// Idempotency guard: the second ack is silently dropped (same as
    /// [`StakeAggregator`]'s idempotency per author). This is not an error
    /// in the BFT sense — it may be a gossip duplicate.
    #[error("commit-ack equivocation: signer {signer} already submitted an ack for this block")]
    Equivocation {
        /// The address that submitted a duplicate ack.
        signer: Address,
    },

    /// Stake arithmetic overflow accumulating signer power.
    ///
    /// Practically unreachable — requires total stake near `u128::MAX`.
    #[error("stake overflow accumulating commit-ack signers: {source}")]
    StakeOverflow {
        /// Underlying consensus error.
        #[source]
        source: ConsensusError,
    },
}

// ── CommitAckAccumulator ──────────────────────────────────────────────────────

/// Accumulates commit-acknowledgements for a single `(height, header_digest)`
/// pair until ≥ 2f+1 stake is reached, then produces a [`QuorumCert`].
///
/// ## Design
///
/// Wraps [`StakeAggregator`] (DRY — AGENTS §2.1) for the stake-weighted
/// threshold check. Adds per-ack validation (height/digest match, membership,
/// sig injection) and tracks the per-signer [`Signature`] for QC assembly.
///
/// ## Idempotency
///
/// [`StakeAggregator`] is idempotent per author — a duplicate ack from the
/// same signer is a no-op on the stake side. The accumulator additionally
/// returns [`CommitAckError::Equivocation`] on the second ack so the caller
/// can log it (not a crash — AGENTS §7.2).
///
/// ## Determinism (AGENTS §7.1)
///
/// `signers: BTreeMap<Address, Signature>` — deterministic iteration order.
/// The resulting [`QuorumCert`] has the same byte representation regardless
/// of the order in which acks arrived.
#[derive(Debug)]
pub struct CommitAckAccumulator {
    /// Block height this accumulator is tracking.
    height: u64,
    /// Canonical header digest this accumulator is tracking.
    header_digest: Hash,
    /// Stake-weighted quorum aggregator (wraps BTreeSet for idempotency).
    inner: StakeAggregator,
    /// Per-signer signatures collected so far (BTreeMap for determinism).
    signers: BTreeMap<Address, Signature>,
    /// Total voting power of the committee (for QC assembly).
    total_power: Amount,
}

impl CommitAckAccumulator {
    /// Create a new accumulator for the given `(height, header_digest)` pair.
    ///
    /// `total_power` is `ValidatorSet::total_power` for the current epoch.
    /// The accumulator is ready to accept acks immediately after construction.
    #[must_use]
    pub fn new(height: u64, header_digest: Hash, total_power: Amount) -> Self {
        Self {
            height,
            header_digest,
            inner: StakeAggregator::quorum(total_power),
            signers: BTreeMap::new(),
            total_power,
        }
    }

    /// Create a new accumulator from a [`ValidatorSet`].
    ///
    /// Convenience constructor — extracts `total_power` from the set.
    #[must_use]
    pub fn for_validator_set(height: u64, header_digest: Hash, vset: &ValidatorSet) -> Self {
        Self::new(height, header_digest, vset.total_power)
    }

    /// The block height this accumulator is tracking.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.height
    }

    /// The header digest this accumulator is tracking.
    #[must_use]
    pub fn header_digest(&self) -> Hash {
        self.header_digest
    }

    /// Returns `true` if ≥ 2f+1 stake has been accumulated (quorum reached).
    #[must_use]
    pub fn has_quorum(&self) -> bool {
        self.inner.is_reached()
    }

    /// The number of distinct signers accumulated so far.
    ///
    /// **Diagnostic only.** Quorum is stake-weighted — this count carries no
    /// quorum semantics.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.len()
    }

    /// Add a commit-ack to the accumulator.
    ///
    /// ## Validation (in order)
    ///
    /// 1. Height matches this accumulator's height.
    /// 2. Header digest matches this accumulator's digest.
    /// 3. Signer is a member of `vset`.
    /// 4. `sig_ok` is `true` (injected by the node layer via `lemma-crypto`).
    /// 5. Signer has not already submitted an ack (idempotency / equivocation guard).
    ///
    /// ## Returns
    ///
    /// - `Ok(true)` — quorum is now reached (on the crossing call and every
    ///   subsequent valid call).
    /// - `Ok(false)` — quorum not yet reached.
    /// - `Err(CommitAckError::*)` — validation failed; ack is dropped.
    ///
    /// ## No panics (AGENTS §7.2)
    ///
    /// All failure paths return `Err`. A crafted ack must never crash the node.
    ///
    /// # Errors
    ///
    /// See [`CommitAckError`] variants.
    pub fn add(
        &mut self,
        ack: &CommitAckPayload,
        vset: &ValidatorSet,
        sig_ok: bool,
    ) -> Result<bool, CommitAckError> {
        // ── Check 1: Height match ─────────────────────────────────────────────
        if ack.height != self.height {
            return Err(CommitAckError::HeightMismatch {
                expected: self.height,
                got: ack.height,
            });
        }

        // ── Check 2: Digest match ─────────────────────────────────────────────
        if ack.header_digest != self.header_digest {
            return Err(CommitAckError::DigestMismatch {
                expected: self.header_digest,
                got: ack.header_digest,
            });
        }

        // ── Check 3: Signer membership ────────────────────────────────────────
        let member = vset
            .members
            .get(&ack.signer)
            .ok_or(CommitAckError::UnknownSigner { signer: ack.signer })?;

        // ── Check 4: Signature validity (injected) ────────────────────────────
        if !sig_ok {
            return Err(CommitAckError::InvalidSignature { signer: ack.signer });
        }

        // ── Check 5: Equivocation guard ───────────────────────────────────────
        // StakeAggregator is idempotent per author (stake side), but we also
        // need to detect and report the duplicate at the ack level.
        if self.signers.contains_key(&ack.signer) {
            return Err(CommitAckError::Equivocation { signer: ack.signer });
        }

        // ── Accumulate stake ──────────────────────────────────────────────────
        // StakeAggregator::add is infallible for new authors (idempotency guard
        // above ensures this is a new author). StakeOverflow is practically
        // unreachable but must be handled (AGENTS §7.4).
        let reached = self
            .inner
            .add(ack.signer, member.power)
            .map_err(|e| CommitAckError::StakeOverflow { source: e })?;

        // Record the signer's signature for QC assembly (BTreeMap — deterministic).
        self.signers.insert(ack.signer, ack.signature.clone());

        Ok(reached)
    }

    /// Produce a [`QuorumCert`] from the accumulated acks.
    ///
    /// Returns `None` if quorum has not been reached yet.
    ///
    /// The resulting cert has:
    /// - `height` = this accumulator's height.
    /// - `header_digest` = this accumulator's header digest.
    /// - `signers` = `BTreeMap<Address, Signature>` of all valid acks collected
    ///   so far (deterministic order — AGENTS §7.1).
    ///
    /// The cert can be verified with `lemma_consensus::verify_quorum_cert`
    /// (sig injection pattern — the caller provides `sig_results`).
    #[must_use]
    pub fn try_build_qc(&self) -> Option<QuorumCert> {
        if !self.inner.is_reached() {
            return None;
        }
        Some(QuorumCert::new(
            self.height,
            self.header_digest,
            self.signers.clone(),
        ))
    }

    /// The accumulated stake in raw Drop units (diagnostic / test accessor).
    #[must_use]
    pub fn accumulated_stake(&self) -> u128 {
        self.inner.accumulated()
    }

    /// The total committee power in raw Drop units (diagnostic / test accessor).
    #[must_use]
    pub fn total_power(&self) -> u128 {
        self.total_power.as_drop()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
