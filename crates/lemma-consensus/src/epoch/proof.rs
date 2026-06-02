//! # Epoch-change proof + sequential verification (spec §4.4, closes 12 §3.3)
//!
//! Implements the two verification modes from `docs/12-NETWORK_SYNC_SPEC §3`:
//!
//! - **`verify_full`** — sequential (adjacent-block) verification:
//!   validator-set authentication + quorum cert. Used by the node for every
//!   new finalized block.
//!
//! - **`verify_epoch_change`** — epoch-walk proof: verifies an ordered chain
//!   of end-of-epoch boundary headers, each certified by its epoch's committee,
//!   advancing the trust anchor `ValidatorSet(N) → ValidatorSet(N+1) → …`.
//!   Used by light clients and syncing nodes.
//!
//! ## What makes a block final
//!
//! Under Lemma's absolute BFT finality, a block is final immediately once
//! its [`QuorumCert`] accumulates ≥ 2f+1 voting-power in valid signatures.
//! There is no re-org, no fork-choice — a header that passes `verify_full`
//! is permanently final.
//!
//! ## Epoch-change proof invariant
//!
//! The 2f+1 commit on the end-of-epoch boundary block IS the epoch-change
//! proof (spec §4.4). A light client:
//! 1. Trusts epoch N's `ValidatorSet` (out-of-band, from genesis config).
//! 2. Obtains the boundary header + cert for epoch N.
//! 3. Verifies the cert against epoch N's committee.
//! 4. Reads `header.next_validators_hash` — this is epoch N+1's committee hash.
//! 5. Advances trust: commits `ValidatorSet(N+1)` if `hash(vset_N+1) == next_validators_hash`.
//! 6. Repeats for each epoch gap.
//!
//! ## Signature injection (B3-2 pattern)
//!
//! `lemma-consensus` does not import `lemma-crypto`. Header digests and
//! signature verification results are injected by the caller.
//!
//! ## Determinism
//!
//! All predicates are pure functions of their inputs. No `SystemTime`, no floats,
//! no `HashMap`. Same inputs → same result on every node.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address, hash::Hash, header::BlockHeader, validator_set::ValidatorSet, QuorumCert,
};

use crate::cert::{verify_quorum_cert, CertError};

// ── ProofError ────────────────────────────────────────────────────────────────

/// Errors that cause epoch-change proof or sequential verification to fail.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProofError {
    /// Empty proof — at least one boundary header is required.
    #[error("epoch-change proof is empty: at least one boundary header is required")]
    EmptyProof,

    /// Proof slices have mismatched lengths.
    ///
    /// `boundary_headers`, `boundary_certs`, and `next_validator_sets`
    /// must all be the same length.
    #[error(
        "epoch-change proof length mismatch: \
         headers={headers}, certs={certs}, next_vsets={next_vsets}"
    )]
    LengthMismatch {
        headers: usize,
        certs: usize,
        next_vsets: usize,
    },

    /// Length of injected `header_digests` or `sig_results` does not match
    /// the number of boundary headers.
    #[error(
        "injected data length mismatch: \
         headers={headers}, header_digests={digests}, sig_result_maps={sig_maps}"
    )]
    InjectedDataLengthMismatch {
        headers: usize,
        digests: usize,
        sig_maps: usize,
    },

    /// A boundary header's `validators_hash` does not match the expected
    /// validator set hash at that step of the chain.
    ///
    /// This means the proof's internal chain of trust is broken at `index`.
    #[error(
        "validator-set hash mismatch at proof step {index}: \
         header.validators_hash={got}, expected {expected}"
    )]
    ValidatorSetHashMismatch {
        /// The step (0-indexed) in the proof where the mismatch occurred.
        index: usize,
        /// The hash the step expected (from the previous boundary or the initial vset).
        expected: Hash,
        /// The hash found in `boundary_headers[index].validators_hash`.
        got: Hash,
    },

    /// A boundary header's `next_validators_hash` does not match the hash
    /// of the provided `next_validator_sets[index]`.
    ///
    /// The next committee claimed in the proof is not the one authenticated
    /// by the boundary header.
    #[error(
        "next-validator-set hash mismatch at proof step {index}: \
         header.next_validators_hash={expected}, actual hash of provided vset={got}"
    )]
    NextValidatorSetHashMismatch {
        /// The step where the mismatch occurred.
        index: usize,
        /// The hash committed in `boundary_headers[index].next_validators_hash`.
        expected: Hash,
        /// The hash of `next_validator_sets[index]` as computed.
        got: Hash,
    },

    /// The quorum certificate for a boundary header failed verification.
    #[error("cert verification failed at proof step {index}: {source}")]
    CertFailed {
        /// The step where the cert failed.
        index: usize,
        /// Underlying cert error.
        #[source]
        source: CertError,
    },
}

// ── EpochChangeProof ──────────────────────────────────────────────────────────

/// An ordered chain of quorum-certified end-of-epoch boundary headers.
///
/// Used by light clients and syncing nodes to advance from a trusted epoch N
/// to a later epoch without verifying every intermediate block.
///
/// ## Invariants (checked by [`verify_epoch_change`])
///
/// - All three slices are the same length (≥ 1).
/// - For each step `i`, `boundary_certs[i]` is a valid ≥ 2f+1 cert over
///   `boundary_headers[i]` from the committee of the epoch at step `i`.
/// - For each step `i`, `hash(next_validator_sets[i]) == boundary_headers[i].next_validators_hash`.
///
/// ## Usage
///
/// ```ignore
/// // Light client trusts epoch N's ValidatorSet:
/// let result = verify_epoch_change(
///     &proof, &trusted_vset, &header_digests, &sig_results
/// );
/// if result.is_ok() {
///     // Trust the last vset in proof.next_validator_sets
///     let new_committee = proof.next_validator_sets.last().unwrap();
/// }
/// ```
#[derive(Debug, Clone)]
pub struct EpochChangeProof {
    /// Ordered end-of-epoch boundary headers.
    ///
    /// Each header's `validators_hash` commits the committee that certified it;
    /// each header's `next_validators_hash` commits the next epoch's committee.
    pub boundary_headers: Vec<BlockHeader>,

    /// Quorum certificate for each boundary header. Same length as `boundary_headers`.
    pub boundary_certs: Vec<QuorumCert>,

    /// Next-epoch validator sets, authenticated by each boundary header's
    /// `next_validators_hash`. Same length as `boundary_headers`.
    ///
    /// `next_validator_sets[i]` is the committee the light client will use
    /// to verify the NEXT boundary header (step `i+1`).
    pub next_validator_sets: Vec<ValidatorSet>,
}

// ── verify_full ───────────────────────────────────────────────────────────────

/// Verify a single block header against its validator set and quorum cert.
///
/// Sequential ("full") verification per `docs/12-NETWORK_SYNC_SPEC §3.2`.
/// Runs three checks:
///
/// 1. `vset.hash() == header.validators_hash` — the provided validator set
///    is the one that was authorized to sign this block.
/// 2. `qc.header_digest == header_digest` — the cert covers this header.
/// 3. The cert accumulates ≥ 2f+1 voting power in valid signatures.
///
/// ## Parameters
///
/// - `vset` — the validator set for the block's epoch (trusted by the caller).
/// - `header` — the block header being verified.
/// - `header_digest` — Blake3(`header`) injected by the caller (B3-2 pattern).
/// - `qc` — the quorum certificate from the block's consensus commit.
/// - `sig_results` — per-signer sig verification results (injected, B3-2).
///
/// ## Note on error `index` field
///
/// Errors from this function carry `index: 0` — this is a placeholder since
/// `verify_full` is single-header (no iteration). Callers iterating many
/// headers should use [`verify_epoch_change`] directly (which sets `index`
/// correctly per step) rather than calling `verify_full` in a loop.
///
/// # Errors
///
/// - [`ProofError::ValidatorSetHashMismatch`] if `vset.hash() ≠ header.validators_hash`.
/// - [`ProofError::CertFailed`] (wrapping a [`CertError`]) if cert verification fails.
pub fn verify_full(
    vset: &ValidatorSet,
    header: &BlockHeader,
    header_digest: Hash,
    qc: &QuorumCert,
    sig_results: &BTreeMap<Address, bool>,
) -> Result<(), ProofError> {
    // ── Check 1: Validator-set authentication ─────────────────────────────────
    //
    // The provided vset must be the one committed in the header.
    // This prevents a node from verifying with a substituted committee.
    let vset_hash = vset.hash();
    if vset_hash != header.validators_hash {
        return Err(ProofError::ValidatorSetHashMismatch {
            index: 0,
            expected: vset_hash,
            got: header.validators_hash,
        });
    }

    // ── Checks 2–4: Cert verification (digest + membership + quorum) ──────────
    verify_quorum_cert(qc, vset, header_digest, sig_results).map_err(|e| ProofError::CertFailed {
        index: 0,
        source: e,
    })
}

// ── verify_epoch_change ───────────────────────────────────────────────────────

/// Verify an [`EpochChangeProof`] — walk boundary headers advancing the trust anchor.
///
/// Starting from `initial_vset` (the trusted epoch N committee), verifies each
/// boundary header + cert in sequence. Each step:
/// 1. Checks the boundary header's `validators_hash` matches the current trusted vset.
/// 2. Verifies the quorum cert against the current trusted vset.
/// 3. Checks `hash(next_validator_sets[i]) == boundary_headers[i].next_validators_hash`.
/// 4. Advances the trusted vset to `next_validator_sets[i]`.
///
/// If all steps pass, the proof is valid and the caller may trust the
/// last entry of `proof.next_validator_sets` as the new committee.
///
/// ## Parameters
///
/// - `proof` — the epoch-change proof to verify.
/// - `initial_vset` — the light client's currently trusted validator set (epoch N).
/// - `header_digests` — Blake3(`boundary_headers[i]`) for each step (injected, B3-2).
///   Must have the same length as `proof.boundary_headers`.
/// - `sig_results` — per-cert, per-signer sig verification results (injected, B3-2).
///   Must have the same length as `proof.boundary_headers`.
///
/// # Errors
///
/// See [`ProofError`] variants. The first failing check returns immediately.
pub fn verify_epoch_change(
    proof: &EpochChangeProof,
    initial_vset: &ValidatorSet,
    header_digests: &[Hash],
    sig_results: &[BTreeMap<Address, bool>],
) -> Result<(), ProofError> {
    // ── Structural checks ─────────────────────────────────────────────────────
    if proof.boundary_headers.is_empty() {
        return Err(ProofError::EmptyProof);
    }
    let n = proof.boundary_headers.len();
    if proof.boundary_certs.len() != n || proof.next_validator_sets.len() != n {
        return Err(ProofError::LengthMismatch {
            headers: n,
            certs: proof.boundary_certs.len(),
            next_vsets: proof.next_validator_sets.len(),
        });
    }
    if header_digests.len() != n || sig_results.len() != n {
        return Err(ProofError::InjectedDataLengthMismatch {
            headers: n,
            digests: header_digests.len(),
            sig_maps: sig_results.len(),
        });
    }

    // ── Walk boundary headers ─────────────────────────────────────────────────
    let mut current_vset = initial_vset;

    for i in 0..n {
        let header = &proof.boundary_headers[i];
        let qc = &proof.boundary_certs[i];
        let next_vset = &proof.next_validator_sets[i];

        // Step A: Check that the boundary header's validators_hash matches the
        //         current trusted committee. This ties each header to the chain.
        let current_hash = current_vset.hash();
        if current_hash != header.validators_hash {
            return Err(ProofError::ValidatorSetHashMismatch {
                index: i,
                expected: current_hash,
                got: header.validators_hash,
            });
        }

        // Step B: Verify the quorum cert for this boundary header.
        verify_quorum_cert(qc, current_vset, header_digests[i], &sig_results[i]).map_err(|e| {
            ProofError::CertFailed {
                index: i,
                source: e,
            }
        })?;

        // Step C: Authenticate the next validator set via the boundary header.
        //
        // `header.next_validators_hash` is committed in the boundary header and
        // was signed by the current committee's 2f+1 quorum. So if the cert
        // passes, the light client can trust that hash-chain one step forward.
        let next_vset_hash = next_vset.hash();
        if next_vset_hash != header.next_validators_hash {
            return Err(ProofError::NextValidatorSetHashMismatch {
                index: i,
                expected: header.next_validators_hash,
                got: next_vset_hash,
            });
        }

        // Advance trust anchor to the next epoch's committee.
        current_vset = next_vset;
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
