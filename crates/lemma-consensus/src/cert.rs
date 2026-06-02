//! # Quorum-certificate verification (spec §3.2)
//!
//! Provides [`verify_quorum_cert`] — the stake-weighted 2f+1 verification
//! function for [`QuorumCert`] (defined in `lemma-core`).
//!
//! ## Why here, not in `lemma-core`
//!
//! Verification requires [`StakeAggregator`] (this crate). The type itself
//! lives in `lemma-core` so both `lemma-consensus` and `lemma-network` can
//! import it without circular dependencies. The verification logic stays here.
//!
//! ## Signature injection (B3-2 pattern)
//!
//! Hybrid Ed25519+ML-DSA signature verification is injected as
//! `sig_results: &BTreeMap<Address, bool>`. The node binary calls
//! `lemma-crypto` and passes the results; `lemma-consensus` does not
//! depend on `lemma-crypto`.
//!
//! ## Determinism
//!
//! `verify_quorum_cert` is pure over its inputs. `BTreeMap` iteration
//! is deterministic (AGENTS §7.1). No `SystemTime`.

use std::collections::BTreeMap;

use lemma_core::{address::Address, hash::Hash, validator_set::ValidatorSet, QuorumCert};

use crate::stake::StakeAggregator;

// ── CertError ─────────────────────────────────────────────────────────────────

/// Errors that cause quorum-certificate verification to fail.
///
/// Every variant returns `Err` without mutating state. Never panics on
/// adversarial / crafted evidence (AGENTS §7.2).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    /// The certificate covers a different header digest than expected.
    ///
    /// `qc.header_digest` must match the Blake3 digest of the header being
    /// certified (`lemma-crypto::hash(header)`, injected by caller).
    #[error("certificate digest mismatch: cert covers {got}, expected {expected}")]
    DigestMismatch {
        /// The digest the caller expected the cert to cover.
        expected: Hash,
        /// The digest embedded in the certificate.
        got: Hash,
    },

    /// A signer in the certificate is not a member of the validator set.
    ///
    /// Every signer must be a current committee member — non-members cannot
    /// contribute to quorum. This may indicate a forged or stale cert.
    #[error("signer {signer} is not a member of the validator set")]
    NonMemberSigner {
        /// The address that is not in the committee.
        signer: Address,
    },

    /// A signer's signature failed verification (hybrid Ed25519 + ML-DSA).
    ///
    /// Injected as `sig_results[signer] == false` (B3-2 pattern). A cert
    /// containing any invalid signature is rejected — all signers must have
    /// valid proofs.
    #[error("invalid signature from signer {signer}")]
    InvalidSignature {
        /// The address whose signature failed.
        signer: Address,
    },

    /// The cert does not accumulate ≥ 2/3 voting power (strict 2f+1).
    ///
    /// `accumulated * 3 ≤ total * 2` — not enough stake behind the cert.
    #[error(
        "insufficient quorum: accumulated {accumulated} Drop, \
         need strictly > 2/3 of {total} Drop total"
    )]
    InsufficientQuorum {
        /// Accumulated voting power from valid signers.
        accumulated: u128,
        /// Total committee voting power.
        total: u128,
    },

    /// Stake arithmetic overflow accumulating signer power.
    ///
    /// Practically unreachable — requires total stake near u128::MAX.
    #[error("stake overflow accumulating cert signers: {source}")]
    StakeOverflow {
        /// Underlying consensus error (wraps `ConsensusError::StakeOverflow`).
        #[source]
        source: crate::error::ConsensusError,
    },
}

// ── verify_quorum_cert ────────────────────────────────────────────────────────

/// Verify a [`QuorumCert`] against a validator set and expected header digest.
///
/// ## Checks (in order)
///
/// 1. `qc.header_digest == expected_digest` — cert covers the right header.
/// 2. Every signer in `qc.signers` is a member of `vset`.
/// 3. Every signer's signature is valid (`sig_results[signer] == true`).
/// 4. Sum of valid signers' voting power **strictly > 2/3** of total
///    (integer form: `accumulated * 3 > total * 2`). Uses [`StakeAggregator`].
///
/// ## Signature injection (B3-2)
///
/// `sig_results` maps each signing address to a bool: `true` = valid hybrid
/// Ed25519+ML-DSA signature over `expected_digest`. Computed by the caller
/// via `lemma-crypto`; `lemma-consensus` does not call `lemma-crypto`.
///
/// Signers absent from `sig_results` are treated as having invalid sigs.
///
/// ## Determinism
///
/// Pure. `BTreeMap`/`BTreeSet` iteration. No `SystemTime`.
///
/// # Errors
///
/// See [`CertError`] variants — `Err` is returned immediately on the first
/// failing check.
pub fn verify_quorum_cert(
    qc: &QuorumCert,
    vset: &ValidatorSet,
    expected_digest: Hash,
    sig_results: &BTreeMap<Address, bool>,
) -> Result<(), CertError> {
    // ── Check 1: Cert covers the expected header ──────────────────────────────
    if qc.header_digest != expected_digest {
        return Err(CertError::DigestMismatch {
            expected: expected_digest,
            got: qc.header_digest,
        });
    }

    // ── Checks 2–4: Membership + valid sig + stake accumulation ──────────────
    //
    // StakeAggregator is idempotent per author (stake.rs) — double-counting
    // the same signer is impossible even if qc.signers has duplicates (BTreeMap
    // guarantees unique keys, so no duplicates here, but the guard is free).
    let mut agg = StakeAggregator::quorum(vset.total_power);

    // BTreeMap iteration is canonically sorted by Address — deterministic.
    for addr in qc.signers.keys() {
        // Check 2: signer must be in committee.
        let member = vset
            .members
            .get(addr)
            .ok_or(CertError::NonMemberSigner { signer: *addr })?;

        // Check 3: signature must be valid (injected).
        let sig_ok = sig_results.get(addr).copied().unwrap_or(false);
        if !sig_ok {
            return Err(CertError::InvalidSignature { signer: *addr });
        }

        // Accumulate stake. StakeAggregator::add returns Ok(bool) unless overflow.
        agg.add(*addr, member.power)
            .map_err(|e| CertError::StakeOverflow { source: e })?;
    }

    // Check 4: quorum reached?
    if !agg.is_reached() {
        return Err(CertError::InsufficientQuorum {
            accumulated: agg.accumulated(),
            total: vset.total_power.as_drop(),
        });
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
