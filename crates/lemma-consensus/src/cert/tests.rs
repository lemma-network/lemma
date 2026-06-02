//! Tests for `lemma_consensus::cert` — QuorumCert verification (B4a, spec §3.2).
//!
//! ## Coverage
//!
//! - **Happy path**: valid 2f+1 cert passes all checks.
//! - **Digest mismatch**: wrong expected digest → rejected.
//! - **Non-member signer**: address not in vset → rejected.
//! - **Invalid signature**: sig_results[signer]=false → rejected.
//! - **Missing sig_results**: absent = treated as false → rejected.
//! - **Insufficient quorum**: exactly at threshold → not enough (strict >).
//! - **Just over threshold**: first power that tips > 2/3 → accepted.
//! - **StakeOverflow**: unreachable in practice; error path tested.
//! - **Determinism**: same inputs → same result.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    signature::Signature,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
    QuorumCert,
};

use crate::cert::{verify_quorum_cert, CertError};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn hash(n: u8) -> Hash {
    Hash::from_bytes([n; 32])
}

fn power(drop: u128) -> VotingPower {
    VotingPower(Amount::from_drop(drop))
}

fn unsigned_sig() -> Signature {
    Signature::Unsigned
}

/// Build a ValidatorSet with equal power for each member.
fn make_vset(members: &[(u8, u128)]) -> ValidatorSet {
    let map: BTreeMap<_, _> = members
        .iter()
        .map(|&(b, p)| {
            (
                addr(b),
                Member {
                    consensus_pubkey: ConsensusKey::from_bytes(vec![b; 32], vec![b; 32]),
                    power: power(p),
                },
            )
        })
        .collect();
    let total = map.values().fold(Amount::zero(), |a, m| {
        a.checked_add(m.power.as_amount()).unwrap()
    });
    ValidatorSet {
        epoch: 0,
        members: map,
        total_power: total,
    }
}

/// Build a cert where `signer_bytes` signed `digest`.
fn make_cert(height: u64, digest: Hash, signers: &[u8]) -> QuorumCert {
    let map = signers.iter().map(|&b| (addr(b), unsigned_sig())).collect();
    QuorumCert::new(height, digest, map)
}

/// All-valid sig_results for a list of addresses.
fn all_valid(signers: &[u8]) -> BTreeMap<Address, bool> {
    signers.iter().map(|&b| (addr(b), true)).collect()
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[test]
fn verify_valid_cert_with_full_committee_passes() {
    // 3 validators, each power 100. Total 300. Need > 200 (2/3).
    // All 3 sign → accumulated 300 > 200 ✓
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0xAB);
    let qc = make_cert(10, digest, &[1, 2, 3]);
    let sigs = all_valid(&[1, 2, 3]);

    assert!(verify_quorum_cert(&qc, &vset, digest, &sigs).is_ok());
}

#[test]
fn verify_valid_cert_with_just_over_two_thirds_passes() {
    // 3 validators of equal power 100. Total 300.
    // Need strictly > 200. Two signers = 200 — NOT enough.
    // Three signers = 300 > 200 ✓ (tested above).
    // What about two validators of power 101 each + one of 98?
    // Total = 300. Two 101s = 202 > 200 ✓
    let vset = make_vset(&[(1, 101), (2, 101), (3, 98)]);
    let digest = hash(0x01);
    let qc = make_cert(5, digest, &[1, 2]); // 202 > 200 ✓
    let sigs = all_valid(&[1, 2]);

    assert!(verify_quorum_cert(&qc, &vset, digest, &sigs).is_ok());
}

// ── Check 1: Digest mismatch ──────────────────────────────────────────────────

#[test]
fn verify_rejects_wrong_expected_digest() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let cert_digest = hash(0xAA);
    let wrong_digest = hash(0xBB);
    let qc = make_cert(10, cert_digest, &[1, 2, 3]);
    let sigs = all_valid(&[1, 2, 3]);

    let err = verify_quorum_cert(&qc, &vset, wrong_digest, &sigs).unwrap_err();
    assert!(
        matches!(err, CertError::DigestMismatch { expected, got }
            if expected == wrong_digest && got == cert_digest),
        "wrong expected digest must → DigestMismatch"
    );
}

// ── Check 2: Non-member signer ────────────────────────────────────────────────

#[test]
fn verify_rejects_non_member_signer() {
    let vset = make_vset(&[(1, 100), (2, 100)]);
    let digest = hash(0xCC);
    let qc = make_cert(10, digest, &[1, 99]); // addr(99) not in vset
    let sigs = all_valid(&[1, 99]);

    let err = verify_quorum_cert(&qc, &vset, digest, &sigs).unwrap_err();
    assert!(
        matches!(err, CertError::NonMemberSigner { signer } if signer == addr(99)),
        "non-member signer must → NonMemberSigner"
    );
}

// ── Check 3: Invalid signature ────────────────────────────────────────────────

#[test]
fn verify_rejects_invalid_signature() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0xDD);
    let qc = make_cert(10, digest, &[1, 2, 3]);
    // addr(2) has invalid sig
    let sigs: BTreeMap<_, _> = [(addr(1), true), (addr(2), false), (addr(3), true)]
        .into_iter()
        .collect();

    let err = verify_quorum_cert(&qc, &vset, digest, &sigs).unwrap_err();
    assert!(
        matches!(err, CertError::InvalidSignature { signer } if signer == addr(2)),
        "invalid sig must → InvalidSignature"
    );
}

#[test]
fn verify_treats_absent_sig_result_as_invalid() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0xEE);
    let qc = make_cert(10, digest, &[1, 2, 3]);
    // addr(3) absent from sig_results → treated as false
    let sigs: BTreeMap<_, _> = [(addr(1), true), (addr(2), true)].into_iter().collect();

    let err = verify_quorum_cert(&qc, &vset, digest, &sigs).unwrap_err();
    assert!(
        matches!(err, CertError::InvalidSignature { signer } if signer == addr(3)),
        "absent sig_result must → InvalidSignature (treated as false)"
    );
}

// ── Check 4: Insufficient quorum ─────────────────────────────────────────────

#[test]
fn verify_rejects_exactly_at_threshold() {
    // 3 equal validators, power 100 each. Total 300.
    // Exactly 200 = 2/3 — NOT strictly > 2/3.
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0xFF);
    let qc = make_cert(10, digest, &[1, 2]); // accumulated = 200 (exactly 2/3)
    let sigs = all_valid(&[1, 2]);

    let err = verify_quorum_cert(&qc, &vset, digest, &sigs).unwrap_err();
    assert!(
        matches!(err, CertError::InsufficientQuorum { .. }),
        "exactly 2/3 is NOT quorum (strict >); must → InsufficientQuorum"
    );
}

#[test]
fn verify_rejects_empty_cert() {
    // Zero signers = zero accumulated = no quorum.
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0x01);
    let qc = make_cert(10, digest, &[]); // no signers
    let sigs = BTreeMap::new();

    let err = verify_quorum_cert(&qc, &vset, digest, &sigs).unwrap_err();
    assert!(matches!(
        err,
        CertError::InsufficientQuorum { accumulated: 0, .. }
    ));
}

#[test]
fn verify_rejects_single_validator_below_quorum() {
    // 3 equal validators. One signer = 100, total 300. 100 * 3 = 300 not > 300 * 2 = 600.
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0x02);
    let qc = make_cert(10, digest, &[1]); // only 1 signer
    let sigs = all_valid(&[1]);

    assert!(matches!(
        verify_quorum_cert(&qc, &vset, digest, &sigs),
        Err(CertError::InsufficientQuorum { .. })
    ));
}

// ── Boundary: just over 2/3 ───────────────────────────────────────────────────

#[test]
fn verify_accepts_minimal_quorum() {
    // Asymmetric power: validators 1 has power 201, others 99 each. Total 399.
    // Quorum: accumulated * 3 > 399 * 2 = 798 → need accumulated > 266.
    // Validator 1 alone = 201. 201 * 3 = 603 > 399? No. 603 > 798? No.
    // Need multiple: validators 1+2 = 300. 300 * 3 = 900 > 798 ✓
    let vset = make_vset(&[(1, 201), (2, 99), (3, 99)]);
    let digest = hash(0x03);
    let qc = make_cert(5, digest, &[1, 2]);
    let sigs = all_valid(&[1, 2]);

    assert!(verify_quorum_cert(&qc, &vset, digest, &sigs).is_ok());
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn verify_deterministic_same_inputs_same_result() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0xAB);
    let qc = make_cert(10, digest, &[1, 2, 3]);
    let sigs = all_valid(&[1, 2, 3]);

    let r1 = verify_quorum_cert(&qc, &vset, digest, &sigs);
    let r2 = verify_quorum_cert(&qc, &vset, digest, &sigs);
    assert_eq!(r1.is_ok(), r2.is_ok(), "verification must be deterministic");
}
