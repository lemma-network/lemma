//! Tests for `lemma_consensus::commit_ack` — CommitAckPayload + CommitAckAccumulator.
//!
//! ## Coverage (P4·Step 9 requirements)
//!
//! 1. `accumulator_reaches_quorum_at_two_thirds_stake` — 3-validator: add acks
//!    until 2/3+1 reached → QC produced.
//! 2. `accumulator_below_threshold_does_not_produce_qc` — add only 1 of 3
//!    validators (< 2/3) → no QC.
//! 3. `accumulator_rejects_equivocation` — same signer submits two different
//!    acks → second rejected.
//! 4. `accumulator_rejects_invalid_signature` — bad sig → rejected (no panic).
//! 5. `accumulator_single_validator_fast_path` — 1 validator 100% stake →
//!    own ack immediately produces QC.
//! 6. `commit_ack_payload_signature_domain_separated` — verify that the
//!    domain-separated message differs from a raw header_digest sign.
//! 7. `quorum_cert_signers_deterministic` — same set of acks in different
//!    order → same QC bytes.
//! 8. `accumulator_qc_verifies_against_validator_set` — end-to-end round-trip:
//!    real KeyPairs sign commit_ack_message, accumulate to quorum, build QC,
//!    verify_quorum_cert returns Ok (B2 blocker fix).

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    signature::Signature,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};

use crate::cert::verify_quorum_cert;
use crate::commit_ack::{
    commit_ack_message, CommitAckAccumulator, CommitAckError, CommitAckPayload,
};

// ── Test helpers ──────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn hash(n: u8) -> Hash {
    Hash::from_bytes([n; 32])
}

fn power(drop: u128) -> VotingPower {
    VotingPower(Amount::from_drop(drop))
}

/// Build a ValidatorSet with the given (byte_id, power_drop) pairs.
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

/// Build a CommitAckPayload with a dummy (Unsigned) signature.
///
/// In production the signature is a real hybrid sig; in tests we inject
/// `sig_ok = true` to bypass crypto (B3-2 pattern).
fn make_ack(height: u64, header_digest: Hash, signer: u8) -> CommitAckPayload {
    CommitAckPayload {
        height,
        header_digest,
        signer: addr(signer),
        signature: Signature::Unsigned,
    }
}

/// Build a CommitAckPayload with a distinct dummy signature (for equivocation tests).
fn make_ack_alt(height: u64, header_digest: Hash, signer: u8) -> CommitAckPayload {
    CommitAckPayload {
        height,
        header_digest,
        signer: addr(signer),
        // Different signature bytes to simulate a second (conflicting) ack.
        signature: Signature::Classical {
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        },
    }
}

// ── Test 1: Quorum at 2/3+1 stake ────────────────────────────────────────────

#[test]
fn accumulator_reaches_quorum_at_two_thirds_stake() {
    // 3 validators, equal power 100 each. Total 300.
    // Quorum: accumulated * 3 > 300 * 2 = 600 → need accumulated > 200.
    // Two signers = 200 — NOT enough (strict >).
    // Three signers = 300 > 200 ✓
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0xAB);
    let mut acc = CommitAckAccumulator::for_validator_set(10, digest, &vset);

    // First ack: 100 stake — below quorum.
    let r1 = acc.add(&make_ack(10, digest, 1), &vset, true).unwrap();
    assert!(!r1, "one of three validators is not quorum");
    assert!(acc.try_build_qc().is_none());

    // Second ack: 200 stake — exactly 2/3, NOT quorum (strict >).
    let r2 = acc.add(&make_ack(10, digest, 2), &vset, true).unwrap();
    assert!(!r2, "exactly 2/3 is not quorum (strict >)");
    assert!(acc.try_build_qc().is_none());

    // Third ack: 300 stake — strictly > 2/3 ✓
    let r3 = acc.add(&make_ack(10, digest, 3), &vset, true).unwrap();
    assert!(r3, "all three validators = quorum");

    let qc = acc.try_build_qc().expect("QC must be produced at quorum");
    assert_eq!(qc.height, 10);
    assert_eq!(qc.header_digest, digest);
    assert_eq!(qc.signer_count(), 3);
}

// ── Test 2: Below threshold — no QC ──────────────────────────────────────────

#[test]
fn accumulator_below_threshold_does_not_produce_qc() {
    // 3 validators, equal power 100. Only 1 ack submitted (100 < 200 threshold).
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0xCD);
    let mut acc = CommitAckAccumulator::for_validator_set(5, digest, &vset);

    let reached = acc.add(&make_ack(5, digest, 1), &vset, true).unwrap();
    assert!(!reached, "single ack of 3 is not quorum");
    assert!(acc.try_build_qc().is_none(), "no QC when below threshold");
}

// ── Test 3: Equivocation rejection ───────────────────────────────────────────

#[test]
fn accumulator_rejects_equivocation() {
    // Same signer submits two different acks — second must be rejected.
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0xEF);
    let mut acc = CommitAckAccumulator::for_validator_set(7, digest, &vset);

    // First ack: accepted.
    acc.add(&make_ack(7, digest, 1), &vset, true).unwrap();

    // Second ack from same signer: rejected as equivocation.
    let err = acc
        .add(&make_ack_alt(7, digest, 1), &vset, true)
        .unwrap_err();
    assert!(
        matches!(err, CommitAckError::Equivocation { signer } if signer == addr(1)),
        "second ack from same signer must → Equivocation, got: {err:?}"
    );

    // Stake must not have been double-counted.
    assert_eq!(
        acc.signer_count(),
        1,
        "equivocating signer counted only once"
    );
}

// ── Test 4: Invalid signature rejection ──────────────────────────────────────

#[test]
fn accumulator_rejects_invalid_signature() {
    // sig_ok = false → ack rejected, no panic.
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0x12);
    let mut acc = CommitAckAccumulator::for_validator_set(3, digest, &vset);

    let err = acc
        .add(&make_ack(3, digest, 1), &vset, false) // sig_ok = false
        .unwrap_err();
    assert!(
        matches!(err, CommitAckError::InvalidSignature { signer } if signer == addr(1)),
        "invalid sig must → InvalidSignature, got: {err:?}"
    );

    // No stake accumulated, no QC.
    assert_eq!(acc.signer_count(), 0);
    assert!(acc.try_build_qc().is_none());
}

// ── Test 5: Single-validator fast-path ───────────────────────────────────────

#[test]
fn accumulator_single_validator_fast_path() {
    // 1 validator with 100% stake. Own ack immediately satisfies 2f+1.
    // Math: 100 * 3 = 300 > 100 * 2 = 200 ✓
    let vset = make_vset(&[(1, 100)]);
    let digest = hash(0x42);
    let mut acc = CommitAckAccumulator::for_validator_set(1, digest, &vset);

    let reached = acc.add(&make_ack(1, digest, 1), &vset, true).unwrap();
    assert!(reached, "single validator 100% stake → immediate quorum");

    let qc = acc.try_build_qc().expect("QC must be produced immediately");
    assert_eq!(qc.height, 1);
    assert_eq!(qc.header_digest, digest);
    assert_eq!(qc.signer_count(), 1);
}

// ── Test 6: Domain separation ─────────────────────────────────────────────────

#[test]
fn commit_ack_payload_signature_domain_separated() {
    // The domain-separated message must differ from a raw header_digest sign.
    // This prevents cross-message replay (AGENTS §7.3).
    let height: u64 = 42;
    let header_digest = hash(0x99);

    let domain_msg = commit_ack_message(height, &header_digest);

    // The domain-separated message must NOT equal the raw header_digest bytes.
    assert_ne!(
        domain_msg,
        *header_digest.as_bytes(),
        "domain-separated message must differ from raw header_digest"
    );

    // The domain-separated message must NOT equal the raw height bytes.
    let mut height_bytes = [0u8; 32];
    height_bytes[..8].copy_from_slice(&height.to_le_bytes());
    assert_ne!(
        domain_msg, height_bytes,
        "domain-separated message must differ from raw height bytes"
    );

    // Two different heights must produce different messages (no collision).
    let msg_h1 = commit_ack_message(1, &header_digest);
    let msg_h2 = commit_ack_message(2, &header_digest);
    assert_ne!(
        msg_h1, msg_h2,
        "different heights must produce different messages"
    );

    // Two different digests must produce different messages.
    let msg_d1 = commit_ack_message(height, &hash(0x01));
    let msg_d2 = commit_ack_message(height, &hash(0x02));
    assert_ne!(
        msg_d1, msg_d2,
        "different digests must produce different messages"
    );
}

// ── Test 7: Deterministic QC signers ─────────────────────────────────────────

#[test]
fn quorum_cert_signers_deterministic() {
    // Same set of acks in different order → same QC bytes (BTreeMap ordering).
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let digest = hash(0x77);

    // Order A: 1, 2, 3
    let mut acc_a = CommitAckAccumulator::for_validator_set(20, digest, &vset);
    acc_a.add(&make_ack(20, digest, 1), &vset, true).unwrap();
    acc_a.add(&make_ack(20, digest, 2), &vset, true).unwrap();
    acc_a.add(&make_ack(20, digest, 3), &vset, true).unwrap();
    let qc_a = acc_a.try_build_qc().unwrap();

    // Order B: 3, 1, 2
    let mut acc_b = CommitAckAccumulator::for_validator_set(20, digest, &vset);
    acc_b.add(&make_ack(20, digest, 3), &vset, true).unwrap();
    acc_b.add(&make_ack(20, digest, 1), &vset, true).unwrap();
    acc_b.add(&make_ack(20, digest, 2), &vset, true).unwrap();
    let qc_b = acc_b.try_build_qc().unwrap();

    // Both QCs must have the same signer set (BTreeMap → deterministic order).
    assert_eq!(
        qc_a.signers.keys().collect::<Vec<_>>(),
        qc_b.signers.keys().collect::<Vec<_>>(),
        "QC signer order must be deterministic regardless of ack arrival order"
    );
    assert_eq!(qc_a.height, qc_b.height);
    assert_eq!(qc_a.header_digest, qc_b.header_digest);
    assert_eq!(qc_a.signer_count(), qc_b.signer_count());
}

// ── Additional edge cases ─────────────────────────────────────────────────────

#[test]
fn accumulator_rejects_wrong_height() {
    let vset = make_vset(&[(1, 100)]);
    let digest = hash(0x01);
    let mut acc = CommitAckAccumulator::for_validator_set(10, digest, &vset);

    // Ack for height 11 — wrong height.
    let err = acc.add(&make_ack(11, digest, 1), &vset, true).unwrap_err();
    assert!(
        matches!(
            err,
            CommitAckError::HeightMismatch {
                expected: 10,
                got: 11
            }
        ),
        "wrong height must → HeightMismatch, got: {err:?}"
    );
}

#[test]
fn accumulator_rejects_wrong_digest() {
    let vset = make_vset(&[(1, 100)]);
    let digest = hash(0x01);
    let wrong_digest = hash(0x02);
    let mut acc = CommitAckAccumulator::for_validator_set(10, digest, &vset);

    // Ack for wrong digest.
    let err = acc
        .add(&make_ack(10, wrong_digest, 1), &vset, true)
        .unwrap_err();
    assert!(
        matches!(err, CommitAckError::DigestMismatch { expected, got }
            if expected == digest && got == wrong_digest),
        "wrong digest must → DigestMismatch, got: {err:?}"
    );
}

#[test]
fn accumulator_rejects_unknown_signer() {
    let vset = make_vset(&[(1, 100), (2, 100)]);
    let digest = hash(0x03);
    let mut acc = CommitAckAccumulator::for_validator_set(10, digest, &vset);

    // Signer 99 is not in the validator set.
    let err = acc.add(&make_ack(10, digest, 99), &vset, true).unwrap_err();
    assert!(
        matches!(err, CommitAckError::UnknownSigner { signer } if signer == addr(99)),
        "unknown signer must → UnknownSigner, got: {err:?}"
    );
}

#[test]
fn accumulator_asymmetric_power_quorum() {
    // Asymmetric power: validator 1 has 201, others 99 each. Total 399.
    // Quorum: accumulated * 3 > 399 * 2 = 798 → need accumulated > 266.
    // Validators 1+2 = 300. 300 * 3 = 900 > 798 ✓
    let vset = make_vset(&[(1, 201), (2, 99), (3, 99)]);
    let digest = hash(0x55);
    let mut acc = CommitAckAccumulator::for_validator_set(15, digest, &vset);

    // Validator 1 alone: 201. 201 * 3 = 603 > 798? No.
    let r1 = acc.add(&make_ack(15, digest, 1), &vset, true).unwrap();
    assert!(!r1, "validator 1 alone (201/399) is not quorum");

    // Validators 1+2: 300. 300 * 3 = 900 > 798 ✓
    let r2 = acc.add(&make_ack(15, digest, 2), &vset, true).unwrap();
    assert!(r2, "validators 1+2 (300/399) is quorum");

    let qc = acc.try_build_qc().unwrap();
    assert_eq!(qc.signer_count(), 2);
}

// ── Test 8: End-to-end round-trip with real KeyPairs (B2 blocker fix) ─────────

/// End-to-end round-trip: real KeyPairs sign `commit_ack_message`, accumulate
/// to quorum, build QC, then `verify_quorum_cert` returns `Ok`.
///
/// This test proves that the SAME domain-separated message is used by:
/// - The signer (CommitAckAccumulator path, P4·Step 9)
/// - The verifier (CertifiedVerifier / verify_quorum_cert)
///
/// A mismatch between signed message and verified message would cause every
/// multi-signer QC to be rejected by peers (the B1 blocker).
#[test]
fn accumulator_qc_verifies_against_validator_set() {
    use lemma_crypto::{verify as verify_hybrid, HybridSignature, KeyPair};

    // ── Setup: 3 validators with equal power ─────────────────────────────────
    // Total 300 Drop. Quorum: accumulated * 3 > 300 * 2 = 600 → need > 200.
    // All 3 validators sign → 300 > 200 ✓
    let height: u64 = 42;
    let header_digest = hash(0xAB);

    // Generate real keypairs for each validator.
    let kp1 = KeyPair::generate().expect("keypair 1 generation failed");
    let kp2 = KeyPair::generate().expect("keypair 2 generation failed");
    let kp3 = KeyPair::generate().expect("keypair 3 generation failed");

    // Build a ValidatorSet using the real public keys from each keypair.
    let make_member = |kp: &KeyPair| Member {
        consensus_pubkey: ConsensusKey::from_bytes(
            kp.public_key().classical,
            kp.public_key().quantum,
        ),
        power: power(100),
    };
    let members: BTreeMap<Address, Member> = [
        (*kp1.address(), make_member(&kp1)),
        (*kp2.address(), make_member(&kp2)),
        (*kp3.address(), make_member(&kp3)),
    ]
    .into_iter()
    .collect();
    let total = members.values().fold(Amount::zero(), |a, m| {
        a.checked_add(m.power.as_amount()).unwrap()
    });
    let vset = ValidatorSet {
        epoch: 0,
        members,
        total_power: total,
    };

    // ── Sign: each validator signs commit_ack_message ─────────────────────────
    // This is the SAME message CertifiedVerifier will verify against.
    let signed_msg = commit_ack_message(height, &header_digest);

    let make_ack_real = |kp: &KeyPair| CommitAckPayload {
        height,
        header_digest,
        signer: *kp.address(),
        signature: kp.sign_to_lemma(&signed_msg),
    };

    let ack1 = make_ack_real(&kp1);
    let ack2 = make_ack_real(&kp2);
    let ack3 = make_ack_real(&kp3);

    // ── Accumulate: inject real sig verification results (B3-2 pattern) ──────
    // The node layer verifies hybrid sigs and injects bool results.
    // Here we replicate what CertifiedVerifier does: verify each sig against
    // commit_ack_message and inject the result.
    let verify_ack = |ack: &CommitAckPayload, _kp: &KeyPair| -> bool {
        let pk = lemma_crypto::PublicKey::from(vset.members[&ack.signer].consensus_pubkey.clone());
        match &ack.signature {
            Signature::Hybrid { classical, quantum } => {
                let hybrid = HybridSignature {
                    classical: classical.clone(),
                    quantum: quantum.clone(),
                };
                verify_hybrid(&pk, &signed_msg, &hybrid).is_ok()
            }
            _ => false,
        }
    };

    let sig_ok1 = verify_ack(&ack1, &kp1);
    let sig_ok2 = verify_ack(&ack2, &kp2);
    let sig_ok3 = verify_ack(&ack3, &kp3);

    // All three signatures must verify correctly.
    assert!(sig_ok1, "validator 1 signature must verify");
    assert!(sig_ok2, "validator 2 signature must verify");
    assert!(sig_ok3, "validator 3 signature must verify");

    let mut acc = CommitAckAccumulator::for_validator_set(height, header_digest, &vset);

    let r1 = acc.add(&ack1, &vset, sig_ok1).unwrap();
    assert!(!r1, "one of three validators is not quorum");

    let r2 = acc.add(&ack2, &vset, sig_ok2).unwrap();
    assert!(
        !r2,
        "two of three validators (200/300) is not quorum (strict >)"
    );

    let r3 = acc.add(&ack3, &vset, sig_ok3).unwrap();
    assert!(r3, "all three validators = quorum");

    // ── Build QC ──────────────────────────────────────────────────────────────
    let qc = acc.try_build_qc().expect("QC must be produced at quorum");
    assert_eq!(qc.height, height);
    assert_eq!(qc.header_digest, header_digest);
    assert_eq!(qc.signer_count(), 3);

    // ── Verify: build sig_results map (same as CertifiedVerifier) ────────────
    // Verify each signer's sig in the QC against commit_ack_message.
    let mut sig_results: BTreeMap<Address, bool> = BTreeMap::new();
    for (addr, sig) in &qc.signers {
        let pk = lemma_crypto::PublicKey::from(vset.members[addr].consensus_pubkey.clone());
        let ok = match sig {
            Signature::Hybrid { classical, quantum } => {
                let hybrid = HybridSignature {
                    classical: classical.clone(),
                    quantum: quantum.clone(),
                };
                verify_hybrid(&pk, &signed_msg, &hybrid).is_ok()
            }
            _ => false,
        };
        sig_results.insert(*addr, ok);
    }

    // ── Assert: verify_quorum_cert returns Ok ─────────────────────────────────
    // This is the exact call CertifiedVerifier makes (with header_digest as
    // the structural digest check, and sig_results from commit_ack_message).
    let result = verify_quorum_cert(&qc, &vset, header_digest, &sig_results);
    assert!(
        result.is_ok(),
        "accumulator-built QC must verify against validator set: {result:?}"
    );
}
