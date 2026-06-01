//! Tests for `lemma_consensus::epoch::proof` — epoch-change proof §4.4 (B4a).
//!
//! ## Coverage (spec §10)
//!
//! - Light client trusting epoch N verifies boundary cert → reads
//!   next_validators_hash → adopts N+1 committee.
//! - Cannot adopt committee not authorized by quorum-certified boundary header.
//! - verify_full: vset hash mismatch, cert digest mismatch, insufficient quorum.
//! - verify_epoch_change: single hop, multi hop, empty proof, length mismatch,
//!   wrong next_vset hash, wrong validators_hash, cert failure mid-chain.
//! - Determinism: same inputs → same result.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    header::BlockHeader,
    signature::Signature,
    QuorumCert,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};

use crate::epoch::proof::{verify_epoch_change, verify_full, EpochChangeProof, ProofError};

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

fn make_vset(members: &[(u8, u128)]) -> ValidatorSet {
    let map: BTreeMap<_, _> = members
        .iter()
        .map(|&(b, p)| {
            (addr(b), Member {
                consensus_pubkey: ConsensusKey::from_bytes(vec![b; 32], vec![b; 32]),
                power: power(p),
            })
        })
        .collect();
    let total = map.values().fold(Amount::zero(), |a, m| {
        a.checked_add(m.power.as_amount()).unwrap()
    });
    ValidatorSet { epoch: 0, members: map, total_power: total }
}

fn make_cert(digest: Hash, signers: &[u8]) -> QuorumCert {
    let map = signers.iter().map(|&b| (addr(b), Signature::Unsigned)).collect();
    QuorumCert::new(0, digest, map)
}

fn all_valid(signers: &[u8]) -> BTreeMap<Address, bool> {
    signers.iter().map(|&b| (addr(b), true)).collect()
}

/// Build a minimal valid BlockHeader for boundary tests.
///
/// Sets `validators_hash` and `next_validators_hash` to the given values;
/// all other fields get valid-but-arbitrary values.
fn make_boundary_header(
    height: u64,
    epoch: u64,
    validators_hash: Hash,
    next_validators_hash: Hash,
) -> BlockHeader {
    BlockHeader::new(
        height,
        1_700_000_000 + height,           // timestamp
        hash(0),                           // parent_hash
        hash(0),                           // transactions_root
        hash(0),                           // state_root
        hash(0),                           // receipts_root
        addr(0),                           // proposer
        epoch,
        0,                                 // dag_round
        hash(0),                           // dag_anchor
        validators_hash,
        next_validators_hash,
        1_000_000,                         // gas_limit > 0
        0,                                 // gas_used
        Amount::from_drop(1_000_000_000),  // base_fee
        vec![],                            // extra_data
    ).expect("test header must be valid")
}

// ── verify_full ───────────────────────────────────────────────────────────────

#[test]
fn verify_full_valid_passes() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_hash = vset.hash();
    let digest = hash(0xAB);
    let header = make_boundary_header(10, 0, vset_hash, hash(0xFF));
    let qc = make_cert(digest, &[1, 2, 3]);
    let sigs = all_valid(&[1, 2, 3]);

    assert!(verify_full(&vset, &header, digest, &qc, &sigs).is_ok());
}

#[test]
fn verify_full_rejects_wrong_vset_hash() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let wrong_vset_hash = hash(0xFF); // not vset.hash()
    let digest = hash(0xAB);
    let header = make_boundary_header(10, 0, wrong_vset_hash, hash(0xFF));
    let qc = make_cert(digest, &[1, 2, 3]);
    let sigs = all_valid(&[1, 2, 3]);

    let err = verify_full(&vset, &header, digest, &qc, &sigs).unwrap_err();
    assert!(
        matches!(err, ProofError::ValidatorSetHashMismatch { index: 0, .. }),
        "vset hash mismatch must → ValidatorSetHashMismatch"
    );
}

#[test]
fn verify_full_rejects_cert_digest_mismatch() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_hash = vset.hash();
    let cert_digest = hash(0xAA);
    let caller_digest = hash(0xBB); // different from cert
    let header = make_boundary_header(10, 0, vset_hash, hash(0xFF));
    let qc = make_cert(cert_digest, &[1, 2, 3]);
    let sigs = all_valid(&[1, 2, 3]);

    let err = verify_full(&vset, &header, caller_digest, &qc, &sigs).unwrap_err();
    assert!(matches!(err, ProofError::CertFailed { index: 0, .. }));
}

#[test]
fn verify_full_rejects_insufficient_quorum() {
    // Equal power 100 each, total 300. Need >200. Two signers = 200 = exactly threshold → not enough.
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_hash = vset.hash();
    let digest = hash(0xAB);
    let header = make_boundary_header(10, 0, vset_hash, hash(0xFF));
    let qc = make_cert(digest, &[1, 2]); // only 2 of 3
    let sigs = all_valid(&[1, 2]);

    let err = verify_full(&vset, &header, digest, &qc, &sigs).unwrap_err();
    assert!(matches!(err, ProofError::CertFailed { index: 0, .. }));
}

// ── verify_epoch_change: structural checks ────────────────────────────────────

#[test]
fn verify_epoch_change_rejects_empty_proof() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let proof = EpochChangeProof {
        boundary_headers: vec![],
        boundary_certs: vec![],
        next_validator_sets: vec![],
    };

    let err = verify_epoch_change(&proof, &vset, &[], &[]).unwrap_err();
    assert!(matches!(err, ProofError::EmptyProof));
}

#[test]
fn verify_epoch_change_rejects_length_mismatch_certs() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_hash = vset.hash();
    let next_vset = make_vset(&[(4, 100), (5, 100), (6, 100)]);
    let digest = hash(0xAB);

    let proof = EpochChangeProof {
        boundary_headers: vec![make_boundary_header(10, 0, vset_hash, next_vset.hash())],
        boundary_certs: vec![], // length mismatch
        next_validator_sets: vec![next_vset],
    };

    let err = verify_epoch_change(&proof, &vset, &[digest], &[all_valid(&[1, 2, 3])]).unwrap_err();
    assert!(matches!(err, ProofError::LengthMismatch { headers: 1, certs: 0, .. }));
}

#[test]
fn verify_epoch_change_rejects_injected_data_length_mismatch() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_hash = vset.hash();
    let next_vset = make_vset(&[(4, 100), (5, 100), (6, 100)]);
    let digest = hash(0xAB);

    let proof = EpochChangeProof {
        boundary_headers: vec![make_boundary_header(10, 0, vset_hash, next_vset.hash())],
        boundary_certs: vec![make_cert(digest, &[1, 2, 3])],
        next_validator_sets: vec![next_vset],
    };

    // Missing header_digests (length 0 vs 1 header)
    let err = verify_epoch_change(&proof, &vset, &[], &[all_valid(&[1, 2, 3])]).unwrap_err();
    assert!(matches!(err, ProofError::InjectedDataLengthMismatch { headers: 1, digests: 0, .. }));
}

// ── verify_epoch_change: single-hop ──────────────────────────────────────────

/// spec §10: "A light client trusting epoch N verifies the boundary quorum cert,
/// reads next_validators_hash, adopts epoch N+1's committee."
#[test]
fn verify_epoch_change_single_hop_passes() {
    let vset_n = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_n1 = make_vset(&[(4, 100), (5, 100), (6, 100)]);
    let vset_n_hash = vset_n.hash();
    let vset_n1_hash = vset_n1.hash();
    let digest = hash(0xAB);

    let header = make_boundary_header(10, 0, vset_n_hash, vset_n1_hash);
    let qc = make_cert(digest, &[1, 2, 3]);

    let proof = EpochChangeProof {
        boundary_headers: vec![header],
        boundary_certs: vec![qc],
        next_validator_sets: vec![vset_n1],
    };

    assert!(
        verify_epoch_change(&proof, &vset_n, &[digest], &[all_valid(&[1, 2, 3])]).is_ok(),
        "valid single-hop must pass"
    );
}

/// spec §10: "cannot adopt a committee not authorized by a quorum-certified boundary header."
#[test]
fn verify_epoch_change_rejects_wrong_next_vset_hash() {
    let vset_n = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_n_hash = vset_n.hash();
    let claimed_next = make_vset(&[(4, 100), (5, 100), (6, 100)]);
    let forged_next = make_vset(&[(7, 100), (8, 100), (9, 100)]); // not what header commits
    let digest = hash(0xAB);

    // Header commits hash of claimed_next, but proof provides forged_next.
    let header = make_boundary_header(10, 0, vset_n_hash, claimed_next.hash());
    let qc = make_cert(digest, &[1, 2, 3]);

    let proof = EpochChangeProof {
        boundary_headers: vec![header],
        boundary_certs: vec![qc],
        next_validator_sets: vec![forged_next], // wrong!
    };

    let err = verify_epoch_change(&proof, &vset_n, &[digest], &[all_valid(&[1, 2, 3])]).unwrap_err();
    assert!(
        matches!(err, ProofError::NextValidatorSetHashMismatch { index: 0, .. }),
        "forged next_vset must → NextValidatorSetHashMismatch"
    );
}

#[test]
fn verify_epoch_change_rejects_wrong_validators_hash_in_header() {
    let vset_n = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_n1 = make_vset(&[(4, 100), (5, 100), (6, 100)]);
    let wrong_hash = hash(0xFF); // not vset_n.hash()
    let digest = hash(0xAB);

    // Header claims wrong validators_hash.
    let header = make_boundary_header(10, 0, wrong_hash, vset_n1.hash());
    let qc = make_cert(digest, &[1, 2, 3]);

    let proof = EpochChangeProof {
        boundary_headers: vec![header],
        boundary_certs: vec![qc],
        next_validator_sets: vec![vset_n1],
    };

    let err = verify_epoch_change(&proof, &vset_n, &[digest], &[all_valid(&[1, 2, 3])]).unwrap_err();
    assert!(
        matches!(err, ProofError::ValidatorSetHashMismatch { index: 0, .. }),
        "wrong validators_hash in boundary header must → ValidatorSetHashMismatch"
    );
}

#[test]
fn verify_epoch_change_rejects_insufficient_quorum() {
    let vset_n = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_n1 = make_vset(&[(4, 100), (5, 100), (6, 100)]);
    let vset_n_hash = vset_n.hash();
    let digest = hash(0xAB);

    let header = make_boundary_header(10, 0, vset_n_hash, vset_n1.hash());
    let qc = make_cert(digest, &[1, 2]); // only 2/3, not >2/3

    let proof = EpochChangeProof {
        boundary_headers: vec![header],
        boundary_certs: vec![qc],
        next_validator_sets: vec![vset_n1],
    };

    let err = verify_epoch_change(&proof, &vset_n, &[digest], &[all_valid(&[1, 2])]).unwrap_err();
    assert!(
        matches!(err, ProofError::CertFailed { index: 0, .. }),
        "insufficient quorum must → CertFailed"
    );
}

// ── verify_epoch_change: multi-hop ───────────────────────────────────────────

#[test]
fn verify_epoch_change_multi_hop_passes() {
    // Epoch N → N+1 → N+2 (two boundary headers).
    let vset_n  = make_vset(&[(1, 100), (2, 100), (3, 100)]); // initial trust
    let vset_n1 = make_vset(&[(4, 100), (5, 100), (6, 100)]);
    let vset_n2 = make_vset(&[(7, 100), (8, 100), (9, 100)]);

    let digest_0 = hash(0xA0);
    let digest_1 = hash(0xA1);

    let header_0 = make_boundary_header(10, 0, vset_n.hash(), vset_n1.hash());
    let header_1 = make_boundary_header(20, 1, vset_n1.hash(), vset_n2.hash());
    let qc_0 = make_cert(digest_0, &[1, 2, 3]);
    let qc_1 = make_cert(digest_1, &[4, 5, 6]); // N+1 committee signs

    let proof = EpochChangeProof {
        boundary_headers: vec![header_0, header_1],
        boundary_certs: vec![qc_0, qc_1],
        next_validator_sets: vec![vset_n1, vset_n2],
    };

    assert!(
        verify_epoch_change(
            &proof, &vset_n,
            &[digest_0, digest_1],
            &[all_valid(&[1, 2, 3]), all_valid(&[4, 5, 6])]
        ).is_ok(),
        "valid two-hop epoch-change proof must pass"
    );
}

#[test]
fn verify_epoch_change_multi_hop_fails_at_second_step() {
    let vset_n  = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_n1 = make_vset(&[(4, 100), (5, 100), (6, 100)]);
    let vset_n2 = make_vset(&[(7, 100), (8, 100), (9, 100)]);
    let forged_n2 = make_vset(&[(10, 100), (11, 100), (12, 100)]);

    let digest_0 = hash(0xA0);
    let digest_1 = hash(0xA1);

    let header_0 = make_boundary_header(10, 0, vset_n.hash(), vset_n1.hash());
    let header_1 = make_boundary_header(20, 1, vset_n1.hash(), vset_n2.hash());
    let qc_0 = make_cert(digest_0, &[1, 2, 3]);
    let qc_1 = make_cert(digest_1, &[4, 5, 6]);

    let proof = EpochChangeProof {
        boundary_headers: vec![header_0, header_1],
        boundary_certs: vec![qc_0, qc_1],
        next_validator_sets: vec![vset_n1, forged_n2], // forged at step 1
    };

    let err = verify_epoch_change(
        &proof, &vset_n,
        &[digest_0, digest_1],
        &[all_valid(&[1, 2, 3]), all_valid(&[4, 5, 6])]
    ).unwrap_err();

    assert!(
        matches!(err, ProofError::NextValidatorSetHashMismatch { index: 1, .. }),
        "forged vset at step 1 must → error at index 1"
    );
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn verify_full_deterministic() {
    let vset = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_hash = vset.hash();
    let digest = hash(0xAB);
    let header = make_boundary_header(10, 0, vset_hash, hash(0xFF));
    let qc = make_cert(digest, &[1, 2, 3]);
    let sigs = all_valid(&[1, 2, 3]);

    let r1 = verify_full(&vset, &header, digest, &qc, &sigs);
    let r2 = verify_full(&vset, &header, digest, &qc, &sigs);
    assert_eq!(r1.is_ok(), r2.is_ok(), "verify_full must be deterministic");
}

#[test]
fn verify_epoch_change_deterministic() {
    let vset_n  = make_vset(&[(1, 100), (2, 100), (3, 100)]);
    let vset_n1 = make_vset(&[(4, 100), (5, 100), (6, 100)]);
    let digest = hash(0xAB);
    let header = make_boundary_header(10, 0, vset_n.hash(), vset_n1.hash());
    let qc = make_cert(digest, &[1, 2, 3]);
    let proof = EpochChangeProof {
        boundary_headers: vec![header],
        boundary_certs: vec![qc],
        next_validator_sets: vec![vset_n1],
    };

    let r1 = verify_epoch_change(&proof, &vset_n, &[digest], &[all_valid(&[1, 2, 3])]);
    let r2 = verify_epoch_change(&proof, &vset_n, &[digest], &[all_valid(&[1, 2, 3])]);
    assert_eq!(r1.is_ok(), r2.is_ok(), "verify_epoch_change must be deterministic");
}
