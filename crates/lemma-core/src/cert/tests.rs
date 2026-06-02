//! Tests for `lemma_core::cert` — QuorumCert data type.

use std::collections::BTreeMap;

use crate::{address::Address, cert::QuorumCert, hash::Hash, signature::Signature};

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn hash(n: u8) -> Hash {
    Hash::from_bytes([n; 32])
}

fn dummy_sig() -> Signature {
    Signature::Unsigned
}

#[test]
fn new_creates_quorum_cert_with_correct_fields() {
    let digest = hash(0xAA);
    let mut signers = BTreeMap::new();
    signers.insert(addr(1), dummy_sig());
    signers.insert(addr(2), dummy_sig());

    let qc = QuorumCert::new(42, digest, signers.clone());
    assert_eq!(qc.height, 42);
    assert_eq!(qc.header_digest, digest);
    assert_eq!(qc.signers.len(), 2);
}

#[test]
fn signer_count_reflects_map_length() {
    let mut signers = BTreeMap::new();
    signers.insert(addr(1), dummy_sig());
    signers.insert(addr(2), dummy_sig());
    signers.insert(addr(3), dummy_sig());

    let qc = QuorumCert::new(0, hash(0), signers);
    assert_eq!(qc.signer_count(), 3);
}

#[test]
fn empty_cert_has_zero_signers() {
    let qc = QuorumCert::new(0, hash(0), BTreeMap::new());
    assert_eq!(qc.signer_count(), 0);
}

#[test]
fn cert_equality_by_fields() {
    let make = || {
        QuorumCert::new(10, hash(1), {
            let mut m = BTreeMap::new();
            m.insert(addr(1), dummy_sig());
            m
        })
    };
    assert_eq!(make(), make(), "identical certs must be equal");
}

#[test]
fn cert_inequality_on_different_digest() {
    let qc_a = QuorumCert::new(10, hash(0xAA), BTreeMap::new());
    let qc_b = QuorumCert::new(10, hash(0xBB), BTreeMap::new());
    assert_ne!(qc_a, qc_b);
}

#[test]
fn cert_serializes_and_deserializes() {
    let mut signers = BTreeMap::new();
    signers.insert(addr(1), dummy_sig());
    let qc = QuorumCert::new(99, hash(0xCC), signers);
    let json = serde_json::to_string(&qc).expect("serialize");
    let back: QuorumCert = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(qc, back);
}
