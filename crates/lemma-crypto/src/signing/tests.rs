//! Tests for `lemma_crypto::signing`.
//!
//! Coverage:
//!  - compute_tx_hash: determinism, non-zero, changes with field changes
//!  - sign_transaction: sets hash + Hybrid signature, roundtrip verify
//!  - verify_transaction: happy path, tampered fields, wrong key, error variants

use lemma_core::{
    transaction::{Transaction, TxType},
    Address, Amount, Hash, Signature,
};

use crate::{
    keypair::KeyPair,
    signing::{compute_tx_hash, sign_transaction, verify_transaction},
    CryptoError,
};

// ─── Fixtures ────────────────────────────────────────────────────────────────

fn keypair() -> KeyPair {
    KeyPair::generate().expect("keygen succeeds on healthy OS")
}

/// A minimal valid unsigned transaction using the given keypair's address.
fn unsigned_tx(kp: &KeyPair) -> Transaction {
    Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::zero()),
        /*nonce*/ 0,
        /*chain_id*/ 1,
        /*value*/ Amount::zero(),
        /*gas_limit*/ 1_000_000,
        /*gas_price*/ Amount::from_drop(1_000_000_000),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("valid unsigned tx")
}

// ─── compute_tx_hash ─────────────────────────────────────────────────────────

#[test]
fn compute_tx_hash_succeeds() {
    let kp = keypair();
    let tx = unsigned_tx(&kp);
    assert!(compute_tx_hash(&tx).is_ok());
}

#[test]
fn compute_tx_hash_is_non_zero() {
    let kp = keypair();
    let tx = unsigned_tx(&kp);
    let h = compute_tx_hash(&tx).unwrap();
    assert!(!h.is_zero());
}

#[test]
fn compute_tx_hash_is_deterministic() {
    let kp = keypair();
    let tx = unsigned_tx(&kp);
    assert_eq!(compute_tx_hash(&tx).unwrap(), compute_tx_hash(&tx).unwrap());
}

#[test]
fn compute_tx_hash_differs_for_different_nonce() {
    let kp = keypair();
    let tx1 = unsigned_tx(&kp);
    let tx2 = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::zero()),
        /*nonce*/ 1,
        1,
        Amount::zero(),
        1_000_000,
        Amount::from_drop(1_000_000_000),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .unwrap();
    assert_ne!(
        compute_tx_hash(&tx1).unwrap(),
        compute_tx_hash(&tx2).unwrap()
    );
}

#[test]
fn compute_tx_hash_differs_for_different_chain_id() {
    let kp = keypair();
    let tx1 = unsigned_tx(&kp); // chain_id = 1
    let tx2 = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::zero()),
        0,
        /*chain_id*/ 2,
        Amount::zero(),
        1_000_000,
        Amount::from_drop(1_000_000_000),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .unwrap();
    assert_ne!(
        compute_tx_hash(&tx1).unwrap(),
        compute_tx_hash(&tx2).unwrap(),
        "different chain_id must produce different hash (replay protection)"
    );
}

#[test]
fn compute_tx_hash_ignores_existing_hash_field() {
    // The `hash` field is NOT part of the signing payload — changing it must
    // not change the computed hash (it is the output, not the input).
    let kp = keypair();
    let mut tx1 = unsigned_tx(&kp);
    let mut tx2 = unsigned_tx(&kp);
    tx1.hash = Hash::zero();
    tx2.hash = Hash::from_bytes([0xAB; 32]);
    assert_eq!(
        compute_tx_hash(&tx1).unwrap(),
        compute_tx_hash(&tx2).unwrap(),
        "`hash` field must be excluded from signing payload"
    );
}

#[test]
fn compute_tx_hash_ignores_existing_signature_field() {
    // The `signature` field is NOT part of the signing payload.
    let kp = keypair();
    let mut tx1 = unsigned_tx(&kp);
    let mut tx2 = unsigned_tx(&kp);
    tx1.signature = Signature::Unsigned;
    tx2.signature = Signature::Classical {
        bytes: vec![0u8; 64],
    };
    assert_eq!(
        compute_tx_hash(&tx1).unwrap(),
        compute_tx_hash(&tx2).unwrap(),
        "`signature` field must be excluded from signing payload"
    );
}

// ─── sign_transaction ────────────────────────────────────────────────────────

#[test]
fn sign_transaction_marks_tx_as_signed() {
    let kp = keypair();
    let mut tx = unsigned_tx(&kp);
    sign_transaction(&mut tx, &kp).unwrap();
    assert!(tx.is_signed());
}

#[test]
fn sign_transaction_sets_hybrid_signature() {
    let kp = keypair();
    let mut tx = unsigned_tx(&kp);
    sign_transaction(&mut tx, &kp).unwrap();
    assert!(matches!(tx.signature, Signature::Hybrid { .. }));
}

#[test]
fn sign_transaction_sets_non_zero_hash() {
    let kp = keypair();
    let mut tx = unsigned_tx(&kp);
    sign_transaction(&mut tx, &kp).unwrap();
    assert!(!tx.hash.is_zero());
}

#[test]
fn sign_transaction_hash_matches_compute_tx_hash() {
    // The hash stored in tx.hash after signing must equal compute_tx_hash
    // called on the *pre-sign* body (payload excludes hash+sig fields).
    let kp = keypair();
    let mut tx = unsigned_tx(&kp);
    let expected = compute_tx_hash(&tx).unwrap();
    sign_transaction(&mut tx, &kp).unwrap();
    assert_eq!(tx.hash, expected);
}

// ─── verify_transaction — happy path ─────────────────────────────────────────

#[test]
fn sign_then_verify_succeeds() {
    let kp = keypair();
    let pk = kp.public_key();
    let mut tx = unsigned_tx(&kp);
    sign_transaction(&mut tx, &kp).unwrap();
    assert!(verify_transaction(&tx, &pk).is_ok());
}

#[test]
fn verify_rejects_tampered_data_field() {
    let kp = keypair();
    let pk = kp.public_key();
    let mut tx = unsigned_tx(&kp);
    sign_transaction(&mut tx, &kp).unwrap();
    tx.data = vec![0xFF, 0xFE]; // tamper after signing
    assert!(verify_transaction(&tx, &pk).is_err());
}

#[test]
fn verify_rejects_tampered_nonce() {
    let kp = keypair();
    let pk = kp.public_key();
    let mut tx = unsigned_tx(&kp);
    sign_transaction(&mut tx, &kp).unwrap();
    tx.nonce = 999;
    assert!(verify_transaction(&tx, &pk).is_err());
}

#[test]
fn verify_rejects_tampered_chain_id() {
    let kp = keypair();
    let pk = kp.public_key();
    let mut tx = unsigned_tx(&kp);
    sign_transaction(&mut tx, &kp).unwrap();
    tx.chain_id = 42; // different chain
    assert!(verify_transaction(&tx, &pk).is_err());
}

#[test]
fn verify_rejects_wrong_public_key() {
    let kp1 = keypair();
    let kp2 = keypair();
    let pk2 = kp2.public_key();
    let mut tx = unsigned_tx(&kp1);
    sign_transaction(&mut tx, &kp1).unwrap();
    // tx signed by kp1 must not verify under kp2's public key.
    assert!(verify_transaction(&tx, &pk2).is_err());
}

// ─── verify_transaction — error variant enforcement ──────────────────────────

#[test]
fn verify_returns_unsigned_transaction_for_unsigned_sig() {
    let kp = keypair();
    let pk = kp.public_key();
    let tx = unsigned_tx(&kp); // still Signature::Unsigned
    let result = verify_transaction(&tx, &pk);
    assert!(
        matches!(result, Err(CryptoError::UnsignedTransaction)),
        "expected UnsignedTransaction, got: {result:?}"
    );
}

#[test]
fn verify_returns_hybrid_required_for_classical_sig() {
    let kp = keypair();
    let pk = kp.public_key();
    let mut tx = unsigned_tx(&kp);
    tx.signature = Signature::Classical {
        bytes: vec![0u8; 64],
    };
    let result = verify_transaction(&tx, &pk);
    assert!(
        matches!(
            result,
            Err(CryptoError::HybridSignatureRequired { got: "Classical" })
        ),
        "expected HybridSignatureRequired{{got:Classical}}, got: {result:?}"
    );
}

#[test]
fn verify_returns_hybrid_required_for_post_quantum_sig() {
    let kp = keypair();
    let pk = kp.public_key();
    let mut tx = unsigned_tx(&kp);
    tx.signature = Signature::PostQuantum {
        bytes: vec![0u8; 100],
    };
    let result = verify_transaction(&tx, &pk);
    assert!(
        matches!(
            result,
            Err(CryptoError::HybridSignatureRequired { got: "PostQuantum" })
        ),
        "expected HybridSignatureRequired{{got:PostQuantum}}, got: {result:?}"
    );
}
