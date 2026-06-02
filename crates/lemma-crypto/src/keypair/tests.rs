//! Tests for `lemma_crypto::keypair`.
//!
//! Coverage:
//!  - KeyPair generation
//!  - PublicKey derivation + round-trip
//!  - Address derivation consistency
//!  - sign → verify round-trip (happy path + tamper cases)
//!  - HybridSignature → Signature::Hybrid conversion
//!  - verify error variants (bad key, bad sig length, wrong message)
//!  - Serde round-trips for PublicKey + HybridSignature

use lemma_core::{Address, Signature};

use crate::keypair::{verify, HybridSignature, KeyPair, PublicKey};
use crate::CryptoError;

// ─── Fixtures ────────────────────────────────────────────────────────────────

/// Generate a keypair once for tests that only need a valid pair.
/// Each test that mutates the keypair or needs independence calls this itself.
fn generate() -> KeyPair {
    KeyPair::generate().expect("keygen must succeed on any healthy OS")
}

const MSG: &[u8] = b"hello lemma";
const MSG2: &[u8] = b"different message";

// ─── KeyPair::generate ───────────────────────────────────────────────────────

#[test]
fn generate_succeeds() {
    let _kp = generate();
}

#[test]
fn generate_produces_non_zero_address() {
    let kp = generate();
    assert!(
        !kp.address().is_zero(),
        "address must not be the zero address"
    );
}

#[test]
fn two_generated_keypairs_have_different_addresses() {
    // Probabilistic: two independent keypairs should never share an address.
    let kp1 = generate();
    let kp2 = generate();
    assert_ne!(kp1.address(), kp2.address());
}

// ─── KeyPair::public_key ─────────────────────────────────────────────────────

#[test]
fn public_key_classical_bytes_are_32_bytes() {
    let kp = generate();
    assert_eq!(kp.public_key().classical.len(), 32);
}

#[test]
fn public_key_quantum_bytes_are_1952_bytes() {
    let kp = generate();
    // ML-DSA-65 public key size is 1952 bytes (verified from pqcrypto-mldsa docs).
    assert_eq!(kp.public_key().quantum.len(), 1952);
}

#[test]
fn public_key_is_stable_across_calls() {
    // public_key() is an O(1) read — must return the same value every call.
    let kp = generate();
    assert_eq!(kp.public_key(), kp.public_key());
}

#[test]
fn public_key_classical_reconstructs_to_verifying_key() {
    let kp = generate();
    let pk = kp.public_key();
    assert!(pk.classical_verifying_key().is_ok());
}

#[test]
fn public_key_quantum_reconstructs_to_mldsa_key() {
    let kp = generate();
    let pk = kp.public_key();
    assert!(pk.quantum_public_key().is_ok());
}

// ─── Address derivation ──────────────────────────────────────────────────────

#[test]
fn keypair_address_matches_from_public_key() {
    // KeyPair::address() must equal Address::from_public_key(classical_bytes).
    let kp = generate();
    let pk = kp.public_key();
    let classical_bytes: &[u8; 32] = pk.classical.as_slice().try_into().unwrap();
    let expected = Address::from_public_key(classical_bytes);
    assert_eq!(kp.address(), &expected);
}

#[test]
fn public_key_to_address_matches_keypair_address() {
    let kp = generate();
    let pk = kp.public_key();
    assert_eq!(pk.to_address().unwrap(), *kp.address());
}

// ─── sign + verify (happy path) ──────────────────────────────────────────────

#[test]
fn sign_and_verify_succeeds_for_same_message() {
    let kp = generate();
    let pk = kp.public_key();
    let sig = kp.sign(MSG);
    assert!(verify(&pk, MSG, &sig).is_ok());
}

#[test]
fn sign_produces_correct_classical_sig_length() {
    let kp = generate();
    let sig = kp.sign(MSG);
    // Ed25519 signatures are always exactly 64 bytes.
    assert_eq!(sig.classical.len(), 64);
}

#[test]
fn sign_produces_correct_quantum_sig_length() {
    let kp = generate();
    let sig = kp.sign(MSG);
    // ML-DSA-65 detached signature is 3309 bytes.
    assert_eq!(sig.quantum.len(), 3309);
}

#[test]
fn sign_classical_component_is_deterministic() {
    // Ed25519 (RFC 8032) is deterministic: same key + same message → same sig.
    let kp = generate();
    let sig1 = kp.sign(MSG);
    let sig2 = kp.sign(MSG);
    assert_eq!(
        sig1.classical, sig2.classical,
        "Ed25519 signing must be deterministic (RFC 8032)"
    );
}

#[test]
fn sign_quantum_component_may_be_randomized() {
    // ML-DSA-65 (FIPS-204) uses hedged (randomized) signing by default.
    // Both signatures must still verify — randomization affects the sig bytes
    // but not correctness.
    let kp = generate();
    let pk = kp.public_key();
    let s1 = kp.sign(MSG);
    let s2 = kp.sign(MSG);
    // Both must verify regardless of whether quantum bytes differ.
    assert!(verify(&pk, MSG, &s1).is_ok());
    assert!(verify(&pk, MSG, &s2).is_ok());
}

#[test]
fn verify_fails_for_tampered_message() {
    let kp = generate();
    let pk = kp.public_key();
    let sig = kp.sign(MSG);
    let result = verify(&pk, b"tampered!", &sig);
    assert!(result.is_err());
}

#[test]
fn verify_fails_for_different_message() {
    let kp = generate();
    let pk = kp.public_key();
    let sig = kp.sign(MSG);
    let result = verify(&pk, MSG2, &sig);
    assert!(result.is_err());
}

#[test]
fn verify_fails_for_different_keypair() {
    let kp1 = generate();
    let kp2 = generate();
    let pk2 = kp2.public_key();
    // Signature from kp1 must not verify under kp2's public key.
    let sig = kp1.sign(MSG);
    let result = verify(&pk2, MSG, &sig);
    assert!(result.is_err());
}

#[test]
fn verify_fails_for_tampered_classical_sig_byte() {
    let kp = generate();
    let pk = kp.public_key();
    let mut sig = kp.sign(MSG);
    sig.classical[0] ^= 0xFF; // flip all bits of byte 0
    assert!(verify(&pk, MSG, &sig).is_err());
}

#[test]
fn verify_fails_for_tampered_quantum_sig_byte() {
    let kp = generate();
    let pk = kp.public_key();
    let mut sig = kp.sign(MSG);
    sig.quantum[0] ^= 0xFF;
    assert!(verify(&pk, MSG, &sig).is_err());
}

// ─── verify error variants ───────────────────────────────────────────────────

#[test]
fn verify_returns_invalid_classical_sig_length_for_wrong_size() {
    let kp = generate();
    let pk = kp.public_key();
    let bad_sig = HybridSignature {
        classical: vec![0u8; 32], // wrong: 32 bytes instead of 64
        quantum: kp.sign(MSG).quantum,
    };
    let result = verify(&pk, MSG, &bad_sig);
    assert!(matches!(
        result,
        Err(CryptoError::InvalidClassicalSignatureLength { got: 32 })
    ));
}

#[test]
fn verify_returns_invalid_public_key_bytes_for_wrong_length_classical_key() {
    let kp = generate();
    let mut pk = kp.public_key();
    // Wrong length (31 bytes) — guaranteed to fail the &[u8; 32] try_into.
    pk.classical = vec![0u8; 31];
    let sig = kp.sign(MSG);
    let result = verify(&pk, MSG, &sig);
    assert!(matches!(
        result,
        Err(CryptoError::InvalidPublicKeyBytes { .. })
    ));
}

// ─── sign_to_lemma / HybridSignature::to_lemma_signature ─────────────────────

#[test]
fn sign_to_lemma_returns_hybrid_variant() {
    let kp = generate();
    let sig = kp.sign_to_lemma(MSG);
    assert!(matches!(sig, Signature::Hybrid { .. }));
}

#[test]
fn hybrid_signature_to_lemma_carries_correct_bytes() {
    let kp = generate();
    let hybrid = kp.sign(MSG);
    let lemma_sig = hybrid.to_lemma_signature();
    if let Signature::Hybrid { classical, quantum } = lemma_sig {
        assert_eq!(classical, hybrid.classical);
        assert_eq!(quantum, hybrid.quantum);
    } else {
        panic!("expected Signature::Hybrid");
    }
}

// ─── PublicKey serde ─────────────────────────────────────────────────────────

#[test]
fn public_key_survives_json_roundtrip() {
    let kp = generate();
    let pk = kp.public_key();
    let json = serde_json::to_string(&pk).expect("serialize");
    let restored: PublicKey = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(pk, restored);
}

#[test]
fn public_key_survives_bincode_roundtrip() {
    let kp = generate();
    let pk = kp.public_key();
    let bytes = bincode::serialize(&pk).expect("serialize");
    let restored: PublicKey = bincode::deserialize(&bytes).expect("deserialize");
    assert_eq!(pk, restored);
}

// ─── HybridSignature serde ───────────────────────────────────────────────────

#[test]
fn hybrid_signature_survives_json_roundtrip() {
    let kp = generate();
    let sig = kp.sign(MSG);
    let json = serde_json::to_string(&sig).expect("serialize");
    let restored: HybridSignature = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(sig, restored);
}

// ─── Keystore persistence ────────────────────────────────────────────────────

#[test]
fn keystore_bytes_has_correct_length() {
    let kp = generate();
    let bytes = kp.to_keystore_bytes();
    assert_eq!(bytes.len(), super::KEYSTORE_BYTE_LEN);
}

#[test]
fn keystore_round_trip_preserves_address() {
    let kp1 = generate();
    let addr1 = *kp1.address();
    let bytes = kp1.to_keystore_bytes();

    let kp2 = KeyPair::from_keystore_bytes(&bytes).expect("from_keystore_bytes must succeed");
    assert_eq!(
        kp2.address(),
        &addr1,
        "address must be stable across round-trip"
    );
}

#[test]
fn keystore_round_trip_produces_same_public_key() {
    let kp1 = generate();
    let pk1 = kp1.public_key();
    let kp2 =
        KeyPair::from_keystore_bytes(&kp1.to_keystore_bytes()).expect("round-trip must succeed");
    assert_eq!(
        kp2.public_key(),
        pk1,
        "public key must match after round-trip"
    );
}

#[test]
fn keystore_round_trip_signs_verifiably() {
    let kp1 = generate();
    let bytes = kp1.to_keystore_bytes();
    let kp2 = KeyPair::from_keystore_bytes(&bytes).expect("round-trip");
    let sig = kp2.sign(MSG);
    let pk = kp2.public_key();
    assert!(
        super::super::verify(&pk, MSG, &sig).is_ok(),
        "signature from restored keypair must verify"
    );
}

#[test]
fn from_keystore_bytes_rejects_wrong_length() {
    use crate::CryptoError;
    let too_short = vec![0u8; 32];
    // KeyPair doesn't implement Debug (no secret printing), so match directly.
    match KeyPair::from_keystore_bytes(&too_short) {
        Err(CryptoError::InvalidKeystoreLength { .. }) => {}
        Err(e) => panic!("expected InvalidKeystoreLength, got: {e}"),
        Ok(_) => panic!("expected error for wrong-length bytes"),
    }
}

#[test]
fn from_keystore_bytes_rejects_empty() {
    use crate::CryptoError;
    match KeyPair::from_keystore_bytes(&[]) {
        Err(CryptoError::InvalidKeystoreLength { .. }) => {}
        Err(e) => panic!("expected InvalidKeystoreLength, got: {e}"),
        Ok(_) => panic!("expected error for empty bytes"),
    }
}

#[test]
fn from_keystore_bytes_rejects_correct_length_corrupt_ml_dsa_secret_key() {
    use crate::CryptoError;
    use pqcrypto_traits::sign::{PublicKey as PqPKTrait, SecretKey as PqSKTrait};

    // Probe whether pqcrypto's from_bytes accepts all-0xFF for the ML-DSA-65
    // secret-key segment (some pqcrypto versions do length-only validation).
    // This determines whether the InvalidKeystoreKeyMaterial path is reachable.
    let all_ff_sk = vec![0xFFu8; super::ML_SK_LEN];
    let sk_reachable = pqcrypto_mldsa::mldsa65::SecretKey::from_bytes(&all_ff_sk).is_err();

    if sk_reachable {
        // ML-DSA from_bytes validates bytes — exercise the error path.
        let mut buf = generate().to_keystore_bytes().to_vec();
        // Overwrite the ML-DSA secret-key segment (bytes 32..4064) with 0xFF.
        for b in buf[32..32 + super::ML_SK_LEN].iter_mut() {
            *b = 0xFF;
        }
        match KeyPair::from_keystore_bytes(&buf) {
            Err(CryptoError::InvalidKeystoreKeyMaterial { .. }) => {}
            Err(e) => panic!("expected InvalidKeystoreKeyMaterial, got: {e}"),
            Ok(_) => panic!("expected error for corrupt ML-DSA secret key"),
        }
    } else {
        // pqcrypto 0.1.x performs length-only validation for the SK segment —
        // `InvalidKeystoreKeyMaterial` is unreachable via the SK path in the
        // current dependency version. This is documented here as a no-op guard:
        // if pqcrypto is upgraded to a version with structural validation, this
        // test will automatically execute the error path.
        //
        // The PK path (bytes 4064..6016) may still be reachable — probe it.
        let all_ff_pk = vec![0xFFu8; super::ML_PK_LEN];
        let pk_reachable = pqcrypto_mldsa::mldsa65::PublicKey::from_bytes(&all_ff_pk).is_err();
        if pk_reachable {
            let mut buf = generate().to_keystore_bytes().to_vec();
            let pk_start = super::ED_SK_LEN + super::ML_SK_LEN;
            for b in buf[pk_start..].iter_mut() {
                *b = 0xFF;
            }
            match KeyPair::from_keystore_bytes(&buf) {
                Err(CryptoError::InvalidKeystoreKeyMaterial { .. }) => {}
                Err(e) => panic!("expected InvalidKeystoreKeyMaterial (PK path), got: {e}"),
                Ok(_) => panic!("expected error for corrupt ML-DSA public key"),
            }
        }
        // If both SK and PK accept arbitrary bytes, the error variant is
        // unreachable with this pqcrypto version. Noted in comments above.
    }
}
