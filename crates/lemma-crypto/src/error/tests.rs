//! Tests for `lemma_crypto::error`.
//!
//! Covers Display output, Clone round-trips, PartialEq equality and
//! inequality for every public variant. 100% public API coverage required
//! per AGENTS.md §11.1.

use super::*;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn classical_failed() -> CryptoError {
    CryptoError::ClassicalVerificationFailed
}

fn quantum_failed() -> CryptoError {
    CryptoError::QuantumVerificationFailed
}

fn hybrid_required(got: &'static str) -> CryptoError {
    CryptoError::HybridSignatureRequired { got }
}

fn unsigned_tx() -> CryptoError {
    CryptoError::UnsignedTransaction
}

fn invalid_classical_len(got: usize) -> CryptoError {
    CryptoError::InvalidClassicalSignatureLength { got }
}

fn invalid_quantum_len(got: usize) -> CryptoError {
    // expected is always 3293 for Dilithium3 — the parameter set used by lemma-crypto.
    CryptoError::InvalidQuantumSignatureLength {
        expected: 3293,
        got,
    }
}

fn invalid_pubkey(reason: &str) -> CryptoError {
    CryptoError::InvalidPublicKeyBytes {
        reason: reason.to_string(),
    }
}

fn invalid_quantum_pubkey(reason: &str) -> CryptoError {
    CryptoError::InvalidQuantumPublicKeyBytes {
        reason: reason.to_string(),
    }
}

fn key_gen_failed(reason: &str) -> CryptoError {
    CryptoError::KeyGenerationFailed {
        reason: reason.to_string(),
    }
}

fn serialization_failed(reason: &str) -> CryptoError {
    CryptoError::SerializationFailed {
        reason: reason.to_string(),
    }
}

// ── ClassicalVerificationFailed — Display ─────────────────────────────────────

#[test]
fn classical_verification_failed_displays_correct_message() {
    assert_eq!(
        classical_failed().to_string(),
        "Ed25519 classical signature verification failed",
    );
}

// ── ClassicalVerificationFailed — Clone + PartialEq ──────────────────────────

#[test]
fn classical_verification_failed_clones_equal_to_original() {
    let err = classical_failed();
    assert_eq!(err.clone(), err);
}

#[test]
fn classical_verification_failed_same_variants_are_equal() {
    assert_eq!(classical_failed(), classical_failed());
}

// ── QuantumVerificationFailed — Display ───────────────────────────────────────

#[test]
fn quantum_verification_failed_displays_correct_message() {
    assert_eq!(
        quantum_failed().to_string(),
        "Dilithium post-quantum signature verification failed",
    );
}

// ── QuantumVerificationFailed — Clone + PartialEq ────────────────────────────

#[test]
fn quantum_verification_failed_clones_equal_to_original() {
    let err = quantum_failed();
    assert_eq!(err.clone(), err);
}

#[test]
fn quantum_verification_failed_same_variants_are_equal() {
    assert_eq!(quantum_failed(), quantum_failed());
}

// ── HybridSignatureRequired — Display ─────────────────────────────────────────

#[test]
fn hybrid_signature_required_displays_classical_variant_name() {
    assert_eq!(
        hybrid_required("Classical").to_string(),
        "hybrid signature required for transaction verification, got: Classical",
    );
}

#[test]
fn hybrid_signature_required_displays_post_quantum_variant_name() {
    assert_eq!(
        hybrid_required("PostQuantum").to_string(),
        "hybrid signature required for transaction verification, got: PostQuantum",
    );
}

// ── HybridSignatureRequired — Clone + PartialEq ───────────────────────────────

#[test]
fn hybrid_signature_required_clones_equal_to_original() {
    let err = hybrid_required("Classical");
    assert_eq!(err.clone(), err);
}

#[test]
fn hybrid_signature_required_same_got_are_equal() {
    assert_eq!(hybrid_required("Classical"), hybrid_required("Classical"));
}

#[test]
fn hybrid_signature_required_different_got_are_not_equal() {
    assert_ne!(hybrid_required("Classical"), hybrid_required("PostQuantum"));
}

// ── UnsignedTransaction — Display ─────────────────────────────────────────────

#[test]
fn unsigned_transaction_displays_precondition_message_not_verification_failure() {
    // Message must communicate this is a missing-signature precondition,
    // not a verification failure — the transaction was never signed.
    assert_eq!(
        unsigned_tx().to_string(),
        "transaction has no signature — sign with lemma_crypto::sign before submitting",
    );
}

// ── UnsignedTransaction — Clone + PartialEq ───────────────────────────────────

#[test]
fn unsigned_transaction_clones_equal_to_original() {
    let err = unsigned_tx();
    assert_eq!(err.clone(), err);
}

#[test]
fn unsigned_transaction_same_variants_are_equal() {
    assert_eq!(unsigned_tx(), unsigned_tx());
}

// ── InvalidClassicalSignatureLength — Display ─────────────────────────────────

#[test]
fn invalid_classical_signature_length_displays_expected_and_got_bytes() {
    assert_eq!(
        invalid_classical_len(32).to_string(),
        "invalid Ed25519 signature length: expected 64 bytes, got 32",
    );
}

#[test]
fn invalid_classical_signature_length_displays_zero_got() {
    // Edge case: empty byte slice submitted as a signature.
    assert_eq!(
        invalid_classical_len(0).to_string(),
        "invalid Ed25519 signature length: expected 64 bytes, got 0",
    );
}

// ── InvalidClassicalSignatureLength — Clone + PartialEq ──────────────────────

#[test]
fn invalid_classical_signature_length_clones_equal_to_original() {
    let err = invalid_classical_len(32);
    assert_eq!(err.clone(), err);
}

#[test]
fn invalid_classical_signature_length_same_got_are_equal() {
    assert_eq!(invalid_classical_len(32), invalid_classical_len(32));
}

#[test]
fn invalid_classical_signature_length_different_got_are_not_equal() {
    assert_ne!(invalid_classical_len(32), invalid_classical_len(16));
}

// ── InvalidQuantumSignatureLength — Display ───────────────────────────────────

#[test]
fn invalid_quantum_signature_length_displays_expected_and_got_bytes() {
    assert_eq!(
        invalid_quantum_len(1024).to_string(),
        "invalid Dilithium3 signature length: expected 3293 bytes, got 1024",
    );
}

#[test]
fn invalid_quantum_signature_length_displays_zero_got() {
    // Edge case: empty byte slice submitted as a quantum signature.
    assert_eq!(
        invalid_quantum_len(0).to_string(),
        "invalid Dilithium3 signature length: expected 3293 bytes, got 0",
    );
}

// ── InvalidQuantumSignatureLength — Clone + PartialEq ────────────────────────

#[test]
fn invalid_quantum_signature_length_clones_equal_to_original() {
    let err = invalid_quantum_len(1024);
    assert_eq!(err.clone(), err);
}

#[test]
fn invalid_quantum_signature_length_same_got_are_equal() {
    assert_eq!(invalid_quantum_len(1024), invalid_quantum_len(1024));
}

#[test]
fn invalid_quantum_signature_length_different_got_are_not_equal() {
    assert_ne!(invalid_quantum_len(1024), invalid_quantum_len(512));
}

// ── InvalidPublicKeyBytes — Display ───────────────────────────────────────────

#[test]
fn invalid_public_key_bytes_displays_reason() {
    assert_eq!(
        invalid_pubkey("not a valid curve point").to_string(),
        "invalid Ed25519 public key: not a valid curve point",
    );
}

#[test]
fn invalid_public_key_bytes_displays_empty_reason() {
    // Edge case: empty reason string (e.g. external lib returns no message).
    assert_eq!(
        invalid_pubkey("").to_string(),
        "invalid Ed25519 public key: ",
    );
}

// ── InvalidPublicKeyBytes — Clone + PartialEq ────────────────────────────────

#[test]
fn invalid_public_key_bytes_clones_equal_to_original() {
    let err = invalid_pubkey("bad point");
    assert_eq!(err.clone(), err);
}

#[test]
fn invalid_public_key_bytes_same_reason_are_equal() {
    assert_eq!(invalid_pubkey("bad point"), invalid_pubkey("bad point"));
}

#[test]
fn invalid_public_key_bytes_different_reason_are_not_equal() {
    assert_ne!(invalid_pubkey("bad point"), invalid_pubkey("wrong length"));
}

// ── InvalidQuantumPublicKeyBytes — Display ────────────────────────────────────

#[test]
fn invalid_quantum_public_key_bytes_displays_reason() {
    assert_eq!(
        invalid_quantum_pubkey("malformed Dilithium key material").to_string(),
        "invalid Dilithium public key: malformed Dilithium key material",
    );
}

#[test]
fn invalid_quantum_public_key_bytes_displays_empty_reason() {
    assert_eq!(
        invalid_quantum_pubkey("").to_string(),
        "invalid Dilithium public key: ",
    );
}

// ── InvalidQuantumPublicKeyBytes — Clone + PartialEq ─────────────────────────

#[test]
fn invalid_quantum_public_key_bytes_clones_equal_to_original() {
    let err = invalid_quantum_pubkey("bad key");
    assert_eq!(err.clone(), err);
}

#[test]
fn invalid_quantum_public_key_bytes_same_reason_are_equal() {
    assert_eq!(
        invalid_quantum_pubkey("bad key"),
        invalid_quantum_pubkey("bad key"),
    );
}

#[test]
fn invalid_quantum_public_key_bytes_different_reason_are_not_equal() {
    assert_ne!(
        invalid_quantum_pubkey("bad key"),
        invalid_quantum_pubkey("wrong length"),
    );
}

// ── KeyGenerationFailed — Display ─────────────────────────────────────────────

#[test]
fn key_generation_failed_displays_reason() {
    assert_eq!(
        key_gen_failed("RNG failure").to_string(),
        "key generation failed: RNG failure",
    );
}

// ── KeyGenerationFailed — Clone + PartialEq ──────────────────────────────────

#[test]
fn key_generation_failed_clones_equal_to_original() {
    let err = key_gen_failed("RNG failure");
    assert_eq!(err.clone(), err);
}

#[test]
fn key_generation_failed_same_reason_are_equal() {
    assert_eq!(key_gen_failed("RNG failure"), key_gen_failed("RNG failure"));
}

#[test]
fn key_generation_failed_different_reason_are_not_equal() {
    assert_ne!(
        key_gen_failed("RNG failure"),
        key_gen_failed("entropy exhausted")
    );
}

// ── SerializationFailed — Display ─────────────────────────────────────────────

#[test]
fn serialization_failed_displays_reason() {
    assert_eq!(
        serialization_failed("sequence too long").to_string(),
        "serialization failed: sequence too long",
    );
}

// ── SerializationFailed — Clone + PartialEq ───────────────────────────────────

#[test]
fn serialization_failed_clones_equal_to_original() {
    let err = serialization_failed("eof");
    assert_eq!(err.clone(), err);
}

#[test]
fn serialization_failed_same_reason_are_equal() {
    assert_eq!(serialization_failed("eof"), serialization_failed("eof"));
}

#[test]
fn serialization_failed_different_reason_are_not_equal() {
    assert_ne!(
        serialization_failed("eof"),
        serialization_failed("overflow"),
    );
}

// ── Cross-variant PartialEq — verification group ──────────────────────────────

#[test]
fn classical_and_quantum_verification_failed_are_not_equal() {
    assert_ne!(classical_failed(), quantum_failed());
}

#[test]
fn classical_verification_failed_and_unsigned_transaction_are_not_equal() {
    assert_ne!(classical_failed(), unsigned_tx());
}

#[test]
fn quantum_verification_failed_and_unsigned_transaction_are_not_equal() {
    assert_ne!(quantum_failed(), unsigned_tx());
}

#[test]
fn classical_verification_failed_and_hybrid_required_are_not_equal() {
    assert_ne!(classical_failed(), hybrid_required("Classical"));
}

// ── Cross-variant PartialEq — length group ────────────────────────────────────

#[test]
fn classical_and_quantum_length_errors_with_same_got_are_not_equal() {
    // Same `got` value but different enum variants — must not be equal.
    assert_ne!(invalid_classical_len(32), invalid_quantum_len(32));
}

// ── Cross-variant PartialEq — key group ──────────────────────────────────────

#[test]
fn invalid_classical_and_quantum_public_key_bytes_with_same_reason_are_not_equal() {
    assert_ne!(invalid_pubkey("bad"), invalid_quantum_pubkey("bad"));
}

// ── Cross-variant PartialEq — string-keyed group ─────────────────────────────

#[test]
fn invalid_public_key_bytes_and_serialization_failed_with_same_message_are_not_equal() {
    assert_ne!(invalid_pubkey("bad"), serialization_failed("bad"));
}

#[test]
fn key_generation_failed_and_serialization_failed_with_same_reason_are_not_equal() {
    assert_ne!(key_gen_failed("bad"), serialization_failed("bad"));
}

// ── Cross-variant PartialEq — unit vs struct ──────────────────────────────────

#[test]
fn unsigned_transaction_and_invalid_classical_length_are_not_equal() {
    assert_ne!(unsigned_tx(), invalid_classical_len(0));
}

#[test]
fn classical_verification_failed_and_serialization_failed_are_not_equal() {
    assert_ne!(classical_failed(), serialization_failed("failed"));
}
