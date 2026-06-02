//! Error types for `lemma-crypto`.
//!
//! [`CryptoError`] is the single error type for all cryptographic operations
//! in this crate: hashing, key generation, signing, and verification.
//!
//! ## Usage
//!
//! Prefer the concrete error variants in internal code — every variant carries
//! enough context to identify the failure without re-running the operation:
//!
//! ```ignore
//! use lemma_core::Signature;
//! use lemma_crypto::CryptoError;
//!
//! fn verify_tx(sig: &Signature) -> Result<(), CryptoError> {
//!     // ...
//!     Ok(())
//! }
//! ```

use thiserror::Error;

// ─── CryptoError ─────────────────────────────────────────────────────────────

/// Errors that can occur during cryptographic operations in `lemma-crypto`.
///
/// Covers signing, verification, key generation, key handling, and
/// serialization failures. All variants carry enough context to identify
/// the failure without re-running the operation.
///
/// # Why one flat enum?
///
/// Unlike `lemma-core` (which spans multiple domains), `lemma-crypto` is
/// focused on a single concern. One enum is simpler and avoids unnecessary
/// wrapping.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    // ── Verification ─────────────────────────────────────────────────────────

    /// Ed25519 classical signature verification failed.
    ///
    /// The message, public key, or signature bytes are invalid or mismatched.
    #[error("Ed25519 classical signature verification failed")]
    ClassicalVerificationFailed,

    /// Dilithium post-quantum signature verification failed.
    ///
    /// The message, public key, or signature bytes are invalid or mismatched.
    #[error("Dilithium post-quantum signature verification failed")]
    QuantumVerificationFailed,

    /// Verification requires a [`Signature::Hybrid`] (both classical + quantum).
    ///
    /// Received a [`Signature::Classical`] or [`Signature::PostQuantum`] instead.
    /// The Lemma mempool rejects any non-hybrid transaction signature.
    ///
    /// `got` is a compile-time constant — `"Classical"` or `"PostQuantum"`.
    /// Using `&'static str` prevents runtime-constructed strings and eliminates
    /// the heap allocation while keeping `Clone + PartialEq + Eq`.
    ///
    /// [`Signature::Hybrid`]: lemma_core::Signature::Hybrid
    /// [`Signature::Classical`]: lemma_core::Signature::Classical
    /// [`Signature::PostQuantum`]: lemma_core::Signature::PostQuantum
    #[error("hybrid signature required for transaction verification, got: {got}")]
    HybridSignatureRequired { got: &'static str },

    /// Transaction has no signature and cannot be verified.
    ///
    /// This is a precondition failure, not a verification failure — the
    /// transaction was never signed. Sign with `lemma_crypto::sign` before
    /// submitting to the mempool.
    #[error("transaction has no signature — sign with lemma_crypto::sign before submitting")]
    UnsignedTransaction,

    // ── Key & byte validation ─────────────────────────────────────────────────

    /// Ed25519 signature bytes had the wrong length.
    ///
    /// Ed25519 signatures are always exactly 64 bytes.
    #[error("invalid Ed25519 signature length: expected 64 bytes, got {got}")]
    InvalidClassicalSignatureLength { got: usize },

    /// Dilithium3 signature bytes had the wrong length.
    ///
    /// Dilithium3 signatures (the parameter set used by `lemma-crypto`) are
    /// always exactly 3293 bytes. `expected` is included in the variant for
    /// consistency with [`InvalidClassicalSignatureLength`] and to remain
    /// correct if the parameter set ever changes.
    #[error("invalid Dilithium3 signature length: expected {expected} bytes, got {got}")]
    InvalidQuantumSignatureLength { expected: usize, got: usize },

    /// Ed25519 public key bytes are not a valid curve point.
    ///
    /// Stored as a `String` so this variant remains `Clone + PartialEq + Eq`.
    /// The underlying `ed25519_dalek::SignatureError` is converted on construction.
    #[error("invalid Ed25519 public key: {reason}")]
    InvalidPublicKeyBytes { reason: String },

    /// Dilithium public key bytes are not valid.
    ///
    /// Stored as a `String` so this variant remains `Clone + PartialEq + Eq`.
    #[error("invalid Dilithium public key: {reason}")]
    InvalidQuantumPublicKeyBytes { reason: String },

    // ── Key generation ────────────────────────────────────────────────────────

    /// Key pair generation failed.
    ///
    /// Occurs when the underlying RNG or key derivation step fails.
    /// Stored as a `String` so this variant remains `Clone + PartialEq + Eq`.
    #[error("key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    // ── Serialization ─────────────────────────────────────────────────────────

    /// Serialization or deserialization failed.
    ///
    /// Occurs when a value cannot be serialized to bytes (e.g., before hashing
    /// or signing) or deserialized from bytes (e.g., key material). Scoped
    /// broadly so all modules can reuse this variant without duplication
    /// (AGENTS.md §2.1 — one canonical way per concept).
    ///
    /// Stored as a `String` so this variant remains `Clone + PartialEq + Eq`.
    /// The underlying `bincode::Error` is converted on construction.
    #[error("serialization failed: {reason}")]
    SerializationFailed { reason: String },

    // ── Keystore ──────────────────────────────────────────────────────────────

    /// Keystore bytes are the wrong length for a Lemma hybrid keypair.
    ///
    /// A valid keystore produced by [`KeyPair::to_keystore_bytes`] is always
    /// exactly [`KEYSTORE_BYTE_LEN`](crate::keypair::KEYSTORE_BYTE_LEN) bytes.
    /// A different length indicates a truncated file, wrong format, or
    /// an accidentally supplied public-key file.
    #[error(
        "invalid keystore length: expected {expected} bytes, got {got} \
         (is this a valid lemma keystore file?)"
    )]
    InvalidKeystoreLength { expected: usize, got: usize },

    /// Key material inside a keystore file is cryptographically invalid.
    ///
    /// Indicates corruption or a manually edited file. The keystore was the
    /// right length but the Ed25519 or ML-DSA-65 bytes could not be parsed
    /// into valid keys.
    #[error("invalid keystore key material: {reason}")]
    InvalidKeystoreKeyMaterial { reason: String },
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
