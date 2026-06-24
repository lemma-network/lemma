//! # Lemma Crypto
//!
//! Cryptographic primitives for the Lemma blockchain.
//!
//! Hybrid classical (Ed25519) + post-quantum (Dilithium3) signatures,
//! Blake3 / SHA-256 / Keccak-256 hashing, and key management.
//!
//! ## Modules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`error`] | [`CryptoError`] — single error enum for all crypto ops |
//! | [`hashing`] | [`hash_bytes`], [`hash`], [`sha256`], [`keccak256`] → [`lemma_core::Hash`] |
//! | [`keypair`] | [`KeyPair`], [`PublicKey`], [`HybridSignature`], [`verify`] |
//! | [`signing`] | [`sign_transaction`], [`verify_transaction`], [`compute_tx_hash`], [`sign_message`], [`verify_message`], [`compute_message_hash`] |

pub mod error;
pub mod hashing;
pub mod keypair;
pub mod signing;

pub use error::CryptoError;
pub use hashing::{hash, hash_bytes, keccak256, sha256};
pub use keypair::{verify, HybridSignature, KeyPair, PublicKey, KEYSTORE_BYTE_LEN};
pub use signing::{
    compute_message_hash, compute_tx_hash, sign_message, sign_transaction, verify_message,
    verify_transaction,
};
