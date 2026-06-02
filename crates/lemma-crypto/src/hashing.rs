//! Hash functions for Lemma — Blake3, SHA-256, Keccak-256.
//!
//! This module is the **single canonical location** for all hashing in the
//! Lemma codebase (AGENTS.md §2.2 — one canonical way). Every other crate
//! imports from here; no crate calls `blake3::hash` directly.
//!
//! # Determinism
//!
//! All three functions are **pure and deterministic** (AGENTS.md §7.1):
//! same input → same output on every platform. `hash<T>` uses
//! `bincode::serialize` (v1, fixint encoding, little-endian) — do NOT use
//! `bincode::DefaultOptions`, which uses varint encoding and would produce
//! a different byte sequence.
//!
//! # Hierarchy
//!
//! | Function | Algorithm | Use case |
//! |---|---|---|
//! | [`hash_bytes`] | Blake3 | Raw-bytes hashing: block headers, tx digests, Merkle roots |
//! | [`hash`] | Blake3 (via bincode) | Typed hashing: transactions, blocks, any `Serialize` type |
//! | [`sha256`] | SHA-256 | Compatibility layer: signature schemes, external protocol compatibility |
//! | [`keccak256`] | Keccak-256 | EVM compatibility layer: Solidity ABI encoding, `lemma-vm` host function |

use serde::Serialize;
use sha2::{Digest, Sha256}; // `Digest` re-exports `digest::Digest`; covers Keccak256 too
use sha3::Keccak256; // sha3 0.12 and sha2 0.11 share the same digest 0.11 train

use lemma_core::Hash;

use crate::CryptoError;

// ─── Blake3 (primary hasher) ──────────────────────────────────────────────────

/// Compute the Blake3 hash of raw bytes, returning a [`Hash`].
///
/// This is the **primary hashing primitive** in Lemma — used for block
/// headers, transaction digests, Merkle roots, and address derivation. Prefer
/// this function over [`sha256`] and [`keccak256`] unless cross-protocol
/// compatibility is required.
///
/// # Arguments
///
/// * `data` — byte slice to hash; may be empty.
///
/// # Returns
///
/// A 32-byte [`Hash`] containing the Blake3 digest. Infallible — Blake3
/// is total on any input.
///
/// # Examples
///
/// ```
/// use lemma_crypto::hash_bytes;
///
/// let h = hash_bytes(b"hello lemma");
/// assert!(!h.is_zero());
///
/// // Same input always produces the same output.
/// assert_eq!(hash_bytes(b"hello lemma"), hash_bytes(b"hello lemma"));
/// ```
pub fn hash_bytes(data: &[u8]) -> Hash {
    Hash::from_bytes(*blake3::hash(data).as_bytes())
}

/// Compute the Blake3 hash of any serializable value.
///
/// Serializes `data` to canonical bytes using `bincode::serialize` (v1,
/// fixint little-endian encoding), then hashes the result with Blake3.
/// This is the **canonical way to hash a typed value** such as a
/// [`Transaction`](lemma_core::Transaction) or
/// [`BlockHeader`](lemma_core::BlockHeader) — it guarantees every node
/// produces the same hash for the same value.
///
/// # Arguments
///
/// * `data` — reference to any value implementing [`Serialize`].
///
/// # Returns
///
/// `Ok(Hash)` on success, or
/// [`Err(CryptoError::SerializationFailed)`](CryptoError::SerializationFailed)
/// if `bincode` cannot serialize `data`.
///
/// # Determinism
///
/// Only use `bincode::serialize` (fixint, little-endian) — never
/// `bincode::DefaultOptions` (varint), which encodes integers differently
/// and would break consensus.
///
/// # Examples
///
/// ```
/// use serde::Serialize;
/// use lemma_crypto::hash;
///
/// #[derive(Serialize)]
/// struct Point { x: u32, y: u32 }
///
/// let h = hash(&Point { x: 1, y: 2 }).unwrap();
/// assert!(!h.is_zero());
///
/// // Same value always produces the same hash.
/// assert_eq!(hash(&Point { x: 1, y: 2 }), hash(&Point { x: 1, y: 2 }));
/// ```
pub fn hash<T: Serialize>(data: &T) -> Result<Hash, CryptoError> {
    let bytes = bincode::serialize(data).map_err(|e| CryptoError::SerializationFailed {
        reason: e.to_string(),
    })?;
    Ok(hash_bytes(&bytes))
}

// ─── SHA-256 (compatibility layer) ───────────────────────────────────────────

/// Compute the SHA-256 hash of raw bytes, returning a [`Hash`].
///
/// Used as a **compatibility layer** where SHA-256 is required by an external
/// protocol — for example, within certain signature schemes or when
/// interoperating with tooling that expects SHA-256 digests. For internal
/// Lemma hashing, prefer [`hash_bytes`] (Blake3).
///
/// # Arguments
///
/// * `data` — byte slice to hash; may be empty.
///
/// # Returns
///
/// A 32-byte [`Hash`] containing the SHA-256 digest. Infallible.
///
/// # Examples
///
/// ```
/// use lemma_crypto::sha256;
///
/// let h = sha256(b"hello lemma");
/// assert!(!h.is_zero());
/// assert_eq!(sha256(b"hello lemma"), sha256(b"hello lemma"));
/// ```
pub fn sha256(data: &[u8]) -> Hash {
    let digest: [u8; 32] = Sha256::digest(data).into();
    Hash::from_bytes(digest)
}

// ─── Keccak-256 (EVM compatibility layer) ────────────────────────────────────

/// Compute the Keccak-256 hash of raw bytes, returning a [`Hash`].
///
/// This is the **EVM/Solidity compatibility layer** — Keccak-256 is the hash
/// function used in Ethereum's ABI encoding, `keccak256()` in Solidity, and
/// `eth_getTransactionReceipt` topic hashing. Required by the `lemma-vm`
/// `hash_keccak256` host function (see `08-EXECUTION_SPEC §3`).
///
/// > **Note**: Keccak-256 is **not** the same as SHA3-256. Keccak-256 uses
/// > the original padding byte `0x01`; NIST SHA3-256 uses `0x06`. Ethereum
/// > uses Keccak-256. This function implements the Ethereum variant.
///
/// # Arguments
///
/// * `data` — byte slice to hash; may be empty.
///
/// # Returns
///
/// A 32-byte [`Hash`] containing the Keccak-256 digest. Infallible.
///
/// # Examples
///
/// ```
/// use lemma_crypto::keccak256;
///
/// let h = keccak256(b"hello lemma");
/// assert!(!h.is_zero());
/// assert_eq!(keccak256(b"hello lemma"), keccak256(b"hello lemma"));
/// ```
pub fn keccak256(data: &[u8]) -> Hash {
    let digest: [u8; 32] = Keccak256::digest(data).into();
    Hash::from_bytes(digest)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
