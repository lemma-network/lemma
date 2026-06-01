//! Hash newtype — a 32-byte cryptographic hash.
//!
//! [`Hash`] wraps a `[u8; 32]` with a human-readable hex representation,
//! proper serde support, and a `FromStr` parser. It is the canonical type for
//! all hash values in Lemma: block hashes, transaction hashes, state roots,
//! Merkle tree nodes, and code hashes.
//!
//! Internally stored as raw bytes. Serialized and displayed as a lowercase
//! hex string (64 characters). See `docs/04-BUILD_GUIDE.md` Section 2.1.

use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::HashError;

// ─── Hash ────────────────────────────────────────────────────────────────────

/// A 32-byte cryptographic hash (Blake3 output).
///
/// Serialized and displayed as a lowercase hex string (64 characters).
///
/// # Examples
///
/// ```ignore
/// use lemma_core::Hash;
///
/// let h = Hash::zero();
/// assert_eq!(h.to_string(), "0".repeat(64));
/// assert!(h.is_zero());
/// ```
// `Debug` and `std::hash::Hash` are implemented manually below:
// - `Debug`: to produce `Hash(<hex>)` instead of the default `Hash([u8; 32])` array format
// - `std::hash::Hash`: to avoid name ambiguity between this struct and the `std::hash::Hash` trait
//
// `PartialOrd` and `Ord` are derived so `Hash` can be used as a `BTreeMap` key — needed by the
// pool's priority index and any ordered-hash lookup in consensus/state code.
// Ordering is lexicographic over the raw 32-byte payload — deterministic and consistent across all
// nodes (same reasoning as `Address`; see address.rs).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hash([u8; 32]);

impl Hash {
    /// The zero hash — all 32 bytes are `0x00`.
    ///
    /// Used as a sentinel: the genesis block's `parent_hash`, the zero
    /// code hash for externally-owned accounts, and as a burn marker.
    pub const fn zero() -> Self {
        Hash([0u8; 32])
    }

    /// Create a `Hash` directly from a 32-byte array.
    ///
    /// Infallible — the caller guarantees the array is exactly 32 bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Hash(bytes)
    }

    /// Create a `Hash` from a byte slice, validating its length.
    ///
    /// # Errors
    ///
    /// Returns [`HashError::InvalidLength`] if `bytes.len() != 32`.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, HashError> {
        if bytes.len() != 32 {
            return Err(HashError::InvalidLength { got: bytes.len() });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes);
        Ok(Hash(arr))
    }

    /// Borrow the underlying 32 bytes.
    ///
    /// Use this to pass the raw hash bytes to `lemma-crypto` hashing or
    /// signing functions without cloning. Prefer [`Hash::to_hex`] for
    /// human-readable output and [`Hash::to_string`] for display.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode as a lowercase hex string (64 characters).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Returns `true` if all bytes are zero.
    ///
    /// Direct byte comparison — no temporary allocation.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

// ─── std::hash::Hash ─────────────────────────────────────────────────────────

// Manual impl to avoid ambiguity between `Hash` (our struct) and
// `std::hash::Hash` (the standard trait used in HashMap/HashSet).
impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// ─── Display & Debug ─────────────────────────────────────────────────────────

impl fmt::Display for Hash {
    /// Displays the hash as a 64-character lowercase hex string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for Hash {
    /// Displays as `Hash(<hex>)` for easy identification in debug output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", hex::encode(self.0))
    }
}

// ─── FromStr ─────────────────────────────────────────────────────────────────

impl FromStr for Hash {
    type Err = HashError;

    /// Parse a lowercase (or mixed-case) hex string into a `Hash`.
    ///
    /// # Errors
    ///
    /// - [`HashError::InvalidHex`] — string contains non-hex characters.
    /// - [`HashError::InvalidLength`] — decoded bytes are not exactly 32.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| HashError::InvalidHex {
            reason: e.to_string(),
        })?;
        Self::from_slice(&bytes)
    }
}

// ─── Serde ───────────────────────────────────────────────────────────────────

// Serialize as a lowercase hex string so JSON output is human-readable and
// round-trippable through `FromStr`.
impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let hex_str = String::deserialize(d)?;
        Self::from_str(&hex_str).map_err(de::Error::custom)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
