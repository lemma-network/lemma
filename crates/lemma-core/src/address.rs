//! Address newtype — a 20-byte Lemma account identifier.
//!
//! Lemma addresses are 20 bytes internally, encoded as Bech32m strings for
//! display. The first byte of the Bech32m payload is a *type byte* whose top
//! 5 bits determine the first visible character after `lem1`:
//!
//! | Type     | Byte | First char | Example             |
//! |----------|------|------------|---------------------|
//! | Regular  | 0x00 | `q`        | `lem1q8k2d...l7wz`  |
//! | Contract | 0xC0 | `c`        | `lem1c7a9s...t8nf`  |
//! | Shielded | 0x10 | `z`        | `lem1z4rd8...k2ma`  |
//! | Burn     | 0x6E | `d`        | `lem1deadd...ead..` |
//!
//! # Network prefixes (HRP)
//!
//! | Network  | HRP    | Example prefix |
//! |----------|--------|----------------|
//! | Mainnet  | `lem`  | `lem1q...`     |
//! | Testnet  | `tlem` | `tlem1q...`    |
//! | Devnet   | `dlem` | `dlem1q...`    |
//!
//! # Wire format
//!
//! `payload = [type_byte: u8] ++ [address: [u8; 20]]` — 21 bytes total,
//! then Bech32m-encoded with the appropriate HRP.
//!
//! See `docs/04-BUILD_GUIDE.md` Section 2.1.

use std::fmt;

use bech32::{Bech32m, Hrp};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::error::AddressError;

// ─── HRP constants ───────────────────────────────────────────────────────────

/// Bech32m human-readable part for mainnet addresses (`lem1q...`).
pub const HRP_MAINNET: &str = "lem";

/// Bech32m human-readable part for testnet addresses (`tlem1q...`).
pub const HRP_TESTNET: &str = "tlem";

/// Bech32m human-readable part for devnet addresses (`dlem1q...`).
pub const HRP_DEVNET: &str = "dlem";

// ─── Burn / native-LEM byte constants ────────────────────────────────────────

/// Burn address payload bytes (excluding the type byte).
///
/// Pattern: `[0x7A, 0xD6, 0xE7, 0xAD, 0x6E]` × 4 (5-byte cycle, 4 reps).
/// Together with type byte `0x6E` this encodes to `lem1deaddeaddead...`.
const BURN_BYTES: [u8; 20] = [
    0x7A, 0xD6, 0xE7, 0xAD, 0x6E, 0x7A, 0xD6, 0xE7, 0xAD, 0x6E, 0x7A, 0xD6, 0xE7, 0xAD, 0x6E, 0x7A,
    0xD6, 0xE7, 0xAD, 0x6E,
];

/// Native LEM system contract address bytes.
///
/// Defined as `Blake3(b"lemma:system:native-lem")[0..20]`.
/// Encoded with `AddressType::Contract` → `lem1c...`.
/// Verified by `address::tests::native_lem_bytes_match_blake3_hash`.
const NATIVE_LEM_BYTES: [u8; 20] = [
    0x57, 0x33, 0xD5, 0x18, 0x21, 0xCB, 0xFB, 0x4D, 0x67, 0x00, 0x03, 0x96, 0xD4, 0xB7, 0x6B, 0xAD,
    0x5F, 0x92, 0xC9, 0x69,
];

// ─── AddressType ─────────────────────────────────────────────────────────────

/// Account type encoded as the first byte of the Bech32m payload.
///
/// The type byte's **top 5 bits** are the first Bech32m character index after
/// `hrp1`. Values are chosen to produce recognizable sub-prefixes:
///
/// ```text
/// Regular  0x00 = 00000000 → bits[0..5] = 00000 = idx  0 = 'q'
/// Contract 0xC0 = 11000000 → bits[0..5] = 11000 = idx 24 = 'c'
/// Shielded 0x10 = 00010000 → bits[0..5] = 00010 = idx  2 = 'z'
/// Burn     0x6E = 01101110 → bits[0..5] = 01101 = idx 13 = 'd'
/// ```
// `Serialize`/`Deserialize` are intentionally NOT derived here.
// `AddressType` is encoded as a type byte within the Bech32m payload and is
// never serialized independently — callers use `Address::to_bech32` /
// `Address::from_bech32` for typed encoding/decoding.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddressType {
    /// Externally owned account (EOA) — `lem1q...`
    Regular = 0x00,
    /// Smart contract — `lem1c...`
    Contract = 0xC0,
    /// Veil shielded address — `lem1z...`
    Shielded = 0x10,
    /// Canonical burn / unspendable destination — `lem1dead...`
    Burn = 0x6E,
}

impl AddressType {
    /// Return the raw type byte used in the Bech32m payload.
    pub fn type_byte(self) -> u8 {
        self as u8
    }

    /// Parse an [`AddressType`] from its raw type byte.
    ///
    /// # Errors
    ///
    /// Returns [`AddressError::UnknownAddressType`] for any byte that is not a
    /// known type discriminant.
    pub fn from_type_byte(b: u8) -> Result<Self, AddressError> {
        match b {
            0x00 => Ok(Self::Regular),
            0xC0 => Ok(Self::Contract),
            0x10 => Ok(Self::Shielded),
            0x6E => Ok(Self::Burn),
            _ => Err(AddressError::UnknownAddressType { byte: b }),
        }
    }
}

// ─── Address ─────────────────────────────────────────────────────────────────

/// A 20-byte Lemma account address.
///
/// The address type (`Regular`, `Contract`, etc.) is **not** stored in the
/// struct — it lives only in the encoded Bech32m string. Use
/// [`Address::to_bech32`] with the appropriate type when encoding for display
/// or serialization, and [`Address::from_bech32`] to recover the type when
/// decoding.
///
/// # Serde note
///
/// Serializes as a mainnet Regular Bech32m string (`lem1q...`). Deserializes
/// from any valid Lemma Bech32m string; the type byte and HRP are discarded —
/// only the 20 address bytes are preserved.
// `Debug` and `Serialize`/`Deserialize` are implemented manually below:
// - `Debug`: to emit `Address(lem1q...)` instead of a raw byte array
// - `Serialize`/`Deserialize`: to use Bech32m strings, not raw bytes
//
// `PartialOrd` and `Ord` are derived so `Address` can be used as a `BTreeMap`
// key (required by `GenesisConfig::initial_balances`). Ordering is lexicographic
// over the raw 20-byte payload — deterministic and consistent across all nodes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address([u8; 20]);

impl Address {
    // ── Special addresses ────────────────────────────────────────────────────

    /// The zero address — all 20 bytes are `0x00`.
    ///
    /// This is a **sentinel / technical value** (e.g. genesis block proposer).
    /// It is **not** the canonical burn address — use [`Address::burn`] for
    /// fee destruction.
    pub const fn zero() -> Self {
        Address([0u8; 20])
    }

    /// The canonical burn address → encodes to `lem1dead...` (mainnet).
    ///
    /// All base fees designated for burning are sent here.
    /// No private key exists for this address — it is provably unspendable.
    ///
    /// Bytes: `[0x7A, 0xD6, 0xE7, 0xAD, 0x6E]` × 4 with type byte `0x6E`.
    pub const fn burn() -> Self {
        Address(BURN_BYTES)
    }

    /// The native LEM system contract address → encodes to `lem1c...` (mainnet).
    ///
    /// Defined as `Blake3(b"lemma:system:native-lem")[0..20]`.
    /// Allows native LEM to be used directly as a DEX pair without wrapping
    /// (no WLEM / wLEM equivalent needed).
    pub const fn native_lem() -> Self {
        Address(NATIVE_LEM_BYTES)
    }

    // ── Raw construction ─────────────────────────────────────────────────────

    /// Create an `Address` directly from a raw 20-byte array.
    ///
    /// Infallible — the caller guarantees the array is exactly 20 bytes.
    /// Used by the VM linker to reconstruct addresses from guest memory
    /// (the WASM ABI passes raw 20-byte address payloads).
    pub const fn from_raw_bytes(bytes: [u8; 20]) -> Self {
        Address(bytes)
    }

    // ── Derivation ────────────────────────────────────────────────────────────

    /// Derive a Regular EOA address from an Ed25519 public key.
    ///
    /// Formula: `Blake3(pubkey)[0..20]`.
    pub fn from_public_key(pubkey: &[u8; 32]) -> Self {
        let hash = blake3::hash(pubkey);
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash.as_bytes()[..20]);
        Address(bytes)
    }

    /// Derive a Contract address for a CREATE deployment.
    ///
    /// Formula: `Blake3(deployer_bytes ++ nonce_big_endian)[0..20]`.
    pub fn from_deployer(deployer: &Address, nonce: u64) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&deployer.0);
        hasher.update(&nonce.to_be_bytes());
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..20]);
        Address(bytes)
    }

    /// Derive a Contract address for a CREATE2 deployment.
    ///
    /// Formula: `Blake3(0xff ++ deployer_bytes ++ salt ++ Blake3(bytecode))[0..20]`.
    ///
    /// The `0xff` prefix prevents collision with CREATE addresses.
    pub fn from_deployer_salt(deployer: &Address, salt: &[u8; 32], bytecode: &[u8]) -> Self {
        let code_hash = blake3::hash(bytecode);
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[0xff]);
        hasher.update(&deployer.0);
        hasher.update(salt);
        hasher.update(code_hash.as_bytes());
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hasher.finalize().as_bytes()[..20]);
        Address(bytes)
    }

    // ── Encoding ─────────────────────────────────────────────────────────────

    /// Encode to a Bech32m string with explicit HRP and address type.
    ///
    /// Payload layout: `[type_byte: 1 byte] ++ [address: 20 bytes]` = 21 bytes.
    ///
    /// # Errors
    ///
    /// - [`AddressError::InvalidHrp`] if `hrp` is not one of the known Lemma
    ///   network prefixes (`lem`, `tlem`, `dlem`).
    /// - [`AddressError::InvalidBech32`] on internal encoding failure (should
    ///   not occur with valid inputs).
    pub fn to_bech32(&self, hrp: &str, addr_type: AddressType) -> Result<String, AddressError> {
        if !matches!(hrp, HRP_MAINNET | HRP_TESTNET | HRP_DEVNET) {
            return Err(AddressError::InvalidHrp {
                got: hrp.to_string(),
            });
        }
        let hrp_parsed = Hrp::parse(hrp).map_err(|e| AddressError::InvalidBech32 {
            reason: e.to_string(),
        })?;

        // Prepend type byte to form the 21-byte payload.
        let mut payload = [0u8; 21];
        payload[0] = addr_type.type_byte();
        payload[1..].copy_from_slice(&self.0);

        bech32::encode::<Bech32m>(hrp_parsed, &payload).map_err(|e| AddressError::InvalidBech32 {
            reason: e.to_string(),
        })
    }

    /// Decode from a Bech32m string.
    ///
    /// Returns `(address_bytes, addr_type, hrp_string)`.
    ///
    /// # Errors
    ///
    /// - [`AddressError::InvalidBech32`] — checksum invalid or malformed string.
    /// - [`AddressError::InvalidHrp`] — decoded HRP is not a known Lemma prefix.
    /// - [`AddressError::InvalidPayloadLength`] — payload is not exactly 21 bytes.
    /// - [`AddressError::UnknownAddressType`] — type byte not a known discriminant.
    pub fn from_bech32(s: &str) -> Result<(Self, AddressType, String), AddressError> {
        let (hrp, payload) = bech32::decode(s).map_err(|e| AddressError::InvalidBech32 {
            reason: e.to_string(),
        })?;

        let hrp_str = hrp.to_string();
        if !matches!(hrp_str.as_str(), HRP_MAINNET | HRP_TESTNET | HRP_DEVNET) {
            return Err(AddressError::InvalidHrp { got: hrp_str });
        }

        // Payload must be exactly 21 bytes: 1 type byte + 20 address bytes.
        if payload.len() != 21 {
            return Err(AddressError::InvalidPayloadLength { got: payload.len() });
        }

        let addr_type = AddressType::from_type_byte(payload[0])?;
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&payload[1..]);

        Ok((Address(bytes), addr_type, hrp_str))
    }

    // ── Access ───────────────────────────────────────────────────────────────

    /// Borrow the underlying 20 bytes.
    ///
    /// Use for raw byte operations, hashing, or storage. Prefer
    /// [`Address::to_bech32`] for human-readable output.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Returns `true` if all 20 bytes are zero.
    ///
    /// This is a **technical sentinel check**, not a burn check.
    /// Use [`Address::is_burn`] to test for the canonical burn address.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }

    /// Returns `true` if this is the canonical burn address (`lem1dead...`).
    pub fn is_burn(&self) -> bool {
        self.0 == BURN_BYTES
    }

    /// Returns an abbreviated display string: `lem1q8k2...l7wz`.
    ///
    /// Uses mainnet Regular encoding. Intended for UI display only.
    pub fn short_display(&self) -> String {
        let full = self.to_string();
        if full.len() <= 12 {
            return full;
        }
        // Safety: Bech32m charset is ASCII-only (`qpzry9x8gf2tvdw0s3jn54khce6mua7l`
        // plus the HRP which is also ASCII) — byte indices equal char indices here.
        format!("{}...{}", &full[..8], &full[full.len() - 4..])
    }
}

// ─── Display & Debug ─────────────────────────────────────────────────────────

impl fmt::Display for Address {
    /// Displays as a mainnet Regular Bech32m string (`lem1q...`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // HRP_MAINNET is a compile-time constant that always passes the HRP guard.
        // This path is infallible — `expect` makes any future regression traceable.
        let encoded = self
            .to_bech32(HRP_MAINNET, AddressType::Regular)
            .expect("HRP_MAINNET is a known-valid constant; encoding is infallible");
        write!(f, "{}", encoded)
    }
}

impl fmt::Debug for Address {
    /// Displays as `Address(lem1q...)` for easy identification in debug output.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self)
    }
}

// ─── Serde ───────────────────────────────────────────────────────────────────

/// Serializes as a mainnet Regular Bech32m string (`lem1q...`).
///
/// Note: the address type and HRP are not preserved in serialized form.
/// Deserializing always recovers only the 20 address bytes.
impl Serialize for Address {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let encoded = self
            .to_bech32(HRP_MAINNET, AddressType::Regular)
            .map_err(serde::ser::Error::custom)?;
        s.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let (addr, _type, _hrp) = Self::from_bech32(&s).map_err(de::Error::custom)?;
        Ok(addr)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
