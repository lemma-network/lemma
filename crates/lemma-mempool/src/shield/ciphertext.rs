//! `Ciphertext` wire layout + `ShieldAad` associated data (15-SHIELD_SPEC §2.6).
//!
//! # Wire format
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────────────┐
//! │  u (G1Affine, compressed)       48 bytes                                 │
//! │  w (G2Affine, compressed)       96 bytes                                 │
//! │  chain_id (u64 BE)               8 bytes  ┐                              │
//! │  epoch    (u64 BE)               8 bytes  ├─ ShieldAad (24 bytes total)  │
//! │  submitter_nonce (u64 BE)        8 bytes  ┘                              │
//! │  payload_len (u32 BE)            4 bytes                                 │
//! │  payload (ChaCha20Poly1305)  ≤ MAX_SHIELD_PAYLOAD_BYTES bytes            │
//! └──────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Boundary validation (AGENTS.md §15.2 — validate at the boundary)
//!
//! [`Ciphertext::from_bytes`] is the **sole deserialization entry point**.
//! It performs these checks before returning `Ok`:
//! 1. Subgroup check on `u` (𝔾₁) — rejects off-subgroup points.
//! 2. Subgroup check on `w` (𝔾₂) — mandatory for BLS12-381 G2 (cofactor > 1).
//! 3. Payload length ≤ [`MAX_SHIELD_PAYLOAD_BYTES`].
//!
//! Any failure returns an error — **never panics**.
//!
//! # Determinism
//!
//! [`ShieldAad::to_bytes`] produces a **fixed 24-byte canonical encoding**
//! (three u64 values in big-endian order). This byte string is fed to both
//! `H_𝔾₂(U, aad)` (hash-to-curve input) and `ChaCha20Poly1305` (AEAD AAD)
//! on every node — identical input → identical output (§7).

use ark_bls12_381::{G1Affine, G2Affine};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::shield::{params::MAX_SHIELD_PAYLOAD_BYTES, ShieldError};

// ── Byte-size constants (BLS12-381, fixed) ────────────────────────────────────

/// Compressed G1Affine byte size (BLS12-381): 48 bytes.
pub(crate) const G1_COMPRESSED_BYTES: usize = 48;

/// Compressed G2Affine byte size (BLS12-381): 96 bytes.
pub(crate) const G2_COMPRESSED_BYTES: usize = 96;

/// `ShieldAad` canonical byte size: 3 × u64 = 24 bytes.
pub(crate) const AAD_BYTES: usize = 24;

/// Minimum ciphertext byte length: G1 + G2 + aad + payload_len field.
pub(crate) const MIN_CIPHERTEXT_BYTES: usize =
    G1_COMPRESSED_BYTES + G2_COMPRESSED_BYTES + AAD_BYTES + 4;

// ── ShieldAad ─────────────────────────────────────────────────────────────────

/// Associated data that binds a `Ciphertext` to its context.
///
/// Prevents cross-chain replay (different `chain_id`) and cross-epoch replay
/// (different `epoch`). The canonical byte encoding (§2.6) is fed to both the
/// hash-to-curve function `H_𝔾₂(U, aad)` and the ChaCha20Poly1305 AEAD,
/// so tampering with any field invalidates both the validity check and the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShieldAad {
    /// Chain identifier — prevents ciphertext replay on a different Lemma chain.
    pub chain_id: u64,
    /// Target epoch — the ciphertext is only decryptable under this epoch's `Y`.
    pub epoch: u64,
    /// Submitter nonce — prevents intra-epoch ciphertext replay.
    pub submitter_nonce: u64,
}

impl ShieldAad {
    /// Canonical 24-byte encoding: `chain_id ‖ epoch ‖ submitter_nonce` (BE).
    ///
    /// This is the AAD fed to `H_𝔾₂` and `ChaCha20Poly1305`. Fixed-size and
    /// deterministic — identical on every node for the same logical AAD.
    #[must_use]
    pub fn to_bytes(self) -> [u8; AAD_BYTES] {
        let mut out = [0u8; AAD_BYTES];
        out[0..8].copy_from_slice(&self.chain_id.to_be_bytes());
        out[8..16].copy_from_slice(&self.epoch.to_be_bytes());
        out[16..24].copy_from_slice(&self.submitter_nonce.to_be_bytes());
        out
    }

    /// Decode `ShieldAad` from its 24-byte canonical encoding.
    #[must_use]
    pub fn from_bytes(b: &[u8; AAD_BYTES]) -> Self {
        Self {
            chain_id: u64::from_be_bytes(b[0..8].try_into().expect("slice length == 8")),
            epoch: u64::from_be_bytes(b[8..16].try_into().expect("slice length == 8")),
            submitter_nonce: u64::from_be_bytes(b[16..24].try_into().expect("slice length == 8")),
        }
    }
}

// ── Ciphertext ────────────────────────────────────────────────────────────────

/// A Shield ciphertext: encrypted transaction + TPKE components (§2.6).
///
/// # Construction
///
/// Produced by [`crate::shield::tpke::encrypt`] (client-side) or deserialized
/// via [`Ciphertext::from_bytes`] (network ingress — runs subgroup + payload
/// checks automatically).
///
/// # Serde note
///
/// Serde `Serialize`/`Deserialize` is deferred to S8 (pool/network integration)
/// when the `ark-serialize` serde feature will be enabled. For now, use
/// [`Ciphertext::to_bytes`] / [`Ciphertext::from_bytes`] for all wire encoding.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ciphertext {
    /// `[r]G ∈ 𝔾₁` — ephemeral DH component.
    pub u: G1Affine,
    /// `[r]·H_𝔾₂(U, aad) ∈ 𝔾₂` — ciphertext integrity component.
    pub w: G2Affine,
    /// Associated data — binds the ciphertext to chain + epoch + nonce.
    pub aad: ShieldAad,
    /// ChaCha20Poly1305 ciphertext + 16-byte tag (§1.3, §2.1 step 6).
    pub payload: Vec<u8>,
}

impl Ciphertext {
    /// Serialize to the canonical wire format (see module-level layout).
    ///
    /// # Errors
    ///
    /// [`ShieldError::Serialization`] if `u` or `w` cannot be compressed.
    /// Practically unreachable for well-formed BLS12-381 points.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ShieldError> {
        // Guard: payload must be within the allowed bound (defensive — encrypt
        // checks this already, but in-memory Ciphertexts may be caller-constructed).
        if self.payload.len() > MAX_SHIELD_PAYLOAD_BYTES {
            return Err(ShieldError::PayloadTooLarge {
                len: self.payload.len(),
                max: MAX_SHIELD_PAYLOAD_BYTES,
            });
        }
        let mut out = Vec::with_capacity(MIN_CIPHERTEXT_BYTES + self.payload.len());
        self.u
            .serialize_compressed(&mut out)
            .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
        self.w
            .serialize_compressed(&mut out)
            .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
        out.extend_from_slice(&self.aad.to_bytes());
        // Payload length as u32 BE (≤ MAX_SHIELD_PAYLOAD_BYTES ≤ 4096 << u32::MAX)
        let len_u32 = self.payload.len() as u32;
        out.extend_from_slice(&len_u32.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Deserialize from the canonical wire format, running all boundary checks.
    ///
    /// Performs in order:
    /// 1. Subgroup check on `u` (𝔾₁)
    /// 2. Subgroup check on `w` (𝔾₂) — critical for BLS12-381 G2 (cofactor > 1)
    /// 3. Payload length ≤ [`MAX_SHIELD_PAYLOAD_BYTES`]
    ///
    /// # Errors
    ///
    /// - [`ShieldError::Serialization`] — malformed bytes or truncated input.
    /// - [`ShieldError::InvalidCiphertext`] — off-subgroup point.
    /// - [`ShieldError::PayloadTooLarge`] — payload exceeds the allowed bound.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ShieldError> {
        if bytes.len() < MIN_CIPHERTEXT_BYTES {
            return Err(ShieldError::Serialization(format!(
                "ciphertext too short: {} bytes (minimum {})",
                bytes.len(),
                MIN_CIPHERTEXT_BYTES
            )));
        }

        // Deserialize u and w using arkworks streaming reader.
        // `&mut &[u8]` implements `Read`; each call advances the slice.
        let mut cursor: &[u8] = bytes;

        let u = G1Affine::deserialize_compressed(&mut cursor)
            .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
        // Subgroup check — AGENTS §15.2, 15-SPEC §1.3.
        // For BLS12-381 G1, cofactor h=1 so all on-curve points are in the subgroup;
        // the check is still explicit as defense-in-depth per the spec.
        if !u.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ShieldError::InvalidCiphertext);
        }

        let w = G2Affine::deserialize_compressed(&mut cursor)
            .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
        // Subgroup check — MANDATORY for G2 (cofactor > 1 for BLS12-381 G2).
        if !w.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ShieldError::InvalidCiphertext);
        }

        // After the two point deserializations, cursor points to: aad (24) + len (4) + payload.
        if cursor.len() < AAD_BYTES + 4 {
            return Err(ShieldError::Serialization(
                "ciphertext truncated: missing aad or payload length".into(),
            ));
        }

        let aad_arr: &[u8; AAD_BYTES] = cursor[..AAD_BYTES]
            .try_into()
            .expect("slice length == AAD_BYTES");
        let aad = ShieldAad::from_bytes(aad_arr);
        cursor = &cursor[AAD_BYTES..];

        let payload_len =
            u32::from_be_bytes(cursor[..4].try_into().expect("slice length == 4")) as usize;
        cursor = &cursor[4..];

        // Payload bounds — must precede any allocation (DoS guard, 15-SPEC §2.6).
        if payload_len > MAX_SHIELD_PAYLOAD_BYTES {
            return Err(ShieldError::PayloadTooLarge {
                len: payload_len,
                max: MAX_SHIELD_PAYLOAD_BYTES,
            });
        }
        if cursor.len() < payload_len {
            return Err(ShieldError::Serialization(format!(
                "ciphertext truncated: expected {payload_len} payload bytes, got {}",
                cursor.len()
            )));
        }

        // Strict canonical decoder (S1 review): reject trailing bytes.
        // A canonical encoding has exactly MIN_CIPHERTEXT_BYTES + payload_len bytes.
        // Trailing bytes would allow two different byte strings to produce the same
        // Ciphertext (encoding malleability — not a crypto flaw, but undesirable for
        // a consensus wire format where canonical = unique).
        if cursor.len() != payload_len {
            return Err(ShieldError::Serialization(format!(
                "ciphertext has {} trailing bytes after payload (expected 0)",
                cursor.len() - payload_len
            )));
        }

        Ok(Self {
            u,
            w,
            aad,
            payload: cursor[..payload_len].to_vec(),
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
