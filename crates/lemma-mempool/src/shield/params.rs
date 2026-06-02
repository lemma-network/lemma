//! `ShieldParams` — threshold parameters and frozen protocol constants.
//!
//! All values derived from the committee weight `W` using the BFT 1/3 model
//! (15-SHIELD_SPEC §4.2). Constants in this module are part of the **consensus
//! contract** — they must be identical on every node. Changes require a
//! hard fork (§1.3, §7, FZ-2).
//!
//! # Threshold formulas (FROZEN)
//!
//! | Parameter | Formula | Meaning |
//! |-----------|---------|---------|
//! | `W` | total share count | FFT domain size |
//! | `t` | `⌊W/3⌋ − 1` | secrecy threshold; secure when `< 1/3` weight Byzantine |
//! | `p` | `⌊2W/3⌋` | privacy threshold; `≥ p+1` weight needed to decrypt |
//!
//! # HKDF / hash-to-curve domain separation (FROZEN — FZ-2)
//!
//! Every DST string below is a fixed byte string compiled into the binary.
//! A divergent DST silently breaks cross-node agreement (`H_𝔾₂(U)` diverges).

use crate::shield::ShieldError;

// ── Domain-separation tags (hash-to-curve / hash-to-field) ───────────────────

/// Hash-to-𝔾₂ DST — suite `BLS12381G2_XMD:SHA-256_SSWU_RO_` (RFC 9380).
///
/// Used in `H_𝔾₂(U, aad)` for TPKE ciphertext validity (15-SPEC §1.3, §2.2).
pub const DST_H2G2: &[u8] = b"LEMMA-SHIELD-H2G2-v1";

/// Hash-to-𝔽_r DST — same RFC 9380 construction.
///
/// Used for Fiat-Shamir hash-to-field challenges (15-SPEC §1.3).
pub const DST_H2F: &[u8] = b"LEMMA-SHIELD-H2F-v1";

/// Hash-to-𝔾₂ DST for the independent PVSS correctness-tag generator `û₁`.
///
/// `û₁` = `H_𝔾₂(DST_PVSS_U1)` — a second independent 𝔾₂ generator used
/// only in PVSS: `û₂ = [a_0]û₁` is the correctness tag binding the dealer's
/// constant term `a_0` (15-SHIELD_SPEC §4.1, FZ-4). Independence from the
/// standard generator `H = 𝔾₂::generator()` is guaranteed by the distinct DST.
///
/// **Frozen FZ-4**: changing this DST is a hard fork — all existing PVSS
/// transcripts become unverifiable. Never change without a governance process.
pub const DST_PVSS_U1: &[u8] = b"LEMMA-SHIELD-PVSS-U1-v1";

// ── HKDF constants (symmetric key derivation) ─────────────────────────────────

/// HKDF-SHA256 salt (fixed, compiled in).
///
/// Combined with the pairing output `S ∈ 𝔾_T` to derive the AEAD key and
/// nonce. Fixed salt ensures every node derives the identical key from the
/// same `S` (15-SPEC §1.3, §7.6).
pub const HKDF_SALT: &[u8] = b"LEMMA-SHIELD-HKDF-SALT-v1";

/// HKDF info label for the AEAD symmetric key.
pub const HKDF_INFO_AEAD_KEY: &[u8] = b"LEMMA-SHIELD-AEAD-KEY-v1";

/// HKDF info label for the 96-bit AEAD nonce.
pub const HKDF_INFO_NONCE: &[u8] = b"LEMMA-SHIELD-NONCE-v1";

// ── Payload bound ─────────────────────────────────────────────────────────────

/// Maximum size in bytes of the plaintext carried inside a `Ciphertext.payload`.
///
/// Enforced at ingress (DoS pre-check, 15-SPEC §2.6) before any pairing op.
/// Set to 4 096 bytes (4 KiB): enough for complex contract calldata at launch.
/// Reviewable post-testnet via governance without a hard fork (it is an
/// admission policy, not a consensus constant).
pub const MAX_SHIELD_PAYLOAD_BYTES: usize = 4_096;

// ── Weight granularity ────────────────────────────────────────────────────────

/// Drop units per share (stake-to-weight granularity).
///
/// Each validator receives `⌊stake_drop / WEIGHT_GRANULARITY_DROP⌋` shares in
/// the Ω_i partition. A validator with stake below this threshold receives zero
/// shares and is rejected by `ShieldCommittee::from_validator_set`.
///
/// **Value**: 1 000 000 LEM per share (= `1_000_000 × 10¹⁸` Drop).
///
/// **Rationale**: With the genesis minimum self-stake of 20M LEM, the smallest
/// validator receives 20 shares; the largest practical committee (100 validators
/// × 100M LEM each at 1M-LEM/share) yields W = 10 000 shares — well within the
/// `u16::MAX = 65 535` ShareId ceiling and manageable for FFT. This constant is
/// a **frozen consensus parameter**: changing it alters all Ω_i partitions and
/// requires a hard fork.
pub const WEIGHT_GRANULARITY_DROP: u128 = 1_000_000 * lemma_core::amount::DROPS_PER_LEM;

// ── ShieldParams ──────────────────────────────────────────────────────────────

/// Threshold parameters for one epoch's Shield committee.
///
/// Derived deterministically from total share count `W` using the BFT 1/3
/// model (15-SHIELD_SPEC §4.2). All three values are integers — no floats
/// (AGENTS.md §7.1).
///
/// See [`ShieldParams::for_weight`] for construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShieldParams {
    /// Total share count `W` — size of the (logical) share domain.
    ///
    /// The FFT evaluation domain is the next power-of-two ≥ `W`; the share IDs
    /// are `1, 2, …, W` (integers, as required by `lagrange_basis_at_0_for_all`).
    pub w: u64,

    /// Secrecy threshold `t = ⌊W/3⌋ − 1`.
    ///
    /// The scheme is secure (no coalition of `≤ t` validators can learn the
    /// group secret) when at most `t` weight is Byzantine. Matches the BFT
    /// 1/3 bound: `t < W/3` ⟹ Byzantine weight < 1/3.
    pub t: u64,

    /// Privacy threshold `p = ⌊2W/3⌋`.
    ///
    /// Decryption requires at least `p + 1` share-weight to combine. Any
    /// coalition of `≤ p` weight learns nothing about the plaintext.
    /// `p + 1 > 2/3 × W` ensures a Byzantine minority cannot decrypt alone.
    pub p: u64,
}

impl ShieldParams {
    /// Construct threshold parameters from total weight `W`.
    ///
    /// Applies the BFT 1/3 model (15-SHIELD_SPEC §4.2):
    /// - `t = ⌊W/3⌋ − 1`
    /// - `p = ⌊2W/3⌋`
    ///
    /// Both formulas use overflow-safe integer arithmetic (no 2×W overflow,
    /// no underflow for the `−1` when `W ≥ 4`).
    ///
    /// # Errors
    ///
    /// Returns [`ShieldError::CommitteeTooSmall`] when `W < 4`. With `W = 3`,
    /// `t = 0` still, so W = 4 is the first value that gives unambiguous
    /// threshold separation. The practical minimum is much higher (≥ 20 shares
    /// per validator × ≥ 3 validators = W ≥ 60).
    pub fn for_weight(w: u64) -> Result<Self, ShieldError> {
        // Minimum W: need ⌊W/3⌋ ≥ 1 (so W ≥ 3) to avoid underflow in t,
        // and W ≥ 4 for the first clearly non-degenerate threshold.
        if w < 4 {
            return Err(ShieldError::CommitteeTooSmall { have: w });
        }

        // t = ⌊W/3⌋ − 1.
        // Safe: W ≥ 4 → W/3 ≥ 1 (integer), no underflow.
        let t = w / 3 - 1;

        // p = ⌊2W/3⌋ computed without overflow via the identity:
        //   ⌊2W/3⌋ = 2⌊W/3⌋ + (1 if W mod 3 == 2 else 0)
        // This avoids the 2*W multiplication (which overflows for W > u64::MAX/2).
        // Verified: W=6→4, W=7→4, W=8→5, W=9→6, W=11→7, W=12→8. ✓
        let p = 2 * (w / 3) + u64::from(w % 3 == 2);

        Ok(Self { w, t, p })
    }

    /// Minimum share weight required to decrypt: `p + 1`.
    ///
    /// Combine (15-SPEC §2.5) succeeds iff contributing validators' total
    /// weight ≥ this value. Returns `ShieldError::InsufficientShares` (S4)
    /// when the threshold is not met.
    #[must_use]
    pub fn decrypt_threshold(&self) -> u64 {
        // Safe: p ≤ W − 1 < u64::MAX.
        self.p + 1
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
