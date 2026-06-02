//! Shared Fiat–Shamir expansion and hash-to-curve helpers for Shield crypto.
//!
//! Extracted from `tpke`, `share`, and `pvss` to satisfy AGENTS §2.1 (DRY):
//! all three contained near-identical counter-mode Blake2b512 challenge
//! expansion, and `tpke`/`pvss` duplicated the same `G2Hasher` type alias +
//! `MapToCurveBasedHasher` setup. This module is the single canonical home.
//!
//! All functions are **pure and deterministic** (§7):
//! no side effects, no `SystemTime`, no `HashMap`, no floats.

use ark_bls12_381::{Fr, G2Affine, G2Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap,
    map_to_curve_hasher::MapToCurveBasedHasher,
    HashToCurve,
};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use blake2::{Blake2b512, Digest};
use sha2_v010::Sha256 as Sha256v10;

use crate::shield::ShieldError;

// ── BLS12-381 G2 hash-to-curve ────────────────────────────────────────────────

/// BLS12-381 G2 hash-to-curve hasher (RFC 9380 `G2_XMD:SHA-256_SSWU_RO_`).
///
/// Uses `sha2_v010::Sha256` (sha2 0.10) because arkworks 0.4.x
/// `DefaultFieldHasher` requires the `digest 0.10` trait bounds (DB-13).
type G2Hasher = MapToCurveBasedHasher<
    G2Projective,
    DefaultFieldHasher<Sha256v10, 128>,
    WBMap<ark_bls12_381::g2::Config>,
>;

/// Map bytes to a 𝔾₂ point via RFC 9380 hash-to-curve with `dst`.
///
/// Deterministic: same `(dst, msg)` → same 𝔾₂ point on every node (§7).
/// DSTs are frozen consensus constants — changing one is a **hard fork**.
///
/// Used by:
/// - `tpke::hash_to_g2` with [`DST_H2G2`] — `H_𝔾₂` for encrypt/validate.
/// - `pvss::u1_generator` with [`DST_PVSS_U1`] — independent third generator.
///
/// [`DST_H2G2`]: crate::shield::params::DST_H2G2
/// [`DST_PVSS_U1`]: crate::shield::params::DST_PVSS_U1
///
/// # Errors
///
/// [`ShieldError::HashToCurve`] — RFC 9380 map failed (practically unreachable).
pub(crate) fn hash_to_g2_with_dst(dst: &[u8], msg: &[u8]) -> Result<G2Affine, ShieldError> {
    G2Hasher::new(dst)
        .map_err(|e| ShieldError::HashToCurve(format!("{e:?}")))?
        .hash(msg)
        .map_err(|e| ShieldError::HashToCurve(format!("{e:?}")))
}

// ── Counter-mode Fiat–Shamir challenge expansion ──────────────────────────────

/// Expand `count` Fiat–Shamir challenges `α_0…α_{count-1}` from a pre-built
/// transcript via **counter-mode Blake2b512** (§7.5 pattern).
///
/// Each challenge:
/// ```text
/// α_k = Blake2b512(transcript ‖ k_le64) mod r
/// ```
/// 512-bit digest >> 255-bit `r` → bias negligible.
/// Fully deterministic: same `(transcript, count)` → same `Vec<Fr>`.
///
/// Used by:
/// - `tpke::fiat_shamir_challenges` — batch validity (§2.2).
/// - `pvss::pvss_fiat_shamir_challenges` — batched share pairing (§4.3).
/// - `share::batch_share_challenges` — batch DLEQ verify (§2.4).
pub(crate) fn expand_challenges(transcript: &[u8], count: usize) -> Vec<Fr> {
    (0..count)
        .map(|k| {
            let mut h = Blake2b512::new();
            h.update(transcript);
            h.update((k as u64).to_le_bytes());
            Fr::from_le_bytes_mod_order(&h.finalize())
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
