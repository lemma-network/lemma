//! TPKE — Threshold Public-Key Encryption (S2: encrypt + validity).
//!
//! Implements the **Baek–Zheng GDH threshold cryptosystem** over BLS12-381
//! (15-SHIELD_SPEC §2). This module grows across sub-steps:
//!
//! | Sub-step | Functions added |
//! |----------|----------------|
//! | S2 | [`encrypt`], [`validate`], [`validate_batch`] |
//! | S3 | `decryption_share` + DLEQ proof → `share.rs` |
//! | S4 ✅ | [`CombineShare`], [`combine`] — Lagrange-in-exponent + AEAD decrypt |
//!
//! # Determinism (§7)
//!
//! Every function called in the **validator / settlement path** is deterministic:
//! no `SystemTime`, no `HashMap`, no floats, no per-call randomness.
//! [`encrypt`] is **client-side only** (uses CSPRNG for the ephemeral scalar `r`).
//!
//! # sha2 version note (DB-13)
//!
//! Hash-to-curve (`H_𝔾₂`) uses **`sha2_v010`** (sha2 0.10) because `arkworks
//! 0.4.x DefaultFieldHasher` requires `digest 0.10`. The rest of the module
//! (HKDF, Blake2b challenges) uses the workspace-standard `sha2 0.11`.
//! See `decisions-log.md` DB-13.

use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use secret_sharing_and_dkg::common::ShareId;
use sha2::Sha256;
use std::collections::BTreeMap;

use crate::shield::{
    ciphertext::{Ciphertext, ShieldAad},
    committee::ShieldCommittee,
    domain::ShieldDomain,
    params::{
        DST_H2G2, HKDF_INFO_AEAD_KEY, HKDF_INFO_NONCE, HKDF_SALT, MAX_SHIELD_PAYLOAD_BYTES,
    },
    ShieldError,
};

// ── hash_to_g2 ────────────────────────────────────────────────────────────────

/// Map `(U, aad)` to a 𝔾₂ point via RFC 9380 (BLS12381G2_XMD:SHA-256_SSWU_RO_).
///
/// This is `H_𝔾₂(U, aad)` from 15-SHIELD_SPEC §1.3. Used in both encryption
/// (step 4) and validity checking (§2.2). The mapping is deterministic:
/// same `(U, aad)` → same 𝔾₂ point on every node (§7).
///
/// DST: [`DST_H2G2`] (frozen consensus constant — changing it is a hard fork).
///
/// **sha2_v010 note**: uses `sha2_v010::Sha256` (sha2 0.10) because
/// `arkworks DefaultFieldHasher` requires `digest 0.10` trait bounds.
pub(crate) fn hash_to_g2(u: &G1Affine, aad: &ShieldAad) -> Result<G2Affine, ShieldError> {
    // Message = compressed U ‖ canonical aad bytes.
    // Deterministic: compressed encoding is canonical; aad.to_bytes() is fixed-size BE.
    // Same (U, aad) → same message → same G2 point on every node (§7).
    let mut message = Vec::new();
    u.serialize_compressed(&mut message)
        .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
    message.extend_from_slice(&aad.to_bytes());
    crate::shield::fs::hash_to_g2_with_dst(DST_H2G2, &message)
}

// ── derive_key_nonce ──────────────────────────────────────────────────────────

/// Derive the ChaCha20Poly1305 key and nonce from the pairing output `S`.
///
/// Uses HKDF-SHA256 with the frozen salt and distinct info labels (§1.3, §7.6).
/// Both derivations use the same `S_bytes` as IKM, ensuring they are
/// cryptographically bound to the same ephemeral shared secret.
///
/// Returns `(key_32_bytes, nonce_12_bytes)`.
fn derive_key_nonce(
    s: &<Bls12_381 as Pairing>::TargetField,
) -> Result<([u8; 32], [u8; 12]), ShieldError> {
    // Serialize S ∈ 𝔾_T (= Fq12) to canonical bytes for use as HKDF IKM (§7.6).
    //
    // We use `serialize_uncompressed` because 𝔾_T elements (Fq12) are field elements,
    // not EC points — there is no meaningful "compression" for field elements; the
    // uncompressed canonical encoding IS the unique, deterministic wire form.
    // (Note: 15-SHIELD_SPEC §1.3 uses the word "compressed" loosely to mean
    // "canonical"; this code correctly implements uncompressed Fq12 serialization,
    // which is the frozen HKDF IKM format — changing it is a hard fork. DB-13.)
    let mut s_bytes = Vec::new();
    s.serialize_uncompressed(&mut s_bytes)
        .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), &s_bytes);

    let mut key = [0u8; 32];
    hk.expand(HKDF_INFO_AEAD_KEY, &mut key)
        .map_err(|_| ShieldError::AeadFailure)?;

    let mut nonce = [0u8; 12];
    hk.expand(HKDF_INFO_NONCE, &mut nonce)
        .map_err(|_| ShieldError::AeadFailure)?;

    Ok((key, nonce))
}

// ── encrypt ───────────────────────────────────────────────────────────────────

/// Encrypt `msg` to the epoch public key `Y` (client-side, §2.1).
///
/// Steps (15-SHIELD_SPEC §2.1):
/// 1. Sample ephemeral `r ∈ 𝔽_r` (CSPRNG — encryption is off the consensus
///    path, so per-call randomness is correct here).
/// 2. `S = e([r]Y, H)` — ephemeral shared secret in 𝔾_T.
/// 3. `U = [r]G` — ephemeral DH component (𝔾₁).
/// 4. `W = [r]·H_𝔾₂(U, aad)` — ciphertext integrity component (𝔾₂).
/// 5. Derive symmetric key + nonce from `S` via HKDF-SHA256.
/// 6. `C = ChaCha20Poly1305.encrypt(key, nonce, msg, aad_bytes)`.
///
/// # Errors
///
/// - [`ShieldError::PayloadTooLarge`] — `msg` exceeds [`MAX_SHIELD_PAYLOAD_BYTES`].
/// - [`ShieldError::HashToCurve`] — `H_𝔾₂` map failed (practically unreachable).
/// - [`ShieldError::AeadFailure`] — AEAD encryption failed (practically unreachable).
pub fn encrypt(y: &G1Affine, aad: ShieldAad, msg: &[u8]) -> Result<Ciphertext, ShieldError> {
    if msg.len() > MAX_SHIELD_PAYLOAD_BYTES {
        return Err(ShieldError::PayloadTooLarge {
            len: msg.len(),
            max: MAX_SHIELD_PAYLOAD_BYTES,
        });
    }

    // Step 1: sample r (CSPRNG; client-side only — see §2.1 determinism note)
    let mut rng = ark_std::rand::thread_rng();
    let r = ark_bls12_381::Fr::rand(&mut rng);

    let g = G1Affine::generator();
    let h = G2Affine::generator();

    // Step 2: S = e([r]Y, H)
    let ry: G1Affine = (G1Projective::from(*y) * r).into_affine();
    let s = Bls12_381::pairing(ry, h);

    // Step 3: U = [r]G
    let u: G1Affine = (G1Projective::from(g) * r).into_affine();

    // Step 4: W = [r] · H_𝔾₂(U, aad)
    let h_g2 = hash_to_g2(&u, &aad)?;
    let w: G2Affine = (G2Projective::from(h_g2) * r).into_affine();

    // Steps 5–6: HKDF + AEAD encrypt
    let (key_bytes, nonce_bytes) = derive_key_nonce(&s.0)?;
    let aad_bytes = aad.to_bytes();

    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|_| ShieldError::AeadFailure)?;
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    let payload = cipher
        .encrypt(nonce, Payload { msg, aad: &aad_bytes })
        .map_err(|_| ShieldError::AeadFailure)?;

    Ok(Ciphertext { u, w, aad, payload })
}

// ── validate ──────────────────────────────────────────────────────────────────

/// Validate that a ciphertext is well-formed (§2.2).
///
/// Checks the single-ciphertext pairing equation:
/// ```text
/// e(U, H_𝔾₂(U, aad)) == e(G, W)
/// ```
///
/// This is the **ingress DoS pre-check** (one pairing per ciphertext). Runs
/// at network ingress before the ciphertext enters the pool (11-MEMPOOL_SHIELD_SPEC §5).
/// Also runs post-order, pre-decrypt (see S8 integration).
///
/// # Errors
///
/// - [`ShieldError::InvalidCiphertext`] — pairing equation does not hold.
/// - [`ShieldError::HashToCurve`] — `H_𝔾₂` map failed (practically unreachable).
pub fn validate(ct: &Ciphertext) -> Result<(), ShieldError> {
    // Guard 1: Reject identity (zero) points.
    // e(0_G1, Q) = 1 = e(P, 0_G2) in 𝔾_T for any P, Q — the pairing equation
    // would hold trivially (1 == 1), passing validation for a ciphertext whose
    // "shared secret" S = 1 (GT identity). HKDF(1) produces a fixed, known key:
    // a catastrophic disclosure. Zero U or W is also cryptographically meaningless
    // (encrypting to the identity point provides no security).
    if ct.u.is_zero() || ct.w.is_zero() {
        return Err(ShieldError::InvalidCiphertext);
    }

    // Guard 2: Subgroup checks — every point validated at this entry, regardless
    // of whether it arrived via `from_bytes` (network) or in-memory construction.
    // `from_bytes` checks these too, but `validate` is a `pub` API and must be
    // self-sufficient for any caller (§1.3: "mandatory on every deserialized point").
    // For G1, cofactor = 1, so this is trivially true but included per spec.
    // For G2, cofactor > 1 — small-subgroup confusion attacks are real here.
    if !ct.u.is_in_correct_subgroup_assuming_on_curve()
        || !ct.w.is_in_correct_subgroup_assuming_on_curve()
    {
        return Err(ShieldError::InvalidCiphertext);
    }

    let h_g2 = hash_to_g2(&ct.u, &ct.aad)?;

    let lhs = Bls12_381::pairing(ct.u, h_g2);
    let rhs = Bls12_381::pairing(G1Affine::generator(), ct.w);

    if lhs == rhs {
        Ok(())
    } else {
        Err(ShieldError::InvalidCiphertext)
    }
}

// ── validate_batch ────────────────────────────────────────────────────────────

/// Batch-validate a block of ciphertexts using Fiat–Shamir randomisation (§2.2).
///
/// Cheaper than calling [`validate`] per ciphertext: one multi-pairing replaces
/// `2k` pairings. The Fiat–Shamir challenges `α_j` prevent a cheating prover
/// from passing two invalid ciphertexts whose errors cancel.
///
/// Equation:
/// ```text
/// ∏_j e([α_j]U_j, H_𝔾₂(U_j,aad_j)) == e(G, Σ_j [α_j]W_j)
/// ```
///
/// Implemented as a single multi-pairing over `k+1` pairs (negation trick):
/// ```text
/// ∏_j e([α_j]U_j, H_𝔾₂_j) · e(-G, Σ[α_j]W_j) == 1 in 𝔾_T
/// ```
///
/// # Errors
///
/// - [`ShieldError::InvalidCiphertext`] — batch check fails (at least one invalid).
/// - [`ShieldError::HashToCurve`] / [`ShieldError::Serialization`] — from helpers.
pub fn validate_batch(cts: &[Ciphertext]) -> Result<(), ShieldError> {
    if cts.is_empty() {
        return Ok(());
    }
    if cts.len() == 1 {
        return validate(&cts[0]);
    }

    let alphas = fiat_shamir_challenges(cts)?;

    let mut g1_pairs: Vec<G1Affine> = Vec::with_capacity(cts.len() + 1);
    let mut g2_pairs: Vec<G2Affine> = Vec::with_capacity(cts.len() + 1);
    let mut sum_alpha_w = G2Projective::zero();

    for (ct, &alpha) in cts.iter().zip(alphas.iter()) {
        // Per-element zero + subgroup guards — parity with `validate` (W1/S2 review).
        // A zero or off-subgroup point in any batch element is an invalid ciphertext.
        if ct.u.is_zero()
            || ct.w.is_zero()
            || !ct.u.is_in_correct_subgroup_assuming_on_curve()
            || !ct.w.is_in_correct_subgroup_assuming_on_curve()
        {
            return Err(ShieldError::InvalidCiphertext);
        }
        let h_g2 = hash_to_g2(&ct.u, &ct.aad)?;
        let alpha_u: G1Affine = (G1Projective::from(ct.u) * alpha).into_affine();
        g1_pairs.push(alpha_u);
        g2_pairs.push(h_g2);
        sum_alpha_w += G2Projective::from(ct.w) * alpha;
    }

    // Negation term: e(-G, Σ α_j W_j)
    g1_pairs.push(-G1Affine::generator());
    g2_pairs.push(sum_alpha_w.into_affine());

    // Multi-pairing: product == identity (PairingOutput::zero()) iff all valid.
    let result = Bls12_381::multi_pairing(g1_pairs, g2_pairs);
    if result.is_zero() {
        Ok(())
    } else {
        Err(ShieldError::InvalidCiphertext)
    }
}

// ── combine (S4) ─────────────────────────────────────────────────────────────

/// One contributing validator's input to `combine` (§2.5, corrected formula).
///
/// Carries the validator's recovered TPKE group-element key shares
/// `Z_{i,ω_k} = [dk_i^{-1}] Ŷ_{i,ω_k} = [f(ω_k)] H ∈ 𝔾₂` (§4.5).
///
/// ## Spec correction — why `D_i` is NOT used in combine
///
/// The spec §2.5 formula `S_i = e(D_i, Σ λ_ω Z_{i,ω})` is **mathematically incorrect**
/// when `D_i = [dk_i^{-1}]U` and `Z_{i,ω} = [f(ω)]H`:
///
/// ```text
/// e([dk_inv·r]G, [a₀]H) = e(G,H)^{dk_inv·r·a₀}  ≠  S_enc = e(G,H)^{r·a₀}
/// ```
///
/// The **correct formula** uses `U` (the ciphertext G1 component) — NOT `D_i`:
///
/// ```text
/// S = e(U, Σ_{all ω} λ_ω(0) · Z_{i,ω})
/// = e([r]G, [Σ λ_ω·f(ω)]H) = e([r]G, [f(0)]H) = e([r]G, [a₀]H) = e([r]Y, H) = S_enc  ✓
/// ```
///
/// `D_i = [dk_i^{-1}]U` is the **accountability token** (S3): validators publish it with a
/// DLEQ proof to prove they participated and can be slashed for withholding (13 §5.4).
/// The actual decryption uses `Z_{i,ω}` directly — validators compute and publish these
/// from their private `dk_i` applied to the PVSS transcript (`Z = [dk_inv]Ŷ`).
///
/// `z_shares` must include **all** share IDs in the contributing validator's Ω_i —
/// a missing ID reduces contributing weight below `p+1`.
#[derive(Clone, Debug)]
pub struct CombineShare {
    /// Committee index (for grouping / threshold accounting).
    pub validator_index: u16,
    /// `(ω_k, Z_{i,ω_k})` — per-share recovered TPKE key shares.
    /// Each `Z_{i,ω_k} = [dk_i^{-1}] Ŷ_{i,ω_k} = [f(ω_k)] H ∈ 𝔾₂` (§4.5).
    pub z_shares: Vec<(ShareId, G2Affine)>,
}

/// Reconstruct the plaintext from a threshold subset of `Z` shares (§2.5, corrected).
///
/// **Correct combine formula** (one pairing via bilinearity):
///
/// ```text
/// agg_G2 = Σ_{all ω} λ_ω(0) · Z_{i,ω}        // Lagrange-in-G2 → [a₀]H
/// S       = e(U, agg_G2)                        // single pairing → S_enc = e(G,H)^{r·a₀}
/// k, nonce = HKDF(S)
/// msg      = ChaCha20Poly1305.decrypt(k, nonce, payload, aad)
/// ```
///
/// Correctness: `Σ λ_ω [f(ω)]H = [Σ λ_ω f(ω)]H = [f(0)]H = [a₀]H` (Lagrange).
/// Then `e([r]G, [a₀]H) = e(G,H)^{r·a₀} = e([r][a₀]G, H) = e([r]Y, H) = S_enc`. ✓
///
/// Bilinearity makes the per-validator grouping an implementation convenience only —
/// the final result is identical to one call `e(U, Σ_all λ_ω Z_ω)`.
///
/// ## Preconditions
///
/// - Each validator's `z_shares` are correctly computed from their private `dk_i`
///   and the committed PVSS transcript (node/S8 layer assembles this).
/// - `ct` has been validated via `validate` before calling.
/// - No duplicate or out-of-range share IDs across all entries (validated internally).
///
/// ## Determinism (§7)
///
/// G2 accumulation iterates validators in **ascending `validator_index` order**
/// (BTreeMap) so all nodes compute byte-identical `agg_G2` for the same inputs.
/// No floats, no HashMap, no SystemTime. Returns `Result`, never panics.
///
/// # Errors
///
/// - [`ShieldError::InsufficientShares`] — total contributing weight `< p+1`.
/// - [`ShieldError::Lagrange`] — invalid share-ID subset (0, >W, or duplicates).
/// - [`ShieldError::AeadFailure`] — AEAD decryption failed (wrong key or tampered payload).
pub fn combine(
    ct: &Ciphertext,
    shares: &[CombineShare],
    committee: &ShieldCommittee,
    domain: &ShieldDomain,
) -> Result<Vec<u8>, ShieldError> {
    // ── 1. Threshold gate ─────────────────────────────────────────────────────
    let contributing_weight: u64 = shares.iter().map(|s| s.z_shares.len() as u64).sum();
    let need = committee.params().decrypt_threshold(); // = p+1; single source of truth (§4.2)
    if contributing_weight < need {
        return Err(ShieldError::InsufficientShares { have: contributing_weight, need });
    }

    // ── 2. Collect + sort contributing share-ID set Ω = ⋃_i Ω_i ─────────────
    // Sort for determinism (§7); lagrange_coeffs_for rejects duplicates (W1 closed).
    let omega_all: Vec<ShareId> = {
        let mut ids: Vec<ShareId> = shares
            .iter()
            .flat_map(|s| s.z_shares.iter().map(|&(id, _)| id))
            .collect();
        ids.sort_unstable();
        ids
    };

    // ── 3. Lagrange coefficients λ_ω(0) for the contributing subset ───────────
    let lambdas = domain.lagrange_coeffs_for(omega_all.clone())?;
    // ShareId → λ_k(0)  (BTreeMap: O(log n), deterministic iteration, §7.1)
    let lambda_map: BTreeMap<ShareId, ark_bls12_381::Fr> =
        omega_all.into_iter().zip(lambdas).collect();

    // ── 4. Aggregate G2: agg_G2 = Σ_{all ω} λ_ω · Z_{i,ω}  ─────────────────
    // Sort validators ascending for deterministic accumulation order (§7).
    let mut sorted_shares: Vec<&CombineShare> = shares.iter().collect();
    sorted_shares.sort_by_key(|s| s.validator_index);

    let agg_g2: G2Affine = sorted_shares
        .iter()
        .flat_map(|share| share.z_shares.iter())
        .fold(G2Projective::zero(), |acc, &(id, z)| {
            let lambda = lambda_map.get(&id).copied().unwrap_or_default();
            acc + G2Projective::from(z) * lambda
        })
        .into_affine();

    // ── 5. Single pairing: S = e(U, agg_G2)  ─────────────────────────────────
    // By Lagrange: agg_G2 = [a₀]H, so S = e([r]G, [a₀]H) = e(G,H)^{r·a₀} = S_enc. ✓
    // ONE pairing (bilinearity collapses the per-validator sum into a single G2 elem).
    let s = Bls12_381::pairing(ct.u, agg_g2);

    // ── 6. HKDF + AEAD decrypt (inverse of encrypt steps 5–6) ────────────────
    // Reuse derive_key_nonce — same frozen salt/info constants. DRY (AGENTS §2).
    let (key_bytes, nonce_bytes) = derive_key_nonce(&s.0)?;
    let aad_bytes = ct.aad.to_bytes();

    let cipher = ChaCha20Poly1305::new_from_slice(&key_bytes)
        .map_err(|_| ShieldError::AeadFailure)?;
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, Payload { msg: &ct.payload, aad: &aad_bytes })
        .map_err(|_| ShieldError::AeadFailure)
}

// ── fiat_shamir_challenges ────────────────────────────────────────────────────

/// Derive Fiat–Shamir challenges `α_j ∈ 𝔽_r` for batch validity (§2.2, §7.5).
///
/// Deterministic: same ordered ciphertext list → same `α_j` on every node.
/// Each `α_j` is derived from `Blake2b512(full_transcript ‖ j_le_bytes)[..32]`
/// reduced mod `r`, giving a challenge that depends on the full ordered set.
///
/// # Errors
///
/// [`ShieldError::Serialization`] if a ciphertext cannot be serialized to bytes.
pub(crate) fn fiat_shamir_challenges(
    cts: &[Ciphertext],
) -> Result<Vec<ark_bls12_381::Fr>, ShieldError> {
    // Build the full transcript: all ciphertexts in order (canonical, §7.5).
    let mut transcript: Vec<u8> = Vec::new();
    for ct in cts {
        transcript.extend_from_slice(&ct.to_bytes()?);
    }

    // Derive one scalar per ciphertext via counter-mode Blake2b512 (§7.5).
    // Delegated to `fs::expand_challenges` — single canonical implementation.
    Ok(crate::shield::fs::expand_challenges(&transcript, cts.len()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
