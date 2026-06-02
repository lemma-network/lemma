//! # Shield decryption shares and Chaum–Pedersen DLEQ proofs (S3)
//!
//! Implements the per-validator threshold decryption share and its publicly-verifiable
//! correctness proof (15-SHIELD_SPEC §2.3–2.4, §3).
//!
//! ## Modules
//!
//! | Item | Spec ref | Purpose |
//! |------|----------|---------|
//! | [`DecryptionShare`] | §2.3 | `D_i = [dk_i^{-1}] U` + commitment `cm_i` + DLEQ proof |
//! | [`ShareProof`] | §3.2 | Chaum–Pedersen DLEQ (two Schnorr PoKs, shared witness) |
//! | [`decryption_share`] | §2.3, §3.2 | Produce a share + proof from `dk_i` |
//! | [`verify_share`] | §2.4, §3.2 | DLEQ + pairing tie + correctness (single share) |
//! | [`verify_share_batch`] | §2.4 | Fiat–Shamir multi-pairing batch (multi-validator) |
//!
//! ## Clean-room provenance (DB-11)
//!
//! Implements 15-SHIELD_SPEC §2.3–2.4 and §3 equations derived from the Ferveo
//! paper (ePrint 2022/898) and Baek–Zheng. Uses `schnorr_pok` 0.23.0 (Apache-2.0)
//! `PokDiscreteLogProtocol` as a composable primitive. The GPL-3.0 ferveo codebase
//! was **never read or referenced** (AGENTS §9.3).
//!
//! ## Determinism (§7)
//!
//! All verification paths are fully deterministic: the Fiat–Shamir challenge `c`
//! is recomputed from the public transcript — same bytes → same `𝔽_r` scalar on
//! every node. The prover's blinding `b` is local OS randomness (only in
//! `decryption_share`, off the consensus path).
//!
//! ## DLEQ transcript layout (frozen wire format — changing is a hard fork)
//!
//! Challenge `c` for a single share (§3.2):
//! `challenge_contribution(U, D_i, t_U)  ‖  challenge_contribution(G, cm_i, t_G)`
//! Each `challenge_contribution(base, y, t)` serializes `base ‖ y ‖ t` (compressed).
//! Net byte order: `U ‖ D_i ‖ t_U ‖ G ‖ cm_i ‖ t_G` (all G1 compressed, 48 B each = 288 B).

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use blake2::Blake2b512;
use schnorr_pok::discrete_log::{PokDiscreteLog, PokDiscreteLogProtocol};
use schnorr_pok::pok_generalized_pedersen::compute_random_oracle_challenge;
use std::collections::BTreeMap;

use crate::shield::{ciphertext::Ciphertext, error::ShieldError};

// ── Wire types ────────────────────────────────────────────────────────────────

/// Per-validator threshold decryption share for one ciphertext (§2.3).
///
/// Contains three public values:
/// - `d = D_i = [dk_i^{-1}] U ∈ 𝔾₁` — the decryption share ("fast method": one
///   𝔾₁ scalar-mult, no pairing per ciphertext).
/// - `cm = cm_i = [dk_i^{-1}] G ∈ 𝔾₁` — commitment to `dk_i^{-1}` in base `G`.
///   Needed for the DLEQ pairing tie `e(cm_i, ek_i) = e(G, H)` (§3.1), which proves
///   `dk_i^{-1}` is consistent with the published epoch key `ek_i = [dk_i] H`.
/// - `proof: ShareProof` — Chaum–Pedersen DLEQ proving both `d` and `cm` share
///   the same discrete-log witness `dk_i^{-1}` (§3.2).
///
/// A validator that submits a well-formed share with a valid proof cannot have forged
/// the share: the DLEQ ties `D_i` to `ek_i` so a wrong-but-pairing-consistent share
/// would require breaking discrete log (§3.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptionShare {
    /// Index into `ShieldCommittee::validators[validator_index]`.
    pub validator_index: u16,
    /// `D_i = [dk_i^{-1}] U ∈ 𝔾₁` — the threshold decryption share.
    pub d: G1Affine,
    /// `cm_i = [dk_i^{-1}] G ∈ 𝔾₁` — key witness in base `G` (for pairing tie).
    pub cm: G1Affine,
    /// Chaum–Pedersen DLEQ proof that `log_U(D_i) == log_G(cm_i)` (§3.2).
    pub proof: ShareProof,
}

/// Chaum–Pedersen DLEQ proof binding `D_i` to `cm_i` and `ek_i` (§3.2).
///
/// Composed from two `PokDiscreteLogProtocol` instances sharing **one witness**
/// (`dk_i^{-1}`) and **one blinding scalar** `b`:
///
/// ```text
/// t_U = [b] U   (commitment on base U — public)
/// t_G = [b] G   (commitment on base G — public)
/// c   = H_FS(U, D_i, t_U, G, cm_i, t_G)   (Fiat–Shamir — §7)
/// s   = b + c · dk_i^{-1}                  (shared response — public)
/// ```
///
/// Verification (`verify_share`):
/// ```text
/// [s]U == t_U + [c]D_i   AND   [s]G == t_G + [c]cm_i
/// ```
/// Both checks pass iff `s` encodes the same witness across both bases (DLEQ).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShareProof {
    /// `t_U = [b] U ∈ 𝔾₁` — Schnorr commitment on base `U`.
    pub t_u: G1Affine,
    /// `t_G = [b] G ∈ 𝔾₁` — Schnorr commitment on base `G`.
    pub t_g: G1Affine,
    /// `s = b + c · dk_i^{-1} ∈ 𝔽_r` — shared Schnorr response (same for both checks).
    pub response: Fr,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Produce `D_i = [dk_i^{-1}] U` and a Chaum–Pedersen DLEQ proof (§2.3, §3.2).
///
/// `dk_i` is the validator's epoch decryption scalar (private; it is consumed via
/// an immutable reference and never stored after this call). The DLEQ proof
/// blinding `b` is sampled from OS randomness — this is validator-local and off the
/// consensus/settlement path (§7: "encryption and share production are client-side").
///
/// # Errors
///
/// - [`ShieldError::InvalidKey`] — `dk_i == 0` (no inverse; unreachable for an
///   honestly generated keypair but validated defensively).
/// - [`ShieldError::Serialization`] — FS transcript serialization failed.
pub fn decryption_share(
    dk_i: &Fr,
    validator_index: u16,
    ct: &Ciphertext,
) -> Result<DecryptionShare, ShieldError> {
    // Guard: dk_i must be invertible (no valid share exists for a zero key).
    if dk_i.is_zero() {
        return Err(ShieldError::InvalidKey);
    }
    // Safe unwrap: is_zero() guard ensures inverse exists in 𝔽_r.
    let dk_inv = dk_i.inverse().expect("non-zero field element is invertible");

    // D_i = [dk_i^{-1}] U  (§2.3 "fast path": one 𝔾₁ scalar-mult, no pairing).
    let d: G1Affine = (G1Projective::from(ct.u) * dk_inv).into_affine();
    // cm_i = [dk_i^{-1}] G  (§3.1 commitment; needed for pairing tie in verify_share).
    // G1Projective has no generator() in arkworks 0.4 — AffineRepr carries it.
    let g1_gen = G1Affine::generator();
    let cm: G1Affine = (G1Projective::from(g1_gen) * dk_inv).into_affine();

    // Prover-local blinding — OS randomness is OK here (off consensus path, §7).
    let blinding = Fr::rand(&mut ark_std::rand::thread_rng());

    // Two PokDiscreteLogProtocol instances sharing the SAME witness and blinding.
    // Same (witness, blinding) across both bases = DLEQ: the response s = b + c·dk_inv
    // is identical for both, proving log_U(D_i) == log_G(cm_i) == dk_inv.
    let p_u = PokDiscreteLogProtocol::<G1Affine>::init(dk_inv, blinding, &ct.u);
    let p_g = PokDiscreteLogProtocol::<G1Affine>::init(dk_inv, blinding, &G1Affine::generator());

    // Read commitment points BEFORE gen_proof moves the protocol instances.
    let t_u = p_u.t;
    let t_g = p_g.t;

    // Fiat–Shamir challenge over the canonical transcript (deterministic, §7).
    let c = dleq_challenge(ct.u, d, t_u, G1Affine::generator(), cm, t_g)?;

    // Generate proofs — both yield response s = blinding + c * dk_inv (identical).
    let proof_u = p_u.gen_proof(&c);
    let proof_g = p_g.gen_proof(&c);

    // Invariant: same (witness, blinding, challenge) ⟹ same response on both bases.
    debug_assert_eq!(
        proof_u.response, proof_g.response,
        "DLEQ invariant: shared blinding + witness ⟹ identical responses on both bases"
    );

    Ok(DecryptionShare {
        validator_index,
        d,
        cm,
        proof: ShareProof { t_u, t_g, response: proof_u.response },
    })
}

/// Verify a single decryption share against the ciphertext and published epoch key (§2.4, §3.2).
///
/// Four checks, ordered cheapest-first:
/// 1. **DLEQ on `U`**: `[s]U == t_U + [c]D_i` — proves `log_U(D_i) == dk_inv`
/// 2. **DLEQ on `G`**: `[s]G == t_G + [c]cm_i` — proves `log_G(cm_i) == dk_inv`
/// 3. **Pairing tie**: `e(cm_i, ek_i) == e(G, H)` — binds `dk_inv` to published `ek_i`
/// 4. **Correctness**: `e(D_i, ek_i) == e(U, H)` — confirms share matches ciphertext (§2.4)
///
/// Together, these prevent a malicious validator from submitting a share that passes
/// the bare pairing check (check 4) but corresponds to a wrong `dk_i`: checks 1–3
/// cryptographically bind `D_i` to the same `dk_inv` that appears in `ek_i`.
///
/// # Errors
///
/// - [`ShieldError::InvalidProof`] — one of the DLEQ Schnorr checks fails.
/// - [`ShieldError::InvalidShare`] — a pairing check fails.
/// - [`ShieldError::Serialization`] — FS transcript serialization failed.
pub fn verify_share(
    ek_i: &G2Affine,
    ct: &Ciphertext,
    share: &DecryptionShare,
) -> Result<(), ShieldError> {
    // Recompute Fiat–Shamir challenge identically to prove path (§7 determinism).
    let c = dleq_challenge(
        ct.u,
        share.d,
        share.proof.t_u,
        G1Affine::generator(),
        share.cm,
        share.proof.t_g,
    )?;

    // 1. DLEQ on base U: [s]U == t_U + [c]D_i
    let pok_u = PokDiscreteLog::<G1Affine> { t: share.proof.t_u, response: share.proof.response };
    if !pok_u.verify(&share.d, &ct.u, &c) {
        return Err(ShieldError::InvalidProof);
    }

    // 2. DLEQ on base G: [s]G == t_G + [c]cm_i
    let pok_g = PokDiscreteLog::<G1Affine> { t: share.proof.t_g, response: share.proof.response };
    if !pok_g.verify(&share.cm, &G1Affine::generator(), &c) {
        return Err(ShieldError::InvalidProof);
    }

    // 3. Pairing tie — binds cm_i to ek_i (§3.1):
    //    e(cm_i, ek_i) == e(G, H)  ⟺  [dk_inv]·[dk] = 1 in 𝔽_r  ✓
    //    Implemented as single pairing comparison (matches validate pattern in tpke).
    let h = G2Affine::generator();
    let g = G1Affine::generator();
    if Bls12_381::pairing(share.cm, *ek_i) != Bls12_381::pairing(g, h) {
        return Err(ShieldError::InvalidShare);
    }

    // 4. Correctness pairing (§2.4): e(D_i, ek_i) == e(U, H)
    //    Correctness: e([dk_inv]U, [dk]H) = e(U, H) · (dk_inv·dk = 1) = e(U, H). ✓
    if Bls12_381::pairing(share.d, *ek_i) != Bls12_381::pairing(ct.u, h) {
        return Err(ShieldError::InvalidShare);
    }

    Ok(())
}

/// Batch-verify decryption shares across multiple validators and ciphertexts (§2.4).
///
/// Uses the Fiat–Shamir multi-pairing negation trick (same structure as `validate_batch`
/// in `tpke`). Cheaper than `k` calls to `verify_share`: one multi-pairing replaces
/// `4k` individual pairings. Fiat–Shamir challenges `α_k` prevent two invalid shares
/// from cancelling each other.
///
/// Equation (§2.4, correctness check only — individual DLEQ proofs are NOT batch-checked
/// here; callers must verify proofs individually before calling this for the batch pairing):
/// ```text
/// ∏_i  e( Σ_j [α_{i,j}] D_{i,j},  ek_i )  ==  e( Σ_{i,j} [α_{i,j}] U_j,  H )
/// ```
/// Implemented as multi-pairing with negation: `multi_pairing([MSM_i(D), -MSM_all(U)], [ek_i, H]) == 0`.
///
/// # Arguments
///
/// * `entries` — `(share, ciphertext, ek_i)` triples in the order that determines
///   challenge derivation (must be stable and agreed across all validators, §7).
///   Shares with the same `validator_index` are grouped on the LHS automatically.
///
/// # Errors
///
/// - [`ShieldError::InvalidShare`] — multi-pairing equation fails (at least one bad share).
/// - [`ShieldError::Serialization`] — transcript serialization failed.
pub fn verify_share_batch(
    entries: &[(DecryptionShare, Ciphertext, G2Affine)],
) -> Result<(), ShieldError> {
    if entries.is_empty() {
        return Ok(());
    }
    if entries.len() == 1 {
        let (share, ct, ek) = &entries[0];
        return verify_share(ek, ct, share);
    }

    // Derive Fiat–Shamir challenges α_k for each entry (counter-mode, §7.5 pattern).
    let alphas = batch_share_challenges(entries)?;

    // Group (D_i, α) by validator_index. BTreeMap: deterministic iteration order (§7.1).
    // ek_i is also indexed by validator_index — first-seen ek wins (protocol invariant:
    // same validator_index always carries the same ek within one epoch).
    let mut per_validator: BTreeMap<u16, Vec<(G1Affine, Fr)>> = BTreeMap::new();
    let mut ek_for: BTreeMap<u16, G2Affine> = BTreeMap::new();
    let mut rhs_acc = G1Projective::zero();

    for ((share, ct, ek), &alpha) in entries.iter().zip(alphas.iter()) {
        per_validator
            .entry(share.validator_index)
            .or_default()
            .push((share.d, alpha));
        ek_for.entry(share.validator_index).or_insert(*ek);
        // RHS accumulator: Σ_{all} [α_k] U_k
        rhs_acc += G1Projective::from(ct.u) * alpha;
    }

    // Build multi_pairing inputs.
    // LHS: for each validator i → ( Σ_j [α_{i,j}] D_{i,j},  ek_i )
    // RHS (negated): ( -Σ_{all} [α_k] U_k,  H )
    let mut g1_inputs: Vec<G1Affine> = Vec::with_capacity(per_validator.len() + 1);
    let mut g2_inputs: Vec<G2Affine> = Vec::with_capacity(per_validator.len() + 1);

    for (vidx, d_alphas) in &per_validator {
        let ek = ek_for
            .get(vidx)
            .ok_or_else(|| ShieldError::Serialization("internal: missing ek for validator".into()))?;

        // Σ_j [α_{i,j}] D_{i,j} — accumulated via scalar-mult (correct for all batch sizes)
        let msm_d: G1Affine = d_alphas
            .iter()
            .fold(G1Projective::zero(), |acc, &(d, alpha)| {
                acc + G1Projective::from(d) * alpha
            })
            .into_affine();

        g1_inputs.push(msm_d);
        g2_inputs.push(*ek);
    }

    // Negated RHS: -Σ [α] U, paired with H.
    g1_inputs.push((-rhs_acc).into_affine());
    g2_inputs.push(G2Affine::generator());

    // Multi-pairing: product == identity (PairingOutput::zero()) iff all valid.
    let result = Bls12_381::multi_pairing(g1_inputs, g2_inputs);
    if result.is_zero() {
        Ok(())
    } else {
        Err(ShieldError::InvalidShare)
    }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Compute the Fiat–Shamir challenge `c ∈ 𝔽_r` for one share's DLEQ proof (§3.2).
///
/// Uses `PokDiscreteLogProtocol::compute_challenge_contribution` (the static form of
/// `challenge_contribution`) to build the transcript identically in both the prover
/// and verifier. Each call appends `base ‖ y ‖ t` (all compressed G1Affine, 48 B each).
///
/// **Frozen transcript** (hard fork to change, §7):
/// `(U ‖ D_i ‖ t_U)  ‖  (G ‖ cm_i ‖ t_G)` = 288 bytes.
///
/// Then `c = compute_random_oracle_challenge::<Fr, Blake2b512>(transcript)`.
fn dleq_challenge(
    base_u: G1Affine,
    y_u: G1Affine,
    t_u: G1Affine,
    base_g: G1Affine,
    y_g: G1Affine,
    t_g: G1Affine,
) -> Result<Fr, ShieldError> {
    let mut transcript: Vec<u8> = Vec::with_capacity(288);
    PokDiscreteLogProtocol::<G1Affine>::compute_challenge_contribution(
        &base_u, &y_u, &t_u, &mut transcript,
    )
    .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
    PokDiscreteLogProtocol::<G1Affine>::compute_challenge_contribution(
        &base_g, &y_g, &t_g, &mut transcript,
    )
    .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
    Ok(compute_random_oracle_challenge::<Fr, Blake2b512>(&transcript))
}

/// Derive Fiat–Shamir challenges `α_k ∈ 𝔽_r` for the share batch (§2.4, §7.5).
///
/// Transcript: all `(D_i ‖ U_j ‖ ek_i)` in entry order (compressed), then counter-mode
/// Blake2b512. Same ordered batch → same challenges on every node (deterministic, §7).
fn batch_share_challenges(
    entries: &[(DecryptionShare, Ciphertext, G2Affine)],
) -> Result<Vec<Fr>, ShieldError> {
    let mut transcript: Vec<u8> = Vec::new();
    for (share, ct, ek) in entries {
        share
            .d
            .serialize_compressed(&mut transcript)
            .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
        ct.u
            .serialize_compressed(&mut transcript)
            .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
        ek.serialize_compressed(&mut transcript)
            .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
    }
    // Counter-mode Blake2b512 expansion (§7.5) — canonical implementation in fs.
    Ok(crate::shield::fs::expand_challenges(&transcript, entries.len()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
