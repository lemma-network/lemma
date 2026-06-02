//! # Shield PSS — Per-epoch Proactive Secret Sharing (S7)
//!
//! Implements per-epoch zero-secret resharing (15-SHIELD_SPEC §5).
//! At each epoch boundary the **same** epoch key `Y` is re-issued to the
//! (possibly re-weighted) new committee, refreshing all share values to
//! defeat a mobile adversary — without ever changing `Y`.
//!
//! ## Construction (§5.1, Herzberg et al.)
//!
//! ```text
//! 1. Each old-committee dealer calls `deal_reshare`: PVSS-DKG with a_0 = 0.
//!        F_0 = [0]G = 𝒪  and  û₂ = [0]û₁ = 𝒪  (by construction)
//!    Aggregate constant term = 0 → Y unchanged.
//! 2. `verify_reshare` asserts F_0 == 𝒪 ∧ û₂ == 𝒪, then runs §4.3 steps 2–4
//!    (batched share pairing) against the **new** committee.
//! 3. `combine_shares(z_old, z_zero) → z_new`:
//!        Z_new[ω] = Z_old[ω] + Z_zero[ω]  (𝔾₂ element-wise, §5.1 step 3)
//!    Key-invariance: Σ_{ω∈Ω} λ_ω Z_new[ω] = [f_old(0)]H + [0]H = [a_0]H.
//!    TPKE combine with z_new still reconstructs Y = [a_0]G unchanged. ✓
//! ```
//!
//! ## DRY note (AGENTS §2.1)
//!
//! Phase 4 of `verify_reshare` reuses `pvss::verify_share_pairing` — the
//! shared §4.3 step-2–4 implementation. No duplication of the Horner
//! expansion or batched multi-pairing logic.
//!
//! ## Clean-room provenance (DB-11)
//!
//! Derived from the §4 aggregatable PVSS with `a_0 = 0` enforced, and
//! **Herzberg et al., "Proactive Secret Sharing" (1995)**. The Ferveo book's
//! `keyrefresh.md` is a one-paragraph stub; this derivation is independent
//! (15-SHIELD_SPEC §5.3). The GPL-3.0 ferveo codebase was **never read or
//! referenced** (AGENTS §9.3).
//!
//! ## Crate-dependency note (DB-12)
//!
//! All functions in this module are **pure crypto primitives** — no async,
//! no I/O, no cross-crate calls. The resharing trigger (advance_epoch step-8,
//! post-settlement `ValidatorSet(N+1)` consumption, share-withholding
//! feedback to slashing) is orchestrated by the `lemma-node` layer.

use std::collections::BTreeMap;

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Zero;
use ark_std::UniformRand;
use secret_sharing_and_dkg::common::ShareId;

use crate::shield::{
    committee::ShieldCommittee,
    pvss::{eval_poly, verify_share_pairing, PvssTranscript},
    ShieldError,
};

// ── deal_reshare ──────────────────────────────────────────────────────────────

/// Deal a zero-secret PVSS transcript for epoch resharing (15-SHIELD_SPEC §5.1 step 1).
///
/// Identical to [`pvss::deal`] except the constant term is **forced to zero**:
/// - `coeffs[0] = 0`  →  `F_0 = [0]G = 𝒪`  and  `û₂ = [0]û₁ = 𝒪`
///
/// When N ≥ 1/3·W dealers aggregate their zero-transcripts, the summed constant
/// term remains 0 → epoch key `Y` unchanged (Herzberg et al., §5.1 step 2).
///
/// Shares are encrypted to the **new** committee's epoch keys `ek_i^{new}`,
/// enabling re-weighting (new validator set / new stake weights, §5.1 step 4).
///
/// ## Arguments
///
/// * `tau` — reshare epoch label, e.g. `epoch_N_bytes ‖ epoch_N+1_bytes ‖ DST_PVSS_RESHARE`.
///   Prevents cross-epoch replay; must match `expected_tau` in [`verify_reshare`].
/// * `new_committee` — post-settlement `ValidatorSet(N+1)` committee (§5.3 Aptos guard:
///   always use the *post-settlement* set, never the pre-settlement set).
/// * `eks_new` — new committee validator-index → `ek_i^{new} = [dk_i^{new}]H ∈ 𝔾₂`.
///   Index = 0-based position in `new_committee.iter()` (canonical address order).
/// * `rng` — dealer-local CSPRNG (off consensus path, same rule as `pvss::deal`).
///
/// ## Errors
///
/// - [`ShieldError::Serialization`] — `eks_new` missing an entry for a validator index.
pub fn deal_reshare(
    tau: Vec<u8>,
    new_committee: &ShieldCommittee,
    eks_new: &BTreeMap<u16, G2Affine>,
    rng: &mut impl ark_std::rand::RngCore,
) -> Result<PvssTranscript, ShieldError> {
    let t = new_committee.params().t as usize;
    let g = G1Affine::generator();

    // ── Zero-secret polynomial: a_0 = 0, a_1..a_t random ────────────────────
    // Setting coeffs[0] = 0 forces the constant term to zero.
    // All higher-degree coefficients are drawn from the CSPRNG (standard PVSS).
    let mut coeffs: Vec<Fr> = (0..=t).map(|_| Fr::rand(rng)).collect();
    coeffs[0] = Fr::zero(); // enforced zero constant term (§5.1 step 1)

    // F_j = [a_j]G ∈ 𝔾₁; F_0 = [0]G = 𝒪 by construction.
    let coeff_comms: Vec<G1Affine> = coeffs
        .iter()
        .map(|a| (G1Projective::from(g) * a).into_affine())
        .collect();

    // û₂ = [a_0]û₁ = [0]û₁ = 𝒪; identity by construction (no hash-to-curve needed).
    let tag = G2Affine::zero();

    // enc_shares to the NEW committee (re-weighting, §5.1 step 4).
    // Iterate in canonical BTreeMap address order (deterministic, §7.1).
    let mut enc_shares: BTreeMap<ShareId, G2Affine> = BTreeMap::new();
    for (validator_idx, (_, share_ids)) in new_committee.iter().enumerate() {
        let validator_idx = validator_idx as u16;
        let ek_i = eks_new.get(&validator_idx).ok_or_else(|| {
            ShieldError::Serialization(format!(
                "deal_reshare: missing epoch key for validator_index={validator_idx}"
            ))
        })?;
        for &omega in share_ids {
            let f_omega = eval_poly(&coeffs, omega);
            let y_hat: G2Affine = (G2Projective::from(*ek_i) * f_omega).into_affine();
            enc_shares.insert(omega, y_hat);
        }
    }

    Ok(PvssTranscript { tau, coeff_comms, tag, enc_shares })
}

// ── verify_reshare ────────────────────────────────────────────────────────────

/// Verify a zero-secret resharing transcript (15-SHIELD_SPEC §5.4).
///
/// ## Phases
///
/// 1. **Tau check** — `transcript.tau == expected_tau` (replay guard, §4.1).
/// 2. **Zero-constant assertion** — `F_0 == 𝒪 ∧ tag == 𝒪`.
///    A non-identity `F_0` means the dealer tried to shift `Y` (an attack
///    by a Byzantine validator trying to embed a non-zero contribution into
///    the key). Rejected as [`ShieldError::ReshareAlteredKey`].
///    This replaces the §4.3 constant-term tag pairing used in regular PVSS
///    (where `e(F_0, û₁) == e(G, û₂)` proves the secret is *some* value; here
///    we must prove the secret is *exactly zero*).
/// 3. **Batched share pairing** (§4.3 steps 2–4) against the **new** committee,
///    via [`pvss::verify_share_pairing`] (DRY, AGENTS §2.1).
///
/// ## Errors
///
/// - [`ShieldError::ReshareAlteredKey`] — `F_0 ≠ 𝒪` or `tag ≠ 𝒪`.
/// - [`ShieldError::InvalidTranscript`] — tau mismatch, missing share, or pairing failure.
pub fn verify_reshare(
    expected_tau: &[u8],
    transcript: &PvssTranscript,
    new_committee: &ShieldCommittee,
    eks_new: &BTreeMap<u16, G2Affine>,
) -> Result<(), ShieldError> {
    // Phase 1: tau check (replay guard).
    if transcript.tau != expected_tau {
        return Err(ShieldError::InvalidTranscript);
    }

    // Phase 2: zero-constant assertion (§5.4 — replaces tag pairing for resharing).
    // Non-identity F_0 means the dealer is trying to change Y → reject unconditionally.
    let f0 = transcript.coeff_comms.first().ok_or(ShieldError::InvalidTranscript)?;
    if !f0.is_zero() {
        return Err(ShieldError::ReshareAlteredKey);
    }
    if !transcript.tag.is_zero() {
        return Err(ShieldError::ReshareAlteredKey);
    }

    // Phase 3: §4.3 steps 2–4 (Horner + batched multi-pairing) against new committee.
    verify_share_pairing(transcript, new_committee, eks_new)
}

// ── combine_shares ────────────────────────────────────────────────────────────

// ── Safety contract ───────────────────────────────────────────────────────────
//
// SAFETY (for callers aggregating reshare transcripts):
// Each PvssTranscript passed to `pvss::aggregate` MUST have been individually
// verified by `verify_reshare` BEFORE aggregation. The aggregate itself may be
// re-verified as a belt-and-suspenders check, but per-input verification is the
// primary soundness guard (see GJMMST §4.4 and 15-SHIELD_SPEC §5.4).
// This is the same contract as `pvss::aggregate` + `dkg::run_dkg` for normal DKG.
// The `run_reshare` driver (in the lemma-node orchestration layer, DB-12) must
// enforce this invariant.

/// Add zero-secret resharing shares to old epoch shares (15-SHIELD_SPEC §5.1 step 3).
///
/// ```text
/// Z_new[ω] = Z_old[ω] + Z_zero[ω]   (𝔾₂ element-wise group addition)
/// ```
///
/// ## Key-invariance proof
///
/// ```text
/// Σ_{ω∈Ω} λ_ω Z_new[ω]
///   = Σ λ_ω (Z_old[ω] + Z_zero[ω])
///   = Σ λ_ω Z_old[ω] + Σ λ_ω Z_zero[ω]
///   = [f_old(0)] H  +  [0] H        (zero-polynomial sums to 0 at x=0)
///   = [a_0] H                        (old epoch secret, unchanged)  ✓
/// ```
///
/// TPKE [`combine`][crate::shield::tpke::combine] with the new shares still
/// reconstructs `Y = [a_0]G`, so all previously encrypted ciphertexts remain
/// decryptable under the same epoch key.
///
/// ## Arguments
///
/// * `z_old` — old epoch shares `Z_old[ω] = [dk_i^{old,-1}] Ŷ^{old}[ω]`
///   (from [`pvss::recover_share`] applied to the S6 aggregate transcript).
/// * `z_zero` — resharing zero-shares `Z_zero[ω] = [dk_i^{new,-1}] Ŷ^{zero}[ω]`
///   (from [`pvss::recover_share`] applied to the S7 zero-aggregate transcript).
///
/// Both maps must have the **same ShareId keyset** (same committee W and assignment).
///
/// ## Errors
///
/// [`ShieldError::InvalidTranscript`] — `z_old` and `z_zero` have different ShareId keysets.
pub fn combine_shares(
    z_old: &BTreeMap<ShareId, G2Affine>,
    z_zero: &BTreeMap<ShareId, G2Affine>,
) -> Result<BTreeMap<ShareId, G2Affine>, ShieldError> {
    // Guard: keysets must be identical (same committee, same share IDs).
    if z_old.len() != z_zero.len() || z_old.keys().ne(z_zero.keys()) {
        return Err(ShieldError::InvalidTranscript);
    }

    z_old
        .iter()
        .map(|(&omega, z_o)| {
            let z_z = z_zero.get(&omega).ok_or(ShieldError::InvalidTranscript)?;
            // Z_new[ω] = Z_old[ω] + Z_zero[ω]  (𝔾₂ addition)
            let z_new: G2Affine =
                (G2Projective::from(*z_o) + G2Projective::from(*z_z)).into_affine();
            Ok((omega, z_new))
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
