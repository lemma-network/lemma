//! # PVSS — Publicly Verifiable Secret Sharing (S5: deal + verify)
//!
//! Implements the **modified-SCRAPE PVSS with GJMMST aggregation** over BLS12-381
//! (15-SHIELD_SPEC §4). This module covers:
//!
//! | Sub-step | Functions |
//! |----------|-----------|
//! | S5 ✅ | [`deal`], [`verify`], [`PvssTranscript`], [`u1_generator`] |
//! | S6 ✅ | [`aggregate`], [`recover_share`] |
//! | S7 (helper) | `verify_share_pairing` — shared §4.3 step-2–4 impl (DRY for PSS) |
//!
//! ## Clean-room provenance (DB-11)
//!
//! Derived from the GJMMST Aggregatable-DKG paper (NOT the GPL-3.0 ferveo code —
//! that was never read, AGENTS §9.3). Uses `ark_poly::Radix2EvaluationDomain`
//! for FFT commitment expansion and the SCRAPE-style batched pairing check from
//! §4.3. The `û₁/û₂` correctness-tag form is frozen per FZ-4.
//!
//! ## Key types
//!
//! - `eks: &BTreeMap<u16, G2Affine>` — validator-index → epoch key `ek_i = [dk_i]H`.
//!   Passed by the caller (node layer owns per-epoch key storage, DB-12).
//! - [`PvssTranscript`] — the single-dealer transcript produced by `deal` and
//!   verified by `verify`. Additive aggregation (S6) works on `PvssTranscript`s.
//!
//! ## Determinism (§7)
//!
//! `verify` is fully deterministic: `BTreeMap` iteration, `BTreeSet` for Fiat–Shamir
//! transcript ordering, no floats, no `SystemTime`, no `HashMap`.
//! `deal` uses CSPRNG (off-consensus, dealer-local, same rule as `encrypt`).

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::UniformRand;
use secret_sharing_and_dkg::common::ShareId;
use std::collections::{BTreeMap, BTreeSet};

use crate::shield::{committee::ShieldCommittee, params::DST_PVSS_U1, ShieldError};

// ── Third independent generator û₁ ───────────────────────────────────────────

/// Derive the independent 𝔾₂ generator `û₁` via RFC 9380 hash-to-curve.
///
/// `û₁` is used **only** for the PVSS correctness tag (§4.1, FZ-4):
/// `û₂ = [a_0]û₁` binds the dealer's constant term to a point independent of
/// the standard `H = 𝔾₂::generator()`, preventing cross-protocol confusion.
///
/// DST: [`DST_PVSS_U1`] — frozen. Changing it is a hard fork.
/// The empty-byte message is fixed (the DST carries all entropy needed to
/// produce a distinct, pseudo-random generator with no hidden structure).
///
/// # Errors
///
/// [`ShieldError::HashToCurve`] — RFC 9380 map failed (practically unreachable).
pub fn u1_generator() -> Result<G2Affine, ShieldError> {
    // DST_PVSS_U1 is frozen (FZ-4) — changing it is a hard fork.
    // Empty message: the DST carries all entropy needed for an independent generator.
    crate::shield::fs::hash_to_g2_with_dst(DST_PVSS_U1, &[])
}

// ── PvssTranscript ────────────────────────────────────────────────────────────

/// Single-dealer PVSS transcript (15-SHIELD_SPEC §4.1).
///
/// Produced by [`deal`] and verified by [`verify`]. Multiple transcripts are
/// aggregated element-wise in S6 (`aggregate`) to form the epoch's group secret.
///
/// ## Wire contents
///
/// - `tau` — epoch/instance domain-separation label (prevents cross-epoch replay, §4.1).
/// - `coeff_comms` — `t+1` polynomial commitment points `F_0…F_t = [a_j]G ∈ 𝔾₁`.
/// - `tag` — `û₂ = [a_0]û₁ ∈ 𝔾₂` — correctness tag binding `a_0` to `û₁` (FZ-4).
/// - `enc_shares` — `(ShareId → Ŷ_{i,ω})`: each `Ŷ = [f(ω)]·ek_i ∈ 𝔾₂`.
///   `BTreeMap` guarantees deterministic ordering across all nodes (§7.1).
#[derive(Clone, Debug)]
pub struct PvssTranscript {
    /// Epoch/instance label (tau) — prevents cross-epoch transcript replay (§4.1).
    pub tau: Vec<u8>,
    /// `F_0…F_t = [a_j]G ∈ 𝔾₁` — `t+1` polynomial coefficient commitments.
    pub coeff_comms: Vec<G1Affine>,
    /// `û₂ = [a_0]û₁ ∈ 𝔾₂` — correctness tag (FZ-4 frozen form).
    pub tag: G2Affine,
    /// `Ŷ_{i,ω} = [f(ω)]·ek_i ∈ 𝔾₂` per share-ID (deterministic `BTreeMap`, §7.1).
    pub enc_shares: BTreeMap<ShareId, G2Affine>,
}

// ── deal ──────────────────────────────────────────────────────────────────────

/// Produce a single-dealer PVSS transcript (15-SHIELD_SPEC §4.1).
///
/// Steps:
/// 1. Sample random degree-`t` polynomial `f(x) = Σ a_j x^j` (dealer-local CSPRNG).
/// 2. Coefficient commitments `F_j = [a_j]G ∈ 𝔾₁`.
/// 3. Encrypted shares `Ŷ_{i,ω} = [f(ω)]·ek_i ∈ 𝔾₂` for each validator `i` and
///    each `ω ∈ Ω_i`.
/// 4. Correctness tag `û₂ = [a_0]û₁ ∈ 𝔾₂`.
///
/// `tau` is a caller-supplied domain-separation label (e.g. `epoch ‖ "pvss-deal"`
/// serialised to bytes). It is stored in the transcript and checked by [`verify`].
///
/// # Arguments
///
/// * `tau` — epoch label (prevents replay; must be unique per dealer per epoch).
/// * `committee` — Ω_i partition; provides `t` (secrecy threshold) and share IDs.
/// * `eks` — `validator_index → ek_i = [dk_i]H ∈ 𝔾₂` epoch public keys.
///   Must contain an entry for every validator index present in `committee`.
///
/// # Errors
///
/// - [`ShieldError::HashToCurve`] — `û₁` derivation failed (unreachable).
/// - [`ShieldError::Serialization`] — point not serializable (unreachable for valid points).
pub fn deal(
    tau: Vec<u8>,
    committee: &ShieldCommittee,
    eks: &BTreeMap<u16, G2Affine>,
    rng: &mut impl ark_std::rand::RngCore,
) -> Result<PvssTranscript, ShieldError> {
    let t = committee.params().t as usize; // secrecy threshold; t+1 coefficients
    let g = G1Affine::generator();
    let u1 = u1_generator()?;

    // ── 1. Sample random degree-t polynomial coefficients ─────────────────────
    // Dealer-local CSPRNG — off consensus path (same rule as encrypt/decryption_share).
    let coeffs: Vec<Fr> = (0..=t).map(|_| Fr::rand(rng)).collect();

    // ── 2. Coefficient commitments F_j = [a_j]G ∈ 𝔾₁ ─────────────────────────
    let coeff_comms: Vec<G1Affine> = coeffs
        .iter()
        .map(|a| (G1Projective::from(g) * a).into_affine())
        .collect();

    // ── 3. Encrypted shares Ŷ_{i,ω} = [f(ω)]·ek_i ∈ 𝔾₂ ──────────────────────
    // Iterate committee in BTreeMap address order (deterministic, §7.1).
    // validator_index is 0-based position in committee.iter() — must match eks keys.
    let mut enc_shares: BTreeMap<ShareId, G2Affine> = BTreeMap::new();
    for (validator_idx, (_, share_ids)) in committee.iter().enumerate() {
        let validator_idx = validator_idx as u16;
        let ek_i = eks.get(&validator_idx).ok_or_else(|| {
            ShieldError::Serialization(format!(
                "deal: missing epoch key for validator_index={validator_idx}"
            ))
        })?;

        for &omega in share_ids {
            // f(ω) = Σ a_j · ω^j  (integer ω cast to Fr; 1-indexed share IDs §4.0)
            let f_omega = eval_poly(&coeffs, omega);
            // Ŷ_{i,ω} = [f(ω)] · ek_i
            let y_hat: G2Affine = (G2Projective::from(*ek_i) * f_omega).into_affine();
            enc_shares.insert(omega, y_hat);
        }
    }

    // ── 4. Correctness tag û₂ = [a_0] û₁ ─────────────────────────────────────
    let a0 = coeffs[0];
    let tag: G2Affine = (G2Projective::from(u1) * a0).into_affine();

    Ok(PvssTranscript {
        tau,
        coeff_comms,
        tag,
        enc_shares,
    })
}

// ── verify ────────────────────────────────────────────────────────────────────

/// Verify a single-dealer PVSS transcript (15-SHIELD_SPEC §4.3).
///
/// Four-phase check (any failure → [`ShieldError::InvalidTranscript`]):
///
/// 1. **Tau check** — `transcript.tau == expected_tau` (replay guard, §4.1).
/// 2. **Degenerate-point guard** — `F_0`, `û₂`, all `Ŷ_{i,ω}` must be non-zero
///    and in the prime-order subgroup (guard chain lesson from S2).
/// 3. **Constant-term tag** — `e(F_0, û₁) == e(G, û₂)` (proves `[a_0]` consistent).
/// 4. **Batched share pairing** — Fiat–Shamir multi-pairing over all `Ŷ_{i,ω}`:
///    `∏_{i,ω} e(-G,[α]Ŷ_{i,ω}) · e([α]A_{i,ω}, ek_i) == 1`
///    where `A_k = FFT(F_0…F_t)[k]` are the commitment evaluations (§4.3 step 2–4).
///
/// The FFT expands `t+1` commitments to all `W` evaluation points via
/// `Radix2EvaluationDomain::fft` (arkworks). Share IDs are 1-indexed (§4.0),
/// so `A_k` corresponds to `share_id = k+1` in the FFT output.
///
/// # Arguments
///
/// * `expected_tau` — the expected epoch label (caller-supplied; must match `transcript.tau`).
/// * `transcript` — the dealer's transcript to verify.
/// * `committee` — Ω_i partition (same as used in `deal`).
/// * `eks` — `validator_index → ek_i` epoch public keys.
///
/// # Errors
///
/// [`ShieldError::InvalidTranscript`] — any check fails.
/// [`ShieldError::HashToCurve`] — `û₁` derivation failed (unreachable).
/// [`ShieldError::Serialization`] — transcript serialization for FS failed.
pub fn verify(
    expected_tau: &[u8],
    transcript: &PvssTranscript,
    committee: &ShieldCommittee,
    eks: &BTreeMap<u16, G2Affine>,
) -> Result<(), ShieldError> {
    let g = G1Affine::generator();
    let u1 = u1_generator()?;

    // ── Phase 1: Tau check ────────────────────────────────────────────────────
    if transcript.tau != expected_tau {
        return Err(ShieldError::InvalidTranscript);
    }

    // ── Phase 2: Degenerate-point guard ───────────────────────────────────────
    // F_0 and û₂ guarded before the pairing in phase 3.
    let f0 = transcript
        .coeff_comms
        .first()
        .ok_or(ShieldError::InvalidTranscript)?;
    if f0.is_zero() || !f0.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ShieldError::InvalidTranscript);
    }
    if transcript.tag.is_zero() || !transcript.tag.is_in_correct_subgroup_assuming_on_curve() {
        return Err(ShieldError::InvalidTranscript);
    }
    // enc_shares guarded individually during FFT-expand in phase 4 (avoids double scan).

    // ── Phase 3: Constant-term tag — e(F_0, û₁) == e(G, û₂) ─────────────────
    // Proves dealer's F_0 = [a_0]G is consistent with û₂ = [a_0]û₁ (§4.3 step 1).
    let lhs = Bls12_381::pairing(*f0, u1);
    let rhs = Bls12_381::pairing(g, transcript.tag);
    if lhs != rhs {
        return Err(ShieldError::InvalidTranscript);
    }

    // ── Phase 4: Commitment expansion + batched share pairing (§4.3 steps 2–4) ──
    //
    // Delegated to `verify_share_pairing` — the shared helper is also used by
    // `pss::verify_reshare` (AGENTS §2.1 DRY). See its doc for full algorithm
    // notes: integer eval points (DB-15), Horner in 𝔾₁, FS multi-pairing, §7.
    verify_share_pairing(transcript, committee, eks)
}

// ── verify_share_pairing (shared DRY helper) ──────────────────────────────────

/// Execute §4.3 steps 2–4: Horner commitment expansion + batched FS multi-pairing.
///
/// **Called by:**
/// - [`verify`] — regular PVSS (after Phase-1 tau + Phase-2/3 degenerate/tag checks).
/// - [`pss::verify_reshare`] — zero-secret PSS (after tau + zero-assertion checks).
///
/// ## Algorithm
///
/// 1. **Horner expansion**: `A_ω = Σ_j [a_j·ω^j] G ∈ 𝔾₁` for each share ID ω = 1..=W
///    (integer eval points, DB-15 — matches S4 combine's Lagrange basis).
/// 2. **Fiat–Shamir**: `α_{i,ω} ∈ 𝔽_r` via counter-mode Blake2b512 (`fs::expand_challenges`).
/// 3. **Multi-pairing**: `∏ e(-G, [α]Ŷ) · e([α]A, ek_i) == 1` (negation trick, §7.5).
///
/// ## Determinism (§7)
///
/// BTreeMap iteration → canonical address order; no floats, HashMap, or SystemTime.
/// Byte-identical on every honest node for the same `(transcript, committee, eks)`.
pub(crate) fn verify_share_pairing(
    transcript: &PvssTranscript,
    committee: &ShieldCommittee,
    eks: &BTreeMap<u16, G2Affine>,
) -> Result<(), ShieldError> {
    let g = G1Affine::generator();
    let w = committee.total_weight() as usize;

    // Step 1: Horner commitment expansion — A_ω = [f(ω)]G for ω = 1..=W.
    // Integer share IDs (DB-15); NOT FFT roots-of-unity (see verify for rationale).
    let a_map: BTreeMap<ShareId, G1Affine> = (0..w)
        .map(|k| {
            let omega = (k + 1) as u16; // 1-indexed share ID; safe: k < W ≤ u16::MAX
            let x = Fr::from(u64::from(omega));
            let a_k: G1Affine = transcript
                .coeff_comms
                .iter()
                .rev()
                .fold(G1Projective::zero(), |acc, &fj| {
                    acc * x + G1Projective::from(fj)
                })
                .into_affine();
            (omega, a_k)
        })
        .collect();

    // Step 2: Fiat–Shamir challenges (deterministic, §7.5).
    let alphas = pvss_fiat_shamir_challenges(transcript, committee, eks, &a_map)?;

    // Step 3: Batched multi-pairing — ∏ e(-G, [α]Ŷ) · e([α]A, ek_i) == 1.
    let mut neg_yhat_acc = G2Projective::zero();
    let mut per_val_a: BTreeMap<u16, G1Projective> = BTreeMap::new();
    let mut alpha_iter = alphas.into_iter();

    for (validator_idx, (_, share_ids)) in committee.iter().enumerate() {
        let validator_idx = validator_idx as u16;
        let ek_i = eks
            .get(&validator_idx)
            .ok_or(ShieldError::InvalidTranscript)?;
        if ek_i.is_zero() || !ek_i.is_in_correct_subgroup_assuming_on_curve() {
            return Err(ShieldError::InvalidTranscript);
        }
        for &omega in share_ids {
            let alpha = alpha_iter.next().ok_or(ShieldError::InvalidTranscript)?;
            let y_hat = transcript
                .enc_shares
                .get(&omega)
                .ok_or(ShieldError::InvalidTranscript)?;
            if y_hat.is_zero() || !y_hat.is_in_correct_subgroup_assuming_on_curve() {
                return Err(ShieldError::InvalidTranscript);
            }
            let a_k = a_map.get(&omega).ok_or(ShieldError::InvalidTranscript)?;
            neg_yhat_acc += G2Projective::from(*y_hat) * alpha;
            *per_val_a
                .entry(validator_idx)
                .or_insert(G1Projective::zero()) += G1Projective::from(*a_k) * alpha;
        }
    }

    let mut g1_inputs: Vec<G1Affine> = Vec::with_capacity(per_val_a.len() + 1);
    let mut g2_inputs: Vec<G2Affine> = Vec::with_capacity(per_val_a.len() + 1);
    for (vidx, a_acc) in &per_val_a {
        let ek_i = eks.get(vidx).ok_or(ShieldError::InvalidTranscript)?;
        g1_inputs.push(a_acc.into_affine());
        g2_inputs.push(*ek_i);
    }
    g1_inputs.push(-g);
    g2_inputs.push(neg_yhat_acc.into_affine());

    let result = Bls12_381::multi_pairing(g1_inputs, g2_inputs);
    if result.is_zero() {
        Ok(())
    } else {
        Err(ShieldError::InvalidTranscript)
    }
}

// ── aggregate (S6) ────────────────────────────────────────────────────────────

/// Aggregate `N` individually-verified single-dealer PVSS transcripts into one
/// (15-SHIELD_SPEC §4.4, GJMMST Aggregatable-DKG soundness).
///
/// Element-wise group addition in 𝔾₁ and 𝔾₂:
///
/// ```text
/// F_j      = Σ_{n=1}^{N} F_j^{(n)}        (𝔾₁, t+1 elements)
/// û₂       = Σ_{n=1}^{N} û₂^{(n)}          (𝔾₂)
/// Ŷ_{i,ω}  = Σ_{n=1}^{N} Ŷ_{i,ω}^{(n)}   (𝔾₂, per ShareId)
/// ```
///
/// The result is a valid PVSS transcript for the **summed polynomial** `f = Σ f^{(n)}`.
/// No single dealer knows the group secret `a_0 = Σ a_0^{(n)}`.
/// The epoch public key `Y = F_0 = [Σ a_0^{(n)}] G ∈ 𝔾₁`.
///
/// **Soundness (GJMMST)**: each summand must be verified via `verify` (§4.3)
/// **before** inclusion; the driver (`dkg.rs`) enforces this. A dealer cannot
/// contribute an inconsistent share without failing the per-transcript check
/// (which the aggregate's §4.3 re-check would also catch — belt and suspenders).
///
/// Accumulation is done in projective coordinates (no intermediate `into_affine`
/// conversions — AGENTS §16.1) and converted to affine once at the end.
///
/// # Errors
///
/// [`ShieldError::InvalidTranscript`] — any of:
/// - `transcripts` is empty.
/// - Any transcript has a different `tau` than the first.
/// - Any transcript has a different `coeff_comms.len()` (degree mismatch).
/// - Any transcript has a different `enc_shares` ShareId keyset.
pub fn aggregate(transcripts: &[PvssTranscript]) -> Result<PvssTranscript, ShieldError> {
    // Must have at least one transcript.
    let first = transcripts.first().ok_or(ShieldError::InvalidTranscript)?;
    let t_plus_1 = first.coeff_comms.len();
    let expected_keys: BTreeSet<ShareId> = first.enc_shares.keys().copied().collect();

    // Initialise projective accumulators from the first transcript.
    let mut agg_comms: Vec<G1Projective> = first
        .coeff_comms
        .iter()
        .map(|p| G1Projective::from(*p))
        .collect();
    let mut agg_tag = G2Projective::from(first.tag);
    let mut agg_shares: BTreeMap<ShareId, G2Projective> = first
        .enc_shares
        .iter()
        .map(|(&id, p)| (id, G2Projective::from(*p)))
        .collect();

    // Accumulate remaining transcripts element-wise.
    for tr in &transcripts[1..] {
        // Structural guards — all inputs must be for the same committee/epoch.
        if tr.tau != first.tau {
            return Err(ShieldError::InvalidTranscript);
        }
        if tr.coeff_comms.len() != t_plus_1 {
            return Err(ShieldError::InvalidTranscript);
        }
        let keys: BTreeSet<ShareId> = tr.enc_shares.keys().copied().collect();
        if keys != expected_keys {
            return Err(ShieldError::InvalidTranscript);
        }

        // F_j += F_j^{(n)}  (𝔾₁)
        for (j, p) in tr.coeff_comms.iter().enumerate() {
            agg_comms[j] += G1Projective::from(*p);
        }
        // û₂ += û₂^{(n)}  (𝔾₂)
        agg_tag += G2Projective::from(tr.tag);
        // Ŷ_{i,ω} += Ŷ_{i,ω}^{(n)}  (𝔾₂)
        for (&id, p) in &tr.enc_shares {
            // keyset equality verified above — every id is guaranteed present.
            *agg_shares.get_mut(&id).expect("keyset verified") += G2Projective::from(*p);
        }
    }

    // Convert projective → affine once (AGENTS §16.1).
    Ok(PvssTranscript {
        tau: first.tau.clone(),
        coeff_comms: agg_comms.iter().map(|p| p.into_affine()).collect(),
        tag: agg_tag.into_affine(),
        enc_shares: agg_shares
            .into_iter()
            .map(|(id, p)| (id, p.into_affine()))
            .collect(),
    })
}

// ── recover_share (S6) ────────────────────────────────────────────────────────

/// Recover this validator's TPKE group-element key shares from the aggregated
/// PVSS transcript (15-SHIELD_SPEC §4.5).
///
/// ```text
/// Z_{i,ω} = [dk_i^{-1}] Ŷ_{i,ω} ∈ 𝔾₂
/// ```
///
/// Undoes the `ek_i = [dk_i]H` encryption on each share, revealing the
/// polynomial evaluation `[f(ω)]H` that TPKE `combine` requires (§2.5).
/// The output `Z` values are the `z_shares` field of [`crate::shield::tpke::CombineShare`].
///
/// **Settlement-path safety (§6)**: never panics. `dk_i = 0` is explicitly
/// caught and returned as [`ShieldError::InvalidKey`] before any division.
///
/// # Arguments
///
/// * `dk_i` — this validator's private epoch decryption key (must be non-zero).
/// * `transcript` — the aggregated PVSS transcript (call `aggregate` first).
/// * `share_ids` — the ShareIds assigned to this validator (`committee.share_ids_of(&addr)`).
///
/// # Errors
///
/// - [`ShieldError::InvalidKey`] — `dk_i == 0` (not invertible in 𝔽_r).
/// - [`ShieldError::InvalidTranscript`] — a required `ShareId` is absent from the transcript.
pub fn recover_share(
    dk_i: &Fr,
    transcript: &PvssTranscript,
    share_ids: &[ShareId],
) -> Result<BTreeMap<ShareId, G2Affine>, ShieldError> {
    // Settlement-path safety: zero key → explicit error, never panic (§6, §7.2).
    if dk_i.is_zero() {
        return Err(ShieldError::InvalidKey);
    }
    // `inverse()` returns `None` only if dk_i == 0, which we guarded above.
    let dk_inv = dk_i.inverse().expect("non-zero checked");

    share_ids
        .iter()
        .map(|&omega| {
            let y_hat = transcript
                .enc_shares
                .get(&omega)
                .ok_or(ShieldError::InvalidTranscript)?;
            // Z_{i,ω} = [dk_i^{-1}] Ŷ_{i,ω}
            let z: G2Affine = (G2Projective::from(*y_hat) * dk_inv).into_affine();
            Ok((omega, z))
        })
        .collect()
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Evaluate polynomial `f(x) = Σ a_j x^j` at integer point `x` (cast to `Fr`).
///
/// Uses Horner's method: O(t) multiplications, no allocation.
/// Integer `x` is cast to `Fr::from(x)` (1-indexed share IDs, §4.0).
pub(crate) fn eval_poly(coeffs: &[Fr], x: u16) -> Fr {
    let x_fr = Fr::from(u64::from(x));
    coeffs
        .iter()
        .rev()
        .fold(Fr::zero(), |acc, &a| acc * x_fr + a)
}

/// Derive Fiat–Shamir challenges `α_{i,ω} ∈ 𝔽_r` for the batched §4.3 share check.
///
/// Transcript: for each (validator_idx, share_id) pair in canonical BTreeMap order —
/// `share_id (LE u16) ‖ Ŷ_{i,ω} compressed ‖ A_k compressed ‖ ek_i compressed`.
/// Then counter-mode Blake2b512 (matches the existing `fiat_shamir_challenges` /
/// `batch_share_challenges` pattern in `tpke.rs` / `share.rs` — DRY, §7.5).
///
/// Output order matches the `(validator_idx, share_id)` iteration order of
/// `committee.iter()` — callers must consume with the same iteration order.
///
/// # Errors
///
/// [`ShieldError::Serialization`] — point serialization failed.
fn pvss_fiat_shamir_challenges(
    transcript: &PvssTranscript,
    committee: &ShieldCommittee,
    eks: &BTreeMap<u16, G2Affine>,
    a_map: &BTreeMap<ShareId, G1Affine>,
) -> Result<Vec<Fr>, ShieldError> {
    // Build canonical transcript bytes (all entries, then counter-mode).
    let mut tr: Vec<u8> = Vec::new();
    let mut count = 0usize;

    for (validator_idx, (_, share_ids)) in committee.iter().enumerate() {
        let validator_idx = validator_idx as u16;
        let ek_i = eks
            .get(&validator_idx)
            .ok_or(ShieldError::InvalidTranscript)?;
        for &omega in share_ids {
            let y_hat = transcript
                .enc_shares
                .get(&omega)
                .ok_or(ShieldError::InvalidTranscript)?;
            let a_k = a_map.get(&omega).ok_or(ShieldError::InvalidTranscript)?;

            tr.extend_from_slice(&omega.to_le_bytes());
            y_hat
                .serialize_compressed(&mut tr)
                .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
            a_k.serialize_compressed(&mut tr)
                .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
            ek_i.serialize_compressed(&mut tr)
                .map_err(|e| ShieldError::Serialization(format!("{e:?}")))?;
            count += 1;
        }
    }

    Ok(crate::shield::fs::expand_challenges(&tr, count))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
