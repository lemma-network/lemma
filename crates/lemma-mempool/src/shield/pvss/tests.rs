//! Tests for `shield::pvss` — S5: deal + verify.
//!
//! Test matrix (15-SHIELD_SPEC §11, PVSS row):
//! - `deal_then_verify_accepts_valid_transcript` — happy path roundtrip.
//! - `deal_is_deterministic_for_same_rng_seed` — same seed → byte-identical transcript.
//! - `verify_rejects_wrong_tau` — cross-epoch replay guard.
//! - `verify_rejects_bad_f0_tag` — corrupted coefficient commitment F_0.
//! - `verify_rejects_bad_correctness_tag` — corrupted û₂.
//! - `verify_rejects_bad_enc_share` — corrupted Ŷ_{i,ω}.
//! - `verify_rejects_wrong_ek` — wrong epoch key for verification.
//! - `verify_rejects_zero_tag_degenerate_point` — zero û₂ guard.
//! - `verify_rejects_zero_f0_degenerate_point` — zero F_0 guard.
//! - `verify_rejects_zero_enc_share_degenerate_point` — zero Ŷ guard.
//! - `verify_rejects_missing_enc_share` — transcript missing a share entry.
//! - `fft_commitment_expansion_consistency` — FFT eval matches honest polynomial.
//! - `u1_generator_is_deterministic` — same call → same û₁.
//! - `u1_generator_differs_from_h_generator` — û₁ ≠ H (independent generators).
//! - `u1_generator_is_in_correct_subgroup` — û₁ in prime-order subgroup.
//! - `deal_produces_correct_field_counts` — t+1 coeff_comms, W enc_shares.
//! - `deal_enc_shares_cover_all_share_ids` — IDs exactly 1..=W.
//! - `deal_stores_tau_in_transcript` — tau echoed back.
//! - `deal_verify_with_larger_committee` — W=12, t=3.

use ark_bls12_381::{Fr, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use rand::{rngs::StdRng, SeedableRng};
use std::collections::BTreeMap;

use super::{deal, u1_generator, verify, PvssTranscript};
use crate::shield::{
    committee::ShieldCommittee,
    params::WEIGHT_GRANULARITY_DROP,
    ShieldError,
};
use lemma_core::{
    address::Address,
    amount::Amount,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};

// ── Test fixtures ─────────────────────────────────────────────────────────────

fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952])
}

fn addr(byte: u8) -> Address {
    Address::from_public_key(&[byte; 32])
}

/// Build a `ValidatorSet` from `(addr_byte, shares)` pairs.
fn vset_with_shares(epoch: u64, validators: &[(u8, u64)]) -> ValidatorSet {
    let mut members = BTreeMap::new();
    let mut total_power = Amount::from_drop(0);
    for &(byte, shares) in validators {
        let power_drop = u128::from(shares) * WEIGHT_GRANULARITY_DROP;
        let power = VotingPower(Amount::from_drop(power_drop));
        total_power = total_power
            .checked_add(Amount::from_drop(power_drop))
            .unwrap();
        members.insert(addr(byte), Member { consensus_pubkey: dummy_key(), power });
    }
    ValidatorSet { epoch, members, total_power }
}

/// Generate epoch keys for committee validators (in committee.iter() order).
/// Returns `(eks map, dk scalars vec)`.
fn test_epoch_keys(committee: &ShieldCommittee) -> (BTreeMap<u16, G2Affine>, Vec<Fr>) {
    let h = G2Affine::generator();
    let mut eks = BTreeMap::new();
    let mut dks = Vec::new();
    for (idx, _) in committee.iter().enumerate() {
        let dk = Fr::from((idx + 1) as u64);
        let ek: G2Affine = (G2Projective::from(h) * dk).into_affine();
        eks.insert(idx as u16, ek);
        dks.push(dk);
    }
    (eks, dks)
}

fn test_tau() -> Vec<u8> {
    b"epoch:1:pvss-deal".to_vec()
}

fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Build a valid W=6, t=1 committee + eks + transcript for use across tests.
fn valid_setup() -> (ShieldCommittee, BTreeMap<u16, G2Affine>, PvssTranscript) {
    let vset = vset_with_shares(1, &[(1, 2), (2, 2), (3, 2)]); // W=6, t=1
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_epoch_keys(&committee);
    let transcript =
        deal(test_tau(), &committee, &eks, &mut seeded_rng(42)).unwrap();
    (committee, eks, transcript)
}

// ── u1_generator ─────────────────────────────────────────────────────────────

#[test]
fn u1_generator_is_deterministic() {
    let a = u1_generator().unwrap();
    let b = u1_generator().unwrap();
    assert_eq!(a, b, "u1 must be deterministic across calls");
}

#[test]
fn u1_generator_differs_from_h_generator() {
    let u1 = u1_generator().unwrap();
    assert_ne!(u1, G2Affine::generator(), "u1 must be independent of H");
}

#[test]
fn u1_generator_is_in_correct_subgroup() {
    let u1 = u1_generator().unwrap();
    assert!(
        u1.is_in_correct_subgroup_assuming_on_curve(),
        "u1 must lie in the prime-order G2 subgroup"
    );
}

// ── deal → verify happy path ──────────────────────────────────────────────────

#[test]
fn deal_then_verify_accepts_valid_transcript() {
    let (committee, eks, transcript) = valid_setup();
    assert!(
        verify(&test_tau(), &transcript, &committee, &eks).is_ok(),
        "valid transcript must pass verify"
    );
}

#[test]
fn deal_produces_correct_field_counts() {
    let (committee, _, transcript) = valid_setup();
    let params = committee.params();
    assert_eq!(
        transcript.coeff_comms.len(),
        params.t as usize + 1,
        "must have t+1 coefficient commitments"
    );
    assert_eq!(
        transcript.enc_shares.len(),
        params.w as usize,
        "must have W encrypted shares total"
    );
}

#[test]
fn deal_enc_shares_cover_all_share_ids() {
    let (committee, _, transcript) = valid_setup();
    let w = committee.total_weight() as u16;
    let expected: Vec<u16> = (1u16..=w).collect();
    let mut actual: Vec<u16> = transcript.enc_shares.keys().copied().collect();
    actual.sort_unstable();
    assert_eq!(actual, expected, "enc_shares must cover share IDs 1..=W exactly");
}

#[test]
fn deal_stores_tau_in_transcript() {
    let (committee, eks, _) = valid_setup();
    let custom_tau = b"custom-tau-value".to_vec();
    let transcript =
        deal(custom_tau.clone(), &committee, &eks, &mut seeded_rng(55)).unwrap();
    assert_eq!(transcript.tau, custom_tau, "transcript must echo the supplied tau");
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn deal_is_deterministic_for_same_rng_seed() {
    let vset = vset_with_shares(1, &[(1, 2), (2, 2), (3, 2)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_epoch_keys(&committee);
    let t1 = deal(test_tau(), &committee, &eks, &mut seeded_rng(99)).unwrap();
    let t2 = deal(test_tau(), &committee, &eks, &mut seeded_rng(99)).unwrap();
    assert_eq!(t1.coeff_comms, t2.coeff_comms, "same seed -> same coeff_comms");
    assert_eq!(t1.tag, t2.tag, "same seed -> same tag");
    assert_eq!(t1.enc_shares, t2.enc_shares, "same seed -> same enc_shares");
}

#[test]
fn deal_different_seeds_produce_different_transcripts() {
    let vset = vset_with_shares(1, &[(1, 2), (2, 2), (3, 2)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_epoch_keys(&committee);
    let t1 = deal(test_tau(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    let t2 = deal(test_tau(), &committee, &eks, &mut seeded_rng(2)).unwrap();
    assert_ne!(t1.coeff_comms, t2.coeff_comms, "different seed -> different transcript");
}

// ── verify rejection — tau ────────────────────────────────────────────────────

#[test]
fn verify_rejects_wrong_tau() {
    let (committee, eks, transcript) = valid_setup();
    let wrong_tau = b"epoch:2:pvss-deal".to_vec();
    assert_eq!(
        verify(&wrong_tau, &transcript, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "mismatched tau must be rejected (cross-epoch replay guard)"
    );
}

// ── verify rejection — degenerate points ─────────────────────────────────────

#[test]
fn verify_rejects_zero_f0_degenerate_point() {
    use ark_bls12_381::G1Affine;
    let (committee, eks, mut transcript) = valid_setup();
    transcript.coeff_comms[0] = G1Affine::zero();
    assert_eq!(
        verify(&test_tau(), &transcript, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "zero F_0 must be rejected"
    );
}

#[test]
fn verify_rejects_zero_tag_degenerate_point() {
    let (committee, eks, mut transcript) = valid_setup();
    transcript.tag = G2Affine::zero();
    assert_eq!(
        verify(&test_tau(), &transcript, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "zero u2 tag must be rejected"
    );
}

#[test]
fn verify_rejects_zero_enc_share_degenerate_point() {
    let (committee, eks, mut transcript) = valid_setup();
    if let Some(val) = transcript.enc_shares.values_mut().next() {
        *val = G2Affine::zero();
    }
    assert_eq!(
        verify(&test_tau(), &transcript, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "zero enc_share must be rejected"
    );
}

// ── verify rejection — bad F_0 tag (constant-term pairing) ───────────────────

#[test]
fn verify_rejects_bad_f0_tag() {
    let (committee, eks, mut transcript) = valid_setup();
    // Replace F_0 with F_1 — tag pairing e(F_0,u1) != e(G,u2).
    let f1 = transcript.coeff_comms[1];
    transcript.coeff_comms[0] = f1;
    assert_eq!(
        verify(&test_tau(), &transcript, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "corrupted F_0 must fail the constant-term tag pairing check"
    );
}

#[test]
fn verify_rejects_bad_correctness_tag() {
    let (committee, eks, mut transcript) = valid_setup();
    transcript.tag = G2Affine::generator();
    assert_eq!(
        verify(&test_tau(), &transcript, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "wrong u2 tag must fail the constant-term tag pairing check"
    );
}

// ── verify rejection — bad enc_share (batched pairing) ───────────────────────

#[test]
fn verify_rejects_bad_enc_share() {
    let (committee, eks, mut transcript) = valid_setup();
    // Replace one enc_share with the G2 generator.
    if let Some(val) = transcript.enc_shares.values_mut().next() {
        *val = G2Affine::generator();
    }
    assert_eq!(
        verify(&test_tau(), &transcript, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "corrupted enc_share must fail the batched share pairing check"
    );
}

// ── verify rejection — wrong ek ───────────────────────────────────────────────

#[test]
fn verify_rejects_wrong_ek() {
    let (committee, mut eks, transcript) = valid_setup();
    let h = G2Affine::generator();
    let wrong_dk = Fr::from(9999u64);
    let wrong_ek: G2Affine = (G2Projective::from(h) * wrong_dk).into_affine();
    eks.insert(0, wrong_ek);
    assert_eq!(
        verify(&test_tau(), &transcript, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "wrong ek_i must fail the batched share pairing check"
    );
}

// ── verify rejection — missing enc_share ─────────────────────────────────────

#[test]
fn verify_rejects_missing_enc_share() {
    let (committee, eks, mut transcript) = valid_setup();
    let first_key = *transcript.enc_shares.keys().next().unwrap();
    transcript.enc_shares.remove(&first_key);
    assert_eq!(
        verify(&test_tau(), &transcript, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "transcript missing an enc_share must be rejected"
    );
}

// ── FFT commitment expansion consistency ─────────────────────────────────────

#[test]
fn fft_commitment_expansion_consistency() {
    // deal produces a transcript; verify internally runs FFT expansion + batched
    // pairing. Acceptance = FFT-expanded A_k is consistent with dealer's polynomial.
    let vset = vset_with_shares(1, &[(1, 4), (2, 4)]); // W=8, t=1
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_epoch_keys(&committee);
    let tau = b"fft-test".to_vec();
    let transcript = deal(tau.clone(), &committee, &eks, &mut seeded_rng(7)).unwrap();
    assert!(
        verify(&tau, &transcript, &committee, &eks).is_ok(),
        "FFT commitment expansion must be consistent with the dealer polynomial"
    );
}

// ── Larger committee ──────────────────────────────────────────────────────────

#[test]
fn deal_verify_with_larger_committee() {
    // W=12, t=⌊12/3⌋-1=3 → 4 coeff_comms
    let vset = vset_with_shares(1, &[(1, 3), (2, 3), (3, 3), (4, 3)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_epoch_keys(&committee);
    let tau = b"epoch:5:large".to_vec();
    let transcript = deal(tau.clone(), &committee, &eks, &mut seeded_rng(13)).unwrap();
    assert!(
        verify(&tau, &transcript, &committee, &eks).is_ok(),
        "deal->verify must succeed for W=12 committee"
    );
    assert_eq!(transcript.coeff_comms.len(), 4, "W=12 -> t=3 -> 4 coeff_comms");
    assert_eq!(transcript.enc_shares.len(), 12, "W=12 -> 12 enc_shares");
}
