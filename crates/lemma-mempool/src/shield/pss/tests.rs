//! Tests for `shield::pss` — S7: per-epoch zero-secret resharing (PSS).
//!
//! Test matrix (15-SHIELD_SPEC §11, "Resharing" row):
//! - `deal_reshare_produces_identity_f0_and_tag` — F_0 == 𝒪, tag == 𝒪 by construction.
//! - `deal_reshare_is_deterministic` — same seed → identical transcript.
//! - `deal_reshare_has_correct_share_count` — W enc_shares, t+1 coeff_comms.
//! - `verify_reshare_accepts_valid_transcript` — deal_reshare → verify_reshare passes.
//! - `verify_reshare_rejects_nonzero_f0` — non-identity F_0 → ReshareAlteredKey.
//! - `verify_reshare_rejects_nonzero_tag` — non-identity tag → ReshareAlteredKey.
//! - `verify_reshare_rejects_wrong_tau` — tau mismatch → InvalidTranscript.
//! - `verify_reshare_rejects_corrupted_enc_share` — bad enc_share → InvalidTranscript.
//! - `verify_reshare_rejects_missing_enc_share` — missing enc_share → InvalidTranscript.
//! - `verify_reshare_rejects_wrong_ek` — wrong epoch key → InvalidTranscript.
//! - `aggregate_of_reshare_transcripts_has_identity_f0` — Σ𝒪 = 𝒪 (Y unchanged).
//! - `aggregate_of_reshare_transcripts_passes_verify_reshare` — aggregated zero-transcript still valid.
//! - `combine_shares_produces_element_wise_sum` — Z_new[ω] == Z_old[ω] + Z_zero[ω].
//! - `combine_shares_rejects_mismatched_keysets` — different share IDs → InvalidTranscript.
//! - `combine_shares_with_empty_maps_returns_empty` — edge case: empty maps → Ok(empty).
//! - `key_invariance_round_trip` — full: S6 DKG → encrypt → reshare → combine_shares → decrypt.
//!   Decrypted plaintext must equal original despite share refresh (Y unchanged proof).

use ark_bls12_381::{Fr, G1Affine, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use rand::{rngs::StdRng, SeedableRng};
use std::collections::BTreeMap;

use super::{combine_shares, deal_reshare, verify_reshare};
use crate::shield::{
    committee::ShieldCommittee,
    dkg::run_dkg,
    params::WEIGHT_GRANULARITY_DROP,
    pvss::{aggregate, deal, recover_share, PvssTranscript},
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

fn vset_with_shares(epoch: u64, validators: &[(u8, u64)]) -> ValidatorSet {
    let mut members = BTreeMap::new();
    let mut total_power = Amount::from_drop(0);
    for &(byte, shares) in validators {
        let power_drop = u128::from(shares) * WEIGHT_GRANULARITY_DROP;
        let power = VotingPower(Amount::from_drop(power_drop));
        total_power = total_power
            .checked_add(Amount::from_drop(power_drop))
            .unwrap();
        members.insert(
            addr(byte),
            Member {
                consensus_pubkey: dummy_key(),
                power,
            },
        );
    }
    ValidatorSet {
        epoch,
        members,
        total_power,
    }
}

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

fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

fn test_tau() -> Vec<u8> {
    b"epoch:1:to:2:reshare".to_vec()
}

/// W=6 committee (3 validators × 2 shares each) + epoch keys.
fn setup() -> (ShieldCommittee, BTreeMap<u16, G2Affine>, Vec<Fr>) {
    let vset = vset_with_shares(1, &[(1, 2), (2, 2), (3, 2)]); // W=6
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, dks) = test_epoch_keys(&committee);
    (committee, eks, dks)
}

// ── deal_reshare ──────────────────────────────────────────────────────────────

#[test]
fn deal_reshare_produces_identity_f0_and_tag() {
    let (committee, eks, _) = setup();
    let tr = deal_reshare(test_tau(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    assert!(
        tr.coeff_comms[0].is_zero(),
        "F_0 must be the identity (𝒪) — constant term a_0 = 0 (§5.1 step 1)"
    );
    assert!(
        tr.tag.is_zero(),
        "tag û₂ must be identity (𝒪) — û₂ = [0]û₁ = 𝒪 by construction"
    );
}

#[test]
fn deal_reshare_is_deterministic() {
    let (committee, eks, _) = setup();
    let t1 = deal_reshare(test_tau(), &committee, &eks, &mut seeded_rng(42)).unwrap();
    let t2 = deal_reshare(test_tau(), &committee, &eks, &mut seeded_rng(42)).unwrap();
    assert_eq!(
        t1.coeff_comms, t2.coeff_comms,
        "same seed → same coeff_comms"
    );
    assert_eq!(t1.enc_shares, t2.enc_shares, "same seed → same enc_shares");
    assert_eq!(t1.tag, t2.tag, "same seed → same tag");
}

#[test]
fn deal_reshare_has_correct_share_count() {
    let (committee, eks, _) = setup();
    let tr = deal_reshare(test_tau(), &committee, &eks, &mut seeded_rng(7)).unwrap();
    let params = committee.params();
    assert_eq!(
        tr.coeff_comms.len(),
        params.t as usize + 1,
        "must have t+1 coeff_comms"
    );
    assert_eq!(
        tr.enc_shares.len(),
        params.w as usize,
        "must have W enc_shares"
    );
}

// ── verify_reshare ────────────────────────────────────────────────────────────

#[test]
fn verify_reshare_accepts_valid_transcript() {
    let (committee, eks, _) = setup();
    let tau = test_tau();
    let tr = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    assert!(
        verify_reshare(&tau, &tr, &committee, &eks).is_ok(),
        "valid reshare transcript must pass verify_reshare"
    );
}

#[test]
fn verify_reshare_rejects_nonzero_f0() {
    let (committee, eks, _) = setup();
    let tau = test_tau();
    let mut tr = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    // Replace F_0 with the G1 generator (non-identity) → attempts to shift Y.
    tr.coeff_comms[0] = G1Affine::generator();
    assert_eq!(
        verify_reshare(&tau, &tr, &committee, &eks).unwrap_err(),
        ShieldError::ReshareAlteredKey,
        "non-identity F_0 must be rejected with ReshareAlteredKey"
    );
}

#[test]
fn verify_reshare_rejects_nonzero_tag() {
    let (committee, eks, _) = setup();
    let tau = test_tau();
    let mut tr = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    tr.tag = G2Affine::generator(); // non-identity tag
    assert_eq!(
        verify_reshare(&tau, &tr, &committee, &eks).unwrap_err(),
        ShieldError::ReshareAlteredKey,
        "non-identity tag must be rejected with ReshareAlteredKey"
    );
}

#[test]
fn verify_reshare_rejects_wrong_tau() {
    let (committee, eks, _) = setup();
    let tr = deal_reshare(test_tau(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    let wrong_tau = b"epoch:2:to:3:reshare".to_vec();
    assert_eq!(
        verify_reshare(&wrong_tau, &tr, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "tau mismatch must be rejected"
    );
}

#[test]
fn verify_reshare_rejects_corrupted_enc_share() {
    let (committee, eks, _) = setup();
    let tau = test_tau();
    let mut tr = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    // Replace the first enc_share with the G2 generator (wrong enc_share).
    if let Some(val) = tr.enc_shares.values_mut().next() {
        *val = G2Affine::generator();
    }
    assert_eq!(
        verify_reshare(&tau, &tr, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "corrupted enc_share must fail the batched pairing check"
    );
}

#[test]
fn verify_reshare_rejects_missing_enc_share() {
    let (committee, eks, _) = setup();
    let tau = test_tau();
    let mut tr = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    let first = *tr.enc_shares.keys().next().unwrap();
    tr.enc_shares.remove(&first);
    assert_eq!(
        verify_reshare(&tau, &tr, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "transcript missing an enc_share must be rejected"
    );
}

#[test]
fn verify_reshare_rejects_wrong_ek() {
    let (committee, mut eks, _) = setup();
    let tau = test_tau();
    let tr = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    // Swap the epoch key for validator 0.
    let wrong_dk = Fr::from(9999u64);
    let wrong_ek: G2Affine = (G2Projective::from(G2Affine::generator()) * wrong_dk).into_affine();
    eks.insert(0, wrong_ek);
    assert_eq!(
        verify_reshare(&tau, &tr, &committee, &eks).unwrap_err(),
        ShieldError::InvalidTranscript,
        "wrong epoch key must fail the batched pairing check"
    );
}

// ── aggregate of reshare transcripts ─────────────────────────────────────────

#[test]
fn aggregate_of_reshare_transcripts_has_identity_f0() {
    // Σ F_0^{(n)} = Σ 𝒪 = 𝒪 — Y is unchanged.
    let (committee, eks, _) = setup();
    let tau = test_tau();
    let tr1 = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    let tr2 = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(2)).unwrap();
    let tr3 = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(3)).unwrap();
    let agg = aggregate(&[tr1, tr2, tr3]).unwrap();
    assert!(
        agg.coeff_comms[0].is_zero(),
        "aggregate of zero-secret transcripts must have F_0 == 𝒪"
    );
    assert!(agg.tag.is_zero(), "aggregate tag must be 𝒪");
}

#[test]
fn aggregate_of_reshare_transcripts_passes_verify_reshare() {
    let (committee, eks, _) = setup();
    let tau = test_tau();
    let tr1 = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(10)).unwrap();
    let tr2 = deal_reshare(tau.clone(), &committee, &eks, &mut seeded_rng(20)).unwrap();
    let agg = aggregate(&[tr1, tr2]).unwrap();
    assert!(
        verify_reshare(&tau, &agg, &committee, &eks).is_ok(),
        "aggregate of valid reshare transcripts must pass verify_reshare"
    );
}

// ── combine_shares ────────────────────────────────────────────────────────────

#[test]
fn combine_shares_produces_element_wise_sum() {
    // Z_new[ω] == Z_old[ω] + Z_zero[ω] — verify each element.
    let (committee, eks, dks) = setup();
    let tau_old = b"epoch:0:dkg".to_vec();
    let tau_zero = test_tau();
    let tr_old = deal(tau_old, &committee, &eks, &mut seeded_rng(1)).unwrap();
    let tr_zero = deal_reshare(tau_zero, &committee, &eks, &mut seeded_rng(2)).unwrap();

    let (_, share_ids_0) = committee.iter().next().unwrap();
    let dk0 = dks[0];
    let z_old = recover_share(&dk0, &tr_old, share_ids_0).unwrap();
    let z_zero = recover_share(&dk0, &tr_zero, share_ids_0).unwrap();
    let z_new = combine_shares(&z_old, &z_zero).unwrap();

    for (&omega, z_n) in &z_new {
        let expected: G2Affine =
            (G2Projective::from(z_old[&omega]) + G2Projective::from(z_zero[&omega])).into_affine();
        assert_eq!(*z_n, expected, "Z_new[{omega}] must equal Z_old + Z_zero");
    }
}

#[test]
fn combine_shares_rejects_mismatched_keysets() {
    // z_old has shares 1..=6; z_zero has shares 1..=4 → mismatch.
    let (committee, eks, dks) = setup();
    let tau_old = b"epoch:0:dkg".to_vec();
    let tau_zero = test_tau();
    let tr_old = deal(tau_old, &committee, &eks, &mut seeded_rng(1)).unwrap();
    let tr_zero = deal_reshare(tau_zero, &committee, &eks, &mut seeded_rng(2)).unwrap();

    let (_, share_ids_0) = committee.iter().next().unwrap();
    let (_, share_ids_1) = committee.iter().nth(1).unwrap();
    let z_old = recover_share(&dks[0], &tr_old, share_ids_0).unwrap();
    let z_zero = recover_share(&dks[1], &tr_zero, share_ids_1).unwrap();
    // share_ids_0 and share_ids_1 are different slices of the W=6 committee.
    // If they have different lengths (weight-2 validators have 2 shares each —
    // same size here), force a mismatch by truncating z_zero.
    let mut z_zero_truncated = z_zero.clone();
    let last = *z_zero_truncated.keys().next_back().unwrap();
    z_zero_truncated.remove(&last);
    let err = combine_shares(&z_old, &z_zero_truncated).unwrap_err();
    assert_eq!(
        err,
        ShieldError::InvalidTranscript,
        "mismatched keysets must be rejected"
    );
}

#[test]
fn combine_shares_with_empty_maps_returns_empty() {
    let z_old: BTreeMap<u16, G2Affine> = BTreeMap::new();
    let z_zero: BTreeMap<u16, G2Affine> = BTreeMap::new();
    let result = combine_shares(&z_old, &z_zero).unwrap();
    assert!(result.is_empty(), "empty + empty = empty");
}

// ── Re-weighting: reshare to a structurally different new committee ───────────

#[test]
fn reshare_to_new_committee_deals_correctly() {
    // Old committee: W=6 (3 validators × 2 shares).
    // New committee: W=8 (4 validators × 2 shares) — different weight and validators.
    // deal_reshare must produce a valid transcript for the NEW committee's share IDs.
    let vset_new = vset_with_shares(2, &[(1, 2), (2, 2), (3, 2), (4, 2)]); // W=8
    let new_committee = ShieldCommittee::from_validator_set(&vset_new).unwrap();
    let (eks_new, _) = test_epoch_keys(&new_committee);
    let tau = b"epoch:1:to:2:reshare-reweight".to_vec();

    let tr = deal_reshare(tau.clone(), &new_committee, &eks_new, &mut seeded_rng(77)).unwrap();

    // F_0 == 𝒪 and tag == 𝒪 (key-invariance: same Y).
    assert!(
        tr.coeff_comms[0].is_zero(),
        "F_0 must be identity for new committee too"
    );
    assert!(
        tr.tag.is_zero(),
        "tag must be identity for new committee too"
    );

    // Enc_shares cover the new committee's share IDs exactly (1..=W_new=8).
    let w_new = new_committee.total_weight() as u16;
    let expected_ids: Vec<u16> = (1..=w_new).collect();
    let mut actual_ids: Vec<u16> = tr.enc_shares.keys().copied().collect();
    actual_ids.sort_unstable();
    assert_eq!(
        actual_ids, expected_ids,
        "enc_shares must cover new committee IDs 1..=W_new"
    );

    // verify_reshare must pass for the new committee.
    assert!(
        verify_reshare(&tau, &tr, &new_committee, &eks_new).is_ok(),
        "reshare transcript for new committee must pass verify_reshare"
    );
}

// ── Key-invariance round-trip (§11 "Resharing") ───────────────────────────────

#[test]
fn key_invariance_round_trip() {
    // Full proof of key-invariance:
    //   S6 DKG → encrypt under Y
    //   → all validators reshare (deal_reshare → aggregate)
    //   → recover Z_zero → combine_shares(Z_old, Z_zero) → Z_new
    //   → combine(ct, Z_new) → plaintext == original
    use crate::shield::{
        ciphertext::ShieldAad,
        domain::ShieldDomain,
        tpke::{combine, encrypt, CombineShare},
    };

    let (committee, eks, dks) = setup(); // W=6, t=1
    let tau_dkg = b"epoch:1:dkg".to_vec();
    let tau_reshare = test_tau();

    // ── Step 1: S6 DKG (2 dealers → old aggregate Y, Z_old) ──────────────────
    let dealer_addrs: Vec<Address> = committee.iter().map(|(a, _)| *a).collect();
    let posted: BTreeMap<Address, (PvssTranscript, bool)> = dealer_addrs
        .iter()
        .take(2)
        .enumerate()
        .map(|(i, &addr)| {
            let tr = deal(
                tau_dkg.clone(),
                &committee,
                &eks,
                &mut seeded_rng(100 + i as u64),
            )
            .unwrap();
            (addr, (tr, true))
        })
        .collect();
    let dkg_out = run_dkg(&posted, &committee, &eks, &tau_dkg).unwrap();
    let y = dkg_out.y;

    // ── Step 2: Recover Z_old for all validators ──────────────────────────────
    let z_old_per_validator: Vec<BTreeMap<u16, G2Affine>> = committee
        .iter()
        .enumerate()
        .map(|(idx, (_, share_ids))| {
            recover_share(&dks[idx], &dkg_out.aggregate, share_ids).unwrap()
        })
        .collect();

    // ── Step 3: Encrypt plaintext under Y ────────────────────────────────────
    let aad = ShieldAad {
        chain_id: 1,
        epoch: 1,
        submitter_nonce: 0,
    };
    let plaintext = b"key-invariance-test";
    let ct = encrypt(&y, aad, plaintext).unwrap();

    // ── Step 4: Each validator deals a reshare transcript → aggregate ─────────
    let reshare_transcripts: Vec<PvssTranscript> = (0..3)
        .map(|i| {
            deal_reshare(
                tau_reshare.clone(),
                &committee,
                &eks,
                &mut seeded_rng(200 + i as u64),
            )
            .unwrap()
        })
        .collect();
    let zero_agg = aggregate(&reshare_transcripts).unwrap();
    assert!(
        verify_reshare(&tau_reshare, &zero_agg, &committee, &eks).is_ok(),
        "aggregated reshare transcript must verify"
    );

    // ── Step 5: Recover Z_zero, combine with Z_old → Z_new ───────────────────
    let domain = ShieldDomain::new(committee.total_weight()).unwrap();
    let combine_inputs: Vec<CombineShare> = committee
        .iter()
        .enumerate()
        .map(|(idx, (_, share_ids))| {
            let z_zero = recover_share(&dks[idx], &zero_agg, share_ids).unwrap();
            let z_new = combine_shares(&z_old_per_validator[idx], &z_zero).unwrap();
            CombineShare {
                validator_index: idx as u16,
                z_shares: z_new.into_iter().collect(),
            }
        })
        .collect();

    // ── Step 6: Decrypt with Z_new — Y must be unchanged ─────────────────────
    let decrypted = combine(&ct, &combine_inputs, &committee, &domain).unwrap();
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "decryption with reshared shares must recover the original plaintext (Y invariant)"
    );
}
