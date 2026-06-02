//! Tests for `shield::facade` — S8: Shield handle + withholding predicate.
//!
//! Test matrix (15-SHIELD_SPEC §8.1, §4.3/§5.4):
//! - `new_builds_handle_with_unset_epoch_key`
//! - `set_and_get_epoch_key`
//! - `params_matches_committee`
//! - `encrypt_then_validate_ingress_accepts`
//! - `validate_ingress_rejects_tampered_ciphertext`
//! - `full_round_trip_dkg_encrypt_decrypt` — run_dkg → encrypt → recover → decrypt.
//! - `decrypt_rejects_insufficient_shares`
//! - `run_dkg_via_facade_matches_free_fn`
//! - `reshare_via_facade_keeps_y_invariant` — full reshare round-trip through Shield.
//! - `reshare_rejects_insufficient_weight`
//! - `withholding_set_empty_when_all_dealers_post_valid` (regression: honest-but-unselected NOT flagged)
//! - `withholding_set_flags_no_show`
//! - `withholding_set_flags_faulty_dealer`

use ark_bls12_381::{Fr, G1Affine, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use rand::{rngs::StdRng, SeedableRng};
use std::collections::BTreeMap;

use super::{withholding_set, Shield};
use crate::shield::{
    ciphertext::ShieldAad,
    committee::ShieldCommittee,
    params::WEIGHT_GRANULARITY_DROP,
    pss::{combine_shares, deal_reshare},
    pvss::{deal, recover_share, PvssTranscript},
    tpke::CombineShare,
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

/// W=6 committee (3 validators × 2 shares).
fn committee_w6() -> ShieldCommittee {
    let vset = vset_with_shares(1, &[(1, 2), (2, 2), (3, 2)]);
    ShieldCommittee::from_validator_set(&vset).unwrap()
}

fn dkg_tau() -> Vec<u8> {
    b"epoch:1:dkg".to_vec()
}

/// Build `posted` map for all committee members as dealers.
fn post_all_dealers(
    committee: &ShieldCommittee,
    eks: &BTreeMap<u16, G2Affine>,
    tau: &[u8],
) -> BTreeMap<Address, (PvssTranscript, bool)> {
    committee
        .iter()
        .enumerate()
        .map(|(i, (a, _))| {
            let tr = deal(
                tau.to_vec(),
                committee,
                eks,
                &mut seeded_rng(100 + i as u64),
            )
            .unwrap();
            (*a, (tr, true))
        })
        .collect()
}

/// Recover all validators' Z shares from `aggregate` and build CombineShares.
fn combine_shares_from_aggregate(
    committee: &ShieldCommittee,
    aggregate: &PvssTranscript,
    dks: &[Fr],
) -> Vec<CombineShare> {
    committee
        .iter()
        .enumerate()
        .map(|(idx, (_, share_ids))| {
            let z = recover_share(&dks[idx], aggregate, share_ids).unwrap();
            CombineShare {
                validator_index: idx as u16,
                z_shares: z.into_iter().collect(),
            }
        })
        .collect()
}

// ── Handle construction ───────────────────────────────────────────────────────

#[test]
fn new_builds_handle_with_unset_epoch_key() {
    let shield = Shield::new(committee_w6()).unwrap();
    assert!(
        shield.epoch_key().is_none(),
        "epoch key must be None before DKG"
    );
    assert_eq!(shield.committee().total_weight(), 6, "committee W=6");
}

#[test]
fn set_and_get_epoch_key() {
    let mut shield = Shield::new(committee_w6()).unwrap();
    let y = G1Affine::generator();
    shield.set_epoch_key(y);
    assert_eq!(shield.epoch_key(), Some(&y), "epoch key must be set");
}

#[test]
fn params_matches_committee() {
    let committee = committee_w6();
    let expected = *committee.params();
    let shield = Shield::new(committee).unwrap();
    assert_eq!(
        *shield.params(),
        expected,
        "params must come from the committee"
    );
}

// ── Ingress ────────────────────────────────────────────────────────────────────

#[test]
fn encrypt_then_validate_ingress_accepts() {
    let shield = Shield::new(committee_w6()).unwrap();
    let y = G1Affine::generator(); // any valid G1 point works for encrypt/validate
    let aad = ShieldAad {
        chain_id: 1,
        epoch: 1,
        submitter_nonce: 0,
    };
    let ct = Shield::encrypt(&y, aad, b"hello-shield").unwrap();
    assert!(
        shield.validate_ingress(&ct).is_ok(),
        "freshly encrypted ciphertext must pass ingress validation"
    );
}

#[test]
fn validate_ingress_rejects_tampered_ciphertext() {
    let shield = Shield::new(committee_w6()).unwrap();
    let y = G1Affine::generator();
    let aad = ShieldAad {
        chain_id: 1,
        epoch: 1,
        submitter_nonce: 0,
    };
    let mut ct = Shield::encrypt(&y, aad, b"tamper-me").unwrap();
    // Tamper with U (replace with a different G1 point) → validity pairing must fail.
    ct.u = G1Affine::generator();
    assert!(
        shield.validate_ingress(&ct).is_err(),
        "tampered ciphertext must be rejected by ingress validation"
    );
}

// ── Full DKG → encrypt → decrypt round-trip ───────────────────────────────────

#[test]
fn full_round_trip_dkg_encrypt_decrypt() {
    let committee = committee_w6();
    let (eks, dks) = test_epoch_keys(&committee);
    let tau = dkg_tau();
    let mut shield = Shield::new(committee.clone()).unwrap();

    // 1. DKG via facade.
    let posted = post_all_dealers(&committee, &eks, &tau);
    let dkg = shield.run_dkg(&posted, &eks, &tau).unwrap();
    shield.set_epoch_key(dkg.y);
    let y = *shield.epoch_key().unwrap();

    // 2. Encrypt under Y.
    let aad = ShieldAad {
        chain_id: 1,
        epoch: 1,
        submitter_nonce: 0,
    };
    let plaintext = b"facade-round-trip";
    let ct = Shield::encrypt(&y, aad, plaintext).unwrap();

    // 3. Recover shares + decrypt via facade.
    let shares = combine_shares_from_aggregate(&committee, &dkg.aggregate, &dks);
    let decrypted = shield.decrypt(&ct, &shares).unwrap();
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "decrypt must recover plaintext"
    );
}

#[test]
fn decrypt_rejects_insufficient_shares() {
    let committee = committee_w6();
    let (eks, dks) = test_epoch_keys(&committee);
    let tau = dkg_tau();
    let mut shield = Shield::new(committee.clone()).unwrap();
    let posted = post_all_dealers(&committee, &eks, &tau);
    let dkg = shield.run_dkg(&posted, &eks, &tau).unwrap();
    shield.set_epoch_key(dkg.y);

    let aad = ShieldAad {
        chain_id: 1,
        epoch: 1,
        submitter_nonce: 0,
    };
    let ct = Shield::encrypt(shield.epoch_key().unwrap(), aad, b"x").unwrap();

    // Only one validator's shares (weight 2) — below p+1 = 5.
    let all = combine_shares_from_aggregate(&committee, &dkg.aggregate, &dks);
    let one = vec![all[0].clone()];
    match shield.decrypt(&ct, &one).unwrap_err() {
        ShieldError::InsufficientShares { have, need } => {
            assert!(have < need, "have={have} must be < need={need}");
        }
        other => panic!("expected InsufficientShares, got {other:?}"),
    }
}

#[test]
fn run_dkg_via_facade_matches_free_fn() {
    use crate::shield::dkg::run_dkg as free_run_dkg;
    let committee = committee_w6();
    let (eks, _) = test_epoch_keys(&committee);
    let tau = dkg_tau();
    let shield = Shield::new(committee.clone()).unwrap();
    let posted = post_all_dealers(&committee, &eks, &tau);

    let facade_out = shield.run_dkg(&posted, &eks, &tau).unwrap();
    let free_out = free_run_dkg(&posted, &committee, &eks, &tau).unwrap();
    assert_eq!(
        facade_out.y, free_out.y,
        "facade run_dkg must match free fn"
    );
    assert_eq!(facade_out.selected_dealers, free_out.selected_dealers);
}

// ── Reshare round-trip (key-invariance through the facade) ────────────────────

#[test]
fn reshare_via_facade_keeps_y_invariant() {
    let committee = committee_w6();
    let (eks, dks) = test_epoch_keys(&committee);
    let dkg_tau = dkg_tau();
    let reshare_tau = b"epoch:1:to:2:reshare".to_vec();
    let mut shield = Shield::new(committee.clone()).unwrap();

    // 1. DKG → Y, Z_old.
    let posted = post_all_dealers(&committee, &eks, &dkg_tau);
    let dkg = shield.run_dkg(&posted, &eks, &dkg_tau).unwrap();
    shield.set_epoch_key(dkg.y);
    let y = *shield.epoch_key().unwrap();
    let z_old: Vec<BTreeMap<u16, G2Affine>> = committee
        .iter()
        .enumerate()
        .map(|(idx, (_, share_ids))| recover_share(&dks[idx], &dkg.aggregate, share_ids).unwrap())
        .collect();

    // 2. Encrypt under Y.
    let aad = ShieldAad {
        chain_id: 1,
        epoch: 1,
        submitter_nonce: 0,
    };
    let plaintext = b"reshare-keeps-y";
    let ct = Shield::encrypt(&y, aad, plaintext).unwrap();

    // 3. Reshare via facade (same committee, zero-secret transcripts).
    let reshare_posted: BTreeMap<Address, (PvssTranscript, bool)> = committee
        .iter()
        .enumerate()
        .map(|(i, (a, _))| {
            let tr = deal_reshare(
                reshare_tau.clone(),
                &committee,
                &eks,
                &mut seeded_rng(300 + i as u64),
            )
            .unwrap();
            (*a, (tr, true))
        })
        .collect();
    let reshare_out = shield
        .reshare(&committee, &reshare_posted, &eks, &reshare_tau)
        .unwrap();
    assert!(
        reshare_out.aggregate.coeff_comms[0].is_zero(),
        "resharing aggregate F_0 must be 𝒪 (Y invariant)"
    );

    // 4. Recover Z_zero, combine with Z_old → Z_new, decrypt.
    let shares: Vec<CombineShare> = committee
        .iter()
        .enumerate()
        .map(|(idx, (_, share_ids))| {
            let z_zero = recover_share(&dks[idx], &reshare_out.aggregate, share_ids).unwrap();
            let z_new = combine_shares(&z_old[idx], &z_zero).unwrap();
            CombineShare {
                validator_index: idx as u16,
                z_shares: z_new.into_iter().collect(),
            }
        })
        .collect();
    let decrypted = shield.decrypt(&ct, &shares).unwrap();
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "decrypt with reshared shares must recover plaintext (Y invariant through facade)"
    );
}

#[test]
fn reshare_rejects_insufficient_weight() {
    let committee = committee_w6();
    let (eks, _) = test_epoch_keys(&committee);
    let reshare_tau = b"epoch:1:to:2:reshare".to_vec();
    let shield = Shield::new(committee.clone()).unwrap();
    // Only one dealer (weight 2) → quorum ⌈2·6/3⌉ = 4 not reached.
    let dealer = *committee.iter().next().unwrap().0;
    let tr = deal_reshare(reshare_tau.clone(), &committee, &eks, &mut seeded_rng(1)).unwrap();
    let mut posted = BTreeMap::new();
    posted.insert(dealer, (tr, true));
    match shield
        .reshare(&committee, &posted, &eks, &reshare_tau)
        .unwrap_err()
    {
        ShieldError::DkgQuorumNotReached { have, need } => {
            assert!(have < need, "have={have} < need={need}");
        }
        other => panic!("expected DkgQuorumNotReached, got {other:?}"),
    }
}

// ── withholding_set predicate (§4.3 / §5.4) ───────────────────────────────────

#[test]
fn withholding_set_empty_when_all_dealers_post_valid() {
    // All 3 committee members post valid transcripts → no non-contributors,
    // EVEN THOUGH run_dkg only *selects* 2 of them (quorum ⌈2·6/3⌉=4 met by 2×2).
    // This is the regression guard: honest-but-unselected dealers MUST NOT be flagged.
    let committee = committee_w6();
    let (eks, _) = test_epoch_keys(&committee);
    let tau = dkg_tau();
    let shield = Shield::new(committee.clone()).unwrap();
    let posted = post_all_dealers(&committee, &eks, &tau);
    let dkg = shield.run_dkg(&posted, &eks, &tau).unwrap();

    // Sanity: quorum truncation means not all dealers are selected.
    assert!(
        dkg.selected_dealers.len() < committee.validator_count(),
        "test premise: quorum truncation leaves ≥1 honest dealer unselected"
    );

    let withholders = withholding_set(&committee, &posted, &dkg);
    assert!(
        withholders.is_empty(),
        "no non-contributors when all committee members post valid transcripts \
         (honest-but-unselected dealers must NOT be flagged)"
    );
}

#[test]
fn withholding_set_flags_no_show() {
    // Committee has 3 validators but only 2 post → quorum ⌈2·6/3⌉=4 met by 2×2=4.
    let committee = committee_w6();
    let (eks, _) = test_epoch_keys(&committee);
    let tau = dkg_tau();
    let shield = Shield::new(committee.clone()).unwrap();

    // Post only the first 2 dealers; the 3rd is a no-show (absent from `posted`).
    let dealer_addrs: Vec<Address> = committee.iter().map(|(a, _)| *a).collect();
    let no_show = dealer_addrs[2];
    let posted: BTreeMap<Address, (PvssTranscript, bool)> = dealer_addrs
        .iter()
        .take(2)
        .enumerate()
        .map(|(i, &a)| {
            let tr = deal(
                tau.clone(),
                &committee,
                &eks,
                &mut seeded_rng(100 + i as u64),
            )
            .unwrap();
            (a, (tr, true))
        })
        .collect();
    let dkg = shield.run_dkg(&posted, &eks, &tau).unwrap();
    let withholders = withholding_set(&committee, &posted, &dkg);
    assert!(
        withholders.contains(&no_show),
        "no-show validator must be flagged"
    );
    assert_eq!(
        withholders.len(),
        1,
        "only the no-show is a non-contributor"
    );
}

#[test]
fn withholding_set_flags_faulty_dealer() {
    // 3 dealers post, but 1 has sig_ok=false → faulty_dealers → non-contributor.
    let committee = committee_w6();
    let (eks, _) = test_epoch_keys(&committee);
    let tau = dkg_tau();
    let shield = Shield::new(committee.clone()).unwrap();

    let dealer_addrs: Vec<Address> = committee.iter().map(|(a, _)| *a).collect();
    let faulty = dealer_addrs[2];
    let mut posted = post_all_dealers(&committee, &eks, &tau);
    posted.get_mut(&faulty).unwrap().1 = false; // sig_ok=false
    let dkg = shield.run_dkg(&posted, &eks, &tau).unwrap();

    assert!(
        dkg.faulty_dealers.contains(&faulty),
        "sig_ok=false dealer must be in faulty_dealers"
    );
    let withholders = withholding_set(&committee, &posted, &dkg);
    assert!(
        withholders.contains(&faulty),
        "faulty (invalid-post) dealer must be flagged"
    );
    assert_eq!(
        withholders.len(),
        1,
        "only the faulty dealer is a non-contributor"
    );
}
