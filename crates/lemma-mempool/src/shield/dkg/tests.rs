//! Tests for `shield::dkg` — S6: BFT-native DKG driver.
//!
//! Test matrix (15-SHIELD_SPEC §11, "DKG driver" row):
//! - `run_dkg_succeeds_with_full_committee` — all valid dealers → success.
//! - `run_dkg_y_equals_aggregate_f0` — Y == aggregate.coeff_comms[0].
//! - `run_dkg_is_deterministic` — two runs same inputs → byte-identical Y + coeff_comms.
//! - `run_dkg_rejects_all_false_sig_ok` — all sig_ok=false → DkgQuorumNotReached.
//! - `run_dkg_flags_false_sig_ok_dealer_as_faulty` — sig_ok=false → faulty_dealers, not selected.
//! - `run_dkg_flags_corrupt_transcript_as_faulty` — tampered transcript → faulty_dealers.
//! - `run_dkg_fails_when_insufficient_weight` — low-weight valid → DkgQuorumNotReached.
//! - `run_dkg_empty_posted_fails` — no transcripts → DkgQuorumNotReached.
//! - `run_dkg_selected_dealers_are_subset_of_valid` — selected ⊆ posted, no faulty overlap.
//! - `run_dkg_faulty_dealer_not_in_selected` — faulty and selected are disjoint.

use ark_bls12_381::{Fr, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::CanonicalSerialize;
use rand::{rngs::StdRng, SeedableRng};
use std::collections::BTreeMap;

use super::run_dkg;
use crate::shield::{
    committee::ShieldCommittee,
    params::WEIGHT_GRANULARITY_DROP,
    pvss::{deal, PvssTranscript},
    ShieldError,
};
use lemma_core::{
    address::Address,
    amount::Amount,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};

// ── Type aliases ─────────────────────────────────────────────────────────────

type PostedMap = BTreeMap<Address, (PvssTranscript, bool)>;
type SetupResult = (ShieldCommittee, BTreeMap<u16, G2Affine>, PostedMap);

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
        total_power = total_power.checked_add(Amount::from_drop(power_drop)).unwrap();
        members.insert(addr(byte), Member { consensus_pubkey: dummy_key(), power });
    }
    ValidatorSet { epoch, members, total_power }
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
    b"epoch:1:dkg-test".to_vec()
}

/// W=6 committee (3 validators × 2 shares) with N dealers drawn from committee members.
///
/// Each validator in the committee acts as a dealer — the `posted` map uses the
/// actual committee member `Address`es so `committee.weight_of(addr)` returns non-zero.
fn setup(n_dealers: usize) -> SetupResult {
    let vset = vset_with_shares(1, &[(1, 2), (2, 2), (3, 2)]); // W=6, t=1, quorum=4
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_epoch_keys(&committee);
    let tau = test_tau();
    let dealer_addrs: Vec<Address> = committee.iter().map(|(a, _)| *a).collect();
    let mut posted = BTreeMap::new();
    for (i, &dealer) in dealer_addrs.iter().take(n_dealers).enumerate() {
        let tr = deal(tau.clone(), &committee, &eks, &mut seeded_rng(100 + i as u64)).unwrap();
        posted.insert(dealer, (tr, true));
    }
    (committee, eks, posted)
}

/// First committee member address (smallest in BTreeMap canonical order).
fn first_committee_addr() -> Address {
    let vset = vset_with_shares(1, &[(1, 2), (2, 2), (3, 2)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    // Collect to end the borrow on `committee` before it is dropped.
    let addrs: Vec<Address> = committee.iter().map(|(a, _)| *a).collect();
    addrs[0]
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn run_dkg_succeeds_with_full_committee() {
    let (committee, eks, posted) = setup(3);
    let result = run_dkg(&posted, &committee, &eks, &test_tau());
    assert!(result.is_ok(), "run_dkg must succeed with all valid dealers: {result:?}");
}

#[test]
fn run_dkg_y_equals_aggregate_f0() {
    let (committee, eks, posted) = setup(3);
    let out = run_dkg(&posted, &committee, &eks, &test_tau()).unwrap();
    assert_eq!(
        out.y,
        out.aggregate.coeff_comms[0],
        "Y must always equal the aggregate transcript's F_0"
    );
}

#[test]
fn run_dkg_is_deterministic() {
    let (committee, eks, posted) = setup(3);
    let tau = test_tau();
    let out1 = run_dkg(&posted, &committee, &eks, &tau).unwrap();
    let out2 = run_dkg(&posted, &committee, &eks, &tau).unwrap();

    // Byte-identical Y (§7, DB-15).
    let mut y1 = Vec::new();
    let mut y2 = Vec::new();
    out1.y.serialize_compressed(&mut y1).unwrap();
    out2.y.serialize_compressed(&mut y2).unwrap();
    assert_eq!(y1, y2, "Y must be byte-identical across runs for the same inputs");

    assert_eq!(
        out1.aggregate.coeff_comms, out2.aggregate.coeff_comms,
        "aggregate coeff_comms must be byte-identical"
    );
    assert_eq!(out1.selected_dealers, out2.selected_dealers);
    assert_eq!(out1.faulty_dealers, out2.faulty_dealers);
}

#[test]
fn run_dkg_rejects_all_false_sig_ok() {
    let (committee, eks, mut posted) = setup(3);
    // Set all sig_ok = false.
    for (_, sig_ok) in posted.values_mut() {
        *sig_ok = false;
    }
    let err = run_dkg(&posted, &committee, &eks, &test_tau()).unwrap_err();
    assert_eq!(
        err,
        ShieldError::DkgQuorumNotReached { have: 0, need: 4 },
        "all sig_ok=false must produce DkgQuorumNotReached"
    );
}

#[test]
fn run_dkg_flags_false_sig_ok_dealer_as_faulty() {
    let (committee, eks, mut posted) = setup(3);
    // Mark the first committee member (smallest canonical address) as invalid sig.
    let faulty = first_committee_addr();
    posted.get_mut(&faulty).unwrap().1 = false;
    let out = run_dkg(&posted, &committee, &eks, &test_tau()).unwrap();
    assert!(
        out.faulty_dealers.contains(&faulty),
        "sig_ok=false dealer must appear in faulty_dealers"
    );
    assert!(
        !out.selected_dealers.contains(&faulty),
        "sig_ok=false dealer must NOT appear in selected_dealers"
    );
}

#[test]
fn run_dkg_flags_corrupt_transcript_as_faulty() {
    let (committee, eks, mut posted) = setup(3);
    let faulty = first_committee_addr();
    // Corrupt the transcript: swap F_0 ↔ F_1 (tag pairing will fail verify).
    posted.get_mut(&faulty).unwrap().0.coeff_comms.swap(0, 1);
    let out = run_dkg(&posted, &committee, &eks, &test_tau()).unwrap();
    assert!(
        out.faulty_dealers.contains(&faulty),
        "corrupt transcript must appear in faulty_dealers"
    );
    assert!(
        !out.selected_dealers.contains(&faulty),
        "faulty dealer must NOT be selected"
    );
}

#[test]
fn run_dkg_fails_when_insufficient_weight() {
    // W=6, quorum=⌈2·6/3⌉=4. Only 1 dealer (weight 2) → have=2 < need=4.
    let vset = vset_with_shares(1, &[(1, 2), (2, 2), (3, 2)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_epoch_keys(&committee);
    let tau = test_tau();
    // Use a real committee member address so weight_of() returns 2 (not 0).
    let dealer = first_committee_addr();
    let tr = deal(tau.clone(), &committee, &eks, &mut seeded_rng(42)).unwrap();
    let mut posted = BTreeMap::new();
    posted.insert(dealer, (tr, true));
    match run_dkg(&posted, &committee, &eks, &tau).unwrap_err() {
        ShieldError::DkgQuorumNotReached { have, need } => {
            assert!(have < need, "have={have} must be < need={need}");
        }
        other => panic!("expected DkgQuorumNotReached, got {other:?}"),
    }
}

#[test]
fn run_dkg_empty_posted_fails() {
    let vset = vset_with_shares(1, &[(1, 2), (2, 2), (3, 2)]);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_epoch_keys(&committee);
    let posted: BTreeMap<Address, (PvssTranscript, bool)> = BTreeMap::new();
    let err = run_dkg(&posted, &committee, &eks, &test_tau()).unwrap_err();
    assert_eq!(
        err,
        ShieldError::DkgQuorumNotReached { have: 0, need: 4 },
        "empty posted must fail with DkgQuorumNotReached"
    );
}

#[test]
fn run_dkg_selected_and_faulty_are_disjoint() {
    let (committee, eks, mut posted) = setup(3);
    // Make the first committee member faulty.
    posted.get_mut(&first_committee_addr()).unwrap().1 = false;
    let out = run_dkg(&posted, &committee, &eks, &test_tau()).unwrap();
    for dealer in &out.selected_dealers {
        assert!(
            !out.faulty_dealers.contains(dealer),
            "selected_dealers and faulty_dealers must be disjoint"
        );
    }
}

#[test]
fn run_dkg_selected_is_subset_of_posted() {
    let (committee, eks, posted) = setup(3);
    let out = run_dkg(&posted, &committee, &eks, &test_tau()).unwrap();
    for dealer in &out.selected_dealers {
        assert!(posted.contains_key(dealer), "every selected dealer must have been in posted");
    }
}
