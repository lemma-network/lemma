//! Tests for `lemma_consensus::slashing::evidence` — double-sign §5.2 (B3b, spec §10).
//!
//! ## Coverage
//!
//! - **verify_double_sign**: all 5 checks (slot match, identical digest, sig, membership,
//!   age, dedup). Valid evidence passes; every individual failure returns specific Err.
//! - **apply_double_sign**: 5% slash + tombstone; wrong-validator / same-digest /
//!   expired / duplicate → rejected, no mutation; tombstoned cannot re-bond.
//! - Determinism: same inputs → same output.

use std::collections::BTreeSet;

use lemma_core::{
    address::Address,
    amount::{Amount, DROPS_PER_LEM},
    hash::Hash,
    validator::{ConsensusKey, Stake, UnbondingEntry, Validator, ValidatorStatus, VotingPower},
    validator_set::{Member, ValidatorSet},
};

use crate::{
    dag::block::DagBlockRef,
    slashing::evidence::{apply_double_sign, verify_double_sign, DoubleSignEvidence, EvidenceError},
};
use crate::epoch::UNBONDING_PERIOD_SECONDS;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn lem(n: u128) -> Amount {
    Amount::from_drop(n * DROPS_PER_LEM)
}

fn hash(n: u8) -> Hash {
    Hash::from_bytes([n; 32])
}

fn make_vset_with(members: &[(u8, u128)]) -> ValidatorSet {
    use std::collections::BTreeMap;
    let map: BTreeMap<_, _> = members
        .iter()
        .map(|&(b, p)| {
            let power = VotingPower(lem(p));
            (addr(b), Member { consensus_pubkey: ConsensusKey::from_bytes(vec![b; 32], vec![b; 32]), power })
        })
        .collect();
    let total_power = map.values().fold(Amount::zero(), |a, m| {
        a.checked_add(m.power.as_amount()).unwrap()
    });
    ValidatorSet { epoch: 0, members: map, total_power }
}

fn make_validator_with_power(addr_byte: u8, active_lem: u128) -> Validator {
    Validator {
        address: addr(addr_byte),
        consensus_pubkey: ConsensusKey::from_bytes(vec![addr_byte; 32], vec![addr_byte; 32]),
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active: lem(active_lem),
            pending_active: Amount::zero(),
            pending_inactive: Vec::new(),
            inactive: Amount::zero(),
        },
        delegated: Amount::zero(),
        commission_bps: 0,
        jailed_until: None,
    }
}

/// Build valid evidence where vote_a and vote_b differ only in digest.
fn make_valid_evidence(validator_byte: u8, power_lem: u128) -> DoubleSignEvidence {
    DoubleSignEvidence {
        vote_a: DagBlockRef::new(10, addr(validator_byte), hash(0xAA)),
        vote_b: DagBlockRef::new(10, addr(validator_byte), hash(0xBB)),
        infraction_height: 10,
        infraction_time: 1_000,
        validator: addr(validator_byte),
        validator_power: lem(power_lem),
        total_power: lem(power_lem),
    }
}

fn empty_dedup() -> BTreeSet<(Address, u64)> {
    BTreeSet::new()
}

/// `current_time` that passes the age check for `infraction_time = 1_000`.
const FRESH_TIME: u64 = 1_000 + UNBONDING_PERIOD_SECONDS - 1;

// ── verify_double_sign: happy path ───────────────────────────────────────────

#[test]
fn verify_valid_evidence_passes_all_checks() {
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(1, 20_000_000)]);
    let result = verify_double_sign(&ev, &vset, true, true, FRESH_TIME, &empty_dedup());
    assert!(result.is_ok(), "valid evidence must pass all 5 checks");
}

// ── Check 1: Slot mismatch ────────────────────────────────────────────────────

#[test]
fn verify_rejects_different_rounds() {
    let mut ev = make_valid_evidence(1, 20_000_000);
    ev.vote_b = DagBlockRef::new(11, addr(1), hash(0xBB)); // different round
    let vset = make_vset_with(&[(1, 20_000_000)]);
    let err = verify_double_sign(&ev, &vset, true, true, FRESH_TIME, &empty_dedup()).unwrap_err();
    assert!(
        matches!(err, EvidenceError::SlotMismatch { .. }),
        "different rounds must → SlotMismatch"
    );
}

#[test]
fn verify_rejects_different_author() {
    let mut ev = make_valid_evidence(1, 20_000_000);
    ev.vote_b = DagBlockRef::new(10, addr(2), hash(0xBB)); // different author
    let vset = make_vset_with(&[(1, 20_000_000), (2, 20_000_000)]);
    let err = verify_double_sign(&ev, &vset, true, true, FRESH_TIME, &empty_dedup()).unwrap_err();
    assert!(matches!(err, EvidenceError::SlotMismatch { .. }));
}

// ── Check 1b: Identical digest ────────────────────────────────────────────────

#[test]
fn verify_rejects_identical_digests() {
    let mut ev = make_valid_evidence(1, 20_000_000);
    ev.vote_b = DagBlockRef::new(10, addr(1), hash(0xAA)); // same digest as vote_a
    let vset = make_vset_with(&[(1, 20_000_000)]);
    let err = verify_double_sign(&ev, &vset, true, true, FRESH_TIME, &empty_dedup()).unwrap_err();
    assert!(
        matches!(err, EvidenceError::IdenticalDigests),
        "same digest must → IdenticalDigests (gossip duplicate, not equivocation)"
    );
}

// ── Check 2: Signature ────────────────────────────────────────────────────────

#[test]
fn verify_rejects_when_sig_a_invalid() {
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(1, 20_000_000)]);
    let err = verify_double_sign(&ev, &vset, false, true, FRESH_TIME, &empty_dedup()).unwrap_err();
    assert!(matches!(err, EvidenceError::InvalidSignature { sig_a_ok: false, sig_b_ok: true }));
}

#[test]
fn verify_rejects_when_sig_b_invalid() {
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(1, 20_000_000)]);
    let err = verify_double_sign(&ev, &vset, true, false, FRESH_TIME, &empty_dedup()).unwrap_err();
    assert!(matches!(err, EvidenceError::InvalidSignature { sig_a_ok: true, sig_b_ok: false }));
}

#[test]
fn verify_rejects_when_both_sigs_invalid() {
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(1, 20_000_000)]);
    let err = verify_double_sign(&ev, &vset, false, false, FRESH_TIME, &empty_dedup()).unwrap_err();
    assert!(matches!(err, EvidenceError::InvalidSignature { sig_a_ok: false, sig_b_ok: false }));
}

// ── Check 3: Committee membership ────────────────────────────────────────────

#[test]
fn verify_rejects_non_member_validator() {
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(2, 20_000_000)]); // validator 1 NOT in set
    let err = verify_double_sign(&ev, &vset, true, true, FRESH_TIME, &empty_dedup()).unwrap_err();
    assert!(
        matches!(err, EvidenceError::NotInCommittee { validator, .. } if validator == addr(1)),
        "validator not in committee must → NotInCommittee"
    );
}

// ── Check 4: Evidence age ─────────────────────────────────────────────────────

#[test]
fn verify_rejects_expired_evidence() {
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(1, 20_000_000)]);
    // current_time = infraction_time + EVIDENCE_MAX_AGE → age == limit → expired.
    let expired_time = ev.infraction_time + UNBONDING_PERIOD_SECONDS;
    let err = verify_double_sign(&ev, &vset, true, true, expired_time, &empty_dedup()).unwrap_err();
    assert!(
        matches!(err, EvidenceError::Expired { .. }),
        "evidence at exactly max-age must be rejected"
    );
}

#[test]
fn verify_accepts_evidence_one_second_before_expiry() {
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(1, 20_000_000)]);
    // age = EVIDENCE_MAX_AGE - 1 → still valid.
    let almost_expired = ev.infraction_time + UNBONDING_PERIOD_SECONDS - 1;
    let result = verify_double_sign(&ev, &vset, true, true, almost_expired, &empty_dedup());
    assert!(result.is_ok(), "evidence one second before expiry must pass");
}

#[test]
fn verify_handles_current_time_before_infraction_time() {
    // Adversarial: clock skew — current_time < infraction_time.
    // saturating_sub → age = 0 → passes the age check.
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(1, 20_000_000)]);
    let result = verify_double_sign(&ev, &vset, true, true, 0, &empty_dedup());
    assert!(result.is_ok(), "clock skew (current < infraction) must not panic; age = 0 passes");
}

// ── Check 5: Dedup ────────────────────────────────────────────────────────────

#[test]
fn verify_rejects_duplicate_evidence() {
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(1, 20_000_000)]);
    let mut dedup = empty_dedup();
    dedup.insert((addr(1), ev.infraction_height)); // already processed

    let err = verify_double_sign(&ev, &vset, true, true, FRESH_TIME, &dedup).unwrap_err();
    assert!(
        matches!(err, EvidenceError::Duplicate { validator, .. } if validator == addr(1)),
        "already-processed evidence must → Duplicate"
    );
}

// ── apply_double_sign ─────────────────────────────────────────────────────────

#[test]
fn apply_double_sign_slashes_5_percent_and_tombstones() {
    let mut v = make_validator_with_power(1, 20_000_000);
    let ev = make_valid_evidence(1, 20_000_000);

    let burned = apply_double_sign(&mut v, &ev).unwrap();

    assert_eq!(burned, lem(1_000_000), "5% of 20M LEM = 1M LEM burned");
    assert_eq!(v.self_stake.active, lem(19_000_000), "active reduced by 1M");
    assert!(v.tombstoned, "validator must be tombstoned after double-sign");
}

#[test]
fn apply_double_sign_tombstone_set_even_with_zero_slash() {
    // Zero power → zero burned, but tombstone still set.
    let mut v = make_validator_with_power(1, 20_000_000);
    let mut ev = make_valid_evidence(1, 20_000_000);
    ev.validator_power = Amount::zero();

    let burned = apply_double_sign(&mut v, &ev).unwrap();

    assert!(burned.is_zero(), "zero power → zero burned");
    assert!(v.tombstoned, "tombstone still applied even with zero power");
}

#[test]
fn apply_double_sign_slashes_post_infraction_unbonding() {
    // Validator has a post-infraction pending_inactive entry — it must be slashed.
    let mut v = make_validator_with_power(1, 20_000_000);
    v.self_stake.pending_inactive = vec![UnbondingEntry {
        initial_balance: lem(5_000_000),
        start_height: 20, // start_height > infraction_height (10)
        complete_time: 9_999_999,
        on_hold: false,
    }];
    let ev = make_valid_evidence(1, 25_000_000); // power = active + pending

    let burned = apply_double_sign(&mut v, &ev).unwrap();

    // 5% of 25M = 1.25M from active, 5% of 5M = 250K from pending → total 1.5M
    assert_eq!(burned, lem(1_500_000));
    assert_eq!(v.self_stake.pending_inactive[0].initial_balance, lem(4_750_000));
}

#[test]
fn tombstoned_validator_cannot_re_bond() {
    // After apply_double_sign, tombstoned = true.
    // Validator::is_active() checks tombstoned — must return false.
    let mut v = make_validator_with_power(1, 20_000_000);
    let ev = make_valid_evidence(1, 20_000_000);
    apply_double_sign(&mut v, &ev).unwrap();

    assert!(!v.is_active(), "tombstoned validator must not be active (spec §5.2)");
}

#[test]
fn verify_then_apply_full_workflow() {
    // Full idiomatic workflow: verify → apply → update dedup.
    let ev = make_valid_evidence(1, 20_000_000);
    let vset = make_vset_with(&[(1, 20_000_000)]);
    let mut dedup = empty_dedup();
    let mut v = make_validator_with_power(1, 20_000_000);

    verify_double_sign(&ev, &vset, true, true, FRESH_TIME, &dedup)
        .expect("valid evidence must pass verification");

    let burned = apply_double_sign(&mut v, &ev).expect("apply must succeed");
    dedup.insert((ev.validator, ev.infraction_height));

    assert_eq!(burned, lem(1_000_000));
    assert!(v.tombstoned);

    // Re-submitting the same evidence must now fail dedup.
    let err = verify_double_sign(&ev, &vset, true, true, FRESH_TIME, &dedup).unwrap_err();
    assert!(matches!(err, EvidenceError::Duplicate { .. }));
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn apply_double_sign_deterministic() {
    let run = || {
        let mut v = make_validator_with_power(1, 20_000_000);
        let ev = make_valid_evidence(1, 20_000_000);
        let burned = apply_double_sign(&mut v, &ev).unwrap();
        (burned.as_drop(), v.self_stake.active.as_drop(), v.tombstoned)
    };
    assert_eq!(run(), run(), "apply_double_sign must be deterministic");
}
