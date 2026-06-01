//! Tests for `lemma_consensus::epoch::recovery` — force_epoch_close §6 (B4b).
//!
//! ## Coverage (spec §10)
//!
//! - Accepts ≥ 2f+1 cert → applies settlement → returns RecoveryOutput.
//! - Rejects < 2f+1 cert → Err(InsufficientQuorum), no state change.
//! - Rejects rollback: at_commit_index > last_final → Err(RollbackForbidden), no change.
//! - Rejects replay: already in dedup set → Err(Duplicate), no state change.
//! - Two nodes with identical inputs → identical EpochOutput (determinism).
//! - RecoveryOutput carries the cert + at_commit_index.
//! - Uses standard advance_epoch settlement (EpochOutput fields match).

use std::collections::{BTreeMap, BTreeSet};

use lemma_core::{
    address::Address,
    amount::{Amount, DROPS_PER_LEM},
    hash::Hash,
    signature::Signature,
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus, VotingPower},
    validator_set::{Member, ValidatorSet},
    Epoch, QuorumCert,
};

use crate::epoch::{
    recovery::{force_epoch_close, RecoveryError},
    GENESIS_MIN_VALIDATOR_STAKE_DROP,
};

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

fn min_stake() -> Amount {
    Amount::from_drop(GENESIS_MIN_VALIDATOR_STAKE_DROP)
}

fn make_validator(n: u8, active_lem: u128) -> Validator {
    Validator {
        address: addr(n),
        consensus_pubkey: ConsensusKey::from_bytes(vec![n; 32], vec![n; 32]),
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

fn make_vset(members: &[(u8, u128)]) -> ValidatorSet {
    let map: BTreeMap<_, _> = members
        .iter()
        .map(|&(b, p)| {
            (addr(b), Member {
                consensus_pubkey: ConsensusKey::from_bytes(vec![b; 32], vec![b; 32]),
                power: VotingPower(lem(p)),
            })
        })
        .collect();
    let total = map.values().fold(Amount::zero(), |a, m| {
        a.checked_add(m.power.as_amount()).unwrap()
    });
    ValidatorSet { epoch: 0, members: map, total_power: total }
}

fn make_epoch(number: u64, validators: &BTreeMap<Address, Validator>) -> Epoch {
    let members: BTreeMap<_, _> = validators
        .iter()
        .filter(|(_, v)| v.is_active())
        .map(|(a, v)| {
            (*a, Member {
                consensus_pubkey: v.consensus_pubkey.clone(),
                power: v.voting_power().unwrap(),
            })
        })
        .collect();
    let total = members
        .values()
        .fold(Amount::zero(), |a, m| a.checked_add(m.power.as_amount()).unwrap());
    Epoch {
        number,
        start_height: 0,
        start_timestamp: 0,
        validators: ValidatorSet { epoch: number, members, total_power: total },
    }
}

fn make_cert(digest: Hash, signers: &[u8]) -> QuorumCert {
    let map = signers.iter().map(|&b| (addr(b), Signature::Unsigned)).collect();
    QuorumCert::new(0, digest, map)
}

fn all_valid(signers: &[u8]) -> BTreeMap<Address, bool> {
    signers.iter().map(|&b| (addr(b), true)).collect()
}

fn empty_dedup() -> BTreeSet<(u64, u64)> {
    BTreeSet::new()
}

const BLOCK_TIME: u64 = 1_000_000;
const BLOCK_HEIGHT: u64 = 50_000;

/// A recognisable injected recovery message digest (simulates lemma-crypto output).
fn recovery_digest() -> Hash {
    Hash::from_bytes([0xDE; 32]) // 0xDE = "DE"terministic recovery marker
}

/// Standard 3-validator setup: [1,2,3] each with 25M LEM (well above min_stake 20M).
fn three_validator_setup() -> (BTreeMap<Address, Validator>, Epoch) {
    let specs = [(1u8, 25_000_000u128), (2, 25_000_000), (3, 25_000_000)];
    let vs: BTreeMap<_, _> = specs
        .iter()
        .map(|&(b, l)| (addr(b), make_validator(b, l)))
        .collect();
    let epoch = make_epoch(0, &vs);
    (vs, epoch)
}

// ── Happy path ────────────────────────────────────────────────────────────────

/// spec §10: recovery with ≥ 2f+1 cert applies settlement and returns output.
#[test]
fn force_epoch_close_valid_cert_applies_settlement() {
    let (mut vs, epoch) = three_validator_setup();
    let digest = recovery_digest();
    let cert = make_cert(digest, &[1, 2, 3]); // all 3 signers, total 75M > 2/3*75M=50M
    let sigs = all_valid(&[1, 2, 3]);

    let out = force_epoch_close(
        &epoch, &mut vs, &[],
        Amount::zero(),  // zero supply → zero inflation (simplifies test)
        10,              // at_commit_index
        10,              // last_final_commit_index
        cert.clone(), digest, &sigs,
        &empty_dedup(),
        BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    ).unwrap();

    assert_eq!(out.epoch_output.epoch.number, 1, "settlement must advance to epoch 1");
    assert_eq!(out.at_commit_index, 10);
    assert_eq!(out.recovery_cert, cert, "cert returned in output for caller to persist");
}

#[test]
fn force_epoch_close_output_next_validators_hash_matches_vset() {
    let (mut vs, epoch) = three_validator_setup();
    let digest = recovery_digest();
    let cert = make_cert(digest, &[1, 2, 3]);

    let out = force_epoch_close(
        &epoch, &mut vs, &[], Amount::zero(),
        5, 5, cert, digest, &all_valid(&[1, 2, 3]),
        &empty_dedup(), BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    ).unwrap();

    assert_eq!(
        out.epoch_output.next_validators_hash,
        out.epoch_output.epoch.validators.hash(),
        "next_validators_hash must match actual ValidatorSet(N+1).hash()"
    );
}

// ── Pre-check 1: Insufficient quorum ─────────────────────────────────────────

/// spec §10: "Accepts only a ≥ 2f+1 cert; a < 2f+1 cert is rejected."
#[test]
fn force_epoch_close_rejects_insufficient_quorum() {
    let (mut vs, epoch) = three_validator_setup();
    let digest = recovery_digest();
    // Only 2 signers = 50M, total 75M. 50*3 = 150 not > 75*2 = 150 → exactly at threshold, not enough.
    let cert = make_cert(digest, &[1, 2]);
    let sigs = all_valid(&[1, 2]);
    let initial_active = vs[&addr(1)].self_stake.active;

    let err = force_epoch_close(
        &epoch, &mut vs, &[], Amount::zero(),
        5, 5, cert, digest, &sigs,
        &empty_dedup(), BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    ).unwrap_err();

    assert!(
        matches!(err, RecoveryError::InsufficientQuorum { .. }),
        "< 2f+1 cert must → InsufficientQuorum"
    );
    // State must be unchanged (atomicity: pre-checks before any mutation).
    assert_eq!(
        vs[&addr(1)].self_stake.active, initial_active,
        "validator state must be unchanged after rejected recovery"
    );
}

#[test]
fn force_epoch_close_rejects_zero_signers() {
    let (mut vs, epoch) = three_validator_setup();
    let digest = recovery_digest();
    let cert = make_cert(digest, &[]); // no signers

    let err = force_epoch_close(
        &epoch, &mut vs, &[], Amount::zero(),
        5, 5, cert, digest, &BTreeMap::new(),
        &empty_dedup(), BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    ).unwrap_err();

    assert!(matches!(err, RecoveryError::InsufficientQuorum { .. }));
}

// ── Pre-check 2: Rollback forbidden ──────────────────────────────────────────

/// spec §10: "Closes only at an already-final commit; rolling back final is rejected."
#[test]
fn force_epoch_close_rejects_at_commit_index_above_last_final() {
    let (mut vs, epoch) = three_validator_setup();
    let digest = recovery_digest();
    let cert = make_cert(digest, &[1, 2, 3]);

    let err = force_epoch_close(
        &epoch, &mut vs, &[], Amount::zero(),
        100,  // at_commit_index = 100
        99,   // last_final_commit_index = 99 (below 100!)
        cert, digest, &all_valid(&[1, 2, 3]),
        &empty_dedup(), BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    ).unwrap_err();

    assert!(
        matches!(
            err,
            RecoveryError::RollbackForbidden {
                at_commit_index: 100,
                last_final_commit_index: 99,
            }
        ),
        "at_commit > last_final must → RollbackForbidden"
    );
}

#[test]
fn force_epoch_close_accepts_at_commit_exactly_equal_to_last_final() {
    let (mut vs, epoch) = three_validator_setup();
    let digest = recovery_digest();
    let cert = make_cert(digest, &[1, 2, 3]);

    // at_commit == last_final → closing AT a finalized commit (allowed).
    let result = force_epoch_close(
        &epoch, &mut vs, &[], Amount::zero(),
        50, 50, // equal → closing AT the final commit
        cert, digest, &all_valid(&[1, 2, 3]),
        &empty_dedup(), BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    );

    assert!(result.is_ok(), "at_commit == last_final must be accepted");
}

// ── Pre-check 3: Replay prevention ───────────────────────────────────────────

/// spec §10: "Replay of an old recovery message is rejected (uniqueness)."
#[test]
fn force_epoch_close_rejects_duplicate() {
    let (mut vs, epoch) = three_validator_setup();
    let digest = recovery_digest();
    let cert = make_cert(digest, &[1, 2, 3]);

    // Simulate: (epoch=0, commit=5) already applied.
    let mut dedup = BTreeSet::new();
    dedup.insert((0u64, 5u64));

    let err = force_epoch_close(
        &epoch, &mut vs, &[], Amount::zero(),
        5, 5,
        cert, digest, &all_valid(&[1, 2, 3]),
        &dedup, BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    ).unwrap_err();

    assert!(
        matches!(
            err,
            RecoveryError::Duplicate { epoch_number: 0, at_commit_index: 5 }
        ),
        "already-processed recovery must → Duplicate"
    );
}

#[test]
fn force_epoch_close_different_commit_index_not_duplicate() {
    let (mut vs, epoch) = three_validator_setup();
    let digest = recovery_digest();
    let cert = make_cert(digest, &[1, 2, 3]);

    // (epoch=0, commit=5) in dedup, but we're closing at commit=10 → different key.
    let mut dedup = BTreeSet::new();
    dedup.insert((0u64, 5u64));

    let result = force_epoch_close(
        &epoch, &mut vs, &[], Amount::zero(),
        10, 10,  // different commit index → not in dedup
        cert, digest, &all_valid(&[1, 2, 3]),
        &dedup, BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    );

    assert!(result.is_ok(), "different commit index must not be treated as duplicate");
}

// ── Ordering: pre-checks run before settlement ────────────────────────────────

#[test]
fn state_unchanged_after_rollback_forbidden() {
    let (mut vs, epoch) = three_validator_setup();
    let initial_epoch = vs[&addr(1)].self_stake.active;
    let digest = recovery_digest();
    let cert = make_cert(digest, &[1, 2, 3]);

    force_epoch_close(
        &epoch, &mut vs, &[], Amount::zero(),
        999, 5, // at_commit > last_final → rejected
        cert, digest, &all_valid(&[1, 2, 3]),
        &empty_dedup(), BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    ).unwrap_err();

    assert_eq!(
        vs[&addr(1)].self_stake.active, initial_epoch,
        "validator state must be unchanged after pre-check failure"
    );
}

// ── Digest mismatch gate ─────────────────────────────────────────────────────

/// When `recovery_cert_digest` ≠ `cert.header_digest`, the quorum check
/// must fail with InsufficientQuorum (wrapping DigestMismatch). This locks
/// in the contract that the digest gate is wired through force_epoch_close,
/// not just verify_quorum_cert in isolation.
#[test]
fn force_epoch_close_rejects_wrong_recovery_cert_digest() {
    let (mut vs, epoch) = three_validator_setup();
    let cert_digest = recovery_digest();
    let wrong_digest = hash(0xFF); // different from cert_digest
    let cert = make_cert(cert_digest, &[1, 2, 3]);

    let err = force_epoch_close(
        &epoch, &mut vs, &[], Amount::zero(),
        5, 5,
        cert,
        wrong_digest, // wrong expected digest → DigestMismatch inside CertError
        &all_valid(&[1, 2, 3]),
        &empty_dedup(), BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
    ).unwrap_err();

    // The quorum check fails because cert.header_digest ≠ wrong_digest.
    assert!(
        matches!(err, RecoveryError::InsufficientQuorum { .. }),
        "wrong recovery_cert_digest must → InsufficientQuorum (wrapping DigestMismatch)"
    );
}

// ── Determinism ───────────────────────────────────────────────────────────────

/// spec §10: "Two nodes applying the same recovery resume on identical state."
#[test]
fn force_epoch_close_deterministic_same_inputs_same_output() {
    let run = || {
        let (mut vs, epoch) = three_validator_setup();
        let digest = recovery_digest();
        let cert = make_cert(digest, &[1, 2, 3]);
        let out = force_epoch_close(
            &epoch, &mut vs, &[], Amount::zero(),
            10, 10,
            cert, digest, &all_valid(&[1, 2, 3]),
            &empty_dedup(), BLOCK_TIME, BLOCK_HEIGHT, min_stake(),
        ).unwrap();
        out.epoch_output.next_validators_hash
    };

    assert_eq!(run(), run(), "force_epoch_close must be deterministic");
}
