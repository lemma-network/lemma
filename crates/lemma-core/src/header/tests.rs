//! Tests for `lemma_core::header`.
//!
//! Covers `BlockHeader`: construction, validation rules, predicates,
//! gas accounting, serde round-trips, and derived traits.
//! 100% public API coverage per AGENTS.md §11.1.

use super::*;
use crate::{address::Address, amount::Amount, hash::Hash};

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn state_root() -> Hash {
    Hash::from_bytes([0xABu8; 32])
}

fn proposer() -> Address {
    Address::zero()
}

fn base_fee() -> Amount {
    Amount::from_drop(1_000_000_000) // 1 Drip
}

/// Minimal valid genesis header (height 0, gas_used 0).
fn genesis_header() -> BlockHeader {
    BlockHeader::new(
        0,
        1_700_000_000,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,            // epoch
        1,            // protocol_version (genesis = 1)
        0,            // dag_round
        Hash::zero(), // dag_anchor
        Hash::zero(), // validators_hash
        Hash::zero(), // next_validators_hash
        30_000_000,
        0,
        base_fee(),
        vec![],
    )
    .unwrap()
}

/// Minimal valid non-genesis header (height 1, gas_used exactly at 50%).
fn block_1_header() -> BlockHeader {
    BlockHeader::new(
        1,
        1_700_000_001,
        Hash::from_bytes([0x01u8; 32]), // parent = some block hash
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        1,                              // epoch
        1,                              // protocol_version
        10,                             // dag_round
        Hash::from_bytes([0x0Au8; 32]), // dag_anchor
        Hash::from_bytes([0x0Bu8; 32]), // validators_hash
        Hash::from_bytes([0x0Bu8; 32]), // next_validators_hash (same epoch)
        30_000_000,
        15_000_000, // exactly 50% — not above target
        base_fee(),
        vec![],
    )
    .unwrap()
}

// ── Construction ──────────────────────────────────────────────────────────────

#[test]
fn new_genesis_header_with_valid_fields_succeeds() {
    let h = genesis_header();
    assert_eq!(h.height, 0);
    assert_eq!(h.gas_used, 0);
    assert_eq!(h.gas_limit, 30_000_000);
}

#[test]
fn new_non_genesis_header_with_valid_fields_succeeds() {
    let h = block_1_header();
    assert_eq!(h.height, 1);
    assert_eq!(h.gas_used, 15_000_000);
}

#[test]
fn new_header_with_gas_used_equal_to_limit_succeeds() {
    let result = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        21_000,
        21_000, // gas_used == gas_limit is valid
        base_fee(),
        vec![],
    );
    assert!(result.is_ok());
}

#[test]
fn new_header_stores_all_fields_correctly() {
    let extra = vec![0x01, 0x02, 0x03];
    let tx_root = Hash::from_bytes([0xBBu8; 32]);
    let rcpt_root = Hash::from_bytes([0xCCu8; 32]);
    let custom_fee = Amount::from_drop(2_000_000_000);
    let anchor = Hash::from_bytes([0xD0u8; 32]);
    let validators = Hash::from_bytes([0xE0u8; 32]);
    let next_validators = Hash::from_bytes([0xF0u8; 32]);

    let h = BlockHeader::new(
        5,
        1_700_005_000,
        Hash::zero(),
        tx_root,
        state_root(),
        rcpt_root,
        Address::burn(),
        3,  // epoch
        1,  // protocol_version
        77, // dag_round
        anchor,
        validators,
        next_validators,
        50_000_000,
        10_000_000,
        custom_fee,
        extra.clone(),
    )
    .unwrap();

    assert_eq!(h.height, 5);
    assert_eq!(h.timestamp, 1_700_005_000);
    assert_eq!(h.parent_hash, Hash::zero());
    assert_eq!(h.transactions_root, tx_root);
    assert_eq!(h.state_root, state_root());
    assert_eq!(h.receipts_root, rcpt_root);
    assert_eq!(h.proposer, Address::burn());
    assert_eq!(h.epoch, 3);
    assert_eq!(h.protocol_version, 1);
    assert_eq!(h.dag_round, 77);
    assert_eq!(h.dag_anchor, anchor);
    assert_eq!(h.validators_hash, validators);
    assert_eq!(h.next_validators_hash, next_validators);
    assert_eq!(h.gas_limit, 50_000_000);
    assert_eq!(h.gas_used, 10_000_000);
    assert_eq!(h.base_fee, custom_fee);
    assert_eq!(h.extra_data, extra);
}

// ── Consensus provenance / committee commitments ─────────────────────────────

#[test]
fn new_header_stores_consensus_provenance_fields() {
    let anchor = Hash::from_bytes([0x11u8; 32]);
    let validators = Hash::from_bytes([0x22u8; 32]);
    let next_validators = Hash::from_bytes([0x33u8; 32]);

    let h = BlockHeader::new(
        9,
        1_700_009_000,
        Hash::from_bytes([0x09u8; 32]),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        4,   // epoch
        1,   // protocol_version
        128, // dag_round
        anchor,
        validators,
        next_validators,
        30_000_000,
        0,
        base_fee(),
        vec![],
    )
    .unwrap();

    assert_eq!(h.epoch, 4);
    assert_eq!(h.dag_round, 128);
    assert_eq!(h.dag_anchor, anchor);
    assert_eq!(h.validators_hash, validators);
    assert_eq!(h.next_validators_hash, next_validators);
}

#[test]
fn genesis_header_has_zero_consensus_provenance() {
    let h = genesis_header();
    assert_eq!(h.epoch, 0);
    assert_eq!(h.dag_round, 0);
    assert_eq!(h.dag_anchor, Hash::zero());
    assert_eq!(h.validators_hash, Hash::zero());
    assert_eq!(h.next_validators_hash, Hash::zero());
}

// ── Validation failures ───────────────────────────────────────────────────────

#[test]
fn new_header_rejects_zero_gas_limit() {
    let result = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        0, // gas_limit = 0 — invalid
        0,
        base_fee(),
        vec![],
    );
    assert_eq!(result.unwrap_err(), BlockError::GasLimitZero);
}

#[test]
fn new_header_rejects_gas_used_exceeding_gas_limit() {
    let result = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        21_000,
        21_001, // gas_used > gas_limit
        base_fee(),
        vec![],
    );
    assert!(matches!(
        result.unwrap_err(),
        BlockError::GasExceeded {
            used: 21_001,
            limit: 21_000
        }
    ));
}

// ── validate — happy path ─────────────────────────────────────────────────────

#[test]
fn validate_returns_ok_for_valid_genesis_header() {
    assert!(genesis_header().validate().is_ok());
}

#[test]
fn validate_returns_ok_for_valid_non_genesis_header() {
    assert!(block_1_header().validate().is_ok());
}

// ── validate — negative paths (direct construction bypasses new()) ────────────

#[test]
fn validate_rejects_zero_gas_limit_on_deserialized_header() {
    // Bypass new() to simulate a tampered deserialized header — the exact
    // scenario validate() guards against post-deserialization.
    let h = BlockHeader {
        height: 1,
        timestamp: 1_700_000_001,
        parent_hash: Hash::zero(),
        transactions_root: Hash::zero(),
        state_root: state_root(),
        receipts_root: Hash::zero(),
        proposer: proposer(),
        epoch: 0,
        protocol_version: 1,
        dag_round: 0,
        dag_anchor: Hash::zero(),
        validators_hash: Hash::zero(),
        next_validators_hash: Hash::zero(),
        gas_limit: 0, // tampered
        gas_used: 0,
        base_fee: base_fee(),
        extra_data: vec![],
    };
    assert_eq!(h.validate().unwrap_err(), BlockError::GasLimitZero);
}

#[test]
fn validate_rejects_gas_exceeded_on_deserialized_header() {
    let h = BlockHeader {
        height: 1,
        timestamp: 1_700_000_001,
        parent_hash: Hash::zero(),
        transactions_root: Hash::zero(),
        state_root: state_root(),
        receipts_root: Hash::zero(),
        proposer: proposer(),
        epoch: 0,
        protocol_version: 1,
        dag_round: 0,
        dag_anchor: Hash::zero(),
        validators_hash: Hash::zero(),
        next_validators_hash: Hash::zero(),
        gas_limit: 1_000,
        gas_used: 2_000, // tampered
        base_fee: base_fee(),
        extra_data: vec![],
    };
    assert!(matches!(
        h.validate().unwrap_err(),
        BlockError::GasExceeded {
            used: 2_000,
            limit: 1_000
        }
    ));
}

// ── is_genesis ────────────────────────────────────────────────────────────────

#[test]
fn is_genesis_returns_true_for_height_zero() {
    assert!(genesis_header().is_genesis());
}

#[test]
fn is_genesis_returns_false_for_height_one() {
    assert!(!block_1_header().is_genesis());
}

#[test]
fn is_genesis_returns_false_for_large_height() {
    let mut h = genesis_header();
    h.height = 1_000_000;
    assert!(!h.is_genesis());
}

// ── is_above_target_gas ───────────────────────────────────────────────────────

#[test]
fn is_above_target_gas_false_when_gas_used_is_zero() {
    assert!(!genesis_header().is_above_target_gas());
}

#[test]
fn is_above_target_gas_false_when_gas_used_equals_target() {
    // gas_limit = 30_000_000 → target = 15_000_000
    // gas_used = 15_000_000 — equal to target, not above it
    assert!(!block_1_header().is_above_target_gas());
}

#[test]
fn is_above_target_gas_true_when_gas_used_exceeds_half() {
    let h = BlockHeader::new(
        2,
        1_700_000_002,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        30_000_000,
        15_000_001, // one unit above target
        base_fee(),
        vec![],
    )
    .unwrap();
    assert!(h.is_above_target_gas());
}

#[test]
fn is_above_target_gas_true_when_block_is_full() {
    let h = BlockHeader::new(
        2,
        1_700_000_002,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        30_000_000,
        30_000_000, // 100% full
        base_fee(),
        vec![],
    )
    .unwrap();
    assert!(h.is_above_target_gas());
}

#[test]
fn is_above_target_gas_false_when_gas_limit_is_one_and_gas_used_is_zero() {
    // gas_limit=1 → target = 1/2 = 0 (truncates). gas_used=0 → 0 > 0 is false.
    let h = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        1,
        0,
        base_fee(),
        vec![],
    )
    .unwrap();
    assert!(!h.is_above_target_gas());
}

#[test]
fn is_above_target_gas_true_when_gas_limit_is_one_and_gas_used_is_one() {
    // gas_limit=1 → target = 0. gas_used=1 → 1 > 0 is true.
    let h = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        1,
        1,
        base_fee(),
        vec![],
    )
    .unwrap();
    assert!(h.is_above_target_gas());
}

// ── gas_remaining ─────────────────────────────────────────────────────────────

#[test]
fn gas_remaining_equals_limit_when_gas_used_is_zero() {
    assert_eq!(genesis_header().gas_remaining(), 30_000_000);
}

#[test]
fn gas_remaining_returns_correct_headroom() {
    assert_eq!(block_1_header().gas_remaining(), 15_000_000);
}

#[test]
fn gas_remaining_is_zero_when_block_is_full() {
    let h = BlockHeader::new(
        2,
        1_700_000_002,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        21_000,
        21_000,
        base_fee(),
        vec![],
    )
    .unwrap();
    assert_eq!(h.gas_remaining(), 0);
}

#[test]
fn gas_remaining_is_correct_at_max_gas_limit() {
    // Verifies the subtraction doesn't overflow at the u64 boundary.
    // validate() guarantees gas_used <= gas_limit, making this subtraction safe.
    let h = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        u64::MAX,
        u64::MAX - 1,
        base_fee(),
        vec![],
    )
    .unwrap();
    assert_eq!(h.gas_remaining(), 1);
}

// ── Serde ─────────────────────────────────────────────────────────────────────

#[test]
fn genesis_header_roundtrips_through_json() {
    let original = genesis_header();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: BlockHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn header_consensus_provenance_survives_json_roundtrip() {
    // block_1_header carries non-zero epoch/dag_round/dag_anchor/validators —
    // confirm the new commitments round-trip rather than defaulting to zero.
    let original = block_1_header();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: BlockHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.epoch, original.epoch);
    assert_eq!(decoded.dag_round, original.dag_round);
    assert_eq!(decoded.dag_anchor, original.dag_anchor);
    assert_eq!(decoded.validators_hash, original.validators_hash);
    assert_eq!(decoded.next_validators_hash, original.next_validators_hash);
}

#[test]
fn header_with_extra_data_roundtrips_through_json() {
    let original = BlockHeader::new(
        3,
        1_700_000_003,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        proposer(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        30_000_000,
        5_000_000,
        base_fee(),
        vec![0x1E, 0x8A, 0xAA],
    )
    .unwrap();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: BlockHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

// ── Clone / PartialEq ─────────────────────────────────────────────────────────

#[test]
fn header_clone_equals_original() {
    let h = genesis_header();
    assert_eq!(h.clone(), h);
}

#[test]
fn headers_with_different_heights_are_not_equal() {
    let h0 = genesis_header();
    let h1 = block_1_header();
    assert_ne!(h0, h1);
}

#[test]
fn headers_with_different_state_roots_are_not_equal() {
    let h1 = genesis_header();
    let mut h2 = genesis_header();
    h2.state_root = Hash::from_bytes([0xFFu8; 32]);
    assert_ne!(h1, h2);
}

// ── protocol_version (docs/17-VERSIONING_SPEC §7) ────────────────────────────

#[test]
fn protocol_version_in_genesis_is_one() {
    let h = genesis_header();
    assert_eq!(
        h.protocol_version, 1,
        "genesis protocol_version must be 1 (§7.2)"
    );
}

#[test]
fn protocol_version_is_serialized() {
    // Serialize a header, deserialize, assert protocol_version preserved.
    let h = genesis_header();
    let json = serde_json::to_string(&h).unwrap();
    let decoded: BlockHeader = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded.protocol_version, h.protocol_version);
}

#[test]
fn protocol_version_affects_digest() {
    // Two headers identical except protocol_version must produce different
    // canonical digests — protocol_version is bound into BlockHeader::digest()
    // (docs/17-VERSIONING_SPEC §7.2; P3·Step 23).
    let h1 = genesis_header();
    let mut h2 = genesis_header();
    h2.protocol_version = 2;
    assert_ne!(
        h1.digest(),
        h2.digest(),
        "different protocol_version must produce different canonical digest"
    );
}

// ── digest() — canonical header commitment (docs/12-NETWORK_SYNC_SPEC §3.2) ───

#[test]
fn digest_is_deterministic_for_same_header() {
    // Same header → same digest across two independent computations.
    let h = block_1_header();
    assert_eq!(
        h.digest(),
        h.digest(),
        "digest must be deterministic for identical input"
    );
    // And a freshly constructed equal header yields the same digest.
    assert_eq!(block_1_header().digest(), h.digest());
}

#[test]
fn digest_is_nonzero_for_genesis() {
    // Sanity: the hand-framed Blake3 digest is not the zero hash.
    assert!(!genesis_header().digest().is_zero());
}

#[test]
fn digest_changes_when_any_field_changes() {
    // Mutate EACH field in turn (incl. protocol_version) and assert the digest
    // diverges from the baseline — proves every field is bound into the digest.
    let base = block_1_header();
    let base_digest = base.digest();

    // Each closure produces a header that differs from `base` in exactly one
    // field. Distinct sentinel values are chosen to be unequal to the base.
    type FieldMutator = fn(&mut BlockHeader);
    let mutators: Vec<(&str, FieldMutator)> = vec![
        ("height", |h| h.height = h.height.wrapping_add(1)),
        ("timestamp", |h| h.timestamp = h.timestamp.wrapping_add(1)),
        ("parent_hash", |h| {
            h.parent_hash = Hash::from_bytes([0x77u8; 32])
        }),
        ("transactions_root", |h| {
            h.transactions_root = Hash::from_bytes([0x78u8; 32])
        }),
        ("state_root", |h| {
            h.state_root = Hash::from_bytes([0x79u8; 32])
        }),
        ("receipts_root", |h| {
            h.receipts_root = Hash::from_bytes([0x7Au8; 32])
        }),
        ("proposer", |h| h.proposer = Address::burn()),
        ("epoch", |h| h.epoch = h.epoch.wrapping_add(1)),
        ("protocol_version", |h| {
            h.protocol_version = h.protocol_version.wrapping_add(1)
        }),
        ("dag_round", |h| h.dag_round = h.dag_round.wrapping_add(1)),
        ("dag_anchor", |h| {
            h.dag_anchor = Hash::from_bytes([0x7Bu8; 32])
        }),
        ("validators_hash", |h| {
            h.validators_hash = Hash::from_bytes([0x7Cu8; 32])
        }),
        ("next_validators_hash", |h| {
            h.next_validators_hash = Hash::from_bytes([0x7Du8; 32])
        }),
        // gas fields kept valid (gas_used <= gas_limit) so digest() never
        // depends on validate(); digest() hashes raw fields regardless.
        ("gas_limit", |h| h.gas_limit = h.gas_limit.wrapping_add(1)),
        ("gas_used", |h| h.gas_used = h.gas_used.wrapping_add(1)),
        ("base_fee", |h| {
            h.base_fee = Amount::from_drop(h.base_fee.as_drop() + 1)
        }),
        ("extra_data", |h| h.extra_data = vec![0xEEu8]),
    ];

    for (field, mutate) in mutators {
        let mut mutated = base.clone();
        mutate(&mut mutated);
        assert_ne!(
            mutated.digest(),
            base_digest,
            "mutating `{field}` must change the canonical digest"
        );
    }
}

#[test]
fn digest_distinguishes_extra_data_length_boundary() {
    // The length-prefix on extra_data must prevent concatenation ambiguity:
    // two headers whose extra_data differ only in framing must differ.
    let mut a = genesis_header();
    let mut b = genesis_header();
    a.extra_data = vec![0x01, 0x02];
    b.extra_data = vec![0x01, 0x02, 0x03];
    assert_ne!(a.digest(), b.digest());

    // Empty vs single-zero-byte extra_data must also differ (length prefix).
    let mut c = genesis_header();
    let mut d = genesis_header();
    c.extra_data = vec![];
    d.extra_data = vec![0x00];
    assert_ne!(c.digest(), d.digest());
}

#[test]
fn digest_golden_vector_for_genesis_header() {
    // BYTE-STABILITY GOLDEN VECTOR. This pins the canonical digest of a fixed
    // genesis-like header. If this value changes, the header digest framing
    // changed — which is a CONSENSUS-BREAKING, network-forking change. Such a
    // change is only acceptable as a deliberate pre-mainnet re-baseline
    // (docs/17-VERSIONING_SPEC §7.2); update this vector intentionally, never
    // to "make the test pass".
    //
    // Canonical 17-field byte layout (so an independent impl — e.g. a TS/Py
    // light client — can re-derive this vector by hand, NOT by trusting the Rust
    // impl that produced it). All ints big-endian; hashes/addresses raw bytes:
    //   height u64 BE | timestamp u64 BE | parent_hash 32B | transactions_root 32B
    //   | state_root 32B | receipts_root 32B | proposer 20B (Address = [u8;20])
    //   | epoch u64 BE | protocol_version u32 BE | dag_round u64 BE | dag_anchor 32B
    //   | validators_hash 32B | next_validators_hash 32B | gas_limit u64 BE
    //   | gas_used u64 BE | base_fee u128 BE (inner Drop) | extra_data: len u64 BE
    //   then bytes. blake3 over the concatenation.
    let h = genesis_header();
    let expected = "7bf2709f1d4669e48d085adb6a777fed18d138a0113f643aff08a7c1d260d557";
    assert_eq!(
        h.digest().to_hex(),
        expected,
        "genesis header digest must be byte-stable"
    );
}
