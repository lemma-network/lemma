//! Tests for `lemma_core::block`.
//!
//! Covers `Block`: construction, validation rules, predicates, accessors,
//! serde round-trips, and derived traits.
//! 100% public API coverage per AGENTS.md §11.1.

use super::*;
use crate::{
    address::Address,
    amount::Amount,
    cert::QuorumCert,
    error::BlockError,
    hash::Hash,
    header::BlockHeader,
    signature::Signature,
    transaction::{Transaction, TransactionReceipt, TxType},
};

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn state_root() -> Hash {
    Hash::from_bytes([0xABu8; 32])
}

fn base_fee() -> Amount {
    Amount::from_drop(1_000_000_000)
}

fn gas_price() -> Amount {
    Amount::from_drop(1_000_000_000)
}

/// Valid genesis header — 0 gas_used, matches an empty transaction list.
fn genesis_header() -> BlockHeader {
    BlockHeader::new(
        0,
        1_700_000_000,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        Address::zero(),
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

/// Valid non-genesis header — gas_used = 21_000 (one Transfer receipt).
fn block_1_header() -> BlockHeader {
    BlockHeader::new(
        1,
        1_700_000_001,
        Hash::from_bytes([0x01u8; 32]),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        Address::zero(),
        1,                              // epoch
        1,                              // protocol_version
        10,                             // dag_round
        Hash::from_bytes([0x0Au8; 32]), // dag_anchor
        Hash::from_bytes([0x0Bu8; 32]), // validators_hash
        Hash::from_bytes([0x0Bu8; 32]), // next_validators_hash (same epoch)
        30_000_000,
        21_000,
        base_fee(),
        vec![],
    )
    .unwrap()
}

/// Non-genesis header with gas_used = 42_000 (two Transfer receipts).
fn block_2_header() -> BlockHeader {
    BlockHeader::new(
        2,
        1_700_000_002,
        Hash::from_bytes([0x02u8; 32]),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        Address::zero(),
        1,                              // epoch
        1,                              // protocol_version
        11,                             // dag_round
        Hash::from_bytes([0x0Cu8; 32]), // dag_anchor
        Hash::from_bytes([0x0Bu8; 32]), // validators_hash
        Hash::from_bytes([0x0Bu8; 32]), // next_validators_hash (same epoch)
        30_000_000,
        42_000,
        base_fee(),
        vec![],
    )
    .unwrap()
}

/// One valid Transfer transaction.
fn transfer_tx() -> Transaction {
    Transaction::new(
        Hash::zero(),
        Address::zero(),
        Some(Address::burn()),
        0,
        1,
        Amount::zero(),
        21_000,
        gas_price(),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .unwrap()
}

/// Receipt matching `transfer_tx()` — gas_used = 21_000.
fn transfer_receipt() -> TransactionReceipt {
    TransactionReceipt::new(Hash::zero(), true, 21_000, vec![])
}

// ── Construction ──────────────────────────────────────────────────────────────

#[test]
fn new_empty_block_with_valid_header_succeeds() {
    let block = Block::new(genesis_header(), vec![], vec![], None);
    assert!(block.is_ok());
}

#[test]
fn new_block_with_one_tx_and_one_receipt_succeeds() {
    let block = Block::new(
        block_1_header(),
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    );
    assert!(block.is_ok());
}

#[test]
fn new_block_stores_all_fields_correctly() {
    let header = block_1_header();
    let txs = vec![transfer_tx()];
    let receipts = vec![transfer_receipt()];

    let block = Block::new(header.clone(), txs.clone(), receipts.clone(), None).unwrap();

    assert_eq!(block.header, header);
    assert_eq!(block.transactions, txs);
    assert_eq!(block.receipts, receipts);
}

// ── Validation failures ───────────────────────────────────────────────────────

#[test]
fn new_block_rejects_receipt_count_mismatch_more_receipts() {
    // 0 transactions, 1 receipt → mismatch
    let result = Block::new(genesis_header(), vec![], vec![transfer_receipt()], None);
    assert!(matches!(
        result.unwrap_err(),
        BlockError::ReceiptCountMismatch {
            transactions: 0,
            receipts: 1
        }
    ));
}

#[test]
fn new_block_rejects_receipt_count_mismatch_fewer_receipts() {
    // 1 transaction, 0 receipts → mismatch
    let result = Block::new(block_1_header(), vec![transfer_tx()], vec![], None);
    assert!(matches!(
        result.unwrap_err(),
        BlockError::ReceiptCountMismatch {
            transactions: 1,
            receipts: 0
        }
    ));
}

#[test]
fn new_block_rejects_gas_accounting_mismatch() {
    // header claims 99_000 gas used, but receipt only consumed 21_000
    let bad_header = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root(),
        Hash::zero(),
        Address::zero(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        30_000_000,
        99_000, // does not match receipt gas_used
        base_fee(),
        vec![],
    )
    .unwrap();
    let result = Block::new(
        bad_header,
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    );
    assert!(matches!(
        result.unwrap_err(),
        BlockError::GasAccountingMismatch {
            header_gas_used: 99_000,
            receipts_gas_used: 21_000
        }
    ));
}

#[test]
fn new_block_propagates_header_gas_limit_zero_error() {
    let bad_header = BlockHeader {
        height: 1,
        timestamp: 1_700_000_001,
        parent_hash: Hash::zero(),
        transactions_root: Hash::zero(),
        state_root: state_root(),
        receipts_root: Hash::zero(),
        proposer: Address::zero(),
        epoch: 0,
        protocol_version: 1,
        dag_round: 0,
        dag_anchor: Hash::zero(),
        validators_hash: Hash::zero(),
        next_validators_hash: Hash::zero(),
        gas_limit: 0, // invalid
        gas_used: 0,
        base_fee: base_fee(),
        extra_data: vec![],
    };
    let result = Block::new(bad_header, vec![], vec![], None);
    assert_eq!(result.unwrap_err(), BlockError::GasLimitZero);
}

#[test]
fn new_block_propagates_header_gas_exceeded_error() {
    let bad_header = BlockHeader {
        height: 1,
        timestamp: 1_700_000_001,
        parent_hash: Hash::zero(),
        transactions_root: Hash::zero(),
        state_root: state_root(),
        receipts_root: Hash::zero(),
        proposer: Address::zero(),
        epoch: 0,
        protocol_version: 1,
        dag_round: 0,
        dag_anchor: Hash::zero(),
        validators_hash: Hash::zero(),
        next_validators_hash: Hash::zero(),
        gas_limit: 1_000,
        gas_used: 2_000, // invalid
        base_fee: base_fee(),
        extra_data: vec![],
    };
    let result = Block::new(bad_header, vec![], vec![], None);
    assert!(matches!(
        result.unwrap_err(),
        BlockError::GasExceeded {
            used: 2_000,
            limit: 1_000
        }
    ));
}

// ── validate — happy path ─────────────────────────────────────────────────────

#[test]
fn validate_returns_ok_for_empty_block() {
    assert!(Block::new(genesis_header(), vec![], vec![], None)
        .unwrap()
        .validate()
        .is_ok());
}

#[test]
fn validate_returns_ok_for_block_with_transactions() {
    let block = Block::new(
        block_1_header(),
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    )
    .unwrap();
    assert!(block.validate().is_ok());
}

// ── validate — negative paths (direct construction bypasses new()) ────────────

#[test]
fn validate_rejects_receipt_count_mismatch_on_deserialized_block() {
    let block = Block {
        header: genesis_header(),
        transactions: vec![],
        receipts: vec![transfer_receipt()], // tampered: count mismatch
        quorum_cert: None,
    };
    assert!(matches!(
        block.validate().unwrap_err(),
        BlockError::ReceiptCountMismatch {
            transactions: 0,
            receipts: 1
        }
    ));
}

#[test]
fn validate_rejects_gas_limit_zero_on_deserialized_block() {
    let bad_header = BlockHeader {
        height: 1,
        timestamp: 1_700_000_001,
        parent_hash: Hash::zero(),
        transactions_root: Hash::zero(),
        state_root: state_root(),
        receipts_root: Hash::zero(),
        proposer: Address::zero(),
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
    let block = Block {
        header: bad_header,
        transactions: vec![],
        receipts: vec![],
        quorum_cert: None,
    };
    assert_eq!(block.validate().unwrap_err(), BlockError::GasLimitZero);
}

#[test]
fn validate_rejects_gas_exceeded_on_deserialized_block() {
    let bad_header = BlockHeader {
        height: 1,
        timestamp: 1_700_000_001,
        parent_hash: Hash::zero(),
        transactions_root: Hash::zero(),
        state_root: state_root(),
        receipts_root: Hash::zero(),
        proposer: Address::zero(),
        epoch: 0,
        protocol_version: 1,
        dag_round: 0,
        dag_anchor: Hash::zero(),
        validators_hash: Hash::zero(),
        next_validators_hash: Hash::zero(),
        gas_limit: 1_000,
        gas_used: 2_000, // tampered: exceeds limit
        base_fee: base_fee(),
        extra_data: vec![],
    };
    let block = Block {
        header: bad_header,
        transactions: vec![],
        receipts: vec![],
        quorum_cert: None,
    };
    assert!(matches!(
        block.validate().unwrap_err(),
        BlockError::GasExceeded {
            used: 2_000,
            limit: 1_000
        }
    ));
}

#[test]
fn validate_rejects_gas_accounting_mismatch_on_deserialized_block() {
    // Simulate a tampered block where header claims more gas than receipts consumed.
    let block = Block {
        header: block_1_header(), // gas_used = 21_000
        transactions: vec![transfer_tx()],
        receipts: vec![TransactionReceipt::new(Hash::zero(), true, 5_000, vec![])], // tampered
        quorum_cert: None,
    };
    assert!(matches!(
        block.validate().unwrap_err(),
        BlockError::GasAccountingMismatch {
            header_gas_used: 21_000,
            receipts_gas_used: 5_000
        }
    ));
}

// ── is_empty ──────────────────────────────────────────────────────────────────

#[test]
fn is_empty_returns_true_for_block_with_no_transactions() {
    let block = Block::new(genesis_header(), vec![], vec![], None).unwrap();
    assert!(block.is_empty());
}

#[test]
fn is_empty_returns_false_for_block_with_transactions() {
    let block = Block::new(
        block_1_header(),
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    )
    .unwrap();
    assert!(!block.is_empty());
}

// ── is_genesis ────────────────────────────────────────────────────────────────

#[test]
fn is_genesis_returns_true_for_height_zero_block() {
    let block = Block::new(genesis_header(), vec![], vec![], None).unwrap();
    assert!(block.is_genesis());
}

#[test]
fn is_genesis_returns_false_for_height_one_block() {
    let block = Block::new(
        block_1_header(),
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    )
    .unwrap();
    assert!(!block.is_genesis());
}

// ── transaction_count ─────────────────────────────────────────────────────────

#[test]
fn transaction_count_returns_zero_for_empty_block() {
    let block = Block::new(genesis_header(), vec![], vec![], None).unwrap();
    assert_eq!(block.transaction_count(), 0);
}

#[test]
fn transaction_count_returns_one_for_single_tx_block() {
    let block = Block::new(
        block_1_header(),
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    )
    .unwrap();
    assert_eq!(block.transaction_count(), 1);
}

#[test]
fn transaction_count_returns_correct_count_for_multi_tx_block() {
    // Two transactions — header gas_used must match sum of receipts (2 × 21_000 = 42_000).
    let block = Block::new(
        block_2_header(),
        vec![transfer_tx(), transfer_tx()],
        vec![transfer_receipt(), transfer_receipt()],
        None,
    )
    .unwrap();
    assert_eq!(block.transaction_count(), 2);
}

// ── height / timestamp ────────────────────────────────────────────────────────

#[test]
fn height_returns_header_height_for_genesis_block() {
    let block = Block::new(genesis_header(), vec![], vec![], None).unwrap();
    assert_eq!(block.height(), 0);
}

#[test]
fn height_returns_correct_value_for_non_genesis_block() {
    let block = Block::new(
        block_1_header(),
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    )
    .unwrap();
    assert_eq!(block.height(), 1);
}

#[test]
fn timestamp_returns_header_timestamp_for_genesis_block() {
    let block = Block::new(genesis_header(), vec![], vec![], None).unwrap();
    assert_eq!(block.timestamp(), 1_700_000_000);
}

#[test]
fn timestamp_returns_correct_value_for_non_genesis_block() {
    let block = Block::new(
        block_1_header(),
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    )
    .unwrap();
    assert_eq!(block.timestamp(), 1_700_000_001);
}

// ── Serde ─────────────────────────────────────────────────────────────────────

#[test]
fn empty_block_roundtrips_through_json() {
    let original = Block::new(genesis_header(), vec![], vec![], None).unwrap();
    let json = serde_json::to_string(&original).expect("Block should serialize to JSON");
    let decoded: Block = serde_json::from_str(&json).expect("Block should deserialize from JSON");
    assert_eq!(decoded, original);
}

#[test]
fn block_with_transactions_roundtrips_through_json() {
    let original = Block::new(
        block_1_header(),
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    )
    .unwrap();
    let json = serde_json::to_string(&original).expect("Block should serialize to JSON");
    let decoded: Block = serde_json::from_str(&json).expect("Block should deserialize from JSON");
    assert_eq!(decoded, original);
}

// ── Clone / PartialEq ─────────────────────────────────────────────────────────

#[test]
fn block_clone_equals_original() {
    let block = Block::new(genesis_header(), vec![], vec![], None).unwrap();
    assert_eq!(block.clone(), block);
}

#[test]
fn blocks_with_different_heights_are_not_equal() {
    let b0 = Block::new(genesis_header(), vec![], vec![], None).unwrap();
    let b1 = Block::new(
        block_1_header(),
        vec![transfer_tx()],
        vec![transfer_receipt()],
        None,
    )
    .unwrap();
    assert_ne!(b0, b1);
}

// ── quorum_cert field (D·15a) ─────────────────────────────────────────────────

/// Helper: a minimal QuorumCert for testing (no real signatures needed here —
/// we only test the Block wrapper, not crypto validity).
fn test_qc(height: u64) -> QuorumCert {
    use std::collections::BTreeMap;
    QuorumCert::new(height, Hash::from_bytes([0xCC; 32]), BTreeMap::new())
}

#[test]
fn block_with_some_quorum_cert_serializes_and_deserializes() {
    // Arrange: genesis block carrying a QC.
    let qc = test_qc(0);
    let original = Block::new(genesis_header(), vec![], vec![], Some(qc)).unwrap();

    // Act: JSON roundtrip.
    let json = serde_json::to_string(&original).expect("serialize");
    let decoded: Block = serde_json::from_str(&json).expect("deserialize");

    // Assert: roundtrip equality and QC preserved.
    assert_eq!(decoded, original);
    assert!(decoded.quorum_cert.is_some());
}

#[test]
fn block_without_quorum_cert_serializes_and_deserializes() {
    // Arrange: genesis block with no QC (Phase 1 / uncertified range-sync).
    let original = Block::new(genesis_header(), vec![], vec![], None).unwrap();

    // Act: JSON roundtrip.
    let json = serde_json::to_string(&original).expect("serialize");
    let decoded: Block = serde_json::from_str(&json).expect("deserialize");

    // Assert: roundtrip equality and QC absent.
    assert_eq!(decoded, original);
    assert!(decoded.quorum_cert.is_none());
}

#[test]
fn block_validate_ignores_quorum_cert_field() {
    // validate() checks only structural invariants — QC is irrelevant.
    let with_qc = Block::new(genesis_header(), vec![], vec![], Some(test_qc(0))).unwrap();
    let without_qc = Block::new(genesis_header(), vec![], vec![], None).unwrap();
    // Both pass validate() — the QC field does not affect structural checks.
    assert!(with_qc.validate().is_ok());
    assert!(without_qc.validate().is_ok());
}
