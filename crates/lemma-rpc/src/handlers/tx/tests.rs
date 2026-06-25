//! Tests for transaction handlers: `lem_sendTransaction`, `lem_getTransactionReceipt`.

use std::sync::Arc;

use serde_json::json;
use tempfile::tempdir;
use tokio::sync::RwLock;

use lemma_core::{
    address::Address,
    amount::Amount,
    block::Block,
    hash::Hash,
    header::BlockHeader,
    transaction::{Transaction, TransactionReceipt, TxType},
    Signature,
};
use lemma_mempool::pool::Mempool;
use lemma_storage::{chain::ChainStore, db::LemmaDb};

use super::*;
use crate::server::NodeHandle;

// ── Test fixtures ─────────────────────────────────────────────────────────────

fn open_temp_db() -> (Arc<LemmaDb>, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir must succeed");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed");
    (Arc::new(db), dir)
}

fn make_test_handle(db: Arc<LemmaDb>) -> NodeHandle {
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let network = lemma_network::service::NetworkHandle::new_for_test(tx);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    NodeHandle::new(Arc::clone(&db), mempool, network, 1)
}

fn make_block_with_receipt(height: u64, tx_hash: Hash) -> (Block, Hash) {
    let receipt = TransactionReceipt::new(tx_hash, true, 21_000, vec![]);
    let tx = Transaction::new(
        tx_hash,
        Address::zero(),
        Some(Address::from_raw_bytes([1u8; 20])),
        0,
        1,
        Amount::zero(),
        21_000,
        Amount::from_drop(1_000_000_000),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("Transaction::new must succeed");

    let header = BlockHeader::new(
        height,
        1_700_000_000 + height,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        1,
        0,
        Hash::zero(),
        Hash::from_bytes([height as u8; 32]),
        Hash::from_bytes([height as u8; 32]),
        30_000_000,
        21_000,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("BlockHeader::new must succeed");

    let block = Block::new(header, vec![tx], vec![receipt], None).expect("Block::new must succeed");
    let hash = Hash::from_bytes([(height + 1) as u8; 32]);
    (block, hash)
}

// ── lem_getTransactionReceipt ─────────────────────────────────────────────────

#[test]
fn get_transaction_receipt_returns_null_for_empty_chain() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let hash_hex = "a".repeat(64);
    let result = get_transaction_receipt(&handle, &json!([hash_hex])).expect("must succeed");
    assert_eq!(result, serde_json::Value::Null);
}

#[test]
fn get_transaction_receipt_returns_receipt_when_found() {
    let (db, _dir) = open_temp_db();
    let tx_hash = Hash::from_bytes([0xabu8; 32]);
    let (block, block_hash) = make_block_with_receipt(1, tx_hash);
    let chain = ChainStore::new(&db);
    chain
        .put_block(&block, block_hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    let hash_hex = hex::encode(tx_hash.as_bytes());
    let result = get_transaction_receipt(&handle, &json!([hash_hex])).expect("must succeed");

    assert_eq!(result["success"], true);
    assert_eq!(result["gasUsed"], 21_000_u64);
    assert_eq!(result["blockHeight"], 1_u64);
}

#[test]
fn get_transaction_receipt_returns_null_when_not_found() {
    let (db, _dir) = open_temp_db();
    let tx_hash = Hash::from_bytes([0xabu8; 32]);
    let (block, block_hash) = make_block_with_receipt(1, tx_hash);
    let chain = ChainStore::new(&db);
    chain
        .put_block(&block, block_hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    // Search for a different hash.
    let other_hash = hex::encode(Hash::from_bytes([0xcdu8; 32]).as_bytes());
    let result = get_transaction_receipt(&handle, &json!([other_hash])).expect("must succeed");
    assert_eq!(result, serde_json::Value::Null);
}

#[test]
fn get_transaction_receipt_missing_param_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = get_transaction_receipt(&handle, &json!([])).unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

// ── lem_sendTransaction — invalid params ──────────────────────────────────────

#[tokio::test]
async fn send_transaction_missing_params_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = send_transaction(&handle, &json!([])).await.unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

#[tokio::test]
async fn send_transaction_missing_tx_field_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = send_transaction(&handle, &json!([{ "sender_pubkey": {} }]))
        .await
        .unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

#[tokio::test]
async fn send_transaction_missing_pubkey_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = send_transaction(&handle, &json!([{ "tx": {} }]))
        .await
        .unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

#[tokio::test]
async fn send_transaction_invalid_tx_json_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = send_transaction(
        &handle,
        &json!([{
            "tx": { "not_a_valid_tx": true },
            "sender_pubkey": {
                "classical": hex::encode([0u8; 32]),
                "quantum": hex::encode([0u8; 1952]),
            }
        }]),
    )
    .await
    .unwrap_err();
    // Invalid tx JSON → InvalidParams or TransactionRejected
    assert!(matches!(
        err,
        crate::error::RpcError::InvalidParams { .. }
            | crate::error::RpcError::TransactionRejected { .. }
    ));
}
