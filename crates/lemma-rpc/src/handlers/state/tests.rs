//! Tests for state handlers: `lem_getBalance`, `lem_getCode`, `lem_getStorageAt`, `lem_call`.

use std::sync::Arc;

use serde_json::json;
use tempfile::tempdir;
use tokio::sync::RwLock;

use lemma_core::{address::Address, amount::Amount, block::Block, hash::Hash, header::BlockHeader};
use lemma_mempool::pool::Mempool;
use lemma_storage::{chain::ChainStore, db::LemmaDb, state::WorldState};

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

fn addr_hex(addr: &Address) -> String {
    hex::encode(addr.as_bytes())
}

// ── lem_getBalance ────────────────────────────────────────────────────────────

#[test]
fn get_balance_returns_zero_for_unknown_address() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let addr = Address::zero();
    let result = get_balance(&handle, &json!([addr_hex(&addr)])).expect("must succeed");
    assert_eq!(result, json!("0"));
}

#[test]
fn get_balance_missing_param_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = get_balance(&handle, &json!([])).unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

// ── lem_getCode ───────────────────────────────────────────────────────────────

#[test]
fn get_code_returns_0x_for_eoa() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let addr = Address::zero();
    let result = get_code(&handle, &json!([addr_hex(&addr)])).expect("must succeed");
    assert_eq!(result, json!("0x"));
}

/// Commit a block with the given state root so the handler can find it.
fn commit_block_with_state_root(db: &Arc<LemmaDb>, state_root: Hash) {
    let header = BlockHeader::new(
        1,
        1_700_000_001,
        Hash::zero(),
        Hash::zero(),
        state_root,
        Hash::zero(),
        Address::zero(),
        0,
        1,
        0,
        Hash::zero(),
        Hash::from_bytes([1u8; 32]),
        Hash::from_bytes([1u8; 32]),
        30_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("BlockHeader::new must succeed");
    let block = Block::new(header, vec![], vec![], None).expect("Block::new must succeed");
    let hash = Hash::from_bytes([2u8; 32]);
    ChainStore::new(db)
        .put_block(&block, hash)
        .expect("put_block must succeed");
}

#[test]
fn get_balance_returns_balance_for_known_address() {
    let (db, _dir) = open_temp_db();
    let mut state = WorldState::new(Arc::clone(&db));
    let addr = Address::from_raw_bytes([1u8; 20]);
    let account = lemma_storage::Account::new_eoa(Amount::from_drop(1_000_000));
    state
        .put_account(&addr, &account)
        .expect("put_account must succeed");
    // Commit a block with the resulting state root so the handler can find it.
    let state_root = state.commit().expect("commit must succeed");
    commit_block_with_state_root(&db, state_root);

    let handle = make_test_handle(db);
    let result = get_balance(&handle, &json!([addr_hex(&addr)])).expect("must succeed");
    assert_eq!(result, json!("1000000"));
}

#[test]
fn get_code_missing_param_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = get_code(&handle, &json!([])).unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

// ── lem_getStorageAt ──────────────────────────────────────────────────────────

#[test]
fn get_storage_at_returns_0x_for_unwritten_slot() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let addr = Address::zero();
    let slot = "a".repeat(64);
    let result = get_storage_at(&handle, &json!([addr_hex(&addr), slot])).expect("must succeed");
    assert_eq!(result, json!("0x"));
}

#[test]
fn get_storage_at_missing_address_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = get_storage_at(&handle, &json!([])).unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

#[test]
fn get_storage_at_missing_slot_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let addr = Address::zero();
    let err = get_storage_at(&handle, &json!([addr_hex(&addr)])).unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

// ── lem_call ─────────────────────────────────────────────────────────────────

/// `lem_call` is intentionally unimplemented (tracked as lem_call-stub-1).
/// It must return `RpcError::Unsupported` — NOT a misleading stub response —
/// so callers can detect the gap without treating it as a successful empty call.
#[tokio::test]
async fn call_returns_unsupported_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let addr = Address::zero();
    let err = call(&handle, &json!([{ "to": addr_hex(&addr), "data": "0x" }]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, crate::error::RpcError::Unsupported { ref method, .. } if method == "lem_call"),
        "expected Unsupported(lem_call), got: {err:?}"
    );
}

#[tokio::test]
async fn call_missing_to_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = call(&handle, &json!([{ "data": "0x" }])).await.unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

#[tokio::test]
async fn call_missing_params_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = call(&handle, &json!([])).await.unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}
