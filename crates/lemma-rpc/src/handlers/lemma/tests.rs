//! Tests for Lemma-specific handlers: `lem_safetyScore`, `lem_stateAccess`.

use std::sync::Arc;

use serde_json::json;
use tempfile::tempdir;
use tokio::sync::RwLock;

use lemma_core::{address::Address, amount::Amount};
use lemma_mempool::pool::Mempool;
use lemma_storage::{db::LemmaDb, state::WorldState};

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

// ── lem_safetyScore ───────────────────────────────────────────────────────────

#[test]
fn safety_score_returns_null_for_unknown_address() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let addr = Address::from_raw_bytes([0xffu8; 20]);
    let result = safety_score(&handle, &json!([addr_hex(&addr)])).expect("must succeed");
    assert_eq!(result, serde_json::Value::Null);
}

#[test]
fn safety_score_returns_null_for_eoa() {
    let (db, _dir) = open_temp_db();
    let mut state = WorldState::new(Arc::clone(&db));
    let addr = Address::from_raw_bytes([1u8; 20]);
    // EOA: code_hash is zero.
    let account = lemma_storage::Account::new_eoa(Amount::from_drop(1_000));
    state
        .put_account(&addr, &account)
        .expect("put_account must succeed");

    let handle = make_test_handle(db);
    let result = safety_score(&handle, &json!([addr_hex(&addr)])).expect("must succeed");
    assert_eq!(result, serde_json::Value::Null);
}

#[test]
fn safety_score_missing_param_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = safety_score(&handle, &json!([])).unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

// ── lem_stateAccess ───────────────────────────────────────────────────────────

#[test]
fn state_access_returns_null_for_unknown_address() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let addr = Address::from_raw_bytes([0xeeu8; 20]);
    let result = state_access(&handle, &json!([addr_hex(&addr)])).expect("must succeed");
    assert_eq!(result, serde_json::Value::Null);
}

#[test]
fn state_access_returns_null_for_eoa() {
    let (db, _dir) = open_temp_db();
    let mut state = WorldState::new(Arc::clone(&db));
    let addr = Address::from_raw_bytes([2u8; 20]);
    let account = lemma_storage::Account::new_eoa(Amount::zero());
    state
        .put_account(&addr, &account)
        .expect("put_account must succeed");

    let handle = make_test_handle(db);
    let result = state_access(&handle, &json!([addr_hex(&addr)])).expect("must succeed");
    assert_eq!(result, serde_json::Value::Null);
}

#[test]
fn state_access_missing_param_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = state_access(&handle, &json!([])).unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}
