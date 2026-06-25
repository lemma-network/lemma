//! Tests for chain handlers: `lem_blockNumber`, `lem_getBlock`, `lem_getLogs`.

use std::sync::Arc;

use serde_json::json;
use tempfile::tempdir;
use tokio::sync::RwLock;

use lemma_core::{address::Address, amount::Amount, block::Block, hash::Hash, header::BlockHeader};
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

fn make_block_at(height: u64, parent_hash: Hash) -> (Block, Hash) {
    let header = BlockHeader::new(
        height,
        1_700_000_000 + height,
        parent_hash,
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
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("BlockHeader::new must succeed");
    let block = Block::new(header, vec![], vec![], None).expect("Block::new must succeed");
    // Compute the canonical hash from the block bytes — same convention as
    // ChainStore::get_block_with_hash_by_height (serde_json → blake3).
    // This ensures the hash stored in CF_BLOCK_HASH matches what the handler
    // returns for by-height lookups, so by-hash lookups succeed in tests.
    let hash =
        lemma_crypto::hash_bytes(&serde_json::to_vec(&block).expect("Block must be serializable"));
    (block, hash)
}

fn make_test_handle(db: Arc<LemmaDb>) -> NodeHandle {
    // Build a minimal NetworkHandle for tests — we don't need real networking.
    // Use a dummy channel that immediately drops commands (receiver dropped).
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let network = lemma_network::service::NetworkHandle::new_for_test(tx);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    NodeHandle::new(Arc::clone(&db), mempool, network, 1)
}

// ── lem_blockNumber ───────────────────────────────────────────────────────────

#[test]
fn block_number_returns_zero_for_empty_chain() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let result = block_number(&handle).expect("block_number must succeed");
    assert_eq!(result, json!("0x0"));
}

#[test]
fn block_number_returns_current_height() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    let (block, hash) = make_block_at(5, Hash::zero());
    chain
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    let result = block_number(&handle).expect("block_number must succeed");
    assert_eq!(result, json!("0x5"));
}

// ── lem_getBlock ──────────────────────────────────────────────────────────────

#[test]
fn get_block_by_height_returns_block() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    let (block, hash) = make_block_at(1, Hash::zero());
    chain
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    let result = get_block(&handle, &json!([1, false])).expect("get_block must succeed");
    assert_eq!(result["height"], 1);
}

#[test]
fn get_block_by_height_string_returns_block() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    let (block, hash) = make_block_at(3, Hash::zero());
    chain
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    let result = get_block(&handle, &json!(["3", false])).expect("get_block must succeed");
    assert_eq!(result["height"], 3);
}

#[test]
fn get_block_not_found_returns_null() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let result = get_block(&handle, &json!([99, false])).expect("get_block must succeed");
    assert_eq!(result, serde_json::Value::Null);
}

#[test]
fn get_block_missing_params_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let err = get_block(&handle, &json!([])).unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

#[test]
fn get_block_include_txs_false_returns_hashes_only() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    let (block, hash) = make_block_at(1, Hash::zero());
    chain
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    let result = get_block(&handle, &json!([1, false])).expect("get_block must succeed");
    // Empty block — transactions array should be empty.
    assert_eq!(result["transactionCount"], 0);
}

// ── lem_getLogs ───────────────────────────────────────────────────────────────

#[test]
fn get_logs_empty_chain_returns_empty_array() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let result = get_logs(&handle, &json!([{}])).expect("get_logs must succeed");
    assert_eq!(result, json!([]));
}

#[test]
fn get_logs_no_matching_address_returns_empty() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    let (block, hash) = make_block_at(1, Hash::zero());
    chain
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    let filter = json!({
        "fromBlock": 0,
        "toBlock": 1,
        "address": "0000000000000000000000000000000000000001"
    });
    let result = get_logs(&handle, &json!([filter])).expect("get_logs must succeed");
    assert_eq!(result, json!([]));
}

#[test]
fn get_logs_null_params_returns_empty_array() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let result = get_logs(&handle, &serde_json::Value::Null).expect("get_logs must succeed");
    assert_eq!(result, json!([]));
}

// ── lem_getBlock — real hash ──────────────────────────────────────────────────

#[test]
fn get_block_returns_real_hash_not_zeros() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    let (block, hash) = make_block_at(1, Hash::zero());
    chain
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    let result = get_block(&handle, &json!([1, false])).expect("get_block must succeed");

    let returned_hash = result["hash"].as_str().expect("hash must be a string");
    // The returned hash must not be all zeros — it must be the real block hash.
    assert_ne!(
        returned_hash,
        format!("0x{}", "0".repeat(64)),
        "get_block must return the real block hash, not Hash::zero()"
    );
    // The returned hash must be a valid 0x-prefixed 32-byte hex string.
    assert!(returned_hash.starts_with("0x"), "hash must start with 0x");
    assert_eq!(
        returned_hash.len(),
        66,
        "hash must be 66 chars (0x + 64 hex)"
    );
}

#[test]
fn get_block_by_hash_returns_same_hash() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    let (block, stored_hash) = make_block_at(2, Hash::zero());
    chain
        .put_block(&block, stored_hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    // Look up by height first to get the hash.
    let by_height = get_block(&handle, &json!([2, false])).expect("get_block by height");
    let hash_str = by_height["hash"].as_str().expect("hash must be a string");

    // Now look up by hash — the returned hash must match.
    let by_hash = get_block(&handle, &json!([hash_str, false])).expect("get_block by hash");
    assert_eq!(
        by_hash["hash"], by_height["hash"],
        "by-hash and by-height must return the same hash"
    );
    assert_eq!(
        by_hash["height"], by_height["height"],
        "by-hash and by-height must return the same block"
    );
}

// ── lem_getLogs — invalid params ──────────────────────────────────────────────

#[test]
fn get_logs_invalid_from_block_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    // "latest" is a string, not a u64 — must return InvalidParams, not silently coerce to 0.
    let filter = json!({ "fromBlock": "latest" });
    let err = get_logs(&handle, &json!([filter])).unwrap_err();
    assert!(
        matches!(err, crate::error::RpcError::InvalidParams { .. }),
        "expected InvalidParams for non-integer fromBlock, got: {err:?}"
    );
}

#[test]
fn get_logs_invalid_to_block_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let filter = json!({ "toBlock": "pending" });
    let err = get_logs(&handle, &json!([filter])).unwrap_err();
    assert!(
        matches!(err, crate::error::RpcError::InvalidParams { .. }),
        "expected InvalidParams for non-integer toBlock, got: {err:?}"
    );
}

#[test]
fn get_logs_invalid_topic_hex_returns_error() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    // "not-hex" is not valid hex — must return InvalidParams, not silently drop the topic.
    let filter = json!({ "topics": ["not-hex-at-all"] });
    let err = get_logs(&handle, &json!([filter])).unwrap_err();
    assert!(
        matches!(err, crate::error::RpcError::InvalidParams { .. }),
        "expected InvalidParams for malformed topic hex, got: {err:?}"
    );
}

#[test]
fn get_logs_absent_from_to_block_defaults_to_zero_and_tip() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    let (block, hash) = make_block_at(1, Hash::zero());
    chain
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    // No fromBlock/toBlock — should default gracefully (not error).
    let result = get_logs(&handle, &json!([{}])).expect("get_logs must succeed with absent keys");
    assert_eq!(result, json!([]));
}

// ── parse_hex_hash ────────────────────────────────────────────────────────────

#[test]
fn parse_hex_hash_accepts_64_char_hex() {
    let s = "a".repeat(64);
    let result = parse_hex_hash(&s);
    assert!(result.is_ok());
}

#[test]
fn parse_hex_hash_accepts_0x_prefix() {
    let s = format!("0x{}", "b".repeat(64));
    let result = parse_hex_hash(&s);
    assert!(result.is_ok());
}

#[test]
fn parse_hex_hash_rejects_wrong_length() {
    let s = "a".repeat(30); // 15 bytes, not 32
    let err = parse_hex_hash(&s).unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}

#[test]
fn parse_hex_hash_rejects_invalid_hex() {
    let err = parse_hex_hash("zzzz").unwrap_err();
    assert!(matches!(err, crate::error::RpcError::InvalidParams { .. }));
}
