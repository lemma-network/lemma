//! Tests for fee handlers: `lem_gasPrice`.

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

fn make_test_handle(db: Arc<LemmaDb>) -> NodeHandle {
    let (tx, _rx) = tokio::sync::mpsc::channel(1);
    let network = lemma_network::service::NetworkHandle::new_for_test(tx);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    NodeHandle::new(Arc::clone(&db), mempool, network, 1)
}

fn make_block_with_base_fee(height: u64, base_fee_drop: u128) -> (Block, Hash) {
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
        0,
        Amount::from_drop(base_fee_drop),
        vec![],
    )
    .expect("BlockHeader::new must succeed");
    let block = Block::new(header, vec![], vec![], None).expect("Block::new must succeed");
    let hash = Hash::from_bytes([(height + 1) as u8; 32]);
    (block, hash)
}

// ── lem_gasPrice ──────────────────────────────────────────────────────────────

#[test]
fn gas_price_returns_0x0_for_empty_chain() {
    let (db, _dir) = open_temp_db();
    let handle = make_test_handle(db);
    let result = gas_price(&handle).expect("gas_price must succeed");
    assert_eq!(result, json!("0x0"));
}

#[test]
fn gas_price_returns_current_base_fee() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    // 1 Drip = 1_000_000_000 Drop
    let (block, hash) = make_block_with_base_fee(1, 1_000_000_000);
    chain
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    let result = gas_price(&handle).expect("gas_price must succeed");
    // 1_000_000_000 in hex = 0x3b9aca00
    assert_eq!(result, json!("0x3b9aca00"));
}

#[test]
fn gas_price_returns_hex_string() {
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);
    let (block, hash) = make_block_with_base_fee(1, 255);
    chain
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let handle = make_test_handle(db);
    let result = gas_price(&handle).expect("gas_price must succeed");
    assert_eq!(result, json!("0xff"));
}
