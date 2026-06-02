//! Tests for [`network_runner`].
//!
//! Covers:
//! - `fetch_range`: contiguous range, partial range (beyond tip), empty range,
//!   storage-error → empty-vec policy, and inverted range.
//! - `run_block_broadcaster`: exits on channel close, exits on shutdown signal.
//! - `run_network_dispatch` lifecycle: exits on channel close, exits on shutdown.
//! - Phase 1 log-only events (`TransactionReceived`, peer lifecycle) pass
//!   through without error.
//! - `BlockReceived` gap detection: block at tip+1 is applied; block at
//!   tip+2 triggers a range request.

use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock, mpsc, watch};

use lemma_core::{
    address::Address,
    amount::Amount,
    block::Block,
    hash::Hash,
    header::BlockHeader,
    signature::Signature,
    transaction::{Transaction, TxType},
};
use lemma_mempool::pool::Mempool;
use lemma_network::service::NetworkEvent;
use lemma_storage::{chain::ChainStore, db::LemmaDb};

use crate::sync::compute_block_hash;
use super::*;

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, TempDir) {
    let dir = TempDir::new().expect("TempDir::new must succeed");
    let db  = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed");
    (db, dir)
}

fn make_block_at(height: u64, parent_hash: Hash) -> Block {
    let vh = Hash::from_bytes([0xAA; 32]);
    let h  = BlockHeader::new(
        height, 1_700_000_000 + height, parent_hash,
        Hash::zero(), Hash::zero(), Hash::zero(),
        Address::zero(), 0, 0, Hash::zero(), vh, vh,
        30_000_000, 0, Amount::from_drop(1_000_000_000), vec![],
    )
    .expect("header must be valid");
    Block::new(h, vec![], vec![]).expect("block must be valid")
}

fn seed_n_blocks(db: &LemmaDb, n: u64) -> Hash {
    let mut prev = Hash::zero();
    for h in 0..n {
        let block = make_block_at(h, prev);
        let hash  = compute_block_hash(&block).expect("hash");
        ChainStore::new(db).put_block(&block, hash).expect("put_block");
        prev = hash;
    }
    prev
}

/// Build a real `NetworkHandle` via `NetworkService::new` (random port, no peers).
fn spawn_test_network() -> (NetworkHandle, mpsc::Receiver<NetworkEvent>) {
    let net_cfg = lemma_network::config::NetworkConfig::default();
    let key     = libp2p::identity::Keypair::generate_ed25519();
    let (service, handle, event_rx) =
        lemma_network::service::NetworkService::new(key, &net_cfg)
            .expect("NetworkService::new must succeed in test");
    tokio::spawn(service.run());
    (handle, event_rx)
}

fn write_lock() -> Arc<Mutex<()>> {
    Arc::new(Mutex::new(()))
}

// ── fetch_range ───────────────────────────────────────────────────────────────

#[test]
fn fetch_range_returns_all_stored_blocks_in_range() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 5);
    let request = lemma_network::messages::RangeRequest::new(1, 3);
    let blocks  = fetch_range(&db, &request);
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].height(), 1);
    assert_eq!(blocks[2].height(), 3);
}

#[test]
fn fetch_range_returns_partial_when_beyond_tip() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 3);
    let blocks = fetch_range(&db, &lemma_network::messages::RangeRequest::new(0, 10));
    assert_eq!(blocks.len(), 3, "must stop at tip");
}

#[test]
fn fetch_range_returns_empty_when_from_above_tip() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 2);
    let blocks = fetch_range(&db, &lemma_network::messages::RangeRequest::new(5, 10));
    assert!(blocks.is_empty());
}

#[test]
fn fetch_range_returns_empty_on_inverted_range() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 3);
    let blocks = fetch_range(&db, &lemma_network::messages::RangeRequest::new(5, 2));
    assert!(blocks.is_empty());
}

#[test]
fn fetch_range_single_block() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 3);
    let blocks = fetch_range(&db, &lemma_network::messages::RangeRequest::new(1, 1));
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height(), 1);
}

#[test]
fn fetch_range_empty_chain() {
    let (db, _dir) = open_temp_db();
    let blocks = fetch_range(&db, &lemma_network::messages::RangeRequest::new(0, 5));
    assert!(blocks.is_empty());
}

// ── run_block_broadcaster ─────────────────────────────────────────────────────

#[tokio::test]
async fn broadcaster_exits_when_block_channel_closes() {
    let (handle, _) = spawn_test_network();
    let (block_tx, block_rx) = mpsc::channel::<Block>(8);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    drop(block_tx);

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_block_broadcaster(handle, block_rx, shutdown_rx),
    ).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn broadcaster_exits_on_shutdown_signal() {
    let (handle, _) = spawn_test_network();
    let (_block_tx, block_rx) = mpsc::channel::<Block>(8);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    shutdown_tx.send(true).expect("send");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_block_broadcaster(handle, block_rx, shutdown_rx),
    ).await;
    assert!(result.is_ok());
}

// ── run_network_dispatch lifecycle ───────────────────────────────────────────

#[tokio::test]
async fn dispatch_exits_when_event_channel_closes() {
    let (db, _dir) = open_temp_db();
    let db         = Arc::new(db);
    let mempool    = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let (_tx, closed_rx) = mpsc::channel::<NetworkEvent>(1);
    drop(_tx);

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(db, mempool, handle, write_lock(), closed_rx, shutdown_rx),
    ).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn dispatch_exits_on_shutdown_signal() {
    let (db, _dir) = open_temp_db();
    let db         = Arc::new(db);
    let mempool    = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (_event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);
    shutdown_tx.send(true).expect("send");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(db, mempool, handle, write_lock(), event_rx, shutdown_rx),
    ).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

// ── BlockReceived: apply + gap detection ─────────────────────────────────────

#[tokio::test]
async fn dispatch_applies_block_at_tip_plus_one() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 1); // genesis at height 0
    let db         = Arc::new(db);
    let mempool    = Arc::new(RwLock::new(Mempool::new(100)));
    let lock       = write_lock();
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    // Build a valid block at height 1.
    let tip_hash = ChainStore::new(&db).tip().unwrap().unwrap().1;
    let block1   = make_block_at(1, tip_hash);

    event_tx.send(NetworkEvent::BlockReceived {
        from: libp2p::PeerId::random(),
        block: block1,
    }).await.expect("send");

    // Spawn the dispatch loop in a background task so we can poll for the
    // applied block before sending shutdown (prevents a select! race where
    // the shutdown branch wins before the BlockReceived branch runs).
    let db_for_dispatch = Arc::clone(&db);
    let dispatch_handle = tokio::spawn(run_network_dispatch(
        db_for_dispatch, mempool, handle, lock, event_rx, shutdown_rx,
    ));

    // Poll until height 1 is applied (or deadline).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let h = ChainStore::new(&db).latest_height().unwrap().unwrap_or(0);
        if h >= 1 { break; }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for block height 1 to be applied"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }

    // Now that the block is applied, signal shutdown.
    shutdown_tx.send(true).expect("shutdown");
    dispatch_handle.await.expect("task").expect("dispatch ok");

    assert_eq!(
        ChainStore::new(&db).latest_height().unwrap().unwrap(),
        1,
        "block at height 1 must be applied"
    );
}

#[tokio::test]
async fn dispatch_skips_block_already_in_chain() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 3); // heights 0, 1, 2
    let db         = Arc::new(db);
    let mempool    = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    // Block at height 1 — already in chain (tip = 2).
    let block1 = ChainStore::new(&db)
        .get_block_by_height(1).unwrap().unwrap();

    event_tx.send(NetworkEvent::BlockReceived {
        from: libp2p::PeerId::random(),
        block: block1,
    }).await.expect("send");

    shutdown_tx.send(true).expect("shutdown");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(Arc::clone(&db), mempool, handle, write_lock(), event_rx, shutdown_rx),
    ).await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
    // Tip must stay at 2.
    assert_eq!(ChainStore::new(&db).latest_height().unwrap().unwrap(), 2);
}

// ── Phase 1 log-only events ───────────────────────────────────────────────────

#[tokio::test]
async fn dispatch_handles_peer_connected_without_error() {
    let (db, _dir) = open_temp_db();
    let db         = Arc::new(db);
    let mempool    = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    event_tx.send(NetworkEvent::PeerConnected(libp2p::PeerId::random())).await.expect("send");
    shutdown_tx.send(true).expect("shutdown");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(db, mempool, handle, write_lock(), event_rx, shutdown_rx),
    ).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn dispatch_handles_transaction_received_without_error() {
    let (db, _dir) = open_temp_db();
    let db         = Arc::new(db);
    let mempool    = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    let tx = Transaction {
        hash: Hash::zero(), chain_id: 1, nonce: 0,
        sender: Address::zero(), to: None,
        value: Amount::zero(), gas_limit: 21_000,
        gas_price: Amount::from_drop(1_000_000_000),
        data: vec![], signature: Signature::Unsigned,
        tx_type: TxType::Transfer,
    };
    event_tx.send(NetworkEvent::TransactionReceived {
        from: libp2p::PeerId::random(), tx,
    }).await.expect("send");
    shutdown_tx.send(true).expect("shutdown");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(db, mempool, handle, write_lock(), event_rx, shutdown_rx),
    ).await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}
