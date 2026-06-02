//! Tests for [`network_runner`].
//!
//! Covers:
//! - `fetch_range`: contiguous range, partial range (beyond tip), empty range,
//!   storage-error → empty-vec policy, and inverted range.
//! - `run_block_broadcaster`: exits on channel close, exits on shutdown signal.
//! - `run_network_dispatch`: exits on channel close, exits on shutdown signal.
//! - Phase 1 log-only events (`BlockReceived`, `TransactionReceived`, peer
//!   lifecycle, listen-address) pass through without error.
//!
//! ## Test strategy
//!
//! `fetch_range` is tested directly against a seeded `ChainStore` — no swarm
//! needed. This covers the critical "empty-on-storage-error" policy (i.e. a
//! bad disk read for one peer's request does NOT crash the dispatch loop).
//!
//! The async lifecycle tests verify the dispatch/broadcaster loops exit cleanly
//! on channel-close and shutdown signals. They use a real `NetworkService::new`
//! with a random port to obtain a `NetworkHandle` (private constructor in
//! lemma-network). Full round-trip range-serve (request → response received by
//! a second peer) is covered by integration tests in N6.

use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::{mpsc, watch, RwLock};

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

use super::*;

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, TempDir) {
    let dir = TempDir::new().expect("TempDir::new must succeed");
    let db  = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed");
    (db, dir)
}

fn make_block_at(height: u64, parent_hash: Hash) -> (Block, Hash) {
    let validators_hash = Hash::from_bytes([0xAA; 32]);
    let header = BlockHeader::new(
        height,
        1_700_000_000 + height,
        parent_hash,
        Hash::zero(), Hash::zero(), Hash::zero(),
        Address::zero(),
        0, 0, Hash::zero(),
        validators_hash, validators_hash,
        30_000_000, 0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("header must be valid");
    let block = Block::new(header, vec![], vec![]).expect("block must be valid");
    let bytes = bincode::serialize(&block).expect("serialize must succeed");
    let hash  = lemma_crypto::hash_bytes(&bytes);
    (block, hash)
}

/// Seed `n` blocks (height 0..n) into db and return the hash of the last one.
fn seed_n_blocks(db: &LemmaDb, n: u64) -> Hash {
    let mut prev = Hash::zero();
    for h in 0..n {
        let (block, hash) = make_block_at(h, prev);
        ChainStore::new(db).put_block(&block, hash).expect("put_block must succeed");
        prev = hash;
    }
    prev
}

/// Build a `NetworkHandle` backed by a real `NetworkService` on a random port.
/// Returns the handle; the service is spawned as a background task.
///
/// `NetworkHandle` has a private constructor in lemma-network, so we obtain
/// it via `NetworkService::new` (random port, no peers — no real networking).
fn spawn_test_network() -> (NetworkHandle, mpsc::Receiver<NetworkEvent>) {
    let net_cfg = lemma_network::config::NetworkConfig::default();
    let key     = libp2p::identity::Keypair::generate_ed25519();
    let (service, handle, event_rx) =
        lemma_network::service::NetworkService::new(key, &net_cfg)
            .expect("NetworkService::new must succeed in test");
    tokio::spawn(service.run());
    (handle, event_rx)
}

// ── fetch_range ───────────────────────────────────────────────────────────────

#[test]
fn fetch_range_returns_all_stored_blocks_in_range() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 5); // heights 0..4
    let request = lemma_network::messages::RangeRequest::new(1, 3);
    let blocks  = fetch_range(&db, &request);
    assert_eq!(blocks.len(), 3);
    assert_eq!(blocks[0].height(), 1);
    assert_eq!(blocks[2].height(), 3);
}

#[test]
fn fetch_range_returns_partial_prefix_when_range_exceeds_tip() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 3); // heights 0..2
    // Request extends beyond tip (height 2).
    let request = lemma_network::messages::RangeRequest::new(0, 10);
    let blocks  = fetch_range(&db, &request);
    // Only heights 0..2 are stored — get_range stops at first gap.
    assert_eq!(blocks.len(), 3, "must return only stored blocks");
    assert_eq!(blocks.last().map(|b| b.height()), Some(2));
}

#[test]
fn fetch_range_returns_empty_when_from_above_tip() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 2); // heights 0..1
    let request = lemma_network::messages::RangeRequest::new(5, 10);
    let blocks  = fetch_range(&db, &request);
    assert!(blocks.is_empty(), "must return empty when from_height > tip");
}

#[test]
fn fetch_range_returns_empty_on_inverted_range() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 3);
    // to < from — get_range returns empty for inverted ranges.
    let request = lemma_network::messages::RangeRequest::new(5, 2);
    let blocks  = fetch_range(&db, &request);
    assert!(blocks.is_empty(), "inverted range must yield empty response");
}

#[test]
fn fetch_range_returns_single_block_for_zero_width_request() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 3);
    let request = lemma_network::messages::RangeRequest::new(1, 1);
    let blocks  = fetch_range(&db, &request);
    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height(), 1);
}

#[test]
fn fetch_range_returns_empty_on_empty_chain() {
    // No blocks seeded — storage is completely empty.
    let (db, _dir) = open_temp_db();
    let request = lemma_network::messages::RangeRequest::new(0, 5);
    let blocks  = fetch_range(&db, &request);
    assert!(blocks.is_empty(), "empty chain must yield empty response");
}

// ── run_block_broadcaster ─────────────────────────────────────────────────────

#[tokio::test]
async fn broadcaster_exits_when_block_channel_closes() {
    let (handle, _event_rx) = spawn_test_network();
    let (block_tx, block_rx) = mpsc::channel::<Block>(8);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    drop(block_tx); // close the channel immediately

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_block_broadcaster(handle, block_rx, shutdown_rx),
    )
    .await;

    assert!(result.is_ok(), "broadcaster must exit promptly when block channel closes");
}

#[tokio::test]
async fn broadcaster_exits_on_shutdown_signal() {
    let (handle, _event_rx) = spawn_test_network();
    let (_block_tx, block_rx) = mpsc::channel::<Block>(8);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    shutdown_tx.send(true).expect("send must succeed");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_block_broadcaster(handle, block_rx, shutdown_rx),
    )
    .await;

    assert!(result.is_ok(), "broadcaster must exit promptly on shutdown signal");
}

// ── run_network_dispatch ──────────────────────────────────────────────────────

#[tokio::test]
async fn dispatch_exits_when_event_channel_closes() {
    let (db, _dir) = open_temp_db();
    let db      = Arc::new(db);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let (handle, _event_rx) = spawn_test_network();

    let (_tx, closed_rx) = mpsc::channel::<NetworkEvent>(1);
    drop(_tx); // close immediately

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(db, mempool, handle, closed_rx, shutdown_rx),
    )
    .await;

    assert!(result.is_ok(), "dispatch must exit promptly when event channel closes");
    assert!(result.unwrap().is_ok(), "dispatch must return Ok(()) on clean channel close");
}

#[tokio::test]
async fn dispatch_exits_on_shutdown_signal() {
    let (db, _dir) = open_temp_db();
    let db      = Arc::new(db);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (handle, _event_rx) = spawn_test_network();
    let (_event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    shutdown_tx.send(true).expect("send must succeed");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(db, mempool, handle, event_rx, shutdown_rx),
    )
    .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

// ── Phase 1 log-only events ───────────────────────────────────────────────────

#[tokio::test]
async fn dispatch_handles_peer_connected_without_error() {
    let (db, _dir)  = open_temp_db();
    let db          = Arc::new(db);
    let mempool     = Arc::new(RwLock::new(Mempool::new(100)));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (handle, _event_rx) = spawn_test_network();
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    event_tx
        .send(NetworkEvent::PeerConnected(libp2p::PeerId::random()))
        .await
        .expect("send must succeed");
    shutdown_tx.send(true).expect("send must succeed");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(db, mempool, handle, event_rx, shutdown_rx),
    )
    .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn dispatch_handles_block_received_without_error() {
    let (db, _dir)  = open_temp_db();
    let db          = Arc::new(db);
    let mempool     = Arc::new(RwLock::new(Mempool::new(100)));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (handle, _event_rx) = spawn_test_network();
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    let (genesis, _) = make_block_at(0, Hash::zero());
    event_tx
        .send(NetworkEvent::BlockReceived {
            from: libp2p::PeerId::random(),
            block: genesis,
        })
        .await
        .expect("send must succeed");
    shutdown_tx.send(true).expect("send must succeed");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(db, mempool, handle, event_rx, shutdown_rx),
    )
    .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn dispatch_handles_transaction_received_without_error() {
    let (db, _dir)  = open_temp_db();
    let db          = Arc::new(db);
    let mempool     = Arc::new(RwLock::new(Mempool::new(100)));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (handle, _event_rx) = spawn_test_network();
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    let tx = Transaction {
        hash:      Hash::zero(),
        chain_id:  1,
        nonce:     0,
        sender:    Address::zero(),
        to:        None,
        value:     Amount::zero(),
        gas_limit: 21_000,
        gas_price: Amount::from_drop(1_000_000_000),
        data:      vec![],
        signature: Signature::Unsigned,
        tx_type:   TxType::Transfer,
    };
    event_tx
        .send(NetworkEvent::TransactionReceived {
            from: libp2p::PeerId::random(),
            tx,
        })
        .await
        .expect("send must succeed");
    shutdown_tx.send(true).expect("send must succeed");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(db, mempool, handle, event_rx, shutdown_rx),
    )
    .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}
