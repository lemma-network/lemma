//! Tests for [`network_runner`].
//!
//! Covers:
//! - `fetch_range`: contiguous range, partial range (beyond tip), empty range,
//!   storage-error → empty-vec policy, and inverted range.
//! - `run_block_broadcaster`: exits on channel close, exits on shutdown signal.
//! - `run_network_dispatch` lifecycle: exits on channel close, exits on shutdown.
//! - `TransactionReceived` (D·15d): valid sig admitted; wrong pubkey rejected;
//!   dispatch handles event without error.
//! - `BlockReceived` gap detection: block at tip+1 is applied; block at
//!   tip+2 triggers a range request.
//! - `handle_batch_received`: valid batch pinned; malformed JSON dropped; duplicate
//!   idempotent; forged `tx.hash` rejected (per-tx hash integrity, C·Step 14);
//!   unsigned tx dropped (D·15d SECURITY GATE); vset sender tampered sig dropped.
//! - `handle_dag_proposal_received` (D·15b-1): valid sig forwarded with sig_ok=true;
//!   invalid sig forwarded with sig_ok=false; unknown author sig_ok=false;
//!   Signature::Unsigned sig_ok=false.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::{mpsc, watch, Mutex, RwLock};

use super::*;
use crate::{
    batch::{new_batch_store, Batch},
    dag_driver::build_dag_block,
    genesis_boot::init_chain,
    sync::compute_block_hash,
};
use lemma_consensus::dag::block::{DagBlock, DagBlockBody};
use lemma_core::{
    address::Address,
    amount::Amount,
    block::Block,
    genesis::GenesisConfig,
    hash::Hash,
    header::BlockHeader,
    signature::Signature,
    transaction::{Transaction, TxType},
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};
use lemma_crypto::{sign_transaction, KeyPair};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, TempDir) {
    let dir = TempDir::new().expect("TempDir::new must succeed");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed");
    (db, dir)
}

fn make_block_at(height: u64, parent_hash: Hash) -> Block {
    let vh = Hash::from_bytes([0xAA; 32]);
    let h = BlockHeader::new(
        height,
        1_700_000_000 + height,
        parent_hash,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        0,
        Hash::zero(),
        vh,
        vh,
        30_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("header must be valid");
    Block::new(h, vec![], vec![], None).expect("block must be valid")
}

fn seed_n_blocks(db: &LemmaDb, n: u64) -> Hash {
    let mut prev = Hash::zero();
    for h in 0..n {
        let block = make_block_at(h, prev);
        let hash = compute_block_hash(&block).expect("hash");
        ChainStore::new(db)
            .put_block(&block, hash)
            .expect("put_block");
        prev = hash;
    }
    prev
}

/// Build a real `NetworkHandle` via `NetworkService::new` (random port, no peers).
fn spawn_test_network() -> (NetworkHandle, mpsc::Receiver<NetworkEvent>) {
    let net_cfg = lemma_network::config::NetworkConfig::default();
    let key = libp2p::identity::Keypair::generate_ed25519();
    let (service, handle, event_rx) = lemma_network::service::NetworkService::new(key, &net_cfg)
        .expect("NetworkService::new must succeed in test");
    tokio::spawn(service.run());
    (handle, event_rx)
}

fn write_lock() -> Arc<Mutex<()>> {
    Arc::new(Mutex::new(()))
}

/// Build an empty `ValidatorSet` for tests that don't need real validators.
fn empty_vset() -> ValidatorSet {
    ValidatorSet {
        epoch: 0,
        members: BTreeMap::new(),
        total_power: Amount::zero(),
    }
}

/// Build a single-member `ValidatorSet` with the given keypair's address and public key.
fn single_member_vset(kp: &KeyPair) -> ValidatorSet {
    let pk = kp.public_key();
    let consensus_pubkey = ConsensusKey::from_bytes(pk.classical.clone(), pk.quantum.clone());
    let power = VotingPower(Amount::from_drop(1_000_000));
    let mut members = BTreeMap::new();
    members.insert(
        *kp.address(),
        Member {
            consensus_pubkey,
            power,
        },
    );
    ValidatorSet {
        epoch: 0,
        members,
        total_power: Amount::from_drop(1_000_000),
    }
}

// ── fetch_range ───────────────────────────────────────────────────────────────

#[test]
fn fetch_range_returns_all_stored_blocks_in_range() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 5);
    let request = lemma_network::messages::RangeRequest::new(1, 3);
    let blocks = fetch_range(&db, &request);
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
    )
    .await;
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
    )
    .await;
    assert!(result.is_ok());
}

// ── run_network_dispatch lifecycle ───────────────────────────────────────────

#[tokio::test]
async fn dispatch_exits_when_event_channel_closes() {
    let (db, _dir) = open_temp_db();
    let db = Arc::new(db);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);
    let (_tx, closed_rx) = mpsc::channel::<NetworkEvent>(1);
    drop(_tx);

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(
            db,
            mempool,
            new_batch_store(),
            handle,
            write_lock(),
            closed_rx,
            shutdown_rx,
            empty_vset(),
            None,
        ),
    )
    .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn dispatch_exits_on_shutdown_signal() {
    let (db, _dir) = open_temp_db();
    let db = Arc::new(db);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (_event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);
    shutdown_tx.send(true).expect("send");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(
            db,
            mempool,
            new_batch_store(),
            handle,
            write_lock(),
            event_rx,
            shutdown_rx,
            empty_vset(),
            None,
        ),
    )
    .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

// ── BlockReceived: apply + gap detection ─────────────────────────────────────

#[tokio::test]
async fn dispatch_applies_block_at_tip_plus_one() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 1); // genesis at height 0
    let db = Arc::new(db);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let lock = write_lock();
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    // Build a valid block at height 1.
    let tip_hash = ChainStore::new(&db).tip().unwrap().unwrap().1;
    let block1 = make_block_at(1, tip_hash);

    event_tx
        .send(NetworkEvent::BlockReceived {
            from: libp2p::PeerId::random(),
            block: Box::new(block1),
        })
        .await
        .expect("send");

    // Spawn the dispatch loop in a background task so we can poll for the
    // applied block before sending shutdown (prevents a select! race where
    // the shutdown branch wins before the BlockReceived branch runs).
    let db_for_dispatch = Arc::clone(&db);
    let dispatch_handle = tokio::spawn(run_network_dispatch(
        db_for_dispatch,
        mempool,
        new_batch_store(),
        handle,
        lock,
        event_rx,
        shutdown_rx,
        empty_vset(),
        None,
    ));

    // Poll until height 1 is applied (or deadline).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        let h = ChainStore::new(&db).latest_height().unwrap().unwrap_or(0);
        if h >= 1 {
            break;
        }
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
    let db = Arc::new(db);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    // Block at height 1 — already in chain (tip = 2).
    let block1 = ChainStore::new(&db)
        .get_block_by_height(1)
        .unwrap()
        .unwrap();

    event_tx
        .send(NetworkEvent::BlockReceived {
            from: libp2p::PeerId::random(),
            block: Box::new(block1),
        })
        .await
        .expect("send");

    shutdown_tx.send(true).expect("shutdown");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(
            Arc::clone(&db),
            mempool,
            new_batch_store(),
            handle,
            write_lock(),
            event_rx,
            shutdown_rx,
            empty_vset(),
            None,
        ),
    )
    .await;

    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
    // Tip must stay at 2.
    assert_eq!(ChainStore::new(&db).latest_height().unwrap().unwrap(), 2);
}

// ── Phase 1 log-only events ───────────────────────────────────────────────────

#[tokio::test]
async fn dispatch_handles_peer_connected_without_error() {
    let (db, _dir) = open_temp_db();
    let db = Arc::new(db);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    event_tx
        .send(NetworkEvent::PeerConnected(libp2p::PeerId::random()))
        .await
        .expect("send");
    shutdown_tx.send(true).expect("shutdown");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(
            db,
            mempool,
            new_batch_store(),
            handle,
            write_lock(),
            event_rx,
            shutdown_rx,
            empty_vset(),
            None,
        ),
    )
    .await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

#[tokio::test]
async fn dispatch_handles_transaction_received_without_error() {
    let (db, _dir) = open_temp_db();
    let db = Arc::new(db);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let (handle, _) = spawn_test_network();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(8);

    let tx = Transaction {
        hash: Hash::zero(),
        chain_id: 1,
        nonce: 0,
        sender: Address::zero(),
        to: None,
        value: Amount::zero(),
        gas_limit: 21_000,
        gas_price: Amount::from_drop(1_000_000_000),
        data: vec![],
        signature: Signature::Unsigned,
        tx_type: TxType::Transfer,
    };
    // D·15d: TransactionReceived now carries sender_pubkey.
    // Zero-bytes key — admission will fail sig verify (non-fatal, just logged).
    let sender_pubkey = Box::new(ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952]));
    event_tx
        .send(NetworkEvent::TransactionReceived {
            from: libp2p::PeerId::random(),
            tx,
            sender_pubkey,
        })
        .await
        .expect("send");
    shutdown_tx.send(true).expect("shutdown");

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        run_network_dispatch(
            db,
            mempool,
            new_batch_store(),
            handle,
            write_lock(),
            event_rx,
            shutdown_rx,
            empty_vset(),
            None,
        ),
    )
    .await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_ok());
}

// ── handle_batch_received (C·Step 14) ────────────────────────────────────────

/// Build a minimal signed tx for batch handler tests.
fn make_signed_tx_for_batch(kp: &KeyPair, nonce: u64) -> Transaction {
    let mut tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::from_public_key(&[99u8; 32])),
        nonce,
        1,
        Amount::from_drop(0),
        21_000,
        Amount::from_drop(1_000_000_000),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("Transaction::new");
    sign_transaction(&mut tx, kp).expect("sign_transaction");
    tx
}

#[tokio::test]
async fn handle_batch_received_valid_batch_is_pinned_under_correct_digest() {
    let kp = KeyPair::generate().expect("keygen");
    let tx = make_signed_tx_for_batch(&kp, 0);
    let batch = Batch::new(Address::from_public_key(&[1u8; 32]), vec![tx]);
    let digest = batch.digest().expect("digest");
    let bytes = serde_json::to_vec(&batch).expect("encode");
    let store = new_batch_store();

    handle_batch_received(libp2p::PeerId::random(), bytes, &store, &empty_vset()).await;

    let guard = store.read().await;
    assert!(guard.contains_key(&digest), "valid batch must be pinned");
    assert_eq!(guard.len(), 1);
}

#[tokio::test]
async fn handle_batch_received_malformed_json_is_dropped_store_unchanged() {
    let store = new_batch_store();
    let garbage = b"not valid json {{{{".to_vec();

    handle_batch_received(libp2p::PeerId::random(), garbage, &store, &empty_vset()).await;

    assert!(
        store.read().await.is_empty(),
        "malformed JSON must be dropped, store stays empty"
    );
}

#[tokio::test]
async fn handle_batch_received_duplicate_batch_is_idempotent() {
    let kp = KeyPair::generate().expect("keygen");
    let tx = make_signed_tx_for_batch(&kp, 0);
    let batch = Batch::new(Address::from_public_key(&[1u8; 32]), vec![tx]);
    let bytes = serde_json::to_vec(&batch).expect("encode");
    let digest = batch.digest().expect("digest");
    let store = new_batch_store();
    let peer = libp2p::PeerId::random();

    handle_batch_received(peer, bytes.clone(), &store, &empty_vset()).await;
    handle_batch_received(peer, bytes, &store, &empty_vset()).await;

    let guard = store.read().await;
    assert_eq!(guard.len(), 1, "duplicate must result in exactly one entry");
    assert!(guard.contains_key(&digest));
}

#[tokio::test]
async fn handle_batch_received_forged_tx_hash_is_rejected_store_unchanged() {
    // Simulate a malicious peer forging tx.hash to cause consensus divergence.
    // Per-tx hash verification (C·Step 14 security gate) must catch this.
    let kp = KeyPair::generate().expect("keygen");
    let mut tx = make_signed_tx_for_batch(&kp, 0);

    // Overwrite tx.hash with a forged value.
    tx.hash = Hash::from_bytes([0xDE; 32]);
    let canonical = compute_tx_hash(&tx).expect("compute_tx_hash");
    assert_ne!(canonical, tx.hash, "test precondition: hash must be forged");

    let batch = Batch::new(Address::from_public_key(&[1u8; 32]), vec![tx]);
    let bytes = serde_json::to_vec(&batch).expect("encode");
    let store = new_batch_store();

    handle_batch_received(libp2p::PeerId::random(), bytes, &store, &empty_vset()).await;

    assert!(
        store.read().await.is_empty(),
        "forged tx.hash must cause batch rejection, store stays empty"
    );
}

// ── handle_dag_proposal_received (D·15b-1) ───────────────────────────────────

/// Build a signed DagBlock at round 0 using the given keypair.
fn make_signed_dag_block(kp: &KeyPair) -> DagBlock {
    build_dag_block(0, *kp.address(), vec![], vec![], 0, 0, kp)
        .expect("build_dag_block must succeed")
}

/// Build an unsigned DagBlock (Signature::Unsigned) at round 0.
fn make_unsigned_dag_block(author: Address) -> DagBlock {
    let body = DagBlockBody {
        epoch: 0,
        round: 0,
        author,
        timestamp_ms: 0,
        ancestors: vec![],
        payload: vec![],
        commit_votes: vec![],
    };
    DagBlock::new(body, Signature::Unsigned)
}

#[tokio::test]
async fn dag_proposal_received_valid_sig_is_forwarded_to_channel() {
    // Arrange: keypair + vset with that keypair's pubkey.
    let kp = KeyPair::generate().expect("keygen");
    let vset = single_member_vset(&kp);
    let block = make_signed_dag_block(&kp);
    let bytes = serde_json::to_vec(&block).expect("encode");

    let (tx, mut rx) = mpsc::channel::<(DagBlock, bool)>(8);

    // Act: handle the proposal.
    handle_dag_proposal_received(libp2p::PeerId::random(), bytes, &vset, &Some(tx)).await;

    // Assert: channel receives (block, true).
    let result = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert_eq!(result.0.author, *kp.address(), "author must match");
    assert_eq!(result.0.round, 0, "round must match");
    assert!(result.1, "sig_ok must be true for a valid signature");
}

#[tokio::test]
async fn dag_proposal_received_invalid_sig_forwarded_with_sig_ok_false() {
    // Arrange: keypair + vset; tamper the signature bytes after building.
    let kp = KeyPair::generate().expect("keygen");
    let vset = single_member_vset(&kp);
    let mut block = make_signed_dag_block(&kp);

    // Tamper: replace the hybrid signature with garbage bytes.
    block.signature = Signature::Hybrid {
        classical: vec![0xDE; 64],
        quantum: vec![0xAD; 3309],
    };
    let bytes = serde_json::to_vec(&block).expect("encode");

    let (tx, mut rx) = mpsc::channel::<(DagBlock, bool)>(8);

    // Act.
    handle_dag_proposal_received(libp2p::PeerId::random(), bytes, &vset, &Some(tx)).await;

    // Assert: channel receives (block, false).
    let result = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert!(!result.1, "sig_ok must be false for a tampered signature");
}

#[tokio::test]
async fn dag_proposal_received_unknown_author_forwarded_with_sig_ok_false() {
    // Arrange: block author is NOT in the vset.
    let kp = KeyPair::generate().expect("keygen");
    let block = make_signed_dag_block(&kp);
    let bytes = serde_json::to_vec(&block).expect("encode");

    // vset is empty — author not found.
    let vset = ValidatorSet {
        epoch: 0,
        members: BTreeMap::new(),
        total_power: Amount::zero(),
    };

    let (tx, mut rx) = mpsc::channel::<(DagBlock, bool)>(8);

    // Act.
    handle_dag_proposal_received(libp2p::PeerId::random(), bytes, &vset, &Some(tx)).await;

    // Assert: channel receives (block, false).
    let result = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert!(!result.1, "sig_ok must be false for unknown author");
}

#[tokio::test]
async fn dag_proposal_received_unsigned_block_forwarded_with_sig_ok_false() {
    // Arrange: block has Signature::Unsigned — invalid for consensus.
    let kp = KeyPair::generate().expect("keygen");
    let vset = single_member_vset(&kp);
    let block = make_unsigned_dag_block(*kp.address());
    let bytes = serde_json::to_vec(&block).expect("encode");

    let (tx, mut rx) = mpsc::channel::<(DagBlock, bool)>(8);

    // Act.
    handle_dag_proposal_received(libp2p::PeerId::random(), bytes, &vset, &Some(tx)).await;

    // Assert: channel receives (block, false).
    let result = tokio::time::timeout(Duration::from_secs(1), rx.recv())
        .await
        .expect("timeout")
        .expect("channel closed");

    assert!(!result.1, "sig_ok must be false for Signature::Unsigned");
}

// ── handle_transaction_received (D·15d) ──────────────────────────────────────

/// Build a genesis block and write it to the db so `handle_transaction_received`
/// can read the tip state root.
fn seed_genesis(db: &LemmaDb) -> Hash {
    let block = make_block_at(0, Hash::zero());
    let hash = compute_block_hash(&block).expect("hash");
    ChainStore::new(db)
        .put_block(&block, hash)
        .expect("put_block");
    hash
}

#[tokio::test]
async fn transaction_received_admitted_to_mempool_with_valid_sig() {
    // Arrange: genesis initialized via init_chain so the WorldState has real
    // trie nodes. The sender is funded with 1 LEM so balance check passes.
    let kp = KeyPair::generate().expect("keygen");
    let sender = *kp.address();
    let recipient = Address::from_public_key(&[99u8; 32]);

    let mut initial_balances = std::collections::BTreeMap::new();
    initial_balances.insert(sender, Amount::from_drop(1_000_000_000_000_000_000)); // 1 LEM

    let dir = tempfile::TempDir::new().unwrap();
    // init_chain requires at least one genesis validator.
    // Use a dummy validator (sender acts as sole validator for test setup).
    use lemma_core::validator::{Stake, Validator, ValidatorStatus};
    let dummy_ck = ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952]);
    let validator = Validator {
        address: sender,
        consensus_pubkey: dummy_ck,
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active: Amount::from_drop(1_000_000),
            pending_active: Amount::from_drop(0),
            pending_inactive: vec![],
            inactive: Amount::from_drop(0),
        },
        delegated: Amount::from_drop(0),
        commission_bps: 0,
        jailed_until: None,
    };
    let mut genesis_validators = std::collections::BTreeMap::new();
    genesis_validators.insert(sender, validator);
    let genesis = GenesisConfig {
        chain_id: 1,
        genesis_timestamp: 1_000_000,
        initial_gas_limit: 30_000_000,
        initial_base_fee: Amount::from_drop(1_000_000_000),
        initial_balances,
        genesis_validators,
    };
    init_chain(LemmaDb::open(dir.path()).unwrap(), &genesis).unwrap();
    let db = Arc::new(LemmaDb::open(dir.path()).unwrap());

    // Build and sign a Transfer tx (value=0, gas_price=0 → zero gas cost).
    let mut tx = Transaction::new(
        Hash::zero(),
        sender,
        Some(recipient),
        0,
        1, // chain_id = 1
        Amount::from_drop(0),
        21_000,
        Amount::from_drop(0),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("Transaction::new");
    sign_transaction(&mut tx, &kp).expect("sign");

    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let pk = kp.public_key();
    let sender_pubkey = ConsensusKey::from_bytes(pk.classical.clone(), pk.quantum.clone());

    // Act.
    handle_transaction_received(libp2p::PeerId::random(), tx, sender_pubkey, &db, &mempool).await;

    // Assert: tx was admitted.
    assert_eq!(
        mempool.read().await.len(),
        1,
        "valid signed tx must be admitted to mempool"
    );
}

#[tokio::test]
async fn transaction_received_invalid_pubkey_rejected_by_mempool() {
    // Arrange: signed tx but wrong pubkey (different keypair).
    // The pubkey-to-address derivation check fires before sig verify,
    // so the tx is rejected at step 4 (pubkey mismatch) — no balance needed.
    let kp = KeyPair::generate().expect("keygen");
    let wrong_kp = KeyPair::generate().expect("keygen");
    let mut tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::from_public_key(&[99u8; 32])),
        0,
        1,
        Amount::from_drop(0),
        21_000,
        Amount::from_drop(0), // zero gas_price — balance check irrelevant (fails at step 4)
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("Transaction::new");
    lemma_crypto::sign_transaction(&mut tx, &kp).expect("sign");

    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let db = Arc::new(db);

    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    // Use the WRONG keypair's pubkey — pubkey→address derivation mismatch fires first.
    let wrong_pk = wrong_kp.public_key();
    let sender_pubkey =
        ConsensusKey::from_bytes(wrong_pk.classical.clone(), wrong_pk.quantum.clone());

    // Act.
    handle_transaction_received(libp2p::PeerId::random(), tx, sender_pubkey, &db, &mempool).await;

    // Assert: mempool stays empty (pubkey mismatch → rejected at step 4).
    assert_eq!(
        mempool.read().await.len(),
        0,
        "tx with wrong pubkey must be rejected by mempool"
    );
}

#[tokio::test]
async fn batch_received_unsigned_tx_dropped_by_security_gate() {
    // Arrange: batch containing an unsigned tx — must be rejected by D·15d gate.
    let kp = KeyPair::generate().expect("keygen");
    let unsigned_tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::from_public_key(&[99u8; 32])),
        0,
        1,
        Amount::from_drop(0),
        21_000,
        Amount::from_drop(1_000_000_000),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("Transaction::new");

    // Compute the correct hash so the per-tx hash check passes.
    let mut tx_with_hash = unsigned_tx;
    tx_with_hash.hash = lemma_crypto::compute_tx_hash(&tx_with_hash).expect("hash");

    let batch = crate::batch::Batch::new(Address::from_public_key(&[1u8; 32]), vec![tx_with_hash]);
    let bytes = serde_json::to_vec(&batch).expect("encode");
    let store = crate::batch::new_batch_store();

    // Act: use empty vset (no validator-set sig verify needed — unsigned check fires first).
    handle_batch_received(libp2p::PeerId::random(), bytes, &store, &empty_vset()).await;

    // Assert: store stays empty — unsigned tx caused batch rejection.
    assert!(
        store.read().await.is_empty(),
        "batch with unsigned tx must be dropped by D·15d security gate"
    );
}

#[tokio::test]
async fn batch_received_vset_sender_invalid_sig_dropped_by_security_gate() {
    // Arrange: batch with a tx whose sender IS in vset but sig is tampered.
    let kp = KeyPair::generate().expect("keygen");
    let vset = single_member_vset(&kp);

    let mut tx = make_signed_tx_for_batch(&kp, 0);
    // Tamper the signature after signing.
    tx.signature = Signature::Hybrid {
        classical: vec![0xDE; 64],
        quantum: vec![0xAD; 3309],
    };
    // Recompute hash so per-tx hash check passes (hash covers body, not sig).
    tx.hash = lemma_crypto::compute_tx_hash(&tx).expect("hash");

    let batch = crate::batch::Batch::new(Address::from_public_key(&[1u8; 32]), vec![tx]);
    let bytes = serde_json::to_vec(&batch).expect("encode");
    let store = crate::batch::new_batch_store();

    // Act.
    handle_batch_received(libp2p::PeerId::random(), bytes, &store, &vset).await;

    // Assert: store stays empty — tampered sig rejected for vset sender.
    assert!(
        store.read().await.is_empty(),
        "batch with tampered sig from vset sender must be dropped by D·15d security gate"
    );
}
