//! Tests for [`producer`].
//!
//! Covers: build_next_block (chain/base_fee/timestamp/hash correctness),
//! commit_block, chain continuity across multiple blocks, and the async
//! `run` loop (produces blocks until shutdown, error policy).

use std::sync::Arc;
use std::time::Duration;

use tempfile::TempDir;
use tokio::sync::{watch, Mutex, RwLock};

use lemma_core::{address::Address, amount::Amount, block::Block, hash::Hash, header::BlockHeader};
use lemma_mempool::pool::Mempool;
use lemma_storage::{ChainStore, LemmaDb};

use super::*;

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, TempDir) {
    let dir = TempDir::new().expect("TempDir::new must succeed");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed");
    (db, dir)
}

/// A minimal valid genesis block at height 0 with realistic header values.
///
/// Uses non-zero gas_limit (required by BlockHeader::new) and a 1-Drip base
/// fee so calculate_base_fee has a sensible starting point.
fn make_genesis_block() -> (Block, Hash) {
    let validators_hash = Hash::from_bytes([0xAA; 32]);
    let header = BlockHeader::new(
        0,                                // height
        1_700_000_000,                    // timestamp
        Hash::zero(),                     // parent_hash
        Hash::zero(),                     // transactions_root
        Hash::zero(),                     // state_root
        Hash::zero(),                     // receipts_root
        Address::zero(),                  // proposer
        0,                                // epoch
        1,                                // protocol_version (genesis = 1)
        0,                                // dag_round
        Hash::zero(),                     // dag_anchor
        validators_hash,                  // validators_hash
        validators_hash,                  // next_validators_hash
        30_000_000,                       // gas_limit
        0,                                // gas_used
        Amount::from_drop(1_000_000_000), // base_fee = 1 Drip
        vec![],
    )
    .expect("genesis header must be valid");

    let block = Block::new(header, vec![], vec![], None).expect("genesis block must be valid");
    // serde_json is used (not bincode) — see chain.rs serialization note.
    let bytes = serde_json::to_vec(&block).expect("serialize must succeed");
    let hash = lemma_crypto::hash_bytes(&bytes);
    (block, hash)
}

/// Write a genesis block into `db` and return its hash.
fn seed_genesis(db: &LemmaDb) -> Hash {
    let (block, hash) = make_genesis_block();
    ChainStore::new(db)
        .put_block(&block, hash)
        .expect("seed genesis must succeed");
    hash
}

// ── build_next_block ──────────────────────────────────────────────────────────

#[test]
fn build_next_block_produces_block_at_parent_height_plus_one() {
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let chain = ChainStore::new(&db);

    let (block, _) =
        build_next_block(&chain, Address::zero(), 1_700_001_000).expect("build must succeed");

    assert_eq!(
        block.height(),
        1,
        "first produced block must be at height 1"
    );
}

#[test]
fn build_next_block_chains_parent_hash_to_genesis_hash() {
    let (db, _dir) = open_temp_db();
    let genesis_hash = seed_genesis(&db);
    let chain = ChainStore::new(&db);

    let (block, _) =
        build_next_block(&chain, Address::zero(), 1_700_001_000).expect("build must succeed");

    assert_eq!(
        block.header.parent_hash, genesis_hash,
        "parent_hash must equal the genesis block hash"
    );
}

#[test]
fn build_next_block_produces_empty_block_no_txs_no_receipts_zero_gas() {
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let chain = ChainStore::new(&db);

    let (block, _) =
        build_next_block(&chain, Address::zero(), 1_700_001_000).expect("build must succeed");

    assert!(
        block.is_empty(),
        "Phase 1 block must contain no transactions"
    );
    assert_eq!(block.header.gas_used, 0);
}

#[test]
fn build_next_block_inherits_state_root_from_parent() {
    // No VM execution → state_root must be unchanged from genesis.
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let genesis = ChainStore::new(&db)
        .get_block_by_height(0)
        .unwrap()
        .unwrap();
    let parent_state_root = genesis.header.state_root;

    let chain = ChainStore::new(&db);
    let (block, _) =
        build_next_block(&chain, Address::zero(), 1_700_001_000).expect("build must succeed");

    assert_eq!(
        block.header.state_root, parent_state_root,
        "Phase 1: state_root must be unchanged (no VM execution)"
    );
}

#[test]
fn build_next_block_computes_base_fee_from_parent() {
    // Genesis has 0 gas_used → fee decreases or stays at floor.
    // We just assert it's a valid Amount (non-panic, no overflow).
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let chain = ChainStore::new(&db);

    let (block, _) =
        build_next_block(&chain, Address::zero(), 1_700_001_000).expect("build must succeed");

    // base_fee must be >= MIN_BASE_FEE_DROP (anti-spam floor).
    let min = lemma_consensus::MIN_BASE_FEE_DROP;
    assert!(
        block.header.base_fee.as_drop() >= min,
        "base_fee must be at least MIN_BASE_FEE_DROP ({min}), got {}",
        block.header.base_fee.as_drop()
    );
}

#[test]
fn build_next_block_clamps_timestamp_to_parent_plus_one() {
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let genesis = ChainStore::new(&db)
        .get_block_by_height(0)
        .unwrap()
        .unwrap();
    let chain = ChainStore::new(&db);

    // Pass a timestamp BEFORE genesis (e.g. 0) — must be clamped.
    let (block, _) = build_next_block(&chain, Address::zero(), 0)
        .expect("build must succeed even with stale timestamp");

    assert_eq!(
        block.header.timestamp,
        genesis.header.timestamp + 1,
        "timestamp must be clamped to parent.timestamp + 1"
    );
}

#[test]
fn build_next_block_errors_when_chain_uninitialised() {
    // No genesis block in DB → tip() returns None → Config error.
    let (db, _dir) = open_temp_db();
    let chain = ChainStore::new(&db);

    let err = build_next_block(&chain, Address::zero(), 1_700_000_000)
        .expect_err("must error when chain has no genesis");
    assert!(
        matches!(err, NodeError::Config(_)),
        "expected Config error, got: {err:?}"
    );
}

#[test]
fn build_next_block_returns_deterministic_hash() {
    // Same parent → same block → same hash on every call.
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let chain = ChainStore::new(&db);
    let ts = 1_700_001_000;

    let (_, hash_a) = build_next_block(&chain, Address::zero(), ts).expect("build a");
    let (_, hash_b) = build_next_block(&chain, Address::zero(), ts).expect("build b");

    assert_eq!(hash_a, hash_b, "same inputs must produce same hash");
}

// ── commit_block ──────────────────────────────────────────────────────────────

#[test]
fn commit_block_persists_and_advances_tip() {
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let chain = ChainStore::new(&db);

    let (block, hash) = build_next_block(&chain, Address::zero(), 1_700_001_000).unwrap();
    commit_block(&chain, &block, hash).expect("commit must succeed");

    let tip = chain.tip().unwrap().unwrap();
    assert_eq!(tip.0, 1, "tip height must advance to 1");
    assert_eq!(tip.1, hash, "tip hash must match committed hash");
}

#[test]
fn commit_block_makes_block_retrievable_by_height_and_hash() {
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let chain = ChainStore::new(&db);

    let (block, hash) = build_next_block(&chain, Address::zero(), 1_700_001_000).unwrap();
    commit_block(&chain, &block, hash).expect("commit must succeed");

    assert!(
        chain.get_block_by_height(1).unwrap().is_some(),
        "get by height must find block"
    );
    assert!(
        chain.get_block_by_hash(&hash).unwrap().is_some(),
        "get by hash must find block"
    );
}

// ── Sequential chain continuity ───────────────────────────────────────────────

#[test]
fn three_sequential_build_commit_cycles_produce_continuous_chain() {
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let chain = ChainStore::new(&db);

    let mut prev_hash = chain.tip().unwrap().unwrap().1; // genesis hash

    for i in 1u64..=3 {
        let ts = 1_700_000_000 + i;
        let (block, hash) = build_next_block(&chain, Address::zero(), ts).unwrap();
        assert_eq!(block.height(), i);
        assert_eq!(
            block.header.parent_hash, prev_hash,
            "height {i}: parent_hash must link to previous block"
        );
        commit_block(&chain, &block, hash).unwrap();
        prev_hash = hash;
    }

    assert_eq!(chain.latest_height().unwrap().unwrap(), 3);
}

// ── Async run loop ────────────────────────────────────────────────────────────

#[tokio::test]
async fn run_produces_blocks_until_shutdown() {
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let db = Arc::new(db);

    let mempool = Arc::new(RwLock::new(Mempool::new(64)));
    let cfg = ProducerConfig {
        block_interval_ms: 1,
    }; // 1 ms → fast test
    let (tx, rx) = watch::channel(false);

    let db_task = db.clone();
    let mp_task = mempool.clone();
    let write_lock = Arc::new(Mutex::new(()));
    let handle = tokio::spawn(async move {
        run(db_task, mp_task, cfg, Address::zero(), None, write_lock, rx).await
    });

    // Poll until tip reaches height 3 (or timeout after 5 s).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let h = ChainStore::new(&db).latest_height().unwrap().unwrap_or(0);
        if h >= 3 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for height 3 (currently at {h})"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    // Signal shutdown.
    tx.send(true).expect("shutdown send must succeed");
    handle
        .await
        .expect("task must not panic")
        .expect("run must return Ok");

    let final_height = ChainStore::new(&db).latest_height().unwrap().unwrap();
    assert!(
        final_height >= 3,
        "chain must have at least 3 blocks after run"
    );
}

#[tokio::test]
async fn run_skips_tick_on_build_error_and_continues() {
    // Seed NO genesis block → every tick will produce a Config error → warn
    // and skip. The loop must not crash; it continues until shutdown.
    let (db, _dir) = open_temp_db();
    // No seed_genesis call — chain is uninitialised.
    let db = Arc::new(db);

    let mempool = Arc::new(RwLock::new(Mempool::new(64)));
    let cfg = ProducerConfig {
        block_interval_ms: 1,
    };
    let (tx, rx) = watch::channel(false);

    let db_task = db.clone();
    let mp_task = mempool.clone();
    let write_lock = Arc::new(Mutex::new(()));
    let handle = tokio::spawn(async move {
        run(db_task, mp_task, cfg, Address::zero(), None, write_lock, rx).await
    });

    // Let it tick a few times (all will warn+skip), then shut down.
    tokio::time::sleep(Duration::from_millis(10)).await;
    tx.send(true).expect("shutdown send must succeed");
    handle
        .await
        .expect("task must not panic")
        .expect("run must return Ok");

    // No blocks produced — tip is None (chain still uninitialised).
    assert!(
        ChainStore::new(&db).latest_height().unwrap().is_none(),
        "no blocks should be produced when chain is uninitialised"
    );
}

// ── block_tx channel emission ─────────────────────────────────────────────────

#[tokio::test]
async fn run_emits_committed_blocks_on_block_tx_channel() {
    // Verify the channel seam: each produced block is sent on block_tx.
    let (db, _dir) = open_temp_db();
    seed_genesis(&db);
    let db = Arc::new(db);

    let mempool = Arc::new(RwLock::new(Mempool::new(64)));
    let cfg = ProducerConfig {
        block_interval_ms: 1,
    };
    let (tx, rx) = watch::channel(false);
    let (block_tx, mut block_rx) = tokio::sync::mpsc::channel(16);

    let db_task = db.clone();
    let mp_task = mempool.clone();
    let write_lock = Arc::new(Mutex::new(()));
    let handle = tokio::spawn(async move {
        run(
            db_task,
            mp_task,
            cfg,
            Address::zero(),
            Some(block_tx),
            write_lock,
            rx,
        )
        .await
    });

    // Wait until at least 2 blocks are received on the channel.
    let mut received = 0usize;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while received < 2 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for 2 blocks on block_tx (got {received})"
        );
        match tokio::time::timeout(Duration::from_millis(10), block_rx.recv()).await {
            Ok(Some(_)) => received += 1,
            Ok(None) => break, // sender dropped
            Err(_) => {}       // timeout — retry
        }
    }

    assert!(
        received >= 2,
        "must receive at least 2 blocks on block_tx channel"
    );

    tx.send(true).expect("shutdown must succeed");
    handle
        .await
        .expect("task must not panic")
        .expect("run must return Ok");
}
