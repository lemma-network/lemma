//! Integration test: two-node range sync (Phase 1 milestone).
//!
//! Demonstrates the Phase-1 "2 nodes sync blocks via P2P" milestone
//! (04-BUILD_GUIDE §2.6 Phase-1 checklist item).
//!
//! ## What this tests
//!
//! A "source" node (node A) has a fully produced chain of N blocks.
//! A "destination" node (node B) has only genesis (height 0).
//! Node B applies the range [1..N] from node A's chain using
//! `apply_synced_block` + `StructuralVerifier`.
//!
//! This tests the full apply path — including the write-lock, the
//! double-check tip pattern, and `SyncTracker` gap detection — without
//! a live network stack (avoiding real libp2p in CI).
//!
//! Full round-trip two-node sync with real P2P (gossip → gap detect →
//! `RequestRange` → `RangeResponse` → apply) is verified manually by
//! running two `lemma-node` binaries on the same host, which is the
//! ultimate validation of the Phase-1 milestone.

use std::sync::Arc;

use tempfile::TempDir;
use tokio::sync::Mutex;

use lemma_core::{
    address::Address,
    amount::Amount,
    block::Block,
    hash::Hash,
    header::BlockHeader,
};
use lemma_node::{
    StructuralVerifier, SyncTracker,
    apply_synced_block, ApplyOutcome,
};
use libp2p::PeerId;
use lemma_storage::{chain::ChainStore, db::LemmaDb};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, TempDir) {
    let dir = TempDir::new().expect("TempDir");
    let db  = LemmaDb::open(dir.path()).expect("LemmaDb::open");
    (db, dir)
}

fn make_block(height: u64, parent_hash: Hash) -> (Block, Hash) {
    let vh = Hash::from_bytes([0xCC; 32]);
    let h  = BlockHeader::new(
        height,
        1_700_000_000 + height,
        parent_hash,
        Hash::zero(), Hash::zero(), Hash::zero(),
        Address::zero(), 0, 0, Hash::zero(), vh, vh,
        30_000_000, 0, Amount::from_drop(1_000_000_000), vec![],
    )
    .expect("header");
    let block = Block::new(h, vec![], vec![]).expect("block");
    let bytes = bincode::serialize(&block).expect("serialize");
    let hash  = lemma_crypto::hash_bytes(&bytes);
    (block, hash)
}

fn seed_chain(db: &LemmaDb, n: u64) {
    let mut prev = Hash::zero();
    for h in 0..n {
        let (block, hash) = make_block(h, prev);
        ChainStore::new(db).put_block(&block, hash).expect("put_block");
        prev = hash;
    }
}

// ── Integration test ──────────────────────────────────────────────────────────

/// Two-node sync: B (height 0) catches up to A (height 10) via range apply.
#[tokio::test]
async fn two_node_range_sync_applies_all_blocks() {
    const CHAIN_LENGTH: u64 = 10;

    // Node A: fully produced chain (heights 0..9).
    let (db_a, _dir_a) = open_temp_db();
    seed_chain(&db_a, CHAIN_LENGTH);

    // Node B: only genesis (height 0).
    let (db_b, _dir_b) = open_temp_db();
    seed_chain(&db_b, 1);
    let db_b      = Arc::new(db_b);
    let write_lock = Arc::new(Mutex::new(()));
    let verifier   = StructuralVerifier;

    // Simulate node B detecting it's behind and applying blocks from A.
    for h in 1..CHAIN_LENGTH {
        let block = ChainStore::new(&db_a)
            .get_block_by_height(h)
            .expect("get block")
            .expect("block exists");

        let outcome = apply_synced_block(&block, &db_b, &write_lock, &verifier)
            .await
            .expect("apply must succeed");

        assert!(
            matches!(outcome, ApplyOutcome::Applied { height, .. } if height == h),
            "height {h}: expected Applied, got {outcome:?}"
        );
    }

    let final_tip = ChainStore::new(&db_b)
        .latest_height()
        .expect("latest_height")
        .expect("tip must exist");

    assert_eq!(
        final_tip,
        CHAIN_LENGTH - 1,
        "node B must be fully synced to node A's tip"
    );
}

/// Structural verify blocks a tampered block: wrong parent_hash → rejected.
#[tokio::test]
async fn sync_rejects_tampered_parent_hash() {
    let (db_a, _dir_a) = open_temp_db();
    seed_chain(&db_a, 3); // heights 0, 1, 2

    let (db_b, _dir_b) = open_temp_db();
    seed_chain(&db_b, 1); // genesis only
    let db_b      = Arc::new(db_b);
    let write_lock = Arc::new(Mutex::new(()));
    let verifier   = StructuralVerifier;

    // Tamper: take block 1 from A but forge parent_hash.
    let good_block = ChainStore::new(&db_a)
        .get_block_by_height(1).expect("get").expect("exists");
    let tampered_header = BlockHeader::new(
        1, good_block.header.timestamp,
        Hash::from_bytes([0xFF; 32]), // wrong parent
        Hash::zero(), Hash::zero(), Hash::zero(),
        Address::zero(), 0, 0, Hash::zero(),
        Hash::from_bytes([0xCC; 32]), Hash::from_bytes([0xCC; 32]),
        30_000_000, 0, Amount::from_drop(1_000_000_000), vec![],
    ).expect("header");
    let tampered_block = Block::new(tampered_header, vec![], vec![]).expect("block");

    let err = apply_synced_block(&tampered_block, &db_b, &write_lock, &verifier)
        .await
        .expect_err("tampered block must be rejected");

    assert!(
        matches!(err, lemma_node::NodeError::Verify(_)),
        "expected Verify error, got: {err}"
    );
    // Tip must not have advanced.
    assert_eq!(
        ChainStore::new(&db_b).latest_height().unwrap().unwrap(),
        0,
        "tip must not advance on tampered block"
    );
}

/// SyncTracker correctly identifies gaps and chunks large ranges.
#[test]
fn sync_tracker_identifies_gap_and_chunks() {
    let mut tracker = SyncTracker::new();
    tracker.observe(300, PeerId::random()); // network tip at height 300

    // First chunk: local_tip=0, max_range=256.
    let chunk1 = tracker.next_request(0, 256).expect("chunk 1");
    assert_eq!(chunk1, (1, 256));

    // Simulate applying chunk 1.
    tracker.on_tip_advanced(256);

    // Second chunk: local_tip=256, max_range=256.
    let chunk2 = tracker.next_request(256, 256).expect("chunk 2");
    assert_eq!(chunk2, (257, 300));

    // Simulate applying chunk 2 — now fully synced.
    tracker.on_tip_advanced(300);

    // No more gaps.
    assert!(tracker.next_request(300, 256).is_none());
}
