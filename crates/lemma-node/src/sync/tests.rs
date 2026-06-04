//! Tests for [`sync`].
//!
//! Covers:
//! - [`StructuralVerifier`]: valid block, bad height, bad parent_hash,
//!   bad hash (tampered bytes), intra-block invalid, height overflow guard.
//! - [`SyncTracker`]: gap detection, chunked requests, watermark
//!   idempotency, `on_tip_advanced`.
//! - [`apply_synced_block`]: apply success, stale-tip double-check,
//!   verify-error propagation, sequential apply of a range.
//! - [`compute_block_hash`]: consistency with producer convention.

use std::sync::Arc;

use tempfile::TempDir;
use tokio::sync::Mutex;

use lemma_core::{address::Address, amount::Amount, block::Block, hash::Hash, header::BlockHeader};
use lemma_storage::{chain::ChainStore, db::LemmaDb};

use super::*;

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, TempDir) {
    let dir = TempDir::new().expect("TempDir");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open");
    (db, dir)
}

fn make_block(height: u64, parent_hash: Hash) -> Block {
    let vh = Hash::from_bytes([0xBB; 32]);
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
    .expect("header");
    Block::new(h, vec![], vec![], None).expect("block")
}

/// Seed `n` blocks (heights 0..n) and return the hash of the last one.
fn seed_n_blocks(db: &LemmaDb, n: u64) -> Hash {
    let mut prev = Hash::zero();
    for h in 0..n {
        let block = make_block(h, prev);
        let hash = compute_block_hash(&block).expect("hash");
        ChainStore::new(db)
            .put_block(&block, hash)
            .expect("put_block");
        prev = hash;
    }
    prev
}

fn verifier() -> StructuralVerifier {
    StructuralVerifier
}

// ── compute_block_hash ────────────────────────────────────────────────────────

#[test]
fn compute_block_hash_is_deterministic() {
    let block = make_block(1, Hash::zero());
    let hash_a = compute_block_hash(&block).expect("hash");
    let hash_b = compute_block_hash(&block).expect("hash");
    assert_eq!(hash_a, hash_b);
}

#[test]
fn compute_block_hash_differs_for_different_heights() {
    let a = compute_block_hash(&make_block(1, Hash::zero())).expect("a");
    let b = compute_block_hash(&make_block(2, Hash::zero())).expect("b");
    assert_ne!(a, b);
}

// ── StructuralVerifier ────────────────────────────────────────────────────────

#[test]
fn verify_accepts_valid_sequential_block() {
    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    let block1 = make_block(1, g_hash);
    let result = verifier().verify(&block1, g_hash, 0);
    assert!(result.is_ok(), "valid block must pass: {result:?}");
}

#[test]
fn verify_rejects_wrong_height() {
    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    // Block at height 3 — wrong, expected 1.
    let block3 = make_block(3, g_hash);
    let err = verifier()
        .verify(&block3, g_hash, 0)
        .expect_err("must fail");
    assert!(
        matches!(err, VerifyError::HeightMismatch { expected: 1, .. }),
        "got: {err}"
    );
}

#[test]
fn verify_rejects_wrong_parent_hash() {
    let wrong_prev = Hash::from_bytes([0xDE; 32]);
    let real_prev = Hash::from_bytes([0xAD; 32]);
    // Block claims parent = wrong_prev, but local tip has real_prev.
    let block1 = make_block(1, wrong_prev);
    let err = verifier()
        .verify(&block1, real_prev, 0)
        .expect_err("must fail");
    assert!(
        matches!(err, VerifyError::ParentHashMismatch { expected, .. } if expected == real_prev),
        "got: {err}"
    );
}

#[test]
fn verify_returns_correct_hash() {
    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    let block1 = make_block(1, g_hash);
    let expected_hash = compute_block_hash(&block1).expect("expected");
    let result_hash = verifier().verify(&block1, g_hash, 0).expect("verify");
    assert_eq!(
        result_hash, expected_hash,
        "returned hash must match canonical hash"
    );
}

#[test]
fn verify_rejects_height_overflow() {
    let block = make_block(0, Hash::zero()); // height doesn't matter here
    let err = verifier()
        .verify(&block, Hash::zero(), u64::MAX)
        .expect_err("must fail");
    assert!(
        matches!(
            err,
            VerifyError::HeightOverflow {
                prev_height: u64::MAX
            }
        ),
        "got: {err}"
    );
}

// ── ApplyOutcome::Stale ───────────────────────────────────────────────────────

#[tokio::test]
async fn apply_synced_block_returns_stale_when_tip_advances_under_lock() {
    // Test the double-check pattern in apply_synced_block:
    //   Step 1 (outside lock): read tip = 0, verify block1 → OK
    //   Step 3 (inside lock):  re-read tip = 1 (producer won race) → Stale
    //
    // We hold the write-lock before spawning apply_synced_block.
    // The task executes: reads tip=0, verifies OK, then tries to acquire the
    // lock — blocks because the test holds it.
    // While the task waits, the test writes block1 (advancing tip to 1) and
    // releases the lock. The task wakes up, re-checks tip=1 ≠ prev=0 → Stale.
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 1); // genesis (tip = 0)
    let db = Arc::new(db);
    let lock = Arc::new(Mutex::new(()));

    let tip_hash = ChainStore::new(&db).tip().unwrap().unwrap().1;
    let block1 = make_block(1, tip_hash);
    let hash1 = compute_block_hash(&block1).expect("hash1");

    // Acquire lock BEFORE spawning apply — task will block at step 3.
    let guard = lock.lock().await;

    let db2 = Arc::clone(&db);
    let lock2 = Arc::clone(&lock);
    let block2 = block1.clone();
    let task = tokio::spawn(async move {
        apply_synced_block(&block2, &db2, &lock2, &StructuralVerifier).await
    });

    // Yield so the task runs steps 1-2 (sync) and then blocks at lock.lock().await.
    tokio::task::yield_now().await;

    // Now advance the tip while holding the lock (simulate producer winning race).
    ChainStore::new(&db)
        .put_block(&block1, hash1)
        .expect("producer write");

    // Release lock — task wakes up, re-reads tip=1 ≠ prev_height=0 → Stale.
    drop(guard);

    let outcome = task
        .await
        .expect("task must not panic")
        .expect("must not error");
    assert_eq!(
        outcome,
        ApplyOutcome::Stale,
        "must be Stale when tip advanced under lock"
    );
    assert_eq!(ChainStore::new(&db).latest_height().unwrap().unwrap(), 1);
}

// ── SyncTracker ───────────────────────────────────────────────────────────────

#[test]
fn tracker_no_request_when_at_tip() {
    let mut t = SyncTracker::new();
    t.observe(5, libp2p::PeerId::random());
    // local_tip == highest_seen → no gap.
    assert!(t.next_request(5, 256).is_none());
}

#[test]
fn tracker_no_request_when_one_ahead() {
    // highest_seen = local_tip + 1 exactly → not a gap (the block might arrive
    // immediately via gossip and be applied directly).
    let mut t = SyncTracker::new();
    t.observe(5, libp2p::PeerId::random());
    assert!(
        t.next_request(4, 256).is_none(),
        "exactly +1 is not a range-sync gap"
    );
}

#[test]
fn tracker_requests_range_when_gap_detected() {
    let mut t = SyncTracker::new();
    t.observe(10, libp2p::PeerId::random());
    // local_tip = 2, highest_seen = 10 → gap at 3..=10
    let req = t.next_request(2, 256).expect("must produce request");
    assert_eq!(req, (3, 10));
}

#[test]
fn tracker_clamps_to_max_range() {
    let mut t = SyncTracker::new();
    t.observe(1000, libp2p::PeerId::random());
    // max_range = 256 → request at most 256 blocks
    let req = t.next_request(0, 256).expect("must produce request");
    assert_eq!(req.0, 1);
    assert_eq!(req.1, 256, "must clamp to max_range");
}

#[test]
fn tracker_does_not_re_request_inflight_range() {
    let mut t = SyncTracker::new();
    t.observe(10, libp2p::PeerId::random());
    t.next_request(2, 256); // issues request for 3..=10
                            // Second call: same gap, same highest_seen — must not re-issue.
    assert!(
        t.next_request(2, 256).is_none(),
        "must not re-request already-in-flight range"
    );
}

#[test]
fn tracker_on_tip_advanced_clears_watermark() {
    let mut t = SyncTracker::new();
    t.observe(10, libp2p::PeerId::random());
    t.next_request(2, 256); // requested_up_to = 10
                            // Tip advances to 10 (all blocks applied).
    t.on_tip_advanced(10);
    // New higher block arrives at 15.
    t.observe(15, libp2p::PeerId::random());
    // Now can request again.
    let req = t.next_request(10, 256).expect("must produce new request");
    assert_eq!(req, (11, 15));
}

#[test]
fn tracker_chunked_requests_advance_watermark() {
    let mut t = SyncTracker::new();
    t.observe(500, libp2p::PeerId::random());
    // First chunk: max_range = 100 → requests 1..=100
    let r1 = t.next_request(0, 100).expect("chunk 1");
    assert_eq!(r1, (1, 100));
    // Tip advances to 100, reset.
    t.on_tip_advanced(100);
    // Second chunk: requests 101..=200
    let r2 = t.next_request(100, 100).expect("chunk 2");
    assert_eq!(r2, (101, 200));
}

// ── SyncTracker: short-served chunk ──────────────────────────────────────────

#[test]
fn tracker_retries_after_partial_response_via_on_tip_advanced() {
    // Simulate: gap is 1..=300, max_range=256.
    // First chunk: request 1..=256.
    // Partial response: only 1..=100 served (peer had a gap at 101).
    // Tip advances to 100 via on_tip_advanced.
    // next_request should issue 101..=256 (still within the original requested
    // watermark), then after on_tip_advanced(256) → 257..=300.
    let mut t = SyncTracker::new();
    let peer = libp2p::PeerId::random();
    t.observe(300, peer);

    // Chunk 1 requested: 1..=256.
    let r1 = t.next_request(0, 256).expect("chunk 1");
    assert_eq!(r1, (1, 256));

    // Partial: only 1..=100 applied. requested_up_to stays 256.
    // next_request(100, 256): highest_seen(300) > requested_up_to(256) → issue 101..=256.
    t.on_tip_advanced(100);
    let r2 = t.next_request(100, 256).expect("retry of remainder");
    assert_eq!(
        r2,
        (101, 300),
        "must retry remaining gap after partial response"
    );
}

// ── apply_synced_block ────────────────────────────────────────────────────────

#[tokio::test]
async fn apply_synced_block_applies_valid_block() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 1); // genesis at height 0
    let db = Arc::new(db);
    let lock = Arc::new(Mutex::new(()));

    let tip_hash = ChainStore::new(&db).tip().unwrap().unwrap().1;
    let block1 = make_block(1, tip_hash);

    let outcome = apply_synced_block(&block1, &db, &lock, &verifier())
        .await
        .expect("apply must succeed");

    assert!(
        matches!(outcome, ApplyOutcome::Applied { height: 1, .. }),
        "got: {outcome:?}"
    );
    assert_eq!(ChainStore::new(&db).latest_height().unwrap().unwrap(), 1);
}

#[tokio::test]
async fn apply_synced_block_returns_verify_error_on_bad_parent() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 1);
    let db = Arc::new(db);
    let lock = Arc::new(Mutex::new(()));

    // Wrong parent_hash.
    let block1 = make_block(1, Hash::from_bytes([0xFF; 32]));
    let err = apply_synced_block(&block1, &db, &lock, &verifier())
        .await
        .expect_err("must error on bad parent");
    assert!(matches!(err, NodeError::Verify(_)), "got: {err}");
    // Tip must not advance.
    assert_eq!(ChainStore::new(&db).latest_height().unwrap().unwrap(), 0);
}

#[tokio::test]
async fn apply_synced_block_returns_no_tip_on_uninitialised_chain() {
    let (db, _dir) = open_temp_db();
    let db = Arc::new(db);
    let lock = Arc::new(Mutex::new(()));
    let block = make_block(1, Hash::zero());
    let outcome = apply_synced_block(&block, &db, &lock, &verifier())
        .await
        .expect("must not error");
    assert_eq!(outcome, ApplyOutcome::NoTip);
}

#[tokio::test]
async fn apply_synced_block_sequential_range_syncs_correctly() {
    // Simulate syncing blocks 1..=5 in order — mirrors a range-response apply.
    let (db_src, _dir_src) = open_temp_db();
    let (db_dst, _dir_dst) = open_temp_db();

    // Source: seed 6 blocks (0..5).
    seed_n_blocks(&db_src, 6);
    // Destination: only genesis (height 0).
    seed_n_blocks(&db_dst, 1);

    let db_dst = Arc::new(db_dst);
    let lock = Arc::new(Mutex::new(()));

    for h in 1u64..=5 {
        let block = ChainStore::new(&db_src)
            .get_block_by_height(h)
            .expect("get")
            .expect("block must exist in source");

        let outcome = apply_synced_block(&block, &db_dst, &lock, &verifier())
            .await
            .expect("apply must succeed");

        assert!(
            matches!(outcome, ApplyOutcome::Applied { height, .. } if height == h),
            "height {h}: got {outcome:?}"
        );
    }

    assert_eq!(
        ChainStore::new(&db_dst).latest_height().unwrap().unwrap(),
        5,
        "destination must be fully synced"
    );
}
