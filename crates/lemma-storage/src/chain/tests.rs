//! Tests for [`ChainStore`].
//!
//! Covers: put/get roundtrip (by height + by hash), tip tracking, range
//! queries (happy + gap + inverted + empty chain), atomic CF writes, and
//! metadata advancement logic (tip only advances forward).
//!
//! All tests use `tempfile::tempdir()` for DB isolation per the storage test
//! convention (db/tests.rs pattern).

use tempfile::tempdir;

use lemma_core::{address::Address, amount::Amount, block::Block, hash::Hash, header::BlockHeader};

use super::*;
use crate::{
    db::{CF_BLOCKS, CF_BLOCK_HASH, CF_METADATA},
    LemmaDb, StorageError,
};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir must succeed");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed");
    (db, dir)
}

/// Build a minimal valid genesis block (height = 0).
fn genesis_block() -> (Block, Hash) {
    make_block_at(0, Hash::zero())
}

/// Build a minimal valid block at `height` chained to `parent_hash`.
///
/// No transactions, gas_used = 0. All optional roots = Hash::zero().
fn make_block_at(height: u64, parent_hash: Hash) -> (Block, Hash) {
    let validators_hash = Hash::from_bytes([height as u8; 32]);
    let header = BlockHeader::new(
        height,
        1_700_000_000 + height,
        parent_hash,
        Hash::zero(),    // transactions_root
        Hash::zero(),    // state_root
        Hash::zero(),    // receipts_root
        Address::zero(), // proposer
        0,               // epoch
        0,               // dag_round
        Hash::zero(),    // dag_anchor
        validators_hash,
        validators_hash, // next_validators_hash
        30_000_000,      // gas_limit
        0,               // gas_used
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("BlockHeader::new must succeed for valid params");

    let block =
        Block::new(header, vec![], vec![], None).expect("Block::new must succeed for valid params");

    // Compute hash from serialized bytes (canonical path, same as genesis_boot).
    // serde_json is used (not bincode) — see chain.rs serialization note.
    let bytes = serde_json::to_vec(&block).expect("serde_json::to_vec must succeed");
    let hash = lemma_crypto::hash_bytes(&bytes);
    (block, hash)
}

// ── put_block + get_block ─────────────────────────────────────────────────────

#[test]
fn put_block_then_get_by_height_returns_same_block() {
    let (db, _dir) = open_temp_db();
    let (block, hash) = genesis_block();
    let store = ChainStore::new(&db);

    store
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let got = store
        .get_block_by_height(0)
        .expect("get_block_by_height must succeed")
        .expect("block must be present");
    assert_eq!(got.height(), 0);
    assert_eq!(got.header.parent_hash, Hash::zero());
}

#[test]
fn put_block_then_get_by_hash_returns_same_block() {
    let (db, _dir) = open_temp_db();
    let (block, hash) = genesis_block();
    let store = ChainStore::new(&db);

    store
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let got = store
        .get_block_by_hash(&hash)
        .expect("get_block_by_hash must succeed")
        .expect("block must be present");
    assert_eq!(got.height(), block.height());
}

#[test]
fn put_block_height_and_hash_indexes_return_identical_bytes() {
    let (db, _dir) = open_temp_db();
    let (block, hash) = genesis_block();
    let store = ChainStore::new(&db);
    store
        .put_block(&block, hash)
        .expect("put_block must succeed");

    // Both CF entries must contain the same encoded bytes — confirmed by
    // reading the raw CF entries and comparing.
    let by_height = db
        .get(CF_BLOCKS, &0u64.to_be_bytes())
        .expect("CF_BLOCKS get must succeed")
        .expect("block must exist at height 0");
    let by_hash = db
        .get(CF_BLOCK_HASH, hash.as_bytes())
        .expect("CF_BLOCK_HASH get must succeed")
        .expect("block must exist by hash");
    assert_eq!(
        by_height, by_hash,
        "height and hash CFs must store identical bytes"
    );
}

#[test]
fn get_block_by_height_returns_none_for_missing_height() {
    let (db, _dir) = open_temp_db();
    let result = ChainStore::new(&db)
        .get_block_by_height(99)
        .expect("get_block_by_height must not error on missing key");
    assert!(result.is_none());
}

#[test]
fn get_block_by_hash_returns_none_for_unknown_hash() {
    let (db, _dir) = open_temp_db();
    let result = ChainStore::new(&db)
        .get_block_by_hash(&Hash::from_bytes([0xAB; 32]))
        .expect("get_block_by_hash must not error on missing key");
    assert!(result.is_none());
}

// ── tip / latest_height ───────────────────────────────────────────────────────

#[test]
fn tip_returns_none_on_empty_chain() {
    let (db, _dir) = open_temp_db();
    let tip = ChainStore::new(&db).tip().expect("tip must not error");
    assert!(tip.is_none(), "uninitialised chain must have no tip");
}

#[test]
fn latest_height_returns_none_on_empty_chain() {
    let (db, _dir) = open_temp_db();
    let h = ChainStore::new(&db)
        .latest_height()
        .expect("latest_height must not error");
    assert!(h.is_none());
}

#[test]
fn tip_returns_correct_height_and_hash_after_genesis() {
    let (db, _dir) = open_temp_db();
    let (block, hash) = genesis_block();
    let store = ChainStore::new(&db);
    store
        .put_block(&block, hash)
        .expect("put_block must succeed");

    let (height, tip_hash) = store
        .tip()
        .expect("tip must succeed")
        .expect("tip must be Some");
    assert_eq!(height, 0);
    assert_eq!(tip_hash, hash);
}

#[test]
fn tip_advances_with_each_committed_block() {
    let (db, _dir) = open_temp_db();
    let store = ChainStore::new(&db);

    let (b0, h0) = genesis_block();
    store.put_block(&b0, h0).expect("put b0");

    let (b1, h1) = make_block_at(1, h0);
    store.put_block(&b1, h1).expect("put b1");

    let (b2, h2) = make_block_at(2, h1);
    store.put_block(&b2, h2).expect("put b2");

    let (height, tip_hash) = store
        .tip()
        .expect("tip must succeed")
        .expect("tip must be Some");
    assert_eq!(height, 2);
    assert_eq!(tip_hash, h2);
}

#[test]
fn latest_height_matches_tip_after_multiple_puts() {
    let (db, _dir) = open_temp_db();
    let store = ChainStore::new(&db);

    let (b0, h0) = genesis_block();
    store.put_block(&b0, h0).expect("put b0");
    let (b1, h1) = make_block_at(1, h0);
    store.put_block(&b1, h1).expect("put b1");

    assert_eq!(store.latest_height().expect("latest_height").unwrap(), 1);
}

// ── tip does NOT regress (backfill path) ──────────────────────────────────────

#[test]
fn put_block_does_not_overwrite_tip_when_writing_earlier_height() {
    // Simulates range-sync backfill: tip is at 5, we fill gap at height 2.
    let (db, _dir) = open_temp_db();
    let store = ChainStore::new(&db);

    // Write block 0..=5 in order to establish tip.
    let (b0, h0) = genesis_block();
    store.put_block(&b0, h0).expect("put b0");
    let mut prev_hash = h0;
    for i in 1u64..=5 {
        let (b, h) = make_block_at(i, prev_hash);
        store.put_block(&b, h).expect("put b{i}");
        prev_hash = h;
    }
    let (tip_before, _) = store.tip().unwrap().unwrap();
    assert_eq!(tip_before, 5, "tip should be 5 before backfill");

    // Now "backfill" block 2 with a fresh (different) block at height 2.
    // (In practice range-sync writes the original block; this tests that
    // tip doesn't regress.)
    let (b2, h2) = make_block_at(2, h0); // height=2, parent=h0 (fresh hash)
    store.put_block(&b2, h2).expect("backfill put must succeed");

    let (tip_after, _) = store.tip().unwrap().unwrap();
    assert_eq!(tip_after, 5, "tip must NOT regress after backfill write");
}

// ── put_block atomicity ───────────────────────────────────────────────────────

#[test]
fn put_block_writes_all_four_cf_entries_atomically() {
    let (db, _dir) = open_temp_db();
    let (block, hash) = genesis_block();
    ChainStore::new(&db)
        .put_block(&block, hash)
        .expect("put_block must succeed");

    // All four writes must be present after a single put_block call.
    assert!(
        db.get(CF_BLOCKS, &0u64.to_be_bytes()).unwrap().is_some(),
        "CF_BLOCKS missing"
    );
    assert!(
        db.get(CF_BLOCK_HASH, hash.as_bytes()).unwrap().is_some(),
        "CF_BLOCK_HASH missing"
    );
    assert!(
        db.get(CF_METADATA, META_LATEST_HEIGHT).unwrap().is_some(),
        "latest_height missing"
    );
    assert!(
        db.get(CF_METADATA, META_LATEST_HASH).unwrap().is_some(),
        "latest_hash missing"
    );
}

// ── tip advancement — exact-height re-write ───────────────────────────────────

#[test]
fn put_block_at_same_height_advances_tip_hash() {
    // The `>=` (not `>`) guard means re-writing the same height DOES update the
    // tip hash. This covers deliberate re-indexing of the genesis block (e.g.
    // during recovery). The `>=` choice is intentional — lock it with a test.
    let (db, _dir) = open_temp_db();
    let store = ChainStore::new(&db);

    let (b0_v1, h0_v1) = genesis_block();
    store
        .put_block(&b0_v1, h0_v1)
        .expect("first put must succeed");
    let (tip_height_1, tip_hash_1) = store.tip().unwrap().unwrap();
    assert_eq!(tip_height_1, 0);
    assert_eq!(tip_hash_1, h0_v1);

    // Write a different block at the same height (different hash).
    let (b0_v2, h0_v2) = make_block_at(0, Hash::from_bytes([0xFF; 32])); // different parent
    assert_ne!(h0_v1, h0_v2, "test fixture must produce different hashes");
    store
        .put_block(&b0_v2, h0_v2)
        .expect("second put at same height must succeed");

    let (tip_height_2, tip_hash_2) = store.tip().unwrap().unwrap();
    assert_eq!(tip_height_2, 0, "height unchanged");
    assert_eq!(
        tip_hash_2, h0_v2,
        "tip hash must update to new hash at same height"
    );
}

// ── corruption paths ──────────────────────────────────────────────────────────

#[test]
fn latest_height_returns_serialization_error_for_malformed_metadata() {
    // Write 7 bytes (not 8) for latest_height — simulates partial write / corruption.
    let (db, _dir) = open_temp_db();
    db.put(CF_METADATA, META_LATEST_HEIGHT, &[0u8; 7])
        .expect("direct db put must succeed");

    let err = ChainStore::new(&db)
        .latest_height()
        .expect_err("malformed latest_height must return Err");
    assert!(
        matches!(err, StorageError::SerializationFailed { .. }),
        "expected SerializationFailed, got: {err:?}",
    );
}

#[test]
fn tip_returns_corrupted_when_hash_missing_but_height_present() {
    // Write latest_height but NOT latest_hash — partial write / corruption.
    let (db, _dir) = open_temp_db();
    db.put(CF_METADATA, META_LATEST_HEIGHT, &42u64.to_be_bytes())
        .expect("direct db put must succeed");
    // latest_hash deliberately absent.

    let err = ChainStore::new(&db)
        .tip()
        .expect_err("height-present + hash-absent must return Err");
    assert!(
        matches!(err, StorageError::Corrupted { .. }),
        "expected Corrupted, got: {err:?}",
    );
}

// ── get_range ─────────────────────────────────────────────────────────────────

#[test]
fn get_range_returns_contiguous_blocks() {
    let (db, _dir) = open_temp_db();
    let store = ChainStore::new(&db);

    let (b0, h0) = genesis_block();
    store.put_block(&b0, h0).expect("put b0");
    let (b1, h1) = make_block_at(1, h0);
    store.put_block(&b1, h1).expect("put b1");
    let (b2, h2) = make_block_at(2, h1);
    store.put_block(&b2, h2).expect("put b2");

    let range = store.get_range(0, 2).expect("get_range must succeed");
    assert_eq!(range.len(), 3);
    assert_eq!(range[0].height(), 0);
    assert_eq!(range[1].height(), 1);
    assert_eq!(range[2].height(), 2);
}

#[test]
fn get_range_stops_at_first_gap_returns_contiguous_prefix() {
    // Heights 0, 1, 3 written — 2 is missing. get_range(0, 3) → [0, 1].
    let (db, _dir) = open_temp_db();
    let store = ChainStore::new(&db);

    let (b0, h0) = genesis_block();
    store.put_block(&b0, h0).expect("put b0");
    let (b1, h1) = make_block_at(1, h0);
    store.put_block(&b1, h1).expect("put b1");
    // Skip height 2.
    let (b3, h3) = make_block_at(3, h1); // height 3, parent h1 (skip step)
    store.put_block(&b3, h3).expect("put b3");

    let range = store.get_range(0, 3).expect("get_range must succeed");
    assert_eq!(range.len(), 2, "must stop at the gap (height 2 missing)");
    assert_eq!(range[0].height(), 0);
    assert_eq!(range[1].height(), 1);
}

#[test]
fn get_range_single_height_from_equals_to() {
    let (db, _dir) = open_temp_db();
    let (block, hash) = genesis_block();
    let store = ChainStore::new(&db);
    store.put_block(&block, hash).expect("put b0");

    let range = store.get_range(0, 0).expect("get_range single block");
    assert_eq!(range.len(), 1);
    assert_eq!(range[0].height(), 0);
}

#[test]
fn get_range_returns_empty_when_inverted() {
    let (db, _dir) = open_temp_db();
    let (b0, h0) = genesis_block();
    ChainStore::new(&db).put_block(&b0, h0).expect("put b0");

    let range = ChainStore::new(&db)
        .get_range(5, 2) // inverted
        .expect("inverted range must not error");
    assert!(range.is_empty(), "inverted range must return empty Vec");
}

#[test]
fn get_range_returns_empty_when_from_above_tip() {
    let (db, _dir) = open_temp_db();
    let (b0, h0) = genesis_block();
    ChainStore::new(&db).put_block(&b0, h0).expect("put b0");

    // tip is at 0; request from 100
    let range = ChainStore::new(&db)
        .get_range(100, 200)
        .expect("above-tip range must not error");
    assert!(range.is_empty());
}

#[test]
fn get_range_returns_empty_on_empty_chain() {
    let (db, _dir) = open_temp_db();
    let range = ChainStore::new(&db)
        .get_range(0, 10)
        .expect("empty chain range must not error");
    assert!(range.is_empty());
}

#[test]
fn get_range_partial_subrange() {
    // Blocks 0–4 written; request 1–3.
    let (db, _dir) = open_temp_db();
    let store = ChainStore::new(&db);

    let mut prev = Hash::zero();
    for i in 0u64..5 {
        let (b, h) = make_block_at(i, prev);
        store.put_block(&b, h).expect("put");
        prev = h;
    }

    let range = store.get_range(1, 3).expect("subrange must succeed");
    assert_eq!(range.len(), 3);
    assert_eq!(range[0].height(), 1);
    assert_eq!(range[2].height(), 3);
}
