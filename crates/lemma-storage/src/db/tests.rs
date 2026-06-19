//! Tests for `lemma_storage::db`.
//!
//! Covers: database open/reopen, all 9 column families, get/put/delete
//! single-key ops, batch writes across column families, missing-key
//! semantics, and the `From<rocksdb::Error>` → `StorageError::Database`
//! conversion (issue #3 — deferred from error/tests.rs).
//!
//! All tests use `tempfile::tempdir()` for isolation — each test gets its
//! own directory that is cleaned up on drop regardless of test outcome.

use tempfile::tempdir;

use super::*;
use crate::StorageError;

// ── Shared fixtures ───────────────────────────────────────────────────────────

/// Open a fresh `LemmaDb` in a temporary directory.
///
/// Panics on failure — fixture functions must not fail silently.
fn open_temp_db() -> (LemmaDb, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir creation must succeed");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed on a fresh temp dir");
    (db, dir)
}

// ── Open — success paths ──────────────────────────────────────────────────────

#[test]
fn open_creates_database_at_fresh_path() {
    let dir = tempdir().expect("tempdir creation must succeed");
    let result = LemmaDb::open(dir.path());
    assert!(
        result.is_ok(),
        "open should succeed on a fresh directory: {result:?}"
    );
}

#[test]
fn open_existing_database_reopens_cleanly() {
    // Open once to create, open again to verify idempotency.
    let dir = tempdir().expect("tempdir creation must succeed");
    let _ = LemmaDb::open(dir.path()).expect("first open must succeed");
    let result = LemmaDb::open(dir.path());
    assert!(
        result.is_ok(),
        "reopening an existing database must succeed: {result:?}"
    );
}

#[test]
fn open_preserves_data_across_reopen() {
    let dir = tempdir().expect("tempdir creation must succeed");

    {
        // Drop `db` before reopening — RocksDB requires exclusive access.
        let db = LemmaDb::open(dir.path()).expect("first open must succeed");
        db.put(CF_METADATA, b"key", b"value")
            .expect("put must succeed");
    } // `db` dropped here, releasing the RocksDB lock

    // Read back in second session.
    let db2 = LemmaDb::open(dir.path()).expect("second open must succeed");
    let val = db2.get(CF_METADATA, b"key").expect("get must succeed");
    assert_eq!(val, Some(b"value".to_vec()));
}

// ── Open — From<rocksdb::Error> integration test (issue #3) ──────────────────

#[test]
fn open_regular_file_path_produces_database_error() {
    // Create a regular file at the path we'll pass to LemmaDb::open.
    // RocksDB expects a directory; passing a file causes it to emit an error,
    // which our From<rocksdb::Error> impl converts to StorageError::Database.
    // This closes issue #3 deferred from error/tests.rs.
    let dir = tempdir().expect("tempdir creation must succeed");
    let file_path = dir.path().join("not_a_directory.txt");
    std::fs::write(&file_path, b"I am a file").expect("test file write must succeed");

    let result = LemmaDb::open(&file_path);
    assert!(
        matches!(result, Err(StorageError::Database { .. })),
        "opening a file path should produce StorageError::Database, got: {result:?}",
    );
}

// ── Column families — all 9 reachable ────────────────────────────────────────

#[test]
fn all_column_families_are_accessible_after_open() {
    let (db, _dir) = open_temp_db();

    // One round-trip per CF — if any CF is missing, put/get returns Err.
    for &cf_name in ALL_CFS {
        let result = db.put(cf_name, b"probe", b"1");
        assert!(
            result.is_ok(),
            "put into CF '{cf_name}' should succeed after open, got: {result:?}",
        );
        let val = db.get(cf_name, b"probe").unwrap();
        assert_eq!(
            val,
            Some(b"1".to_vec()),
            "get from CF '{cf_name}' must return written value"
        );
    }
}

#[test]
fn all_nine_column_family_constants_are_distinct() {
    // Guard: if any two constants accidentally share a name, tests above would
    // silently pass while cross-contaminating data.
    let mut seen = std::collections::BTreeSet::new();
    for &name in ALL_CFS {
        assert!(
            seen.insert(name),
            "duplicate column family name found: '{name}'",
        );
    }
    assert_eq!(seen.len(), 9, "expected exactly 9 distinct column families");
}

// ── get — single key ─────────────────────────────────────────────────────────

#[test]
fn get_returns_none_for_missing_key() {
    let (db, _dir) = open_temp_db();
    let result = db.get(CF_STATE, b"nonexistent_key");
    assert_eq!(result.unwrap(), None);
}

#[test]
fn get_returns_value_after_put() {
    let (db, _dir) = open_temp_db();
    db.put(CF_STATE, b"account_key", b"account_bytes").unwrap();
    let val = db.get(CF_STATE, b"account_key").unwrap();
    assert_eq!(val, Some(b"account_bytes".to_vec()));
}

#[test]
fn get_returns_none_after_delete() {
    let (db, _dir) = open_temp_db();
    db.put(CF_STATE, b"k", b"v").unwrap();
    db.delete(CF_STATE, b"k").unwrap();
    assert_eq!(db.get(CF_STATE, b"k").unwrap(), None);
}

// ── put — single key ─────────────────────────────────────────────────────────

#[test]
fn put_overwrites_existing_value() {
    let (db, _dir) = open_temp_db();
    db.put(CF_METADATA, b"latest_height", &42u64.to_be_bytes())
        .unwrap();
    db.put(CF_METADATA, b"latest_height", &99u64.to_be_bytes())
        .unwrap();
    let val = db.get(CF_METADATA, b"latest_height").unwrap().unwrap();
    assert_eq!(val, 99u64.to_be_bytes().to_vec());
}

#[test]
fn put_empty_value_is_valid() {
    // Empty values are legal in RocksDB (key exists, value = zero bytes).
    let (db, _dir) = open_temp_db();
    db.put(CF_METADATA, b"empty_val_key", b"").unwrap();
    let val = db.get(CF_METADATA, b"empty_val_key").unwrap();
    assert_eq!(val, Some(vec![]));
}

#[test]
fn put_and_get_across_different_column_families_are_independent() {
    // The same key in two different CFs must hold independent values.
    let (db, _dir) = open_temp_db();
    db.put(CF_STATE, b"shared_key", b"state_value").unwrap();
    db.put(CF_METADATA, b"shared_key", b"metadata_value")
        .unwrap();

    assert_eq!(
        db.get(CF_STATE, b"shared_key").unwrap(),
        Some(b"state_value".to_vec()),
    );
    assert_eq!(
        db.get(CF_METADATA, b"shared_key").unwrap(),
        Some(b"metadata_value".to_vec()),
    );
}

// ── delete ────────────────────────────────────────────────────────────────────

#[test]
fn delete_nonexistent_key_succeeds() {
    // Deleting a key that doesn't exist is a no-op — must not return an error.
    let (db, _dir) = open_temp_db();
    let result = db.delete(CF_STATE, b"ghost_key");
    assert!(
        result.is_ok(),
        "delete of missing key must succeed: {result:?}"
    );
}

#[test]
fn delete_removes_key_from_correct_column_family_only() {
    let (db, _dir) = open_temp_db();
    db.put(CF_STATE, b"k", b"state_v").unwrap();
    db.put(CF_METADATA, b"k", b"meta_v").unwrap();

    // Delete from CF_STATE only.
    db.delete(CF_STATE, b"k").unwrap();

    assert_eq!(
        db.get(CF_STATE, b"k").unwrap(),
        None,
        "CF_STATE key must be deleted"
    );
    assert_eq!(
        db.get(CF_METADATA, b"k").unwrap(),
        Some(b"meta_v".to_vec()),
        "CF_METADATA key must be unaffected",
    );
}

// ── write_batch ───────────────────────────────────────────────────────────────

#[test]
fn write_batch_commits_multiple_puts() {
    let (db, _dir) = open_temp_db();
    let mut batch = db.new_batch();
    db.batch_put(&mut batch, CF_BLOCKS, &1u64.to_be_bytes(), b"block_1")
        .unwrap();
    db.batch_put(&mut batch, CF_BLOCKS, &2u64.to_be_bytes(), b"block_2")
        .unwrap();
    db.batch_put(&mut batch, CF_BLOCKS, &3u64.to_be_bytes(), b"block_3")
        .unwrap();
    db.write_batch(batch).unwrap();

    assert_eq!(
        db.get(CF_BLOCKS, &1u64.to_be_bytes()).unwrap(),
        Some(b"block_1".to_vec())
    );
    assert_eq!(
        db.get(CF_BLOCKS, &2u64.to_be_bytes()).unwrap(),
        Some(b"block_2".to_vec())
    );
    assert_eq!(
        db.get(CF_BLOCKS, &3u64.to_be_bytes()).unwrap(),
        Some(b"block_3".to_vec())
    );
}

#[test]
fn write_batch_spans_multiple_column_families() {
    // A batch touching CF_BLOCKS, CF_RECEIPTS, and CF_METADATA atomically —
    // simulates the real block-write pattern.
    let (db, _dir) = open_temp_db();
    let height_key = 42u64.to_be_bytes();
    let tx_hash = [0xabu8; 32];

    let mut batch = db.new_batch();
    db.batch_put(&mut batch, CF_BLOCKS, &height_key, b"block_bytes")
        .unwrap();
    db.batch_put(&mut batch, CF_RECEIPTS, &tx_hash, b"receipt_bytes")
        .unwrap();
    db.batch_put(&mut batch, CF_METADATA, b"latest_height", &height_key)
        .unwrap();
    db.write_batch(batch).unwrap();

    assert_eq!(
        db.get(CF_BLOCKS, &height_key).unwrap(),
        Some(b"block_bytes".to_vec())
    );
    assert_eq!(
        db.get(CF_RECEIPTS, &tx_hash).unwrap(),
        Some(b"receipt_bytes".to_vec())
    );
    assert_eq!(
        db.get(CF_METADATA, b"latest_height").unwrap(),
        Some(height_key.to_vec())
    );
}

#[test]
fn write_batch_delete_removes_key() {
    let (db, _dir) = open_temp_db();
    db.put(CF_TRIE_NODES, b"node_hash", b"node_bytes").unwrap();

    let mut batch = db.new_batch();
    db.batch_delete(&mut batch, CF_TRIE_NODES, b"node_hash")
        .unwrap();
    db.write_batch(batch).unwrap();

    assert_eq!(db.get(CF_TRIE_NODES, b"node_hash").unwrap(), None);
}

#[test]
fn empty_write_batch_succeeds() {
    // Committing a zero-operation batch is valid — must not error.
    let (db, _dir) = open_temp_db();
    let batch = db.new_batch();
    let result = db.write_batch(batch);
    assert!(
        result.is_ok(),
        "empty batch commit must succeed: {result:?}"
    );
}

#[test]
fn write_batch_put_then_delete_same_key_results_in_absence() {
    // Stage a put then a delete for the same key in the same batch.
    // RocksDB applies operations in order — the delete wins.
    let (db, _dir) = open_temp_db();
    let mut batch = db.new_batch();
    db.batch_put(&mut batch, CF_STATE, b"k", b"v").unwrap();
    db.batch_delete(&mut batch, CF_STATE, b"k").unwrap();
    db.write_batch(batch).unwrap();

    assert_eq!(db.get(CF_STATE, b"k").unwrap(), None);
}

// ── new_batch is tied to DB instance ─────────────────────────────────────────

#[test]
fn new_batch_produces_empty_batch() {
    // `WriteBatch` in rocksdb 0.24 has no public `is_empty()` — verify
    // indirectly: committing an empty batch must leave existing data unchanged.
    let (db, _dir) = open_temp_db();
    db.put(CF_STATE, b"sentinel", b"present").unwrap();

    let batch = db.new_batch();
    db.write_batch(batch).unwrap();

    // Sentinel must still be there — empty batch changed nothing.
    assert_eq!(
        db.get(CF_STATE, b"sentinel").unwrap(),
        Some(b"present".to_vec())
    );
}

// ── ColumnFamilyNotFound — negative-path coverage ────────────────────────────

#[test]
fn get_unknown_column_family_returns_column_family_not_found() {
    let (db, _dir) = open_temp_db();
    let result = db.get("unknown_cf", b"key");
    assert!(
        matches!(
            result,
            Err(StorageError::ColumnFamilyNotFound { name: "unknown_cf" })
        ),
        "expected ColumnFamilyNotFound, got: {result:?}",
    );
}

#[test]
fn put_unknown_column_family_returns_column_family_not_found() {
    let (db, _dir) = open_temp_db();
    let result = db.put("unknown_cf", b"key", b"value");
    assert!(
        matches!(
            result,
            Err(StorageError::ColumnFamilyNotFound { name: "unknown_cf" })
        ),
        "expected ColumnFamilyNotFound, got: {result:?}",
    );
}

#[test]
fn delete_unknown_column_family_returns_column_family_not_found() {
    let (db, _dir) = open_temp_db();
    let result = db.delete("unknown_cf", b"key");
    assert!(
        matches!(
            result,
            Err(StorageError::ColumnFamilyNotFound { name: "unknown_cf" })
        ),
        "expected ColumnFamilyNotFound, got: {result:?}",
    );
}

#[test]
fn batch_put_unknown_column_family_returns_column_family_not_found() {
    let (db, _dir) = open_temp_db();
    let mut batch = db.new_batch();
    let result = db.batch_put(&mut batch, "unknown_cf", b"key", b"value");
    assert!(
        matches!(
            result,
            Err(StorageError::ColumnFamilyNotFound { name: "unknown_cf" })
        ),
        "expected ColumnFamilyNotFound, got: {result:?}",
    );
}

#[test]
fn batch_delete_unknown_column_family_returns_column_family_not_found() {
    let (db, _dir) = open_temp_db();
    let mut batch = db.new_batch();
    let result = db.batch_delete(&mut batch, "unknown_cf", b"key");
    assert!(
        matches!(
            result,
            Err(StorageError::ColumnFamilyNotFound { name: "unknown_cf" })
        ),
        "expected ColumnFamilyNotFound, got: {result:?}",
    );
}
