//! Tests for `lemma_storage::error`.
//!
//! Covers Display output, Clone round-trips, PartialEq equality and
//! inequality for every public variant, and From conversions for external
//! error types. 100% public API coverage required per AGENTS.md §11.1.

use super::*;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn database_err(reason: &str) -> StorageError {
    StorageError::Database {
        reason: reason.to_string(),
    }
}

fn cf_not_found(name: &'static str) -> StorageError {
    StorageError::ColumnFamilyNotFound { name }
}

fn batch_failed(reason: &str) -> StorageError {
    StorageError::BatchFailed {
        reason: reason.to_string(),
    }
}

fn corrupted(reason: &str) -> StorageError {
    StorageError::Corrupted {
        reason: reason.to_string(),
    }
}

fn key_not_found(key: &str) -> StorageError {
    StorageError::KeyNotFound {
        key: key.to_string(),
    }
}

fn invalid_key_length(expected: usize, got: usize) -> StorageError {
    StorageError::InvalidKeyLength { expected, got }
}

fn trie_node_not_found(hash: &str) -> StorageError {
    StorageError::TrieNodeNotFound {
        hash: hash.to_string(),
    }
}

fn trie_root_mismatch(expected: &str, got: &str) -> StorageError {
    StorageError::TrieRootMismatch {
        expected: expected.to_string(),
        got: got.to_string(),
    }
}

fn invalid_proof(key: &str) -> StorageError {
    StorageError::InvalidProof {
        key: key.to_string(),
    }
}

fn account_not_found(address: &str) -> StorageError {
    StorageError::AccountNotFound {
        address: address.to_string(),
    }
}

fn snapshot_failed(reason: &str) -> StorageError {
    StorageError::SnapshotFailed {
        reason: reason.to_string(),
    }
}

fn restore_failed(reason: &str) -> StorageError {
    StorageError::RestoreFailed {
        reason: reason.to_string(),
    }
}

fn serialization_failed(reason: &str) -> StorageError {
    StorageError::SerializationFailed {
        reason: reason.to_string(),
    }
}

// ── Database — Display ────────────────────────────────────────────────────────

#[test]
fn database_error_displays_reason() {
    assert_eq!(
        database_err("IO error: No such file or directory").to_string(),
        "RocksDB error: IO error: No such file or directory",
    );
}

#[test]
fn database_error_displays_empty_reason() {
    // Edge case: RocksDB returns an empty message.
    assert_eq!(database_err("").to_string(), "RocksDB error: ",);
}

// ── Database — Clone + PartialEq ──────────────────────────────────────────────

#[test]
fn database_error_clones_equal_to_original() {
    let err = database_err("disk full");
    assert_eq!(err.clone(), err);
}

#[test]
fn database_error_same_reason_are_equal() {
    assert_eq!(database_err("disk full"), database_err("disk full"));
}

#[test]
fn database_error_different_reason_are_not_equal() {
    assert_ne!(database_err("disk full"), database_err("corrupt sst"));
}

// ── ColumnFamilyNotFound — Display ────────────────────────────────────────────

#[test]
fn column_family_not_found_displays_quoted_name() {
    assert_eq!(
        cf_not_found("state").to_string(),
        "column family not found: \"state\"",
    );
}

#[test]
fn column_family_not_found_displays_trie_nodes_name() {
    assert_eq!(
        cf_not_found("trie_nodes").to_string(),
        "column family not found: \"trie_nodes\"",
    );
}

// ── ColumnFamilyNotFound — Clone + PartialEq ─────────────────────────────────

#[test]
fn column_family_not_found_clones_equal_to_original() {
    let err = cf_not_found("state");
    assert_eq!(err.clone(), err);
}

#[test]
fn column_family_not_found_same_name_are_equal() {
    assert_eq!(cf_not_found("state"), cf_not_found("state"));
}

#[test]
fn column_family_not_found_different_name_are_not_equal() {
    assert_ne!(cf_not_found("state"), cf_not_found("blocks"));
}

// ── BatchFailed — Display ─────────────────────────────────────────────────────

#[test]
fn batch_failed_displays_reason() {
    assert_eq!(
        batch_failed("write stalled").to_string(),
        "batch write failed: write stalled",
    );
}

// ── BatchFailed — Clone + PartialEq ──────────────────────────────────────────

#[test]
fn batch_failed_clones_equal_to_original() {
    let err = batch_failed("write stalled");
    assert_eq!(err.clone(), err);
}

#[test]
fn batch_failed_same_reason_are_equal() {
    assert_eq!(batch_failed("write stalled"), batch_failed("write stalled"));
}

#[test]
fn batch_failed_different_reason_are_not_equal() {
    assert_ne!(
        batch_failed("write stalled"),
        batch_failed("compaction error")
    );
}

// ── Corrupted — Display ───────────────────────────────────────────────────────

#[test]
fn corrupted_displays_reason() {
    assert_eq!(
        corrupted("checksum mismatch in block 42").to_string(),
        "database corrupted: checksum mismatch in block 42",
    );
}

// ── Corrupted — Clone + PartialEq ─────────────────────────────────────────────

#[test]
fn corrupted_clones_equal_to_original() {
    let err = corrupted("manifest inconsistency");
    assert_eq!(err.clone(), err);
}

#[test]
fn corrupted_same_reason_are_equal() {
    assert_eq!(
        corrupted("manifest inconsistency"),
        corrupted("manifest inconsistency"),
    );
}

#[test]
fn corrupted_different_reason_are_not_equal() {
    assert_ne!(
        corrupted("manifest inconsistency"),
        corrupted("checksum mismatch"),
    );
}

// ── KeyNotFound — Display ─────────────────────────────────────────────────────

#[test]
fn key_not_found_displays_key() {
    assert_eq!(
        key_not_found("0xdeadbeef").to_string(),
        "key not found: 0xdeadbeef",
    );
}

#[test]
fn key_not_found_displays_empty_key() {
    // Edge case: empty key slice lookup.
    assert_eq!(key_not_found("").to_string(), "key not found: ",);
}

// ── KeyNotFound — Clone + PartialEq ──────────────────────────────────────────

#[test]
fn key_not_found_clones_equal_to_original() {
    let err = key_not_found("0xdeadbeef");
    assert_eq!(err.clone(), err);
}

#[test]
fn key_not_found_same_key_are_equal() {
    assert_eq!(key_not_found("0xdeadbeef"), key_not_found("0xdeadbeef"));
}

#[test]
fn key_not_found_different_key_are_not_equal() {
    assert_ne!(key_not_found("0xdeadbeef"), key_not_found("0xcafebabe"));
}

// ── InvalidKeyLength — Display ────────────────────────────────────────────────

#[test]
fn invalid_key_length_displays_expected_and_got() {
    // Composite key: contract_addr (20) + storage_slot (32) = 52 bytes.
    assert_eq!(
        invalid_key_length(52, 20).to_string(),
        "invalid key length: expected 52 bytes, got 20",
    );
}

#[test]
fn invalid_key_length_displays_zero_got() {
    // Edge case: completely empty key passed to a composite-key lookup.
    assert_eq!(
        invalid_key_length(52, 0).to_string(),
        "invalid key length: expected 52 bytes, got 0",
    );
}

// ── InvalidKeyLength — Clone + PartialEq ─────────────────────────────────────

#[test]
fn invalid_key_length_clones_equal_to_original() {
    let err = invalid_key_length(52, 20);
    assert_eq!(err.clone(), err);
}

#[test]
fn invalid_key_length_same_values_are_equal() {
    assert_eq!(invalid_key_length(52, 20), invalid_key_length(52, 20));
}

#[test]
fn invalid_key_length_different_got_are_not_equal() {
    assert_ne!(invalid_key_length(52, 20), invalid_key_length(52, 32));
}

#[test]
fn invalid_key_length_different_expected_are_not_equal() {
    assert_ne!(invalid_key_length(52, 20), invalid_key_length(32, 20));
}

// ── TrieNodeNotFound — Display ────────────────────────────────────────────────

#[test]
fn trie_node_not_found_displays_hash() {
    assert_eq!(
        trie_node_not_found("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc7b4b7b8b8e7a89")
            .to_string(),
        "trie node not found: af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc7b4b7b8b8e7a89",
    );
}

// ── TrieNodeNotFound — Clone + PartialEq ─────────────────────────────────────

#[test]
fn trie_node_not_found_clones_equal_to_original() {
    let err = trie_node_not_found("aabbcc");
    assert_eq!(err.clone(), err);
}

#[test]
fn trie_node_not_found_same_hash_are_equal() {
    assert_eq!(trie_node_not_found("aabbcc"), trie_node_not_found("aabbcc"));
}

#[test]
fn trie_node_not_found_different_hash_are_not_equal() {
    assert_ne!(trie_node_not_found("aabbcc"), trie_node_not_found("ddeeff"));
}

// ── TrieRootMismatch — Display ────────────────────────────────────────────────

#[test]
fn trie_root_mismatch_displays_expected_and_got() {
    assert_eq!(
        trie_root_mismatch("aabbcc", "ddeeff").to_string(),
        "trie root mismatch: expected aabbcc, got ddeeff",
    );
}

// ── TrieRootMismatch — Clone + PartialEq ─────────────────────────────────────

#[test]
fn trie_root_mismatch_clones_equal_to_original() {
    let err = trie_root_mismatch("aabbcc", "ddeeff");
    assert_eq!(err.clone(), err);
}

#[test]
fn trie_root_mismatch_same_values_are_equal() {
    assert_eq!(
        trie_root_mismatch("aabbcc", "ddeeff"),
        trie_root_mismatch("aabbcc", "ddeeff"),
    );
}

#[test]
fn trie_root_mismatch_different_got_are_not_equal() {
    assert_ne!(
        trie_root_mismatch("aabbcc", "ddeeff"),
        trie_root_mismatch("aabbcc", "112233"),
    );
}

#[test]
fn trie_root_mismatch_different_expected_are_not_equal() {
    assert_ne!(
        trie_root_mismatch("aabbcc", "ddeeff"),
        trie_root_mismatch("112233", "ddeeff"),
    );
}

// ── InvalidProof — Display ────────────────────────────────────────────────────

#[test]
fn invalid_proof_displays_key() {
    assert_eq!(
        invalid_proof("lem1q...").to_string(),
        "invalid Merkle proof for key: lem1q...",
    );
}

// ── InvalidProof — Clone + PartialEq ─────────────────────────────────────────

#[test]
fn invalid_proof_clones_equal_to_original() {
    let err = invalid_proof("aabbcc");
    assert_eq!(err.clone(), err);
}

#[test]
fn invalid_proof_same_key_are_equal() {
    assert_eq!(invalid_proof("aabbcc"), invalid_proof("aabbcc"));
}

#[test]
fn invalid_proof_different_key_are_not_equal() {
    assert_ne!(invalid_proof("aabbcc"), invalid_proof("ddeeff"));
}

// ── AccountNotFound — Display ─────────────────────────────────────────────────

#[test]
fn account_not_found_displays_address() {
    assert_eq!(
        account_not_found("lem1qexampleaddress").to_string(),
        "account not found: lem1qexampleaddress",
    );
}

// ── AccountNotFound — Clone + PartialEq ──────────────────────────────────────

#[test]
fn account_not_found_clones_equal_to_original() {
    let err = account_not_found("lem1qexampleaddress");
    assert_eq!(err.clone(), err);
}

#[test]
fn account_not_found_same_address_are_equal() {
    assert_eq!(
        account_not_found("lem1qexampleaddress"),
        account_not_found("lem1qexampleaddress"),
    );
}

#[test]
fn account_not_found_different_address_are_not_equal() {
    assert_ne!(
        account_not_found("lem1qexampleaddress"),
        account_not_found("lem1qotheraddress"),
    );
}

// ── SnapshotFailed — Display ──────────────────────────────────────────────────

#[test]
fn snapshot_failed_displays_reason() {
    assert_eq!(
        snapshot_failed("permission denied: /var/snapshots/epoch_5").to_string(),
        "snapshot failed: permission denied: /var/snapshots/epoch_5",
    );
}

// ── SnapshotFailed — Clone + PartialEq ───────────────────────────────────────

#[test]
fn snapshot_failed_clones_equal_to_original() {
    let err = snapshot_failed("disk full");
    assert_eq!(err.clone(), err);
}

#[test]
fn snapshot_failed_same_reason_are_equal() {
    assert_eq!(snapshot_failed("disk full"), snapshot_failed("disk full"));
}

#[test]
fn snapshot_failed_different_reason_are_not_equal() {
    assert_ne!(
        snapshot_failed("disk full"),
        snapshot_failed("permission denied")
    );
}

// ── RestoreFailed — Display ───────────────────────────────────────────────────

#[test]
fn restore_failed_displays_reason() {
    assert_eq!(
        restore_failed("checksum mismatch: snapshot corrupted").to_string(),
        "restore failed: checksum mismatch: snapshot corrupted",
    );
}

// ── RestoreFailed — Clone + PartialEq ────────────────────────────────────────

#[test]
fn restore_failed_clones_equal_to_original() {
    let err = restore_failed("file not found");
    assert_eq!(err.clone(), err);
}

#[test]
fn restore_failed_same_reason_are_equal() {
    assert_eq!(
        restore_failed("file not found"),
        restore_failed("file not found")
    );
}

#[test]
fn restore_failed_different_reason_are_not_equal() {
    assert_ne!(
        restore_failed("file not found"),
        restore_failed("checksum mismatch"),
    );
}

// ── SerializationFailed — Display ─────────────────────────────────────────────

#[test]
fn serialization_failed_displays_reason() {
    assert_eq!(
        serialization_failed("sequence too long").to_string(),
        "serialization failed: sequence too long",
    );
}

#[test]
fn serialization_failed_displays_empty_reason() {
    assert_eq!(
        serialization_failed("").to_string(),
        "serialization failed: ",
    );
}

// ── SerializationFailed — Clone + PartialEq ───────────────────────────────────

#[test]
fn serialization_failed_clones_equal_to_original() {
    let err = serialization_failed("unexpected eof");
    assert_eq!(err.clone(), err);
}

#[test]
fn serialization_failed_same_reason_are_equal() {
    assert_eq!(
        serialization_failed("unexpected eof"),
        serialization_failed("unexpected eof"),
    );
}

#[test]
fn serialization_failed_different_reason_are_not_equal() {
    assert_ne!(
        serialization_failed("unexpected eof"),
        serialization_failed("invalid tag"),
    );
}

// ── From<bincode::Error> ──────────────────────────────────────────────────────

#[test]
fn from_bincode_error_produces_serialization_failed_variant() {
    // Deserializing an empty slice as u64 always fails — reliable bincode error.
    let bincode_err = bincode::deserialize::<u64>(&[]).unwrap_err();
    let storage_err = StorageError::from(bincode_err);
    assert!(
        matches!(storage_err, StorageError::SerializationFailed { .. }),
        "expected SerializationFailed, got {storage_err:?}",
    );
}

#[test]
fn from_bincode_error_preserves_error_message() {
    // Capture the message first, then consume the error into StorageError —
    // one deserialize call, no duplication.
    let bincode_err = bincode::deserialize::<u64>(&[]).unwrap_err();
    let expected_reason = bincode_err.to_string();
    let storage_err = StorageError::from(bincode_err);
    let StorageError::SerializationFailed { reason: stored } = storage_err else {
        panic!("expected SerializationFailed");
    };
    assert_eq!(stored, expected_reason);
}

// ── From<rocksdb::Error> — integration note ───────────────────────────────────
//
// `rocksdb::Error` has no public constructor, so From<rocksdb::Error> is
// tested in db/tests.rs where a real DB open failure produces one naturally
// (e.g. opening a path that is a regular file, not a directory).
// TODO(dev): add from_rocksdb_error_produces_database_variant test in
// db/tests.rs once the RocksDB wrapper exists — issue #3

// ── Cross-variant PartialEq — database group ──────────────────────────────────

#[test]
fn database_and_batch_failed_with_same_reason_are_not_equal() {
    // Same reason string, different variants — must not be equal.
    assert_ne!(database_err("error"), batch_failed("error"));
}

#[test]
fn database_and_corrupted_with_same_reason_are_not_equal() {
    assert_ne!(database_err("error"), corrupted("error"));
}

#[test]
fn batch_failed_and_corrupted_with_same_reason_are_not_equal() {
    assert_ne!(batch_failed("error"), corrupted("error"));
}

// ── Cross-variant PartialEq — key group ──────────────────────────────────────

#[test]
fn key_not_found_and_account_not_found_with_same_string_are_not_equal() {
    assert_ne!(key_not_found("lem1q..."), account_not_found("lem1q..."));
}

#[test]
fn trie_node_not_found_and_key_not_found_with_same_string_are_not_equal() {
    assert_ne!(trie_node_not_found("aabb"), key_not_found("aabb"));
}

// ── Cross-variant PartialEq — trie group ─────────────────────────────────────

#[test]
fn trie_node_not_found_and_invalid_proof_with_same_string_are_not_equal() {
    assert_ne!(trie_node_not_found("aabb"), invalid_proof("aabb"));
}

#[test]
fn trie_root_mismatch_and_invalid_proof_are_not_equal() {
    // TrieRootMismatch has two fields; InvalidProof has one — can never be equal.
    assert_ne!(trie_root_mismatch("aabb", "ccdd"), invalid_proof("aabb"),);
}

// ── Cross-variant PartialEq — snapshot group ─────────────────────────────────

#[test]
fn snapshot_failed_and_restore_failed_with_same_reason_are_not_equal() {
    assert_ne!(snapshot_failed("error"), restore_failed("error"));
}

// ── Cross-variant PartialEq — serialization vs others ────────────────────────

#[test]
fn serialization_failed_and_database_with_same_reason_are_not_equal() {
    assert_ne!(serialization_failed("error"), database_err("error"));
}

#[test]
fn serialization_failed_and_key_not_found_with_same_string_are_not_equal() {
    assert_ne!(serialization_failed("key"), key_not_found("key"));
}

// ── Cross-variant PartialEq — cf vs others ───────────────────────────────────

#[test]
fn column_family_not_found_and_key_not_found_are_not_equal() {
    // ColumnFamilyNotFound uses &'static str, KeyNotFound uses String.
    assert_ne!(cf_not_found("state"), key_not_found("state"));
}

#[test]
fn column_family_not_found_and_account_not_found_are_not_equal() {
    // Both are "not found" variants — the most semantically confusing pairing.
    // ColumnFamilyNotFound (&'static str) must not equal AccountNotFound (String)
    // even when both hold the same textual content.
    assert_ne!(cf_not_found("state"), account_not_found("state"));
}
