//! Error types for `lemma-storage`.
//!
//! [`StorageError`] is the single error type for all storage operations in
//! this crate: RocksDB I/O, column family access, Merkle trie operations,
//! world state reads/writes, and state snapshot management.
//!
//! # Why one flat enum?
//!
//! `lemma-storage` is focused on a single concern: persistence. One enum is
//! simpler and avoids unnecessary wrapping (same reasoning as `CryptoError`
//! in `lemma-crypto`).
//!
//! External errors (`rocksdb::Error`, `bincode::Error`) are stored as
//! `String` so this enum remains `Clone + PartialEq + Eq` — consistent with
//! all other error types in the Lemma codebase.
//!
//! ## Usage
//!
//! ```ignore
//! use lemma_storage::StorageError;
//!
//! fn open_db(path: &str) -> Result<(), StorageError> {
//!     // ...
//!     Ok(())
//! }
//! ```

use thiserror::Error;

// ─── StorageError ─────────────────────────────────────────────────────────────

/// Errors that can occur during storage operations in `lemma-storage`.
///
/// Covers RocksDB I/O, column family access, Merkle trie operations, world
/// state reads/writes, and state snapshot management.
///
/// All variants carry enough context to identify the failure without
/// re-running the operation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StorageError {
    // ── Database I/O ─────────────────────────────────────────────────────────
    /// A RocksDB operation failed.
    ///
    /// The underlying `rocksdb::Error` is converted to its `Display` string
    /// so this variant remains `Clone + PartialEq + Eq`.
    #[error("RocksDB error: {reason}")]
    Database { reason: String },

    /// A named column family was not found when opening the database.
    ///
    /// `name` is a compile-time `&'static str` — column family names are
    /// declared as constants, so no heap allocation is needed and the variant
    /// remains `Clone + PartialEq + Eq` without string comparison issues.
    #[error("column family not found: \"{name}\"")]
    ColumnFamilyNotFound { name: &'static str },

    /// A batched write failed to commit to RocksDB.
    ///
    /// Batch writes are used for atomic multi-key updates — e.g. writing a
    /// block and all its receipts in one commit. A failure here means the
    /// entire batch was rejected; no partial writes occur (RocksDB guarantee).
    #[error("batch write failed: {reason}")]
    BatchFailed { reason: String },

    /// The database appears to be corrupted.
    ///
    /// Triggered when checksums fail, manifest files are inconsistent, or
    /// RocksDB reports an unrecoverable I/O error. The node operator must
    /// repair or resync from a trusted snapshot.
    #[error("database corrupted: {reason}")]
    Corrupted { reason: String },

    // ── Key / Value ──────────────────────────────────────────────────────────
    /// A raw byte-key lookup returned no result.
    ///
    /// Distinguished from [`AccountNotFound`] by scope: `KeyNotFound` is for
    /// raw byte-key lookups in `db.rs`, while `AccountNotFound` is for typed
    /// address lookups in `state.rs`.
    ///
    /// [`AccountNotFound`]: StorageError::AccountNotFound
    #[error("key not found: {key}")]
    KeyNotFound { key: String },

    /// A composite key had the wrong byte length.
    ///
    /// Composite keys (e.g. `contract_addr ++ storage_slot`, which is
    /// 20 + 32 = 52 bytes) have a fixed expected length. A mismatch
    /// indicates a caller bug, not a missing value.
    #[error("invalid key length: expected {expected} bytes, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    // ── Trie ─────────────────────────────────────────────────────────────────
    /// A trie node referenced by hash was not found in the `trie_nodes`
    /// column family.
    ///
    /// This should not occur if the trie is written and flushed atomically
    /// (per AGENTS.md §16.2 batch operations). If it does, the trie is
    /// inconsistent — treat as a [`Corrupted`] condition.
    ///
    /// `hash` is the hex-encoded Blake3 hash of the missing node.
    ///
    /// [`Corrupted`]: StorageError::Corrupted
    #[error("trie node not found: {hash}")]
    TrieNodeNotFound { hash: String },

    /// The computed trie root after proof traversal does not match the
    /// expected root.
    ///
    /// Indicates a tampered proof or a state root mismatch between the block
    /// header and the actual trie contents. Both hashes are hex-encoded Blake3
    /// digests for easy comparison in logs.
    #[error("trie root mismatch: expected {expected}, got {got}")]
    TrieRootMismatch { expected: String, got: String },

    /// A Merkle proof failed verification.
    ///
    /// The proof path for `key` did not hash up to the known root. Either the
    /// proof was forged or truncated, or the provided root is wrong.
    ///
    /// `key` is hex-encoded so it is always printable, regardless of the
    /// underlying byte content.
    #[error("invalid Merkle proof for key: {key}")]
    InvalidProof { key: String },

    // ── State ─────────────────────────────────────────────────────────────────
    /// No account exists at the given address.
    ///
    /// Returned by `WorldState::get_account` when the address has no entry in
    /// the `state` column family. New addresses have an implicit zero-balance
    /// account — this error only fires when an account is explicitly expected
    /// to exist (e.g. during transaction validation).
    ///
    /// `address` is the Bech32m display string so this variant remains
    /// `Clone + PartialEq + Eq`.
    #[error("account not found: {address}")]
    AccountNotFound { address: String },

    // ── Snapshot ──────────────────────────────────────────────────────────────
    /// A state snapshot could not be created.
    ///
    /// Snapshots are taken at epoch boundaries for crash recovery. A failure
    /// here does not affect the current block — recovery will fall back to the
    /// previous checkpoint.
    #[error("snapshot failed: {reason}")]
    SnapshotFailed { reason: String },

    /// A state restore from snapshot failed.
    ///
    /// Triggered during node startup when the snapshot file is missing,
    /// truncated, or its checksum does not match. The node must resync from
    /// genesis or a trusted peer snapshot.
    #[error("restore failed: {reason}")]
    RestoreFailed { reason: String },

    // ── Serialization ─────────────────────────────────────────────────────────
    /// A serialization or deserialization step failed.
    ///
    /// Occurs when encoding a value to bytes before writing to RocksDB, or
    /// decoding bytes read from RocksDB back into a typed value. All storage
    /// modules reuse this variant (AGENTS.md §2.1 — one canonical way per
    /// concept).
    ///
    /// Stored as a `String` so this variant remains `Clone + PartialEq + Eq`.
    /// The underlying `bincode::Error` is converted on construction via
    /// [`From<bincode::Error>`].
    #[error("serialization failed: {reason}")]
    SerializationFailed { reason: String },
}

// ─── Constructors ─────────────────────────────────────────────────────────────

impl StorageError {
    /// Wrap a RocksDB error that occurred during a batch write commit.
    ///
    /// Use this **instead of** `?` (which would produce [`StorageError::Database`]
    /// via `From<rocksdb::Error>`) when the failure site is a `WriteBatch::write()`
    /// call. This keeps `BatchFailed` semantically distinct from general I/O
    /// failures so callers can differentiate the two error paths.
    ///
    /// # Example (in `db.rs`)
    ///
    /// ```ignore
    /// db.write(batch).map_err(StorageError::batch_failed)?;
    /// ```
    pub fn batch_failed(e: rocksdb::Error) -> Self {
        Self::BatchFailed {
            reason: e.into_string(),
        }
    }
}

// ─── From conversions ─────────────────────────────────────────────────────────

impl From<rocksdb::Error> for StorageError {
    /// Convert a `rocksdb::Error` into [`StorageError::Database`].
    ///
    /// The full `Display` string of the RocksDB error is preserved in
    /// `reason` so the original message is not lost at the boundary.
    ///
    /// For batch-write failures, use [`StorageError::batch_failed`] instead
    /// so the error variant reflects the actual operation that failed.
    fn from(e: rocksdb::Error) -> Self {
        Self::Database {
            reason: e.into_string(),
        }
    }
}

impl From<bincode::Error> for StorageError {
    /// Convert a `bincode::Error` into [`StorageError::SerializationFailed`].
    ///
    /// `bincode::Error` is `Box<bincode::ErrorKind>`, which is not
    /// `Clone + PartialEq + Eq`, so the `Display` string is stored instead.
    fn from(e: bincode::Error) -> Self {
        Self::SerializationFailed {
            reason: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for StorageError {
    /// Convert a `serde_json::Error` into [`StorageError::SerializationFailed`].
    ///
    /// `serde_json::Error` is not `Clone + PartialEq + Eq`, so the `Display`
    /// string is stored. Used by `ChainStore` block storage (Block contains
    /// `Signature` with internally-tagged serde format, which bincode cannot
    /// deserialize — see `chain.rs` module doc).
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationFailed {
            reason: e.to_string(),
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
