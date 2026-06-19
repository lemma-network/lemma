//! RocksDB wrapper with column family management for Lemma.
//!
//! [`LemmaDb`] opens (or creates) a RocksDB database with all 9 column
//! families defined in the Lemma storage spec. All operations are routed
//! through typed methods that resolve column family handles internally —
//! callers never deal with raw handle lifetime gymnastics.
//!
//! ## Column families
//!
//! | Constant | CF name | Contents |
//! |----------|---------|----------|
//! | [`CF_STATE`] | `state` | Account state (`Address` → `Account`) |
//! | [`CF_STORAGE`] | `storage` | Contract storage (`addr ++ slot` → value) |
//! | [`CF_BLOCKS`] | `blocks` | Blocks by height (`u64 BE` → `Block`) |
//! | [`CF_BLOCK_HASH`] | `block_hash` | Blocks by hash (`Hash` → `Block`) |
//! | [`CF_TRANSACTIONS`] | `transactions` | Transactions by hash |
//! | [`CF_RECEIPTS`] | `receipts` | Transaction receipts |
//! | [`CF_TRIE_NODES`] | `trie_nodes` | Merkle Patricia Trie nodes |
//! | [`CF_METADATA`] | `metadata` | Chain metadata (latest height, etc.) |
//! | [`CF_CODE`] | `code` | Content-addressed bytecode store (`blake3(bytecode)` → bytecode) |
//!
//! ## Batch writes
//!
//! Use batch writes for any multi-key update that must be atomic (e.g.
//! writing a block + all its receipts). Per AGENTS.md §16.2 and BUILD_GUIDE
//! §10, never commit to RocksDB one key at a time in hot paths.
//!
//! ```ignore
//! let mut batch = LemmaDb::new_batch();
//! db.batch_put(&mut batch, CF_BLOCKS, &height_key, &block_bytes)?;
//! db.batch_put(&mut batch, CF_RECEIPTS, &tx_hash, &receipt_bytes)?;
//! db.write_batch(batch)?;
//! ```

use std::path::Path;

use rocksdb::{
    checkpoint::Checkpoint, AsColumnFamilyRef, ColumnFamilyDescriptor, Options, WriteBatch, DB,
};

use crate::StorageError;

// ─── Column family name constants ─────────────────────────────────────────────

/// Column family for account state: `Address (20 bytes)` → bincode-encoded `Account`.
pub const CF_STATE: &str = "state";

/// Column family for contract storage: `addr (20 bytes) ++ slot (32 bytes)` → value.
///
/// The 52-byte composite key uniquely identifies a storage slot within a
/// contract. A key with the wrong length surfaces as
/// [`StorageError::InvalidKeyLength`] on the caller side.
pub const CF_STORAGE: &str = "storage";

/// Column family for blocks indexed by height: `u64 big-endian` → `Block`.
///
/// Big-endian encoding ensures lexicographic order equals numeric order,
/// making range scans (e.g. blocks 100–200) efficient via RocksDB's native
/// prefix iterator.
pub const CF_BLOCKS: &str = "blocks";

/// Column family for blocks indexed by hash: `Hash (32 bytes)` → `Block`.
pub const CF_BLOCK_HASH: &str = "block_hash";

/// Column family for transactions: `Hash (32 bytes)` → `Transaction`.
pub const CF_TRANSACTIONS: &str = "transactions";

/// Column family for transaction receipts: `Hash (32 bytes)` → `Receipt`.
pub const CF_RECEIPTS: &str = "receipts";

/// Column family for Merkle Patricia Trie nodes: `Hash (32 bytes)` → `TrieNode`.
///
/// All trie node writes must be batched per block (AGENTS.md §16.2 +
/// BUILD_GUIDE §10). Never write a single trie node per commit.
pub const CF_TRIE_NODES: &str = "trie_nodes";

/// Column family for chain metadata: well-known byte-string keys → values.
///
/// Examples: `b"latest_height"` → `u64 BE`, `b"latest_hash"` → `Hash (32 bytes)`.
pub const CF_METADATA: &str = "metadata";

/// Content-addressed bytecode store.
///
/// Key: `blake3(bytecode)` (32 bytes). Value: raw WASM bytecode.
///
/// **Append-only — never deleted.** The first deployer of a given bytecode
/// pays the storage cost; later deployers of identical bytecode pay only the
/// account pointer write (`Account.code_hash` in `CF_STATE`). This deduplicates
/// bytecode across contract instances without reference-counting.
///
/// See DB-A23 and 08-EXECUTION_SPEC §3.4(b).
pub const CF_CODE: &str = "code";

/// All 9 column family names in stable declaration order.
///
/// Used by [`LemmaDb::open`] to build `ColumnFamilyDescriptor`s. Order must
/// not change once a database has been written to disk — RocksDB tracks CFs
/// by name, not index, but keeping the list stable avoids surprises.
pub(crate) const ALL_CFS: &[&str] = &[
    CF_STATE,
    CF_STORAGE,
    CF_BLOCKS,
    CF_BLOCK_HASH,
    CF_TRANSACTIONS,
    CF_RECEIPTS,
    CF_TRIE_NODES,
    CF_METADATA,
    CF_CODE,
];

// ─── LemmaDb ──────────────────────────────────────────────────────────────────

/// RocksDB wrapper for Lemma's persistent storage layer.
///
/// Owns a single RocksDB database handle and exposes typed read, write, and
/// batch-write operations routed through named column families. All 9 column
/// families are opened (and created if missing) at construction time, so
/// there are no deferred failures after [`open`] returns `Ok`.
///
/// `LemmaDb` is `Send + Sync` because [`rocksdb::DB`] is `Send + Sync`.
///
/// [`open`]: LemmaDb::open
#[derive(Debug)]
pub struct LemmaDb {
    db: DB,
}

impl LemmaDb {
    /// Open (or create) the Lemma database at `path`.
    ///
    /// Creates the directory and all 9 column families if they do not exist.
    /// If the database already exists, any missing column families from
    /// [`ALL_CFS`] are created automatically.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Database`] if RocksDB fails to open — e.g.
    /// `path` is a regular file (not a directory), permissions are
    /// insufficient, or the WAL is corrupt.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let mut opts = Options::default();
        // Create the database directory if it does not already exist.
        opts.create_if_missing(true);
        // Create any column family listed in ALL_CFS that is not yet on disk.
        opts.create_missing_column_families(true);

        let cfs: Vec<ColumnFamilyDescriptor> = ALL_CFS
            .iter()
            .map(|&name| ColumnFamilyDescriptor::new(name, Options::default()))
            .collect();

        let db = DB::open_cf_descriptors(&opts, path, cfs)?;
        Ok(Self { db })
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Resolve a column family handle by name.
    ///
    /// Returns `Err(ColumnFamilyNotFound)` as a safety net for caller bugs
    /// (e.g. passing a typo'd or unregistered CF name). After a successful
    /// [`open`], all 9 CFs in [`ALL_CFS`] are guaranteed to exist.
    ///
    /// Using `impl AsColumnFamilyRef + '_` avoids exposing the internal
    /// `rocksdb::BoundColumnFamily` type in the public API.
    ///
    /// [`open`]: LemmaDb::open
    fn resolve_cf(&self, name: &'static str) -> Result<impl AsColumnFamilyRef + '_, StorageError> {
        self.db
            .cf_handle(name)
            .ok_or(StorageError::ColumnFamilyNotFound { name })
    }

    // ── Single-key operations ─────────────────────────────────────────────────

    /// Read a raw value by key from the given column family.
    ///
    /// Returns `Ok(None)` if the key does not exist — absence is not an
    /// error at this layer. Higher layers (e.g. `state.rs`) convert
    /// `Ok(None)` into domain-specific errors like
    /// [`StorageError::AccountNotFound`].
    ///
    /// `cf_name` must be one of the 9 column family constants declared in
    /// this module (`CF_STATE`, `CF_BLOCKS`, `CF_CODE`, etc.). The `&'static str`
    /// bound is intentional — column family names are compile-time constants, not
    /// runtime strings.
    ///
    /// # Errors
    ///
    /// - [`StorageError::ColumnFamilyNotFound`] — `cf_name` is not one of the
    ///   9 registered constants.
    /// - [`StorageError::Database`] — RocksDB I/O failure.
    pub fn get(&self, cf_name: &'static str, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let cf = self.resolve_cf(cf_name)?;
        Ok(self.db.get_cf(&cf, key)?)
    }

    /// Write a raw key-value pair to the given column family.
    ///
    /// If `key` already exists its value is overwritten. For multi-key
    /// updates that must be atomic, prefer [`write_batch`].
    ///
    /// `cf_name` must be one of the 9 column family constants (`CF_STATE`,
    /// `CF_BLOCKS`, `CF_CODE`, etc.) — see [`get`] for the full constraint explanation.
    ///
    /// # Errors
    ///
    /// - [`StorageError::ColumnFamilyNotFound`] — unknown `cf_name`.
    /// - [`StorageError::Database`] — RocksDB I/O failure.
    ///
    /// [`write_batch`]: LemmaDb::write_batch
    /// [`get`]: LemmaDb::get
    pub fn put(&self, cf_name: &'static str, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
        let cf = self.resolve_cf(cf_name)?;
        Ok(self.db.put_cf(&cf, key, value)?)
    }

    /// Delete a key from the given column family.
    ///
    /// If `key` does not exist this is a no-op — not an error.
    ///
    /// `cf_name` must be one of the 9 column family constants (`CF_STATE`,
    /// `CF_BLOCKS`, `CF_CODE`, etc.) — see [`get`] for the full constraint explanation.
    ///
    /// # Errors
    ///
    /// - [`StorageError::ColumnFamilyNotFound`] — unknown `cf_name`.
    /// - [`StorageError::Database`] — RocksDB I/O failure.
    ///
    /// [`get`]: LemmaDb::get
    pub fn delete(&self, cf_name: &'static str, key: &[u8]) -> Result<(), StorageError> {
        let cf = self.resolve_cf(cf_name)?;
        Ok(self.db.delete_cf(&cf, key)?)
    }

    // ── Batch operations ──────────────────────────────────────────────────────

    /// Create a new empty write batch tied to this database instance.
    ///
    /// Taking `&self` ensures the batch is always committed to the same
    /// `LemmaDb` that staged its operations — prevents staging ops against
    /// `db_a` and accidentally committing via `db_b`.
    ///
    /// Accumulate operations with [`batch_put`] / [`batch_delete`], then
    /// commit atomically with [`write_batch`].
    ///
    /// [`batch_put`]: LemmaDb::batch_put
    /// [`batch_delete`]: LemmaDb::batch_delete
    /// [`write_batch`]: LemmaDb::write_batch
    pub fn new_batch(&self) -> WriteBatch {
        WriteBatch::default()
    }

    /// Stage a put operation in a write batch.
    ///
    /// The column family handle is resolved at staging time so
    /// [`StorageError::ColumnFamilyNotFound`] surfaces before the batch is
    /// committed, not during.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ColumnFamilyNotFound`] if `cf_name` is not one
    /// of the 8 registered column family constants.
    pub fn batch_put(
        &self,
        batch: &mut WriteBatch,
        cf_name: &'static str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), StorageError> {
        let cf = self.resolve_cf(cf_name)?;
        batch.put_cf(&cf, key, value);
        Ok(())
    }

    /// Stage a delete operation in a write batch.
    ///
    /// The column family handle is resolved at staging time. If `key` does
    /// not exist when the batch commits, the staged delete is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::ColumnFamilyNotFound`] if `cf_name` is not one
    /// of the 8 registered column family constants.
    pub fn batch_delete(
        &self,
        batch: &mut WriteBatch,
        cf_name: &'static str,
        key: &[u8],
    ) -> Result<(), StorageError> {
        let cf = self.resolve_cf(cf_name)?;
        batch.delete_cf(&cf, key);
        Ok(())
    }

    /// Commit a write batch to RocksDB atomically.
    ///
    /// All operations in the batch succeed or fail together (RocksDB
    /// atomicity guarantee). Uses [`StorageError::batch_failed`] — not `?`
    /// via `From<rocksdb::Error>` — so callers can distinguish batch commit
    /// failures from general I/O failures.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::BatchFailed`] on commit failure.
    pub fn write_batch(&self, batch: WriteBatch) -> Result<(), StorageError> {
        self.db.write(batch).map_err(StorageError::batch_failed)
    }

    // ── Checkpoint ────────────────────────────────────────────────────────────

    /// Create a RocksDB checkpoint (point-in-time physical copy) at `path`.
    ///
    /// Uses RocksDB's checkpoint mechanism, which hard-links SST files into
    /// `path` — the operation is nearly instant and storage-efficient. The
    /// resulting directory is a complete, openable RocksDB database.
    ///
    /// Used by [`SnapshotManager`] to create crash-recovery snapshots at
    /// epoch boundaries. Do not call this directly; use the snapshot module.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SnapshotFailed`] if RocksDB fails to create
    /// the checkpoint (e.g. `path` already exists, insufficient disk space,
    /// or filesystem doesn't support hard links).
    ///
    /// [`SnapshotManager`]: crate::snapshot::SnapshotManager
    pub fn create_checkpoint<P: AsRef<Path>>(&self, path: P) -> Result<(), StorageError> {
        let checkpoint = Checkpoint::new(&self.db).map_err(|e| StorageError::SnapshotFailed {
            reason: format!("failed to create checkpoint object: {e}"),
        })?;
        checkpoint
            .create_checkpoint(path)
            .map_err(|e| StorageError::SnapshotFailed {
                reason: format!("failed to write checkpoint: {e}"),
            })
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
