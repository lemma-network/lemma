//! State snapshot management for crash recovery.
//!
//! A snapshot is a **RocksDB checkpoint** — a hard-linked, point-in-time
//! physical copy of the database. Creating a snapshot is nearly instant and
//! storage-efficient (SST files are shared until they diverge). Restoring
//! from a snapshot requires only `LemmaDb::open(snapshot_path)` followed by
//! `WorldState::with_state_root(db, metadata.state_root)`.
//!
//! ## Snapshot layout
//!
//! ```text
//! <snapshot_dir>/
//! ├── snapshot_001000/          # checkpoint at height 1000
//! │   ├── metadata.json         # SnapshotMetadata (height, state_root, timestamp)
//! │   └── <RocksDB files>       # CURRENT, MANIFEST-*, *.sst, ...
//! ├── snapshot_002000/
//! │   └── ...
//! └── snapshot_003000/
//!     └── ...
//! ```
//!
//! ## Lifecycle
//!
//! 1. **Create** — `SnapshotManager::create_snapshot(db, metadata)`:
//!    - Calls `LemmaDb::create_checkpoint(path)` to hard-link the SST files.
//!    - Writes `metadata.json` alongside the checkpoint.
//!    - Prunes oldest snapshots beyond `max_snapshots`.
//!
//! 2. **Restore** — `SnapshotManager::restore_path(height)`:
//!    - Returns the checkpoint directory path.
//!    - Caller opens it with `LemmaDb::open(path)` +
//!      `WorldState::with_state_root(db, metadata.state_root)`.
//!
//! ## What this module does NOT do
//!
//! - **Snapshot scheduling** — the node decides when to snapshot (at epoch
//!   boundaries, or every `SNAPSHOT_INTERVAL` blocks). Scheduling lives in
//!   `lemma-node`.
//! - **State-sync serving** (chunk + range proof) — lives in `lemma-network`.
//! - **Async creation** — Phase 2. For Phase 1, snapshots are synchronous.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use lemma_core::Hash;
use serde::{Deserialize, Serialize};

use crate::{db::LemmaDb, StorageError};

/// Filename for snapshot metadata within each snapshot directory.
const METADATA_FILENAME: &str = "metadata.json";

/// Prefix used to name snapshot subdirectories.
///
/// Format: `snapshot_<height_zero_padded_12>` — zero-padded to 12 digits so
/// lexicographic sort equals numeric sort up to height 999_999_999_999.
const SNAPSHOT_DIR_PREFIX: &str = "snapshot_";

/// Suffix for staging directories used during atomic snapshot creation.
///
/// A staging directory (`snapshot_<height>.tmp`) holds the in-progress
/// checkpoint. Once complete it is renamed to the final name. On startup,
/// any leftover `.tmp` directories are cleaned up before creating a new
/// snapshot at that height.
const STAGING_SUFFIX: &str = ".tmp";

/// Maximum byte size of a `metadata.json` file.
///
/// A well-formed metadata file is ~150 bytes. Refusing to read files larger
/// than 4 KiB guards against a corrupted or accidentally replaced file
/// consuming excessive memory during startup.
const MAX_METADATA_BYTES: u64 = 4 * 1024;

// ─── SnapshotMetadata ─────────────────────────────────────────────────────────

/// Metadata stored alongside each RocksDB checkpoint.
///
/// Written as `metadata.json` in the snapshot directory. JSON is used (rather
/// than bincode) so the file is human-readable and inspectable with standard
/// tools — important for incident response and operational debugging.
///
/// The `state_root` is the cryptographic anchor for the snapshot: after
/// restore, `WorldState::with_state_root(db, metadata.state_root)` resumes
/// the exact state captured at `height`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Block height at which this snapshot was taken.
    ///
    /// The snapshot represents the world state *after* all transactions in
    /// block `height` have been applied and committed.
    pub height: u64,

    /// Blake3 Merkle root of the world state trie at `height`.
    ///
    /// Used to resume [`WorldState`] after restore:
    /// `WorldState::with_state_root(db, metadata.state_root)`.
    ///
    /// [`WorldState`]: crate::state::WorldState
    pub state_root: Hash,

    /// Unix timestamp (seconds since epoch) when this snapshot was created.
    ///
    /// Used for display and pruning — not for consensus. Never use this for
    /// any timing that affects chain state.
    pub timestamp: u64,
}

impl SnapshotMetadata {
    /// Create metadata for a snapshot taken at `height` with `state_root`.
    ///
    /// `timestamp` is set to the current wall-clock time. If the system
    /// clock is unavailable, falls back to `0` — this only affects display,
    /// never consensus.
    pub fn new(height: u64, state_root: Hash) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        Self {
            height,
            state_root,
            timestamp,
        }
    }
}

// ─── SnapshotManager ──────────────────────────────────────────────────────────

/// Manages snapshot creation, listing, and pruning.
///
/// A `SnapshotManager` is bound to a single `snapshot_dir` on disk. Multiple
/// `SnapshotManager` instances pointing to the same directory are unsupported
/// — create one per node process.
///
/// ## No database reference
///
/// `SnapshotManager` intentionally holds no reference to [`LemmaDb`] — the
/// database is passed per-call to [`create_snapshot`]. This avoids lifetime
/// entanglement and allows the manager to outlive individual database
/// instances (e.g. during restore, the old DB is closed before the snapshot
/// DB is opened).
///
/// ## Thread safety
///
/// `SnapshotManager` is `Send + Sync` (it holds only a `PathBuf` and `usize`).
/// Concurrent calls to `create_snapshot` from multiple threads are safe at the
/// `SnapshotManager` level, but callers must ensure `LemmaDb` is not being
/// written to concurrently during checkpoint creation.
///
/// [`create_snapshot`]: SnapshotManager::create_snapshot
pub struct SnapshotManager {
    /// Base directory where all snapshot subdirectories live.
    snapshot_dir: PathBuf,
    /// Maximum number of snapshots to retain. Older snapshots are pruned
    /// automatically after each `create_snapshot`. `0` means unlimited.
    max_snapshots: usize,
}

impl SnapshotManager {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Create a `SnapshotManager` rooted at `snapshot_dir`.
    ///
    /// The directory is created if it does not exist.
    ///
    /// `max_snapshots` controls how many snapshots to retain. Older snapshots
    /// are pruned automatically on each `create_snapshot`. `0` = unlimited
    /// (no pruning). Recommended default: `3`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SnapshotFailed`] if `snapshot_dir` cannot be
    /// created (e.g. insufficient permissions).
    pub fn new<P: AsRef<Path>>(
        snapshot_dir: P,
        max_snapshots: usize,
    ) -> Result<Self, StorageError> {
        let snapshot_dir = snapshot_dir.as_ref().to_path_buf();
        fs::create_dir_all(&snapshot_dir).map_err(|e| StorageError::SnapshotFailed {
            reason: format!(
                "cannot create snapshot directory '{}': {e}",
                snapshot_dir.display()
            ),
        })?;
        Ok(Self {
            snapshot_dir,
            max_snapshots,
        })
    }

    // ── Create ────────────────────────────────────────────────────────────────

    /// Create a snapshot of `db` at `metadata.height`.
    ///
    /// Uses an atomic staging-path pattern to avoid data loss on crash:
    ///
    /// 1. Write checkpoint to `snapshot_<height>.tmp` (staging).
    /// 2. Write `metadata.json` inside the staging directory.
    /// 3. Remove the old `snapshot_<height>` (final) if it exists.
    /// 4. `fs::rename` staging → final (atomic on Linux, same filesystem).
    ///
    /// If the process crashes between steps 1–3, the staging directory is
    /// cleaned up on the next call. The old snapshot at this height (if any)
    /// is not removed until step 3, so a crash before step 3 leaves the
    /// previous snapshot intact.
    ///
    /// After creating, prunes oldest snapshots if `max_snapshots > 0`.
    /// **Prune failure is non-fatal** — the snapshot was successfully created;
    /// pruning will be retried on the next call.
    ///
    /// Returns the path to the new snapshot directory.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SnapshotFailed`] if the checkpoint or rename
    /// step fails. Prune failure is logged to stderr but does not propagate.
    pub fn create_snapshot(
        &self,
        db: &LemmaDb,
        metadata: &SnapshotMetadata,
    ) -> Result<PathBuf, StorageError> {
        let final_path = self.snapshot_path(metadata.height);
        let staging_path = self.staging_path(metadata.height);

        // Clean up any leftover staging dir from a previous crashed attempt.
        if staging_path.exists() {
            fs::remove_dir_all(&staging_path).map_err(|e| StorageError::SnapshotFailed {
                reason: format!(
                    "cannot remove stale staging dir '{}': {e}",
                    staging_path.display()
                ),
            })?;
        }

        // Create the RocksDB checkpoint into the staging directory.
        db.create_checkpoint(&staging_path)?;

        // Write metadata inside the staging directory.
        self.write_metadata(&staging_path, metadata)?;

        // Atomically replace the final snapshot directory.
        // On Linux, fs::rename is atomic when src and dst are on the same
        // filesystem. Since both paths are under snapshot_dir, this is
        // guaranteed to be same-filesystem.
        if final_path.exists() {
            fs::remove_dir_all(&final_path).map_err(|e| StorageError::SnapshotFailed {
                reason: format!(
                    "cannot remove existing snapshot '{}': {e}",
                    final_path.display()
                ),
            })?;
        }
        fs::rename(&staging_path, &final_path).map_err(|e| StorageError::SnapshotFailed {
            reason: format!(
                "cannot rename staging snapshot to '{}': {e}",
                final_path.display()
            ),
        })?;

        // Prune oldest snapshots beyond max_snapshots.
        // Non-fatal: the snapshot was successfully created; pruning will be
        // retried on the next create_snapshot call.
        if self.max_snapshots > 0 {
            if let Err(e) = self.prune() {
                // TODO(node): surface this as a warning metric in Phase 2.
                eprintln!("lemma-storage: snapshot prune failed (non-fatal): {e}");
            }
        }

        Ok(final_path)
    }

    // ── List / Query ──────────────────────────────────────────────────────────

    /// List all valid snapshots, sorted by height descending (newest first).
    ///
    /// Snapshots with missing or unparseable `metadata.json` are silently
    /// skipped — a partial write during a previous crash should not prevent
    /// the node from reading the other snapshots.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SnapshotFailed`] if `snapshot_dir` cannot be
    /// read (e.g. the directory was deleted externally).
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotMetadata>, StorageError> {
        let entries =
            fs::read_dir(&self.snapshot_dir).map_err(|e| StorageError::SnapshotFailed {
                reason: format!(
                    "cannot read snapshot directory '{}': {e}",
                    self.snapshot_dir.display()
                ),
            })?;

        let mut snapshots: Vec<SnapshotMetadata> = entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                // Only consider directories whose name starts with the prefix.
                if !path.is_dir() {
                    return None;
                }
                let name = path.file_name()?.to_str()?;
                if !name.starts_with(SNAPSHOT_DIR_PREFIX) {
                    return None;
                }
                // Read metadata; skip on any error (partial write).
                self.read_metadata(&path).ok()
            })
            .collect();

        // Sort newest-first (highest height first).
        snapshots.sort_by_key(|s| std::cmp::Reverse(s.height));
        Ok(snapshots)
    }

    /// Return the metadata for the most recent (highest-height) valid snapshot,
    /// or `None` if no snapshots exist.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`list_snapshots`].
    ///
    /// [`list_snapshots`]: SnapshotManager::list_snapshots
    pub fn latest_snapshot(&self) -> Result<Option<SnapshotMetadata>, StorageError> {
        Ok(self.list_snapshots()?.into_iter().next())
    }

    // ── Restore ───────────────────────────────────────────────────────────────

    /// Return the metadata for the snapshot at `height`, if it exists.
    ///
    /// Use this to verify a snapshot before restoring:
    ///
    /// ```ignore
    /// let meta = manager.snapshot_metadata(height)?
    ///     .ok_or(StorageError::RestoreFailed { reason: "snapshot not found".into() })?;
    /// let db = LemmaDb::open(manager.restore_path(height)?)?;
    /// let ws = WorldState::with_state_root(db, meta.state_root);
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::RestoreFailed`] if the metadata file is missing
    /// or corrupt.
    pub fn snapshot_metadata(&self, height: u64) -> Result<Option<SnapshotMetadata>, StorageError> {
        let path = self.snapshot_path(height);
        if !path.exists() {
            return Ok(None);
        }
        let meta = self
            .read_metadata(&path)
            .map_err(|_| StorageError::RestoreFailed {
                reason: format!(
                    "metadata.json for snapshot at height {height} is missing or corrupt"
                ),
            })?;
        Ok(Some(meta))
    }

    /// Return the filesystem path of the snapshot directory at `height`.
    ///
    /// The returned path is the root of a valid RocksDB database directory
    /// that can be opened with `LemmaDb::open(path)`.
    ///
    /// > **Note**: a successful `restore_path` confirms the directory exists
    /// > and has valid metadata, but does **not** guarantee the RocksDB
    /// > checkpoint files are intact (e.g. a disk-full mid-checkpoint can
    /// > produce a valid `metadata.json` alongside a corrupt database).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::RestoreFailed`] if no snapshot exists at
    /// `height`. Use [`snapshot_metadata`] to check existence without
    /// opening the database.
    ///
    /// [`snapshot_metadata`]: SnapshotManager::snapshot_metadata
    pub fn restore_path(&self, height: u64) -> Result<PathBuf, StorageError> {
        let path = self.snapshot_path(height);
        if !path.exists() {
            return Err(StorageError::RestoreFailed {
                reason: format!("no snapshot found at height {height}"),
            });
        }
        Ok(path)
    }

    // ── Prune ─────────────────────────────────────────────────────────────────

    /// Remove oldest snapshots, keeping only the `max_snapshots` most recent.
    ///
    /// If `max_snapshots == 0` (unlimited), this is a no-op. Returns the
    /// number of snapshots removed.
    ///
    /// Snapshots are identified by their directory name — a directory with a
    /// corrupt `metadata.json` is still counted and pruned by age (determined
    /// from the directory name's height suffix).
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SnapshotFailed`] if a snapshot directory cannot
    /// be removed. Does **not** fail on partial success — removes as many as
    /// possible and reports the first removal error.
    pub fn prune(&self) -> Result<usize, StorageError> {
        if self.max_snapshots == 0 {
            return Ok(0);
        }

        // Collect all snapshot directories sorted newest-first by height.
        let all_dirs = self.all_snapshot_dirs()?;

        let to_remove = all_dirs
            .into_iter()
            .skip(self.max_snapshots)
            .collect::<Vec<_>>();
        let count = to_remove.len();

        for dir in to_remove {
            fs::remove_dir_all(&dir).map_err(|e| StorageError::SnapshotFailed {
                reason: format!("cannot prune snapshot '{}': {e}", dir.display()),
            })?;
        }

        Ok(count)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Canonical path for the final snapshot directory at `height`.
    fn snapshot_path(&self, height: u64) -> PathBuf {
        // Zero-pad to 12 digits so lexicographic sort matches numeric sort
        // (up to height 999_999_999_999). Rust's `str::parse::<u64>()` handles
        // zero-padded decimal strings correctly — no octal ambiguity unlike C/Python.
        self.snapshot_dir
            .join(format!("{SNAPSHOT_DIR_PREFIX}{height:012}"))
    }

    /// Staging path used during atomic snapshot creation (see `create_snapshot`).
    fn staging_path(&self, height: u64) -> PathBuf {
        // `.tmp` suffix ensures all_snapshot_dirs skips it: strip_prefix succeeds
        // but the trailing ".tmp" makes parse::<u64>() fail, so it is filtered out.
        self.snapshot_dir
            .join(format!("{SNAPSHOT_DIR_PREFIX}{height:012}{STAGING_SUFFIX}"))
    }

    /// Write `metadata` as `metadata.json` inside `snapshot_path`.
    ///
    /// Named `write_metadata` (not `serialize_metadata`) because this function
    /// performs both JSON serialization AND filesystem I/O. The canonical verb
    /// list (AGENTS.md §2.3) covers pure type↔bytes conversion; this is I/O.
    fn write_metadata(
        &self,
        snapshot_path: &Path,
        metadata: &SnapshotMetadata,
    ) -> Result<(), StorageError> {
        let meta_path = snapshot_path.join(METADATA_FILENAME);
        let json =
            serde_json::to_string_pretty(metadata).map_err(|e| StorageError::SnapshotFailed {
                reason: format!("cannot serialise snapshot metadata: {e}"),
            })?;
        fs::write(&meta_path, json).map_err(|e| StorageError::SnapshotFailed {
            reason: format!(
                "cannot write metadata.json to '{}': {e}",
                meta_path.display()
            ),
        })
    }

    /// Read and deserialise `metadata.json` from `snapshot_path`.
    ///
    /// Named `read_metadata` for the same reason as `write_metadata` (I/O + parse).
    /// Guards against suspiciously large files (> `MAX_METADATA_BYTES`) to
    /// prevent OOM from a corrupted or accidentally replaced metadata file.
    ///
    /// Silently skipping corrupt metadata in `list_snapshots` is intentional:
    /// a partial write from a previous crash must not prevent reading other
    /// snapshots. TODO(node): emit a warning metric when a snapshot is skipped.
    fn read_metadata(&self, snapshot_path: &Path) -> Result<SnapshotMetadata, StorageError> {
        let meta_path = snapshot_path.join(METADATA_FILENAME);

        // Guard against oversized / malicious metadata files.
        let file_size = meta_path.metadata().map(|m| m.len()).unwrap_or(0);
        if file_size > MAX_METADATA_BYTES {
            return Err(StorageError::RestoreFailed {
                reason: format!(
                    "'{}' is suspiciously large ({file_size} bytes, limit {MAX_METADATA_BYTES})",
                    meta_path.display()
                ),
            });
        }

        let json = fs::read_to_string(&meta_path).map_err(|e| StorageError::RestoreFailed {
            reason: format!("cannot read '{}': {e}", meta_path.display()),
        })?;
        serde_json::from_str(&json).map_err(|e| StorageError::RestoreFailed {
            reason: format!("cannot parse '{}': {e}", meta_path.display()),
        })
    }

    /// Return all snapshot directories sorted newest-first (by height parsed
    /// from directory name). Directories whose names cannot be parsed as
    /// `<prefix><u64>` are skipped (including `.tmp` staging directories).
    fn all_snapshot_dirs(&self) -> Result<Vec<PathBuf>, StorageError> {
        let entries =
            fs::read_dir(&self.snapshot_dir).map_err(|e| StorageError::SnapshotFailed {
                reason: format!(
                    "cannot read snapshot directory '{}': {e}",
                    self.snapshot_dir.display()
                ),
            })?;

        let mut dirs: Vec<(u64, PathBuf)> = entries
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if !path.is_dir() {
                    return None;
                }
                let name = path.file_name()?.to_str()?;
                // strip_prefix filters non-snapshot dirs; parse::<u64>() additionally
                // rejects staging dirs ("snapshot_000001000.tmp" → parse fails).
                let height_str = name.strip_prefix(SNAPSHOT_DIR_PREFIX)?;
                // Zero-padded decimal strings parse correctly in Rust —
                // "000001000".parse::<u64>() returns Ok(1000).
                let height: u64 = height_str.parse().ok()?;
                Some((height, path))
            })
            .collect();

        // Newest-first (highest height first).
        dirs.sort_by_key(|d| std::cmp::Reverse(d.0));
        Ok(dirs.into_iter().map(|(_, p)| p).collect())
    }
}

#[cfg(test)]
mod tests;
