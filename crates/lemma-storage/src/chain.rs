//! Typed block-store over [`LemmaDb`].
//!
//! [`ChainStore`] is a **borrowed view** over a [`LemmaDb`] handle — it holds
//! `&LemmaDb` and does not own or move the database. This mirrors the pattern
//! used by the trie layer (which also creates short-lived views per operation)
//! and by reth's `ProviderFactory`/`DatabaseProvider` (which hands out cheap
//! views over an `Arc`-shared DB).
//!
//! ## Why a borrowed view (not ownership or `Arc`)
//!
//! `WorldState` currently *owns* `LemmaDb` (a deliberate choice to avoid
//! self-referential lifetime issues — see `state.rs` doc). All `LemmaDb`
//! methods take `&self` (RocksDB internals are already `Send + Sync`), so a
//! `&LemmaDb` borrow supports both reads and writes without owning the handle.
//!
//! **N3 forward note (MUST READ before implementing N3):**
//! When the async driver, network task, and future RPC task need to share the
//! DB handle *concurrently*, the pattern is:
//! ```text
//! Arc<LemmaDb>            ← opened once, shared by all async tasks
//!                            (the reth ProviderFactory model)
//! ChainStore::new(&db)    ← &*arc, still a borrowed view, zero-cost
//! Arc<RwLock<WorldState>> ← for mutable state access across tasks
//! ```
//! N3 should open a single `LemmaDb`, wrap it in `Arc`, and hand `&*arc` to
//! both `WorldState` (via `Arc<RwLock<WorldState>>`) and `ChainStore` views.
//!
//! **Critical**: `ChainStore::put_block` does a read-then-write on the tip
//! metadata (see its doc comment). This read-then-write is NOT atomic across
//! two concurrent callers. N3 MUST ensure `put_block` is always called by the
//! **sole producer task** (not from multiple tasks concurrently), OR that it is
//! called under the same exclusive write lock that guards `WorldState`. The
//! `Arc<LemmaDb>` gives shared access; write exclusivity must be enforced by
//! the caller (same discipline as `WorldState::put_account`).
//!
//! See `state.rs` §Thread safety note and `docs/04-BUILD_GUIDE §10`.
//!
//! ## Persistence model
//!
//! Every committed block is written to **three locations atomically** (one
//! `WriteBatch`, AGENTS.md §16.2):
//!
//! | CF | Key | Value |
//! |---|---|---|
//! | `CF_BLOCKS` | `height: u64` big-endian | `bincode(Block)` |
//! | `CF_BLOCK_HASH` | `hash: [u8; 32]` | `bincode(Block)` |
//! | `CF_METADATA` | `b"latest_height"` | `height: u64` big-endian |
//! | `CF_METADATA` | `b"latest_hash"` | `hash: [u8; 32]` |
//!
//! `CF_BLOCKS` uses big-endian height keys so RocksDB's lexicographic ordering
//! equals numeric ordering, enabling efficient range scans (db.rs §CF_BLOCKS).
//!
//! ## Consumers
//!
//! - `lemma-node::genesis_boot` — writes the genesis block (height 0).
//! - `lemma-node` N3 producer — writes each committed block.
//! - `lemma-node` N6 range-sync — reads blocks to serve `RangeResponse`.
//! - `lemma-rpc` (Phase 4) — `lem_getBlock`, `lem_blockNumber` endpoints.
//!
//! Two+ consumers in different crates → belongs in `lemma-storage` (AGENTS.md
//! §2.4: shared utilities live in the lower crate, imported not duplicated).

use lemma_core::{block::Block, hash::Hash};

use crate::{
    db::{CF_BLOCK_HASH, CF_BLOCKS, CF_METADATA},
    LemmaDb, StorageError,
};

// ── Metadata key constants ────────────────────────────────────────────────────

/// `CF_METADATA` key for the latest committed block height (`u64` big-endian).
///
/// The single source of truth for this key — genesis_boot and the producer both
/// write through [`ChainStore::put_block`] which updates this atomically.
pub(crate) const META_LATEST_HEIGHT: &[u8] = b"latest_height";

/// `CF_METADATA` key for the latest committed block hash (32 bytes).
pub(crate) const META_LATEST_HASH: &[u8] = b"latest_hash";

// ── ChainStore ────────────────────────────────────────────────────────────────

/// Typed block read/write/tip access over a borrowed [`LemmaDb`].
///
/// Construct with [`ChainStore::new`]; the lifetime `'a` is tied to the DB
/// handle. See the [module-level docs](self) for the ownership rationale and
/// the N3 `Arc<LemmaDb>` forward note.
#[derive(Debug)]
pub struct ChainStore<'a> {
    db: &'a LemmaDb,
}

impl<'a> ChainStore<'a> {
    /// Construct a [`ChainStore`] view over `db`.
    ///
    /// Zero-cost — no allocations, no DB access.
    #[must_use]
    pub fn new(db: &'a LemmaDb) -> Self {
        Self { db }
    }

    // ── Writes ────────────────────────────────────────────────────────────────

    /// Persist `block` (identified by `hash`) atomically to all three CF
    /// locations plus chain-tip metadata (AGENTS.md §16.2).
    ///
    /// `block` is serialized **once**; the same bytes are stored under both
    /// the height index (`CF_BLOCKS`) and hash index (`CF_BLOCK_HASH`).
    ///
    /// **Tip advancement**: metadata (`latest_height` / `latest_hash`) is
    /// updated only when `block.height() >= current latest_height`. Callers
    /// that backfill gaps (e.g. range-sync, N6) do NOT overwrite the tip when
    /// writing a block whose height is below the current chain tip.
    ///
    /// **Tip race under concurrent writers**: the block + tip writes ARE
    /// committed in one atomic `WriteBatch`, but the `latest_height()` read
    /// (used to decide whether to advance the tip) is NOT serialized with a
    /// concurrent caller's batch. Two concurrent `put_block` calls at heights
    /// N and N+1 can both observe the same pre-write tip, both decide
    /// `advance = true`, and then race — the lower height can clobber the
    /// higher-height tip. For Phase 1 this is safe because the producer is the
    /// **sole writer** in a single async task. N3 MUST call `put_block` under
    /// the same write lock that guards `WorldState` — see the module-level N3
    /// forward note and `state.rs` §Thread safety.
    ///
    /// # Errors
    ///
    /// - [`StorageError::SerializationFailed`] — `bincode` could not encode `block`.
    /// - [`StorageError::BatchFailed`] — RocksDB commit failed.
    /// - [`StorageError::Database`] — underlying RocksDB I/O error.
    pub fn put_block(&self, block: &Block, hash: Hash) -> Result<(), StorageError> {
        let block_bytes = bincode::serialize(block)
            .map_err(StorageError::from)?;

        let height = block.height();
        let height_key = height.to_be_bytes();

        let mut batch = self.db.new_batch();
        self.db.batch_put(&mut batch, CF_BLOCKS,     &height_key,        &block_bytes)?;
        self.db.batch_put(&mut batch, CF_BLOCK_HASH, hash.as_bytes(),    &block_bytes)?;

        // Advance chain-tip metadata only when this block is at or above the
        // current tip (handles both fresh chains and normal producer writes).
        let advance = match self.latest_height()? {
            None          => true,               // uninitialised — always set
            Some(current) => height >= current,  // >= handles exact-height re-write
        };
        if advance {
            self.db.batch_put(&mut batch, CF_METADATA, META_LATEST_HEIGHT, &height_key)?;
            self.db.batch_put(&mut batch, CF_METADATA, META_LATEST_HASH,   hash.as_bytes())?;
        }

        self.db.write_batch(batch)
    }

    // ── Reads — by index ─────────────────────────────────────────────────────

    /// Retrieve the block at `height`, or `None` if no block has been committed
    /// at that height.
    ///
    /// # Errors
    ///
    /// - [`StorageError::SerializationFailed`] — stored bytes are not a valid
    ///   `Block` (indicates DB corruption).
    /// - [`StorageError::Database`] — RocksDB I/O error.
    pub fn get_block_by_height(&self, height: u64) -> Result<Option<Block>, StorageError> {
        let Some(bytes) = self.db.get(CF_BLOCKS, &height.to_be_bytes())? else {
            return Ok(None);
        };
        Ok(Some(bincode::deserialize(&bytes).map_err(StorageError::from)?))
    }

    /// Retrieve the block with `hash`, or `None` if not found.
    ///
    /// # Errors
    ///
    /// Same as [`get_block_by_height`].
    ///
    /// [`get_block_by_height`]: ChainStore::get_block_by_height
    pub fn get_block_by_hash(&self, hash: &Hash) -> Result<Option<Block>, StorageError> {
        let Some(bytes) = self.db.get(CF_BLOCK_HASH, hash.as_bytes())? else {
            return Ok(None);
        };
        Ok(Some(bincode::deserialize(&bytes).map_err(StorageError::from)?))
    }

    // ── Reads — chain tip ────────────────────────────────────────────────────

    /// Return `(latest_height, latest_hash)`, or `None` for an uninitialised
    /// chain (no block written yet).
    ///
    /// # Errors
    ///
    /// - [`StorageError::SerializationFailed`] — metadata bytes are malformed.
    /// - [`StorageError::Database`] — RocksDB I/O error.
    pub fn tip(&self) -> Result<Option<(u64, Hash)>, StorageError> {
        let Some(height) = self.latest_height()? else {
            return Ok(None);
        };
        let hash = self.latest_hash()?.ok_or_else(|| {
            // Both keys must exist together — if height is present but hash is
            // absent, the DB is in a partially-written state (bug in put_block
            // or external mutation). Surface it as corruption.
            StorageError::Corrupted {
                reason: "latest_height present but latest_hash missing — DB state inconsistent"
                    .into(),
            }
        })?;
        Ok(Some((height, hash)))
    }

    /// Return the latest committed block height, or `None` for an uninitialised
    /// chain.
    ///
    /// # Errors
    ///
    /// See [`tip`](ChainStore::tip).
    pub fn latest_height(&self) -> Result<Option<u64>, StorageError> {
        let Some(bytes) = self.db.get(CF_METADATA, META_LATEST_HEIGHT)? else {
            return Ok(None);
        };
        let arr: [u8; 8] = bytes.as_slice().try_into().map_err(|_| {
            StorageError::SerializationFailed {
                reason: format!(
                    "latest_height: expected 8 bytes, got {}",
                    bytes.len()
                ),
            }
        })?;
        Ok(Some(u64::from_be_bytes(arr)))
    }

    // ── Reads — range sync ───────────────────────────────────────────────────

    /// Return the contiguous prefix of blocks from `from` through `to`
    /// (inclusive), stopping at the first missing height.
    ///
    /// This is the server side of the range / backfill sync path
    /// (`docs/12-NETWORK_SYNC_SPEC §2.2`). The caller is responsible for
    /// bounding the range via `RangeRequest::validate(max_range)` (in
    /// `lemma-network`) **before** calling this method — unbounded scans are
    /// a DoS vector (AGENTS.md §15.2).
    ///
    /// Returns an empty `Vec` when `from > to` or when `from` is above the
    /// current chain tip.
    ///
    /// # Errors
    ///
    /// - [`StorageError::SerializationFailed`] — a stored block is corrupt.
    /// - [`StorageError::Database`] — RocksDB I/O error.
    pub fn get_range(&self, from: u64, to: u64) -> Result<Vec<Block>, StorageError> {
        if from > to {
            return Ok(vec![]);
        }
        // Defense-in-depth allocation cap: even if the caller passes an
        // unbounded range, we never pre-allocate more than MAX_RANGE_CAPACITY
        // slots. The network layer validates RangeRequest width ≤ 256
        // (DEFAULT_MAX_RANGE) before calling this, but `get_range` is `pub`
        // so future callers might not. Saturate to the cap rather than risk
        // a ~18-exabyte with_capacity on `from=0, to=u64::MAX`
        // (AGENTS.md §15.2 — validate at the boundary).
        const MAX_RANGE_CAPACITY: usize = 512; // 2× DEFAULT_MAX_RANGE — generous but bounded
        let capacity = usize::try_from(to - from + 1)
            .unwrap_or(MAX_RANGE_CAPACITY)
            .min(MAX_RANGE_CAPACITY);
        let mut blocks = Vec::with_capacity(capacity);
        for height in from..=to {
            match self.get_block_by_height(height)? {
                Some(block) => blocks.push(block),
                None        => break, // stop at first gap — contiguous prefix only
            }
        }
        Ok(blocks)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn latest_hash(&self) -> Result<Option<Hash>, StorageError> {
        let Some(bytes) = self.db.get(CF_METADATA, META_LATEST_HASH)? else {
            return Ok(None);
        };
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            StorageError::SerializationFailed {
                reason: format!("latest_hash: expected 32 bytes, got {}", bytes.len()),
            }
        })?;
        Ok(Some(Hash::from_bytes(arr)))
    }
}

#[cfg(test)]
mod tests;
