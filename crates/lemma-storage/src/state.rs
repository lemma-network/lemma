//! World state — typed account and contract storage access.
//!
//! [`WorldState`] is the single entry point for all state reads and writes on
//! the Lemma chain. It owns a [`LemmaDb`] and tracks the current state trie
//! root. The VM, consensus, and RPC layers interact with chain state exclusively
//! through this module.
//!
//! ## Account model
//!
//! Every address has exactly one [`Account`]. Accounts that have never been
//! written to are implicitly all-zero (zero balance, zero nonce, `Hash::zero()`
//! for `code_hash` and `storage_root`). [`WorldState::get_account`] returns
//! `Ok(None)` for nonexistent addresses; convenience methods like
//! [`WorldState::get_balance`] return the zero value instead of an error.
//!
//! ## Contract storage
//!
//! Contract storage slots use the `CF_STORAGE` column family with a 52-byte
//! composite key: `contract_address (20 bytes) ++ storage_slot (32 bytes)`.
//! Per-contract storage tries are a Phase 2 concern (VM integration). For
//! Phase 1, contract storage is written to `CF_STORAGE` directly.
//!
//! ## State trie + state root
//!
//! Every [`put_account`] call inserts the address → bincode(Account) mapping
//! into a [`MerklePatriciaTrie`] backed by the `CF_TRIE_NODES` column family.
//! The trie root after all writes is the `state_root` committed to
//! [`BlockHeader::state_root`]. Call [`WorldState::commit`] to obtain the
//! current root for block production.
//!
//! ## Block-level batching (Phase 2 note)
//!
//! Each [`put_account`] currently commits a single `WriteBatch` covering the
//! modified trie nodes. True block-level batching (accumulate all writes for
//! an entire block in one atomic RocksDB write) requires refactoring
//! [`MerklePatriciaTrie::insert`] to accept an external batch — deferred to
//! Phase 2 when the VM integration layer is built.
//!
//! [`put_account`]: WorldState::put_account
//! [`BlockHeader::state_root`]: lemma_core::BlockHeader

use std::sync::Arc;

use lemma_core::{Address, Amount, Hash};

use crate::{
    account::Account,
    db::{LemmaDb, CF_CODE, CF_STORAGE},
    trie::{MerklePatriciaTrie, MerkleProof},
    StorageError,
};

/// Length of a composite contract-storage key: 20 (address) + 32 (slot).
const STORAGE_KEY_LEN: usize = 52;

// ─── WorldState ───────────────────────────────────────────────────────────────

/// Typed world-state access over a [`LemmaDb`].
///
/// `WorldState` holds an `Arc<LemmaDb>` so it can be constructed from a shared
/// database handle (the running node shares `Arc<LemmaDb>` across tasks).
/// All account and contract storage reads/writes go through this struct.
///
/// ## Lifetime note
///
/// [`MerklePatriciaTrie`] borrows `&LemmaDb`, creating a self-referential
/// lifetime if we stored it as a field. Instead `WorldState` stores only the
/// root hash and creates short-lived trie instances per operation — no lifetime
/// gymnastics, no `unsafe`. With `Arc<LemmaDb>`, trie instances borrow from
/// `&*self.db` (the deref target) for the duration of the method call only.
///
/// ## Thread safety
///
/// `WorldState` is **not** `Sync`. Concurrent access from multiple threads
/// requires an `Arc<RwLock<WorldState>>` on the caller side
/// (see `04-BUILD_GUIDE.md §10`).
pub struct WorldState {
    /// Shared database handle. `Arc` allows construction from the node's shared
    /// `Arc<LemmaDb>` without transferring ownership.
    db: Arc<LemmaDb>,
    /// Current state trie root. `None` for a fresh (empty) state.
    state_root: Option<Hash>,
}

impl WorldState {
    // ── Construction ──────────────────────────────────────────────────────────

    /// Create a new empty world state backed by `db`.
    ///
    /// The state trie starts empty (`state_root = None`). Use this for genesis
    /// block construction or unit tests.
    pub fn new(db: Arc<LemmaDb>) -> Self {
        Self {
            db,
            state_root: None,
        }
    }

    /// Resume world state from a persisted `state_root`.
    ///
    /// Used when loading an existing chain from disk, or when the node
    /// execution layer needs a read-only snapshot of committed state.
    /// The root hash must correspond to trie nodes already present in the
    /// `trie_nodes` column family — if not, the first account read will return
    /// [`StorageError::TrieNodeNotFound`].
    pub fn with_state_root(db: Arc<LemmaDb>, state_root: Hash) -> Self {
        Self {
            db,
            state_root: Some(state_root),
        }
    }

    // ── State root ────────────────────────────────────────────────────────────

    /// The current state trie root, or `None` if no accounts have been written.
    ///
    /// This value becomes [`BlockHeader::state_root`] at block commit time.
    /// Call [`commit`] to obtain it explicitly after a batch of writes.
    ///
    /// [`BlockHeader::state_root`]: lemma_core::BlockHeader
    /// [`commit`]: WorldState::commit
    pub fn state_root(&self) -> Option<Hash> {
        self.state_root
    }

    /// Finalise a block's state changes and return the state root.
    ///
    /// For Phase 1 this simply returns [`state_root`]. In Phase 2, this will
    /// flush the accumulated write batch to RocksDB atomically.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::KeyNotFound`] if the trie is empty (no accounts
    /// written yet). The caller should not commit an empty block.
    ///
    /// [`state_root`]: WorldState::state_root
    // SEC-2: use KeyNotFound rather than InvalidProof — "empty state" is not
    // a proof failure. Wrong error variant on the settlement path causes
    // callers to misclassify the condition and trigger the wrong recovery.
    #[must_use = "the state root must be stored in BlockHeader::state_root"]
    pub fn commit(&self) -> Result<Hash, StorageError> {
        self.state_root.ok_or(StorageError::KeyNotFound {
            key: "(state trie is empty — no accounts written)".to_string(),
        })
    }

    // ── Account CRUD ──────────────────────────────────────────────────────────

    /// Look up the account at `address`.
    ///
    /// Returns `Ok(None)` if the address has never been written. Callers that
    /// require an account to exist (e.g. transaction validation) should convert
    /// `None` to [`StorageError::AccountNotFound`] using `.ok_or_else(...)`.
    ///
    /// # Errors
    ///
    /// - [`StorageError::TrieNodeNotFound`] — trie corruption or wrong root.
    /// - [`StorageError::SerializationFailed`] — bincode decode failed.
    pub fn get_account(&self, address: &Address) -> Result<Option<Account>, StorageError> {
        let Some(root) = self.state_root else {
            // Empty trie (WorldState::new with no puts yet) — every address is
            // implicitly absent. WorldState::with_state_root always sets
            // state_root = Some(...), so this branch is unreachable for resumed state.
            return Ok(None);
        };
        let trie = MerklePatriciaTrie::with_root(&self.db, root);
        let Some(bytes) = trie.get(address.as_bytes())? else {
            return Ok(None);
        };
        let account = bincode::deserialize(&bytes)?;
        Ok(Some(account))
    }

    /// Insert or update the account at `address`.
    ///
    /// Serialises `account` with bincode, inserts the key-value pair into the
    /// state trie, and updates [`state_root`] to the new trie root.
    ///
    /// # Errors
    ///
    /// - [`StorageError::SerializationFailed`] — bincode encode failed.
    /// - [`StorageError::BatchFailed`] — RocksDB commit failed.
    ///
    /// [`state_root`]: WorldState::state_root
    pub fn put_account(
        &mut self,
        address: &Address,
        account: &Account,
    ) -> Result<(), StorageError> {
        let bytes = bincode::serialize(account)?;
        let mut trie = self.open_trie_mut();
        trie.insert(address.as_bytes(), bytes)?;
        // insert() writes all trie nodes atomically via WriteBatch before updating
        // trie.root(). If insert() errors, the ? propagates and state_root is
        // unchanged — the state remains consistent with its pre-call value.
        self.state_root = trie.root();
        Ok(())
    }

    // ── Account convenience ───────────────────────────────────────────────────

    /// Return the liquid LEM balance of `address`, or [`Amount::zero()`] if
    /// the account does not exist.
    ///
    /// Returns `balance` directly (the liquid portion).
    /// Use [`get_account`] + [`Account::available_balance`] if you need the
    /// spendable balance excluding staked LEM.
    ///
    /// [`get_account`]: WorldState::get_account
    pub fn get_balance(&self, address: &Address) -> Result<Amount, StorageError> {
        Ok(self
            .get_account(address)?
            .map_or(Amount::zero(), |a| a.balance))
    }

    /// Return the transaction nonce of `address`, or `0` if the account does
    /// not exist.
    pub fn get_nonce(&self, address: &Address) -> Result<u64, StorageError> {
        Ok(self.get_account(address)?.map_or(0, |a| a.nonce))
    }

    /// Increment the nonce of `address` by one.
    ///
    /// If the account does not exist, creates a default (zero-balance, zero
    /// code) account with `nonce = 1`.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Corrupted`] — nonce is already at `u64::MAX`. This
    ///   is unreachable in any realistic chain (1 tx/s for 584 billion years),
    ///   but `saturating_add` is forbidden here: silent saturation would leave
    ///   nonce permanently at `u64::MAX`, making all future transactions with
    ///   `nonce == u64::MAX` permanently valid — a replay attack surface.
    /// - [`StorageError::SerializationFailed`] — bincode encode/decode failed.
    /// - [`StorageError::BatchFailed`] — RocksDB commit failed.
    pub fn increment_nonce(&mut self, address: &Address) -> Result<(), StorageError> {
        let mut account = self.get_account(address)?.unwrap_or_default();
        // SEC-1: use checked_add, not saturating_add. Silent saturation at
        // u64::MAX creates a replay attack surface on the nonce check.
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or_else(|| StorageError::Corrupted {
                reason: format!(
                    "nonce overflow at {} (nonce == u64::MAX)",
                    hex::encode(address.as_bytes()),
                ),
            })?;
        self.put_account(address, &account)
    }

    // ── Contract storage ──────────────────────────────────────────────────────

    /// Read a contract storage slot.
    ///
    /// The slot is identified by `address` (20 bytes) + `slot` (32 bytes),
    /// stored in the `CF_STORAGE` column family with a 52-byte composite key.
    ///
    /// Returns `Ok(None)` if the slot has never been written.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Database`] — RocksDB read failed.
    pub fn get_storage(
        &self,
        address: &Address,
        slot: &Hash,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let key = storage_key(address, slot);
        self.db.get(CF_STORAGE, &key)
    }

    /// Write a value to a contract storage slot.
    ///
    /// The value is stored raw (no serialization) in `CF_STORAGE`.
    /// Writing an empty `value` is valid (not the same as deletion — use
    /// [`delete_storage`] to remove a slot).
    ///
    /// [`delete_storage`]: WorldState::delete_storage
    ///
    /// # Errors
    ///
    /// - [`StorageError::BatchFailed`] — RocksDB write failed.
    pub fn put_storage(
        &mut self,
        address: &Address,
        slot: &Hash,
        value: &[u8],
    ) -> Result<(), StorageError> {
        let key = storage_key(address, slot);
        self.db.put(CF_STORAGE, &key, value)
    }

    /// Delete a contract storage slot.
    ///
    /// After deletion, [`get_storage`] returns `Ok(None)` for this slot.
    ///
    /// [`get_storage`]: WorldState::get_storage
    ///
    /// # Errors
    ///
    /// - [`StorageError::Database`] — RocksDB delete failed.
    pub fn delete_storage(&mut self, address: &Address, slot: &Hash) -> Result<(), StorageError> {
        let key = storage_key(address, slot);
        self.db.delete(CF_STORAGE, &key)
    }

    // ── Bytecode store ────────────────────────────────────────────────────────

    /// Store contract bytecode in the content-addressed code store.
    ///
    /// The key is `code_hash` (the Blake3 hash of `bytecode`). The caller is
    /// responsible for computing `code_hash = blake3(bytecode)` before calling
    /// this method — typically done by the deploy handler in the execution layer.
    ///
    /// **Append-only / idempotent:** if `code_hash` is already present in
    /// `CF_CODE`, this method returns `Ok(())` immediately without overwriting
    /// the existing value. This enforces the spec invariant that bytecode is
    /// never mutated or deleted after first write (08-EXECUTION_SPEC §3.4(b),
    /// DB-A23). The first deployer of a given bytecode pays the storage cost;
    /// later deployers of identical bytecode pay only the account pointer write.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Database`] — RocksDB read or write failed.
    pub fn put_code(&self, code_hash: &Hash, bytecode: &[u8]) -> Result<(), StorageError> {
        // Append-only: check presence before writing. If the hash is already
        // stored, return immediately — no overwrite, no error.
        if self.db.get(CF_CODE, code_hash.as_bytes())?.is_some() {
            return Ok(());
        }
        self.db.put(CF_CODE, code_hash.as_bytes(), bytecode)
    }

    /// Retrieve contract bytecode by its content hash.
    ///
    /// Returns `Ok(None)` if no bytecode has been stored under `code_hash`.
    /// Returns `Ok(Some(bytes))` if the bytecode is present.
    ///
    /// The returned bytes are the raw WASM bytecode as originally stored by
    /// [`put_code`]. The caller can verify integrity by recomputing
    /// `blake3(bytes)` and comparing to `code_hash`.
    ///
    /// [`put_code`]: WorldState::put_code
    ///
    /// # Errors
    ///
    /// - [`StorageError::Database`] — RocksDB read failed.
    pub fn get_code(&self, code_hash: &Hash) -> Result<Option<Vec<u8>>, StorageError> {
        self.db.get(CF_CODE, code_hash.as_bytes())
    }

    // ── Proof ─────────────────────────────────────────────────────────────────

    /// Generate a Merkle proof for the account at `address`.
    ///
    /// Returns an **inclusion proof** if the account exists, or a
    /// **non-inclusion proof** if it does not. The proof can be verified
    /// offline via [`MerkleProof::verify`].
    ///
    /// # Errors
    ///
    /// - [`StorageError::InvalidProof`] — state is empty (no state root yet).
    /// - [`StorageError::TrieNodeNotFound`] — trie corruption.
    pub fn generate_account_proof(&self, address: &Address) -> Result<MerkleProof, StorageError> {
        let root = self.state_root.ok_or(StorageError::InvalidProof {
            key: hex::encode(address.as_bytes()),
        })?;
        let trie = MerklePatriciaTrie::with_root(&self.db, root);
        trie.generate_proof(address.as_bytes())
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Open a mutable trie instance rooted at the current state root.
    ///
    /// If `state_root` is `None` (empty state), opens a fresh empty trie.
    /// The trie borrows `&*self.db` for the duration of the returned value;
    /// the borrow is scoped to the calling method, never stored in `self`.
    fn open_trie_mut(&self) -> MerklePatriciaTrie<'_> {
        match self.state_root {
            Some(root) => MerklePatriciaTrie::with_root(&self.db, root),
            None => MerklePatriciaTrie::new(&self.db),
        }
    }
}

// ─── Key helpers ──────────────────────────────────────────────────────────────

/// Build the 52-byte composite key for a contract storage slot.
///
/// Layout: `address (20 bytes) ++ slot (32 bytes)`.
/// This matches the `CF_STORAGE` column family key format defined in `db.rs`.
fn storage_key(address: &Address, slot: &Hash) -> [u8; STORAGE_KEY_LEN] {
    let addr_bytes = address.as_bytes();
    let slot_bytes = slot.as_bytes();
    // Layout: address (20 bytes) ++ slot (32 bytes) = 52 bytes.
    // These debug assertions catch any future repr change to Address or Hash.
    debug_assert_eq!(addr_bytes.len(), 20, "Address must be 20 bytes");
    debug_assert_eq!(slot_bytes.len(), 32, "Hash must be 32 bytes");
    let mut key = [0u8; STORAGE_KEY_LEN];
    key[..20].copy_from_slice(addr_bytes);
    key[20..].copy_from_slice(slot_bytes);
    key
}

#[cfg(test)]
mod tests;
