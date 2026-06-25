//! Scratch state overlay and snapshot for single-transaction isolation.
//!
//! [`ScratchState`] buffers all writes from a single transaction. On success,
//! `commit_with_nonce()` flushes them to the underlying state. On failure,
//! `discard()` returns the inner reference unchanged — no partial writes reach
//! canonical state.
//!
//! [`ScratchSnapshot`] is an owned `'static` snapshot of scratch state, used
//! by `execute_call` to satisfy wasmtime's `'static` bound on `HostState`.
//!
//! Split from `executor.rs` for file-size compliance (AGENTS §3.1 < 300 lines,
//! V-5 audit fix).

use std::collections::{BTreeMap, BTreeSet};

use lemma_core::{address::Address, amount::Amount, hash::Hash};

use crate::state::ContractStateView;

// ── ScratchState ──────────────────────────────────────────────────────────────

/// Buffers writes from a single transaction; committed or discarded atomically.
///
/// Reads fall through to `inner` if not present in the scratch buffers.
/// Writes stay in scratch until `commit_with_nonce` (success) or `discard`
/// (failure).
///
/// ## Determinism
///
/// All maps use [`BTreeMap`] — deterministic iteration order (AGENTS.md §7.1).
/// Never use `HashMap` here.
///
/// ## Storage read semantics
///
/// - Key present with `Some(v)` → return that value (written this tx).
/// - Key present with `None` → return `None` (deleted this tx).
/// - Key absent → fall through to `inner.read()`.
pub(crate) struct ScratchState<'a, S: ContractStateView> {
    inner: &'a mut S,
    /// Storage writes: `None` = deleted, `Some(v)` = written.
    storage_writes: BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>>,
    balance_writes: BTreeMap<Address, Amount>,
    nonce_writes: BTreeMap<Address, u64>,
    /// Legacy code writes (kept for backward compat with InMemoryStateView test double).
    /// Production deploy path uses `code_hash_writes` + `code_store_writes` instead.
    code_writes: BTreeMap<Address, Vec<u8>>,
    /// Thin pointer: `contract_address → code_hash` (DB-A22).
    ///
    /// Set by `execute_deploy` after successful compilation. On commit, flushed
    /// to `inner.set_code()` with the full bytecode resolved from `code_store_writes`.
    code_hash_writes: BTreeMap<Address, Hash>,
    /// Content-addressed bytecode store: `code_hash → bytecode` (DB-A23).
    ///
    /// Written only by the first deployer of a given bytecode. Later deployers
    /// of identical bytecode skip this write and pay only the base pointer cost.
    code_store_writes: BTreeMap<Hash, Vec<u8>>,
}

impl<'a, S: ContractStateView> ScratchState<'a, S> {
    /// Create a new scratch overlay over `inner`.
    pub(crate) fn new(inner: &'a mut S) -> Self {
        Self {
            inner,
            storage_writes: BTreeMap::new(),
            balance_writes: BTreeMap::new(),
            nonce_writes: BTreeMap::new(),
            code_writes: BTreeMap::new(),
            code_hash_writes: BTreeMap::new(),
            code_store_writes: BTreeMap::new(),
        }
    }

    // ── Safety-invariant accessors (P3·Step 18-05) ─────────────────────────────

    /// Read access to the storage writes for safety-invariant checking.
    ///
    /// Returns a reference to the `BTreeMap` of `(contract_addr, key) → Option<value>`.
    /// `Some(v)` = written, `None` = deleted. Used by [`validate_safety_invariants`]
    /// to inspect the state diff without cloning.
    pub(crate) fn storage_writes_ref(&self) -> &BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>> {
        &self.storage_writes
    }

    /// Read access to the canonical (inner) state for safety-invariant checking.
    ///
    /// Returns a reference to the underlying state view (pre-transaction state).
    /// Used by [`validate_safety_invariants`] to read old values for ratchet checks.
    pub(crate) fn inner_ref(&self) -> &S {
        self.inner
    }

    // ── Deploy-path helpers (thin pointer + content store) ────────────────────

    /// Store bytecode in the content-addressed scratch store (DB-A23).
    ///
    /// Called by `execute_deploy` for the first deployer of a given bytecode.
    /// Later deployers of identical bytecode skip this call.
    pub(crate) fn put_code_content(&mut self, hash: Hash, bytes: Vec<u8>) {
        self.code_store_writes.insert(hash, bytes);
    }

    /// Set the thin pointer: `contract_address → code_hash` (DB-A22).
    ///
    /// Called by `execute_deploy` after successful compilation and dedup check.
    pub(crate) fn set_code_hash_ptr(&mut self, addr: &Address, hash: Hash) {
        self.code_hash_writes.insert(*addr, hash);
    }

    /// Resolve bytecode for a contract address via the thin-pointer path.
    ///
    /// Resolution order:
    /// 1. Check `code_hash_writes` for a thin pointer set this transaction.
    /// 2. If found, look up bytecode in `code_store_writes`.
    /// 3. Fall back to `inner.code()` for contracts deployed in prior transactions
    ///    (InMemoryStateView stores full bytecode; production MvStateView resolves
    ///    via its own code_hash → bytecode path).
    ///
    /// This is the canonical bytecode-loading path for `execute_call`.
    pub(crate) fn resolve_code(&self, addr: &Address) -> Option<Vec<u8>> {
        // Check if a thin pointer was set this transaction.
        if let Some(hash) = self.code_hash_writes.get(addr) {
            // Resolve bytecode from the content store (same transaction).
            if let Some(bytes) = self.code_store_writes.get(hash) {
                return Some(bytes.clone());
            }
            // Hash registered but bytecode not in scratch — this is the later-deployer
            // case where the bytecode was already in committed state. Fall through to
            // inner.code() which resolves via the committed store.
        }
        // Fall through to inner for contracts deployed in prior transactions.
        self.inner.code(addr)
    }

    /// Snapshot the current scratch state into an owned [`ScratchSnapshot`].
    ///
    /// Used by `execute_call` to give the host an owned `'static` state view
    /// without requiring `ScratchState` to be `'static`. After execution,
    /// writes are merged back via `merge_snapshot`.
    ///
    /// ## M4 fix — canonical read-through
    ///
    /// The snapshot now carries a clone of `inner` as a [`CanonicalStateRead`]
    /// so that WASM `storage_read` can observe values from prior committed
    /// transactions. `S: Clone` is required to produce the owned `'static`
    /// canonical reader without lifetime parameters.
    ///
    /// The snapshot captures:
    /// - All scratch writes accumulated so far (highest priority).
    /// - A tombstone set for keys deleted this transaction.
    /// - A clone of `inner` for canonical fall-through (M4 fix).
    ///
    /// For B4 (single-frame, no cross-contract calls), this is semantically
    /// correct. Phase 3 will replace this with a proper multi-frame state stack.
    pub(crate) fn snapshot(&self) -> ScratchSnapshot
    where
        S: Clone + 'static,
    {
        ScratchSnapshot {
            storage: self
                .storage_writes
                .iter()
                .filter_map(|(k, v)| v.as_ref().map(|val| (k.clone(), val.clone())))
                .collect(),
            storage_deletes: self
                .storage_writes
                .iter()
                .filter_map(|(k, v)| if v.is_none() { Some(k.clone()) } else { None })
                .collect(),
            balances: self.balance_writes.clone(),
            nonces: self.nonce_writes.clone(),
            code: self.code_writes.clone(),
            code_hashes: self.code_hash_writes.clone(),
            code_store: self.code_store_writes.clone(),
            // M4 fix: clone inner to provide canonical read-through for WASM storage_read.
            // The clone is cheap for InMemoryStateView (BTreeMap clone) and for
            // MvStateView (Arc clone for mv + base; RefCell clone for captured/writes).
            canonical: Box::new(self.inner.clone()),
        }
    }

    /// Merge writes from a completed [`ScratchSnapshot`] back into this scratch.
    ///
    /// Called after `execute_call` completes successfully. Overwrites any
    /// existing scratch entries with the host's final values.
    pub(crate) fn merge_snapshot(&mut self, snap: ScratchSnapshot) {
        for (k, v) in snap.storage {
            self.storage_writes.insert(k, Some(v));
        }
        for k in snap.storage_deletes {
            self.storage_writes.insert(k, None);
        }
        for (addr, amt) in snap.balances {
            self.balance_writes.insert(addr, amt);
        }
        for (addr, n) in snap.nonces {
            self.nonce_writes.insert(addr, n);
        }
        for (addr, code) in snap.code {
            self.code_writes.insert(addr, code);
        }
        for (addr, hash) in snap.code_hashes {
            self.code_hash_writes.insert(addr, hash);
        }
        for (hash, bytes) in snap.code_store {
            self.code_store_writes.insert(hash, bytes);
        }
        // `canonical` is a read-only view — no writes to merge back.
    }

    /// Commit all scratch writes to `inner` and advance the sender's nonce.
    ///
    /// Called on success. After this call, `inner` reflects all writes.
    pub(crate) fn commit_with_nonce(self, sender: &Address) {
        // Flush storage writes.
        for ((contract, key), value) in self.storage_writes {
            match value {
                Some(v) => self.inner.write(&contract, &key, v),
                None => self.inner.delete(&contract, &key),
            }
        }
        // Flush balance writes.
        for (addr, amount) in self.balance_writes {
            self.inner.set_balance(&addr, amount);
        }
        // Flush nonce writes (excluding sender — we advance below).
        for (addr, nonce) in self.nonce_writes {
            if addr != *sender {
                self.inner.set_nonce(&addr, nonce);
            }
        }
        // Flush legacy code writes (backward compat with InMemoryStateView test double).
        for (addr, code) in self.code_writes {
            self.inner.set_code(&addr, code);
        }
        // Flush thin-pointer + content-store writes (new deploy path, DB-A22/A23).
        //
        // For each contract address with a registered code_hash, resolve the full
        // bytecode from code_store_writes and call inner.set_code(). This keeps
        // InMemoryStateView and MvStateView working unchanged — they store full
        // bytecode by address and serve it via code(). The content-addressed dedup
        // is enforced at the scratch layer (gas savings); the underlying state view
        // sees the resolved bytecode as before.
        //
        // execute_deploy always stores bytecode in code_store_writes (for both first
        // and later deployers), so the lookup here always succeeds for any address
        // that was deployed in this transaction.
        //
        // LOCKSTEP: block_exec.rs `apply_one_write` (StateKey::Code branch) performs
        // the same code_hash→bytecode resolution for the node-level WorldState path.
        // If the thin-pointer encoding changes here, update block_exec.rs too.
        for (addr, hash) in &self.code_hash_writes {
            if let Some(bytes) = self.code_store_writes.get(hash) {
                self.inner.set_code(addr, bytes.clone());
            }
            // If bytecode is not in code_store_writes, the deploy was not completed
            // in this transaction (should not happen — execute_deploy always stores it).
        }
        // Advance sender nonce.
        let current = self.inner.nonce(sender);
        // saturating_add: nonce at u64::MAX stays there rather than wrapping.
        self.inner.set_nonce(sender, current.saturating_add(1));
    }

    /// Discard all scratch writes and return a mutable reference to `inner`.
    ///
    /// Called on failure. No writes reach canonical state.
    pub(crate) fn discard(self) -> &'a mut S {
        // Drop all scratch buffers — inner is unchanged.
        self.inner
    }
}

impl<S: ContractStateView> ContractStateView for ScratchState<'_, S> {
    fn read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        match self.storage_writes.get(&(*contract, key.to_vec())) {
            Some(Some(v)) => Some(v.clone()),       // written this tx
            Some(None) => None,                     // deleted this tx
            None => self.inner.read(contract, key), // fall through
        }
    }

    fn write(&mut self, contract: &Address, key: &[u8], value: Vec<u8>) {
        self.storage_writes
            .insert((*contract, key.to_vec()), Some(value));
    }

    fn delete(&mut self, contract: &Address, key: &[u8]) {
        self.storage_writes.insert((*contract, key.to_vec()), None);
    }

    fn exists(&self, contract: &Address, key: &[u8]) -> bool {
        match self.storage_writes.get(&(*contract, key.to_vec())) {
            Some(Some(_)) => true,
            Some(None) => false,
            None => self.inner.exists(contract, key),
        }
    }

    fn balance(&self, addr: &Address) -> Amount {
        self.balance_writes
            .get(addr)
            .copied()
            .unwrap_or_else(|| self.inner.balance(addr))
    }

    fn set_balance(&mut self, addr: &Address, amount: Amount) {
        self.balance_writes.insert(*addr, amount);
    }

    fn nonce(&self, addr: &Address) -> u64 {
        self.nonce_writes
            .get(addr)
            .copied()
            .unwrap_or_else(|| self.inner.nonce(addr))
    }

    fn set_nonce(&mut self, addr: &Address, nonce: u64) {
        self.nonce_writes.insert(*addr, nonce);
    }

    fn code(&self, addr: &Address) -> Option<Vec<u8>> {
        // Try thin-pointer path first (new deploy path, DB-A22/A23).
        if let Some(hash) = self.code_hash_writes.get(addr) {
            if let Some(bytes) = self.code_store_writes.get(hash) {
                return Some(bytes.clone());
            }
        }
        // Fall back to legacy code_writes map, then inner.
        self.code_writes
            .get(addr)
            .cloned()
            .or_else(|| self.inner.code(addr))
    }

    fn set_code(&mut self, addr: &Address, code: Vec<u8>) {
        self.code_writes.insert(*addr, code);
    }

    fn has_code_hash(&self, hash: &Hash) -> bool {
        // Check scratch content store first (deployed this tx).
        if self.code_store_writes.contains_key(hash) {
            return true;
        }
        // Fall through to inner (deployed in prior committed txs).
        self.inner.has_code_hash(hash)
    }
}

// ── CanonicalStateRead ────────────────────────────────────────────────────────

/// Minimal read-only view of canonical (committed) state.
///
/// Used by [`ScratchSnapshot`] to fall through to committed state for keys
/// not written in the current transaction (M4 fix). The trait is intentionally
/// narrow — only the operations needed by the WASM host are included.
///
/// # `'static` requirement
///
/// Implementations must be `'static` so that `ScratchSnapshot` (which holds a
/// `Box<dyn CanonicalStateRead + 'static>`) satisfies the wasmtime linker's
/// `'static` bound on `HostState<ScratchSnapshot>`.
///
/// # `clone_box` requirement
///
/// Required by `ScratchSnapshot::clone()` so that the boxed canonical reader
/// can be duplicated when the snapshot is cloned for a callee's `HostState`
/// in cross-contract calls (P3·Step 21 subtask_02). The blanket impl below
/// provides this automatically for all `Clone + ContractStateView + 'static`.
pub(crate) trait CanonicalStateRead: 'static {
    /// Read a storage slot from canonical state.
    fn canonical_read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>>;

    /// Check whether a storage slot exists in canonical state.
    fn canonical_exists(&self, contract: &Address, key: &[u8]) -> bool;

    /// Read the native LEM balance of an account from canonical state.
    fn canonical_balance(&self, addr: &Address) -> Amount;

    /// Read deployed bytecode for a contract address from canonical state.
    ///
    /// Used by `ScratchSnapshot::code()` to fall through to committed state
    /// for contracts deployed in prior transactions (P3·Step 21 subtask_02).
    fn canonical_code(&self, addr: &Address) -> Option<Vec<u8>>;

    /// Clone this reader into a new `Box<dyn CanonicalStateRead + 'static>`.
    ///
    /// Required by `ScratchSnapshot::clone()` — `Box<dyn Trait>` is not
    /// `Clone` by default; this method provides the escape hatch.
    fn clone_box(&self) -> Box<dyn CanonicalStateRead + 'static>;
}

/// Blanket implementation: any `ContractStateView + Clone + 'static` can serve
/// as a canonical reader. The clone is taken at snapshot time so the reader is
/// owned and `'static`.
impl<S: ContractStateView + Clone + 'static> CanonicalStateRead for S {
    fn canonical_read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        self.read(contract, key)
    }

    fn canonical_exists(&self, contract: &Address, key: &[u8]) -> bool {
        self.exists(contract, key)
    }

    fn canonical_balance(&self, addr: &Address) -> Amount {
        self.balance(addr)
    }

    fn canonical_code(&self, addr: &Address) -> Option<Vec<u8>> {
        self.code(addr)
    }

    fn clone_box(&self) -> Box<dyn CanonicalStateRead + 'static> {
        Box::new(self.clone())
    }
}

// ── ScratchSnapshot ───────────────────────────────────────────────────────────

/// Owned snapshot of scratch state for passing into [`HostState`].
///
/// Used by `execute_call` to give the host an owned `'static` state view
/// without requiring `ScratchState` to be `'static`. After execution, writes
/// are merged back into the original scratch via `merge_snapshot`.
///
/// ## M4 fix — read-through to canonical state
///
/// `ScratchSnapshot` now carries a `Box<dyn CanonicalStateRead + 'static>`
/// that is a clone of the inner state taken at snapshot time. The read path
/// falls through in priority order:
///
/// 1. Current-tx writes (`storage` map) — highest priority.
/// 2. Current-tx deletes (`storage_deletes` set) — tombstone: return `None`.
/// 3. Canonical state (`canonical`) — committed state from prior txs.
///
/// This matches `ScratchState::read` semantics and closes M4.
///
/// For B4 (single-frame, no cross-contract calls), this is semantically
/// correct. Phase 3 will replace this with a proper multi-frame state stack.
pub(crate) struct ScratchSnapshot {
    storage: BTreeMap<(Address, Vec<u8>), Vec<u8>>,
    /// Tombstone set: keys deleted in the current transaction.
    ///
    /// A key in `storage_deletes` shadows any canonical value — `read` returns
    /// `None` even if the canonical state has a value for that key.
    storage_deletes: BTreeSet<(Address, Vec<u8>)>,
    balances: BTreeMap<Address, Amount>,
    nonces: BTreeMap<Address, u64>,
    code: BTreeMap<Address, Vec<u8>>,
    /// Thin pointer: `contract_address → code_hash` (DB-A22).
    code_hashes: BTreeMap<Address, Hash>,
    /// Content-addressed bytecode store: `code_hash → bytecode` (DB-A23).
    code_store: BTreeMap<Hash, Vec<u8>>,
    /// Read-through to canonical (committed) state for keys not in this snapshot.
    ///
    /// Cloned from `ScratchState::inner` at snapshot time. Satisfies `'static`
    /// because `S: Clone + 'static` is required by `ScratchState::snapshot`.
    ///
    /// M4 fix: closes the gap where WASM `storage_read` returned `None` for
    /// keys written by prior committed transactions.
    canonical: Box<dyn CanonicalStateRead + 'static>,
}

impl Clone for ScratchSnapshot {
    /// Clone this snapshot for use as a callee's state in cross-contract calls.
    ///
    /// The `canonical` field is a `Box<dyn CanonicalStateRead>` — not `Clone`
    /// by default. We use `clone_box()` (P3·Step 21 subtask_02) to duplicate it.
    /// All other fields are standard `BTreeMap`/`BTreeSet` clones.
    fn clone(&self) -> Self {
        Self {
            storage: self.storage.clone(),
            storage_deletes: self.storage_deletes.clone(),
            balances: self.balances.clone(),
            nonces: self.nonces.clone(),
            code: self.code.clone(),
            code_hashes: self.code_hashes.clone(),
            code_store: self.code_store.clone(),
            canonical: self.canonical.clone_box(),
        }
    }
}

impl ContractStateView for ScratchSnapshot {
    /// Read a storage slot from this snapshot with canonical fall-through.
    ///
    /// ## M4 fix — read priority (matches `ScratchState::read`)
    ///
    /// 1. Key in `storage` (written this tx) → return that value.
    /// 2. Key in `storage_deletes` (deleted this tx) → return `None` (tombstone).
    /// 3. Fall through to `canonical` (committed state from prior txs).
    fn read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        let k = (*contract, key.to_vec());
        // Priority 1: current-tx write.
        if let Some(v) = self.storage.get(&k) {
            return Some(v.clone());
        }
        // Priority 2: current-tx delete (tombstone).
        if self.storage_deletes.contains(&k) {
            return None;
        }
        // Priority 3: fall through to canonical state (M4 fix).
        self.canonical.canonical_read(contract, key)
    }

    fn write(&mut self, contract: &Address, key: &[u8], value: Vec<u8>) {
        let k = (*contract, key.to_vec());
        // A write un-deletes the key: remove from tombstone set.
        self.storage_deletes.remove(&k);
        self.storage.insert(k, value);
    }

    fn delete(&mut self, contract: &Address, key: &[u8]) {
        let k = (*contract, key.to_vec());
        self.storage.remove(&k);
        self.storage_deletes.insert(k);
    }

    fn exists(&self, contract: &Address, key: &[u8]) -> bool {
        let k = (*contract, key.to_vec());
        // Current-tx write → exists.
        if self.storage.contains_key(&k) {
            return true;
        }
        // Current-tx delete (tombstone) → does not exist.
        if self.storage_deletes.contains(&k) {
            return false;
        }
        // Fall through to canonical state (M4 fix).
        self.canonical.canonical_exists(contract, key)
    }

    fn balance(&self, addr: &Address) -> Amount {
        // Current-tx balance write takes priority; fall through to canonical (M4 fix).
        self.balances
            .get(addr)
            .copied()
            .unwrap_or_else(|| self.canonical.canonical_balance(addr))
    }

    fn set_balance(&mut self, addr: &Address, amount: Amount) {
        self.balances.insert(*addr, amount);
    }

    fn nonce(&self, addr: &Address) -> u64 {
        self.nonces.get(addr).copied().unwrap_or(0)
    }

    fn set_nonce(&mut self, addr: &Address, nonce: u64) {
        self.nonces.insert(*addr, nonce);
    }

    fn code(&self, addr: &Address) -> Option<Vec<u8>> {
        // Try thin-pointer path first (new deploy path, DB-A22/A23).
        if let Some(hash) = self.code_hashes.get(addr) {
            if let Some(bytes) = self.code_store.get(hash) {
                return Some(bytes.clone());
            }
        }
        // Fall back to legacy code map (backward compat — current-tx writes).
        if let Some(bytes) = self.code.get(addr) {
            return Some(bytes.clone());
        }
        // Fall through to canonical state (M4 fix for code reads).
        //
        // Contracts deployed in prior committed transactions have their bytecode
        // in the canonical state, not in the current-tx scratch maps. Without
        // this fall-through, `call_contract` cannot load callee bytecode for
        // contracts deployed before the current transaction (P3·Step 21 subtask_02).
        self.canonical.canonical_code(addr)
    }

    fn set_code(&mut self, addr: &Address, code: Vec<u8>) {
        self.code.insert(*addr, code);
    }

    fn has_code_hash(&self, hash: &Hash) -> bool {
        // Check the content store snapshot (deployed this tx).
        self.code_store.contains_key(hash)
        // NOTE: has_code_hash on ScratchSnapshot only sees writes from the current tx.
        // This is acceptable: ScratchSnapshot is only used by execute_call (WASM host),
        // not by execute_deploy (which uses ScratchState directly).
    }

    /// Merge writes from this snapshot into `target` (P3·Step 21 subtask_02).
    ///
    /// Delegates to [`ScratchSnapshot::merge_into`] which applies storage writes,
    /// deletes, balance writes, nonce writes, and code writes to `target`.
    fn merge_writes_into<T: ContractStateView>(&self, target: &mut T) {
        self.merge_into(target);
    }
}

impl ScratchSnapshot {
    /// Merge this snapshot's writes into a target `ContractStateView`.
    ///
    /// Used by the `call_contract` linker closure (P3·Step 21 subtask_02) to
    /// propagate callee state writes back into the caller's state after a
    /// successful cross-contract call.
    ///
    /// Applies in order: storage writes, storage deletes (tombstones), balance
    /// writes, nonce writes, code writes. The `canonical` field is read-only
    /// and is NOT merged (it represents committed state, not new writes).
    pub(crate) fn merge_into<S: ContractStateView>(&self, target: &mut S) {
        // Storage writes (highest priority — overwrite any existing value).
        for ((contract, key), value) in &self.storage {
            target.write(contract, key, value.clone());
        }
        // Storage deletes (tombstones — remove from target).
        for (contract, key) in &self.storage_deletes {
            target.delete(contract, key);
        }
        // Balance writes.
        for (addr, amount) in &self.balances {
            target.set_balance(addr, *amount);
        }
        // Nonce writes.
        //
        // NOTE: Nonce merge is intentional but scoped. No WASM-reachable host fn mutates
        // nonces today (nonces are tx-level, incremented by executor.rs settle(), not by
        // host fns). When nested-deploy / CREATE2 host fn ships, revisit whether callee
        // nonce changes should propagate. Tracked: living-notes Technical Debt VM-merge-nonce-1.
        for (addr, nonce) in &self.nonces {
            target.set_nonce(addr, *nonce);
        }
        // Code writes (legacy path).
        for (addr, code) in &self.code {
            target.set_code(addr, code.clone());
        }
        // Thin-pointer + content-addressed code writes (DB-A22/A23).
        // set_code handles both the address pointer and the content store.
        // For the thin-pointer path, we write via set_code (which stores by address).
        // The code_hashes and code_store maps are internal to ScratchSnapshot;
        // the target receives the resolved bytecode via set_code.
        for (addr, hash) in &self.code_hashes {
            if let Some(bytes) = self.code_store.get(hash) {
                target.set_code(addr, bytes.clone());
            }
        }
    }
}
