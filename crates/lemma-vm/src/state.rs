//! # Contract State View (08-EXECUTION_SPEC §2.3)
//!
//! Defines the [`ContractStateView`] trait — the abstraction over contract
//! storage that host functions read and write. The production implementation
//! (B5 `MvState`) will implement this trait; B3 ships [`InMemoryStateView`]
//! for unit testing.
//!
//! ## Determinism
//!
//! All maps use [`BTreeMap`] — deterministic iteration order is required by
//! the consensus model (AGENTS.md §7.1). Never use `HashMap` here.

use std::collections::BTreeMap;

use lemma_core::{address::Address, amount::Amount, hash::Hash};

// ── ContractStateView ─────────────────────────────────────────────────────────

/// Abstraction over contract storage state.
///
/// B3 owns this trait; B5 `MvState` will provide the production implementation.
/// [`InMemoryStateView`] is the in-process test double.
///
/// # Determinism
///
/// Implementations MUST be deterministic: same sequence of reads/writes/deletes
/// on the same initial state MUST produce the same final state on every node
/// (AGENTS.md §7.1).
pub trait ContractStateView {
    /// Read a storage slot.
    ///
    /// # Arguments
    ///
    /// * `contract` — the contract whose storage is being read.
    /// * `key` — the storage key (arbitrary bytes).
    ///
    /// # Returns
    ///
    /// `Some(value)` if the slot exists, `None` if absent.
    fn read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>>;

    /// Write a storage slot (create or update).
    ///
    /// # Arguments
    ///
    /// * `contract` — the contract whose storage is being written.
    /// * `key` — the storage key.
    /// * `value` — the value to store.
    fn write(&mut self, contract: &Address, key: &[u8], value: Vec<u8>);

    /// Delete a storage slot.
    ///
    /// No-op if the slot is absent — callers do not need to check existence first.
    ///
    /// # Arguments
    ///
    /// * `contract` — the contract whose storage is being modified.
    /// * `key` — the storage key to remove.
    fn delete(&mut self, contract: &Address, key: &[u8]);

    /// Check whether a storage slot exists.
    ///
    /// Avoids a clone on read when only existence is needed.
    ///
    /// # Arguments
    ///
    /// * `contract` — the contract whose storage is being queried.
    /// * `key` — the storage key to check.
    ///
    /// # Returns
    ///
    /// `true` if the slot exists, `false` otherwise.
    fn exists(&self, contract: &Address, key: &[u8]) -> bool;

    /// Read the native LEM balance of an account (in Drop).
    ///
    /// # Arguments
    ///
    /// * `addr` — the account address.
    ///
    /// # Returns
    ///
    /// The balance in Drop. Returns [`Amount::zero()`] if the account has no
    /// recorded balance (new accounts start at zero).
    fn balance(&self, addr: &Address) -> Amount;

    /// Write the native LEM balance of an account (in Drop).
    ///
    /// Used by `transfer` to apply the debit/credit immediately (CEI pattern —
    /// checks-effects-interactions: balance is updated before any further calls).
    ///
    /// # Arguments
    ///
    /// * `addr` — the account address.
    /// * `amount` — the new balance in Drop.
    fn set_balance(&mut self, addr: &Address, amount: Amount);

    /// Read the transaction nonce of an account.
    ///
    /// The nonce is incremented after every executed transaction (including
    /// failed ones) to prevent replay attacks and to derive deterministic
    /// contract addresses on deploy (08-EXECUTION_SPEC §5).
    ///
    /// # Arguments
    ///
    /// * `addr` — the account address.
    ///
    /// # Returns
    ///
    /// The current nonce. Returns `0` for accounts that have never sent a
    /// transaction (new accounts start at nonce 0).
    fn nonce(&self, addr: &Address) -> u64;

    /// Set the transaction nonce of an account.
    ///
    /// Called by the executor after every transaction (success or failure) to
    /// advance the nonce and prevent replay (08-EXECUTION_SPEC §5).
    ///
    /// # Arguments
    ///
    /// * `addr` — the account address.
    /// * `nonce` — the new nonce value.
    fn set_nonce(&mut self, addr: &Address, nonce: u64);

    /// Read deployed bytecode for a contract address.
    ///
    /// # Arguments
    ///
    /// * `addr` — the contract address.
    ///
    /// # Returns
    ///
    /// `Some(bytecode)` if a contract is deployed at `addr`, `None` if the
    /// address is an EOA or has never been deployed to.
    fn code(&self, addr: &Address) -> Option<Vec<u8>>;

    /// Store deployed bytecode at a contract address.
    ///
    /// Called by the executor's deploy path after successful compilation and
    /// address derivation (08-EXECUTION_SPEC §5, B4).
    ///
    /// # Arguments
    ///
    /// * `addr` — the contract address (derived via `Address::from_deployer`).
    /// * `code` — the compiled WASM bytecode to store.
    fn set_code(&mut self, addr: &Address, code: Vec<u8>);

    /// Check whether bytecode with the given content hash is already stored.
    ///
    /// Used by the deploy path for content-addressed dedup (DB-A23): the first
    /// deployer of a given bytecode pays storage gas; later deployers of identical
    /// bytecode pay only the base pointer-write cost.
    ///
    /// # Arguments
    ///
    /// * `hash` — the Blake3 hash of the bytecode to check.
    ///
    /// # Returns
    ///
    /// `true` if bytecode with this hash is already stored (in committed state
    /// or in the current transaction's scratch), `false` otherwise.
    fn has_code_hash(&self, hash: &Hash) -> bool;

    /// Merge writes from this state view into `target`.
    ///
    /// Used by the `call_contract` host function (P3·Step 21 subtask_02) to
    /// propagate callee state writes back into the caller's state after a
    /// successful cross-contract call.
    ///
    /// ## Default implementation
    ///
    /// The default impl is a no-op — suitable for state views that do not
    /// track writes separately (e.g. [`InMemoryStateView`] in unit tests).
    /// [`crate::executor::ScratchSnapshot`] overrides this to apply its
    /// write/delete/balance/nonce/code maps to `target`.
    ///
    /// # Arguments
    ///
    /// * `target` — the state view to merge writes into.
    fn merge_writes_into<T: ContractStateView>(&self, _target: &mut T) {
        // Default: no-op. Override in ScratchSnapshot for production merge.
    }
}

// ── InMemoryStateView ─────────────────────────────────────────────────────────

/// In-memory [`BTreeMap`]-backed state view for unit testing.
///
/// Production code uses B5's `MvState` (multi-version concurrency control).
/// This implementation is intentionally simple — correctness over performance.
///
/// ## Determinism
///
/// Uses [`BTreeMap`] throughout — iteration order is deterministic and sorted
/// (AGENTS.md §7.1). Never use `HashMap` in state implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InMemoryStateView {
    /// Contract storage: `(contract_address, key) → value`.
    storage: BTreeMap<(Address, Vec<u8>), Vec<u8>>,
    /// Account balances in Drop.
    balances: BTreeMap<Address, Amount>,
    /// Account nonces — incremented after every executed transaction.
    nonces: BTreeMap<Address, u64>,
    /// Deployed contract bytecode: `contract_address → WASM bytes`.
    code: BTreeMap<Address, Vec<u8>>,
    /// Content-addressed bytecode store: `code_hash → WASM bytes` (DB-A23).
    ///
    /// Populated by `set_code` (which also inserts into `code` by address).
    /// Used by `has_code_hash` to implement cross-transaction dedup checks.
    code_by_hash: BTreeMap<Hash, Vec<u8>>,
}

impl InMemoryStateView {
    /// Create an empty state view with no storage, zero balances, and no code.
    pub fn new() -> Self {
        Self {
            storage: BTreeMap::new(),
            balances: BTreeMap::new(),
            nonces: BTreeMap::new(),
            code: BTreeMap::new(),
            code_by_hash: BTreeMap::new(),
        }
    }

    /// Create a state view pre-seeded with the given balances.
    ///
    /// Useful for tests that need accounts with non-zero starting balances.
    /// Nonces and code start empty.
    ///
    /// # Arguments
    ///
    /// * `balances` — initial balance map (`address → Amount` in Drop).
    pub fn with_balances(balances: BTreeMap<Address, Amount>) -> Self {
        Self {
            storage: BTreeMap::new(),
            balances,
            nonces: BTreeMap::new(),
            code: BTreeMap::new(),
            code_by_hash: BTreeMap::new(),
        }
    }
}

impl Default for InMemoryStateView {
    fn default() -> Self {
        Self::new()
    }
}

impl ContractStateView for InMemoryStateView {
    fn read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        self.storage.get(&(*contract, key.to_vec())).cloned()
    }

    fn write(&mut self, contract: &Address, key: &[u8], value: Vec<u8>) {
        self.storage.insert((*contract, key.to_vec()), value);
    }

    fn delete(&mut self, contract: &Address, key: &[u8]) {
        self.storage.remove(&(*contract, key.to_vec()));
    }

    fn exists(&self, contract: &Address, key: &[u8]) -> bool {
        self.storage.contains_key(&(*contract, key.to_vec()))
    }

    fn balance(&self, addr: &Address) -> Amount {
        self.balances
            .get(addr)
            .copied()
            .unwrap_or_else(Amount::zero)
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
        self.code.get(addr).cloned()
    }

    fn set_code(&mut self, addr: &Address, code: Vec<u8>) {
        // Also index by content hash for has_code_hash() dedup checks (DB-A23).
        // lemma_crypto::hash_bytes is the canonical Blake3 primitive (AGENTS §2.2).
        let hash = lemma_crypto::hash_bytes(&code);
        self.code_by_hash.insert(hash, code.clone());
        self.code.insert(*addr, code);
    }

    fn has_code_hash(&self, hash: &Hash) -> bool {
        self.code_by_hash.contains_key(hash)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
