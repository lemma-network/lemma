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

use lemma_core::{address::Address, amount::Amount};

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
}

impl InMemoryStateView {
    /// Create an empty state view with no storage and zero balances.
    pub fn new() -> Self {
        Self {
            storage: BTreeMap::new(),
            balances: BTreeMap::new(),
        }
    }

    /// Create a state view pre-seeded with the given balances.
    ///
    /// Useful for tests that need accounts with non-zero starting balances.
    ///
    /// # Arguments
    ///
    /// * `balances` — initial balance map (`address → Amount` in Drop).
    pub fn with_balances(balances: BTreeMap<Address, Amount>) -> Self {
        Self {
            storage: BTreeMap::new(),
            balances,
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
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
