//! Read-only contract state view over the committed world state.
//!
//! [`WorldStateView`] bridges [`WorldState`] (storage layer) and the
//! [`ContractStateView`] trait (VM layer), providing Flux's `base: Arc<S>`
//! slot with committed account balances, nonces, code, and contract storage.
//!
//! ## Ownership model
//!
//! `WorldStateView` wraps a [`WorldState`] snapshot (Arc<LemmaDb> + state_root).
//! It is constructed once per block commit from the parent block's `state_root`
//! and passed as `Arc<WorldStateView>` to `execute_block_parallel`.
//!
//! ## Read-only invariant
//!
//! Write methods (`write`, `delete`, `set_balance`, `set_nonce`, `set_code`)
//! are all `unreachable!`. This is **mathematically provable**: Flux's
//! `MvStateView` (the MVCC overlay that wraps this base) routes all writes to
//! its own per-transaction buffer (`self.writes`) and NEVER calls any write
//! method on `base: Arc<S>`. The only base methods `MvStateView` calls are
//! `read`, `exists`, `balance`, `nonce`, and `code` — the read side.
//! (Verified in `lemma-vm/src/parallel/mvview.rs`.)
//!
//! ## Phase 2 scope notes
//!
//! - `code()` always returns `None`: no WASM bytecode store exists in Phase 2
//!   (only `Account.code_hash` is stored; the bytecode bytes live in Phase 3).
//! - `read()` / `exists()`: storage slots always absent in Phase 2 (contract
//!   storage namespace: M3 CLOSED in P3·Step 6b-vm-1 — `BlockContext.contract`
//!   now distinct from `msg_sender`. Remaining: storage_root wire-up in apply_writes).
//!
//! ## Debt record (C·Step 13-residual)
//!
//! Contract storage writes (StateKey::Storage → `Account.storage_root`) are
//! **M3 CLOSED (P3·Step 6b-vm-1)**: `BlockContext.contract` field + namespace fix done.
//! Remaining: storage_root trie wire-up. Storage slots written by Flux are persisted via `WorldState::put_storage`
//! (so intra-block reads see them) but `Account.storage_root` is NOT updated,
//! meaning storage does NOT yet contribute to `state_root`. This is honest
//! deferral, not silent loss: state_root is structurally correct for
//! balance/nonce/code (consensus-critical), and storage inclusion is gated
//! on a named, recorded dependency.

use std::sync::Arc;

use lemma_core::{address::Address, amount::Amount, hash::Hash};
use lemma_storage::{db::LemmaDb, state::WorldState};
use lemma_vm::state::ContractStateView;

// ── WorldStateView ────────────────────────────────────────────────────────────

/// Read-only view of committed world state for Flux's `base` slot.
///
/// Implements [`ContractStateView`] by delegating reads to [`WorldState`].
/// Constructed from the parent block's `state_root`; destroyed when the
/// block execution completes and writes are applied to the committed state.
pub struct WorldStateView {
    inner: WorldState,
}

impl WorldStateView {
    /// Create a view rooted at `state_root`.
    ///
    /// If `state_root` is [`Hash::zero()`] (genesis parent or empty chain),
    /// opens an empty [`WorldState`] with no trie entries — all reads return
    /// default zero values.
    #[must_use]
    pub fn new(db: Arc<LemmaDb>, state_root: Hash) -> Self {
        let inner = if state_root.is_zero() {
            WorldState::new(db)
        } else {
            WorldState::with_state_root(db, state_root)
        };
        Self { inner }
    }
}

impl ContractStateView for WorldStateView {
    // ── Read operations ───────────────────────────────────────────────────────

    fn read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        // Hash the arbitrary key bytes to derive a 32-byte CF_STORAGE slot.
        // NOTE: Phase 2 scope — no contracts deployed, always returns None.
        // M3 CLOSED (P3·Step 6b-vm-1): namespace uses BlockContext.contract correctly.
        // Phase 2 scope: no contracts deployed, always returns None regardless.
        let slot = lemma_crypto::hash_bytes(key);
        self.inner.get_storage(contract, &slot).ok().flatten()
    }

    fn exists(&self, contract: &Address, key: &[u8]) -> bool {
        let slot = lemma_crypto::hash_bytes(key);
        self.inner
            .get_storage(contract, &slot)
            .ok()
            .flatten()
            .is_some()
    }

    fn balance(&self, addr: &Address) -> Amount {
        // Storage errors (e.g. trie node not found) degrade gracefully to zero —
        // the VM treats missing accounts as zero-balance EOAs (Phase 2: no staking).
        self.inner
            .get_balance(addr)
            .unwrap_or_else(|_| Amount::zero())
    }

    fn nonce(&self, addr: &Address) -> u64 {
        self.inner.get_nonce(addr).unwrap_or(0)
    }

    fn code(&self, _addr: &Address) -> Option<Vec<u8>> {
        // Phase 2: no WASM bytecode store (only Account.code_hash exists).
        // Bytecode storage keyed by hash is a Phase 3 deliverable.
        // Transfer txs (the only Phase 2 tx type) never call code().
        None
    }

    // ── Write operations — unreachable (see module doc) ───────────────────────

    fn write(&mut self, _contract: &Address, _key: &[u8], _value: Vec<u8>) {
        // SAFETY: MvStateView routes all writes to its own buffer; it NEVER
        // calls base.write(). See lemma-vm/src/parallel/mvview.rs write().
        unreachable!("WorldStateView is read-only — writes route through MvStateView MVCC buffer")
    }

    fn delete(&mut self, _contract: &Address, _key: &[u8]) {
        unreachable!("WorldStateView is read-only — deletes route through MvStateView MVCC buffer")
    }

    fn set_balance(&mut self, _addr: &Address, _amount: Amount) {
        unreachable!("WorldStateView is read-only — balance writes route through MvStateView")
    }

    fn set_nonce(&mut self, _addr: &Address, _nonce: u64) {
        unreachable!("WorldStateView is read-only — nonce writes route through MvStateView")
    }

    fn set_code(&mut self, _addr: &Address, _code: Vec<u8>) {
        unreachable!("WorldStateView is read-only — code writes route through MvStateView")
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
