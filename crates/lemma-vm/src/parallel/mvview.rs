//! # MVCC ↔ Executor Bridge (08-EXECUTION_SPEC §1.1, §1.3)
//!
//! [`MvStateView`] implements [`ContractStateView`] over an [`MvState`] for one
//! transaction index. It is the adapter that lets B4's
//! [`crate::executor::Executor::execute_transaction`] run UNCHANGED against the
//! multi-version store — the single execution path shared by both schedulers
//! (DRY; AGENTS.md §2). Reads resolve through MVCC and are recorded for
//! validation; writes are buffered until the incarnation completes.
//!
//! ## Single-owner interior mutability
//!
//! [`ContractStateView::read`] takes `&self`, so recording reads needs interior
//! mutability ([`RefCell`]). This is sound: each [`MvStateView`] is owned by ONE
//! worker executing ONE transaction at a time — it is never shared across
//! threads. The shared, concurrent part is the [`MvState`] ([`DashMap`]) it
//! borrows.
//!
//! ## Estimate handling (conservative, correct)
//!
//! When a read lands on an estimate-flagged entry (the producer is
//! re-executing), the view returns the committed *base* value and records the
//! read as a base fall-through while remembering the lowest blocking txn in
//! [`MvStateView::min_blocking_txn`]. Once the producer republishes a real
//! value, re-validation re-resolves the key to a concrete version, mismatches
//! the recorded fall-through, and forces a re-execution (08-EXECUTION_SPEC
//! §1.3).
//!
//! `min_blocking_txn` is **computed but not consulted by the v1 scheduler** —
//! commit-time re-execution against the fully-committed prefix is always correct
//! without it. It is reserved for the v1.5 lock-free scheduler's deferred-
//! re-execution optimization (Technical Debt B5-min-blocking in living-notes).

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::sync::Arc;

use lemma_core::{address::Address, amount::Amount};

use crate::parallel::conflict::{CapturedReads, ObservedRead};
use crate::parallel::mvstate::{MvReadResult, MvState, StateKey, StateValue};
use crate::state::ContractStateView;

// ── MvStateView ─────────────────────────────────────────────────────────────

/// A per-transaction MVCC overlay implementing [`ContractStateView`].
///
/// `S` is the committed base state (the slot-0 fall-through). The shared
/// [`MvState`] and base are held via [`Arc`] so the view is `'static` when
/// `S: 'static` — a hard requirement of B4's
/// [`crate::executor::Executor::execute_transaction`] (the WASM store's
/// `func_wrap` closures demand `'static`). This is what lets the single B4
/// execution path run UNCHANGED here (DRY; AGENTS.md §2).
pub struct MvStateView<S: ContractStateView> {
    /// Shared multi-version store (concurrent).
    mv: Arc<MvState>,
    /// Committed base state — fall-through for keys absent below `txn_idx`.
    base: Arc<S>,
    /// The block index of the transaction this view executes.
    txn_idx: u32,
    /// Reads recorded this incarnation (single-owner interior mutability).
    captured: RefCell<CapturedReads>,
    /// Writes buffered this incarnation, sorted by [`StateKey`].
    writes: RefCell<BTreeMap<StateKey, StateValue>>,
    /// Lowest txn index whose estimate this view observed (`None` = none).
    min_blocking_txn: Cell<Option<u32>>,
}

impl<S: ContractStateView> MvStateView<S> {
    /// Create a view for `txn_idx` over `mv` with `base` as the fall-through.
    pub fn new(mv: Arc<MvState>, base: Arc<S>, txn_idx: u32) -> Self {
        Self {
            mv,
            base,
            txn_idx,
            captured: RefCell::new(CapturedReads::new()),
            writes: RefCell::new(BTreeMap::new()),
            min_blocking_txn: Cell::new(None),
        }
    }

    /// Consume the view, returning its buffered writes and captured reads.
    ///
    /// Called after execution: writes are committed to [`MvState`] as this
    /// version's writes; captured reads are stored for later validation.
    pub fn into_parts(self) -> (BTreeMap<StateKey, StateValue>, CapturedReads) {
        (self.writes.into_inner(), self.captured.into_inner())
    }

    /// The lowest blocking txn index observed via an estimate, if any.
    ///
    /// Reserved for the v1.5 lock-free scheduler's deferred-re-execution
    /// optimization; the v1 scheduler does not consult it (commit-time
    /// re-execution against the committed prefix is always correct without it).
    #[allow(dead_code)] // reserved for v1.5 scheduler — see module docs + Tech Debt B5-min-blocking
    pub fn min_blocking_txn(&self) -> Option<u32> {
        self.min_blocking_txn.get()
    }

    /// Record that this incarnation observed a blocking estimate at `txn_idx`.
    fn note_blocking(&self, txn_idx: u32) {
        let updated = match self.min_blocking_txn.get() {
            Some(cur) => cur.min(txn_idx),
            None => txn_idx,
        };
        self.min_blocking_txn.set(Some(updated));
    }

    /// Resolve `key` through MVCC + base, recording the observed read.
    ///
    /// Returns the resolved [`StateValue`] when an MVCC write exists below
    /// `txn_idx`; otherwise returns `None` so the caller applies its
    /// kind-specific base default. On an estimate, falls back to base and notes
    /// the blocking txn.
    fn resolve(&self, key: &StateKey) -> Option<StateValue> {
        // A buffered write from THIS incarnation takes precedence (read-own-write).
        if let Some(v) = self.writes.borrow().get(key) {
            return Some(v.clone());
        }
        match self.mv.read(key, self.txn_idx) {
            MvReadResult::Value { version, value } => {
                self.captured.borrow_mut().record(
                    key.clone(),
                    ObservedRead::Versioned {
                        version,
                        value: value.clone(),
                    },
                );
                Some(value)
            }
            MvReadResult::Estimate { blocking_txn } => {
                self.note_blocking(blocking_txn);
                self.captured
                    .borrow_mut()
                    .record(key.clone(), ObservedRead::BaseFallthrough);
                None
            }
            MvReadResult::NotFound => {
                self.captured
                    .borrow_mut()
                    .record(key.clone(), ObservedRead::BaseFallthrough);
                None
            }
        }
    }

    /// Buffer a write for `key`.
    fn buffer(&self, key: StateKey, value: StateValue) {
        self.writes.borrow_mut().insert(key, value);
    }
}

// ── ContractStateView impl ──────────────────────────────────────────────────

impl<S: ContractStateView> ContractStateView for MvStateView<S> {
    fn read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        let sk = StateKey::Storage {
            contract: *contract,
            key: key.to_vec(),
        };
        match self.resolve(&sk) {
            Some(StateValue::Storage(v)) => v,
            Some(_) => None, // type mismatch is impossible by construction
            None => self.base.read(contract, key),
        }
    }

    fn write(&mut self, contract: &Address, key: &[u8], value: Vec<u8>) {
        self.buffer(
            StateKey::Storage {
                contract: *contract,
                key: key.to_vec(),
            },
            StateValue::Storage(Some(value)),
        );
    }

    fn delete(&mut self, contract: &Address, key: &[u8]) {
        self.buffer(
            StateKey::Storage {
                contract: *contract,
                key: key.to_vec(),
            },
            StateValue::Storage(None),
        );
    }

    fn exists(&self, contract: &Address, key: &[u8]) -> bool {
        let sk = StateKey::Storage {
            contract: *contract,
            key: key.to_vec(),
        };
        match self.resolve(&sk) {
            Some(StateValue::Storage(v)) => v.is_some(),
            Some(_) => false,
            None => self.base.exists(contract, key),
        }
    }

    fn balance(&self, addr: &Address) -> Amount {
        match self.resolve(&StateKey::Balance(*addr)) {
            Some(StateValue::Balance(a)) => a,
            Some(_) => Amount::zero(),
            None => self.base.balance(addr),
        }
    }

    fn set_balance(&mut self, addr: &Address, amount: Amount) {
        self.buffer(StateKey::Balance(*addr), StateValue::Balance(amount));
    }

    fn nonce(&self, addr: &Address) -> u64 {
        match self.resolve(&StateKey::Nonce(*addr)) {
            Some(StateValue::Nonce(n)) => n,
            Some(_) => 0,
            None => self.base.nonce(addr),
        }
    }

    fn set_nonce(&mut self, addr: &Address, nonce: u64) {
        self.buffer(StateKey::Nonce(*addr), StateValue::Nonce(nonce));
    }

    fn code(&self, addr: &Address) -> Option<Vec<u8>> {
        match self.resolve(&StateKey::Code(*addr)) {
            Some(StateValue::Code(c)) => c,
            Some(_) => None,
            None => self.base.code(addr),
        }
    }

    fn set_code(&mut self, addr: &Address, code: Vec<u8>) {
        self.buffer(StateKey::Code(*addr), StateValue::Code(Some(code)));
    }

    fn has_code_hash(&self, hash: &lemma_core::Hash) -> bool {
        // MvStateView tracks code by address (StateKey::Code), not by hash.
        // For the content-addressed dedup check (DB-A23), fall through to the
        // base state which maintains the hash index (InMemoryStateView.code_by_hash
        // or the production WorldState CF_CODE store).
        //
        // NOTE: This does NOT check buffered writes in the current incarnation.
        // A same-block deploy of identical bytecode by a later tx will not see
        // the earlier tx's write until it is committed to base. This is acceptable:
        // the dedup is a gas-savings optimization, not a correctness invariant.
        // Worst case: two txs in the same block both pay first-deployer gas.
        // Intentional-deferred: full same-block dedup requires a CodeHash StateKey
        // variant in MvState (tracked in living-notes Technical Debt).
        self.base.has_code_hash(hash)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
