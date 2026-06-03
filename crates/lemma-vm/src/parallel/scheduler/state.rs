//! # Shared Scheduler State (08-EXECUTION_SPEC §1.6)
//!
//! [`SchedulerState`] is the mutex-guarded coordination structure for the
//! parallel engine: it tracks the next transaction to dispatch for execution,
//! per-transaction incarnation counts, whether each transaction has produced a
//! speculative result, and the in-order commit cursor. Workers pull [`Task`]s
//! from it and report outcomes back.
//!
//! This is the "correct but mutex-guarded" v1 (B5-staged scope): the lock-free
//! packed-atomic aptos scheduler is deferred to v1.5 behind the
//! [`crate::parallel::scheduler::BlockScheduler`] trait. The serialization
//! guarantee (commit strictly in `txn_idx` order) is identical either way.

use lemma_core::transaction::TransactionReceipt;

use crate::parallel::conflict::CapturedReads;
use crate::parallel::mvstate::StateKey;

// ── TxnState ────────────────────────────────────────────────────────────────

/// Per-transaction speculative bookkeeping.
#[derive(Debug, Default)]
pub(crate) struct TxnState {
    /// Current incarnation (0 = first execution).
    pub incarnation: u32,
    /// `true` once this incarnation has executed and published writes.
    pub executed: bool,
    /// Keys written by the latest executed incarnation (for estimate/remove).
    pub write_keys: Vec<StateKey>,
    /// Reads captured by the latest executed incarnation.
    pub reads: CapturedReads,
    /// Receipt produced by the latest executed incarnation.
    pub receipt: Option<TransactionReceipt>,
}

// ── Task ────────────────────────────────────────────────────────────────────

/// A unit of work handed to a worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Task {
    /// Execute (or re-execute) transaction `txn_idx` at `incarnation`.
    Execute {
        /// Block index of the transaction to execute.
        txn_idx: u32,
        /// Incarnation to stamp the writes with.
        incarnation: u32,
    },
    /// No work available right now, but the block is not finished.
    Idle,
    /// All transactions are committed — workers should exit.
    Done,
}

// ── SchedulerState ──────────────────────────────────────────────────────────

/// Mutex-guarded scheduler coordination state.
pub(crate) struct SchedulerState {
    /// Number of transactions in the block.
    num_txns: u32,
    /// Next transaction index to dispatch for a first execution.
    next_to_execute: u32,
    /// In-order commit cursor: all txns `< commit_idx` are committed.
    commit_idx: u32,
    /// `true` while one worker holds the exclusive right to drive the commit of
    /// `commit_idx` (prevents two workers committing the same slot).
    commit_in_flight: bool,
    /// Per-transaction state, indexed by `txn_idx`.
    txns: Vec<TxnState>,
}

impl SchedulerState {
    /// Create scheduler state for a block of `num_txns` transactions.
    pub(crate) fn new(num_txns: u32) -> Self {
        let txns = (0..num_txns).map(|_| TxnState::default()).collect();
        Self {
            num_txns,
            next_to_execute: 0,
            commit_idx: 0,
            commit_in_flight: false,
            txns,
        }
    }

    /// Atomically claim the right to drive the commit of `commit_idx`.
    ///
    /// Returns `Some(idx)` to exactly one worker when the next-to-commit
    /// transaction has an executed result and no commit is already in flight;
    /// returns `None` otherwise. The claimant MUST later call
    /// [`SchedulerState::commit`] (which clears the in-flight flag).
    pub(crate) fn claim_commit(&mut self) -> Option<u32> {
        if self.is_done() || self.commit_in_flight {
            return None;
        }
        let idx = self.commit_idx;
        if !self.txns[idx as usize].executed {
            return None;
        }
        self.commit_in_flight = true;
        Some(idx)
    }

    /// `true` when every transaction has been committed.
    pub(crate) fn is_done(&self) -> bool {
        self.commit_idx >= self.num_txns
    }

    /// Pick the next task: dispatch a first execution if one is pending,
    /// otherwise idle (the committer thread drives commit/re-execution).
    pub(crate) fn next_task(&mut self) -> Task {
        if self.is_done() {
            return Task::Done;
        }
        if self.next_to_execute < self.num_txns {
            let txn_idx = self.next_to_execute;
            self.next_to_execute += 1;
            let incarnation = self.txns[txn_idx as usize].incarnation;
            return Task::Execute {
                txn_idx,
                incarnation,
            };
        }
        Task::Idle
    }

    /// Record the result of executing `txn_idx`'s incarnation.
    pub(crate) fn record_execution(
        &mut self,
        txn_idx: u32,
        write_keys: Vec<StateKey>,
        reads: CapturedReads,
        receipt: TransactionReceipt,
    ) {
        let st = &mut self.txns[txn_idx as usize];
        st.executed = true;
        st.write_keys = write_keys;
        st.reads = reads;
        st.receipt = Some(receipt);
    }

    /// Take the receipt of `txn_idx`'s latest executed incarnation.
    pub(crate) fn take_receipt(&mut self, txn_idx: u32) -> Option<TransactionReceipt> {
        self.txns[txn_idx as usize].receipt.take()
    }

    /// Current incarnation of `txn_idx`.
    pub(crate) fn incarnation(&self, txn_idx: u32) -> u32 {
        self.txns[txn_idx as usize].incarnation
    }

    /// Captured reads of `txn_idx`'s latest executed incarnation.
    pub(crate) fn reads(&self, txn_idx: u32) -> &CapturedReads {
        &self.txns[txn_idx as usize].reads
    }

    /// Advance the commit cursor past `txn_idx` (must equal `commit_idx`).
    ///
    /// Clears the in-flight commit claim.
    pub(crate) fn commit(&mut self, txn_idx: u32) {
        debug_assert_eq!(txn_idx, self.commit_idx);
        self.commit_idx += 1;
        self.commit_in_flight = false;
    }

    /// Abort `txn_idx`: bump its incarnation and clear its executed flag so it
    /// is re-dispatched. Returns the previous write keys to be marked estimate.
    pub(crate) fn abort(&mut self, txn_idx: u32) -> Vec<StateKey> {
        let st = &mut self.txns[txn_idx as usize];
        st.incarnation += 1;
        st.executed = false;
        std::mem::take(&mut st.write_keys)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
