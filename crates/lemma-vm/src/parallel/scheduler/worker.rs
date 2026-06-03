//! # Parallel Worker Loop (08-EXECUTION_SPEC §1.6)
//!
//! [`WorkerCtx`] is the per-worker view of the shared parallel-execution
//! context. Every rayon worker runs [`WorkerCtx::run`]: it speculatively
//! executes pending transactions and drives the strict in-order commit cursor.
//! The commit point is the serialization guarantee — a transaction commits only
//! after its captured reads validate against the (now-stable) committed prefix,
//! so the observable history equals the serial schedule and the output is
//! identical to [`super::SequentialScheduler`].
//!
//! ## Why re-execution at commit is always final
//!
//! Commits advance strictly in `txn_idx` order, so when worker reaches the
//! commit of `idx`, every txn `< idx` is already committed and immutable in
//! [`MvState`]. A re-execution of `idx` therefore reads a stable prefix and
//! produces a deterministic, validating result — exactly what the sequential
//! oracle would compute for `idx`.

use std::sync::{Arc, Mutex};

use lemma_core::transaction::Transaction;

use crate::executor::Executor;
use crate::host::BlockContext;
use crate::parallel::conflict::validate;
use crate::parallel::mvstate::MvState;
use crate::state::ContractStateView;

use super::run_incarnation;
use super::state::{SchedulerState, Task};

/// Shared, immutable context handed to every worker closure.
pub(super) struct WorkerCtx<'a, S: ContractStateView + Send + Sync + 'static> {
    executor: &'a Executor,
    mv: &'a Arc<MvState>,
    base: &'a Arc<S>,
    txs: &'a [Transaction],
    block: &'a BlockContext,
    sched: &'a Mutex<SchedulerState>,
}

impl<'a, S: ContractStateView + Send + Sync + 'static> WorkerCtx<'a, S> {
    /// Bundle the shared references a worker needs.
    pub(super) fn new(
        executor: &'a Executor,
        mv: &'a Arc<MvState>,
        base: &'a Arc<S>,
        txs: &'a [Transaction],
        block: &'a BlockContext,
        sched: &'a Mutex<SchedulerState>,
    ) -> Self {
        Self {
            executor,
            mv,
            base,
            txs,
            block,
            sched,
        }
    }

    /// Worker loop: speculatively execute pending txns and drive in-order
    /// commit until the block is done.
    pub(super) fn run(&self) {
        loop {
            let task = self.locked(|g| g.next_task());
            match task {
                Task::Execute {
                    txn_idx,
                    incarnation,
                } => self.execute(txn_idx, incarnation),
                Task::Idle => {
                    if !self.try_commit_progress() {
                        // No pending execution and no commit to drive right now:
                        // yield so the worker owning the blocking incarnation
                        // can advance the cursor.
                        std::thread::yield_now();
                    }
                }
                Task::Done => return,
            }
        }
    }

    /// Run `f` while holding the scheduler lock (poison-tolerant).
    fn locked<R>(&self, f: impl FnOnce(&mut SchedulerState) -> R) -> R {
        let mut g = self.sched.lock().unwrap_or_else(|p| p.into_inner());
        f(&mut g)
    }

    /// Speculatively execute `txn_idx`@`incarnation` and record the result.
    fn execute(&self, txn_idx: u32, incarnation: u32) {
        let (keys, reads, receipt) = run_incarnation(
            self.executor,
            self.mv,
            self.base,
            &self.txs[txn_idx as usize],
            self.block,
            txn_idx,
            incarnation,
        );
        self.locked(|g| g.record_execution(txn_idx, keys, reads, receipt));
    }

    /// Attempt to claim and drive the next in-order commit.
    ///
    /// Returns `true` if this worker claimed the commit slot. The claim is
    /// atomic — only one worker drives a given commit slot.
    fn try_commit_progress(&self) -> bool {
        let Some(idx) = self.locked(|g| g.claim_commit()) else {
            return false;
        };
        self.commit_or_reexecute(idx);
        true
    }

    /// Validate `idx`; commit it if its reads are stable, else re-execute
    /// against the now-stable committed prefix and commit the fresh result.
    fn commit_or_reexecute(&self, idx: u32) {
        let valid = self.locked(|g| validate(g.reads(idx), self.mv, idx));
        if valid {
            self.locked(|g| g.commit(idx));
            return;
        }
        // Stale: abort (bump incarnation, flag old writes estimate, drop them),
        // re-execute against the committed prefix, then commit the final result.
        let incarnation = self.locked(|g| {
            let old_keys = g.abort(idx);
            self.mv.mark_estimate(idx, &old_keys);
            self.mv.remove_writes(idx, &old_keys);
            g.incarnation(idx)
        });
        self.execute(idx, incarnation);
        self.locked(|g| g.commit(idx));
    }
}
