//! # Block Schedulers (08-EXECUTION_SPEC §1.6, §1.8, §1.9)
//!
//! Two implementations of the [`BlockScheduler`] trait execute an ordered block
//! of transactions and return receipts (in `txn_idx` order) plus the final
//! committed writes (sorted, deterministic):
//!
//! - [`SequentialScheduler`] — the §1.8 reference oracle: executes
//!   transactions strictly in order, committing each before the next. Obviously
//!   correct.
//! - [`ParallelScheduler`] — the B5-staged correct engine: a mutex-guarded
//!   scheduler-state struct + a rayon worker pool, enforcing the §1.6 in-order
//!   commit rule. Its observable history equals the serial schedule, so its
//!   receipts and final writes are IDENTICAL to the sequential oracle (the
//!   headline property, proptest-verified in `parallel/tests.rs`).
//!
//! ## DRY (AGENTS.md §2)
//!
//! Both schedulers execute each transaction through [`run_incarnation`], which
//! calls B4's [`Executor::execute_transaction`] against an [`MvStateView`].
//! There is exactly one execution path — the equivalence property depends on
//! it.
//!
//! ## v1.5 deferral (Technical Debt)
//!
//! [`ParallelScheduler`] is the "correct but mutex-guarded" v1. The lock-free
//! packed-atomic aptos scheduler (`decrease_validation_idx` CAS + condvar
//! dependency parking) is deferred behind the [`BlockScheduler`] trait — a
//! contention optimization, NOT a serialization change.

mod state;
mod worker;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use lemma_core::transaction::{Transaction, TransactionReceipt};

use crate::executor::Executor;
use crate::host::BlockContext;
use crate::parallel::conflict::CapturedReads;
use crate::parallel::mvstate::{MvState, StateKey, StateValue, Version};
use crate::parallel::mvview::MvStateView;
use crate::state::ContractStateView;

use state::SchedulerState;
use worker::WorkerCtx;

// ── BlockOutput ─────────────────────────────────────────────────────────────

/// The result of executing an ordered block.
///
/// `receipts` are in `txn_idx` order; `writes` is a sorted, deterministic map
/// of the final committed value per [`StateKey`] (AGENTS.md §7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockOutput {
    /// Per-transaction receipts in block order.
    pub receipts: Vec<TransactionReceipt>,
    /// Final committed writes, sorted by [`StateKey`].
    pub writes: BTreeMap<StateKey, StateValue>,
}

// ── BlockScheduler trait ────────────────────────────────────────────────────

/// Strategy for executing an ordered block (08-EXECUTION_SPEC §1.9).
///
/// The trait boundary lets a future lock-free engine drop in without touching
/// [`MvState`] or the executor.
pub trait BlockScheduler {
    /// Execute `txs` in block order against `base`, returning receipts and the
    /// final committed writes.
    ///
    /// `base` is taken by [`Arc`] because it is the committed slot-0
    /// fall-through shared (read-only) by every worker and by every
    /// per-transaction [`MvStateView`]. The `Arc` also makes the view `'static`,
    /// which B4's [`Executor::execute_transaction`] requires (its WASM store's
    /// `func_wrap` closures demand `'static`) — this is what lets both
    /// schedulers reuse the single B4 execution path (DRY; AGENTS.md §2).
    ///
    /// Implementations MUST produce identical output for the same ordered block
    /// (the serialization guarantee, §1.6).
    fn execute_block<S: ContractStateView + Send + Sync + 'static>(
        &self,
        executor: &Executor,
        txs: &[Transaction],
        block: &BlockContext,
        base: Arc<S>,
    ) -> BlockOutput;
}

// ── Shared execution primitive (DRY) ────────────────────────────────────────

/// Execute one incarnation of `tx` at `txn_idx`, publishing writes to `mv`.
///
/// Runs B4's [`Executor::execute_transaction`] against an [`MvStateView`], then
/// commits the buffered writes to `mv` stamped with `(txn_idx, incarnation)`.
/// Returns the written keys, captured reads, and the receipt. This is the
/// SINGLE execution path shared by both schedulers (AGENTS.md §2).
pub(super) fn run_incarnation<S: ContractStateView + 'static>(
    executor: &Executor,
    mv: &Arc<MvState>,
    base: &Arc<S>,
    tx: &Transaction,
    block: &BlockContext,
    txn_idx: u32,
    incarnation: u32,
) -> (Vec<StateKey>, CapturedReads, TransactionReceipt) {
    let mut view = MvStateView::new(Arc::clone(mv), Arc::clone(base), txn_idx);
    let receipt = executor.execute_transaction(tx, block.clone(), &mut view);
    let (writes, reads) = view.into_parts();

    let version = Version::new(txn_idx, incarnation);
    let write_keys: Vec<StateKey> = writes.keys().cloned().collect();
    for (key, value) in writes {
        mv.write(key, version, value);
    }
    (write_keys, reads, receipt)
}

// ── SequentialScheduler (the oracle) ────────────────────────────────────────

/// The §1.8 reference oracle: strict in-order execution, no speculation.
#[derive(Debug, Default, Clone, Copy)]
pub struct SequentialScheduler;

impl SequentialScheduler {
    /// Create a new sequential scheduler.
    pub fn new() -> Self {
        Self
    }
}

impl BlockScheduler for SequentialScheduler {
    fn execute_block<S: ContractStateView + Send + Sync + 'static>(
        &self,
        executor: &Executor,
        txs: &[Transaction],
        block: &BlockContext,
        base: Arc<S>,
    ) -> BlockOutput {
        let mv = Arc::new(MvState::new());
        let mut receipts = Vec::with_capacity(txs.len());
        for (idx, tx) in txs.iter().enumerate() {
            let txn_idx = idx as u32;
            // Each txn reads all committed lower writes (strictly below) and
            // base — exactly the sequential schedule.
            let (_keys, _reads, receipt) =
                run_incarnation(executor, &mv, &base, tx, block, txn_idx, 0);
            receipts.push(receipt);
        }
        BlockOutput {
            receipts,
            writes: mv.snapshot_committed_into_btreemap(),
        }
    }
}

// ── ParallelScheduler ───────────────────────────────────────────────────────

/// The B5-staged correct parallel engine (mutex-guarded + rayon).
#[derive(Debug, Clone, Copy)]
pub struct ParallelScheduler {
    /// Number of worker threads in the pool.
    num_workers: usize,
}

impl ParallelScheduler {
    /// Create a parallel scheduler with `num_workers` worker threads.
    ///
    /// `num_workers` is clamped to at least 1.
    pub fn new(num_workers: usize) -> Self {
        Self {
            num_workers: num_workers.max(1),
        }
    }
}

impl Default for ParallelScheduler {
    fn default() -> Self {
        Self::new(num_cpus_or_default())
    }
}

/// Best-effort worker count: available parallelism, defaulting to 4.
///
/// Shared by [`ParallelScheduler::default`] and
/// [`crate::parallel::FluxConfig::default`] (single source of truth).
pub(super) fn num_cpus_or_default() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

impl BlockScheduler for ParallelScheduler {
    fn execute_block<S: ContractStateView + Send + Sync + 'static>(
        &self,
        executor: &Executor,
        txs: &[Transaction],
        block: &BlockContext,
        base: Arc<S>,
    ) -> BlockOutput {
        // Tiny blocks (or a single worker) run sequentially — identical result,
        // no pool overhead (§1.8 fallback).
        if txs.len() <= 1 || self.num_workers == 1 {
            return SequentialScheduler.execute_block(executor, txs, block, Arc::clone(&base));
        }
        match self.run_parallel(executor, txs, block, &base) {
            Some(output) => output,
            // Pool build failure → deterministic sequential fallback (§1.8,
            // AGENTS §9.3: scheduler errors never halt the node).
            None => SequentialScheduler.execute_block(executor, txs, block, base),
        }
    }
}

impl ParallelScheduler {
    /// Run the worker pool; returns `None` if the pool cannot be built.
    fn run_parallel<S: ContractStateView + Send + Sync + 'static>(
        &self,
        executor: &Executor,
        txs: &[Transaction],
        block: &BlockContext,
        base: &Arc<S>,
    ) -> Option<BlockOutput> {
        let num_txns = txs.len() as u32;
        let mv = Arc::new(MvState::new());
        let sched = Mutex::new(SchedulerState::new(num_txns));

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(self.num_workers)
            .build()
            .ok()?;

        let ctx = WorkerCtx::new(executor, &mv, base, txs, block, &sched);

        pool.install(|| {
            rayon::scope(|s| {
                for _ in 0..self.num_workers {
                    s.spawn(|_| ctx.run());
                }
            });
        });

        let receipts = collect_receipts(&sched, txs);
        Some(BlockOutput {
            receipts,
            writes: mv.snapshot_committed_into_btreemap(),
        })
    }
}

/// Drain the per-txn receipts from the scheduler in block order.
///
/// Every committed transaction has a recorded receipt; the `unwrap_or_else`
/// fallback is a defensive failed receipt that can never fire in practice but
/// guarantees the settlement path never panics (Sui-stall lesson, AGENTS §9.3).
fn collect_receipts(sched: &Mutex<SchedulerState>, txs: &[Transaction]) -> Vec<TransactionReceipt> {
    let mut guard = sched.lock().unwrap_or_else(|p| p.into_inner());
    txs.iter()
        .enumerate()
        .map(|(idx, tx)| {
            guard
                .take_receipt(idx as u32)
                .unwrap_or_else(|| TransactionReceipt::new(tx.hash, false, 0, vec![]))
        })
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
