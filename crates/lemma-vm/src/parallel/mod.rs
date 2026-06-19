//! # Flux: Parallel Execution (Block-STM model) — B5
//!
//! Flux executes an ordered block of transactions optimistically in parallel
//! while guaranteeing the result is byte-for-byte identical to a strict
//! sequential execution of the same block (08-EXECUTION_SPEC §1, §6). It adapts
//! the Block-STM design (aptos-core, Apache-2.0) to LemmaVM.
//!
//! ## Headline property (non-negotiable, AGENTS.md §7.1)
//!
//! ```text
//! parallel result == sequential result
//! ```
//!
//! For the same ordered block, [`ParallelScheduler`] and [`SequentialScheduler`]
//! produce identical receipts (per `txn_idx`) AND identical final writes. This
//! is verified by the proptest oracle in `tests.rs`.
//!
//! ## Module map
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`mvstate`]  | [`MvState`] multi-version store + [`StateKey`]/[`StateValue`] |
//! | [`conflict`] | [`conflict::CapturedReads`] + [`conflict::validate`] |
//! | [`mvview`]   | [`mvview::MvStateView`]: MVCC ↔ B4 executor bridge |
//! | [`scheduler`]| [`BlockScheduler`] trait + sequential/parallel engines |
//!
//! ## Determinism (AGENTS.md §7.1)
//!
//! [`MvState`] is backed by `DashMap` (the sole concurrency-container
//! exception) but its iteration order NEVER escapes: final writes are collected
//! into a sorted [`std::collections::BTreeMap`] keyed by [`StateKey`] before any
//! hashing or comparison. Everything consensus-visible is keyed by `txn_idx`;
//! no `SystemTime`, `rand`, or thread schedule influences any result.
//!
//! ## B5-staged scope
//!
//! [`ParallelScheduler`] is the "correct but mutex-guarded" v1. The lock-free
//! packed-atomic aptos scheduler is deferred to v1.5 behind the
//! [`BlockScheduler`] trait (Technical Debt; a contention optimization, not a
//! serialization change).

pub mod conflict;
pub mod mvstate;
pub mod mvview;
pub mod scheduler;

use std::sync::Arc;

use lemma_core::transaction::Transaction;

use crate::executor::Executor;
use crate::host::BlockContext;
use crate::state::ContractStateView;

pub use mvstate::{MvReadResult, MvState, StateKey, StateValue, Version};
pub use scheduler::{BlockOutput, BlockScheduler, ParallelScheduler, SequentialScheduler};

// ── FluxConfig ──────────────────────────────────────────────────────────────

/// Configuration for parallel block execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FluxConfig {
    /// Number of worker threads (clamped to ≥ 1 by [`ParallelScheduler`]).
    pub num_workers: usize,
}

impl Default for FluxConfig {
    /// Default to the machine's available parallelism (min 1).
    fn default() -> Self {
        Self {
            num_workers: scheduler::num_cpus_or_default(),
        }
    }
}

// ── Convenience entry points ────────────────────────────────────────────────

/// Execute `txs` in parallel against `base` (08-EXECUTION_SPEC §1.6).
///
/// Produces output identical to [`execute_block_sequential`] for the same
/// ordered block (the headline equivalence property).
///
/// # Arguments
///
/// * `executor` — the shared single-transaction executor (B4).
/// * `txs` — the ordered block of transactions.
/// * `block` — deterministic block context from consensus.
/// * `base` — committed base state ([`Arc`]-shared slot-0 fall-through).
/// * `config` — worker-pool configuration.
pub fn execute_block_parallel<S: ContractStateView + Clone + Send + Sync + 'static>(
    executor: &Executor,
    txs: &[Transaction],
    block: &BlockContext,
    base: Arc<S>,
    config: FluxConfig,
) -> BlockOutput {
    ParallelScheduler::new(config.num_workers).execute_block(executor, txs, block, base)
}

/// Execute `txs` strictly in order against `base` — the §1.8 oracle.
///
/// # Arguments
///
/// See [`execute_block_parallel`] (no worker config — execution is serial).
pub fn execute_block_sequential<S: ContractStateView + Clone + Send + Sync + 'static>(
    executor: &Executor,
    txs: &[Transaction],
    block: &BlockContext,
    base: Arc<S>,
) -> BlockOutput {
    SequentialScheduler.execute_block(executor, txs, block, base)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
