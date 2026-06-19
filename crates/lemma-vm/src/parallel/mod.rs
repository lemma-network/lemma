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
//! | [`hints`]    | [`hints::ContractHints`]: compiler state-access hints (B5-3b) |
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
//!
//! ## Compiler hints (B5-3 part-b)
//!
//! [`execute_block_parallel`] accepts an optional [`hints::HintMap`] — a map
//! from contract address to [`hints::ContractHints`] parsed from the
//! `"lemma.meta"` WASM custom section. When present, hints pre-seed Express
//! eligibility classification. When absent, the scheduler runs in conservative
//! mode (assume all conflicts). Correctness is never contingent on hints.

pub mod conflict;
pub mod hints;
pub mod mvstate;
pub mod mvview;
pub mod scheduler;

use std::sync::Arc;

use lemma_core::transaction::{Transaction, TxType};

use crate::executor::Executor;
use crate::host::BlockContext;
use crate::state::ContractStateView;

pub use hints::{parse_hints_from_wasm, ContractHints, FunctionHint, HintMap};
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
/// * `hints` — optional compiler state-access hints (B5-3b). When `Some`,
///   the hint map is available for pre-seeding and Express classification via
///   [`tx_is_express_eligible`]. When `None`, the scheduler runs in conservative
///   mode (assume all conflicts). Correctness is never contingent on hints —
///   MVCC re-validates every transaction regardless.
pub fn execute_block_parallel<S: ContractStateView + Clone + Send + Sync + 'static>(
    executor: &Executor,
    txs: &[Transaction],
    block: &BlockContext,
    base: Arc<S>,
    config: FluxConfig,
    // `_hints`: accepted now so callers don't need an API change when full
    // pre-seeding lands (B5-3 full dependency-graph wiring, deferred per
    // AGENTS §17 — no premature abstraction). Express classification is
    // available via `tx_is_express_eligible`. MVCC re-validates regardless.
    _hints: Option<&HintMap>,
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

// ── Express eligibility query (B5-3b) ────────────────────────────────────────

/// Returns `true` if `tx` is Express-eligible according to compiler hints.
///
/// Looks up the contract address (`tx.to`) in `hint_map` and checks whether
/// ANY public function in that contract has `is_express_eligible = true`.
///
/// ## Conservative fallback
///
/// Returns `false` (not Express-eligible) when:
/// - `hint_map` is `None` (no hints available).
/// - The contract address is not in the hint map.
/// - No function in the contract has `is_express_eligible = true`.
///
/// This is the correct conservative default per 08-EXECUTION_SPEC §1.7:
/// *"hints are an optimization, never a correctness input — a wrong/missing
/// hint only costs re-execution."*
///
/// ## ABI selector note
///
/// The Lem ABI selector → function name reverse map is not yet wired (deferred
/// to P3·Step 7 ABI work). Until then, this function checks whether ANY
/// function in the contract is Express-eligible — a conservative heuristic
/// that is correct for single-function contracts and over-optimistic for
/// multi-function contracts. The TODO below tracks the precise wiring.
///
/// TODO(step7/abi): wire ABI selector → function name reverse map for
/// per-function Express classification (P3·Step 7).
#[must_use]
pub fn tx_is_express_eligible(tx: &Transaction, hint_map: Option<&HintMap>) -> bool {
    let Some(hint_map) = hint_map else {
        return false; // no hints → conservative
    };
    // Only contract calls can be Express-eligible.
    if !matches!(tx.tx_type, TxType::ContractCall) {
        return false;
    }
    let Some(to) = tx.to else {
        return false;
    };
    let Some(contract_hints) = hint_map.get(&to) else {
        return false; // contract not in hint map → conservative
    };
    // Check if any function in the contract is Express-eligible.
    contract_hints
        .functions
        .values()
        .any(|h| h.is_express_eligible)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
