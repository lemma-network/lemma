//! # Single-Transaction Executor + Panic-Free Settlement (B4)
//!
//! This module implements the settlement boundary described in
//! 08-EXECUTION_SPEC §5: every ordered transaction produces a
//! [`TransactionReceipt`] — never an `Err`, never a panic.
//!
//! ## Settlement contract (spec §5 golden rule)
//!
//! ```text
//! execute_transaction ALWAYS returns TransactionReceipt.
//! OOG, trap, InsufficientFunds, invalid WASM → failed receipt.
//! A reverted tx STILL advances the nonce.
//! A reverted tx STILL charges gas.
//! A reverted tx has logs = vec![].
//! gas_used ≤ gas_limit — always.
//! ```
//!
//! ## Scratch state overlay
//!
//! [`ScratchState`] buffers all writes from a single transaction. On success,
//! `commit_with_nonce()` flushes them to the underlying state. On failure,
//! `discard()` returns the inner reference unchanged — no partial writes reach
//! canonical state.
//!
//! ## WASM entry point convention (Phase-3-replaceable)
//!
//! B4 uses a minimal raw ABI: the entry point is an exported function named
//! `"call"` taking no arguments and returning nothing (`fn() -> ()`).
//! Phase 3 (Lem compiler) will define the real calling convention with
//! calldata ptr/len and return ptr/len via WASM linear memory.
//!
//! ## Module structure (V-5 audit fix)
//!
//! Split into focused submodules for file-size compliance (AGENTS §3.1 < 300):
//! - `call` — `execute_call`, `run_wasm_with_entry`, `run_wasm_call`, trap mapping
//! - `deploy` — `execute_deploy`, registry auto-population
//! - `settle` — `settle()` receipt building + safety-invariant check
//! - `scratch` — `ScratchState`, `ScratchSnapshot`, `CanonicalStateRead`
//! - `linker` — wasmtime host-function registration

mod call;
mod deploy;
pub mod linker;
mod scratch;
mod settle;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use lemma_core::{
    address::Address,
    transaction::{Log, Transaction, TransactionReceipt, TxType},
};
use tracing::warn;

use crate::{
    error::VmError,
    gas::{gas_used, FuelMeter, Gas, GasMeter, GasSchedule},
    host::BlockContext,
    runtime::LemmaEngine,
    safety_manifest::SafetyManifest,
    state::ContractStateView,
};

// Re-export types used by other modules in the crate.
pub(crate) use call::run_wasm_call;
pub(crate) use scratch::ScratchState;

// ── Type aliases ──────────────────────────────────────────────────────────────

/// Return type for `execute_deploy` and `execute_call`: the execution result
/// paired with the contract's safety manifest (if any) for `settle()`.
type ExecResult = (Result<Vec<Log>, VmError>, Option<(Address, SafetyManifest)>);

// ── Entry point constants ─────────────────────────────────────────────────────

/// WASM entry point for contract calls.
///
/// Phase-3-replaceable: the Lem compiler will define the real calling
/// convention (calldata ptr/len, return ptr/len via linear memory).
/// B4 uses the simplest possible ABI: `fn() -> ()`.
const ENTRY_POINT: &str = "call";

/// WASM entry point for the constructor (init) function.
///
/// Invoked once at deploy time, after bytecode is compiled and stored.
/// Same ABI as `"call"`: `fn() -> ()`. Optional — if the module does not
/// export `"init"`, deploy succeeds without constructor execution.
///
/// See 08-EXECUTION_SPEC §4.5 and docs/04-BUILD_GUIDE.md §P3·Step 7.
const INIT_ENTRY_POINT: &str = "init";

// ── Executor ──────────────────────────────────────────────────────────────────

/// Single-transaction executor with panic-free settlement.
///
/// Create once per block (see `execute_committed_block`) and reuse across
/// transactions within that block. The engine is cheaply cloneable
/// (`Arc`-backed); the schedule is `Copy`.
///
/// ## Cold/warm code tracking (08-EXECUTION_SPEC §3.4(c), DB-A22)
///
/// `warm_code` tracks which `code_hash` values have already been charged the
/// `code_cold_surcharge` in the current block. The first call to a given
/// `code_hash` in a block is "cold" — it charges the flat AOT-compile
/// surcharge. Subsequent calls to the same `code_hash` in the same block are
/// "warm" — no surcharge.
///
/// `Mutex<BTreeSet<Hash>>` provides thread-safe interior mutability so the
/// parallel scheduler can share `&Executor` across worker threads while still
/// updating the warm set. `BTreeSet` (not `HashSet`) for determinism
/// (AGENTS.md §7.1).
///
/// The warm set resets at block boundaries because `Executor` is created fresh
/// per block in `execute_committed_block`.
///
/// # Settlement contract
///
/// [`Executor::execute_transaction`] NEVER returns `Err`. Every failure path
/// produces a failed [`TransactionReceipt`] (08-EXECUTION_SPEC §5).
pub struct Executor {
    /// Shared wasmtime engine — deterministic config, cloneable.
    pub(crate) engine: LemmaEngine,
    /// Named gas cost constants for all operation categories.
    pub(crate) schedule: GasSchedule,
    /// Block-scoped warm code set: `code_hash` values already charged the
    /// cold surcharge in this block (08-EXECUTION_SPEC §3.4(c), DB-A22).
    ///
    /// `Mutex` for thread-safe interior mutability (parallel scheduler shares
    /// `&Executor` across workers). `BTreeSet` for determinism (AGENTS §7.1).
    pub(crate) warm_code: Mutex<BTreeSet<lemma_core::hash::Hash>>,
    /// Cached safety manifests per contract address (P3·Step 18, DB-A51).
    ///
    /// Populated on first call/deploy to a contract. Subsequent calls to the
    /// same contract in the same block reuse the cached manifest.
    ///
    /// `BTreeMap` for deterministic iteration (AGENTS §7.1).
    /// `Mutex` for thread-safe interior mutability (parallel scheduler shares
    /// `&Executor` across worker threads).
    pub(crate) safety_manifests: Mutex<BTreeMap<Address, SafetyManifest>>,
}

impl Executor {
    /// Create a new `Executor`.
    ///
    /// Call once per block (not once at node startup) so the `warm_code` set
    /// resets at block boundaries (08-EXECUTION_SPEC §3.4(c)).
    ///
    /// # Arguments
    ///
    /// * `engine` — shared [`LemmaEngine`] (create once at startup, clone cheaply).
    /// * `schedule` — gas cost schedule (use [`GasSchedule::devnet`] for tests).
    pub fn new(engine: LemmaEngine, schedule: GasSchedule) -> Self {
        Self {
            engine,
            schedule,
            warm_code: Mutex::new(BTreeSet::new()),
            safety_manifests: Mutex::new(BTreeMap::new()),
        }
    }

    /// Execute a single transaction and return its receipt.
    ///
    /// **This function NEVER returns `Err`.** Every failure — OOG, trap,
    /// `InsufficientFunds`, invalid WASM — produces a failed receipt
    /// (08-EXECUTION_SPEC §5, AGENTS.md §9.3 "no panics in the settlement path").
    ///
    /// ## Settlement invariants
    ///
    /// - `receipt.gas_used ≤ tx.gas_limit` — always.
    /// - Nonce is incremented even on failure.
    /// - `receipt.logs` is empty on failure (reverted state discards events).
    /// - Partial state writes are never committed on failure.
    ///
    /// # Arguments
    ///
    /// * `tx` — the transaction to execute.
    /// * `block` — deterministic block context from consensus.
    /// * `state` — mutable state backend (writes are applied on success).
    pub fn execute_transaction<S: ContractStateView + Clone + 'static>(
        &self,
        tx: &Transaction,
        block: BlockContext,
        state: &mut S,
    ) -> TransactionReceipt {
        // Charge intrinsic gas first — before any side effects.
        let gas_limit = Gas::new(tx.gas_limit);
        let mut meter = FuelMeter::new(gas_limit);

        let intrinsic = self.intrinsic_gas(tx);
        if meter.charge(intrinsic).is_err() {
            // OOG on intrinsic — advance nonce, charge full gas_limit.
            let current_nonce = state.nonce(&tx.sender);
            // saturating_add: nonce at u64::MAX stays there rather than wrapping to 0
            // (wrapped nonce = silent replay-protection reset — AGENTS §7.4).
            state.set_nonce(&tx.sender, current_nonce.saturating_add(1));
            return TransactionReceipt::new(tx.hash, false, tx.gas_limit, vec![]);
        }

        // Create scratch overlay — all writes buffer here until commit/discard.
        let mut scratch = ScratchState::new(state);

        // ── Warden pre-application check (P3·Step 13, 14-AGENT_LAYER §3) ────
        //
        // If this transaction is signed by a session key (agent tx), validate
        // it against the agent's on-chain policy before execution. Counter
        // updates go into the scratch overlay — they are committed/discarded
        // atomically with the transaction (spec §3 line 201: "only on full
        // success; reverts roll these back with the tx").
        // Mandate receipt log produced by Warden for applied agent txs (§11, Step 17).
        // Built after warden_check returns Applied; prepended to contract logs in settle().
        // None for non-agent txs or when warden_check is not reached.
        let mut mandate_log: Option<Log> = None;

        if let Some(ref session_key) = tx.session_key {
            // Charge Warden gas before the check (charge-before-execute, AGENTS §7.5).
            if meter.charge(self.schedule.warden_check).is_err() {
                return self.fail_before_execution(tx, scratch, &meter, "OOG on warden_check gas");
            }

            match crate::warden::warden_check(tx, session_key, block.epoch, &mut scratch) {
                Ok(lemma_core::agent::WardenOutcome::Applied) => {
                    // Policy checks passed, counters updated in scratch.
                    // Build the AP2-aligned Mandate Receipt log (§11, Step 17) — emitted
                    // on every applied agent tx as a non-repudiable audit trail.
                    let action = crate::warden::classify_action(tx);
                    mandate_log = crate::warden::build_mandate_receipt_log(
                        tx,
                        session_key,
                        block.epoch,
                        action,
                        &scratch,
                    );
                    // Proceed to execution.
                }

                Ok(lemma_core::agent::WardenOutcome::PendingOwnerCosign) => {
                    // Co-sign step-up: tx value ≥ cosign_threshold but no owner
                    // co-signature present (14 §2.3.4, P3·Step 14).
                    //
                    // This is NOT a PolicyViolation — do NOT call handle_violation.
                    // The epoch-reset counters written by warden_check are already
                    // in scratch and will be discarded here with the scratch state.
                    // The owner resubmits with Transaction::owner_cosignature set.
                    return self.fail_before_execution(
                        tx,
                        scratch,
                        &meter,
                        "co-sign required (not a violation)",
                    );
                }

                Ok(_) => {
                    // Future WardenOutcome variants (#[non_exhaustive]).
                    // Fail-CLOSED: unknown outcomes discard scratch + fail receipt.
                    // An unknown outcome could be a hold/pending state from a
                    // future step (e.g. AnomalyHold). Treating it as pass-through
                    // would apply a held tx — a security regression (L3 CR fix).
                    return self.fail_before_execution(
                        tx,
                        scratch,
                        &meter,
                        "unknown WardenOutcome — failing closed (non-violation)",
                    );
                }

                Err(violation) => {
                    // Policy violation: discard scratch (no partial state from failed
                    // checks), run dead-man's switch on inner, then advance nonce.
                    //
                    // ORDERING: handle_violation MUST be called on `inner` (after
                    // discard), NOT on `scratch`. scratch.discard() throws away all
                    // scratch writes — if handle_violation wrote to scratch the
                    // violation counter would be silently lost. Writing to `inner`
                    // ensures the counter persists to canonical state regardless of
                    // the failed tx. (Found by executor integration test CR-S15-6.)
                    //
                    // Exception: AgentsPaused is an owner-level emergency freeze,
                    // NOT a per-policy misbehavior. Penalizing the dead-man's switch
                    // would auto-revoke innocent policies and make it harder to unpause.
                    // AnomalyHold DOES count (§9.1: "dead-man's switch counter
                    // increments") — it falls through to handle_violation as usual.
                    //
                    // NOTE: This arm cannot use fail_before_execution because
                    // handle_violation must write to `inner` (canonical state) BETWEEN
                    // discard and nonce advance. The other 3 arms have no such
                    // intermediate write and share the common helper.
                    let inner = scratch.discard();
                    let current_nonce = inner.nonce(&tx.sender);

                    if violation != lemma_core::agent::PolicyViolation::AgentsPaused {
                        crate::warden::handle_violation(tx, session_key, block.epoch, inner);
                    }
                    inner.set_nonce(&tx.sender, current_nonce.saturating_add(1));

                    warn!(
                        tx_hash = %tx.hash,
                        violation = %violation,
                        "warden: policy violation — producing failed receipt"
                    );

                    let used =
                        gas_used(Gas::new(tx.gas_limit), meter.remaining()).unwrap_or(Gas::ZERO);
                    return TransactionReceipt::new(
                        tx.hash,
                        false,
                        used.as_u64().min(tx.gas_limit),
                        vec![],
                    );
                }
            }
        }

        // Dispatch to the appropriate execution path.
        //
        // Each path returns `(Result<Vec<Log>, VmError>, Option<(Address, SafetyManifest)>)`.
        // The tuple carries the contract address alongside the manifest so that
        // settle() uses the correct storage namespace for invariant checks (C2 fix).
        // Transfers have no contract → `None`. Deploy/call parse the manifest
        // from the contract's `"lemma.meta"` WASM custom section (P3·Step 18).
        let (result, manifest) = match tx.tx_type {
            TxType::Transfer => (
                self.execute_transfer(tx, &mut scratch, &mut meter),
                None, // no contract → no manifest
            ),
            TxType::ContractDeploy => self.execute_deploy(tx, block, &mut scratch, &mut meter),
            TxType::ContractCall => self.execute_call(tx, block, &mut scratch, &mut meter),
            // Unsupported tx types in B4 — produce a failed receipt.
            _ => (
                Err(VmError::InvalidParameter {
                    reason: format!("tx type {} not supported in B4", tx.tx_type),
                }),
                None,
            ),
        };

        self.settle(tx, result, manifest, mandate_log, scratch, meter)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Produce a failed receipt after discarding scratch and advancing the nonce.
    ///
    /// Consolidates the repeated "discard scratch → advance nonce → compute
    /// gas_used → build failed receipt" pattern from the warden match arms
    /// (V-5 audit fix, AGENTS §2.1 DRY). The settlement contract is preserved:
    ///
    /// - Receipt always produced (never panic).
    /// - Nonce advanced (saturating — AGENTS §7.4).
    /// - Gas charged (clamped to gas_limit).
    /// - Logs empty (failure).
    /// - State unchanged (scratch discarded).
    ///
    /// # Arguments
    ///
    /// * `tx` — the failing transaction.
    /// * `scratch` — scratch overlay to discard (consumed).
    /// * `meter` — fuel meter for gas_used computation.
    /// * `reason` — human-readable reason for the warn log.
    fn fail_before_execution<S: ContractStateView>(
        &self,
        tx: &Transaction,
        scratch: ScratchState<'_, S>,
        meter: &FuelMeter,
        reason: &str,
    ) -> TransactionReceipt {
        let inner = scratch.discard();
        let current_nonce = inner.nonce(&tx.sender);
        // saturating_add: nonce at u64::MAX stays there rather than wrapping to 0
        // (wrapped nonce = silent replay-protection reset — AGENTS §7.4).
        inner.set_nonce(&tx.sender, current_nonce.saturating_add(1));

        warn!(
            tx_hash = %tx.hash,
            reason = reason,
            "warden: pre-execution failure — producing failed receipt"
        );

        let used = gas_used(Gas::new(tx.gas_limit), meter.remaining()).unwrap_or(Gas::ZERO);
        TransactionReceipt::new(tx.hash, false, used.as_u64().min(tx.gas_limit), vec![])
    }

    /// Compute intrinsic gas: `tx_base + tx_calldata_per_byte × data.len()`.
    ///
    /// Charged before any execution begins (spec §3.1 rule 1).
    /// Uses a temporary meter so the canonical `charge_per_byte` path (AGENTS §2.1 DRY)
    /// computes the cost without side effects. On overflow, `charge_per_byte` saturates
    /// to OOG and the temporary meter's remaining stays at MAX — giving `Gas(0)` from
    /// `MAX − MAX`. This is unreachable in practice because calldata size is bounded
    /// at the mempool boundary (AGENTS §15.2).
    fn intrinsic_gas(&self, tx: &Transaction) -> Gas {
        let mut tmp = FuelMeter::new(Gas::new(u64::MAX));
        // Canonical base + per_byte * len path (gas.rs charge_per_byte).
        // Overflow saturates; real meter rejects if needed.
        let _ = tmp.charge_per_byte(
            self.schedule.tx_base,
            self.schedule.tx_calldata_per_byte,
            tx.data.len(),
        );
        // Gas consumed = MAX - remaining.
        Gas::new(u64::MAX.saturating_sub(tmp.remaining().as_u64()))
    }

    /// Execute a `Transfer` transaction (no WASM involved).
    ///
    /// Performs a checked balance move from sender to recipient.
    ///
    /// # Errors
    ///
    /// - [`VmError::InsufficientFunds`] — sender balance < `tx.value`.
    fn execute_transfer<S: ContractStateView>(
        &self,
        tx: &Transaction,
        scratch: &mut ScratchState<'_, S>,
        meter: &mut FuelMeter,
    ) -> Result<Vec<Log>, VmError> {
        // Charge the value-transfer gas cost.
        meter.charge(self.schedule.call_value_transfer)?;

        let to = tx.to.ok_or_else(|| VmError::InvalidParameter {
            reason: "Transfer tx missing recipient".into(),
        })?;

        let from_balance = scratch.balance(&tx.sender);
        let new_from =
            from_balance
                .checked_sub(tx.value)
                .map_err(|_| VmError::InsufficientFunds {
                    required: tx.value,
                    available: from_balance,
                })?;

        // Apply debit (CEI — effect before interaction).
        scratch.set_balance(&tx.sender, new_from);

        // Credit recipient — checked add; overflow is theoretically impossible
        // (total supply fits in u128) but handled defensively.
        let to_balance = scratch.balance(&to);
        let new_to = to_balance
            .checked_add(tx.value)
            .map_err(|_| VmError::InvalidParameter {
                reason: "transfer: recipient balance overflow".into(),
            });

        match new_to {
            Ok(new_to_amount) => {
                scratch.set_balance(&to, new_to_amount);
            }
            Err(e) => {
                // Undo the debit to keep scratch consistent on overflow.
                scratch.set_balance(&tx.sender, from_balance);
                return Err(e);
            }
        }

        Ok(vec![])
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
