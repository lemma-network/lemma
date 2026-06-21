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

pub mod linker;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    transaction::{Log, Transaction, TransactionReceipt, TxType},
    MAX_CONTRACT_WASM_SIZE,
};
use tracing::warn;

use crate::{
    error::VmError,
    gas::{gas_used, FuelMeter, Gas, GasMeter, GasSchedule},
    host::{BlockContext, CallContext, HostState},
    runtime::LemmaEngine,
    safety_manifest::{check_safety_invariants, parse_safety_manifest, SafetyManifest},
    state::ContractStateView,
};

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
    engine: LemmaEngine,
    /// Named gas cost constants for all operation categories.
    schedule: GasSchedule,
    /// Block-scoped warm code set: `code_hash` values already charged the
    /// cold surcharge in this block (08-EXECUTION_SPEC §3.4(c), DB-A22).
    ///
    /// `Mutex` for thread-safe interior mutability (parallel scheduler shares
    /// `&Executor` across workers). `BTreeSet` for determinism (AGENTS §7.1).
    warm_code: Mutex<BTreeSet<Hash>>,
    /// Cached safety manifests per contract address (P3·Step 18, DB-A51).
    ///
    /// Populated on first call/deploy to a contract. Subsequent calls to the
    /// same contract in the same block reuse the cached manifest.
    ///
    /// `BTreeMap` for deterministic iteration (AGENTS §7.1).
    /// `Mutex` for thread-safe interior mutability (parallel scheduler shares
    /// `&Executor` across worker threads).
    safety_manifests: Mutex<BTreeMap<Address, SafetyManifest>>,
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

        self.settle(tx, result, manifest, scratch, meter)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

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

    /// Execute a `ContractDeploy` transaction.
    ///
    /// Implements the full deploy design contract (08-EXECUTION_SPEC §3.4(a)(b)(c)):
    ///
    /// 1. **Size gate** (DB-A21): reject oversized bytecode BEFORE charging gas.
    ///    A validator must never let an oversized module occupy its AOT compiler.
    /// 2. **Content-addressed dedup** (DB-A23): bytecode is stored in CF_CODE keyed
    ///    by `blake3(bytecode)`. First deployer pays storage gas; later deployers of
    ///    identical bytecode pay only the base pointer-write cost.
    /// 3. **Thin pointer** (DB-A22): `Account.code_hash = blake3(bytecode)` — the
    ///    account record holds only the 32-byte hash, not the full bytecode.
    /// 4. **Init constructor** (P3·Step 7): if the module exports `"init"`, invoke
    ///    it once after the thin pointer is set. Init gas is charged from the same
    ///    meter. If init traps, the entire deploy fails — no contract is registered.
    ///
    /// # Errors
    ///
    /// - [`VmError::ContractTooLarge`] — bytecode exceeds `MAX_CONTRACT_WASM_SIZE`
    ///   (returned BEFORE gas is charged — DoS protection).
    /// - [`VmError::CompilationFailed`] — bytecode is not valid WASM/WAT.
    /// - [`VmError::InvalidParameter`] — address already has code deployed.
    /// - Any [`VmError`] from init execution — deploy fails, no contract registered.
    fn execute_deploy<S: ContractStateView + Clone + 'static>(
        &self,
        tx: &Transaction,
        block: BlockContext,
        scratch: &mut ScratchState<'_, S>,
        meter: &mut FuelMeter,
    ) -> ExecResult {
        // 1. SIZE GATE — reject-before-charge (DB-A21, 08-EXECUTION_SPEC §3.4(a)).
        //    No gas is charged for an oversized module: the validator did no meaningful
        //    work beyond the size check, and charging gas would reward DoS attempts.
        if tx.data.len() > MAX_CONTRACT_WASM_SIZE {
            return (
                Err(VmError::ContractTooLarge {
                    size: tx.data.len(),
                    limit: MAX_CONTRACT_WASM_SIZE,
                }),
                None,
            );
        }

        // 2. COMPUTE code_hash = blake3(bytecode).
        //    lemma_crypto::hash_bytes is the canonical Blake3 primitive (AGENTS §2.2).
        let code_hash: Hash = lemma_crypto::hash_bytes(&tx.data);

        // 3. DERIVE contract address from deployer + current nonce.
        let current_nonce = scratch.nonce(&tx.sender);
        let contract_addr = Address::from_deployer(&tx.sender, current_nonce);

        // 4. GUARD: address must not already have code (no re-deploy).
        //    scratch.code() checks: thin-pointer map (this tx) → legacy code_writes
        //    (this tx) → inner.code() (prior committed txs). Covers all cases.
        if scratch.code(&contract_addr).is_some() {
            return (
                Err(VmError::InvalidParameter {
                    reason: format!("contract already deployed at {contract_addr}"),
                }),
                None,
            );
        }

        // 5. COMPILE bytecode — fail fast before storing anything.
        //    (compile_module accepts both binary WASM and WAT text)
        //    The compiled module is reused for init invocation below (step 8).
        let module = match self.engine.compile_module(&tx.data) {
            Ok(m) => m,
            Err(e) => return (Err(e), None),
        };

        // 6. CONTENT-ADDRESSED DEDUP (DB-A23, 08-EXECUTION_SPEC §3.4(b/c)).
        //    Check whether this code_hash is already in the content store.
        //    First deployer: store bytecode + charge storage gas.
        //    Later deployer: skip storage gas, charge only base (pointer write).
        //
        //    has_code_hash() checks both scratch (this tx) and inner (prior txs),
        //    enabling cross-transaction dedup savings.
        //
        //    NOTE: We always store bytecode in code_store_writes (even for later
        //    deployers) so that commit_with_nonce can resolve bytecode for
        //    inner.set_code(). The dedup savings are in GAS, not in scratch storage
        //    (scratch is per-transaction and discarded after commit).
        let is_first_deployer = !scratch.has_code_hash(&code_hash);

        if is_first_deployer {
            // First deployer pays storage cost: base + per_byte × len (AGENTS §2.1 DRY).
            if let Err(e) = meter.charge_per_byte(
                self.schedule.deploy_base,
                self.schedule.deploy_storage_per_byte,
                tx.data.len(),
            ) {
                return (Err(e), None);
            }
        } else {
            // Later deployer: only the account pointer write — base cost only.
            if let Err(e) = meter.charge(self.schedule.deploy_base) {
                return (Err(e), None);
            }
        }

        // Always store bytecode in the content-addressed scratch store so that
        // commit_with_nonce can resolve it for inner.set_code(). For later deployers,
        // this is a no-op if the hash is already present (BTreeMap::insert overwrites
        // with the same value — idempotent and correct).
        scratch.put_code_content(code_hash, tx.data.clone());

        // 7. SET thin pointer: Account.code_hash = blake3(bytecode).
        //    Always set regardless of first/later deployer — the account record
        //    must point to the code_hash so execute_call can resolve bytecode.
        scratch.set_code_hash_ptr(&contract_addr, code_hash);

        // 8. INIT CONSTRUCTOR INVOCATION (P3·Step 7, 08-EXECUTION_SPEC §4.5).
        //
        //    If the compiled module exports "init", invoke it once now.
        //    Init runs with:
        //      - msg.sender = tx.sender (the deployer)
        //      - contract   = contract_addr (the newly derived address)
        //      - calldata   = empty (constructor args are not yet defined in B4)
        //
        //    State writes from init are accumulated in the same scratch overlay
        //    and committed together with the deploy on success. If init traps or
        //    runs out of gas, the entire deploy fails — no contract is registered
        //    and scratch is discarded by settle() (AGENTS §7.2 — no panics).
        //
        //    Modules without an "init" export deploy successfully without a
        //    constructor (defaults-only deploy).
        //
        //    Gas: init execution is charged from the same meter as the deploy.
        //    The snapshot/merge pattern (same as execute_call) satisfies the
        //    'static bound on the linker's func_wrap closures without requiring
        //    ScratchState to be 'static (Phase 3 will replace with multi-frame stack).
        let init_block_ctx = BlockContext {
            contract: contract_addr,
            msg_sender: tx.sender,
            ..block
        };

        let snapshot = scratch.snapshot();
        let init_host = HostState::new(
            FuelMeter::new(meter.remaining()),
            self.engine.clone(), // engine for cross-contract calls (LemmaEngine = Arc<wasmtime::Engine> newtype)
            self.schedule,
            CallContext::new(),
            init_block_ctx,
            snapshot,
            vec![], // init calldata: empty (B4 — constructor args deferred to Phase 3)
        );

        let (init_consumed, init_host_after) =
            match self.run_wasm_with_entry(&module, init_host, INIT_ENTRY_POINT) {
                Ok(r) => r,
                Err(e) => return (Err(e), None),
            };

        // Merge init's state writes back into the deploy's scratch overlay.
        // On success, these writes are committed together with the deploy.
        scratch.merge_snapshot(init_host_after.state);

        // Charge init gas from the outer meter.
        // run_wasm_with_entry already returned Ok, so init_consumed ≤ meter.remaining().
        // The match above ensures we only reach here on success.
        let _ = meter.charge(init_consumed);

        // 9. REGISTRY AUTO-POPULATION (DB-A48/DB-A54, P3·Step 7 subtask_09).
        //
        //    If the deployed WASM exports any IToken interface function
        //    ("transfer", "transferFrom", "balanceOf", "approve"), write a
        //    metadata entry into the registry system contract's storage namespace.
        //
        //    Key layout (40 bytes, deterministic — AGENTS §7.1):
        //      registry_addr.as_bytes() (20) ++ contract_addr.as_bytes() (20)
        //
        //    Value: minimal JSON metadata `{"address":"<hex>","is_token":true}`.
        //
        //    This is a best-effort, append-only write. If detection or the write
        //    fails for any reason, we log a warning and continue — the deploy
        //    MUST NOT be failed by registry issues (DB-A54 decision 2, AGENTS §7.2).
        try_write_registry_entry(&module, &contract_addr, scratch);

        // 10. PARSE SAFETY MANIFEST from the deploy bytecode (P3·Step 18, DB-A51).
        //
        //     tx.data is the WASM bytecode — parse the manifest from it now so
        //     settle() (and later, the invariant enforcer) has access to it.
        //     Also cache it for subsequent calls to this contract in the same block.
        let manifest = parse_safety_manifest(&tx.data);

        // C1 fix: charge invariant-check gas if manifest has constraints (DB-A51).
        // Charge BEFORE the check runs (charge-before-execute, AGENTS §7.5).
        if !manifest.constraints.is_empty() {
            if let Err(e) = meter.charge(self.schedule.invariant_check) {
                return (Err(e), Some((contract_addr, manifest)));
            }
        }

        {
            // W1 fix: recover from poisoned mutex instead of panicking.
            let mut cache = self
                .safety_manifests
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache.insert(contract_addr, manifest.clone());
        }

        // C2 fix: pass contract_addr alongside manifest so settle() uses the
        // correct storage namespace (not tx.sender which is the deployer EOA).
        (Ok(vec![]), Some((contract_addr, manifest)))
    }

    /// Execute a `ContractCall` transaction.
    ///
    /// Loads the contract bytecode, instantiates it with the linker, sets fuel,
    /// calls the entry point, and collects the outcome.
    ///
    /// ## Lifetime note
    ///
    /// `func_wrap` closures in the linker require `'static` bounds on the store
    /// data type `S`. To satisfy this without requiring `ScratchState` to be
    /// `'static`, we snapshot the relevant state into an owned [`ScratchSnapshot`]
    /// (which is `'static`), run WASM against it, then merge writes back into
    /// the original scratch. For B4 (single-frame, no cross-contract calls),
    /// this is semantically correct. Phase 3 will replace this with a proper
    /// multi-frame state stack.
    ///
    /// # Errors
    ///
    /// - [`VmError::InvalidParameter`] — no code at `tx.to`.
    /// - [`VmError::CompilationFailed`] — stored bytecode is corrupt.
    /// - [`VmError::InstantiationFailed`] — module cannot be instantiated.
    /// - [`VmError::OutOfGas`] — fuel exhausted during execution.
    /// - [`VmError::StackOverflow`] — native WASM stack exceeded.
    /// - [`VmError::TrapUnknown`] — any other WASM trap.
    fn execute_call<S: ContractStateView + Clone + 'static>(
        &self,
        tx: &Transaction,
        block: BlockContext,
        scratch: &mut ScratchState<'_, S>,
        meter: &mut FuelMeter,
    ) -> ExecResult {
        let contract_addr = match tx.to {
            Some(addr) => addr,
            None => {
                return (
                    Err(VmError::InvalidParameter {
                        reason: "ContractCall tx missing recipient".into(),
                    }),
                    None,
                )
            }
        };

        // Load bytecode via the thin-pointer path:
        //   1. Resolve code_hash from the account's thin pointer.
        //   2. Fetch bytecode from the content-addressed store by code_hash.
        // Falls back to the legacy `code()` path for InMemoryStateView compatibility
        // (test double stores full bytecode directly; production MvStateView uses
        // the thin-pointer path via set_code_hash_ptr → commit_with_nonce).
        let bytecode = match scratch.resolve_code(&contract_addr) {
            Some(b) => b,
            None => {
                return (
                    Err(VmError::InvalidParameter {
                        reason: format!("no contract deployed at {contract_addr}"),
                    }),
                    None,
                )
            }
        };

        // Cold/warm code access tracking (08-EXECUTION_SPEC §3.4(c), DB-A22).
        //
        // Compute the code_hash for this bytecode to determine cold vs warm.
        // The warm set is block-scoped: first call to a code_hash in a block
        // charges the flat AOT-compile surcharge; subsequent calls are warm
        // (no surcharge — the compiled module is already in the engine cache).
        //
        // Gas is charged BEFORE execution (spec §3.1 rule 1, AGENTS §7.5).
        // Surcharge is FLAT per cold module, NOT per-instruction.
        //
        // Mutex::lock() is infallible in practice (only panics if a thread
        // holding the lock panicked — impossible here since we hold no lock
        // across any panic boundary). The `expect` message is for diagnostics.
        // Load or retrieve cached safety manifest for this contract (P3·Step 18).
        //
        // The manifest is parsed from the contract's `"lemma.meta"` WASM custom
        // section on first access and cached for subsequent calls in the same block.
        // BTreeMap for determinism (AGENTS §7.1), Mutex for thread safety.
        let code_hash = lemma_crypto::hash_bytes(&bytecode);
        let manifest = {
            // W1 fix: recover from poisoned mutex instead of panicking.
            let mut cache = self
                .safety_manifests
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache
                .entry(contract_addr)
                .or_insert_with(|| parse_safety_manifest(&bytecode))
                .clone()
        };

        // C1 fix: charge invariant-check gas if manifest has constraints (DB-A51).
        // Charge BEFORE the check runs (charge-before-execute, AGENTS §7.5).
        if !manifest.constraints.is_empty() {
            if let Err(e) = meter.charge(self.schedule.invariant_check) {
                return (Err(e), Some((contract_addr, manifest)));
            }
        }

        {
            // Scope the lock guard so it is released before WASM execution.
            // W1 fix: recover from poisoned mutex instead of panicking.
            let mut warm = self.warm_code.lock().unwrap_or_else(|e| e.into_inner());
            if warm.insert(code_hash) {
                // First call to this code_hash in this block: code-cold.
                // Charge the flat surcharge BEFORE execution (spec §3.1 rule 1).
                if let Err(e) = meter.charge(self.schedule.code_cold_surcharge) {
                    return (Err(e), Some((contract_addr, manifest)));
                }
            }
            // If insert() returned false, the hash was already present: code-warm.
            // No surcharge — execution fuel only.
        }

        // Compile the stored bytecode.
        let module = match self.engine.compile_module(&bytecode) {
            Ok(m) => m,
            Err(e) => return (Err(e), Some((contract_addr, manifest))),
        };

        // Snapshot scratch state into an owned view for the host.
        // This satisfies the 'static bound on the linker's func_wrap closures.
        let snapshot = scratch.snapshot();

        // M3 fix: pass contract_addr so host functions use the correct storage namespace.
        // Previously storage ops keyed on block.msg_sender (caller) instead of the
        // executing contract — all state reads/writes went to the wrong address namespace.
        // See 08-EXECUTION_SPEC §4.5 and DB-A53. M3 closed.
        let host = HostState::new(
            FuelMeter::new(meter.remaining()),
            self.engine.clone(), // engine for cross-contract calls (LemmaEngine = Arc<wasmtime::Engine> newtype)
            self.schedule,
            CallContext::new(),
            BlockContext {
                contract: contract_addr,
                ..block
            },
            snapshot,
            tx.data.clone(), // calldata for input() host fn (DB-A53 §4.5)
        );

        let (wasm_consumed, host_after) = match self.run_wasm(&module, host) {
            Ok(r) => r,
            Err(e) => return (Err(e), Some((contract_addr, manifest))),
        };

        // Destructure host_after to avoid partial-move issues.
        let HostState {
            state: snap,
            events,
            return_data,
            meter: host_meter,
            ..
        } = host_after;

        // return_data: captured by value_return() host fn. Not yet surfaced in
        // TransactionReceipt (consumed by cross-contract calls in P3·Step 7).
        // For now, drop it with explicit acknowledgment.
        let _ = return_data;

        // Refund accumulator: storage_delete credits refunds onto host_meter via
        // the sync-wrap pattern (6b-vm-2). The capped_refund() value is available
        // here but NOT yet applied to gas_used — settle() computes gas_used as
        // `initial - remaining` WITHOUT subtracting the refund.
        //
        // Intentional-deferred: wiring capped_refund into the settlement path
        // requires a settle() redesign (refund must be subtracted from gas_used
        // AFTER capping at remaining/2, per EIP-3529 / spec §3.1 rule 6).
        // Until then, deleting-tx gas_used is slightly higher than the spec model.
        // Tracked in living-notes Technical Debt: "storage_delete refund not applied".
        let _ = host_meter;

        // Merge host state writes back into scratch.
        scratch.merge_snapshot(snap);

        // M1 closed: host-fn charges are deducted from Store fuel via caller.set_fuel()
        // in linker.rs, so wasm_consumed (= initial_fuel - store.get_fuel()) already
        // includes both WASM-instruction fuel AND host-function gas charges.
        // The outer meter.charge(wasm_consumed) therefore reflects total gas correctly.
        let _ = meter.charge(wasm_consumed);

        // Collect events from the host (cleared on failure in settle).
        // C2 fix: pass contract_addr alongside manifest so settle() uses the
        // correct storage namespace for invariant checks.
        (Ok(events), Some((contract_addr, manifest)))
    }

    /// Run a compiled WASM module to completion.
    ///
    /// Sets wasmtime fuel from the host meter, calls the `"call"` entry point,
    /// reads back remaining fuel, and returns `(gas_consumed, host_state)`.
    ///
    /// ## Fuel sync
    ///
    /// FuelMeter tracks host-fn charges in Rust. wasmtime Store tracks WASM
    /// instruction fuel independently. Before execution we sync them; after
    /// execution we compute total consumed.
    ///
    /// # Errors
    ///
    /// Maps wasmtime traps to [`VmError`] variants.
    fn run_wasm<S: ContractStateView + 'static>(
        &self,
        module: &wasmtime::Module,
        host: HostState<S>,
    ) -> Result<(Gas, HostState<S>), VmError> {
        let initial_fuel = host.meter.remaining();

        let mut store = wasmtime::Store::new(self.engine.inner(), host);

        // Set wasmtime fuel from the meter's remaining budget.
        store
            .set_fuel(initial_fuel.as_u64())
            .map_err(|e| VmError::InvalidParameter {
                reason: format!("set_fuel failed: {e}"),
            })?;

        // Build linker and instantiate.
        let linker = linker::build_linker::<S>(&self.engine)?;
        let instance =
            linker
                .instantiate(&mut store, module)
                .map_err(|e| VmError::InstantiationFailed {
                    reason: e.to_string(),
                })?;

        // Get the typed entry-point function.
        let func = instance
            .get_typed_func::<(), ()>(&mut store, ENTRY_POINT)
            .map_err(|e| VmError::InstantiationFailed {
                reason: e.to_string(),
            })?;

        // Call the entry point — map traps to VmError.
        func.call(&mut store, ()).map_err(map_trap_to_vm_error)?;

        // Compute WASM instruction fuel consumed.
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let wasm_consumed = Gas(initial_fuel.as_u64().saturating_sub(fuel_remaining));

        Ok((wasm_consumed, store.into_data()))
    }

    /// Run the optional `"init"` constructor of a compiled WASM module.
    ///
    /// Identical to [`run_wasm`] except:
    /// - Calls [`INIT_ENTRY_POINT`] (`"init"`) instead of `"call"`.
    /// - If the module does NOT export `"init"`, returns `Ok((Gas::ZERO, host))`
    ///   — absence is a no-op (defaults-only deploy), not an error.
    ///
    /// ## Fuel sync
    ///
    /// Same fuel-sync pattern as [`run_wasm`]: initial fuel from host meter,
    /// consumed = initial − remaining after execution.
    ///
    /// # Errors
    ///
    /// - [`VmError::InstantiationFailed`] — module cannot be instantiated.
    /// - [`VmError::OutOfGas`] — init exhausted the gas budget.
    /// - [`VmError::StackOverflow`] — native WASM stack exceeded during init.
    /// - [`VmError::TrapUnknown`] — any other WASM trap during init.
    fn run_wasm_with_entry<S: ContractStateView + 'static>(
        &self,
        module: &wasmtime::Module,
        host: HostState<S>,
        entry_point: &str,
    ) -> Result<(Gas, HostState<S>), VmError> {
        let initial_fuel = host.meter.remaining();

        let mut store = wasmtime::Store::new(self.engine.inner(), host);

        // Set wasmtime fuel from the meter's remaining budget.
        store
            .set_fuel(initial_fuel.as_u64())
            .map_err(|e| VmError::InvalidParameter {
                reason: format!("set_fuel failed: {e}"),
            })?;

        // Build linker and instantiate.
        let linker = linker::build_linker::<S>(&self.engine)?;
        let instance =
            linker
                .instantiate(&mut store, module)
                .map_err(|e| VmError::InstantiationFailed {
                    reason: e.to_string(),
                })?;

        // Look up the entry-point function.
        // get_typed_func returns Err if the export is absent or has the wrong type.
        // Absence of "init" is a no-op (defaults-only deploy) — return host unchanged.
        let func = match instance.get_typed_func::<(), ()>(&mut store, entry_point) {
            Ok(f) => f,
            Err(_) => {
                // Entry point not exported — no-op, zero gas consumed.
                return Ok((Gas::ZERO, store.into_data()));
            }
        };

        // Call the entry point — map traps to VmError.
        func.call(&mut store, ()).map_err(map_trap_to_vm_error)?;

        // Compute WASM instruction fuel consumed.
        let fuel_remaining = store.get_fuel().unwrap_or(0);
        let wasm_consumed = Gas(initial_fuel.as_u64().saturating_sub(fuel_remaining));

        Ok((wasm_consumed, store.into_data()))
    }

    /// Apply the execution result to canonical state and build the receipt.
    ///
    /// ## Settlement logic
    ///
    /// 1. On success: flush scratch writes to state, record logs.
    /// 2. On failure: discard scratch (writes reverted), clear logs.
    /// 3. Either way: advance nonce, charge gas (clamped to gas_limit).
    /// 4. Build and return the receipt — never panic.
    ///
    /// ## Safety manifest (P3·Step 18, DB-A51)
    ///
    /// `manifest` is `Some((contract_addr, manifest))` for contract calls and
    /// deploys (parsed from the contract's `"lemma.meta"` WASM custom section).
    /// `None` for plain transfers (no contract, no manifest).
    ///
    /// The `contract_addr` is the address of the executing contract — NOT
    /// `tx.sender` (which is the caller/deployer EOA). This ensures the
    /// invariant check inspects the correct storage namespace (C2 fix).
    fn settle<S: ContractStateView>(
        &self,
        tx: &Transaction,
        result: Result<Vec<Log>, VmError>,
        manifest: Option<(Address, SafetyManifest)>,
        scratch: ScratchState<'_, S>,
        meter: FuelMeter,
    ) -> TransactionReceipt {
        // Compute gas used — clamp to gas_limit (spec invariant: gas_used ≤ gas_limit).
        let initial = Gas::new(tx.gas_limit);
        let used_gas = gas_used(initial, meter.remaining()).unwrap_or_else(|| {
            // remaining > initial indicates a meter bug — log and use 0.
            warn!(
                tx_hash = %tx.hash,
                "gas meter remaining exceeded initial budget — clamping gas_used to 0"
            );
            Gas::ZERO
        });
        // Clamp: gas_used ≤ gas_limit (defensive — should already hold).
        let gas_used_clamped = used_gas.0.min(tx.gas_limit);

        match result {
            Ok(logs) => {
                // P3·Step 18-05 (DB-A51): post-execution safety-invariant check.
                //
                // If the manifest has constraints, verify the state diff before
                // committing. A violation converts success → failure (scratch
                // discarded, failed receipt produced). This is the runtime pair
                // of compile-time SAFETY-001/002/005/009.
                //
                // C2 fix: `contract_addr` is plumbed from execute_call/execute_deploy
                // so settle() uses the correct storage namespace. Previously used
                // `tx.to.unwrap_or(tx.sender)` which was WRONG for deploys (tx.to
                // is None, fell back to tx.sender = deployer EOA, not the contract).
                if let Some((contract_addr, ref m)) = manifest {
                    if !m.constraints.is_empty() {
                        if let Err(violation) = check_safety_invariants(
                            m,
                            &contract_addr,
                            scratch.storage_writes_ref(),
                            scratch.inner_ref(),
                        ) {
                            // Invariant violated: convert success → failure.
                            // Discard scratch (no partial writes reach canonical state).
                            let inner = scratch.discard();
                            let current_nonce = inner.nonce(&tx.sender);
                            // saturating_add: nonce at u64::MAX stays there rather than wrapping.
                            inner.set_nonce(&tx.sender, current_nonce.saturating_add(1));

                            warn!(
                                tx_hash = %tx.hash,
                                error = %violation,
                                "honeypot invariant violated — reverting transaction"
                            );

                            return TransactionReceipt::new(
                                tx.hash,
                                false,
                                gas_used_clamped,
                                vec![],
                            );
                        }
                    }
                }

                // No violation — commit scratch writes to canonical state and advance nonce.
                scratch.commit_with_nonce(&tx.sender);
                TransactionReceipt::new(tx.hash, true, gas_used_clamped, logs)
            }
            Err(err) => {
                // Failure: discard scratch (no partial writes reach canonical state).
                // Advance nonce on the canonical state directly.
                let inner = scratch.discard();
                let current_nonce = inner.nonce(&tx.sender);
                // saturating_add: nonce at u64::MAX stays there rather than wrapping.
                inner.set_nonce(&tx.sender, current_nonce.saturating_add(1));

                // Log the failure for observability (not a panic — just a warn).
                warn!(
                    tx_hash = %tx.hash,
                    error = %err,
                    gas_used = gas_used_clamped,
                    "transaction failed — producing failed receipt"
                );

                // Failed receipt: success=false, logs=[] (spec §5 H2 invariant).
                TransactionReceipt::new(tx.hash, false, gas_used_clamped, vec![])
            }
        }
    }
}

// ── Registry auto-population (DB-A48/DB-A54) ─────────────────────────────────

/// IToken interface export names used for token detection (DB-A54 decision 2).
///
/// A deployed WASM is classified as a token if it exports ANY of these names.
/// This matches the IToken interface defined in `03-LANGUAGE_SPEC §24`.
const ITOKEN_EXPORTS: &[&str] = &["transfer", "transferFrom", "balanceOf", "approve"];

/// Attempt to write a registry entry for a newly deployed token contract.
///
/// Called after successful init invocation in `execute_deploy`. Inspects the
/// compiled module's exports to detect IToken interface compliance, then writes
/// a metadata entry into the registry system contract's storage namespace.
///
/// ## Key layout (40 bytes, deterministic — AGENTS §7.1)
///
/// ```text
/// key = registry_addr.as_bytes() (20) ++ contract_addr.as_bytes() (20)
/// ```
///
/// The key is stored under the registry system contract's storage namespace
/// (first argument to `scratch.write`), so the full storage address is:
/// `(registry_addr, key)` where `key` is the 40-byte concatenation above.
///
/// ## Best-effort semantics (DB-A54 decision 2, AGENTS §7.2)
///
/// This function NEVER propagates errors. Any failure (export inspection,
/// JSON formatting, storage write) is logged as a warning and silently
/// ignored. The deploy MUST NOT fail due to registry issues.
fn try_write_registry_entry<S: ContractStateView>(
    module: &wasmtime::Module,
    contract_addr: &Address,
    scratch: &mut ScratchState<'_, S>,
) {
    // Detect IToken interface: check if the module exports any IToken function.
    // wasmtime::Module::get_export(name) returns Some(ExternType) if the export
    // exists, None otherwise. We check ExternType::Func to ensure it is a function
    // (not a memory or global with the same name). O(1) per lookup.
    // This is a pure inspection — no instantiation, no gas, no side effects.
    let is_token = ITOKEN_EXPORTS
        .iter()
        .any(|&name| matches!(module.get_export(name), Some(wasmtime::ExternType::Func(_))));

    if !is_token {
        // Non-token contract — no registry entry needed.
        return;
    }

    // Build the 40-byte registry key:
    //   registry_addr.as_bytes() (20) ++ contract_addr.as_bytes() (20)
    // This is deterministic: same inputs → same key on every node (AGENTS §7.1).
    let registry_addr = Address::registry();
    let mut key = [0u8; 40];
    key[..20].copy_from_slice(registry_addr.as_bytes());
    key[20..].copy_from_slice(contract_addr.as_bytes());

    // Build minimal JSON metadata value.
    // Format: {"address":"<hex>","is_token":true}
    // Hex-encode the 20-byte address for human-readable JSON.
    let addr_hex: String = contract_addr
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let metadata = format!(r#"{{"address":"{addr_hex}","is_token":true}}"#);

    // Write to the registry system contract's storage namespace.
    // Key = 40-byte concatenation; value = UTF-8 JSON bytes.
    // On any failure, warn and continue — never fail the deploy.
    scratch.write(&registry_addr, &key, metadata.into_bytes());

    tracing::debug!(
        contract = %contract_addr,
        "registry: token contract auto-registered (DB-A54)"
    );
}

// ── Trap → VmError mapping ────────────────────────────────────────────────────

/// Map a wasmtime `anyhow::Error` (from `.call()`) to a [`VmError`].
///
/// wasmtime returns `anyhow::Error` from typed function calls. We downcast
/// to `wasmtime::Trap` to distinguish OOG from other traps.
///
/// Pattern confirmed from wasmtime 45 docs (context.md §wasmtime 45 API reference).
fn map_trap_to_vm_error(e: wasmtime::Error) -> VmError {
    if let Some(trap) = e.downcast_ref::<wasmtime::Trap>() {
        match trap {
            wasmtime::Trap::OutOfFuel => VmError::OutOfGas,
            wasmtime::Trap::StackOverflow => VmError::StackOverflow,
            _ => VmError::TrapUnknown {
                message: format!("{trap}"),
            },
        }
    } else {
        VmError::TrapUnknown {
            message: e.to_string(),
        }
    }
}

// ── ScratchState ──────────────────────────────────────────────────────────────

/// Buffers writes from a single transaction; committed or discarded atomically.
///
/// Reads fall through to `inner` if not present in the scratch buffers.
/// Writes stay in scratch until `commit_with_nonce` (success) or `discard`
/// (failure).
///
/// ## Determinism
///
/// All maps use [`BTreeMap`] — deterministic iteration order (AGENTS.md §7.1).
/// Never use `HashMap` here.
///
/// ## Storage read semantics
///
/// - Key present with `Some(v)` → return that value (written this tx).
/// - Key present with `None` → return `None` (deleted this tx).
/// - Key absent → fall through to `inner.read()`.
pub(crate) struct ScratchState<'a, S: ContractStateView> {
    inner: &'a mut S,
    /// Storage writes: `None` = deleted, `Some(v)` = written.
    storage_writes: BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>>,
    balance_writes: BTreeMap<Address, Amount>,
    nonce_writes: BTreeMap<Address, u64>,
    /// Legacy code writes (kept for backward compat with InMemoryStateView test double).
    /// Production deploy path uses `code_hash_writes` + `code_store_writes` instead.
    code_writes: BTreeMap<Address, Vec<u8>>,
    /// Thin pointer: `contract_address → code_hash` (DB-A22).
    ///
    /// Set by `execute_deploy` after successful compilation. On commit, flushed
    /// to `inner.set_code()` with the full bytecode resolved from `code_store_writes`.
    code_hash_writes: BTreeMap<Address, Hash>,
    /// Content-addressed bytecode store: `code_hash → bytecode` (DB-A23).
    ///
    /// Written only by the first deployer of a given bytecode. Later deployers
    /// of identical bytecode skip this write and pay only the base pointer cost.
    code_store_writes: BTreeMap<Hash, Vec<u8>>,
}

impl<'a, S: ContractStateView> ScratchState<'a, S> {
    /// Create a new scratch overlay over `inner`.
    pub(crate) fn new(inner: &'a mut S) -> Self {
        Self {
            inner,
            storage_writes: BTreeMap::new(),
            balance_writes: BTreeMap::new(),
            nonce_writes: BTreeMap::new(),
            code_writes: BTreeMap::new(),
            code_hash_writes: BTreeMap::new(),
            code_store_writes: BTreeMap::new(),
        }
    }

    // ── Safety-invariant accessors (P3·Step 18-05) ─────────────────────────────

    /// Read access to the storage writes for safety-invariant checking.
    ///
    /// Returns a reference to the `BTreeMap` of `(contract_addr, key) → Option<value>`.
    /// `Some(v)` = written, `None` = deleted. Used by [`check_safety_invariants`]
    /// to inspect the state diff without cloning.
    pub(crate) fn storage_writes_ref(&self) -> &BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>> {
        &self.storage_writes
    }

    /// Read access to the canonical (inner) state for safety-invariant checking.
    ///
    /// Returns a reference to the underlying state view (pre-transaction state).
    /// Used by [`check_safety_invariants`] to read old values for ratchet checks.
    pub(crate) fn inner_ref(&self) -> &S {
        self.inner
    }

    // ── Deploy-path helpers (thin pointer + content store) ────────────────────

    /// Store bytecode in the content-addressed scratch store (DB-A23).
    ///
    /// Called by `execute_deploy` for the first deployer of a given bytecode.
    /// Later deployers of identical bytecode skip this call.
    pub(crate) fn put_code_content(&mut self, hash: Hash, bytes: Vec<u8>) {
        self.code_store_writes.insert(hash, bytes);
    }

    /// Look up bytecode in the content-addressed scratch store by hash.
    ///
    /// Returns `Some(&bytes)` if this hash was stored in the current transaction,
    /// `None` if not present in scratch (may still exist in committed state).
    // consumer: execute_call cold/warm path (P3·Step 7 subtask_06)
    #[allow(dead_code)]
    pub(crate) fn get_code_content(&self, hash: &Hash) -> Option<&Vec<u8>> {
        self.code_store_writes.get(hash)
    }

    /// Set the thin pointer: `contract_address → code_hash` (DB-A22).
    ///
    /// Called by `execute_deploy` after successful compilation and dedup check.
    pub(crate) fn set_code_hash_ptr(&mut self, addr: &Address, hash: Hash) {
        self.code_hash_writes.insert(*addr, hash);
    }

    /// Get the thin pointer for a contract address.
    ///
    /// Returns `Some(hash)` if a code_hash was registered for this address in
    /// the current transaction, `None` otherwise.
    // consumer: init invocation path (P3·Step 7 subtask_07)
    #[allow(dead_code)]
    pub(crate) fn get_code_hash_ptr(&self, addr: &Address) -> Option<Hash> {
        self.code_hash_writes.get(addr).copied()
    }

    /// Resolve bytecode for a contract address via the thin-pointer path.
    ///
    /// Resolution order:
    /// 1. Check `code_hash_writes` for a thin pointer set this transaction.
    /// 2. If found, look up bytecode in `code_store_writes`.
    /// 3. Fall back to `inner.code()` for contracts deployed in prior transactions
    ///    (InMemoryStateView stores full bytecode; production MvStateView resolves
    ///    via its own code_hash → bytecode path).
    ///
    /// This is the canonical bytecode-loading path for `execute_call`.
    pub(crate) fn resolve_code(&self, addr: &Address) -> Option<Vec<u8>> {
        // Check if a thin pointer was set this transaction.
        if let Some(hash) = self.code_hash_writes.get(addr) {
            // Resolve bytecode from the content store (same transaction).
            if let Some(bytes) = self.code_store_writes.get(hash) {
                return Some(bytes.clone());
            }
            // Hash registered but bytecode not in scratch — this is the later-deployer
            // case where the bytecode was already in committed state. Fall through to
            // inner.code() which resolves via the committed store.
        }
        // Fall through to inner for contracts deployed in prior transactions.
        self.inner.code(addr)
    }

    /// Snapshot the current scratch state into an owned [`ScratchSnapshot`].
    ///
    /// Used by `execute_call` to give the host an owned `'static` state view
    /// without requiring `ScratchState` to be `'static`. After execution,
    /// writes are merged back via `merge_snapshot`.
    ///
    /// ## M4 fix — canonical read-through
    ///
    /// The snapshot now carries a clone of `inner` as a [`CanonicalStateRead`]
    /// so that WASM `storage_read` can observe values from prior committed
    /// transactions. `S: Clone` is required to produce the owned `'static`
    /// canonical reader without lifetime parameters.
    ///
    /// The snapshot captures:
    /// - All scratch writes accumulated so far (highest priority).
    /// - A tombstone set for keys deleted this transaction.
    /// - A clone of `inner` for canonical fall-through (M4 fix).
    ///
    /// For B4 (single-frame, no cross-contract calls), this is semantically
    /// correct. Phase 3 will replace this with a proper multi-frame state stack.
    pub(crate) fn snapshot(&self) -> ScratchSnapshot
    where
        S: Clone + 'static,
    {
        ScratchSnapshot {
            storage: self
                .storage_writes
                .iter()
                .filter_map(|(k, v)| v.as_ref().map(|val| (k.clone(), val.clone())))
                .collect(),
            storage_deletes: self
                .storage_writes
                .iter()
                .filter_map(|(k, v)| if v.is_none() { Some(k.clone()) } else { None })
                .collect(),
            balances: self.balance_writes.clone(),
            nonces: self.nonce_writes.clone(),
            code: self.code_writes.clone(),
            code_hashes: self.code_hash_writes.clone(),
            code_store: self.code_store_writes.clone(),
            // M4 fix: clone inner to provide canonical read-through for WASM storage_read.
            // The clone is cheap for InMemoryStateView (BTreeMap clone) and for
            // MvStateView (Arc clone for mv + base; RefCell clone for captured/writes).
            canonical: Box::new(self.inner.clone()),
        }
    }

    /// Merge writes from a completed [`ScratchSnapshot`] back into this scratch.
    ///
    /// Called after `execute_call` completes successfully. Overwrites any
    /// existing scratch entries with the host's final values.
    pub(crate) fn merge_snapshot(&mut self, snap: ScratchSnapshot) {
        for (k, v) in snap.storage {
            self.storage_writes.insert(k, Some(v));
        }
        for k in snap.storage_deletes {
            self.storage_writes.insert(k, None);
        }
        for (addr, amt) in snap.balances {
            self.balance_writes.insert(addr, amt);
        }
        for (addr, n) in snap.nonces {
            self.nonce_writes.insert(addr, n);
        }
        for (addr, code) in snap.code {
            self.code_writes.insert(addr, code);
        }
        for (addr, hash) in snap.code_hashes {
            self.code_hash_writes.insert(addr, hash);
        }
        for (hash, bytes) in snap.code_store {
            self.code_store_writes.insert(hash, bytes);
        }
        // `canonical` is a read-only view — no writes to merge back.
    }

    /// Commit all scratch writes to `inner` and advance the sender's nonce.
    ///
    /// Called on success. After this call, `inner` reflects all writes.
    pub(crate) fn commit_with_nonce(self, sender: &Address) {
        // Flush storage writes.
        for ((contract, key), value) in self.storage_writes {
            match value {
                Some(v) => self.inner.write(&contract, &key, v),
                None => self.inner.delete(&contract, &key),
            }
        }
        // Flush balance writes.
        for (addr, amount) in self.balance_writes {
            self.inner.set_balance(&addr, amount);
        }
        // Flush nonce writes (excluding sender — we advance below).
        for (addr, nonce) in self.nonce_writes {
            if addr != *sender {
                self.inner.set_nonce(&addr, nonce);
            }
        }
        // Flush legacy code writes (backward compat with InMemoryStateView test double).
        for (addr, code) in self.code_writes {
            self.inner.set_code(&addr, code);
        }
        // Flush thin-pointer + content-store writes (new deploy path, DB-A22/A23).
        //
        // For each contract address with a registered code_hash, resolve the full
        // bytecode from code_store_writes and call inner.set_code(). This keeps
        // InMemoryStateView and MvStateView working unchanged — they store full
        // bytecode by address and serve it via code(). The content-addressed dedup
        // is enforced at the scratch layer (gas savings); the underlying state view
        // sees the resolved bytecode as before.
        //
        // execute_deploy always stores bytecode in code_store_writes (for both first
        // and later deployers), so the lookup here always succeeds for any address
        // that was deployed in this transaction.
        for (addr, hash) in &self.code_hash_writes {
            if let Some(bytes) = self.code_store_writes.get(hash) {
                self.inner.set_code(addr, bytes.clone());
            }
            // If bytecode is not in code_store_writes, the deploy was not completed
            // in this transaction (should not happen — execute_deploy always stores it).
        }
        // Advance sender nonce.
        let current = self.inner.nonce(sender);
        // saturating_add: nonce at u64::MAX stays there rather than wrapping.
        self.inner.set_nonce(sender, current.saturating_add(1));
    }

    /// Discard all scratch writes and return a mutable reference to `inner`.
    ///
    /// Called on failure. No writes reach canonical state.
    pub(crate) fn discard(self) -> &'a mut S {
        // Drop all scratch buffers — inner is unchanged.
        self.inner
    }
}

impl<S: ContractStateView> ContractStateView for ScratchState<'_, S> {
    fn read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        match self.storage_writes.get(&(*contract, key.to_vec())) {
            Some(Some(v)) => Some(v.clone()),       // written this tx
            Some(None) => None,                     // deleted this tx
            None => self.inner.read(contract, key), // fall through
        }
    }

    fn write(&mut self, contract: &Address, key: &[u8], value: Vec<u8>) {
        self.storage_writes
            .insert((*contract, key.to_vec()), Some(value));
    }

    fn delete(&mut self, contract: &Address, key: &[u8]) {
        self.storage_writes.insert((*contract, key.to_vec()), None);
    }

    fn exists(&self, contract: &Address, key: &[u8]) -> bool {
        match self.storage_writes.get(&(*contract, key.to_vec())) {
            Some(Some(_)) => true,
            Some(None) => false,
            None => self.inner.exists(contract, key),
        }
    }

    fn balance(&self, addr: &Address) -> Amount {
        self.balance_writes
            .get(addr)
            .copied()
            .unwrap_or_else(|| self.inner.balance(addr))
    }

    fn set_balance(&mut self, addr: &Address, amount: Amount) {
        self.balance_writes.insert(*addr, amount);
    }

    fn nonce(&self, addr: &Address) -> u64 {
        self.nonce_writes
            .get(addr)
            .copied()
            .unwrap_or_else(|| self.inner.nonce(addr))
    }

    fn set_nonce(&mut self, addr: &Address, nonce: u64) {
        self.nonce_writes.insert(*addr, nonce);
    }

    fn code(&self, addr: &Address) -> Option<Vec<u8>> {
        // Try thin-pointer path first (new deploy path, DB-A22/A23).
        if let Some(hash) = self.code_hash_writes.get(addr) {
            if let Some(bytes) = self.code_store_writes.get(hash) {
                return Some(bytes.clone());
            }
        }
        // Fall back to legacy code_writes map, then inner.
        self.code_writes
            .get(addr)
            .cloned()
            .or_else(|| self.inner.code(addr))
    }

    fn set_code(&mut self, addr: &Address, code: Vec<u8>) {
        self.code_writes.insert(*addr, code);
    }

    fn has_code_hash(&self, hash: &Hash) -> bool {
        // Check scratch content store first (deployed this tx).
        if self.code_store_writes.contains_key(hash) {
            return true;
        }
        // Fall through to inner (deployed in prior committed txs).
        self.inner.has_code_hash(hash)
    }
}

// ── CanonicalStateRead ────────────────────────────────────────────────────────

/// Minimal read-only view of canonical (committed) state.
///
/// Used by [`ScratchSnapshot`] to fall through to committed state for keys
/// not written in the current transaction (M4 fix). The trait is intentionally
/// narrow — only the operations needed by the WASM host are included.
///
/// # `'static` requirement
///
/// Implementations must be `'static` so that `ScratchSnapshot` (which holds a
/// `Box<dyn CanonicalStateRead + 'static>`) satisfies the wasmtime linker's
/// `'static` bound on `HostState<ScratchSnapshot>`.
pub(crate) trait CanonicalStateRead: 'static {
    /// Read a storage slot from canonical state.
    fn canonical_read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>>;

    /// Check whether a storage slot exists in canonical state.
    fn canonical_exists(&self, contract: &Address, key: &[u8]) -> bool;

    /// Read the native LEM balance of an account from canonical state.
    fn canonical_balance(&self, addr: &Address) -> Amount;
}

/// Blanket implementation: any `ContractStateView + Clone + 'static` can serve
/// as a canonical reader. The clone is taken at snapshot time so the reader is
/// owned and `'static`.
impl<S: ContractStateView + Clone + 'static> CanonicalStateRead for S {
    fn canonical_read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        self.read(contract, key)
    }

    fn canonical_exists(&self, contract: &Address, key: &[u8]) -> bool {
        self.exists(contract, key)
    }

    fn canonical_balance(&self, addr: &Address) -> Amount {
        self.balance(addr)
    }
}

// ── ScratchSnapshot ───────────────────────────────────────────────────────────

/// Owned snapshot of scratch state for passing into [`HostState`].
///
/// Used by `execute_call` to give the host an owned `'static` state view
/// without requiring `ScratchState` to be `'static`. After execution, writes
/// are merged back into the original scratch via `merge_snapshot`.
///
/// ## M4 fix — read-through to canonical state
///
/// `ScratchSnapshot` now carries a `Box<dyn CanonicalStateRead + 'static>`
/// that is a clone of the inner state taken at snapshot time. The read path
/// falls through in priority order:
///
/// 1. Current-tx writes (`storage` map) — highest priority.
/// 2. Current-tx deletes (`storage_deletes` set) — tombstone: return `None`.
/// 3. Canonical state (`canonical`) — committed state from prior txs.
///
/// This matches `ScratchState::read` semantics and closes M4.
///
/// For B4 (single-frame, no cross-contract calls), this is semantically
/// correct. Phase 3 will replace this with a proper multi-frame state stack.
pub(crate) struct ScratchSnapshot {
    storage: BTreeMap<(Address, Vec<u8>), Vec<u8>>,
    /// Tombstone set: keys deleted in the current transaction.
    ///
    /// A key in `storage_deletes` shadows any canonical value — `read` returns
    /// `None` even if the canonical state has a value for that key.
    storage_deletes: BTreeSet<(Address, Vec<u8>)>,
    balances: BTreeMap<Address, Amount>,
    nonces: BTreeMap<Address, u64>,
    code: BTreeMap<Address, Vec<u8>>,
    /// Thin pointer: `contract_address → code_hash` (DB-A22).
    code_hashes: BTreeMap<Address, Hash>,
    /// Content-addressed bytecode store: `code_hash → bytecode` (DB-A23).
    code_store: BTreeMap<Hash, Vec<u8>>,
    /// Read-through to canonical (committed) state for keys not in this snapshot.
    ///
    /// Cloned from `ScratchState::inner` at snapshot time. Satisfies `'static`
    /// because `S: Clone + 'static` is required by `ScratchState::snapshot`.
    ///
    /// M4 fix: closes the gap where WASM `storage_read` returned `None` for
    /// keys written by prior committed transactions.
    canonical: Box<dyn CanonicalStateRead + 'static>,
}

impl ContractStateView for ScratchSnapshot {
    /// Read a storage slot from this snapshot with canonical fall-through.
    ///
    /// ## M4 fix — read priority (matches `ScratchState::read`)
    ///
    /// 1. Key in `storage` (written this tx) → return that value.
    /// 2. Key in `storage_deletes` (deleted this tx) → return `None` (tombstone).
    /// 3. Fall through to `canonical` (committed state from prior txs).
    fn read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        let k = (*contract, key.to_vec());
        // Priority 1: current-tx write.
        if let Some(v) = self.storage.get(&k) {
            return Some(v.clone());
        }
        // Priority 2: current-tx delete (tombstone).
        if self.storage_deletes.contains(&k) {
            return None;
        }
        // Priority 3: fall through to canonical state (M4 fix).
        self.canonical.canonical_read(contract, key)
    }

    fn write(&mut self, contract: &Address, key: &[u8], value: Vec<u8>) {
        let k = (*contract, key.to_vec());
        // A write un-deletes the key: remove from tombstone set.
        self.storage_deletes.remove(&k);
        self.storage.insert(k, value);
    }

    fn delete(&mut self, contract: &Address, key: &[u8]) {
        let k = (*contract, key.to_vec());
        self.storage.remove(&k);
        self.storage_deletes.insert(k);
    }

    fn exists(&self, contract: &Address, key: &[u8]) -> bool {
        let k = (*contract, key.to_vec());
        // Current-tx write → exists.
        if self.storage.contains_key(&k) {
            return true;
        }
        // Current-tx delete (tombstone) → does not exist.
        if self.storage_deletes.contains(&k) {
            return false;
        }
        // Fall through to canonical state (M4 fix).
        self.canonical.canonical_exists(contract, key)
    }

    fn balance(&self, addr: &Address) -> Amount {
        // Current-tx balance write takes priority; fall through to canonical (M4 fix).
        self.balances
            .get(addr)
            .copied()
            .unwrap_or_else(|| self.canonical.canonical_balance(addr))
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
        // Try thin-pointer path first (new deploy path, DB-A22/A23).
        if let Some(hash) = self.code_hashes.get(addr) {
            if let Some(bytes) = self.code_store.get(hash) {
                return Some(bytes.clone());
            }
        }
        // Fall back to legacy code map (backward compat).
        self.code.get(addr).cloned()
    }

    fn set_code(&mut self, addr: &Address, code: Vec<u8>) {
        self.code.insert(*addr, code);
    }

    fn has_code_hash(&self, hash: &Hash) -> bool {
        // Check the content store snapshot (deployed this tx).
        self.code_store.contains_key(hash)
        // NOTE: has_code_hash on ScratchSnapshot only sees writes from the current tx.
        // This is acceptable: ScratchSnapshot is only used by execute_call (WASM host),
        // not by execute_deploy (which uses ScratchState directly).
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
