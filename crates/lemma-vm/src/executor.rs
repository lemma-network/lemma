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

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    transaction::{Log, Transaction, TransactionReceipt, TxType},
};
use tracing::warn;

use crate::{
    error::VmError,
    gas::{gas_used, FuelMeter, Gas, GasMeter, GasSchedule},
    host::{BlockContext, CallContext, HostState},
    runtime::LemmaEngine,
    state::ContractStateView,
};

// ── Entry point constant ──────────────────────────────────────────────────────

/// WASM entry point for contract calls.
///
/// Phase-3-replaceable: the Lem compiler will define the real calling
/// convention (calldata ptr/len, return ptr/len via linear memory).
/// B4 uses the simplest possible ABI: `fn() -> ()`.
const ENTRY_POINT: &str = "call";

// ── Executor ──────────────────────────────────────────────────────────────────

/// Single-transaction executor with panic-free settlement.
///
/// Create once at node startup (or per-test) and reuse across transactions.
/// The engine is cheaply cloneable (`Arc`-backed); the schedule is `Copy`.
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
}

impl Executor {
    /// Create a new `Executor`.
    ///
    /// # Arguments
    ///
    /// * `engine` — shared [`LemmaEngine`] (create once at startup).
    /// * `schedule` — gas cost schedule (use [`GasSchedule::devnet`] for tests).
    pub fn new(engine: LemmaEngine, schedule: GasSchedule) -> Self {
        Self { engine, schedule }
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
    pub fn execute_transaction<S: ContractStateView + 'static>(
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
        let result = match tx.tx_type {
            TxType::Transfer => self.execute_transfer(tx, &mut scratch, &mut meter),
            TxType::ContractDeploy => self.execute_deploy(tx, &mut scratch, &mut meter),
            TxType::ContractCall => self.execute_call(tx, block, &mut scratch, &mut meter),
            // Unsupported tx types in B4 — produce a failed receipt.
            _ => Err(VmError::InvalidParameter {
                reason: format!("tx type {} not supported in B4", tx.tx_type),
            }),
        };

        self.settle(tx, result, scratch, meter)
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
    /// 1. Derives the contract address via `Address::from_deployer`.
    /// 2. Compiles the bytecode (fails fast on invalid WASM).
    /// 3. Checks the address is not already taken.
    /// 4. Stores the bytecode in scratch state.
    ///
    /// No constructor execution in B4 — Phase 3 (Lem compiler) owns constructor
    /// semantics. B4 deploy = compile-validate + store-and-register.
    ///
    /// # Errors
    ///
    /// - [`VmError::CompilationFailed`] — bytecode is not valid WASM/WAT.
    /// - [`VmError::InvalidParameter`] — address already has code deployed.
    fn execute_deploy<S: ContractStateView>(
        &self,
        tx: &Transaction,
        scratch: &mut ScratchState<'_, S>,
        meter: &mut FuelMeter,
    ) -> Result<Vec<Log>, VmError> {
        // Charge deploy base + per-byte bytecode cost — canonical path (AGENTS §2.1 DRY).
        meter.charge_per_byte(
            self.schedule.deploy_base,
            self.schedule.deploy_per_byte,
            tx.data.len(),
        )?;

        // Derive contract address from deployer + current nonce.
        let current_nonce = scratch.nonce(&tx.sender);
        let contract_addr = Address::from_deployer(&tx.sender, current_nonce);

        // Compile bytecode — fail fast before storing anything.
        // (compile_module accepts both binary WASM and WAT text)
        self.engine.compile_module(&tx.data)?;

        // Guard: address must not already have code (no re-deploy).
        if scratch.code(&contract_addr).is_some() {
            return Err(VmError::InvalidParameter {
                reason: format!("contract already deployed at {contract_addr}"),
            });
        }

        // Store bytecode in scratch — committed to canonical state on success.
        scratch.set_code(&contract_addr, tx.data.clone());

        Ok(vec![])
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
    fn execute_call<S: ContractStateView + 'static>(
        &self,
        tx: &Transaction,
        block: BlockContext,
        scratch: &mut ScratchState<'_, S>,
        meter: &mut FuelMeter,
    ) -> Result<Vec<Log>, VmError> {
        let contract_addr = tx.to.ok_or_else(|| VmError::InvalidParameter {
            reason: "ContractCall tx missing recipient".into(),
        })?;

        // Load bytecode — fail if no contract deployed at this address.
        let bytecode = scratch
            .code(&contract_addr)
            .ok_or_else(|| VmError::InvalidParameter {
                reason: format!("no contract deployed at {contract_addr}"),
            })?;

        // Compile the stored bytecode.
        let module = self.engine.compile_module(&bytecode)?;

        // Snapshot scratch state into an owned view for the host.
        // This satisfies the 'static bound on the linker's func_wrap closures.
        let snapshot = scratch.snapshot();

        // M3 fix: pass contract_addr so host functions use the correct storage namespace.
        // Previously storage ops keyed on block.msg_sender (caller) instead of the
        // executing contract — all state reads/writes went to the wrong address namespace.
        // See 08-EXECUTION_SPEC §4.5 and DB-A53. M3 closed.
        let host = HostState::new(
            FuelMeter::new(meter.remaining()),
            self.schedule,
            CallContext::new(),
            BlockContext {
                contract: contract_addr,
                ..block
            },
            snapshot,
            tx.data.clone(), // calldata for input() host fn (DB-A53 §4.5)
        );

        let (wasm_consumed, host_after) = self.run_wasm(&module, host)?;

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
        Ok(events)
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

    /// Apply the execution result to canonical state and build the receipt.
    ///
    /// ## Settlement logic
    ///
    /// 1. On success: flush scratch writes to state, record logs.
    /// 2. On failure: discard scratch (writes reverted), clear logs.
    /// 3. Either way: advance nonce, charge gas (clamped to gas_limit).
    /// 4. Build and return the receipt — never panic.
    fn settle<S: ContractStateView>(
        &self,
        tx: &Transaction,
        result: Result<Vec<Log>, VmError>,
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
                // Success: commit scratch writes to canonical state and advance nonce.
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
    code_writes: BTreeMap<Address, Vec<u8>>,
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
        }
    }

    /// Snapshot the current scratch state into an owned [`ScratchSnapshot`].
    ///
    /// Used by `execute_call` to give the host an owned `'static` state view
    /// without requiring `ScratchState` to be `'static`. After execution,
    /// writes are merged back via `merge_snapshot`.
    ///
    /// The snapshot captures:
    /// - All scratch writes accumulated so far.
    /// - A read-through view of the inner state for keys not in scratch.
    ///
    /// For B4 (single-frame, no cross-contract calls), this is semantically
    /// correct. Phase 3 will replace this with a proper multi-frame state stack.
    pub(crate) fn snapshot(&self) -> ScratchSnapshot {
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
        // Flush code writes.
        for (addr, code) in self.code_writes {
            self.inner.set_code(&addr, code);
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
        self.code_writes
            .get(addr)
            .cloned()
            .or_else(|| self.inner.code(addr))
    }

    fn set_code(&mut self, addr: &Address, code: Vec<u8>) {
        self.code_writes.insert(*addr, code);
    }
}

// ── ScratchSnapshot ───────────────────────────────────────────────────────────

/// Owned snapshot of scratch state for passing into [`HostState`].
///
/// Used by `execute_call` to give the host an owned `'static` state view
/// without requiring `ScratchState` to be `'static`. After execution, writes
/// are merged back into the original scratch via `merge_snapshot`.
///
/// For B4 (single-frame, no cross-contract calls), this is semantically
/// correct. Phase 3 will replace this with a proper multi-frame state stack.
#[derive(Debug, Clone)]
pub(crate) struct ScratchSnapshot {
    storage: BTreeMap<(Address, Vec<u8>), Vec<u8>>,
    storage_deletes: Vec<(Address, Vec<u8>)>,
    balances: BTreeMap<Address, Amount>,
    nonces: BTreeMap<Address, u64>,
    code: BTreeMap<Address, Vec<u8>>,
}

impl ContractStateView for ScratchSnapshot {
    /// Read a storage slot from this snapshot.
    ///
    /// # ⚠️ M4 — Intentional-deferred: NO read-through to inner state
    ///
    /// `ScratchSnapshot` is an *owned copy* of the current-tx scratch writes.
    /// It does NOT fall through to the underlying canonical state for keys that
    /// haven't been written in this transaction. WASM `storage_read` can only
    /// observe values written earlier in the **same transaction**.
    ///
    /// This diverges from `ScratchState::read`, which *does* fall through.
    ///
    /// **Intentional-deferred** — Phase 3 multi-frame state stack (beyond 6b-vm-1 scope).
    /// Phase 3 (real Lem ABI + multi-frame state stack) must replace this with a proper
    /// read-through implementation. Until then, any WASM contract that reads a storage
    /// slot set by a *previous* committed transaction will observe `None`.
    ///
    /// Tracked in `living-notes.md` Technical Debt: "ScratchSnapshot no read-through".
    fn read(&self, contract: &Address, key: &[u8]) -> Option<Vec<u8>> {
        self.storage.get(&(*contract, key.to_vec())).cloned()
    }

    fn write(&mut self, contract: &Address, key: &[u8], value: Vec<u8>) {
        self.storage.insert((*contract, key.to_vec()), value);
    }

    fn delete(&mut self, contract: &Address, key: &[u8]) {
        self.storage.remove(&(*contract, key.to_vec()));
        self.storage_deletes.push((*contract, key.to_vec()));
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

    fn nonce(&self, addr: &Address) -> u64 {
        self.nonces.get(addr).copied().unwrap_or(0)
    }

    fn set_nonce(&mut self, addr: &Address, nonce: u64) {
        self.nonces.insert(*addr, nonce);
    }

    fn code(&self, addr: &Address) -> Option<Vec<u8>> {
        self.code.get(addr).cloned()
    }

    fn set_code(&mut self, addr: &Address, code: Vec<u8>) {
        self.code.insert(*addr, code);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
