//! Call execution path + WASM runner for [`Executor`].
//!
//! Contains `execute_call`, `run_wasm_with_entry` (the sole WASM execution
//! method on `Executor`), `run_wasm_call` (free-function variant for
//! cross-contract calls), and `map_trap_to_vm_error`. Split from `executor.rs`
//! for file-size compliance (AGENTS §3.1 < 300 lines, V-5 audit fix).

use lemma_core::transaction::Transaction;

use crate::{
    error::VmError,
    gas::{FuelMeter, Gas, GasMeter},
    host::{BlockContext, CallContext, HostState},
    runtime::LemmaEngine,
    safety_manifest::parse_safety_manifest,
    state::ContractStateView,
};

use super::{linker, ExecResult, Executor, ScratchState, ENTRY_POINT};

impl Executor {
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
    pub(crate) fn execute_call<S: ContractStateView + Clone + 'static>(
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

        // Parse the contract's host-ABI version for dispatch (DB-A58 L2).
        // Defaults to 1 if absent (backward compat for pre-Step-20 contracts).
        let host_abi = crate::safety_manifest::parse_host_abi(&bytecode);

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

        let (wasm_consumed, host_after) =
            match self.run_wasm_with_entry(host_abi, &module, host, ENTRY_POINT) {
                Ok((gas, host_state)) => {
                    // "call" MUST exist for ContractCall — absence is an error, not a no-op.
                    // run_wasm_with_entry returns (Gas::ZERO, host) when the entry point is
                    // absent. For INIT_ENTRY_POINT that is correct (defaults-only deploy).
                    // For ENTRY_POINT ("call"), absence means the contract has no callable
                    // entry — this is an invalid contract, not a silent success.
                    if gas == Gas::ZERO
                        && !module.exports().any(|e| {
                            e.name() == ENTRY_POINT
                                && matches!(e.ty(), wasmtime::ExternType::Func(_))
                        })
                    {
                        return (
                            Err(VmError::InstantiationFailed {
                                reason: format!(
                                    "contract has no \"{ENTRY_POINT}\" export — cannot call"
                                ),
                            }),
                            Some((contract_addr, manifest)),
                        );
                    }
                    (gas, host_state)
                }
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

    /// Run a compiled WASM module to completion via the given entry point.
    ///
    /// This is the **sole** WASM execution method on `Executor` (V-DRY-2).
    /// Both `execute_call` and `execute_deploy` (init) route through here.
    ///
    /// Sets wasmtime fuel from the host meter, calls `entry_point`, reads back
    /// remaining fuel, and returns `(gas_consumed, host_state)`.
    ///
    /// If the module does NOT export `entry_point`, returns
    /// `Ok((Gas::ZERO, host))` — absence is a no-op. Callers that require the
    /// entry point to exist (e.g. `execute_call` with `ENTRY_POINT`) must check
    /// the `Gas::ZERO` return and map it to an error themselves.
    ///
    /// ## Fuel sync
    ///
    /// FuelMeter tracks host-fn charges in Rust. wasmtime Store tracks WASM
    /// instruction fuel independently. Before execution we sync them; after
    /// execution we compute total consumed.
    ///
    /// # Errors
    ///
    /// - [`VmError::InstantiationFailed`] — module cannot be instantiated.
    /// - [`VmError::OutOfGas`] — execution exhausted the gas budget.
    /// - [`VmError::StackOverflow`] — native WASM stack exceeded.
    /// - [`VmError::TrapUnknown`] — any other WASM trap.
    pub(crate) fn run_wasm_with_entry<S: ContractStateView + Clone + 'static>(
        &self,
        abi: u32,
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

        // Build linker for the contract's host-ABI version (DB-A58 L2).
        let linker = linker::build_linker_for_abi::<S>(abi, &self.engine)?;
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

// ── run_wasm_call ─────────────────────────────────────────────────────────────

/// Run a compiled WASM module to completion for a cross-contract call.
///
/// This is the free-function equivalent of [`Executor::run_wasm_with_entry`],
/// used by the `call_contract` host function (P3·Step 21 subtask_02) to
/// execute a callee contract from inside a host callback.
///
/// ## Why a free function?
///
/// `Executor::run_wasm_with_entry` is a method on `Executor` and requires
/// `&self` for the engine reference. Inside a host callback, we have the
/// engine via `HostState::engine` (an `Arc`-backed `LemmaEngine` clone). A
/// free function avoids the need to construct a full `Executor` for the
/// recursive call.
///
/// ## Fuel sync
///
/// Same pattern as `Executor::run_wasm_with_entry`: initial fuel from host
/// meter, consumed = initial − remaining after execution.
///
/// # Type parameter
///
/// `S` must be `ContractStateView + Clone + 'static`. In production, `S` is
/// always `ScratchSnapshot`. In tests, `S` may be `InMemoryStateView`.
///
/// # Errors
///
/// Maps wasmtime traps to [`VmError`] variants.
pub(crate) fn run_wasm_call<S: ContractStateView + Clone + 'static>(
    abi: u32,
    engine: &LemmaEngine,
    module: &wasmtime::Module,
    host: HostState<S>,
) -> Result<(Gas, HostState<S>), VmError> {
    let initial_fuel = host.meter.remaining();

    let mut store = wasmtime::Store::new(engine.inner(), host);

    // Set wasmtime fuel from the meter's remaining budget.
    store
        .set_fuel(initial_fuel.as_u64())
        .map_err(|e| VmError::InvalidParameter {
            reason: format!("run_wasm_call: set_fuel failed: {e}"),
        })?;

    // Build linker for the callee's host-ABI version (DB-A58 L2).
    let linker = linker::build_linker_for_abi::<S>(abi, engine)?;
    let instance =
        linker
            .instantiate(&mut store, module)
            .map_err(|e| VmError::InstantiationFailed {
                reason: e.to_string(),
            })?;

    // Get the typed entry-point function.
    let func = instance
        .get_typed_func::<(), ()>(&mut store, super::ENTRY_POINT)
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
