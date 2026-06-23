//! # Host Functions (08-EXECUTION_SPEC §4)
//!
//! This module provides the bridge between WASM contract execution and the
//! Lemma node's state, crypto, and event subsystems.
//!
//! ## Structure
//!
//! | Item | Role |
//! |------|------|
//! | [`BlockContext`] | Deterministic per-call context from consensus |
//! | [`CallContext`]  | Reentrancy guard + call depth tracker (§2.3) |
//! | [`HostState`]    | Bundles meter, schedule, context, state, events |
//! | [`HostFunctions`]| Trait: all 16 host functions (§4) |
//!
//! ## Determinism contract
//!
//! Every host function is deterministic — no `SystemTime`, no `rand`.
//! All context values come from consensus (block header, tx fields).
//! `BTreeSet` is used for `warm_keys` and `active` — never `HashSet`
//! (AGENTS.md §7.1).
//!
//! ## No-panic contract (Sui-stall lesson)
//!
//! Every host function returns `Result` — never panics (AGENTS.md §7.2,
//! §9.3). OOG, reentrancy, and insufficient funds all produce typed errors.

use lemma_core::{address::Address, amount::Amount, hash::Hash, transaction::Log};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    error::VmError,
    gas::{FuelMeter, Gas, GasMeter, GasSchedule},
    runtime::{LemmaEngine, MAX_CALL_DEPTH},
    state::ContractStateView,
};

// ── BlockContext ──────────────────────────────────────────────────────────────

/// Deterministic per-call context sourced from consensus.
///
/// All fields come from the block header or transaction — never from
/// `SystemTime`, `rand`, or any non-deterministic source (AGENTS.md §7.1,
/// 07-CONSENSUS_SPEC §5.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockContext {
    /// Current block height (from consensus — never `SystemTime`).
    pub height: u64,
    /// Block timestamp in seconds (from consensus — never wall-clock).
    pub timestamp: u64,
    /// The immediate caller of the current call frame (msg.sender).
    pub msg_sender: Address,
    /// Native LEM value attached to this call (in Drop).
    pub msg_value: Amount,
    /// The original transaction sender (tx.origin — the EOA that signed).
    pub tx_origin: Address,
    /// The address of the contract currently executing.
    ///
    /// Used for storage namespace isolation (storage_read/write/delete, transfer.from).
    /// Distinct from `msg_sender` (the caller) — `contract` is the callee whose
    /// storage is being accessed. See decisions-log DB-A53 §4.5 and
    /// 08-EXECUTION_SPEC §4.5.
    pub contract: Address,

    /// Current epoch number (validator-set era, from consensus).
    ///
    /// Used by Warden for policy expiry checks and per-epoch counter resets
    /// (14-AGENT_LAYER §3). Sourced from the parent block header's epoch
    /// field — deterministic, never from `SystemTime` (AGENTS §7.1).
    ///
    /// Added in P3·Step 13 (Warden policy enforcement).
    pub epoch: u64,
}

// ── CallContext ───────────────────────────────────────────────────────────────

/// Reentrancy guard and call depth tracker (08-EXECUTION_SPEC §2.3).
///
/// Tracks which contract addresses have a live frame on the call stack.
/// Uses [`BTreeSet`] for deterministic ordering (AGENTS.md §7.1).
///
/// # Invariants
///
/// - `depth` equals `active.len()` at all times.
/// - `enter_call` / `exit_call` must be called symmetrically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallContext {
    /// Current call nesting depth (0 = top-level transaction).
    depth: u32,
    /// Addresses with a live frame on the call stack.
    ///
    /// `BTreeSet` — deterministic iteration order (AGENTS.md §7.1).
    /// Never use `HashSet` here.
    active: BTreeSet<Address>,
}

impl CallContext {
    /// Create a new `CallContext` at depth 0 with no active frames.
    pub fn new() -> Self {
        Self {
            depth: 0,
            active: BTreeSet::new(),
        }
    }

    /// Enter a call to `callee`.
    ///
    /// Checks depth limit first, then reentrancy. On success, increments
    /// `depth` and inserts `callee` into `active`.
    ///
    /// # Errors
    ///
    /// - [`VmError::CallDepthExceeded`] — `depth >= MAX_CALL_DEPTH`.
    /// - [`VmError::Reentrancy`] — `callee` already has a live frame.
    pub fn enter_call(&mut self, callee: Address) -> Result<(), VmError> {
        // Depth check first (spec §2.3 order).
        if self.depth >= MAX_CALL_DEPTH {
            return Err(VmError::CallDepthExceeded);
        }
        // Reentrancy check second.
        if self.active.contains(&callee) {
            return Err(VmError::Reentrancy { addr: callee });
        }
        self.depth += 1;
        self.active.insert(callee);
        Ok(())
    }

    /// Exit a call to `callee`.
    ///
    /// Decrements `depth` and removes `callee` from `active`.
    /// Infallible — callers guarantee `enter_call`/`exit_call` symmetry.
    pub fn exit_call(&mut self, callee: &Address) {
        // Saturating sub prevents underflow if called asymmetrically (defensive).
        self.depth = self.depth.saturating_sub(1);
        self.active.remove(callee);
    }

    /// Current call nesting depth.
    pub fn depth(&self) -> u32 {
        self.depth
    }
}

impl Default for CallContext {
    fn default() -> Self {
        Self::new()
    }
}

// ── HostState ─────────────────────────────────────────────────────────────────

/// Bundles all state needed by host functions during contract execution.
///
/// `S` is the state backend — [`crate::state::InMemoryStateView`] for tests,
/// B5's `MvState` for production.
///
/// # Determinism
///
/// `warm_keys` uses [`BTreeSet`] — deterministic iteration order (AGENTS §7.1).
pub struct HostState<S: ContractStateView> {
    /// Gas meter — charges are applied before side effects.
    pub meter: FuelMeter,
    /// WASM engine for compiling + running callee contracts in cross-contract calls.
    ///
    /// `LemmaEngine` is already an `Arc<wasmtime::Engine>` newtype — cloning it is O(1)
    /// (atomic refcount increment, no bytecode recompilation). Required by
    /// `call_contract`/`static_call`/`delegate_call` host functions which must
    /// compile+run the callee's WASM from inside a host callback. No outer `Arc`
    /// needed — double-wrapping would add a redundant allocation per subtask spawn.
    pub engine: LemmaEngine,
    /// Named gas cost constants for all operation categories.
    pub schedule: GasSchedule,
    /// Reentrancy guard and call depth tracker.
    pub call_ctx: CallContext,
    /// Deterministic per-call context from consensus.
    pub block: BlockContext,
    /// Contract storage and balance state.
    pub state: S,
    /// Events accumulated during this transaction (cleared on revert).
    pub events: Vec<Log>,
    /// EIP-2929 warm storage set — slots accessed in this tx pay warm cost.
    ///
    /// `BTreeSet` for deterministic ordering (AGENTS.md §7.1).
    pub warm_keys: BTreeSet<(Address, Vec<u8>)>,
    /// Register channel — variable-length host results (DB-A53 §4.5).
    ///
    /// `BTreeMap` for deterministic ordering (AGENTS §7.1 — never HashMap).
    /// Populated by host functions that return variable-length data; consumed
    /// by the guest via register-read host functions (6b-vm-2).
    pub registers: BTreeMap<u32, Vec<u8>>,
    /// Transaction calldata, pre-loaded by the executor before invoking "call".
    ///
    /// Populated by executor.rs; consumed by the `input()` host function (6b-vm-2).
    pub calldata: Vec<u8>,
    /// Return data written by the guest via `value_return()` (6b-vm-2).
    pub return_data: Vec<u8>,
}

impl<S: ContractStateView> HostState<S> {
    /// Create a new `HostState`.
    ///
    /// # Arguments
    ///
    /// * `meter` — pre-funded gas meter for this transaction.
    /// * `engine` — WASM engine for cross-contract call compilation.
    /// * `schedule` — gas cost constants.
    /// * `call_ctx` — reentrancy / depth tracker (typically `CallContext::new()`).
    /// * `block` — deterministic context from consensus.
    /// * `state` — contract storage and balance backend.
    /// * `calldata` — transaction calldata for the `input()` host function (6b-vm-2).
    pub fn new(
        meter: FuelMeter,
        engine: LemmaEngine,
        schedule: GasSchedule,
        call_ctx: CallContext,
        block: BlockContext,
        state: S,
        calldata: Vec<u8>,
    ) -> Self {
        Self {
            meter,
            engine,
            schedule,
            call_ctx,
            block,
            state,
            events: Vec::new(),
            warm_keys: BTreeSet::new(),
            registers: BTreeMap::new(),
            calldata,
            return_data: Vec::new(),
        }
    }

    /// Check whether a storage key is warm (already accessed this tx).
    fn is_warm(&self, contract: &Address, key: &[u8]) -> bool {
        self.warm_keys.contains(&(*contract, key.to_vec()))
    }

    /// Mark a storage key as warm.
    fn mark_warm(&mut self, contract: &Address, key: &[u8]) {
        self.warm_keys.insert((*contract, key.to_vec()));
    }
}

// ── HostFunctions trait ───────────────────────────────────────────────────────

/// All 16 host functions exposed to WASM contracts via the `HostFunctions` trait (08-EXECUTION_SPEC §4).
///
/// Note: the ABI `IMPORT_ORDER` (lemma-lang `codegen/abi.rs`) has 17 entries — the
/// two sets differ because the trait includes `tx_origin`, `balance_of`, and crypto
/// helpers not in the ABI import table, while `static_call`/`delegate_call` are
/// registered in the linker but not yet in this trait (added in P3·Step 21 subtasks 03-04).
///
/// ## Contract
///
/// 1. **Charge before execute** — gas is charged before any side effect.
/// 2. **Result only** — every function returns `Result`; never panics.
/// 3. **Deterministic** — no `SystemTime`, no `rand`, no float arithmetic.
pub trait HostFunctions {
    // ── Storage ───────────────────────────────────────────────────────────────

    /// Read a storage slot for the current contract.
    ///
    /// # Errors
    ///
    /// [`VmError::OutOfGas`] if the gas budget is exhausted.
    fn storage_read(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, VmError>;

    /// Write a storage slot for the current contract.
    ///
    /// # Errors
    ///
    /// [`VmError::OutOfGas`] if the gas budget is exhausted.
    fn storage_write(&mut self, key: &[u8], value: &[u8]) -> Result<(), VmError>;

    /// Delete a storage slot for the current contract.
    ///
    /// # Errors
    ///
    /// [`VmError::OutOfGas`] if the gas budget is exhausted.
    fn storage_delete(&mut self, key: &[u8]) -> Result<(), VmError>;

    // ── Context ───────────────────────────────────────────────────────────────

    /// Return the immediate caller address (msg.sender).
    ///
    /// # Errors
    ///
    /// Infallible in practice; `Result` for trait uniformity.
    fn msg_sender(&mut self) -> Result<Address, VmError>;

    /// Return the native LEM value attached to this call (in Drop).
    ///
    /// # Errors
    ///
    /// Infallible in practice; `Result` for trait uniformity.
    fn msg_value(&mut self) -> Result<Amount, VmError>;

    /// Return the current block height.
    ///
    /// # Errors
    ///
    /// Infallible in practice; `Result` for trait uniformity.
    fn block_height(&mut self) -> Result<u64, VmError>;

    /// Return the current block timestamp (seconds, from consensus).
    ///
    /// # Errors
    ///
    /// Infallible in practice; `Result` for trait uniformity.
    fn block_timestamp(&mut self) -> Result<u64, VmError>;

    /// Return the original transaction sender (tx.origin — the signing EOA).
    ///
    /// # Errors
    ///
    /// Infallible in practice; `Result` for trait uniformity.
    fn tx_origin(&mut self) -> Result<Address, VmError>;

    // ── Token ops ─────────────────────────────────────────────────────────────

    /// Transfer native LEM from the current contract to `to`.
    ///
    /// Applies the debit/credit immediately (CEI — checks-effects-interactions).
    ///
    /// # Errors
    ///
    /// - [`VmError::OutOfGas`] — gas exhausted before transfer.
    /// - [`VmError::InsufficientFunds`] — sender balance < `amount`.
    fn transfer(&mut self, to: Address, amount: Amount) -> Result<(), VmError>;

    /// Return the native LEM balance of `addr` (in Drop).
    ///
    /// # Errors
    ///
    /// [`VmError::OutOfGas`] if the gas budget is exhausted.
    fn balance_of(&mut self, addr: Address) -> Result<Amount, VmError>;

    // ── Crypto ────────────────────────────────────────────────────────────────

    /// Compute the Blake3 hash of `data`.
    ///
    /// # Errors
    ///
    /// [`VmError::OutOfGas`] if the gas budget is exhausted.
    fn hash_blake3(&mut self, data: &[u8]) -> Result<Hash, VmError>;

    /// Compute the Keccak-256 hash of `data`.
    ///
    /// # Errors
    ///
    /// [`VmError::OutOfGas`] if the gas budget is exhausted.
    fn hash_keccak256(&mut self, data: &[u8]) -> Result<Hash, VmError>;

    /// Verify a hybrid signature (Ed25519 + ML-DSA-65).
    ///
    /// Deserializes `pubkey` and `sig` from raw bytes at the boundary.
    ///
    /// # Arguments
    ///
    /// * `pubkey` — serialized [`lemma_crypto::PublicKey`] (bincode).
    /// * `msg` — the message that was signed.
    /// * `sig` — serialized [`lemma_crypto::HybridSignature`] (bincode).
    ///
    /// # Returns
    ///
    /// `Ok(true)` if both classical and post-quantum signatures verify.
    /// `Ok(false)` if the signature is invalid (not an error — contracts
    /// may handle invalid sigs gracefully).
    ///
    /// # Errors
    ///
    /// - [`VmError::OutOfGas`] — gas exhausted.
    /// - [`VmError::InvalidParameter`] — `pubkey` or `sig` bytes cannot be
    ///   deserialized into the expected types.
    fn verify_signature(&mut self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, VmError>;

    // ── Events ────────────────────────────────────────────────────────────────

    /// Emit a contract event.
    ///
    /// # Arguments
    ///
    /// * `topics` — indexed event parameters (first is conventionally the
    ///   event signature hash).
    /// * `data` — ABI-encoded non-indexed parameters.
    ///
    /// # Errors
    ///
    /// [`VmError::OutOfGas`] if the gas budget is exhausted.
    fn emit_event(&mut self, topics: &[Hash], data: &[u8]) -> Result<(), VmError>;

    // ── Cross-contract ────────────────────────────────────────────────────────

    /// Call another contract (63/64 gas forwarding + depth + reentrancy).
    ///
    /// # Production call path
    ///
    /// **Only reachable from unit tests.** The production call path is:
    /// `linker.rs dispatch_call(CallMode::Normal)` — the linker closure (index 14)
    /// has access to the full wasmtime execution context and performs the actual
    /// WASM execution. This trait method handles only the pre-execution checks
    /// (reentrancy + gas) for unit-test coverage of those checks.
    ///
    /// Returns `Ok(vec![])` after checks pass (not `Err(InvalidParameter)` as the
    /// stale B3 comment said — the B4 linker path is now wired and this method
    /// is only called directly in host/tests.rs unit tests).
    ///
    /// # Errors
    ///
    /// - [`VmError::OutOfGas`] — gas exhausted before forwarding.
    /// - [`VmError::CallDepthExceeded`] — depth limit reached.
    /// - [`VmError::Reentrancy`] — `addr` already has a live frame.
    fn call_contract(&mut self, addr: Address, data: &[u8], gas: Gas) -> Result<Vec<u8>, VmError>;

    /// Return the remaining gas budget.
    ///
    /// # Errors
    ///
    /// Infallible in practice; `Result` for trait uniformity.
    fn gas_remaining(&mut self) -> Result<Gas, VmError>;
}

// ── HostFunctions impl for HostState ─────────────────────────────────────────

impl<S: ContractStateView> HostFunctions for HostState<S> {
    fn storage_read(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>, VmError> {
        // M3 fix: use contract address, not msg_sender
        let contract = self.block.contract;
        let cost = if self.is_warm(&contract, key) {
            self.schedule.storage_read_warm
        } else {
            self.schedule.storage_read_cold
        };
        self.meter.charge(cost)?;
        self.mark_warm(&contract, key);
        Ok(self.state.read(&contract, key))
    }

    fn storage_write(&mut self, key: &[u8], value: &[u8]) -> Result<(), VmError> {
        // M3 fix: use contract address, not msg_sender
        let contract = self.block.contract;
        let cost = if self.state.exists(&contract, key) {
            self.schedule.storage_write_update
        } else {
            self.schedule.storage_write_create
        };
        self.meter.charge(cost)?;
        self.state.write(&contract, key, value.to_vec());
        self.mark_warm(&contract, key);
        Ok(())
    }

    fn storage_delete(&mut self, key: &[u8]) -> Result<(), VmError> {
        // M3 fix: use contract address, not msg_sender
        let contract = self.block.contract;
        self.meter.charge(self.schedule.storage_delete)?;
        self.state.delete(&contract, key);
        self.meter.refund(self.schedule.storage_delete_refund);
        self.mark_warm(&contract, key);
        Ok(())
    }

    fn msg_sender(&mut self) -> Result<Address, VmError> {
        Ok(self.block.msg_sender)
    }

    fn msg_value(&mut self) -> Result<Amount, VmError> {
        Ok(self.block.msg_value)
    }

    fn block_height(&mut self) -> Result<u64, VmError> {
        Ok(self.block.height)
    }

    fn block_timestamp(&mut self) -> Result<u64, VmError> {
        Ok(self.block.timestamp)
    }

    fn tx_origin(&mut self) -> Result<Address, VmError> {
        Ok(self.block.tx_origin)
    }

    fn transfer(&mut self, to: Address, amount: Amount) -> Result<(), VmError> {
        // Charge before any state mutation (CEI — charge is the "check").
        self.meter.charge(self.schedule.call_value_transfer)?;

        // M3 fix: use contract address, not msg_sender
        // The contract's OWN balance is what it transfers from, not the caller's balance.
        let from = self.block.contract;
        let from_balance = self.state.balance(&from);

        // Checked subtraction — insufficient funds → typed error, no panic.
        let new_from =
            from_balance
                .checked_sub(amount)
                .map_err(|_| VmError::InsufficientFunds {
                    required: amount,
                    available: from_balance,
                })?;

        // Apply debit immediately (CEI — effect before any further interaction).
        self.state.set_balance(&from, new_from);

        // Credit recipient — checked add; overflow is theoretically impossible
        // (total supply fits in u128) but we handle it defensively.
        let to_balance = self.state.balance(&to);
        let new_to = to_balance.checked_add(amount).map_err(|_| {
            // Undo the debit to keep state consistent on overflow.
            self.state.set_balance(&from, from_balance);
            VmError::InvalidParameter {
                reason: "transfer: recipient balance overflow".into(),
            }
        })?;
        self.state.set_balance(&to, new_to);
        Ok(())
    }

    fn balance_of(&mut self, addr: Address) -> Result<Amount, VmError> {
        // Balance reads always charge cold cost (no warm-tracking for balances
        // in B3). Rationale: balance reads are rare within a single tx relative
        // to storage ops; the implementation complexity of a separate balance
        // warm-set is deferred to post-benchmarking. Warm-tracking for storage
        // slots is applied via `warm_keys` (EIP-2929). Revisit if profiling
        // shows repeated balance_of calls are a hot path (AGENTS §16.3).
        self.meter.charge(self.schedule.storage_read_cold)?;
        Ok(self.state.balance(&addr))
    }

    fn hash_blake3(&mut self, data: &[u8]) -> Result<Hash, VmError> {
        self.meter.charge_per_byte(
            self.schedule.hash_blake3_base,
            self.schedule.hash_blake3_per_byte,
            data.len(),
        )?;
        Ok(lemma_crypto::hash_bytes(data))
    }

    fn hash_keccak256(&mut self, data: &[u8]) -> Result<Hash, VmError> {
        self.meter.charge_per_byte(
            self.schedule.hash_keccak256_base,
            self.schedule.hash_keccak256_per_byte,
            data.len(),
        )?;
        Ok(lemma_crypto::keccak256(data))
    }

    fn verify_signature(&mut self, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<bool, VmError> {
        // Charge the FULL hybrid cost before deserialization (spec §4 + §3.2):
        // lemma_crypto::verify performs BOTH Ed25519 AND ML-DSA-65 — charging
        // only verify_ed25519 (3_000) would under-price by ~10× (verify_mldsa65 = 30_000),
        // creating a spam/DoS vector where an attacker pays 3 k gas for 33 k CPU.
        let hybrid_cost = self
            .schedule
            .verify_ed25519
            .checked_add(self.schedule.verify_mldsa65)
            .ok_or(VmError::OutOfGas)?;
        self.meter.charge(hybrid_cost)?;

        // Deserialize at the boundary — invalid bytes → InvalidParameter, not panic.
        let pk: lemma_crypto::PublicKey =
            bincode::deserialize(pubkey).map_err(|e| VmError::InvalidParameter {
                reason: format!("verify_signature: invalid pubkey bytes: {e}"),
            })?;
        let hybrid_sig: lemma_crypto::HybridSignature =
            bincode::deserialize(sig).map_err(|e| VmError::InvalidParameter {
                reason: format!("verify_signature: invalid sig bytes: {e}"),
            })?;

        // CryptoError → false (invalid sig is not a VM error — contracts may handle it).
        Ok(lemma_crypto::verify(&pk, msg, &hybrid_sig).is_ok())
    }

    fn emit_event(&mut self, topics: &[Hash], data: &[u8]) -> Result<(), VmError> {
        self.meter.charge_per_byte(
            self.schedule.emit_event_base,
            self.schedule.emit_event_per_byte,
            data.len(),
        )?;
        // M3 fix: events are attributed to the EXECUTING CONTRACT, not the caller.
        // msg_sender is who called the contract; contract is what emitted the event.
        // See 08-EXECUTION_SPEC §4 and DB-A53; same namespace fix as storage ops.
        let contract = self.block.contract;
        self.events
            .push(Log::new(contract, topics.to_vec(), data.to_vec()));
        Ok(())
    }

    fn call_contract(&mut self, addr: Address, _data: &[u8], gas: Gas) -> Result<Vec<u8>, VmError> {
        // Reentrancy + depth check first (spec §2.3). enter_call increments
        // depth and inserts addr into active — MUST be unwound on every
        // subsequent failure path to preserve: "depth == active.len()".
        self.call_ctx.enter_call(addr)?;

        // Charge the cross-contract call base cost (spec §3.2 — CALL base).
        // This is the realistic OOG point; charge(to_callee) below is safe by
        // construction (to_callee <= forwardable <= remaining), but we unwind
        // defensively on both paths.
        if let Err(e) = self.meter.charge(self.schedule.call_base) {
            self.call_ctx.exit_call(&addr);
            return Err(e);
        }

        // 63/64 gas forwarding (spec §2.4). forwardable <= remaining after
        // call_base is already charged, so to_callee <= remaining — safe.
        let forwardable = self.meter.forwardable();
        let to_callee = gas.min(forwardable);
        if let Err(e) = self.meter.charge(to_callee) {
            self.call_ctx.exit_call(&addr);
            return Err(e);
        }

        // Gas/reentrancy checks passed. The actual WASM execution is performed
        // by the linker's call_contract closure (index 14 in linker.rs), which
        // has access to the full wasmtime execution context. This trait method
        // handles the pre-execution checks; the linker handles execution.
        //
        // Only reachable from unit tests (host/tests.rs). Production call path:
        // linker.rs dispatch_call(CallMode::Normal). The linker closure overrides
        // this return value with real return data from the callee's value_return().
        self.call_ctx.exit_call(&addr);

        // Return empty data — only reached in unit tests that call the trait method
        // directly (to test reentrancy/gas checks without a full WASM execution).
        Ok(vec![])
    }

    fn gas_remaining(&mut self) -> Result<Gas, VmError> {
        Ok(self.meter.remaining())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
