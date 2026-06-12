//! # Linker — wasmtime host-function registration (B4)
//!
//! Builds a [`wasmtime::Linker`] with all LemmaVM host functions registered
//! under the `"lemma"` import module.
//!
//! ## Import convention
//!
//! All host imports use the form `(import "lemma" "fn_name" ...)`.
//! The WASM type mapping for memory-taking host functions uses a raw
//! pointer/length ABI (`i32` ptr + `i32` len). This is a **Phase-3-replaceable
//! placeholder** — the Lem compiler owns the real ABI and memory marshalling.
//!
//! ## B4 scope
//!
//! For B4 tests we wire the zero-argument / simple-integer host functions
//! that need no memory marshalling:
//! - `block_height() -> i64`
//! - `block_timestamp() -> i64`
//! - `gas_remaining() -> i64`
//! - `msg_value() -> i64`
//!
//! Memory-taking host functions (`storage_read`, `storage_write`, etc.) are
//! registered as **safe stubs** that return a sentinel value so that any WASM
//! module importing them can instantiate successfully. Real marshalling is
//! Phase 3.
//!
//! ## M1 fix: shared-budget gas charging
//!
//! Host-function gas charges are deducted from the wasmtime Store fuel via
//! `charge_fuel` (caller.set_fuel). This ensures host-fn costs flow into
//! `wasm_consumed` (= initial_fuel − store.get_fuel()) in executor.rs,
//! preventing the double-budget DoS where a contract could spend full limit
//! on WASM instructions AND full limit on host-fn charges at no cost.

use wasmtime::Caller;

use crate::{host::HostState, runtime::LemmaEngine, state::ContractStateView, VmError};

// ── Gas-charge helper ─────────────────────────────────────────────────────────

/// Charge `cost` gas units against the wasmtime Store fuel (AGENTS §7.5: charge before execute).
///
/// This is the M1 fix: charging Store fuel (not the HostState inner meter) ensures host-fn
/// costs are deducted from the SAME pool as WASM instruction costs, making `wasm_consumed`
/// after `run_wasm` reflect total gas (instructions + host fns).
///
/// Returns `Err` (→ WASM trap → failed receipt) if fuel is insufficient.
fn charge_fuel<T>(caller: &mut Caller<'_, T>, cost: u64) -> Result<(), wasmtime::Error> {
    let remaining = caller.get_fuel()?;
    let new_remaining = remaining
        .checked_sub(cost)
        .ok_or_else(|| wasmtime::Error::msg("out of gas"))?;
    caller.set_fuel(new_remaining)
}

// ── Linker builder ────────────────────────────────────────────────────────────

/// Build a [`wasmtime::Linker`] with all B4 host functions registered.
///
/// All host imports are registered under the `"lemma"` module name.
/// Simple context-query functions are fully wired; memory-taking functions
/// are registered as Phase-3-replaceable stubs.
///
/// # Type parameter
///
/// `S` must be `'static` because `func_wrap` closures must be `'static`
/// (wasmtime requirement — the linker outlives any individual store).
///
/// # Errors
///
/// Returns [`VmError::InstantiationFailed`] if any `func_wrap` call fails
/// (extremely unlikely with correct WASM type signatures).
pub fn build_linker<S: ContractStateView + 'static>(
    engine: &LemmaEngine,
) -> Result<wasmtime::Linker<HostState<S>>, VmError> {
    let mut linker: wasmtime::Linker<HostState<S>> = wasmtime::Linker::new(engine.inner());

    // ── Context query host functions (fully wired, M1 gas charging) ───────────

    // `block_height() -> i64`
    // Returns the current block height from consensus context.
    // M1 fix: charge context_query gas via Store fuel before returning.
    linker
        .func_wrap(
            "lemma",
            "block_height",
            |mut caller: Caller<'_, HostState<S>>| -> Result<i64, wasmtime::Error> {
                // Charge before reading (AGENTS §7.5 — charge-before-execute).
                let cost = caller.data().schedule.context_query.as_u64();
                charge_fuel(&mut caller, cost)?;
                Ok(caller.data().block.height as i64)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `block_timestamp() -> i64`
    // Returns the block timestamp in seconds (from consensus — never wall-clock).
    // M1 fix: charge context_query gas via Store fuel before returning.
    linker
        .func_wrap(
            "lemma",
            "block_timestamp",
            |mut caller: Caller<'_, HostState<S>>| -> Result<i64, wasmtime::Error> {
                // Charge before reading (AGENTS §7.5 — charge-before-execute).
                let cost = caller.data().schedule.context_query.as_u64();
                charge_fuel(&mut caller, cost)?;
                Ok(caller.data().block.timestamp as i64)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `gas_remaining() -> i64`
    // Returns the remaining Store fuel (source of truth after M1 fix).
    // NOTE: does NOT charge itself — charging gas_remaining would be circular
    // (every call would consume gas to report gas, creating infinite OOG loops).
    // Source of truth is Store fuel, not HostState.meter (M1 fix).
    linker
        .func_wrap(
            "lemma",
            "gas_remaining",
            |caller: Caller<'_, HostState<S>>| -> Result<i64, wasmtime::Error> {
                // No gas charge for gas_remaining (would be circular).
                // Source of truth is Store fuel, not HostState.meter (M1 fix).
                caller.get_fuel().map(|f| f as i64)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `msg_value() -> i64`
    // Returns the native LEM value attached to this call (in Drop, truncated to i64).
    // M1 fix: charge context_query gas via Store fuel before returning.
    linker
        .func_wrap(
            "lemma",
            "msg_value",
            |mut caller: Caller<'_, HostState<S>>| -> Result<i64, wasmtime::Error> {
                // Charge before reading (AGENTS §7.5 — charge-before-execute).
                let cost = caller.data().schedule.context_query.as_u64();
                charge_fuel(&mut caller, cost)?;
                // Drop is u128; truncate to i64 for WASM. Full u128 support is Phase 3.
                Ok(caller.data().block.msg_value.as_drop() as i64)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Memory-taking host functions (Phase-3-replaceable stubs) ─────────────
    // These stubs allow any WASM module that imports them to instantiate
    // successfully. Real memory marshalling (ptr/len ABI) is Phase 3.

    // `storage_read(key_ptr: i32, key_len: i32) -> i32`
    // Stub: returns 0 (sentinel — no data). Phase 3 wires real memory access.
    // Gas charging is Phase 3 (memory marshalling required to know key length).
    linker
        .func_wrap(
            "lemma",
            "storage_read",
            |_caller: Caller<'_, HostState<S>>,
             _key_ptr: i32,
             _key_len: i32|
             -> Result<i32, wasmtime::Error> {
                // Phase-3-replaceable ABI stub — returns sentinel 0.
                Ok(0_i32)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `storage_write(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32)`
    // M1 fix: charges real gas via Store fuel so host-fn cost flows into gas_used.
    // Memory marshalling (real key/value read + state write) is 6b-vm-2.
    // NOTE: ignoring _key_ptr/_key_len/_val_ptr/_val_len until 6b-vm-2 wires real memory.
    linker
        .func_wrap(
            "lemma",
            "storage_write",
            |mut caller: Caller<'_, HostState<S>>,
             _key_ptr: i32,
             _key_len: i32,
             _val_ptr: i32,
             _val_len: i32|
             -> Result<(), wasmtime::Error> {
                // Charge gas before any side effect (AGENTS §7.5 — charge-before-execute).
                // Use storage_write_create cost (conservative — real path checks exists() in 6b-vm-2).
                let cost = caller.data().schedule.storage_write_create.as_u64();
                charge_fuel(&mut caller, cost)?;
                // Memory marshalling (real key/value read + state write) is 6b-vm-2.
                Ok(())
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `storage_delete(key_ptr: i32, key_len: i32)`
    // Stub: no-op. Phase 3 wires real memory access.
    linker
        .func_wrap(
            "lemma",
            "storage_delete",
            |_caller: Caller<'_, HostState<S>>,
             _key_ptr: i32,
             _key_len: i32|
             -> Result<(), wasmtime::Error> {
                // Phase-3-replaceable ABI stub — no-op.
                Ok(())
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `emit_event(topics_ptr: i32, topics_len: i32, data_ptr: i32, data_len: i32)`
    // Stub: no-op. Phase 3 wires real event emission with memory marshalling.
    linker
        .func_wrap(
            "lemma",
            "emit_event",
            |_caller: Caller<'_, HostState<S>>,
             _topics_ptr: i32,
             _topics_len: i32,
             _data_ptr: i32,
             _data_len: i32|
             -> Result<(), wasmtime::Error> {
                // Phase-3-replaceable ABI stub — no-op.
                Ok(())
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `transfer(to_ptr: i32, to_len: i32, amount: i64) -> i32`
    // Stub: returns 0 (success sentinel). Phase 3 wires real transfer.
    linker
        .func_wrap(
            "lemma",
            "transfer",
            |_caller: Caller<'_, HostState<S>>,
             _to_ptr: i32,
             _to_len: i32,
             _amount: i64|
             -> Result<i32, wasmtime::Error> {
                // Phase-3-replaceable ABI stub — returns 0 (success sentinel).
                Ok(0_i32)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    Ok(linker)
}
