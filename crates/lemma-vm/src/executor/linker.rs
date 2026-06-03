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

use wasmtime::Caller;

use crate::{
    error::VmError, gas::GasMeter, host::HostState, runtime::LemmaEngine, state::ContractStateView,
};

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

    // ── Context query host functions (fully wired) ────────────────────────────

    // `block_height() -> i64`
    // Returns the current block height from consensus context.
    linker
        .func_wrap(
            "lemma",
            "block_height",
            |caller: Caller<'_, HostState<S>>| -> i64 { caller.data().block.height as i64 },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `block_timestamp() -> i64`
    // Returns the block timestamp in seconds (from consensus — never wall-clock).
    linker
        .func_wrap(
            "lemma",
            "block_timestamp",
            |caller: Caller<'_, HostState<S>>| -> i64 { caller.data().block.timestamp as i64 },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `gas_remaining() -> i64`
    // Returns the remaining gas budget from the FuelMeter.
    linker
        .func_wrap(
            "lemma",
            "gas_remaining",
            |caller: Caller<'_, HostState<S>>| -> i64 {
                caller.data().meter.remaining().as_u64() as i64
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `msg_value() -> i64`
    // Returns the native LEM value attached to this call (in Drop, truncated to i64).
    linker
        .func_wrap(
            "lemma",
            "msg_value",
            |caller: Caller<'_, HostState<S>>| -> i64 {
                // Drop is u128; truncate to i64 for WASM. Full u128 support is Phase 3.
                caller.data().block.msg_value.as_drop() as i64
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
    linker
        .func_wrap(
            "lemma",
            "storage_read",
            |_caller: Caller<'_, HostState<S>>, _key_ptr: i32, _key_len: i32| -> i32 {
                // Phase-3-replaceable ABI stub — returns sentinel 0.
                0_i32
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // `storage_write(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32)`
    // Stub: no-op. Phase 3 wires real memory access.
    linker
        .func_wrap(
            "lemma",
            "storage_write",
            |_caller: Caller<'_, HostState<S>>,
             _key_ptr: i32,
             _key_len: i32,
             _val_ptr: i32,
             _val_len: i32| {
                // Phase-3-replaceable ABI stub — no-op.
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
            |_caller: Caller<'_, HostState<S>>, _key_ptr: i32, _key_len: i32| {
                // Phase-3-replaceable ABI stub — no-op.
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
             _data_len: i32| {
                // Phase-3-replaceable ABI stub — no-op.
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
            |_caller: Caller<'_, HostState<S>>, _to_ptr: i32, _to_len: i32, _amount: i64| -> i32 {
                // Phase-3-replaceable ABI stub — returns 0 (success sentinel).
                0_i32
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    Ok(linker)
}
