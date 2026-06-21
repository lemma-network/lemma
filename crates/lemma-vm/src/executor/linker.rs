//! # Linker — wasmtime host-function registration (6b-vm-2)
//!
//! Builds a [`wasmtime::Linker`] with all 17 LemmaVM host functions registered
//! under the `"lemma"` import module.
//!
//! ## Import convention
//!
//! All host imports use the form `(import "lemma" "fn_name" ...)`.
//! The WASM type mapping for memory-taking host functions uses a raw
//! pointer/length ABI (`i32` ptr + `i32` len). The canonical import order
//! matches `lemma-lang/src/codegen/abi.rs::IMPORT_ORDER` (DB-A53 §4.5).
//!
//! ## 17 host functions (canonical order)
//!
//! | Index | Name            | Signature                                                                    |
//! |-------|-----------------|------------------------------------------------------------------------------|
//! |  0    | block_height    | `() -> i64`                                                                  |
//! |  1    | block_timestamp | `() -> i64`                                                                  |
//! |  2    | gas_remaining   | `() -> i64`                                                                  |
//! |  3    | msg_value       | `() -> i64`                                                                  |
//! |  4    | msg_sender      | `(register_id: i32)`                                                         |
//! |  5    | input           | `(register_id: i32)`                                                         |
//! |  6    | register_len    | `(register_id: i32) -> i64`                                                  |
//! |  7    | read_register   | `(register_id: i32, ptr: i32)`                                               |
//! |  8    | storage_read    | `(key_ptr: i32, key_len: i32, reg: i32) -> i32`                              |
//! |  9    | storage_write   | `(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32)`                   |
//! | 10    | storage_delete  | `(key_ptr: i32, key_len: i32)`                                               |
//! | 11    | emit_event      | `(topics_ptr: i32, topics_len: i32, data_ptr: i32, data_len: i32)`           |
//! | 12    | transfer        | `(to_ptr: i32, to_len: i32, amount: i64) -> i32`                             |
//! | 13    | value_return    | `(ptr: i32, len: i32)`                                                       |
//! | 14    | call_contract   | `(addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64, value: i64) -> i32` |
//! | 15    | static_call     | `(addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64) -> i32`             |
//! | 16    | delegate_call   | `(addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64) -> i32`             |
//!
//! Indices 14–16 are registered as stubs that trap with `"not implemented"`.
//! Full implementations land in P3·Step 21 subtasks 02–04.
//!
//! ## Gas model
//!
//! Host-function gas charges are deducted from the wasmtime Store fuel via
//! `charge_fuel` (caller.set_fuel). This ensures host-fn costs flow into
//! `wasm_consumed` (= initial_fuel − store.get_fuel()) in executor.rs.
//!
//! Memory-taking functions additionally charge `memory_copy_per_byte × len`
//! for each host↔guest memory copy (DoS protection).
//!
//! Storage/transfer/emit_event functions use the sync-wrap pattern to reuse
//! the tested `HostFunctions` trait methods: sync Store fuel → FuelMeter,
//! call trait method, sync FuelMeter → Store fuel.

use lemma_core::{address::Address, amount::Amount, hash::Hash};
use wasmtime::{Caller, Memory};

use crate::{
    gas::{Gas, GasMeter},
    host::{HostFunctions, HostState},
    runtime::LemmaEngine,
    state::ContractStateView,
    VmError,
};

// ── Gas-charge helper ─────────────────────────────────────────────────────────

/// Charge `cost` gas units against the wasmtime Store fuel (AGENTS §7.5: charge before execute).
///
/// Returns `Err` (→ WASM trap → failed receipt) if fuel is insufficient.
fn charge_fuel<T>(caller: &mut Caller<'_, T>, cost: u64) -> Result<(), wasmtime::Error> {
    let remaining = caller.get_fuel()?;
    let new_remaining = remaining
        .checked_sub(cost)
        .ok_or_else(|| wasmtime::Error::msg("out of gas"))?;
    caller.set_fuel(new_remaining)
}

// ── Memory marshalling helpers (private, DRY core — AGENTS §2) ───────────────

/// Resolve the guest's exported `"memory"`. Trap if absent (ABI invariant).
fn get_memory<T: 'static>(caller: &mut Caller<'_, T>) -> Result<Memory, wasmtime::Error> {
    caller
        .get_export("memory")
        .and_then(|ext| ext.into_memory())
        .ok_or_else(|| wasmtime::Error::msg("contract must export \"memory\""))
}

/// Read `len` bytes from guest memory at `ptr`. Charges `memory_copy_per_byte × len`
/// against Store fuel BEFORE reading (AGENTS §7.5: charge before side effect).
/// Traps on OOB or OOG. Uses `Memory::read` (bounds-checked, never panics).
fn read_guest_bytes<S: ContractStateView + 'static>(
    caller: &mut Caller<'_, HostState<S>>,
    mem: &Memory,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, wasmtime::Error> {
    let ptr = ptr as u32 as usize;
    let len = len as u32 as usize;
    // Charge per-byte copy gas BEFORE reading.
    let copy_cost = caller
        .data()
        .schedule
        .memory_copy_per_byte
        .as_u64()
        .checked_mul(len as u64)
        .ok_or_else(|| wasmtime::Error::msg("memory copy gas overflow"))?;
    charge_fuel(caller, copy_cost)?;
    // Bounds-checked read — never panics (Memory::read returns MemoryAccessError on OOB).
    let mut buf = vec![0u8; len];
    mem.read(caller, ptr, &mut buf)
        .map_err(|_| wasmtime::Error::msg("memory read out of bounds"))?;
    Ok(buf)
}

/// Write `bytes` to guest memory at `ptr`. Charges `memory_copy_per_byte × bytes.len()`
/// against Store fuel BEFORE writing (AGENTS §7.5). Traps on OOB or OOG.
fn write_guest_bytes<S: ContractStateView + 'static>(
    caller: &mut Caller<'_, HostState<S>>,
    mem: &Memory,
    ptr: i32,
    bytes: &[u8],
) -> Result<(), wasmtime::Error> {
    let ptr = ptr as u32 as usize;
    let copy_cost = caller
        .data()
        .schedule
        .memory_copy_per_byte
        .as_u64()
        .checked_mul(bytes.len() as u64)
        .ok_or_else(|| wasmtime::Error::msg("memory copy gas overflow"))?;
    charge_fuel(caller, copy_cost)?;
    mem.write(caller, ptr, bytes)
        .map_err(|_| wasmtime::Error::msg("memory write out of bounds"))?;
    Ok(())
}

// ── Linker builder ────────────────────────────────────────────────────────────

/// Build a [`wasmtime::Linker`] with all 17 host functions registered.
///
/// All host imports are registered under the `"lemma"` module name.
/// Registration order matches the canonical import order from
/// `lemma-lang/src/codegen/abi.rs::IMPORT_ORDER` (DB-A53 §4.5).
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

    // ── Index 0: block_height() -> i64 ───────────────────────────────────────

    linker
        .func_wrap(
            "lemma",
            "block_height",
            |mut caller: Caller<'_, HostState<S>>| -> Result<i64, wasmtime::Error> {
                let cost = caller.data().schedule.context_query.as_u64();
                charge_fuel(&mut caller, cost)?;
                Ok(caller.data().block.height as i64)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 1: block_timestamp() -> i64 ────────────────────────────────────

    linker
        .func_wrap(
            "lemma",
            "block_timestamp",
            |mut caller: Caller<'_, HostState<S>>| -> Result<i64, wasmtime::Error> {
                let cost = caller.data().schedule.context_query.as_u64();
                charge_fuel(&mut caller, cost)?;
                Ok(caller.data().block.timestamp as i64)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 2: gas_remaining() -> i64 ──────────────────────────────────────
    // NOTE: does NOT charge itself — charging gas_remaining would be circular.

    linker
        .func_wrap(
            "lemma",
            "gas_remaining",
            |caller: Caller<'_, HostState<S>>| -> Result<i64, wasmtime::Error> {
                caller.get_fuel().map(|f| f as i64)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 3: msg_value() -> i64 ──────────────────────────────────────────

    linker
        .func_wrap(
            "lemma",
            "msg_value",
            |mut caller: Caller<'_, HostState<S>>| -> Result<i64, wasmtime::Error> {
                let cost = caller.data().schedule.context_query.as_u64();
                charge_fuel(&mut caller, cost)?;
                Ok(caller.data().block.msg_value.as_drop() as i64)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 4: msg_sender(register_id: i32) ───────────────────────────────
    // Writes the 20-byte caller address into the specified register.

    linker
        .func_wrap(
            "lemma",
            "msg_sender",
            |mut caller: Caller<'_, HostState<S>>,
             register_id: i32|
             -> Result<(), wasmtime::Error> {
                let cost = caller.data().schedule.context_query.as_u64();
                charge_fuel(&mut caller, cost)?;
                let addr_bytes = caller.data().block.msg_sender.as_bytes().to_vec();
                caller
                    .data_mut()
                    .registers
                    .insert(register_id as u32, addr_bytes);
                Ok(())
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 5: input(register_id: i32) ─────────────────────────────────────
    // Writes tx.data (calldata) into the specified register.

    linker
        .func_wrap(
            "lemma",
            "input",
            |mut caller: Caller<'_, HostState<S>>,
             register_id: i32|
             -> Result<(), wasmtime::Error> {
                let calldata = caller.data().calldata.clone();
                // Per-byte gas for calldata copy into register.
                let copy_cost = caller
                    .data()
                    .schedule
                    .memory_copy_per_byte
                    .as_u64()
                    .checked_mul(calldata.len() as u64)
                    .ok_or_else(|| wasmtime::Error::msg("input gas overflow"))?;
                charge_fuel(&mut caller, copy_cost)?;
                caller
                    .data_mut()
                    .registers
                    .insert(register_id as u32, calldata);
                Ok(())
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 6: register_len(register_id: i32) -> i64 ──────────────────────
    // Infallible — no memory access, no gas charge. Returns -1 for unset registers.

    linker
        .func_wrap(
            "lemma",
            "register_len",
            |caller: Caller<'_, HostState<S>>, register_id: i32| -> i64 {
                caller
                    .data()
                    .registers
                    .get(&(register_id as u32))
                    .map(|v| v.len() as i64)
                    .unwrap_or(-1_i64) // REGISTER_EMPTY sentinel (DB-A53 §4.5)
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 7: read_register(register_id: i32, ptr: i32) ──────────────────
    // Copies register bytes into guest memory at ptr.

    linker
        .func_wrap(
            "lemma",
            "read_register",
            |mut caller: Caller<'_, HostState<S>>,
             register_id: i32,
             ptr: i32|
             -> Result<(), wasmtime::Error> {
                let mem = get_memory(&mut caller)?;
                let data = caller
                    .data()
                    .registers
                    .get(&(register_id as u32))
                    .cloned()
                    .ok_or_else(|| wasmtime::Error::msg("read_register: register not set"))?;
                write_guest_bytes(&mut caller, &mem, ptr, &data)?;
                Ok(())
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 8: storage_read(key_ptr, key_len, register_id) -> i32 ─────────
    // Reads key from guest memory, calls trait storage_read, writes result to register.
    // Returns 0 (STORAGE_FOUND) or -1 (STORAGE_NOT_FOUND).
    //
    // M4 RESOLVED (P3·Step 7 subtask_08): ScratchSnapshot now reads through to
    // canonical state for keys not written in the current tx. See executor.rs
    // ScratchSnapshot::read and CanonicalStateRead trait.

    linker
        .func_wrap(
            "lemma",
            "storage_read",
            |mut caller: Caller<'_, HostState<S>>,
             key_ptr: i32,
             key_len: i32,
             register_id: i32|
             -> Result<i32, wasmtime::Error> {
                let mem = get_memory(&mut caller)?;
                let key = read_guest_bytes(&mut caller, &mem, key_ptr, key_len)?;
                // Sync down: Store fuel → FuelMeter
                let fuel = caller.get_fuel()?;
                caller.data_mut().meter.set_remaining(Gas::new(fuel));
                // Call trait method (charges meter — reuses all tested gas logic).
                let result = caller.data_mut().storage_read(&key);
                // Sync up: FuelMeter → Store fuel
                let remaining = caller.data().meter.remaining();
                caller.set_fuel(remaining.as_u64())?;
                let opt_value = result.map_err(|e| wasmtime::Error::msg(e.to_string()))?;
                match opt_value {
                    Some(value) => {
                        caller
                            .data_mut()
                            .registers
                            .insert(register_id as u32, value);
                        Ok(0) // STORAGE_FOUND
                    }
                    None => Ok(-1_i32), // STORAGE_NOT_FOUND
                }
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 9: storage_write(key_ptr, key_len, val_ptr, val_len) ───────────
    // Reads key+value from guest memory, calls trait storage_write.

    linker
        .func_wrap(
            "lemma",
            "storage_write",
            |mut caller: Caller<'_, HostState<S>>,
             key_ptr: i32,
             key_len: i32,
             val_ptr: i32,
             val_len: i32|
             -> Result<(), wasmtime::Error> {
                let mem = get_memory(&mut caller)?;
                let key = read_guest_bytes(&mut caller, &mem, key_ptr, key_len)?;
                let value = read_guest_bytes(&mut caller, &mem, val_ptr, val_len)?;
                // Sync down: Store fuel → FuelMeter
                let fuel = caller.get_fuel()?;
                caller.data_mut().meter.set_remaining(Gas::new(fuel));
                // Call trait method (charges meter — warm/cold/create/update logic).
                let result = caller.data_mut().storage_write(&key, &value);
                // Sync up: FuelMeter → Store fuel
                let remaining = caller.data().meter.remaining();
                caller.set_fuel(remaining.as_u64())?;
                result.map_err(|e| wasmtime::Error::msg(e.to_string()))
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 10: storage_delete(key_ptr, key_len) ───────────────────────────

    linker
        .func_wrap(
            "lemma",
            "storage_delete",
            |mut caller: Caller<'_, HostState<S>>,
             key_ptr: i32,
             key_len: i32|
             -> Result<(), wasmtime::Error> {
                let mem = get_memory(&mut caller)?;
                let key = read_guest_bytes(&mut caller, &mem, key_ptr, key_len)?;
                // Sync down + call trait + sync up
                let fuel = caller.get_fuel()?;
                caller.data_mut().meter.set_remaining(Gas::new(fuel));
                let result = caller.data_mut().storage_delete(&key);
                let remaining = caller.data().meter.remaining();
                caller.set_fuel(remaining.as_u64())?;
                result.map_err(|e| wasmtime::Error::msg(e.to_string()))
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 11: emit_event(topics_ptr, topics_len, data_ptr, data_len) ─────
    // Topics are a flat byte slice of 32-byte hashes; topics_len MUST be a multiple of 32.

    linker
        .func_wrap(
            "lemma",
            "emit_event",
            |mut caller: Caller<'_, HostState<S>>,
             topics_ptr: i32,
             topics_len: i32,
             data_ptr: i32,
             data_len: i32|
             -> Result<(), wasmtime::Error> {
                let mem = get_memory(&mut caller)?;
                let topics_bytes = read_guest_bytes(&mut caller, &mem, topics_ptr, topics_len)?;
                let data = read_guest_bytes(&mut caller, &mem, data_ptr, data_len)?;
                // Decode topics: each topic is a 32-byte Hash. topics_len MUST be a multiple of 32.
                if topics_bytes.len() % 32 != 0 {
                    return Err(wasmtime::Error::msg(
                        "emit_event: topics_len must be a multiple of 32",
                    ));
                }
                let topics: Vec<Hash> = topics_bytes
                    .chunks_exact(32)
                    .map(|chunk| {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(chunk);
                        Hash::from_bytes(arr)
                    })
                    .collect();
                // Sync down + call trait + sync up
                let fuel = caller.get_fuel()?;
                caller.data_mut().meter.set_remaining(Gas::new(fuel));
                let result = caller.data_mut().emit_event(&topics, &data);
                let remaining = caller.data().meter.remaining();
                caller.set_fuel(remaining.as_u64())?;
                result.map_err(|e| wasmtime::Error::msg(e.to_string()))
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 12: transfer(to_ptr, to_len, amount) -> i32 ───────────────────
    // Returns 0 (TRANSFER_OK) or 1 (TRANSFER_INSUFFICIENT).
    // Address must be exactly 20 bytes (Lemma address size).
    // Negative i64 amount → trap (not silent cast to huge u128).

    linker
        .func_wrap(
            "lemma",
            "transfer",
            |mut caller: Caller<'_, HostState<S>>,
             to_ptr: i32,
             to_len: i32,
             amount: i64|
             -> Result<i32, wasmtime::Error> {
                let mem = get_memory(&mut caller)?;
                let to_bytes = read_guest_bytes(&mut caller, &mem, to_ptr, to_len)?;
                // Address MUST be exactly 20 bytes (Lemma address size).
                if to_bytes.len() != 20 {
                    return Err(wasmtime::Error::msg(
                        "transfer: address must be exactly 20 bytes",
                    ));
                }
                // Negative amount → trap (not silent cast to huge u128).
                if amount < 0 {
                    return Err(wasmtime::Error::msg("transfer: negative amount"));
                }
                let amount_u128 = amount as u64 as u128;
                let transfer_amount = Amount::from_drop(amount_u128);
                let mut addr_arr = [0u8; 20];
                addr_arr.copy_from_slice(&to_bytes);
                let to_addr = Address::from_raw_bytes(addr_arr);
                // Sync down + call trait + sync up
                let fuel = caller.get_fuel()?;
                caller.data_mut().meter.set_remaining(Gas::new(fuel));
                let result = caller.data_mut().transfer(to_addr, transfer_amount);
                let remaining = caller.data().meter.remaining();
                caller.set_fuel(remaining.as_u64())?;
                match result {
                    Ok(()) => Ok(0),                                 // TRANSFER_OK
                    Err(VmError::InsufficientFunds { .. }) => Ok(1), // TRANSFER_INSUFFICIENT
                    Err(e) => Err(wasmtime::Error::msg(e.to_string())),
                }
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 13: value_return(ptr, len) ─────────────────────────────────────
    // Captures guest return data into host state. Consumed by cross-contract
    // calls in P3·Step 7; for now extracted and dropped in execute_call.

    linker
        .func_wrap(
            "lemma",
            "value_return",
            |mut caller: Caller<'_, HostState<S>>,
             ptr: i32,
             len: i32|
             -> Result<(), wasmtime::Error> {
                let mem = get_memory(&mut caller)?;
                let data = read_guest_bytes(&mut caller, &mem, ptr, len)?;
                caller.data_mut().return_data = data;
                Ok(())
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 14: call_contract(addr_ptr, addr_len, data_reg, gas, value) -> i32
    // Stub — full implementation in P3·Step 21 subtask_02.
    // Registered here so WASM modules with 17 imports can be instantiated.
    // Traps if called — contracts must not invoke cross-contract calls until
    // the full implementation lands.

    linker
        .func_wrap(
            "lemma",
            "call_contract",
            |_caller: Caller<'_, HostState<S>>,
             _addr_ptr: i32,
             _addr_len: i32,
             _data_reg: i32,
             _gas: i64,
             _value: i64|
             -> Result<i32, wasmtime::Error> {
                Err(wasmtime::Error::msg(
                    "call_contract: not implemented (P3·Step 21 subtask_02)",
                ))
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 15: static_call(addr_ptr, addr_len, data_reg, gas) -> i32
    // Stub — full implementation in P3·Step 21 subtask_03.

    linker
        .func_wrap(
            "lemma",
            "static_call",
            |_caller: Caller<'_, HostState<S>>,
             _addr_ptr: i32,
             _addr_len: i32,
             _data_reg: i32,
             _gas: i64|
             -> Result<i32, wasmtime::Error> {
                Err(wasmtime::Error::msg(
                    "static_call: not implemented (P3·Step 21 subtask_03)",
                ))
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    // ── Index 16: delegate_call(addr_ptr, addr_len, data_reg, gas) -> i32
    // Stub — full implementation in P3·Step 21 subtask_04.

    linker
        .func_wrap(
            "lemma",
            "delegate_call",
            |_caller: Caller<'_, HostState<S>>,
             _addr_ptr: i32,
             _addr_len: i32,
             _data_reg: i32,
             _gas: i64|
             -> Result<i32, wasmtime::Error> {
                Err(wasmtime::Error::msg(
                    "delegate_call: not implemented (P3·Step 21 subtask_04)",
                ))
            },
        )
        .map_err(|e| VmError::InstantiationFailed {
            reason: e.to_string(),
        })?;

    Ok(linker)
}
