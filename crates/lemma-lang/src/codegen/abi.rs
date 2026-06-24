//! # ABI byte contract — lemma-lang side (DB-A53)
//!
//! This module is the **lemma-lang half** of the cross-crate ABI byte contract
//! defined in `docs/08-EXECUTION_SPEC.md §4.5` and recorded in `decisions-log.md`
//! DB-A53.
//!
//! It exports the constants that govern:
//! - WASM module/export names (`IMPORT_MODULE`, `ENTRY_POINT`, `MEMORY_EXPORT`)
//! - Well-known register IDs (`REG_CALLDATA`, `REG_SCRATCH`)
//! - Return sentinels for `transfer`, `storage_read`, and `register_len`
//! - The canonical host function name set (`host_fn` submodule)
//! - The canonical host import order (`IMPORT_ORDER`) that determines WASM function
//!   indices — both codegen (this crate) and the VM linker (`lemma-vm`) MUST use
//!   this exact order
//!
//! ## Cross-crate boundary (AGENTS §8)
//!
//! This module MUST NOT import from `lemma-vm`. The ABI contract is shared by
//! publishing constants here (lemma-lang side) and mirroring them in the VM linker
//! (lemma-vm side). The two sides are kept in sync by the spec in §4.5 — not by a
//! shared crate dependency.
//!
//! ## ABI invariant
//!
//! `IMPORT_ORDER` defines the WASM function index of each host import. Inserting or
//! reordering entries is a **breaking ABI change**. New imports MUST be appended at
//! the end. The VM linker (subtask 6b-vm-linker) registers imports in the same order.
//!
//! ## Full ABI emission
//!
//! ABI descriptor emission (function selectors, argument types, JSON) is P3·Step 6i.
//! This module provides only the byte-contract constants used by lowering (6c/6e).
//!
//! ## Dead-code allow
//!
//! All constants in this module are `#[allow(dead_code)]` because the lowering
//! passes that consume them (P3·Step 6c/6e) are not yet implemented. The constants
//! are the spec — they must exist now so the VM linker (subtask 6b-vm-linker) and
//! lowering (6c/6e) can implement against them. Removing the allow would hide the
//! spec behind a compile error until every consumer is built simultaneously.
#![allow(dead_code)]

use crate::type_checker::typed_contract::TypedContract;

// ── WASM module and export names ──────────────────────────────────────────────

/// WASM import module name for all LemmaVM host functions.
///
/// Every host import is declared as `(import "lemma" "<fn_name>" ...)`.
pub(crate) const IMPORT_MODULE: &str = "lemma";

/// WASM export name for the contract entry point.
///
/// The Lem compiler emits exactly one exported function with this name.
/// WASM type: `fn() -> ()` — no value-stack args, no return value.
/// Success = normal return; revert = WASM trap (executor converts to failed receipt).
pub(crate) const ENTRY_POINT: &str = "call";

/// WASM export name for the contract's linear memory.
///
/// The contract module MUST export its memory under this name so the host can
/// access guest memory for `read_register` writes and `value_return` reads.
pub(crate) const MEMORY_EXPORT: &str = "memory";

/// WASM global export name for the guest bump-heap base address.
///
/// Codegen sets this to the first byte past the static data segment (typically
/// page 1 = offset 65536). The guest bump allocator starts here and grows upward.
/// The host never reads this global — it is a codegen-internal layout marker.
pub(crate) const HEAP_BASE_GLOBAL: &str = "__heap_base";

// ── Well-known register IDs ───────────────────────────────────────────────────

/// Register ID for calldata.
///
/// Before invoking `"call"`, the executor writes `tx.data` bytes into this register.
/// The guest pulls calldata via `input(REG_CALLDATA)` or reads register 0 directly.
pub(crate) const REG_CALLDATA: u32 = 0;

/// Register ID for general-purpose scratch use.
///
/// Used by codegen for storage reads and other variable-length host results.
/// Both codegen and the VM linker agree on this ID — it is part of the ABI spec.
pub(crate) const REG_SCRATCH: u32 = 1;

// ── Return sentinels ──────────────────────────────────────────────────────────

/// `transfer()` return value: operation succeeded.
pub(crate) const TRANSFER_OK: i32 = 0;

/// `transfer()` return value: insufficient balance.
pub(crate) const TRANSFER_INSUFFICIENT: i32 = 1;

/// `storage_read()` return value: key was found; value bytes are in the register.
pub(crate) const STORAGE_FOUND: i32 = 0;

/// `storage_read()` return value: key was not found; register is unset.
///
/// Using -1 (not 0) so the guest can distinguish "key absent" from "key present
/// with a zero-length value" (a stored empty value returns `STORAGE_FOUND`).
pub(crate) const STORAGE_NOT_FOUND: i32 = -1;

/// `register_len()` return value when the register has never been written.
///
/// Using -1 (not 0) so the guest can distinguish "register unset" from "register
/// holds a zero-length value". A stored empty value returns 0 from `register_len`.
pub(crate) const REGISTER_EMPTY: i64 = -1;

// ── Host function names ───────────────────────────────────────────────────────

/// Canonical host function names, in canonical import order (DB-A53 §4.5).
///
/// The ORDER of these names in [`IMPORT_ORDER`] defines the WASM function index
/// of each import. Changing this order is an ABI break. Add new imports ONLY at
/// the end of `IMPORT_ORDER`.
pub(crate) mod host_fn {
    /// `block_height() -> i64` — current block height from consensus.
    pub(crate) const BLOCK_HEIGHT: &str = "block_height";

    /// `block_timestamp() -> i64` — block timestamp in seconds (from consensus, never wall-clock).
    pub(crate) const BLOCK_TIMESTAMP: &str = "block_timestamp";

    /// `gas_remaining() -> i64` — remaining gas budget from the FuelMeter.
    pub(crate) const GAS_REMAINING: &str = "gas_remaining";

    /// `msg_value() -> i64` — native LEM value attached to this call (in Drop, truncated to i64).
    pub(crate) const MSG_VALUE: &str = "msg_value";

    /// `msg_sender(register_id: i32)` — writes 20-byte caller `Address` into register.
    ///
    /// Lowering deferred to P3·Step 7 (cross-contract calls). Stub in linker for now.
    pub(crate) const MSG_SENDER: &str = "msg_sender";

    /// `input(register_id: i32)` — writes tx.data (calldata) into the specified register.
    ///
    /// The executor pre-loads calldata into register 0 before invoking `"call"`.
    /// The guest calls `input(REG_CALLDATA)` in its prologue to pull calldata into
    /// a register it can then materialize via `register_len` + `read_register`.
    pub(crate) const INPUT: &str = "input";

    /// `register_len(register_id: i32) -> i64` — byte count of register contents.
    ///
    /// Returns [`REGISTER_EMPTY`] (-1) if the register has never been written.
    /// Returns 0 if the register holds a zero-length value (distinct from absent).
    pub(crate) const REGISTER_LEN: &str = "register_len";

    /// `read_register(register_id: i32, ptr: i32)` — copies register bytes into guest memory at ptr.
    ///
    /// The guest MUST allocate at least `register_len(register_id)` bytes at `ptr`
    /// before calling this function.
    pub(crate) const READ_REGISTER: &str = "read_register";

    /// `storage_read(key_ptr: i32, key_len: i32, register_id: i32) -> i32`
    ///
    /// Reads the value for the key at `guest[key_ptr..key_ptr+key_len]`.
    /// Returns [`STORAGE_FOUND`] (0) and writes value bytes into `register_id` on hit.
    /// Returns [`STORAGE_NOT_FOUND`] (-1) and leaves register unset on miss.
    pub(crate) const STORAGE_READ: &str = "storage_read";

    /// `storage_write(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32)`
    ///
    /// Writes `guest[val_ptr..val_ptr+val_len]` under `guest[key_ptr..key_ptr+key_len]`.
    pub(crate) const STORAGE_WRITE: &str = "storage_write";

    /// `storage_delete(key_ptr: i32, key_len: i32)`
    ///
    /// Removes the entry for `guest[key_ptr..key_ptr+key_len]` from contract storage.
    pub(crate) const STORAGE_DELETE: &str = "storage_delete";

    /// `emit_event(topics_ptr: i32, topics_len: i32, data_ptr: i32, data_len: i32)`
    ///
    /// Emits a contract event. Topics are a flat byte slice of 32-byte hashes.
    pub(crate) const EMIT_EVENT: &str = "emit_event";

    /// `transfer(to_ptr: i32, to_len: i32, amount: i64) -> i32`
    ///
    /// Transfers `amount` Drop to the address at `guest[to_ptr..to_ptr+to_len]`.
    /// Returns [`TRANSFER_OK`] (0) on success, [`TRANSFER_INSUFFICIENT`] (1) on
    /// insufficient balance. Never panics (AGENTS §7.2, Sui-stall lesson).
    pub(crate) const TRANSFER: &str = "transfer";

    /// `value_return(ptr: i32, len: i32)`
    ///
    /// Returns `guest[ptr..ptr+len]` as the call's return data. The host copies
    /// the bytes immediately (before the WASM stack unwinds). The guest must not
    /// reuse `ptr` before `value_return` returns.
    pub(crate) const VALUE_RETURN: &str = "value_return";

    /// `call_contract(addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64, value: i64) -> i32`
    ///
    /// Executes the contract at address `addr` with `calldata` from register `data_reg`,
    /// forwarding `gas` (capped at 63/64 of remaining) and `value` Drop.
    /// Returns result register ID on success, or a negative error sentinel on failure.
    /// Callee state writes are merged into caller state on success, discarded on revert.
    /// Uses 63/64 gas forwarding rule (08-EXECUTION_SPEC §2.4).
    pub(crate) const CALL_CONTRACT: &str = "call_contract";

    /// `static_call(addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64) -> i32`
    ///
    /// Same as `call_contract` but ALL callee state writes are discarded — only return
    /// data flows back. Read-only enforced at the host level.
    /// No value parameter (static calls cannot transfer value).
    pub(crate) const STATIC_CALL: &str = "static_call";

    /// `delegate_call(addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64) -> i32`
    ///
    /// Runs callee's WASM code with CALLER's storage namespace and msg.sender context.
    /// Storage reads/writes land in caller's address space, not callee's.
    /// Requires `#[allowDelegate]` annotation at call site (SAFETY-011).
    pub(crate) const DELEGATE_CALL: &str = "delegate_call";
}

// ── Canonical import order ────────────────────────────────────────────────────

/// Canonical host import order for the WASM import section (DB-A53 §4.5, AGENTS §7.1).
///
/// Both codegen (lemma-lang) and the VM linker (lemma-vm) MUST declare/register
/// imports in this exact order. The position of each name is its WASM function index.
///
/// **ABI invariant**: new imports MUST be appended; inserting or reordering is a
/// breaking change that shifts every subsequent function index.
///
/// The contract's first own function has WASM index [`HOST_IMPORT_COUNT`].
pub(crate) const IMPORT_ORDER: &[&str] = &[
    host_fn::BLOCK_HEIGHT,    // index 0
    host_fn::BLOCK_TIMESTAMP, // index 1
    host_fn::GAS_REMAINING,   // index 2
    host_fn::MSG_VALUE,       // index 3
    host_fn::MSG_SENDER,      // index 4
    host_fn::INPUT,           // index 5
    host_fn::REGISTER_LEN,    // index 6
    host_fn::READ_REGISTER,   // index 7
    host_fn::STORAGE_READ,    // index 8
    host_fn::STORAGE_WRITE,   // index 9
    host_fn::STORAGE_DELETE,  // index 10
    host_fn::EMIT_EVENT,      // index 11
    host_fn::TRANSFER,        // index 12
    host_fn::VALUE_RETURN,    // index 13
    host_fn::CALL_CONTRACT,   // index 14
    host_fn::STATIC_CALL,     // index 15
    host_fn::DELEGATE_CALL,   // index 16
];

/// Number of host imports.
///
/// The contract's first own function has WASM function index `HOST_IMPORT_COUNT`.
/// Computed from `IMPORT_ORDER.len()` — never a hardcoded integer — so it stays
/// correct when new imports are appended.
pub(crate) const HOST_IMPORT_COUNT: u32 = IMPORT_ORDER.len() as u32;

// ── Host function index constants ─────────────────────────────────────────────
//
// These constants derive the WASM function index of each cross-contract call
// host function from its position in IMPORT_ORDER. Using named constants here
// instead of magic integers (AGENTS §3.3) ensures that if IMPORT_ORDER is ever
// extended, the indices stay in sync automatically.
//
// The `position()` call is O(n) at runtime but n=17 — negligible. The compiler
// may constant-fold these at compile time since IMPORT_ORDER is a `const`.

/// WASM function index for `call_contract` — derived from IMPORT_ORDER position.
///
/// Replaces the magic literal `14` in cross-contract call lowering (AGENTS §3.3).
/// If IMPORT_ORDER is reordered (an ABI break), this constant updates automatically.
pub(crate) const CALL_CONTRACT_INDEX: u32 = {
    let mut i = 0u32;
    while i < IMPORT_ORDER.len() as u32 {
        if const_str_eq(IMPORT_ORDER[i as usize], host_fn::CALL_CONTRACT) {
            break;
        }
        i += 1;
    }
    i
};

/// WASM function index for `static_call` — derived from IMPORT_ORDER position.
///
/// Replaces the magic literal `15` in cross-contract call lowering (AGENTS §3.3).
pub(crate) const STATIC_CALL_INDEX: u32 = {
    let mut i = 0u32;
    while i < IMPORT_ORDER.len() as u32 {
        if const_str_eq(IMPORT_ORDER[i as usize], host_fn::STATIC_CALL) {
            break;
        }
        i += 1;
    }
    i
};

/// WASM function index for `delegate_call` — derived from IMPORT_ORDER position.
///
/// Replaces the magic literal `16` in cross-contract call lowering (AGENTS §3.3).
pub(crate) const DELEGATE_CALL_INDEX: u32 = {
    let mut i = 0u32;
    while i < IMPORT_ORDER.len() as u32 {
        if const_str_eq(IMPORT_ORDER[i as usize], host_fn::DELEGATE_CALL) {
            break;
        }
        i += 1;
    }
    i
};

/// Const-compatible byte-by-byte string equality helper.
///
/// Rust's `const fn` context does not support `==` on `&str` directly (as of
/// stable Rust 1.78). This helper provides a const-evaluable comparison used
/// only in the index constant initialisers above.
const fn const_str_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// ── ABI descriptor emission (P3·Step 6i) ─────────────────────────────────────

use serde::Serialize;

use crate::parser::Visibility;
use crate::type_checker::types::SymbolSig;

use super::wasm::{compute_selector, type_canonical_name};

/// A single parameter in the ABI descriptor.
///
/// `type` is the canonical Lem type name (e.g. `"Address"`, `"u128"`, `"bool"`).
#[derive(Serialize)]
struct ParamDescriptor {
    name: String,
    #[serde(rename = "type")]
    ty: String,
}

/// ABI descriptor for one public contract function.
///
/// `selector` is the 4-byte LE blake3 dispatch selector used in calldata
/// (see `compute_selector` in `wasm.rs` and DB-A53 §4.5).
#[derive(Serialize)]
struct FunctionDescriptor {
    name: String,
    /// 4-byte LE function selector (u32). Callers encode as little-endian bytes.
    selector: u32,
    params: Vec<ParamDescriptor>,
    /// Canonical return type name, or `"()"` for unit functions.
    returns: String,
}

/// Build the contract ABI descriptor as a JSON byte array.
///
/// Returns a UTF-8 JSON `[{"name":…,"selector":…,"params":[…],"returns":…}, …]`
/// array containing one entry per **public** contract function (visibility `pub`
/// or `external`). Private functions and modifiers are excluded.
///
/// The output is embedded in the `"lemma.abi"` WASM custom section by
/// `emit_module` (P3·Step 6i). It is also the basis for off-chain ABI tooling
/// (SDK ABI encoding, explorer display, wallet contract interaction).
///
/// ## Determinism
///
/// Functions are emitted in the order returned by [`TypedContract::functions`],
/// which preserves source declaration order. Param names and types come from
/// the resolved symbol arena (deterministic across compilations of the same
/// source). The JSON serializer is deterministic for structs (no map iteration).
///
/// ## Error handling
///
/// If a function's selector cannot be computed (missing symbol — should not
/// occur for well-formed programs), the error is **propagated**, never skipped.
/// `emit_module` computes the same selectors for its dispatch table, so the ABI
/// function set and the dispatch function set must always agree on which
/// functions exist — silently skipping one here (the old behaviour) could make
/// the ABI and the live dispatch table disagree (L-2 asymmetry bug). Selector
/// *collisions* across the dispatchable set are caught earlier by
/// `detect_selector_collisions` in `emit_module`.
///
/// # Errors
///
/// Returns [`crate::error::LangError::Codegen`] if any public function's
/// selector cannot be computed.
// consumer: codegen/wasm.rs "lemma.abi" custom-section embed (P3·Step 6i)
pub(crate) fn build_abi(contract: &TypedContract<'_>) -> Result<Vec<u8>, crate::error::LangError> {
    let mut descriptors: Vec<FunctionDescriptor> = Vec::new();

    // Selector set guard: a standalone build_abi caller (ABI-only tooling) must
    // also reject colliding selectors, not just the emit_module pipeline (L-2, 🔵-1).
    let mut seen_selectors: std::collections::BTreeMap<u32, String> =
        std::collections::BTreeMap::new();

    for func in contract.functions() {
        // Include only externally-callable functions WITH a body. This filter
        // MUST be character-for-character identical to emit_module's dispatch
        // filter (wasm.rs) — a body-less `pub fn` (interface signature) would
        // otherwise land in the ABI but not the dispatch table (L-2 asymmetry).
        // Modifiers, private helpers, and receive/fallback specials are
        // dispatched differently (not via the selector mechanism).
        if !matches!(func.visibility, Visibility::Pub | Visibility::External) {
            continue;
        }
        if func.body.is_none() {
            continue;
        }

        // Compute 4-byte selector (blake3 over canonical signature string).
        // Propagate on failure — the ABI function set MUST match the dispatch
        // function set that emit_module builds from the same selectors (L-2).
        let selector = compute_selector(&func, contract)?;

        // Reject duplicate selectors at the ABI layer too (L-2, idempotent with
        // emit_module's detect_selector_collisions).
        if let Some(prev) = seen_selectors.insert(selector, func.name.to_string()) {
            return Err(crate::error::LangError::Codegen {
                message: format!(
                    "selector collision between {prev}() and {}() (selector {selector:#010x})",
                    func.name
                ),
            });
        }

        // Resolve parameter names + canonical types from the symbol arena.
        // The FnSig carries (name: String, ty: ResolvedType, has_default: bool).
        let params: Vec<ParamDescriptor> = match func.symbol_id {
            Some(sym_id) => match contract.sig(sym_id) {
                Some(SymbolSig::Function(fn_sig)) => fn_sig
                    .params
                    .iter()
                    .map(|(name, ty, _)| ParamDescriptor {
                        name: name.clone(),
                        ty: type_canonical_name(ty),
                    })
                    .collect(),
                _ => Vec::new(),
            },
            None => Vec::new(),
        };

        // Return type — Unit/no-annotation functions use "()" for ABI consumers.
        let returns = func
            .return_type
            .as_ref()
            .map(type_canonical_name)
            .unwrap_or_else(|| "()".into());

        descriptors.push(FunctionDescriptor {
            name: func.name.to_owned(),
            selector,
            params,
            returns,
        });
    }

    // Serialize to JSON bytes. Infallible for our fully-serializable types
    // (structs with String/u32/Vec fields). unwrap_or_default returns empty
    // on the impossible error (serde_json only fails for non-serializable types
    // or recursive references, which our types don't have).
    Ok(serde_json::to_vec(&descriptors).unwrap_or_default())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
