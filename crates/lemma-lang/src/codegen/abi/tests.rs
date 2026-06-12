//! Tests for `codegen::abi` — ABI byte contract constants (DB-A53).
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.
//! Test naming: `{action}_{outcome}` (AGENTS §11.3).
//!
//! These tests verify the correctness and internal consistency of the ABI
//! constants defined in `codegen/abi.rs`. They are the compile-time guard
//! that catches accidental ABI breaks (reordering, duplicates, wrong sentinels).

use std::collections::BTreeSet;

use crate::codegen::abi::{
    build_abi, host_fn, ENTRY_POINT, HEAP_BASE_GLOBAL, HOST_IMPORT_COUNT, IMPORT_MODULE,
    IMPORT_ORDER, MEMORY_EXPORT, REGISTER_EMPTY, REG_CALLDATA, REG_SCRATCH, STORAGE_FOUND,
    STORAGE_NOT_FOUND, TRANSFER_INSUFFICIENT, TRANSFER_OK,
};
use crate::type_checker::TypedAst;
use crate::{parse, tokenize};

// ─── Shared fixtures ──────────────────────────────────────────────────────────

fn typed_ast_for(src: &str) -> TypedAst {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    crate::type_checker::check_skip_wf(ast).expect("check_skip_wf failed")
}

// ─── WASM name constants ──────────────────────────────────────────────────────

#[test]
fn import_module_is_nonempty_string() {
    assert!(!IMPORT_MODULE.is_empty(), "IMPORT_MODULE must not be empty");
}

#[test]
fn entry_point_is_nonempty_string() {
    assert!(!ENTRY_POINT.is_empty(), "ENTRY_POINT must not be empty");
}

#[test]
fn memory_export_is_nonempty_string() {
    assert!(!MEMORY_EXPORT.is_empty(), "MEMORY_EXPORT must not be empty");
}

#[test]
fn heap_base_global_is_nonempty_string() {
    assert!(
        !HEAP_BASE_GLOBAL.is_empty(),
        "HEAP_BASE_GLOBAL must not be empty"
    );
}

// ─── Register IDs ─────────────────────────────────────────────────────────────

#[test]
fn reg_calldata_and_scratch_are_distinct() {
    // Two distinct well-known registers must not alias each other.
    assert_ne!(
        REG_CALLDATA, REG_SCRATCH,
        "REG_CALLDATA and REG_SCRATCH must be distinct register IDs"
    );
}

// ─── Sentinels ────────────────────────────────────────────────────────────────

#[test]
fn transfer_sentinels_are_distinct() {
    assert_ne!(
        TRANSFER_OK, TRANSFER_INSUFFICIENT,
        "TRANSFER_OK and TRANSFER_INSUFFICIENT must be distinct"
    );
}

#[test]
fn storage_sentinels_are_distinct() {
    assert_ne!(
        STORAGE_FOUND, STORAGE_NOT_FOUND,
        "STORAGE_FOUND and STORAGE_NOT_FOUND must be distinct"
    );
}

#[test]
fn register_empty_sentinel_is_negative() {
    // REGISTER_EMPTY must be negative so the guest can distinguish "unset register"
    // from "register holds a zero-length value" (which returns 0 from register_len).
    // Use const block to satisfy clippy::assertions_on_constants.
    const { assert!(REGISTER_EMPTY < 0) }
}

#[test]
fn storage_not_found_sentinel_is_negative() {
    // STORAGE_NOT_FOUND must be negative so the guest can distinguish "key absent"
    // from "key present with a zero-length value" (which returns STORAGE_FOUND = 0).
    // Use const block to satisfy clippy::assertions_on_constants.
    const { assert!(STORAGE_NOT_FOUND < 0) }
}

// ─── host_fn names ────────────────────────────────────────────────────────────

#[test]
fn all_host_fn_names_are_nonempty() {
    let names = [
        host_fn::BLOCK_HEIGHT,
        host_fn::BLOCK_TIMESTAMP,
        host_fn::GAS_REMAINING,
        host_fn::MSG_VALUE,
        host_fn::MSG_SENDER,
        host_fn::INPUT,
        host_fn::REGISTER_LEN,
        host_fn::READ_REGISTER,
        host_fn::STORAGE_READ,
        host_fn::STORAGE_WRITE,
        host_fn::STORAGE_DELETE,
        host_fn::EMIT_EVENT,
        host_fn::TRANSFER,
        host_fn::VALUE_RETURN,
    ];
    for name in &names {
        assert!(!name.is_empty(), "host_fn name must not be empty: {name:?}");
    }
}

#[test]
fn all_host_fn_names_are_unique() {
    // Collect all 14 host_fn constants into a BTreeSet (deterministic — AGENTS §7.1).
    // If any two constants share the same string, the set will be smaller than 14.
    let names: BTreeSet<&str> = [
        host_fn::BLOCK_HEIGHT,
        host_fn::BLOCK_TIMESTAMP,
        host_fn::GAS_REMAINING,
        host_fn::MSG_VALUE,
        host_fn::MSG_SENDER,
        host_fn::INPUT,
        host_fn::REGISTER_LEN,
        host_fn::READ_REGISTER,
        host_fn::STORAGE_READ,
        host_fn::STORAGE_WRITE,
        host_fn::STORAGE_DELETE,
        host_fn::EMIT_EVENT,
        host_fn::TRANSFER,
        host_fn::VALUE_RETURN,
    ]
    .into_iter()
    .collect();

    assert_eq!(
        names.len(),
        14,
        "all 14 host_fn names must be unique; found {} distinct names",
        names.len()
    );
}

// ─── IMPORT_ORDER integrity ───────────────────────────────────────────────────

#[test]
fn import_order_length_is_fourteen() {
    assert_eq!(
        IMPORT_ORDER.len(),
        14,
        "IMPORT_ORDER must contain exactly 14 entries (DB-A53 §4.5)"
    );
}

#[test]
fn import_order_has_no_duplicates() {
    // BTreeSet dedup — if any name appears twice, the set shrinks.
    let unique: BTreeSet<&str> = IMPORT_ORDER.iter().copied().collect();
    assert_eq!(
        unique.len(),
        IMPORT_ORDER.len(),
        "IMPORT_ORDER must have no duplicate entries; found {} unique out of {}",
        unique.len(),
        IMPORT_ORDER.len()
    );
}

#[test]
fn import_order_contains_all_host_fn_names() {
    // Every host_fn:: constant must appear in IMPORT_ORDER.
    let order_set: BTreeSet<&str> = IMPORT_ORDER.iter().copied().collect();
    let all_names = [
        host_fn::BLOCK_HEIGHT,
        host_fn::BLOCK_TIMESTAMP,
        host_fn::GAS_REMAINING,
        host_fn::MSG_VALUE,
        host_fn::MSG_SENDER,
        host_fn::INPUT,
        host_fn::REGISTER_LEN,
        host_fn::READ_REGISTER,
        host_fn::STORAGE_READ,
        host_fn::STORAGE_WRITE,
        host_fn::STORAGE_DELETE,
        host_fn::EMIT_EVENT,
        host_fn::TRANSFER,
        host_fn::VALUE_RETURN,
    ];
    for name in &all_names {
        assert!(
            order_set.contains(name),
            "host_fn::{name} is missing from IMPORT_ORDER"
        );
    }
}

#[test]
fn import_order_first_is_block_height() {
    // Index 0 is the ABI-stable first import. Changing it shifts all subsequent indices.
    assert_eq!(
        IMPORT_ORDER[0],
        host_fn::BLOCK_HEIGHT,
        "IMPORT_ORDER[0] must be BLOCK_HEIGHT (ABI invariant)"
    );
}

#[test]
fn import_order_last_is_value_return() {
    // Index 13 is the ABI-stable last import. New imports are appended at index 14+.
    assert_eq!(
        IMPORT_ORDER[13],
        host_fn::VALUE_RETURN,
        "IMPORT_ORDER[13] must be VALUE_RETURN (ABI invariant)"
    );
}

#[test]
fn host_import_count_matches_import_order_len() {
    // HOST_IMPORT_COUNT is computed from IMPORT_ORDER.len() — this test guards against
    // any future refactor that might accidentally hardcode a stale integer.
    assert_eq!(
        HOST_IMPORT_COUNT as usize,
        IMPORT_ORDER.len(),
        "HOST_IMPORT_COUNT must equal IMPORT_ORDER.len()"
    );
}

// ─── ABI stability invariant ──────────────────────────────────────────────────

#[test]
fn adding_to_end_of_import_order_would_not_shift_existing_indices() {
    // Verify that the existing 14 entries are at stable indices 0..13.
    // A new import at index 14 would not shift any of these.
    // This test documents the ABI invariant: existing indices are frozen.
    assert_eq!(
        IMPORT_ORDER[0],
        host_fn::BLOCK_HEIGHT,
        "index 0 must remain BLOCK_HEIGHT"
    );
    assert_eq!(
        IMPORT_ORDER[1],
        host_fn::BLOCK_TIMESTAMP,
        "index 1 must remain BLOCK_TIMESTAMP"
    );
    assert_eq!(
        IMPORT_ORDER[2],
        host_fn::GAS_REMAINING,
        "index 2 must remain GAS_REMAINING"
    );
    assert_eq!(
        IMPORT_ORDER[3],
        host_fn::MSG_VALUE,
        "index 3 must remain MSG_VALUE"
    );
    assert_eq!(
        IMPORT_ORDER[4],
        host_fn::MSG_SENDER,
        "index 4 must remain MSG_SENDER"
    );
    assert_eq!(IMPORT_ORDER[5], host_fn::INPUT, "index 5 must remain INPUT");
    assert_eq!(
        IMPORT_ORDER[6],
        host_fn::REGISTER_LEN,
        "index 6 must remain REGISTER_LEN"
    );
    assert_eq!(
        IMPORT_ORDER[7],
        host_fn::READ_REGISTER,
        "index 7 must remain READ_REGISTER"
    );
    assert_eq!(
        IMPORT_ORDER[8],
        host_fn::STORAGE_READ,
        "index 8 must remain STORAGE_READ"
    );
    assert_eq!(
        IMPORT_ORDER[9],
        host_fn::STORAGE_WRITE,
        "index 9 must remain STORAGE_WRITE"
    );
    assert_eq!(
        IMPORT_ORDER[10],
        host_fn::STORAGE_DELETE,
        "index 10 must remain STORAGE_DELETE"
    );
    assert_eq!(
        IMPORT_ORDER[11],
        host_fn::EMIT_EVENT,
        "index 11 must remain EMIT_EVENT"
    );
    assert_eq!(
        IMPORT_ORDER[12],
        host_fn::TRANSFER,
        "index 12 must remain TRANSFER"
    );
    assert_eq!(
        IMPORT_ORDER[13],
        host_fn::VALUE_RETURN,
        "index 13 must remain VALUE_RETURN"
    );
}

// ─── build_abi — stub contract ────────────────────────────────────────────────

#[test]
fn build_abi_returns_empty_bytes_in_stub_phase() {
    // In P3·Step 6b the ABI emitter is still a stub — it returns empty bytes.
    // Full ABI emission (function signatures, parameter/return type encoding)
    // is implemented in P3·Step 6i.
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let abi_bytes = build_abi(&contracts[0]);
    assert_eq!(
        abi_bytes,
        vec![],
        "expected empty ABI bytes in stub phase, got {} bytes",
        abi_bytes.len()
    );
}

#[test]
fn build_abi_is_deterministic_in_stub_phase() {
    // Even the stub must be deterministic (AGENTS §7.1).
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let first = build_abi(&contracts[0]);
    let second = build_abi(&contracts[0]);
    assert_eq!(first, second, "build_abi stub is not deterministic");
}
