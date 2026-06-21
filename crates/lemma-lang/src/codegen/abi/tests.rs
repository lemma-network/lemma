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

// `serde_json` is available as a dev-dep via the workspace (P3·Step 6i tests).
// It is used in the build_abi functional tests below to parse and inspect the
// emitted JSON without hardcoding byte offsets.

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
        host_fn::CALL_CONTRACT,
        host_fn::STATIC_CALL,
        host_fn::DELEGATE_CALL,
    ];
    for name in &names {
        assert!(!name.is_empty(), "host_fn name must not be empty: {name:?}");
    }
}

#[test]
fn all_host_fn_names_are_unique() {
    // Collect all 17 host_fn constants into a BTreeSet (deterministic — AGENTS §7.1).
    // If any two constants share the same string, the set will be smaller than 17.
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
        host_fn::CALL_CONTRACT,
        host_fn::STATIC_CALL,
        host_fn::DELEGATE_CALL,
    ]
    .into_iter()
    .collect();

    assert_eq!(
        names.len(),
        17,
        "all 17 host_fn names must be unique; found {} distinct names",
        names.len()
    );
}

// ─── IMPORT_ORDER integrity ───────────────────────────────────────────────────

#[test]
fn import_order_length_is_seventeen() {
    assert_eq!(
        IMPORT_ORDER.len(),
        17,
        "IMPORT_ORDER must contain exactly 17 entries (DB-A53 §4.5, P3·Step 21)"
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
        host_fn::CALL_CONTRACT,
        host_fn::STATIC_CALL,
        host_fn::DELEGATE_CALL,
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
fn import_order_index_13_is_value_return() {
    // Index 13 is the ABI-stable pre-cross-contract-call boundary.
    // New cross-contract call imports are appended at indices 14–16.
    assert_eq!(
        IMPORT_ORDER[13],
        host_fn::VALUE_RETURN,
        "IMPORT_ORDER[13] must be VALUE_RETURN (ABI invariant)"
    );
}

#[test]
fn import_order_cross_contract_calls_at_indices_14_15_16() {
    // Indices 14–16 are the cross-contract call host functions (P3·Step 21).
    // These are appended after the original 14 — ABI invariant preserved.
    assert_eq!(
        IMPORT_ORDER[14],
        host_fn::CALL_CONTRACT,
        "IMPORT_ORDER[14] must be CALL_CONTRACT"
    );
    assert_eq!(
        IMPORT_ORDER[15],
        host_fn::STATIC_CALL,
        "IMPORT_ORDER[15] must be STATIC_CALL"
    );
    assert_eq!(
        IMPORT_ORDER[16],
        host_fn::DELEGATE_CALL,
        "IMPORT_ORDER[16] must be DELEGATE_CALL"
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
    // Verify that the original 14 entries remain at stable indices 0..13.
    // The 3 cross-contract call imports at 14–16 did not shift any of these.
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

// ─── build_abi — functional tests (P3·Step 6i) ───────────────────────────────

#[test]
fn build_abi_empty_contract_returns_empty_json_array() {
    // A contract with no public functions produces a valid empty JSON array.
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let abi_bytes = build_abi(&contracts[0]);
    let json: serde_json::Value =
        serde_json::from_slice(&abi_bytes).expect("build_abi must return valid JSON");
    assert!(json.is_array(), "ABI JSON must be an array, got: {json}");
    assert_eq!(
        json.as_array().unwrap().len(),
        0,
        "empty contract ABI must have zero entries"
    );
}

#[test]
fn build_abi_includes_public_function() {
    // A public function appears in the ABI with correct name and param types.
    let typed = typed_ast_for("contract C { pub fn transfer(to: Address, amount: u128) { } }");
    let contracts = typed.contracts();
    let abi_bytes = build_abi(&contracts[0]);
    let json: serde_json::Value = serde_json::from_slice(&abi_bytes).expect("valid JSON");
    let fns = json.as_array().expect("array");
    assert_eq!(fns.len(), 1, "expected exactly 1 public function");

    let f = &fns[0];
    assert_eq!(f["name"], "transfer");
    assert!(f["selector"].is_number(), "selector must be a number");

    let params = f["params"].as_array().expect("params must be array");
    assert_eq!(params.len(), 2);
    assert_eq!(params[0]["name"], "to");
    assert_eq!(params[0]["type"], "Address");
    assert_eq!(params[1]["name"], "amount");
    assert_eq!(params[1]["type"], "u128");
}

#[test]
fn build_abi_excludes_private_function() {
    // Private functions must NOT appear in the ABI.
    let typed = typed_ast_for("contract C { fn internal_helper() { } pub fn visible() { } }");
    let contracts = typed.contracts();
    let abi_bytes = build_abi(&contracts[0]);
    let json: serde_json::Value = serde_json::from_slice(&abi_bytes).expect("valid JSON");
    let fns = json.as_array().expect("array");

    assert!(
        fns.iter().all(|f| f["name"] != "internal_helper"),
        "private function must not appear in ABI"
    );
    assert_eq!(fns.len(), 1, "only the public function should be in ABI");
    assert_eq!(fns[0]["name"], "visible");
}

#[test]
fn build_abi_return_type_is_present() {
    // Return types are emitted correctly.
    let typed = typed_ast_for(
        "contract C { pub fn get_balance(owner: Address) -> u128 { return 0u128; } }",
    );
    let contracts = typed.contracts();
    let abi_bytes = build_abi(&contracts[0]);
    let json: serde_json::Value = serde_json::from_slice(&abi_bytes).expect("valid JSON");
    let fns = json.as_array().expect("array");
    assert_eq!(fns.len(), 1);
    assert_eq!(fns[0]["returns"], "u128");
}

#[test]
fn build_abi_is_deterministic() {
    // Two calls on the same contract must produce byte-identical JSON (AGENTS §7.1).
    let typed = typed_ast_for("contract C { pub fn f(x: u64) -> bool { return true; } }");
    let contracts = typed.contracts();
    let first = build_abi(&contracts[0]);
    let second = build_abi(&contracts[0]);
    assert_eq!(first, second, "build_abi must be deterministic");
}
