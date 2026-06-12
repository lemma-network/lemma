//! Tests for `codegen::compile` (the orchestrator entry point).
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.
//! Test naming: `{action}_{outcome}` (AGENTS §11.3).

use crate::codegen::compile;
use crate::type_checker::TypedAst;
use crate::{parse, tokenize};

// ─── Shared fixtures ──────────────────────────────────────────────────────────

/// Parse and type-check a minimal contract, skipping the WF + safety passes.
///
/// Used to obtain a `TypedAst` for contracts that are intentionally minimal
/// (no `init`, no `transfer`) without triggering WF-003/SAFETY-001 violations.
fn typed_ast_for(src: &str) -> TypedAst {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    crate::type_checker::check_skip_wf(ast).expect("check_skip_wf failed")
}

// ─── compile — basic smoke tests ─────────────────────────────────────────────

#[test]
fn compile_returns_non_empty_bytes_for_minimal_contract() {
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    assert_eq!(contracts.len(), 1);
    let result = compile(&contracts[0]);
    assert!(result.is_ok(), "compile failed: {:?}", result.err());
    let bytes = result.unwrap();
    assert!(!bytes.is_empty(), "compile returned empty bytes");
}

#[test]
fn compile_produces_wasm_magic_header() {
    // Every valid WASM binary starts with the 4-byte magic `\0asm` (0x00 0x61 0x73 0x6D).
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = compile(&contracts[0]).expect("compile failed");
    assert!(
        bytes.len() >= 4,
        "WASM binary too short: {} bytes",
        bytes.len()
    );
    assert_eq!(
        &bytes[..4],
        b"\0asm",
        "WASM magic header missing; got: {:?}",
        &bytes[..4]
    );
}

#[test]
fn compile_produces_deterministic_output_for_same_contract() {
    // Calling compile twice on the same contract must produce byte-identical output.
    // This is the core determinism requirement (AGENTS §7.1, decisions-log DB-A52).
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let first = compile(&contracts[0]).expect("first compile failed");
    let second = compile(&contracts[0]).expect("second compile failed");
    assert_eq!(
        first, second,
        "compile is not deterministic: outputs differ"
    );
}
