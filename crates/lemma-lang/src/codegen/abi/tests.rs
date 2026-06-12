//! Tests for `codegen::abi::build_abi`.
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.
//! Test naming: `{action}_{outcome}` (AGENTS §11.3).
//!
//! In P3·Step 6a `build_abi` is a stub returning `vec![]`.
//! These tests verify the stub contract and will be extended in P3·Step 6i.

use crate::codegen::abi::build_abi;
use crate::type_checker::TypedAst;
use crate::{parse, tokenize};

// ─── Shared fixtures ──────────────────────────────────────────────────────────

fn typed_ast_for(src: &str) -> TypedAst {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    crate::type_checker::check_skip_wf(ast).expect("check_skip_wf failed")
}

// ─── build_abi — stub contract ────────────────────────────────────────────────

#[test]
fn build_abi_returns_empty_bytes_in_stub_phase() {
    // In P3·Step 6a the ABI emitter is a stub — it returns empty bytes.
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
