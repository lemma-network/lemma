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

// ─── u128 + Address codegen (subtask_08) ─────────────────────────────────────

#[test]
fn compile_accepts_u128_state_field() {
    // A contract with a u128 state field should compile through the full pipeline.
    let typed = typed_ast_for(
        "contract Counter {
            state { total: u128 }
            pub fn getTotal() -> u128 {
                return self.total
            }
        }",
    );
    let contracts = typed.contracts();
    let result = compile(&contracts[0]);
    assert!(result.is_ok(), "compile failed: {:?}", result.err());
    let bytes = result.unwrap();
    assert_eq!(&bytes[..4], b"\0asm", "WASM magic header missing");
}

#[test]
fn compile_accepts_address_param() {
    // A contract with an Address parameter should compile.
    let typed = typed_ast_for(
        "contract Vault {
            state { owner: Address }
            pub fn setOwner(addr: Address) {
                self.owner = addr
            }
        }",
    );
    let contracts = typed.contracts();
    let result = compile(&contracts[0]);
    assert!(result.is_ok(), "compile failed: {:?}", result.err());
}

#[test]
fn compile_accepts_u128_param_and_arithmetic() {
    // A contract with u128 params and checked add/sub should compile.
    let typed = typed_ast_for(
        "contract Token {
            state { supply: u128 }
            pub fn add(amount: u128) {
                self.supply = self.supply + amount
            }
            pub fn sub(amount: u128) {
                self.supply = self.supply - amount
            }
        }",
    );
    let contracts = typed.contracts();
    let result = compile(&contracts[0]);
    assert!(result.is_ok(), "compile failed: {:?}", result.err());
}

#[test]
fn compile_accepts_u128_comparison() {
    // u128 comparisons (>=, <, ==) should compile.
    let typed = typed_ast_for(
        "contract Guard {
            state { limit: u128 }
            pub fn check(amount: u128) -> bool {
                return amount >= self.limit
            }
        }",
    );
    let contracts = typed.contracts();
    let result = compile(&contracts[0]);
    assert!(result.is_ok(), "compile failed: {:?}", result.err());
}

#[test]
fn compile_accepts_transfer_like_function() {
    // A simplified transfer function with Address + u128 params.
    // This is the core token use case that subtask_08 unblocks.
    let typed = typed_ast_for(
        "contract SimpleToken {
            state { supply: u128 }
            pub fn mint(to: Address, amount: u128) {
                self.supply = self.supply + amount
            }
        }",
    );
    let contracts = typed.contracts();
    let result = compile(&contracts[0]);
    assert!(result.is_ok(), "compile failed: {:?}", result.err());
}

#[test]
fn compile_u128_deterministic() {
    // u128 codegen must be deterministic (AGENTS §7.1).
    let typed = typed_ast_for(
        "contract Token {
            state { supply: u128 }
            pub fn add(amount: u128) {
                self.supply = self.supply + amount
            }
        }",
    );
    let contracts = typed.contracts();
    let first = compile(&contracts[0]).expect("first compile failed");
    let second = compile(&contracts[0]).expect("second compile failed");
    assert_eq!(first, second, "u128 codegen is not deterministic");
}
