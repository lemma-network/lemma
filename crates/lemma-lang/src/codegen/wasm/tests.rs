//! Tests for `codegen::wasm::emit_module`.
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.
//! Test naming: `{action}_{outcome}` (AGENTS §11.3).
//!
//! ## Validation strategy
//!
//! Uses `wasmparser::validate` (dev-dependency) to verify that the emitted
//! bytes constitute a structurally valid WebAssembly binary. This is the
//! canonical validation approach — wasmparser is the same org (bytecodealliance)
//! as wasm-encoder and wasmtime, so it validates against the same spec version.

use crate::codegen::wasm::emit_module;
use crate::type_checker::TypedAst;
use crate::{parse, tokenize};

// ─── Shared fixtures ──────────────────────────────────────────────────────────

/// Parse and type-check a minimal contract, skipping the WF + safety passes.
fn typed_ast_for(src: &str) -> TypedAst {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    crate::type_checker::check_skip_wf(ast).expect("check_skip_wf failed")
}

// ─── emit_module — structural validity ───────────────────────────────────────

#[test]
fn emit_module_returns_valid_wasm_bytes() {
    // The emitted bytes must pass wasmparser's structural validation.
    // This is the primary acceptance criterion for P3·Step 6a.
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "emitted WASM failed wasmparser validation: {:?}",
        result.err()
    );
}

#[test]
fn emit_module_produces_wasm_magic_and_version() {
    // WASM binary format: 4-byte magic `\0asm` + 4-byte version `\x01\x00\x00\x00`.
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    assert!(
        bytes.len() >= 8,
        "WASM binary too short: {} bytes",
        bytes.len()
    );
    assert_eq!(&bytes[..4], b"\0asm", "WASM magic header missing");
    assert_eq!(
        &bytes[4..8],
        &[0x01, 0x00, 0x00, 0x00],
        "WASM version field incorrect"
    );
}

// ─── emit_module — determinism ────────────────────────────────────────────────

#[test]
fn emit_module_produces_deterministic_output() {
    // Calling emit_module twice on the same TypedContract must produce
    // byte-identical output. This is the core determinism requirement
    // (AGENTS §7.1, decisions-log DB-A52): every validator node must
    // produce the same WASM bytes from the same Lem source.
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let first = emit_module(&contracts[0]).expect("first emit failed");
    let second = emit_module(&contracts[0]).expect("second emit failed");
    assert_eq!(
        first, second,
        "emit_module is not deterministic: outputs differ between calls"
    );
}

// ─── emit_module — entry point export ────────────────────────────────────────

#[test]
fn emit_module_exports_call_entrypoint() {
    // The emitted WASM must export a function named "call".
    // The VM executor (lemma-vm executor.rs ENTRY_POINT = "call") looks for
    // this export by name (08-EXECUTION_SPEC §1).
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    // Parse the exports using wasmparser to verify the "call" export exists.
    let mut found_call_export = false;
    let mut parser = wasmparser::Parser::new(0);
    let mut remaining = bytes.as_slice();

    loop {
        let payload = match parser.parse(remaining, true) {
            Ok(wasmparser::Chunk::Parsed { consumed, payload }) => {
                remaining = &remaining[consumed..];
                payload
            }
            Ok(wasmparser::Chunk::NeedMoreData(_)) => break,
            Err(e) => panic!("wasmparser error: {e}"),
        };

        match payload {
            wasmparser::Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.expect("export read failed");
                    if export.name == "call" {
                        if let wasmparser::ExternalKind::Func = export.kind {
                            found_call_export = true;
                        }
                    }
                }
            }
            wasmparser::Payload::End(_) => break,
            _ => {}
        }
    }

    assert!(
        found_call_export,
        "emitted WASM does not export a function named 'call'"
    );
}

#[test]
fn emit_module_call_export_references_valid_function_index() {
    // The "call" export must reference function index 0 (the sole defined
    // function in the 6a skeleton). This verifies the function/export index
    // wiring is correct.
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let mut call_func_index: Option<u32> = None;
    let mut parser = wasmparser::Parser::new(0);
    let mut remaining = bytes.as_slice();

    loop {
        let payload = match parser.parse(remaining, true) {
            Ok(wasmparser::Chunk::Parsed { consumed, payload }) => {
                remaining = &remaining[consumed..];
                payload
            }
            Ok(wasmparser::Chunk::NeedMoreData(_)) => break,
            Err(e) => panic!("wasmparser error: {e}"),
        };

        match payload {
            wasmparser::Payload::ExportSection(reader) => {
                for export in reader {
                    let export = export.expect("export read failed");
                    if export.name == "call" {
                        call_func_index = Some(export.index);
                    }
                }
            }
            wasmparser::Payload::End(_) => break,
            _ => {}
        }
    }

    assert_eq!(
        call_func_index,
        Some(0),
        "expected 'call' export to reference function index 0, got: {:?}",
        call_func_index
    );
}
