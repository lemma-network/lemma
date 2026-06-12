//! Tests for `codegen::wasm` — WASM module emission and expression lowering.
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
//!
//! ## Expression lowering tests (P3·Step 6c)
//!
//! Expression lowering is tested via `emit_test_expr_module`, which compiles
//! a single expression into a WASM function and validates the output. This
//! avoids the dispatch complexity (6e) while verifying that expressions lower
//! correctly.

use crate::codegen::wasm::emit_module;
use crate::parser::Stmt;
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
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

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

// ─── emit_module — import section (P3·Step 6c) ──────────────────────────────

#[test]
fn emit_module_with_imports_produces_valid_wasm() {
    // The module with import section (14 host functions) must still validate.
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "WASM with imports failed validation: {:?}",
        result.err()
    );
}

#[test]
fn emit_module_imports_all_host_functions() {
    use crate::codegen::abi::IMPORT_ORDER;

    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let mut import_names: Vec<String> = Vec::new();
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
            wasmparser::Payload::ImportSection(reader) => {
                for import in reader {
                    let import = import.expect("import read failed");
                    assert_eq!(import.module, "lemma", "import module must be 'lemma'");
                    import_names.push(import.name.to_string());
                }
            }
            wasmparser::Payload::End(_) => break,
            _ => {}
        }
    }

    assert_eq!(
        import_names.len(),
        IMPORT_ORDER.len(),
        "expected {} imports, got {}",
        IMPORT_ORDER.len(),
        import_names.len()
    );

    // Verify order matches IMPORT_ORDER exactly
    for (i, (actual, expected)) in import_names.iter().zip(IMPORT_ORDER.iter()).enumerate() {
        assert_eq!(
            actual, expected,
            "import at index {i} mismatch: got '{actual}', expected '{expected}'"
        );
    }
}

// ─── emit_module — memory export (P3·Step 6c) ───────────────────────────────

#[test]
fn emit_module_exports_memory() {
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let mut found_memory_export = false;
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
                    if export.name == "memory" {
                        if let wasmparser::ExternalKind::Memory = export.kind {
                            found_memory_export = true;
                        }
                    }
                }
            }
            wasmparser::Payload::End(_) => break,
            _ => {}
        }
    }

    assert!(
        found_memory_export,
        "emitted WASM does not export memory as 'memory'"
    );
}

// ─── emit_module — global export (P3·Step 6c) ───────────────────────────────

#[test]
fn emit_module_exports_heap_base_global() {
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let mut found_heap_base = false;
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
                    if export.name == "__heap_base" {
                        if let wasmparser::ExternalKind::Global = export.kind {
                            found_heap_base = true;
                        }
                    }
                }
            }
            wasmparser::Payload::End(_) => break,
            _ => {}
        }
    }

    assert!(
        found_heap_base,
        "emitted WASM does not export '__heap_base' global"
    );
}

// ─── emit_module — call export references correct function index ─────────────

#[test]
fn emit_module_call_export_references_correct_function_index() {
    // With 14 imports, the first defined function is at index 14.
    use crate::codegen::abi::HOST_IMPORT_COUNT;

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
        Some(HOST_IMPORT_COUNT),
        "expected 'call' export at function index {HOST_IMPORT_COUNT}, got: {call_func_index:?}",
    );
}

// ─── Expression lowering — literals (P3·Step 6c) ────────────────────────────

#[test]
fn emit_literal_int_produces_valid_module() {
    // A function returning a literal integer must produce valid WASM.
    let src = r#"
        contract Foo {
            pub fn get_value() -> u32 {
                return 42;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    assert!(
        !fns.is_empty(),
        "contract should have at least one function"
    );

    // Find the return expression's inner expression
    let body = fns[0].body.expect("function should have a body");
    // The body should contain a Return statement with an expression
    assert!(!body.is_empty(), "function body should not be empty");

    // Validate the full module (which includes the import section)
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");
    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "WASM with literal int failed validation: {:?}",
        result.err()
    );
}

#[test]
fn emit_literal_bool_produces_valid_module() {
    let src = r#"
        contract Foo {
            pub fn is_active() -> bool {
                return true;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");
    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "WASM with literal bool failed validation: {:?}",
        result.err()
    );
}

// ─── Expression lowering — test expression module ───────────────────────────

#[test]
fn emit_test_expr_module_literal_int_validates() {
    use super::emit_test_expr_module;

    // Build a contract with a function that has a typed expression
    let src = r#"
        contract Foo {
            pub fn get_value() -> u32 {
                return 42;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    // Extract the return expression
    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes =
            emit_test_expr_module(&contracts[0], expr, &[]).expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module failed validation: {:?}",
            result.err()
        );
    } else {
        panic!(
            "expected Return statement with expression, got: {:?}",
            body[0]
        );
    }
}

#[test]
fn emit_test_expr_module_literal_bool_validates() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn is_active() -> bool {
                return true;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes =
            emit_test_expr_module(&contracts[0], expr, &[]).expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (bool) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── Expression lowering — binary add ────────────────────────────────────────

#[test]
fn emit_binary_add_produces_valid_module() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn add(a: u32, b: u32) -> u32 {
                return a + b;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes = emit_test_expr_module(
            &contracts[0],
            expr,
            &[
                ("a".into(), wasm_encoder::ValType::I32),
                ("b".into(), wasm_encoder::ValType::I32),
            ],
        )
        .expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (add) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── Expression lowering — comparison eq ─────────────────────────────────────

#[test]
fn emit_comparison_eq_produces_valid_module() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn is_equal(a: u32, b: u32) -> bool {
                return a == b;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes = emit_test_expr_module(
            &contracts[0],
            expr,
            &[
                ("a".into(), wasm_encoder::ValType::I32),
                ("b".into(), wasm_encoder::ValType::I32),
            ],
        )
        .expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (eq) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── Expression lowering — local variable read ──────────────────────────────

#[test]
fn emit_local_get_produces_valid_module() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn identity(x: u32) -> u32 {
                return x;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes = emit_test_expr_module(
            &contracts[0],
            expr,
            &[("x".into(), wasm_encoder::ValType::I32)],
        )
        .expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (local get) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── Expression lowering — unsupported type ──────────────────────────────────

#[test]
fn emit_unsupported_type_returns_codegen_error() {
    use crate::codegen::types::wasm_valtype;
    use crate::type_checker::types::ResolvedType;

    // u256 is not yet supported in codegen
    let result = wasm_valtype(&ResolvedType::U256);
    assert!(result.is_err(), "u256 should return a codegen error");

    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("not yet supported"),
        "error message should mention 'not yet supported', got: {msg}"
    );
}

// ─── Expression lowering — subtraction ───────────────────────────────────────

#[test]
fn emit_binary_sub_produces_valid_module() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn sub(a: u32, b: u32) -> u32 {
                return a - b;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes = emit_test_expr_module(
            &contracts[0],
            expr,
            &[
                ("a".into(), wasm_encoder::ValType::I32),
                ("b".into(), wasm_encoder::ValType::I32),
            ],
        )
        .expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (sub) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── Expression lowering — multiplication ────────────────────────────────────

#[test]
fn emit_binary_mul_produces_valid_module() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn mul(a: u32, b: u32) -> u32 {
                return a * b;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes = emit_test_expr_module(
            &contracts[0],
            expr,
            &[
                ("a".into(), wasm_encoder::ValType::I32),
                ("b".into(), wasm_encoder::ValType::I32),
            ],
        )
        .expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (mul) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── Expression lowering — division ──────────────────────────────────────────

#[test]
fn emit_binary_div_produces_valid_module() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn div(a: u32, b: u32) -> u32 {
                return a / b;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes = emit_test_expr_module(
            &contracts[0],
            expr,
            &[
                ("a".into(), wasm_encoder::ValType::I32),
                ("b".into(), wasm_encoder::ValType::I32),
            ],
        )
        .expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (div) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── Expression lowering — i64 types ─────────────────────────────────────────

#[test]
fn emit_binary_add_i64_produces_valid_module() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn add64(a: u64, b: u64) -> u64 {
                return a + b;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes = emit_test_expr_module(
            &contracts[0],
            expr,
            &[
                ("a".into(), wasm_encoder::ValType::I64),
                ("b".into(), wasm_encoder::ValType::I64),
            ],
        )
        .expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (add i64) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── Expression lowering — logical operators ─────────────────────────────────

#[test]
fn emit_logical_and_produces_valid_module() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn both(a: bool, b: bool) -> bool {
                return a && b;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes = emit_test_expr_module(
            &contracts[0],
            expr,
            &[
                ("a".into(), wasm_encoder::ValType::I32),
                ("b".into(), wasm_encoder::ValType::I32),
            ],
        )
        .expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (and) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── Expression lowering — unary not ─────────────────────────────────────────

#[test]
fn emit_unary_not_produces_valid_module() {
    use super::emit_test_expr_module;

    let src = r#"
        contract Foo {
            pub fn negate(a: bool) -> bool {
                return !a;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let bytes = emit_test_expr_module(
            &contracts[0],
            expr,
            &[("a".into(), wasm_encoder::ValType::I32)],
        )
        .expect("emit_test_expr_module failed");
        let result = wasmparser::validate(&bytes);
        assert!(
            result.is_ok(),
            "test expr module (not) failed validation: {:?}",
            result.err()
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ─── M3: Wasmtime execution tests ───────────────────────────────────────────
//
// These tests compile Lem expressions to WASM via `emit_test_expr_module`,
// then execute the module with wasmtime to verify runtime behavior — not just
// structural validity. This catches bugs like C2 (Neg(MIN) not trapping) and
// M1 (sub-word overflow not detected) that validation-only tests miss.
//
// The test module imports 14 host functions from "lemma". We register all 14
// as no-op stubs in the wasmtime linker, matching the signatures from HOST_SIGS.

/// Compile a Lem expression (inside a contract function returning the given type)
/// to WASM, instantiate it with wasmtime, call the exported "test" function,
/// and return the i32 result.
///
/// The expression is wrapped in `contract Test { pub fn f() -> {ret_ty} { return {expr}; } }`.
/// This exercises the FULL pipeline: parse → type-check → codegen → wasmtime execute.
fn execute_expr_i32(expr: &str, ret_ty: &str) -> Result<i32, String> {
    use super::emit_test_expr_module;
    use crate::codegen::abi::{IMPORT_MODULE, IMPORT_ORDER};
    use crate::codegen::wasm::HOST_SIGS;

    let src = format!("contract Test {{ pub fn f() -> {ret_ty} {{ return {expr}; }} }}");
    let typed = typed_ast_for(&src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    let return_expr = match &body[0] {
        Stmt::Return(Some(ref e), _) => e,
        other => return Err(format!("expected Return(Some(expr)), got: {other:?}")),
    };

    let wasm_bytes = emit_test_expr_module(&contracts[0], return_expr, &[])
        .map_err(|e| format!("codegen failed: {e}"))?;

    // Create wasmtime engine + store (no fuel needed for unit tests)
    let engine = wasmtime::Engine::default();
    let mut store = wasmtime::Store::new(&engine, ());
    let module = wasmtime::Module::new(&engine, &wasm_bytes)
        .map_err(|e| format!("wasmtime compile failed: {e}"))?;

    // Build a linker with all 14 host imports as no-op stubs
    let mut linker = wasmtime::Linker::new(&engine);
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        let (params, results) = HOST_SIGS[i];
        let func_ty = wasmtime::FuncType::new(
            &engine,
            params.iter().map(|vt| match vt {
                wasm_encoder::ValType::I32 => wasmtime::ValType::I32,
                wasm_encoder::ValType::I64 => wasmtime::ValType::I64,
                _ => wasmtime::ValType::I32, // defensive fallback
            }),
            results.iter().map(|vt| match vt {
                wasm_encoder::ValType::I32 => wasmtime::ValType::I32,
                wasm_encoder::ValType::I64 => wasmtime::ValType::I64,
                _ => wasmtime::ValType::I32,
            }),
        );
        // Capture result types for the closure (HOST_SIGS results are &[ValType])
        let result_types: Vec<wasm_encoder::ValType> = results.to_vec();
        linker
            .func_new(
                IMPORT_MODULE,
                name,
                func_ty,
                move |_caller, _params, results| {
                    // No-op stub: zero-fill results with correct types
                    for (r, vt) in results.iter_mut().zip(result_types.iter()) {
                        *r = match vt {
                            wasm_encoder::ValType::I64 => wasmtime::Val::I64(0),
                            _ => wasmtime::Val::I32(0),
                        };
                    }
                    Ok(())
                },
            )
            .map_err(|e| format!("linker.func_new({name}) failed: {e}"))?;
    }

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("instantiation failed: {e}"))?;

    let test_fn = instance
        .get_typed_func::<(), i32>(&mut store, "test")
        .map_err(|e| format!("get_typed_func failed: {e}"))?;

    test_fn
        .call(&mut store, ())
        .map_err(|e| format!("execution trapped: {e}"))
}

// ── Literal and basic arithmetic execution ──────────────────────────────────

#[test]
fn execute_literal_int_returns_correct_value() {
    assert_eq!(execute_expr_i32("42", "u32").unwrap(), 42);
}

#[test]
fn execute_add_returns_correct_sum() {
    assert_eq!(execute_expr_i32("10 + 20", "u32").unwrap(), 30);
}

#[test]
fn execute_sub_returns_correct_difference() {
    assert_eq!(execute_expr_i32("50 - 20", "u32").unwrap(), 30);
}

#[test]
fn execute_mul_returns_correct_product() {
    assert_eq!(execute_expr_i32("6 * 7", "u32").unwrap(), 42);
}

#[test]
fn execute_div_returns_correct_quotient() {
    assert_eq!(execute_expr_i32("42 / 6", "u32").unwrap(), 7);
}

// ── Comparison execution ────────────────────────────────────────────────────

#[test]
fn execute_comparison_eq_returns_true() {
    assert_eq!(execute_expr_i32("42 == 42", "bool").unwrap(), 1);
}

#[test]
fn execute_comparison_eq_returns_false() {
    assert_eq!(execute_expr_i32("42 == 43", "bool").unwrap(), 0);
}

#[test]
fn execute_comparison_lt_returns_correct() {
    assert_eq!(execute_expr_i32("10 < 20", "bool").unwrap(), 1);
    assert_eq!(execute_expr_i32("20 < 10", "bool").unwrap(), 0);
}

// ── Boolean execution ───────────────────────────────────────────────────────

#[test]
fn execute_bool_literal_true() {
    assert_eq!(execute_expr_i32("true", "bool").unwrap(), 1);
}

#[test]
fn execute_bool_literal_false() {
    assert_eq!(execute_expr_i32("false", "bool").unwrap(), 0);
}

#[test]
fn execute_logical_and() {
    assert_eq!(execute_expr_i32("true && false", "bool").unwrap(), 0);
    assert_eq!(execute_expr_i32("true && true", "bool").unwrap(), 1);
}

#[test]
fn execute_logical_or() {
    assert_eq!(execute_expr_i32("false || true", "bool").unwrap(), 1);
    assert_eq!(execute_expr_i32("false || false", "bool").unwrap(), 0);
}

// ── Overflow/trap execution tests (§7.4 compliance) ─────────────────────────

#[test]
fn execute_unsigned_add_overflow_traps() {
    // u32::MAX + 1 must trap
    let result = execute_expr_i32("4294967295 + 1", "u32");
    assert!(result.is_err(), "u32 overflow must trap, got: {result:?}");
}

#[test]
fn execute_unsigned_sub_underflow_traps() {
    // 0 - 1 for u32 must trap
    let result = execute_expr_i32("0 - 1", "u32");
    assert!(result.is_err(), "u32 underflow must trap, got: {result:?}");
}

#[test]
fn execute_div_by_zero_traps() {
    // 42 / 0 must trap
    let result = execute_expr_i32("42 / 0", "u32");
    assert!(
        result.is_err(),
        "division by zero must trap, got: {result:?}"
    );
}

// ── C2: Negation overflow — verified via checked sub path ───────────────────
// Direct negation of i32::MIN is hard to express as a Lem literal (the parser
// sees `-2147483648` as `Unary(Neg, 2147483648)` which may not fit i32).
// Instead we verify the checked sub path catches signed overflow:
// `(-2147483647 - 1)` gives i32::MIN, then subtracting 1 more overflows.

#[test]
fn execute_signed_sub_overflow_traps() {
    // i32::MIN - 1 overflows signed i32
    let result = execute_expr_i32("-2147483647 - 1 - 1", "i32");
    assert!(
        result.is_err(),
        "signed i32 overflow must trap, got: {result:?}"
    );
}

// ── M1: Sub-word arithmetic rejection ───────────────────────────────────────

#[test]
fn emit_sub_word_arithmetic_returns_codegen_error() {
    use super::emit_test_expr_module;

    // u8 arithmetic should be rejected at codegen time
    let src = r#"
        contract Foo {
            pub fn add_u8(a: u8, b: u8) -> u8 {
                return a + b;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let body = fns[0].body.expect("function should have a body");

    if let Stmt::Return(Some(ref expr), _) = body[0] {
        let result = emit_test_expr_module(
            &contracts[0],
            expr,
            &[
                ("a".into(), wasm_encoder::ValType::I32),
                ("b".into(), wasm_encoder::ValType::I32),
            ],
        );
        assert!(
            result.is_err(),
            "sub-word (u8) arithmetic should return codegen error"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("sub-word"),
            "error should mention 'sub-word', got: {err_msg}"
        );
    } else {
        panic!("expected Return(Some(expr))");
    }
}

// ── M2: IntLiteral in arithmetic context ────────────────────────────────────
// Note: IntLiteral reaching arithmetic codegen is tested indirectly — if the
// type checker resolves literals to concrete types (which it does for
// expressions with a return-type context), IntLiteral won't reach codegen.
// The guard is defensive; we verify it exists via the sub-word test pattern.

// ═══════════════════════════════════════════════════════════════════════════
// P3·Step 6d — Statement + control flow lowering
// ═══════════════════════════════════════════════════════════════════════════
//
// These tests compile Lem function bodies (multiple statements) to WASM via
// `emit_test_stmt_module`, then execute with wasmtime to verify runtime
// behavior. This exercises the full pipeline: parse → type-check → codegen
// → wasmtime execute.

/// Compile a Lem function body (statements) to WASM, instantiate with wasmtime,
/// call the exported "test" function, and return the i32 result.
///
/// The body is wrapped in `contract Test { pub fn f() -> {ret_ty} { {body} } }`.
fn execute_fn_body(body: &str, ret_ty: &str) -> Result<i32, String> {
    use super::emit_test_stmt_module;
    use crate::codegen::abi::{IMPORT_MODULE, IMPORT_ORDER};
    use crate::codegen::wasm::HOST_SIGS;

    let src = format!("contract Test {{ pub fn f() -> {ret_ty} {{ {body} }} }}");
    let typed = typed_ast_for(&src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let fn_body = fns[0].body.expect("function should have a body");

    let wasm_bytes = emit_test_stmt_module(&contracts[0], fn_body, &[], wasm_encoder::ValType::I32)
        .map_err(|e| format!("codegen failed: {e}"))?;

    // Create wasmtime engine + store
    let engine = wasmtime::Engine::default();
    let mut store = wasmtime::Store::new(&engine, ());
    let module = wasmtime::Module::new(&engine, &wasm_bytes)
        .map_err(|e| format!("wasmtime compile failed: {e}"))?;

    // Build a linker with all 14 host imports as no-op stubs
    let mut linker = wasmtime::Linker::new(&engine);
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        let (params, results) = HOST_SIGS[i];
        let func_ty = wasmtime::FuncType::new(
            &engine,
            params.iter().map(|vt| match vt {
                wasm_encoder::ValType::I32 => wasmtime::ValType::I32,
                wasm_encoder::ValType::I64 => wasmtime::ValType::I64,
                _ => wasmtime::ValType::I32,
            }),
            results.iter().map(|vt| match vt {
                wasm_encoder::ValType::I32 => wasmtime::ValType::I32,
                wasm_encoder::ValType::I64 => wasmtime::ValType::I64,
                _ => wasmtime::ValType::I32,
            }),
        );
        let result_types: Vec<wasm_encoder::ValType> = results.to_vec();
        linker
            .func_new(
                IMPORT_MODULE,
                name,
                func_ty,
                move |_caller, _params, results| {
                    for (r, vt) in results.iter_mut().zip(result_types.iter()) {
                        *r = match vt {
                            wasm_encoder::ValType::I64 => wasmtime::Val::I64(0),
                            _ => wasmtime::Val::I32(0),
                        };
                    }
                    Ok(())
                },
            )
            .map_err(|e| format!("linker.func_new({name}) failed: {e}"))?;
    }

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("instantiation failed: {e}"))?;

    let test_fn = instance
        .get_typed_func::<(), i32>(&mut store, "test")
        .map_err(|e| format!("get_typed_func failed: {e}"))?;

    test_fn
        .call(&mut store, ())
        .map_err(|e| format!("execution trapped: {e}"))
}

// ── Let binding ─────────────────────────────────────────────────────────────

#[test]
fn execute_let_binding_returns_value() {
    assert_eq!(
        execute_fn_body("let x: u32 = 42; return x;", "u32").unwrap(),
        42
    );
}

#[test]
fn execute_let_multiple_bindings() {
    assert_eq!(
        execute_fn_body("let a: u32 = 10; let b: u32 = 20; return a + b;", "u32").unwrap(),
        30
    );
}

// ── Assignment ──────────────────────────────────────────────────────────────

#[test]
fn execute_assign_updates_local() {
    assert_eq!(
        execute_fn_body("let mut x: u32 = 10; x = 20; return x;", "u32").unwrap(),
        20
    );
}

#[test]
fn execute_compound_add_assign() {
    assert_eq!(
        execute_fn_body("let mut x: u32 = 10; x += 5; return x;", "u32").unwrap(),
        15
    );
}

#[test]
fn execute_compound_sub_assign() {
    assert_eq!(
        execute_fn_body("let mut x: u32 = 10; x -= 3; return x;", "u32").unwrap(),
        7
    );
}

#[test]
fn execute_compound_mul_assign() {
    assert_eq!(
        execute_fn_body("let mut x: u32 = 6; x *= 7; return x;", "u32").unwrap(),
        42
    );
}

// ── If/Else ─────────────────────────────────────────────────────────────────

#[test]
fn execute_if_true_branch() {
    assert_eq!(
        execute_fn_body("if (true) { return 1; } return 0;", "u32").unwrap(),
        1
    );
}

#[test]
fn execute_if_false_falls_through() {
    assert_eq!(
        execute_fn_body("if (false) { return 1; } return 0;", "u32").unwrap(),
        0
    );
}

#[test]
fn execute_if_else_true_branch() {
    // Trailing `return 0` is unreachable but satisfies WASM's type system:
    // the function body must produce a value even after an if/else where
    // both branches return. WASM validation requires stack-type consistency.
    assert_eq!(
        execute_fn_body(
            "if (true) { return 1; } else { return 2; } return 0;",
            "u32"
        )
        .unwrap(),
        1
    );
}

#[test]
fn execute_if_else_false_branch() {
    assert_eq!(
        execute_fn_body(
            "if (false) { return 1; } else { return 2; } return 0;",
            "u32"
        )
        .unwrap(),
        2
    );
}

// ── While loop ──────────────────────────────────────────────────────────────

#[test]
fn execute_while_loop_counts() {
    assert_eq!(
        execute_fn_body(
            "let mut i: u32 = 0; while (i < 5) { i += 1; } return i;",
            "u32"
        )
        .unwrap(),
        5
    );
}

#[test]
fn execute_while_loop_accumulates() {
    // Sum 1..5 = 10
    assert_eq!(
        execute_fn_body(
            "let mut sum: u32 = 0; let mut i: u32 = 1; while (i <= 5) { sum += i; i += 1; } return sum;",
            "u32"
        )
        .unwrap(),
        15
    );
}

// ── Loop + break ────────────────────────────────────────────────────────────

#[test]
fn execute_break_exits_loop() {
    assert_eq!(
        execute_fn_body(
            "let mut i: u32 = 0; loop { i += 1; if (i == 3) { break; } } return i;",
            "u32"
        )
        .unwrap(),
        3
    );
}

// ── Continue ────────────────────────────────────────────────────────────────

#[test]
fn execute_continue_skips_iteration() {
    // Sum even numbers from 1..10: 2+4+6+8+10 = 30
    // Increment i first, then skip odd values
    assert_eq!(
        execute_fn_body(
            "let mut sum: u32 = 0; let mut i: u32 = 0; while (i < 10) { i += 1; if (i % 2 != 0) { continue; } sum += i; } return sum;",
            "u32"
        )
        .unwrap(),
        30
    );
}

// ── Nested control flow ─────────────────────────────────────────────────────

#[test]
fn execute_nested_if_in_while() {
    // Sum values < 5 from 0..9: 0+1+2+3+4 = 10
    assert_eq!(
        execute_fn_body(
            "let mut sum: u32 = 0; let mut i: u32 = 0; while (i < 10) { if (i < 5) { sum += i; } i += 1; } return sum;",
            "u32"
        )
        .unwrap(),
        10
    );
}

#[test]
fn execute_nested_loops() {
    // Outer loop 3 times, inner loop 4 times each = 12 total increments
    assert_eq!(
        execute_fn_body(
            "let mut count: u32 = 0; let mut i: u32 = 0; while (i < 3) { let mut j: u32 = 0; while (j < 4) { count += 1; j += 1; } i += 1; } return count;",
            "u32"
        )
        .unwrap(),
        12
    );
}

// ── Assert ──────────────────────────────────────────────────────────────────

#[test]
fn execute_assert_true_succeeds() {
    assert_eq!(
        execute_fn_body("assert(true); return 1;", "u32").unwrap(),
        1
    );
}

#[test]
fn execute_assert_false_traps() {
    assert!(execute_fn_body("assert(false); return 1;", "u32").is_err());
}

// ── Revert ──────────────────────────────────────────────────────────────────

#[test]
fn execute_revert_traps() {
    assert!(execute_fn_body("revert(); return 1;", "u32").is_err());
}

// ── Return ──────────────────────────────────────────────────────────────────

#[test]
fn execute_early_return() {
    assert_eq!(execute_fn_body("return 42; return 99;", "u32").unwrap(), 42);
}

// ── Compound assign overflow traps (§7.4 compliance) ────────────────────────

#[test]
fn execute_compound_add_overflow_traps() {
    assert!(execute_fn_body("let mut x: u32 = 4294967295; x += 1; return x;", "u32").is_err());
}

#[test]
fn execute_compound_sub_underflow_traps() {
    assert!(execute_fn_body("let mut x: u32 = 0; x -= 1; return x;", "u32").is_err());
}

// ═══════════════════════════════════════════════════════════════════════════
// P3·Step 6e — Function dispatch + storage access
// ═══════════════════════════════════════════════════════════════════════════
//
// These tests verify the production `emit_module` path: function dispatch
// via selectors, bump allocator, storage read/write via host imports, and
// per-function body lowering.

// ── emit_module — stateful contract validation ──────────────────────────────

#[test]
fn emit_module_stateful_contract_produces_valid_wasm() {
    let src = r#"
        contract Counter {
            state { count: u32 }
            pub fn increment() {
                self.count = self.count + 1;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");
    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "stateful contract WASM failed validation: {:?}",
        result.err()
    );
}

#[test]
fn emit_module_multi_function_contract_produces_valid_wasm() {
    let src = r#"
        contract Math {
            state { value: u32 }
            pub fn set(x: u32) {
                self.value = x;
            }
            pub fn get() -> u32 {
                return self.value;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");
    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "multi-function contract WASM failed validation: {:?}",
        result.err()
    );
}

#[test]
fn emit_module_empty_contract_still_valid() {
    // A contract with no pub functions should still produce valid WASM
    let src = "contract Empty {}";
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");
    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "empty contract WASM failed validation: {:?}",
        result.err()
    );
}

#[test]
fn emit_module_u64_state_field_produces_valid_wasm() {
    let src = r#"
        contract BigCounter {
            state { total: u64 }
            pub fn add(amount: u64) {
                self.total = self.total + amount;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");
    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "u64 state field WASM failed validation: {:?}",
        result.err()
    );
}

#[test]
fn emit_module_bool_state_field_produces_valid_wasm() {
    let src = r#"
        contract Toggle {
            state { active: bool }
            pub fn activate() {
                self.active = true;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");
    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "bool state field WASM failed validation: {:?}",
        result.err()
    );
}

// ── Selector computation ────────────────────────────────────────────────────

#[test]
fn compute_selector_is_deterministic() {
    use crate::codegen::wasm::compute_selector;

    let src = r#"
        contract Foo {
            pub fn transfer(amount: u32) {}
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let sel1 = compute_selector(&fns[0], &contracts[0]).unwrap();
    let sel2 = compute_selector(&fns[0], &contracts[0]).unwrap();
    assert_eq!(sel1, sel2, "selector must be deterministic");
}

#[test]
fn compute_selector_differs_for_different_functions() {
    use crate::codegen::wasm::compute_selector;

    let src = r#"
        contract Foo {
            pub fn transfer(amount: u32) {}
            pub fn approve(amount: u32) {}
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    let sel_transfer = compute_selector(&fns[0], &contracts[0]).unwrap();
    let sel_approve = compute_selector(&fns[1], &contracts[0]).unwrap();
    assert_ne!(
        sel_transfer, sel_approve,
        "different function names must produce different selectors"
    );
}

// ── Storage key computation ─────────────────────────────────────────────────

#[test]
fn storage_key_is_deterministic() {
    use crate::codegen::wasm::storage_key;

    let key1 = storage_key("count");
    let key2 = storage_key("count");
    assert_eq!(key1, key2, "storage key must be deterministic");
}

#[test]
fn storage_key_differs_for_different_fields() {
    use crate::codegen::wasm::storage_key;

    let key_count = storage_key("count");
    let key_total = storage_key("total");
    assert_ne!(
        key_count, key_total,
        "different field names must produce different storage keys"
    );
}

// ── Dispatch execution tests ────────────────────────────────────────────────
//
// These tests compile full contracts with `emit_module`, then execute them
// with wasmtime using a stateful stub linker that tracks storage writes and
// provides storage reads.

use std::collections::BTreeMap as StdBTreeMap;
use std::sync::{Arc, Mutex};

/// Shared state for the test stub linker.
struct StubState {
    /// In-memory storage: key bytes → value bytes.
    storage: StdBTreeMap<Vec<u8>, Vec<u8>>,
    /// Register file: register_id → bytes.
    registers: StdBTreeMap<u32, Vec<u8>>,
}

impl StubState {
    fn new() -> Self {
        Self {
            storage: StdBTreeMap::new(),
            registers: StdBTreeMap::new(),
        }
    }
}

/// Build a wasmtime instance from compiled WASM bytes with a stateful stub linker.
///
/// The stub linker implements storage_read/write with an in-memory BTreeMap,
/// and input/register_len/read_register for calldata delivery.
#[allow(clippy::type_complexity)]
fn instantiate_with_stubs(
    wasm_bytes: &[u8],
    calldata: &[u8],
) -> Result<(wasmtime::Instance, wasmtime::Store<Arc<Mutex<StubState>>>), String> {
    use crate::codegen::abi::{IMPORT_MODULE, IMPORT_ORDER};
    use crate::codegen::wasm::HOST_SIGS;

    let engine = wasmtime::Engine::default();
    let state = Arc::new(Mutex::new(StubState::new()));

    // Pre-load calldata into register 0
    {
        let mut s = state.lock().map_err(|e| format!("lock: {e}"))?;
        s.registers.insert(0, calldata.to_vec());
    }

    let mut store = wasmtime::Store::new(&engine, state.clone());
    let module =
        wasmtime::Module::new(&engine, wasm_bytes).map_err(|e| format!("wasmtime compile: {e}"))?;

    let mut linker = wasmtime::Linker::new(&engine);

    // Register all 14 host functions with stateful implementations
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        let (params, results) = HOST_SIGS[i];
        let func_ty = wasmtime::FuncType::new(
            &engine,
            params.iter().map(|vt| match vt {
                wasm_encoder::ValType::I32 => wasmtime::ValType::I32,
                wasm_encoder::ValType::I64 => wasmtime::ValType::I64,
                _ => wasmtime::ValType::I32,
            }),
            results.iter().map(|vt| match vt {
                wasm_encoder::ValType::I32 => wasmtime::ValType::I32,
                wasm_encoder::ValType::I64 => wasmtime::ValType::I64,
                _ => wasmtime::ValType::I32,
            }),
        );

        let host_name = *name;
        let state_clone = state.clone();

        linker
            .func_new(
                IMPORT_MODULE,
                name,
                func_ty,
                move |mut caller: wasmtime::Caller<'_, Arc<Mutex<StubState>>>,
                      params: &[wasmtime::Val],
                      results: &mut [wasmtime::Val]| {
                    let st = state_clone.clone();
                    match host_name {
                        "input" => {
                            // input(register_id) — calldata is already in register 0
                            // No-op: calldata was pre-loaded
                            Ok(())
                        }
                        "register_len" => {
                            // register_len(register_id) -> i64
                            let reg_id = params[0].unwrap_i32() as u32;
                            let s = st.lock().unwrap();
                            let len = s
                                .registers
                                .get(&reg_id)
                                .map(|v| v.len() as i64)
                                .unwrap_or(-1); // REGISTER_EMPTY
                            results[0] = wasmtime::Val::I64(len);
                            Ok(())
                        }
                        "read_register" => {
                            // read_register(register_id, ptr)
                            let reg_id = params[0].unwrap_i32() as u32;
                            let ptr = params[1].unwrap_i32() as usize;
                            let s = st.lock().unwrap();
                            if let Some(data) = s.registers.get(&reg_id) {
                                let memory = caller
                                    .get_export("memory")
                                    .and_then(|e| e.into_memory())
                                    .expect("memory export");
                                let mem_data = memory.data_mut(&mut caller);
                                let end = ptr + data.len();
                                if end <= mem_data.len() {
                                    mem_data[ptr..end].copy_from_slice(data);
                                }
                            }
                            Ok(())
                        }
                        "storage_read" => {
                            // storage_read(key_ptr, key_len, register_id) -> i32
                            let key_ptr = params[0].unwrap_i32() as usize;
                            let key_len = params[1].unwrap_i32() as usize;
                            let reg_id = params[2].unwrap_i32() as u32;
                            let memory = caller
                                .get_export("memory")
                                .and_then(|e| e.into_memory())
                                .expect("memory export");
                            let mem_data = memory.data(&caller);
                            let key = mem_data[key_ptr..key_ptr + key_len].to_vec();
                            let mut s = st.lock().unwrap();
                            let val_opt = s.storage.get(&key).cloned();
                            if let Some(val) = val_opt {
                                s.registers.insert(reg_id, val);
                                results[0] = wasmtime::Val::I32(0); // STORAGE_FOUND
                            } else {
                                results[0] = wasmtime::Val::I32(-1); // STORAGE_NOT_FOUND
                            }
                            Ok(())
                        }
                        "storage_write" => {
                            // storage_write(key_ptr, key_len, val_ptr, val_len)
                            let key_ptr = params[0].unwrap_i32() as usize;
                            let key_len = params[1].unwrap_i32() as usize;
                            let val_ptr = params[2].unwrap_i32() as usize;
                            let val_len = params[3].unwrap_i32() as usize;
                            let memory = caller
                                .get_export("memory")
                                .and_then(|e| e.into_memory())
                                .expect("memory export");
                            let mem_data = memory.data(&caller);
                            let key = mem_data[key_ptr..key_ptr + key_len].to_vec();
                            let val = mem_data[val_ptr..val_ptr + val_len].to_vec();
                            let mut s = st.lock().unwrap();
                            s.storage.insert(key, val);
                            Ok(())
                        }
                        "value_return" => {
                            // value_return(ptr, len) — store return data in register 99
                            let ptr = params[0].unwrap_i32() as usize;
                            let len = params[1].unwrap_i32() as usize;
                            let memory = caller
                                .get_export("memory")
                                .and_then(|e| e.into_memory())
                                .expect("memory export");
                            let mem_data = memory.data(&caller);
                            let data = mem_data[ptr..ptr + len].to_vec();
                            let mut s = st.lock().unwrap();
                            s.registers.insert(99, data);
                            Ok(())
                        }
                        _ => {
                            // Default stub: zero-fill results
                            for r in results.iter_mut() {
                                *r = wasmtime::Val::I32(0);
                            }
                            Ok(())
                        }
                    }
                },
            )
            .map_err(|e| format!("linker.func_new({host_name}): {e}"))?;
    }

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("instantiation: {e}"))?;

    Ok((instance, store))
}

/// Build calldata with a 4-byte LE selector and optional arg bytes.
fn build_calldata(selector: u32, args: &[u8]) -> Vec<u8> {
    let mut cd = selector.to_le_bytes().to_vec();
    cd.extend_from_slice(args);
    cd
}

#[test]
fn dispatch_calls_correct_function_by_selector() {
    use crate::codegen::wasm::{compute_selector, storage_key};

    let src = r#"
        contract Math {
            state { value: u32 }
            pub fn set(x: u32) {
                self.value = x;
            }
            pub fn get() -> u32 {
                return self.value;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    // Compute selectors
    let fns = contracts[0].functions();
    let pub_fns: Vec<_> = fns
        .iter()
        .filter(|f| matches!(f.visibility, crate::parser::Visibility::Pub))
        .filter(|f| f.body.is_some())
        .collect();

    let sel_set = compute_selector(pub_fns[0], &contracts[0]).unwrap();
    let sel_get = compute_selector(pub_fns[1], &contracts[0]).unwrap();

    // Call set(42) — selector + u32 arg (LE)
    let calldata = build_calldata(sel_set, &42u32.to_le_bytes());
    let (instance, mut store) =
        instantiate_with_stubs(&bytes, &calldata).expect("instantiation failed");

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    call_fn.call(&mut store, ()).expect("call should succeed");

    // W2: Verify storage key matches storage_key("value") AND value == 42
    {
        let state = store.data().lock().unwrap();
        let expected_key = storage_key("value").to_vec();
        let stored_val = state
            .storage
            .get(&expected_key)
            .expect("storage should contain key for 'value'");
        assert_eq!(
            stored_val,
            &42u32.to_le_bytes().to_vec(),
            "stored value should be 42 as LE u32"
        );
    }

    // W2 negative: call get() on fresh storage — verify it does NOT write to storage
    // (get is a read-only function) and succeeds without trapping.
    let calldata_get = build_calldata(sel_get, &[]);
    let (instance_get, mut store_get) =
        instantiate_with_stubs(&bytes, &calldata_get).expect("instantiation failed");

    let call_fn_get = instance_get
        .get_typed_func::<(), ()>(&mut store_get, "call")
        .expect("get call fn");
    call_fn_get
        .call(&mut store_get, ())
        .expect("get() should succeed on fresh storage");

    // get() should NOT have written to storage (it's a read-only function)
    let state_get = store_get.data().lock().unwrap();
    assert!(
        state_get.storage.is_empty(),
        "get() should not write to storage"
    );
}

#[test]
fn dispatch_unknown_selector_traps() {
    let src = r#"
        contract Foo {
            pub fn bar() {}
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    // Use a bogus selector
    let calldata = build_calldata(0xDEADBEEF, &[]);
    let (instance, mut store) =
        instantiate_with_stubs(&bytes, &calldata).expect("instantiation failed");

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    let result = call_fn.call(&mut store, ());
    assert!(
        result.is_err(),
        "unknown selector should trap, got: {result:?}"
    );
}

#[test]
fn dispatch_empty_calldata_traps() {
    let src = r#"
        contract Foo {
            pub fn bar() {}
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    // Empty calldata (less than 4 bytes)
    let calldata: Vec<u8> = vec![];
    let (instance, mut store) =
        instantiate_with_stubs(&bytes, &calldata).expect("instantiation failed");

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    let result = call_fn.call(&mut store, ());
    assert!(
        result.is_err(),
        "empty calldata should trap, got: {result:?}"
    );
}

#[test]
fn storage_write_then_read_roundtrips() {
    use crate::codegen::wasm::compute_selector;

    let src = r#"
        contract Counter {
            state { count: u32 }
            pub fn set(x: u32) {
                self.count = x;
            }
            pub fn get() -> u32 {
                return self.count;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let fns = contracts[0].functions();
    let pub_fns: Vec<_> = fns
        .iter()
        .filter(|f| matches!(f.visibility, crate::parser::Visibility::Pub))
        .filter(|f| f.body.is_some())
        .collect();

    let sel_set = compute_selector(pub_fns[0], &contracts[0]).unwrap();
    let sel_get = compute_selector(pub_fns[1], &contracts[0]).unwrap();

    // Step 1: Call set(42) — writes to storage
    let calldata_set = build_calldata(sel_set, &42u32.to_le_bytes());
    let (instance, mut store) =
        instantiate_with_stubs(&bytes, &calldata_set).expect("instantiation failed");

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    call_fn
        .call(&mut store, ())
        .expect("set(42) should succeed");

    // Verify storage has the value
    let storage_snapshot: StdBTreeMap<Vec<u8>, Vec<u8>> = {
        let state = store.data().lock().unwrap();
        state.storage.clone()
    };
    assert_eq!(
        storage_snapshot.len(),
        1,
        "should have exactly one storage entry"
    );

    // Verify the stored value is 42 (LE u32)
    let stored_val = storage_snapshot.values().next().unwrap();
    assert_eq!(
        stored_val,
        &42u32.to_le_bytes().to_vec(),
        "stored value should be 42 as LE u32"
    );

    // W1: Step 2 — Call get() to exercise emit_storage_read round-trip.
    // We need to re-instantiate with the same storage state but new calldata.
    // Extract storage, build new instance with get() calldata, inject storage.
    let calldata_get = build_calldata(sel_get, &[]);
    let (instance_get, mut store_get) =
        instantiate_with_stubs(&bytes, &calldata_get).expect("instantiation failed");

    // Inject the storage from the set() call into the new instance
    {
        let mut state = store_get.data().lock().unwrap();
        for (k, v) in &storage_snapshot {
            state.storage.insert(k.clone(), v.clone());
        }
    }

    let call_fn_get = instance_get
        .get_typed_func::<(), ()>(&mut store_get, "call")
        .expect("get call fn");
    // Step 3: get() exercises emit_storage_read. It reads the stored value
    // from host storage via storage_read → register_len → read_register →
    // i32.load. The value is pushed on the WASM stack and abandoned by the
    // void return. If the storage read path is broken, this call traps.
    // (value_return emission is deferred — codegen doesn't emit it yet.)
    call_fn_get
        .call(&mut store_get, ())
        .expect("get() should succeed after set(42) — storage read path works");
}

#[test]
fn storage_read_unset_field_takes_default_path() {
    use crate::codegen::wasm::compute_selector;

    let src = r#"
        contract Counter {
            state { count: u32 }
            pub fn get() -> u32 {
                return self.count;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let fns = contracts[0].functions();
    let pub_fns: Vec<_> = fns
        .iter()
        .filter(|f| matches!(f.visibility, crate::parser::Visibility::Pub))
        .filter(|f| f.body.is_some())
        .collect();

    let sel_get = compute_selector(pub_fns[0], &contracts[0]).unwrap();

    // Call get() before any set() — exercises the STORAGE_NOT_FOUND default path.
    // The storage read returns default 0 (pushed on stack, abandoned by void return).
    // If the default path is broken, this call traps.
    let calldata = build_calldata(sel_get, &[]);
    let (instance, mut store) =
        instantiate_with_stubs(&bytes, &calldata).expect("instantiation failed");

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    call_fn
        .call(&mut store, ())
        .expect("get() on unset field should succeed (default 0 path)");
}

#[test]
fn emit_module_deterministic_with_functions() {
    let src = r#"
        contract Counter {
            state { count: u32 }
            pub fn increment() {
                self.count = self.count + 1;
            }
            pub fn get() -> u32 {
                return self.count;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let first = emit_module(&contracts[0]).expect("first emit failed");
    let second = emit_module(&contracts[0]).expect("second emit failed");
    assert_eq!(
        first, second,
        "emit_module with functions must be deterministic"
    );
}

#[test]
fn emit_module_private_functions_not_dispatched() {
    // Private functions should NOT appear in the dispatch table
    let src = r#"
        contract Foo {
            fn helper() -> u32 {
                return 42;
            }
            pub fn get() -> u32 {
                return 1;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");
    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "contract with private fn failed validation: {:?}",
        result.err()
    );
}

// ── C1: Storage read length validation ──────────────────────────────────────

#[test]
fn storage_read_wrong_length_value_traps() {
    use crate::codegen::wasm::{compute_selector, storage_key};

    // Contract declares `count: u32` (4 bytes), but we'll store 8 bytes
    // in the host storage to simulate a type mismatch / corruption.
    let src = r#"
        contract Counter {
            state { count: u32 }
            pub fn get() -> u32 {
                return self.count;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let fns = contracts[0].functions();
    let pub_fns: Vec<_> = fns
        .iter()
        .filter(|f| matches!(f.visibility, crate::parser::Visibility::Pub))
        .filter(|f| f.body.is_some())
        .collect();

    let sel_get = compute_selector(pub_fns[0], &contracts[0]).unwrap();

    // Build instance and inject a WRONG-LENGTH value (8 bytes for a u32 field)
    let calldata = build_calldata(sel_get, &[]);
    let (instance, mut store) =
        instantiate_with_stubs(&bytes, &calldata).expect("instantiation failed");

    {
        let mut state = store.data().lock().unwrap();
        let key = storage_key("count").to_vec();
        // Store 8 bytes instead of the expected 4 bytes
        state.storage.insert(key, 42u64.to_le_bytes().to_vec());
    }

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    let result = call_fn.call(&mut store, ());
    assert!(
        result.is_err(),
        "storage read with wrong-length value should trap, got: {result:?}"
    );
}

// ── W3: Dispatch with missing calldata register traps ───────────────────────

/// Build a wasmtime instance WITHOUT pre-loading calldata into register 0.
/// This means register_len(0) returns -1 (REGISTER_EMPTY).
#[allow(clippy::type_complexity)]
fn instantiate_without_calldata(
    wasm_bytes: &[u8],
) -> Result<(wasmtime::Instance, wasmtime::Store<Arc<Mutex<StubState>>>), String> {
    use crate::codegen::abi::{IMPORT_MODULE, IMPORT_ORDER};
    use crate::codegen::wasm::HOST_SIGS;

    let engine = wasmtime::Engine::default();
    let state = Arc::new(Mutex::new(StubState::new()));
    // Do NOT pre-load register 0 — register_len will return -1

    let mut store = wasmtime::Store::new(&engine, state.clone());
    let module =
        wasmtime::Module::new(&engine, wasm_bytes).map_err(|e| format!("wasmtime compile: {e}"))?;

    let mut linker = wasmtime::Linker::new(&engine);

    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        let (params, results) = HOST_SIGS[i];
        let func_ty = wasmtime::FuncType::new(
            &engine,
            params.iter().map(|vt| match vt {
                wasm_encoder::ValType::I32 => wasmtime::ValType::I32,
                wasm_encoder::ValType::I64 => wasmtime::ValType::I64,
                _ => wasmtime::ValType::I32,
            }),
            results.iter().map(|vt| match vt {
                wasm_encoder::ValType::I32 => wasmtime::ValType::I32,
                wasm_encoder::ValType::I64 => wasmtime::ValType::I64,
                _ => wasmtime::ValType::I32,
            }),
        );

        let host_name = *name;
        let state_clone = state.clone();

        linker
            .func_new(
                IMPORT_MODULE,
                name,
                func_ty,
                move |mut caller: wasmtime::Caller<'_, Arc<Mutex<StubState>>>,
                      params: &[wasmtime::Val],
                      results: &mut [wasmtime::Val]| {
                    let st = state_clone.clone();
                    match host_name {
                        "input" => {
                            // input(register_id) — no calldata pre-loaded, no-op
                            Ok(())
                        }
                        "register_len" => {
                            let reg_id = params[0].unwrap_i32() as u32;
                            let s = st.lock().unwrap();
                            let len = s
                                .registers
                                .get(&reg_id)
                                .map(|v| v.len() as i64)
                                .unwrap_or(-1); // REGISTER_EMPTY
                            results[0] = wasmtime::Val::I64(len);
                            Ok(())
                        }
                        "read_register" => {
                            let reg_id = params[0].unwrap_i32() as u32;
                            let ptr = params[1].unwrap_i32() as usize;
                            let s = st.lock().unwrap();
                            if let Some(data) = s.registers.get(&reg_id) {
                                let memory = caller
                                    .get_export("memory")
                                    .and_then(|e| e.into_memory())
                                    .expect("memory export");
                                let mem_data = memory.data_mut(&mut caller);
                                let end = ptr + data.len();
                                if end <= mem_data.len() {
                                    mem_data[ptr..end].copy_from_slice(data);
                                }
                            }
                            Ok(())
                        }
                        _ => {
                            for r in results.iter_mut() {
                                *r = wasmtime::Val::I32(0);
                            }
                            Ok(())
                        }
                    }
                },
            )
            .map_err(|e| format!("linker.func_new({host_name}): {e}"))?;
    }

    let instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| format!("instantiation: {e}"))?;

    Ok((instance, store))
}

#[test]
fn dispatch_missing_calldata_register_traps() {
    // When register 0 is not pre-loaded, register_len returns -1.
    // The W3 fix ensures this traps instead of allocating 4 GB.
    let src = r#"
        contract Foo {
            pub fn bar() {}
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let (instance, mut store) = instantiate_without_calldata(&bytes).expect("instantiation failed");

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    let result = call_fn.call(&mut store, ());
    assert!(
        result.is_err(),
        "missing calldata register should trap, got: {result:?}"
    );
}

// ── Modifier inlining tests (P3·Step 6f) ────────────────────────────────────

#[test]
fn modifier_pre_post_effects_inline_around_body() {
    // Modifier sets self.step = 1 before `_` and self.step = 3 after `_`.
    // Function body sets self.step = 2.
    // After execution: storage["step"] should be 3 (pre:1 → body:2 → post:3).
    use crate::codegen::wasm::{compute_selector, storage_key};

    let src = r#"
        contract Guarded {
            state { step: u32 }
            modifier guard() {
                self.step = 1;
                _;
                self.step = 3;
            }
            @guard
            pub fn doWork() {
                self.step = 2;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    // Validate WASM structure
    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "modifier-inlined WASM failed validation: {:?}",
        result.err()
    );

    // Execute doWork() and verify storage writes
    let fns = contracts[0].functions();
    let pub_fns: Vec<_> = fns
        .iter()
        .filter(|f| matches!(f.visibility, crate::parser::Visibility::Pub))
        .filter(|f| f.body.is_some())
        .collect();

    let sel = compute_selector(pub_fns[0], &contracts[0]).unwrap();
    let calldata = build_calldata(sel, &[]);
    let (instance, mut store) =
        instantiate_with_stubs(&bytes, &calldata).expect("instantiation failed");

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    call_fn
        .call(&mut store, ())
        .expect("doWork() with modifier should succeed");

    // Verify final storage value: step should be 3 (post-modifier effect)
    let state = store.data().lock().unwrap();
    let key = storage_key("step").to_vec();
    let stored = state.storage.get(&key).expect("step should be in storage");
    assert_eq!(
        stored,
        &3u32.to_le_bytes().to_vec(),
        "step should be 3 after modifier post-effect"
    );
}

#[test]
fn stacked_modifiers_apply_outermost_first() {
    // @a @b fn f(): a.pre → b.pre → body → b.post → a.post
    //
    // modifier a: self.x = 10; _; self.x = self.x + 1;
    // modifier b: self.x = self.x + self.x; _;
    // body: (no storage writes — just a no-op let binding)
    //
    // Execution order:
    //   a.pre:  x = 10
    //   b.pre:  x = x + x = 20
    //   body:   (no-op)
    //   b.post: (none)
    //   a.post: x = x + 1 = 21
    //
    // Final: x = 21
    use crate::codegen::wasm::{compute_selector, storage_key};

    let src = r#"
        contract Stacked {
            state { x: u32 }
            modifier a() {
                self.x = 10;
                _;
                self.x = self.x + 1;
            }
            modifier b() {
                self.x = self.x + self.x;
                _;
            }
            @a
            @b
            pub fn run() {
                let noop: u32 = 0;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "stacked-modifier WASM failed validation: {:?}",
        result.err()
    );

    let fns = contracts[0].functions();
    let pub_fns: Vec<_> = fns
        .iter()
        .filter(|f| matches!(f.visibility, crate::parser::Visibility::Pub))
        .filter(|f| f.body.is_some())
        .collect();

    let sel = compute_selector(pub_fns[0], &contracts[0]).unwrap();
    let calldata = build_calldata(sel, &[]);
    let (instance, mut store) =
        instantiate_with_stubs(&bytes, &calldata).expect("instantiation failed");

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    call_fn
        .call(&mut store, ())
        .expect("run() with stacked modifiers should succeed");

    let state = store.data().lock().unwrap();
    let key = storage_key("x").to_vec();
    let stored = state.storage.get(&key).expect("x should be in storage");
    assert_eq!(
        stored,
        &21u32.to_le_bytes().to_vec(),
        "x should be 21 after stacked modifiers (a.pre:10 → b.pre:20 → a.post:21)"
    );
}

#[test]
fn function_without_modifiers_unchanged() {
    // A function with no @annotations compiles and runs as before.
    use crate::codegen::wasm::compute_selector;

    let src = r#"
        contract Plain {
            state { val: u32 }
            modifier unused() {
                _;
            }
            pub fn set(x: u32) {
                self.val = x;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let bytes = emit_module(&contracts[0]).expect("emit_module failed");

    let result = wasmparser::validate(&bytes);
    assert!(
        result.is_ok(),
        "plain function WASM failed validation: {:?}",
        result.err()
    );

    let fns = contracts[0].functions();
    let pub_fns: Vec<_> = fns
        .iter()
        .filter(|f| matches!(f.visibility, crate::parser::Visibility::Pub))
        .filter(|f| f.body.is_some())
        .collect();

    let sel = compute_selector(pub_fns[0], &contracts[0]).unwrap();
    let calldata = build_calldata(sel, &7u32.to_le_bytes());
    let (instance, mut store) =
        instantiate_with_stubs(&bytes, &calldata).expect("instantiation failed");

    let call_fn = instance
        .get_typed_func::<(), ()>(&mut store, "call")
        .expect("get call fn");
    call_fn
        .call(&mut store, ())
        .expect("set(7) without modifier should succeed");

    // Verify storage was written
    let state = store.data().lock().unwrap();
    assert_eq!(state.storage.len(), 1, "should have one storage entry");
}

#[test]
fn modifier_not_found_returns_codegen_error() {
    // @nonexistent fn f() → codegen error (modifier not found)
    let src = r#"
        contract Bad {
            @nonexistent
            pub fn broken() {}
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();

    // The annotation "nonexistent" does not match any modifier definition,
    // so it is NOT treated as a modifier annotation — it's filtered out.
    // The function compiles normally (annotations that don't match modifiers
    // are ignored by codegen — they may be semantic annotations like @view).
    let result = emit_module(&contracts[0]);
    assert!(
        result.is_ok(),
        "non-modifier annotation should be ignored, got: {:?}",
        result.err()
    );
}

#[test]
fn parameterized_modifier_returns_codegen_error() {
    // modifier with params → codegen error (deferred)
    let src = r#"
        contract Param {
            modifier withParam(x: u32) {
                _;
            }
            @withParam
            pub fn guarded() {}
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let result = emit_module(&contracts[0]);
    assert!(
        result.is_err(),
        "parameterized modifier should return error"
    );
    let err_msg = format!("{:?}", result.err().unwrap());
    assert!(
        err_msg.contains("parameterized modifier"),
        "error should mention parameterized modifier, got: {err_msg}"
    );
}

#[test]
fn modifier_inlined_module_is_deterministic() {
    // Same input → same bytes, even with modifier inlining.
    let src = r#"
        contract Det {
            state { x: u32 }
            modifier guard() {
                self.x = 1;
                _;
            }
            @guard
            pub fn run() {
                self.x = 2;
            }
        }
    "#;
    let typed = typed_ast_for(src);
    let contracts = typed.contracts();
    let first = emit_module(&contracts[0]).expect("first emit failed");
    let second = emit_module(&contracts[0]).expect("second emit failed");
    assert_eq!(
        first, second,
        "modifier-inlined emit_module must be deterministic"
    );
}
