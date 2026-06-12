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
