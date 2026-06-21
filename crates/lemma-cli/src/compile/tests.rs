//! Integration tests for `compile::compile_contract` (P3·Step 10).
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.
//! Test naming: `{action}_{outcome}` (AGENTS §11.3).
//!
//! All tests run the full pipeline end-to-end:
//!   write .lem → compile_contract() → inspect output files.

use std::fs;

use super::compile_contract;
use crate::error::LemmaCliError;

// ── Shared fixtures ───────────────────────────────────────────────────────────

/// Minimal Lem contract that passes the full pipeline
/// (type-check + WF-001…015 + SAFETY-001…025 + codegen).
///
/// A plain empty contract has no token-specific WF or safety requirements.
const MINIMAL_CONTRACT: &str = "contract Foo {}";

/// Lem contract with a public function that uses only codegen-supported types.
///
/// Address and u128 params are deferred in codegen/types.rs (multi-word /
/// reference types not yet lowered — Step 6 known limitation). This fixture
/// uses u32 (→ I32 WASM valtype, always supported) to exercise ABI emission.
const CONTRACT_WITH_PUB_FN: &str = r#"
contract Counter {
    pub fn increment(amount: u32) {}
    pub fn get() -> u32 { return 0u32; }
}
"#;

/// Lem source with a lex error (invalid character `@` in identifier position).
const INVALID_LEX_SOURCE: &str = "contract @Bad {}";

/// Lem source with two contracts — used to verify multi-contract output.
const TWO_CONTRACTS: &str = "contract Alpha {}\ncontract Beta {}";

/// Lem source containing only a struct definition (no contracts).
///
/// `compile_contract` should return an empty vec and exit cleanly — struct-only
/// files are valid Lem source but produce no deployable artifacts.
const STRUCT_ONLY_SOURCE: &str = "struct Point { x: u32, y: u32 }";

// ── Helper ────────────────────────────────────────────────────────────────────

/// Write `source` to a temp file and return (temp_dir, source_path).
///
/// The temp dir is returned so it is not dropped before the test finishes.
fn write_temp_source(source: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir failed");
    let path = dir.path().join("contract.lem");
    fs::write(&path, source).expect("write source failed");
    (dir, path)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn compile_produces_three_output_files() {
    let (dir, src) = write_temp_source(MINIMAL_CONTRACT);
    let out = dir.path().join("out");

    let outputs = compile_contract(&src, &out).expect("compile failed");
    assert_eq!(outputs.len(), 1);

    assert!(outputs[0].wasm.exists(), ".wasm not written");
    assert!(outputs[0].abi_json.exists(), ".abi.json not written");
    assert!(outputs[0].meta_json.exists(), ".meta.json not written");
}

#[test]
fn compile_wasm_has_wasm_magic_header() {
    // Every valid WASM binary begins with the 4-byte magic `\0asm` (AGENTS §7.1).
    let (dir, src) = write_temp_source(MINIMAL_CONTRACT);
    let out = dir.path().join("out");

    let outputs = compile_contract(&src, &out).expect("compile failed");
    let wasm_bytes = fs::read(&outputs[0].wasm).expect("read wasm failed");

    assert!(wasm_bytes.len() >= 4, "WASM binary too short");
    assert_eq!(&wasm_bytes[..4], b"\0asm", "WASM magic missing");
}

#[test]
fn compile_abi_json_is_valid_json() {
    let (dir, src) = write_temp_source(MINIMAL_CONTRACT);
    let out = dir.path().join("out");

    let outputs = compile_contract(&src, &out).expect("compile failed");
    let bytes = fs::read(&outputs[0].abi_json).expect("read abi.json failed");

    let parsed: serde_json::Value =
        serde_json::from_slice(&bytes).expect(".abi.json is not valid JSON");

    // ABI is a JSON array of function descriptors.
    assert!(parsed.is_array(), ".abi.json should be a JSON array");
}

#[test]
fn compile_meta_json_has_required_keys() {
    let (dir, src) = write_temp_source(MINIMAL_CONTRACT);
    let out = dir.path().join("out");

    let outputs = compile_contract(&src, &out).expect("compile failed");
    let bytes = fs::read(&outputs[0].meta_json).expect("read meta.json failed");

    let obj: serde_json::Value =
        serde_json::from_slice(&bytes).expect(".meta.json is not valid JSON");

    // Mandatory keys from `metadata::build_metadata` (P3·Step 6i, Step 19).
    assert!(
        obj.get("contract").is_some(),
        "meta.json missing 'contract'"
    );
    assert!(
        obj.get("compiler").is_some(),
        "meta.json missing 'compiler'"
    );
    assert!(
        obj.get("safety_ruleset").is_some(),
        "meta.json missing 'safety_ruleset'"
    );
    assert!(
        obj.get("functions").is_some(),
        "meta.json missing 'functions'"
    );
}

#[test]
fn compile_meta_json_embeds_contract_name() {
    let (dir, src) = write_temp_source(MINIMAL_CONTRACT);
    let out = dir.path().join("out");

    let outputs = compile_contract(&src, &out).expect("compile failed");
    let bytes = fs::read(&outputs[0].meta_json).expect("read meta.json failed");
    let obj: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(
        obj["contract"].as_str(),
        Some("Foo"),
        "meta.json 'contract' should match source name"
    );
}

#[test]
fn compile_rejects_source_with_lex_error() {
    let (dir, src) = write_temp_source(INVALID_LEX_SOURCE);
    let out = dir.path().join("out");

    let err = compile_contract(&src, &out).expect_err("expected compile to fail");
    assert!(
        matches!(err, LemmaCliError::CompileFailed(_)),
        "expected CompileFailed, got: {err:?}"
    );
}

#[test]
fn compile_creates_output_directory_when_absent() {
    let (dir, src) = write_temp_source(MINIMAL_CONTRACT);
    // Point to a nested path that does not exist yet.
    let out = dir.path().join("nested").join("output");

    assert!(!out.exists(), "output dir should not exist before compile");
    compile_contract(&src, &out).expect("compile failed");
    assert!(out.is_dir(), "compile should create the output directory");
}

#[test]
fn compile_produces_one_output_per_contract() {
    let (dir, src) = write_temp_source(TWO_CONTRACTS);
    let out = dir.path().join("out");

    let outputs = compile_contract(&src, &out).expect("compile failed");
    assert_eq!(outputs.len(), 2, "expected 2 outputs for 2 contracts");

    let names: Vec<_> = outputs
        .iter()
        .map(|o| o.wasm.file_stem().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(names.contains(&"Alpha".to_owned()));
    assert!(names.contains(&"Beta".to_owned()));
}

#[test]
fn compile_source_with_no_contracts_produces_empty_output() {
    // Struct-only source is valid Lem but yields no deployable artifacts.
    // compile_contract must return Ok([]) — not an error, not a panic.
    let (dir, src) = write_temp_source(STRUCT_ONLY_SOURCE);
    let out = dir.path().join("out");

    let outputs = compile_contract(&src, &out).expect("compile failed");
    assert!(
        outputs.is_empty(),
        "expected empty output for struct-only source, got {} artifact(s)",
        outputs.len()
    );
}

#[test]
fn compile_contract_with_public_fn_produces_non_empty_abi() {
    // Public functions must appear in the ABI descriptor.
    // Uses u32 params (I32 WASM valtype) — Address/u128 params are deferred
    // in codegen/types.rs until multi-word/reference type lowering ships.
    let (dir, src) = write_temp_source(CONTRACT_WITH_PUB_FN);
    let out = dir.path().join("out");

    let outputs = compile_contract(&src, &out).expect("compile failed");
    let bytes = fs::read(&outputs[0].abi_json).expect("read abi.json failed");
    let arr: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert!(
        arr.as_array().is_some_and(|a| !a.is_empty()),
        ".abi.json should contain at least one entry for 'increment'/'get'"
    );
}
