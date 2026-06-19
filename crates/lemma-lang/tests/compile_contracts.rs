//! Integration tests — P3·Step 6j pipeline closeout.
//!
//! Exercises the **full public compiler pipeline** end-to-end:
//!
//! ```text
//! tokenize → parse → check (WF + safety) → compile → Vec<u8> (WASM binary)
//! ```
//!
//! Every test uses only the PUBLIC crate API:
//! `lemma_lang::{tokenize, parse, check, compile}`.
//!
//! These are crate-level integration tests (in `tests/`) — not internal unit
//! tests — so they exercise the crate exactly as external consumers do.
//!
//! ## Layout
//!
//! - `compile_*_produces_valid_wasm` — positive e2e: contracts that MUST
//!   compile to structurally valid WASM (`wasmparser::validate`).
//! - `compile_pipeline_is_deterministic` — same source → byte-identical output
//!   on every call (AGENTS §7.1 determinism requirement).
//! - `compile_produces_*_custom_section` — ABI + metadata sections present
//!   (B5-3 part-a, P3·Step 6i).
//! - `compile_type_error_surfaces_before_codegen` — pipeline ordering: type
//!   errors are caught by `check()`, never reach `compile()`.
//! - `compile_different_contracts_produce_different_bytes` — sanity: distinct
//!   programs produce distinct binaries.

use lemma_lang::error::LangError;
use lemma_lang::{check, compile, parse, tokenize};

// ─── Pipeline helpers ─────────────────────────────────────────────────────────

/// Run the full `tokenize → parse → check → compile` pipeline on `src`.
///
/// `tokenize` and `parse` are expected to succeed (proven by
/// `parse_contracts.rs`). `check` runs WF + safety. `compile` emits WASM.
// LangError is the intentional top-level pipeline error type (see lib.rs).
#[allow(clippy::result_large_err)]
fn pipeline(src: &str) -> Result<Vec<u8>, LangError> {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    let typed = check(ast)?;
    let contracts = typed.contracts();
    assert!(
        !contracts.is_empty(),
        "source must define at least one contract"
    );
    compile(&contracts[0])
}

/// Scan a WASM binary for a named custom section; return its data if found.
///
/// Uses `wasmparser` (bytecodealliance — same org as wasm-encoder) so the
/// scan is spec-correct, not brittle byte-offset arithmetic.
fn find_custom_section(wasm: &[u8], name: &str) -> Option<Vec<u8>> {
    for payload in wasmparser::Parser::new(0).parse_all(wasm) {
        if let Ok(wasmparser::Payload::CustomSection(cs)) = payload {
            if cs.name() == name {
                return Some(cs.data().to_vec());
            }
        }
    }
    None
}

// ─── Positive e2e: valid WASM ─────────────────────────────────────────────────

/// Scenario 1 — empty contract.
///
/// The simplest possible Lem program. Proves the full pipeline produces a
/// structurally valid WASM binary even with no functions or state.
#[test]
fn compile_empty_contract_produces_valid_wasm() {
    let wasm = pipeline("contract Foo {}").expect("pipeline failed");
    let result = wasmparser::validate(&wasm);
    assert!(
        result.is_ok(),
        "empty contract WASM failed validation: {:?}",
        result.err()
    );
}

/// Scenario 2 — contract with a pure public function.
///
/// No state, no side-effects. Proves expression lowering (u64 arithmetic),
/// parameter handling, and return type lowering work end-to-end through the
/// public API.
#[test]
fn compile_contract_with_pure_function_produces_valid_wasm() {
    let wasm = pipeline("contract Math { pub fn double(x: u64) -> u64 { return x + x; } }")
        .expect("pipeline failed");
    let result = wasmparser::validate(&wasm);
    assert!(
        result.is_ok(),
        "pure-function contract WASM failed validation: {:?}",
        result.err()
    );
}

/// Scenario 3 — contract with state, init, and public functions.
///
/// Exercises the full storage path: init writes a field; get reads it back.
/// The state field uses u64, which is supported in codegen.
#[test]
fn compile_contract_with_state_produces_valid_wasm() {
    let wasm = pipeline(
        r#"contract Store {
    state { value: u64 }
    init() { self.value = 0u64; }
    pub fn set(v: u64) { self.value = v; }
    pub fn get() -> u64 { return self.value; }
}"#,
    )
    .expect("pipeline failed");
    let result = wasmparser::validate(&wasm);
    assert!(
        result.is_ok(),
        "stateful contract WASM failed validation: {:?}",
        result.err()
    );
}

/// Scenario 4 — contract with multiple public functions.
///
/// Proves the selector-based dispatch table handles multiple exported
/// functions. Each function gets a unique blake3-derived selector.
#[test]
fn compile_contract_with_multiple_functions_produces_valid_wasm() {
    let wasm = pipeline(
        r#"contract Arith {
    pub fn add(x: u64, y: u64) -> u64 { return x + y; }
    pub fn sub(x: u64, y: u64) -> u64 { return x - y; }
    pub fn is_zero(x: u64) -> bool { return x == 0u64; }
}"#,
    )
    .expect("pipeline failed");
    let result = wasmparser::validate(&wasm);
    assert!(
        result.is_ok(),
        "multi-function contract WASM failed validation: {:?}",
        result.err()
    );
}

// ─── Determinism ──────────────────────────────────────────────────────────────

/// Same source must produce byte-identical WASM on every call (AGENTS §7.1).
///
/// This is a critical invariant: every validator node must produce the same
/// contract hash for the same source, or deploy-time verification diverges.
#[test]
fn compile_pipeline_is_deterministic() {
    let src = r#"contract Counter {
    state { n: u64 }
    init() { self.n = 0u64; }
    pub fn inc() { self.n = self.n + 1u64; }
    pub fn get() -> u64 { return self.n; }
}"#;
    let first = pipeline(src).expect("first pipeline call failed");
    let second = pipeline(src).expect("second pipeline call failed");
    assert_eq!(
        first, second,
        "compile pipeline must be deterministic: same source → same bytes"
    );
}

// ─── Custom section presence (B5-3 part-a, P3·Step 6i) ───────────────────────

/// Every compiled contract must carry a `"lemma.abi"` WASM custom section.
///
/// The ABI section is consumed by off-chain tooling: SDK ABI encoding,
/// explorer display, wallet contract interaction.
#[test]
fn compile_produces_lemma_abi_custom_section() {
    let wasm = pipeline("contract Foo {}").expect("pipeline failed");
    assert!(
        find_custom_section(&wasm, "lemma.abi").is_some(),
        "compiled WASM must contain a 'lemma.abi' custom section"
    );
}

/// Every compiled contract must carry a `"lemma.meta"` WASM custom section.
///
/// The metadata section is consumed by LemmaVM at deploy time to pre-seed
/// the Flux dependency graph and Express eligibility checks (P3·Step 7).
#[test]
fn compile_produces_lemma_meta_custom_section() {
    let wasm = pipeline("contract Foo {}").expect("pipeline failed");
    assert!(
        find_custom_section(&wasm, "lemma.meta").is_some(),
        "compiled WASM must contain a 'lemma.meta' custom section"
    );
}

/// `"lemma.meta"` must contain the contract name.
///
/// The VM reads the contract name from the metadata at deploy time for
/// logging, indexing, and registry purposes.
#[test]
fn compile_lemma_meta_section_contains_contract_name() {
    let wasm = pipeline("contract MyWidget {}").expect("pipeline failed");
    let data = find_custom_section(&wasm, "lemma.meta").expect("'lemma.meta' must be present");
    let json: serde_json::Value =
        serde_json::from_slice(&data).expect("'lemma.meta' must be valid JSON");
    assert_eq!(
        json["contract"], "MyWidget",
        "'lemma.meta' contract field must match source declaration"
    );
}

// ─── Pipeline ordering ───────────────────────────────────────────────────────

/// Type errors must surface from `check()` — they must never reach `compile()`.
///
/// This proves the pipeline gate ordering: `check()` is the correctness gate;
/// `compile()` only runs on well-typed contracts.
#[test]
fn compile_type_error_surfaces_from_check_not_compile() {
    // `return true` in a `-> u64` function is a ReturnTypeMismatch.
    let tokens = tokenize("contract C { pub fn f() -> u64 { return true; } }").expect("tokenize");
    let ast = parse(tokens).expect("parse");
    let result = check(ast);
    assert!(result.is_err(), "type mismatch must be caught by check()");
    assert!(
        matches!(result.unwrap_err(), LangError::Type(_)),
        "error must be LangError::Type, not LangError::Codegen"
    );
    // compile() is never called — the gate stops here.
}

// ─── Sanity ───────────────────────────────────────────────────────────────────

/// Different contracts must produce different WASM binaries.
///
/// Proves that function names and dispatch tables produce distinct bytes —
/// not a single canonical empty module for all inputs.
#[test]
fn compile_different_contracts_produce_different_bytes() {
    let a = pipeline("contract A { pub fn ping() { } }").expect("A failed");
    let b = pipeline("contract B { pub fn pong(x: u64) -> u64 { return x; } }").expect("B failed");
    assert_ne!(
        a, b,
        "distinct contracts must produce distinct WASM binaries"
    );
}
