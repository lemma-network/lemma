//! Tests for `codegen::metadata::build_metadata` (P3·Step 6i).
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.
//! Test naming: `{action}_{outcome}` (AGENTS §11.3).

use crate::codegen::metadata::build_metadata;
use crate::type_checker::TypedAst;
use crate::{parse, tokenize};

// ─── Shared fixtures ──────────────────────────────────────────────────────────

fn typed_ast_for(src: &str) -> TypedAst {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    crate::type_checker::check_skip_wf(ast).expect("check_skip_wf failed")
}

// ─── build_metadata — functional tests ───────────────────────────────────────

#[test]
fn build_metadata_returns_valid_json() {
    // build_metadata must always return parseable UTF-8 JSON.
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = build_metadata(&contracts[0]);
    assert!(!bytes.is_empty(), "metadata must not be empty bytes");
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).expect("build_metadata must return valid UTF-8 JSON");
    assert!(json.is_object(), "metadata JSON must be a top-level object");
}

#[test]
fn build_metadata_includes_contract_name() {
    // "contract" field must match the declared contract name.
    let typed = typed_ast_for("contract MyToken {}");
    let contracts = typed.contracts();
    let bytes = build_metadata(&contracts[0]);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert_eq!(
        json["contract"], "MyToken",
        "metadata 'contract' field must equal declared contract name"
    );
}

#[test]
fn build_metadata_includes_compiler_field() {
    // "compiler" field must be present and start with "lemma-lang/".
    let typed = typed_ast_for("contract C {}");
    let contracts = typed.contracts();
    let bytes = build_metadata(&contracts[0]);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let compiler = json["compiler"]
        .as_str()
        .expect("compiler must be a string");
    assert!(
        compiler.starts_with("lemma-lang/"),
        "compiler field must start with 'lemma-lang/', got: {compiler}"
    );
}

#[test]
fn build_metadata_public_fn_appears_in_functions() {
    // Public functions produce a hint entry in "functions".
    let typed = typed_ast_for("contract C { pub fn transfer(to: Address, amount: u128) { } }");
    let contracts = typed.contracts();
    let bytes = build_metadata(&contracts[0]);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let fns = json["functions"]
        .as_array()
        .expect("functions must be an array");
    assert_eq!(fns.len(), 1, "one public function → one hint entry");
    assert_eq!(fns[0]["name"], "transfer");
    // State-access fields must be present.
    assert!(fns[0]["is_express_eligible"].is_boolean());
    assert!(fns[0]["reads"].is_array());
    assert!(fns[0]["writes"].is_array());
}

#[test]
fn build_metadata_is_deterministic() {
    // Identical source → byte-identical metadata (AGENTS §7.1).
    let typed = typed_ast_for("contract C { pub fn mint(to: Address, amount: u128) { } }");
    let contracts = typed.contracts();
    let first = build_metadata(&contracts[0]);
    let second = build_metadata(&contracts[0]);
    assert_eq!(first, second, "build_metadata must be deterministic");
}
