//! Tests for `codegen::metadata` (P3·Step 6i, Step 18, Step 19).
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.
//! Test naming: `{action}_{outcome}` (AGENTS §11.3).

use super::{build_metadata, extract_safety_constraints, SafetyConstraintMeta};
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

// ─── build_metadata — safety_ruleset version (P3·Step 19, DB-A58 L1) ─────────

#[test]
fn build_metadata_includes_safety_ruleset_version() {
    // "safety_ruleset" field must be present and equal the compile-time constant.
    let typed = typed_ast_for("contract C {}");
    let contracts = typed.contracts();
    let bytes = build_metadata(&contracts[0]);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let ruleset = json["safety_ruleset"]
        .as_str()
        .expect("safety_ruleset must be a string");
    assert_eq!(
        ruleset, "1.0.0",
        "safety_ruleset must equal SAFETY_RULESET_VERSION constant"
    );
}

// ─── extract_safety_constraints — unit tests (P3·Step 18) ────────────────────

#[test]
fn extract_returns_empty_for_plain_contract() {
    // Plain contract (no token standard) → no safety constraints.
    let typed = typed_ast_for("contract C {}");
    let contracts = typed.contracts();
    let constraints = extract_safety_constraints(&contracts[0]);
    assert!(
        constraints.is_empty(),
        "plain contract must produce zero safety constraints; got {constraints:?}"
    );
}

#[test]
fn extract_ratchet_off_for_mintable_true() {
    // Token with `mintable: true` → RatchetOff constraint on "mintable" key.
    let typed = typed_ast_for(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
mintable: true
}
state { totalSupply: u128 = 0 }
init() {}
}"#,
    );
    let contracts = typed.contracts();
    let constraints = extract_safety_constraints(&contracts[0]);
    assert!(
        constraints.contains(&SafetyConstraintMeta::RatchetOff {
            key: b"mintable".to_vec(),
        }),
        "mintable: true must produce RatchetOff constraint; got {constraints:?}"
    );
}

#[test]
fn extract_no_ratchet_off_for_mintable_false() {
    // Token with `mintable: false` → no RatchetOff (feature already disabled).
    let typed = typed_ast_for(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
mintable: false
}
state { totalSupply: u128 = 0 }
init() {}
}"#,
    );
    let contracts = typed.contracts();
    let constraints = extract_safety_constraints(&contracts[0]);
    let has_mintable_ratchet = constraints
        .iter()
        .any(|c| matches!(c, SafetyConstraintMeta::RatchetOff { key } if key == b"mintable"));
    assert!(
        !has_mintable_ratchet,
        "mintable: false must NOT produce RatchetOff constraint; got {constraints:?}"
    );
}

#[test]
fn extract_fee_cap_for_tax_token() {
    // TaxToken with `maxFeePercent: 1000` → FeeCap constraint.
    let typed = typed_ast_for(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 1000
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0 }
init() {}
}"#,
    );
    let contracts = typed.contracts();
    let constraints = extract_safety_constraints(&contracts[0]);
    let fee_cap = constraints
        .iter()
        .find(|c| matches!(c, SafetyConstraintMeta::FeeCap { .. }));
    assert!(
        fee_cap.is_some(),
        "TaxToken with maxFeePercent must produce FeeCap constraint; got {constraints:?}"
    );
    if let Some(SafetyConstraintMeta::FeeCap {
        fee_keys,
        max_sum_bps,
    }) = fee_cap
    {
        assert_eq!(
            *max_sum_bps, 1000,
            "max_sum_bps must match maxFeePercent config value"
        );
        assert_eq!(
            fee_keys.len(),
            3,
            "FeeCap must include 3 fee component keys"
        );
        assert!(fee_keys.contains(&b"fees.burn".to_vec()));
        assert!(fee_keys.contains(&b"fees.holders".to_vec()));
        assert!(fee_keys.contains(&b"fees.others".to_vec()));
    }
}

#[test]
fn extract_ratchet_up_for_max_wallet() {
    // Token with `maxWallet: 5000000` → RatchetUp constraint.
    let typed = typed_ast_for(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxWallet: 5000000
}
state { totalSupply: u128 = 0 }
init() {}
}"#,
    );
    let contracts = typed.contracts();
    let constraints = extract_safety_constraints(&contracts[0]);
    assert!(
        constraints.contains(&SafetyConstraintMeta::RatchetUp {
            key: b"maxWallet".to_vec(),
        }),
        "maxWallet config must produce RatchetUp constraint; got {constraints:?}"
    );
}

#[test]
fn extract_multiple_constraints() {
    // Token with multiple features → multiple constraints emitted.
    let typed = typed_ast_for(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
mintable: true
pausable: true
freezable: true
maxWallet: 500
}
state { totalSupply: u128 = 0 }
init() {}
}"#,
    );
    let contracts = typed.contracts();
    let constraints = extract_safety_constraints(&contracts[0]);

    // Should have: RatchetOff(mintable), RatchetOff(pausable), RatchetOff(freezable), RatchetUp(maxWallet)
    assert!(
        constraints.contains(&SafetyConstraintMeta::RatchetOff {
            key: b"mintable".to_vec(),
        }),
        "must include RatchetOff for mintable; got {constraints:?}"
    );
    assert!(
        constraints.contains(&SafetyConstraintMeta::RatchetOff {
            key: b"pausable".to_vec(),
        }),
        "must include RatchetOff for pausable; got {constraints:?}"
    );
    assert!(
        constraints.contains(&SafetyConstraintMeta::RatchetOff {
            key: b"freezable".to_vec(),
        }),
        "must include RatchetOff for freezable; got {constraints:?}"
    );
    assert!(
        constraints.contains(&SafetyConstraintMeta::RatchetUp {
            key: b"maxWallet".to_vec(),
        }),
        "must include RatchetUp for maxWallet; got {constraints:?}"
    );
    assert_eq!(
        constraints.len(),
        4,
        "expected exactly 4 constraints (3 RatchetOff + 1 RatchetUp); got {constraints:?}"
    );
}

// ─── build_metadata — safety_constraints integration tests (P3·Step 18) ──────

#[test]
fn build_metadata_omits_safety_constraints_for_plain_contract() {
    // Plain contract → no "safety_constraints" key in JSON (skip_serializing_if).
    let typed = typed_ast_for("contract C {}");
    let contracts = typed.contracts();
    let bytes = build_metadata(&contracts[0]);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert!(
        json.get("safety_constraints").is_none(),
        "plain contract must not have safety_constraints key; got {json}"
    );
}

#[test]
fn build_metadata_includes_safety_constraints_for_token() {
    // Token with mintable: true → safety_constraints array present in JSON.
    let typed = typed_ast_for(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
mintable: true
}
state { totalSupply: u128 = 0 }
init() {}
}"#,
    );
    let contracts = typed.contracts();
    let bytes = build_metadata(&contracts[0]);
    let json: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let sc = json["safety_constraints"]
        .as_array()
        .expect("safety_constraints must be an array");
    assert!(
        !sc.is_empty(),
        "token with mintable: true must have constraints"
    );
    assert_eq!(
        sc[0]["type"], "ratchet_off",
        "first constraint must be ratchet_off"
    );
}

#[test]
fn build_metadata_fee_cap_no_emit_for_plain_token_with_max_fee() {
    // Plain Token (not TaxToken) with maxFeePercent → no FeeCap constraint.
    // FeeCap is only for TaxToken which has the fees state block.
    let typed = typed_ast_for(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
}
state { totalSupply: u128 = 0 }
init() {}
}"#,
    );
    let contracts = typed.contracts();
    let constraints = extract_safety_constraints(&contracts[0]);
    let has_fee_cap = constraints
        .iter()
        .any(|c| matches!(c, SafetyConstraintMeta::FeeCap { .. }));
    assert!(
        !has_fee_cap,
        "plain Token (not TaxToken) must NOT produce FeeCap constraint; got {constraints:?}"
    );
}

// ─── build_metadata — host_abi field (P3·Step 20, DB-A58 L2) ─────────────────

#[test]
fn build_metadata_contains_host_abi_field() {
    // Every compiled contract must carry host_abi in its meta section (DB-A58 L2).
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = build_metadata(&contracts[0]);
    let obj: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    assert!(
        obj.get("host_abi").is_some(),
        "meta.json missing 'host_abi' field"
    );
}

#[test]
fn build_metadata_host_abi_equals_constant() {
    // host_abi must equal HOST_ABI_VERSION (1) — the initial 17-fn set (P3·Step 6b-vm-2).
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let bytes = build_metadata(&contracts[0]);
    let obj: serde_json::Value = serde_json::from_slice(&bytes).expect("valid JSON");
    let host_abi = obj["host_abi"].as_u64().expect("host_abi must be a number");
    assert_eq!(host_abi, 1, "host_abi must equal HOST_ABI_VERSION (1)");
}

#[test]
fn build_metadata_host_abi_is_deterministic() {
    // Identical source → byte-identical host_abi (AGENTS §7.1 determinism).
    let typed = typed_ast_for("contract Foo {}");
    let contracts = typed.contracts();
    let a = build_metadata(&contracts[0]);
    let b = build_metadata(&contracts[0]);
    assert_eq!(a, b, "build_metadata must be deterministic");
}
