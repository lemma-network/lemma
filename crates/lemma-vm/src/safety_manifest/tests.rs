//! Tests for safety manifest types, serialization, and WASM parsing (P3·Step 18).

use super::*;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Build a `RatchetBool` constraint with the given key and locked value.
fn ratchet_bool(key: &[u8], locked_value: &[u8]) -> SafetyConstraint {
    SafetyConstraint::RatchetBool {
        key: key.to_vec(),
        locked_value: locked_value.to_vec(),
    }
}

/// Build a `RatchetOff` constraint with the given key.
fn ratchet_off(key: &[u8]) -> SafetyConstraint {
    SafetyConstraint::RatchetOff { key: key.to_vec() }
}

/// Build a `FeeCap` constraint with the given fee keys and max sum.
fn fee_cap(fee_keys: &[&[u8]], max_sum_bps: u16) -> SafetyConstraint {
    SafetyConstraint::FeeCap {
        fee_keys: fee_keys.iter().map(|k| k.to_vec()).collect(),
        max_sum_bps,
    }
}

/// Build a `RatchetUp` constraint with the given key.
fn ratchet_up(key: &[u8]) -> SafetyConstraint {
    SafetyConstraint::RatchetUp { key: key.to_vec() }
}

/// Serialize to JSON and back, asserting roundtrip equality.
fn assert_roundtrip(original: &SafetyManifest) {
    let json = serde_json::to_string(original).expect("serialize");
    let deserialized: SafetyManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, &deserialized);
}

// ── Per-variant serialization roundtrips ──────────────────────────────────────

#[test]
fn roundtrip_ratchet_bool() {
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    assert_roundtrip(&manifest);
}

#[test]
fn roundtrip_ratchet_off() {
    let manifest = SafetyManifest {
        constraints: vec![ratchet_off(b"mintable")],
    };
    assert_roundtrip(&manifest);
}

#[test]
fn roundtrip_fee_cap() {
    let manifest = SafetyManifest {
        constraints: vec![fee_cap(
            &[b"fees.burn", b"fees.holders", b"fees.others"],
            2500,
        )],
    };
    assert_roundtrip(&manifest);
}

#[test]
fn roundtrip_ratchet_up() {
    let manifest = SafetyManifest {
        constraints: vec![ratchet_up(b"maxWallet")],
    };
    assert_roundtrip(&manifest);
}

// ── Full manifest roundtrip ──────────────────────────────────────────────────

#[test]
fn roundtrip_manifest_with_multiple_constraints() {
    let manifest = SafetyManifest {
        constraints: vec![
            ratchet_bool(b"tradingEnabled", b"\x00"),
            ratchet_off(b"mintable"),
            fee_cap(&[b"fees.burn", b"fees.holders", b"fees.others"], 2500),
            ratchet_up(b"maxWallet"),
        ],
    };
    assert_roundtrip(&manifest);
}

// ── Empty / default manifest ─────────────────────────────────────────────────

#[test]
fn empty_manifest_serializes_and_deserializes() {
    let manifest = SafetyManifest {
        constraints: vec![],
    };
    assert_roundtrip(&manifest);
}

#[test]
fn default_manifest_has_empty_constraints() {
    let manifest = SafetyManifest::default();
    assert!(manifest.constraints.is_empty());
}

#[test]
fn default_manifest_roundtrips() {
    let manifest = SafetyManifest::default();
    assert_roundtrip(&manifest);
}

// ── Tagged enum JSON shape ───────────────────────────────────────────────────

#[test]
fn ratchet_bool_json_contains_type_tag() {
    // Verify the internally-tagged representation produces `"type": "ratchet_bool"`.
    let constraint = ratchet_bool(b"tradingEnabled", b"\x00");
    let json = serde_json::to_string(&constraint).expect("serialize");
    assert!(
        json.contains("\"type\":\"ratchet_bool\""),
        "expected tagged enum with type=ratchet_bool; got: {json}"
    );
}

#[test]
fn fee_cap_json_contains_type_tag() {
    let constraint = fee_cap(&[b"fees.burn"], 1000);
    let json = serde_json::to_string(&constraint).expect("serialize");
    assert!(
        json.contains("\"type\":\"fee_cap\""),
        "expected tagged enum with type=fee_cap; got: {json}"
    );
}

#[test]
fn ratchet_off_json_contains_type_tag() {
    let constraint = ratchet_off(b"mintable");
    let json = serde_json::to_string(&constraint).expect("serialize");
    assert!(
        json.contains("\"type\":\"ratchet_off\""),
        "expected tagged enum with type=ratchet_off; got: {json}"
    );
}

#[test]
fn ratchet_up_json_contains_type_tag() {
    let constraint = ratchet_up(b"maxWallet");
    let json = serde_json::to_string(&constraint).expect("serialize");
    assert!(
        json.contains("\"type\":\"ratchet_up\""),
        "expected tagged enum with type=ratchet_up; got: {json}"
    );
}

// ── parse_safety_manifest from WASM bytecode ─────────────────────────────────

/// Build a minimal valid WASM module with a `"lemma.meta"` custom section
/// containing the given JSON payload.
///
/// Uses `wasm_encoder` to produce a valid WASM binary with:
/// - An empty module (no functions, no memory).
/// - A single custom section named `"lemma.meta"` with `json_bytes` as data.
fn wasm_with_meta_section(json_bytes: &[u8]) -> Vec<u8> {
    use wasm_encoder::{CustomSection, Module};

    let mut module = Module::new();
    module.section(&CustomSection {
        name: std::borrow::Cow::Borrowed("lemma.meta"),
        data: std::borrow::Cow::Borrowed(json_bytes),
    });
    module.finish()
}

/// Build a minimal valid WASM module with NO custom sections.
fn wasm_without_meta_section() -> Vec<u8> {
    use wasm_encoder::Module;
    Module::new().finish()
}

/// Build a `"lemma.meta"` JSON payload with safety_constraints.
fn meta_json_with_constraints(constraints: &[SafetyConstraint]) -> Vec<u8> {
    let constraints_json = serde_json::to_string(constraints).expect("serialize constraints");
    format!(
        "{{\"contract\":\"TestToken\",\"compiler\":\"lemma-lang/0.1.0\",\
         \"functions\":[],\"safety_constraints\":{constraints_json}}}"
    )
    .into_bytes()
}

/// Build a `"lemma.meta"` JSON payload WITHOUT safety_constraints field.
fn meta_json_without_constraints() -> Vec<u8> {
    b"{\"contract\":\"TestToken\",\"compiler\":\"lemma-lang/0.1.0\",\"functions\":[]}".to_vec()
}

#[test]
fn parse_returns_default_for_empty_wasm() {
    // Empty/invalid bytes → default manifest (no panic, no error).
    let manifest = parse_safety_manifest(&[]);
    assert_eq!(manifest, SafetyManifest::default());
    assert!(manifest.constraints.is_empty());
}

#[test]
fn parse_returns_default_for_garbage_bytes() {
    // Random garbage → default manifest (defensive — never crash).
    let manifest = parse_safety_manifest(b"not valid wasm at all");
    assert_eq!(manifest, SafetyManifest::default());
}

#[test]
fn parse_returns_default_for_no_meta_section() {
    // Valid WASM without "lemma.meta" → default manifest.
    let wasm = wasm_without_meta_section();
    let manifest = parse_safety_manifest(&wasm);
    assert_eq!(manifest, SafetyManifest::default());
    assert!(manifest.constraints.is_empty());
}

#[test]
fn parse_returns_default_for_malformed_json_in_meta() {
    // Valid WASM with "lemma.meta" containing invalid JSON → default manifest.
    let wasm = wasm_with_meta_section(b"not json");
    let manifest = parse_safety_manifest(&wasm);
    assert_eq!(manifest, SafetyManifest::default());
}

#[test]
fn parse_returns_default_when_safety_constraints_absent() {
    // Valid WASM with "lemma.meta" but no safety_constraints field → default.
    let json = meta_json_without_constraints();
    let wasm = wasm_with_meta_section(&json);
    let manifest = parse_safety_manifest(&wasm);
    assert_eq!(manifest, SafetyManifest::default());
    assert!(manifest.constraints.is_empty());
}

#[test]
fn parse_extracts_constraints_from_valid_meta() {
    // Valid WASM with "lemma.meta" containing safety_constraints → parsed manifest.
    let constraints = vec![
        ratchet_bool(b"tradingEnabled", b"\x00"),
        ratchet_off(b"mintable"),
        fee_cap(&[b"fees.burn", b"fees.holders"], 2500),
        ratchet_up(b"maxWallet"),
    ];
    let json = meta_json_with_constraints(&constraints);
    let wasm = wasm_with_meta_section(&json);

    let manifest = parse_safety_manifest(&wasm);
    assert_eq!(manifest.constraints.len(), 4);
    assert_eq!(manifest.constraints, constraints);
}

#[test]
fn parse_extracts_single_ratchet_bool_constraint() {
    let constraints = vec![ratchet_bool(b"tradingEnabled", b"\x00")];
    let json = meta_json_with_constraints(&constraints);
    let wasm = wasm_with_meta_section(&json);

    let manifest = parse_safety_manifest(&wasm);
    assert_eq!(manifest.constraints.len(), 1);
    assert_eq!(manifest.constraints[0], constraints[0]);
}

#[test]
fn parse_extracts_empty_constraints_array() {
    // safety_constraints: [] → manifest with empty constraints (not default/None).
    let json = meta_json_with_constraints(&[]);
    let wasm = wasm_with_meta_section(&json);

    let manifest = parse_safety_manifest(&wasm);
    assert!(manifest.constraints.is_empty());
}

// ── validate_safety_invariants tests (P3·Step 18-05) ────────────────────────────

use crate::state::InMemoryStateView;

/// Create a deterministic test address from a seed byte.
fn test_address(seed: u8) -> Address {
    Address::from_public_key(&[seed; 32])
}

/// Build a storage_writes map with a single write.
fn writes_with(addr: &Address, key: &[u8], value: Option<Vec<u8>>) -> StorageWrites {
    let mut map = BTreeMap::new();
    map.insert((*addr, key.to_vec()), value);
    map
}

/// Storage writes map type alias — avoids `clippy::type_complexity`.
type StorageWrites = BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>>;

/// Build a storage_writes map by inserting multiple entries.
///
/// Each call to `insert_write` adds one entry. This avoids a complex
/// slice-of-tuples parameter type that triggers `clippy::type_complexity`.
fn insert_write(map: &mut StorageWrites, addr: &Address, key: &[u8], value: Option<Vec<u8>>) {
    map.insert((*addr, key.to_vec()), value);
}

// ── Empty manifest ───────────────────────────────────────────────────────────

#[test]
fn check_empty_manifest_always_passes() {
    let manifest = SafetyManifest::default();
    let addr = test_address(1);
    let writes = writes_with(&addr, b"anything", Some(vec![42]));
    let canonical = InMemoryStateView::new();

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(result.is_ok());
}

// ── RatchetBool tests ────────────────────────────────────────────────────────

#[test]
fn ratchet_bool_passes_when_key_not_written() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    let writes = BTreeMap::new(); // no writes
    let canonical = InMemoryStateView::new();

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_bool_passes_when_written_to_unlocked_value() {
    // Writing to a value that is NOT the locked value → no violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    // Write tradingEnabled = [1] (unlocked) — this is fine.
    let writes = writes_with(&addr, b"tradingEnabled", Some(vec![1]));
    let canonical = InMemoryStateView::new();

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_bool_passes_when_field_is_new() {
    // New field (no prior value) being set to locked value → no violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    // Write tradingEnabled = [0] (locked), but field didn't exist before.
    let writes = writes_with(&addr, b"tradingEnabled", Some(vec![0]));
    let canonical = InMemoryStateView::new(); // empty — field is new

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_bool_passes_when_already_locked() {
    // Field was already at locked value, writing locked again → no violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    let writes = writes_with(&addr, b"tradingEnabled", Some(vec![0]));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"tradingEnabled", vec![0]); // already locked

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_bool_violates_when_relocking() {
    // Field was unlocked ([1]), now being set to locked ([0]) → violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    let writes = writes_with(&addr, b"tradingEnabled", Some(vec![0]));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"tradingEnabled", vec![1]); // was unlocked

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(result.is_err());
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("ratchet_bool"),
        "error should mention ratchet_bool: {msg}"
    );
    assert!(
        msg.contains("tradingEnabled"),
        "error should mention the key: {msg}"
    );
}

#[test]
fn ratchet_bool_passes_when_deleted() {
    // Deleting a key is not a ratchet-bool violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    let writes = writes_with(&addr, b"tradingEnabled", None); // deleted
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"tradingEnabled", vec![1]);

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

// ── RatchetOff tests ─────────────────────────────────────────────────────────

#[test]
fn ratchet_off_passes_when_key_not_written() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_off(b"mintable")],
    };
    let writes = BTreeMap::new();
    let canonical = InMemoryStateView::new();

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_off_passes_when_disabling() {
    // Transition from on ([1]) to off ([0]) → allowed.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_off(b"mintable")],
    };
    let writes = writes_with(&addr, b"mintable", Some(vec![0]));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"mintable", vec![1]); // was on

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_off_violates_when_re_enabling() {
    // Transition from off ([0]) to on ([1]) → violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_off(b"mintable")],
    };
    let writes = writes_with(&addr, b"mintable", Some(vec![1]));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"mintable", vec![0]); // was off

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("ratchet_off"),
        "error should mention ratchet_off: {msg}"
    );
    assert!(
        msg.contains("mintable"),
        "error should mention the key: {msg}"
    );
}

#[test]
fn ratchet_off_passes_when_already_on() {
    // Was on ([1]), writing on ([1]) again → no state change, no violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_off(b"mintable")],
    };
    let writes = writes_with(&addr, b"mintable", Some(vec![1]));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"mintable", vec![1]); // was already on

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_off_passes_when_field_is_new() {
    // New field being set to on ([1]) → no prior off state, no violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_off(b"mintable")],
    };
    let writes = writes_with(&addr, b"mintable", Some(vec![1]));
    let canonical = InMemoryStateView::new(); // empty

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

// ── FeeCap tests ─────────────────────────────────────────────────────────────

#[test]
fn fee_cap_passes_when_no_fee_keys_written() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![fee_cap(&[b"fees.burn", b"fees.holders"], 2500)],
    };
    let writes = BTreeMap::new();
    let canonical = InMemoryStateView::new();

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn fee_cap_passes_when_sum_within_cap() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![fee_cap(&[b"fees.burn", b"fees.holders"], 2500)],
    };
    // fees.burn = 1000 bps (LE u64)
    let writes = writes_with(&addr, b"fees.burn", Some(1000u64.to_le_bytes().to_vec()));
    let mut canonical = InMemoryStateView::new();
    // fees.holders = 500 bps (from canonical)
    canonical.write(&addr, b"fees.holders", 500u64.to_le_bytes().to_vec());
    // Total: 1000 + 500 = 1500 ≤ 2500 → OK

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn fee_cap_violates_when_sum_exceeds_cap() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![fee_cap(&[b"fees.burn", b"fees.holders"], 2500)],
    };
    // fees.burn = 2000 bps
    let writes = writes_with(&addr, b"fees.burn", Some(2000u64.to_le_bytes().to_vec()));
    let mut canonical = InMemoryStateView::new();
    // fees.holders = 1000 bps
    canonical.write(&addr, b"fees.holders", 1000u64.to_le_bytes().to_vec());
    // Total: 2000 + 1000 = 3000 > 2500 → violation

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("fee_cap"),
        "error should mention fee_cap: {msg}"
    );
    assert!(msg.contains("3000"), "error should mention the sum: {msg}");
    assert!(msg.contains("2500"), "error should mention the cap: {msg}");
}

#[test]
fn fee_cap_passes_when_sum_equals_cap() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![fee_cap(&[b"fees.burn", b"fees.holders"], 2500)],
    };
    // fees.burn = 1500, fees.holders = 1000 → total = 2500 = cap → OK
    let mut writes = BTreeMap::new();
    insert_write(
        &mut writes,
        &addr,
        b"fees.burn",
        Some(1500u64.to_le_bytes().to_vec()),
    );
    insert_write(
        &mut writes,
        &addr,
        b"fees.holders",
        Some(1000u64.to_le_bytes().to_vec()),
    );
    let canonical = InMemoryStateView::new();

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn fee_cap_treats_deleted_key_as_zero() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![fee_cap(&[b"fees.burn", b"fees.holders"], 2500)],
    };
    // fees.burn = 1000, fees.holders deleted → total = 1000 ≤ 2500 → OK
    let mut writes = BTreeMap::new();
    insert_write(
        &mut writes,
        &addr,
        b"fees.burn",
        Some(1000u64.to_le_bytes().to_vec()),
    );
    insert_write(&mut writes, &addr, b"fees.holders", None); // deleted
    let canonical = InMemoryStateView::new();

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

// ── RatchetUp tests ──────────────────────────────────────────────────────────

#[test]
fn ratchet_up_passes_when_key_not_written() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_up(b"maxWallet")],
    };
    let writes = BTreeMap::new();
    let canonical = InMemoryStateView::new();

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_up_passes_when_increasing() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_up(b"maxWallet")],
    };
    // Old: 100, New: 200 → increase → OK
    let writes = writes_with(&addr, b"maxWallet", Some(200u128.to_le_bytes().to_vec()));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"maxWallet", 100u128.to_le_bytes().to_vec());

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_up_passes_when_equal() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_up(b"maxWallet")],
    };
    // Old: 100, New: 100 → same → OK
    let writes = writes_with(&addr, b"maxWallet", Some(100u128.to_le_bytes().to_vec()));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"maxWallet", 100u128.to_le_bytes().to_vec());

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_up_violates_when_decreasing() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_up(b"maxWallet")],
    };
    // Old: 200, New: 100 → decrease → violation
    let writes = writes_with(&addr, b"maxWallet", Some(100u128.to_le_bytes().to_vec()));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"maxWallet", 200u128.to_le_bytes().to_vec());

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("ratchet_up"),
        "error should mention ratchet_up: {msg}"
    );
    assert!(msg.contains("200"), "error should mention old value: {msg}");
    assert!(msg.contains("100"), "error should mention new value: {msg}");
}

#[test]
fn ratchet_up_passes_when_field_is_new() {
    // New field (no prior value) → no ratchet violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_up(b"maxWallet")],
    };
    let writes = writes_with(&addr, b"maxWallet", Some(100u128.to_le_bytes().to_vec()));
    let canonical = InMemoryStateView::new(); // empty

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_up_violates_when_deleted_and_old_nonzero() {
    // Deleting a field with a nonzero old value → decrease to 0 → violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_up(b"maxWallet")],
    };
    let writes = writes_with(&addr, b"maxWallet", None); // deleted
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"maxWallet", 100u128.to_le_bytes().to_vec());

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("ratchet_up"),
        "error should mention ratchet_up: {msg}"
    );
    assert!(
        msg.contains("deleted"),
        "error should mention deletion: {msg}"
    );
}

#[test]
fn ratchet_up_passes_when_deleted_and_old_zero() {
    // Deleting a field with old value 0 → 0 to 0 → no violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_up(b"maxWallet")],
    };
    let writes = writes_with(&addr, b"maxWallet", None); // deleted
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"maxWallet", 0u128.to_le_bytes().to_vec());

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

// ── Multiple constraints ─────────────────────────────────────────────────────

#[test]
fn check_stops_at_first_violation() {
    // Multiple constraints, first one violated → error from first.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![
            ratchet_bool(b"tradingEnabled", b"\x00"),
            ratchet_up(b"maxWallet"),
        ],
    };
    // Violate ratchet_bool: was unlocked ([1]), now locking ([0]).
    let mut writes = BTreeMap::new();
    insert_write(&mut writes, &addr, b"tradingEnabled", Some(vec![0]));
    insert_write(
        &mut writes,
        &addr,
        b"maxWallet",
        Some(50u128.to_le_bytes().to_vec()),
    ); // also decrease
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"tradingEnabled", vec![1]);
    canonical.write(&addr, b"maxWallet", 100u128.to_le_bytes().to_vec());

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(result.is_err());
    // Should be the ratchet_bool violation (first constraint).
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("ratchet_bool"),
        "first violation should be ratchet_bool: {msg}"
    );
}

#[test]
fn check_passes_when_all_constraints_satisfied() {
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![
            ratchet_bool(b"tradingEnabled", b"\x00"),
            ratchet_off(b"mintable"),
            fee_cap(&[b"fees.burn", b"fees.holders"], 2500),
            ratchet_up(b"maxWallet"),
        ],
    };
    // All writes are safe:
    // - tradingEnabled: [0] → [1] (unlocking, not locking)
    // - mintable: [1] → [0] (disabling, allowed)
    // - fees.burn: 500 bps (within cap)
    // - maxWallet: 100 → 200 (increasing)
    let mut writes = BTreeMap::new();
    insert_write(&mut writes, &addr, b"tradingEnabled", Some(vec![1]));
    insert_write(&mut writes, &addr, b"mintable", Some(vec![0]));
    insert_write(
        &mut writes,
        &addr,
        b"fees.burn",
        Some(500u64.to_le_bytes().to_vec()),
    );
    insert_write(
        &mut writes,
        &addr,
        b"maxWallet",
        Some(200u128.to_le_bytes().to_vec()),
    );
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"tradingEnabled", vec![0]);
    canonical.write(&addr, b"mintable", vec![1]);
    canonical.write(&addr, b"fees.holders", 500u64.to_le_bytes().to_vec());
    canonical.write(&addr, b"maxWallet", 100u128.to_le_bytes().to_vec());

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

// ── Different contract address ───────────────────────────────────────────────

#[test]
fn check_ignores_writes_to_different_contract() {
    // Writes to a different contract address should not trigger violations.
    let contract_addr = test_address(1);
    let other_addr = test_address(2);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    // Write to other_addr, not contract_addr → no violation.
    let writes = writes_with(&other_addr, b"tradingEnabled", Some(vec![0]));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&other_addr, b"tradingEnabled", vec![1]);

    assert!(validate_safety_invariants(&manifest, &contract_addr, &writes, &canonical).is_ok());
}

// ── Byte helper tests ────────────────────────────────────────────────────────

#[test]
fn bytes_to_u64_handles_empty() {
    assert_eq!(super::bytes_to_u64(&[]).unwrap(), 0);
}

#[test]
fn bytes_to_u64_handles_short_slice() {
    // [100, 0] → 100 in LE
    assert_eq!(super::bytes_to_u64(&[100, 0]).unwrap(), 100);
}

#[test]
fn bytes_to_u64_handles_full_8_bytes() {
    let val: u64 = 123_456_789;
    assert_eq!(super::bytes_to_u64(&val.to_le_bytes()).unwrap(), val);
}

#[test]
fn bytes_to_u64_rejects_oversized_slice() {
    // C4 fix: more than 8 bytes → Err (reject, not truncate).
    let mut bytes = 42u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xFF, 0xFF]); // 10 bytes total
    let result = super::bytes_to_u64(&bytes);
    assert!(result.is_err(), "oversized u64 encoding must be rejected");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("10 bytes"),
        "error should mention the actual byte count: {msg}"
    );
}

#[test]
fn bytes_to_u128_handles_empty() {
    assert_eq!(super::bytes_to_u128(&[]).unwrap(), 0);
}

#[test]
fn bytes_to_u128_handles_short_slice() {
    assert_eq!(super::bytes_to_u128(&[200, 0]).unwrap(), 200);
}

#[test]
fn bytes_to_u128_handles_full_16_bytes() {
    let val: u128 = 999_999_999_999;
    assert_eq!(super::bytes_to_u128(&val.to_le_bytes()).unwrap(), val);
}

#[test]
fn bytes_to_u128_rejects_oversized_slice() {
    // C4 fix: more than 16 bytes → Err (reject, not truncate).
    let mut bytes = 77u128.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xFF, 0xFF]); // 18 bytes total
    let result = super::bytes_to_u128(&bytes);
    assert!(result.is_err(), "oversized u128 encoding must be rejected");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("18 bytes"),
        "error should mention the actual byte count: {msg}"
    );
}

// ── C3 fix: double-write tests (ScratchState stores final write only) ────────

#[test]
fn ratchet_bool_lock_then_unlock_nets_to_unlocked_passes() {
    // C3: ScratchState only stores the final write. If a tx writes locked then
    // unlocked, the net effect is unlocked → no violation.
    // This test confirms the final-write semantics: the scratch map contains
    // only the last value written to a key.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    // Simulate: first write locked ([0]), then overwrite with unlocked ([1]).
    // ScratchState BTreeMap::insert overwrites → final value is [1] (unlocked).
    let writes = writes_with(&addr, b"tradingEnabled", Some(vec![1])); // net: unlocked
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"tradingEnabled", vec![1]); // was unlocked

    // Net write is unlocked → no violation.
    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_bool_unlock_then_lock_nets_to_locked_violates() {
    // C3: If a tx writes unlocked then locked, the net effect is locked.
    // ScratchState stores only the final write → locked value → violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_bool(b"tradingEnabled", b"\x00")],
    };
    // Simulate: first write unlocked ([1]), then overwrite with locked ([0]).
    // ScratchState BTreeMap::insert overwrites → final value is [0] (locked).
    let writes = writes_with(&addr, b"tradingEnabled", Some(vec![0])); // net: locked
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"tradingEnabled", vec![1]); // was unlocked

    // Net write is locked (was unlocked → now locked) → violation.
    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("ratchet_bool"),
        "error should mention ratchet_bool: {msg}"
    );
}

// ── C4 fix: oversized bytes rejection in invariant checks ────────────────────

#[test]
fn fee_cap_oversized_bytes_rejects() {
    // C4: fee value stored as 9 bytes → violation (oversized u64 encoding).
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![fee_cap(&[b"fees.burn"], 2500)],
    };
    // Write a 9-byte value (exceeds u64's 8-byte limit).
    let oversized_value = vec![0u8; 9];
    let writes = writes_with(&addr, b"fees.burn", Some(oversized_value));
    let canonical = InMemoryStateView::new();

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(result.is_err(), "oversized fee value must be rejected");
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("9 bytes"),
        "error should mention the byte count: {msg}"
    );
}

#[test]
fn ratchet_up_oversized_bytes_rejects() {
    // C4: ratchet-up value stored as 17 bytes → violation (oversized u128 encoding).
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_up(b"maxWallet")],
    };
    // Write a 17-byte value (exceeds u128's 16-byte limit).
    let oversized_value = vec![1u8; 17];
    let writes = writes_with(&addr, b"maxWallet", Some(oversized_value));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"maxWallet", 100u128.to_le_bytes().to_vec());

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(
        result.is_err(),
        "oversized ratchet-up value must be rejected"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("17 bytes"),
        "error should mention the byte count: {msg}"
    );
}

// ── W2 fix: normalized boolean interpretation for RatchetOff ─────────────────

#[test]
fn ratchet_off_multi_byte_truthy_re_enable_violates() {
    // W2: multi-byte truthy value (e.g. [0, 1]) re-enabling from falsy → violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_off(b"mintable")],
    };
    // New value is [0, 1] — truthy (second byte is non-zero).
    let writes = writes_with(&addr, b"mintable", Some(vec![0, 1]));
    let mut canonical = InMemoryStateView::new();
    // Old value is [0, 0] — falsy (all zeros).
    canonical.write(&addr, b"mintable", vec![0, 0]);

    let result = validate_safety_invariants(&manifest, &addr, &writes, &canonical);
    assert!(
        result.is_err(),
        "multi-byte truthy re-enable must be a violation"
    );
}

#[test]
fn ratchet_off_multi_byte_falsy_to_truthy_from_empty_passes() {
    // W2: new field (no prior value) being set to truthy → no violation.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_off(b"mintable")],
    };
    let writes = writes_with(&addr, b"mintable", Some(vec![0, 0, 1]));
    let canonical = InMemoryStateView::new(); // empty — field is new

    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

#[test]
fn ratchet_off_all_zero_multi_byte_is_falsy_no_violation() {
    // W2: writing all-zero multi-byte value is falsy → disabling, not re-enabling.
    let addr = test_address(1);
    let manifest = SafetyManifest {
        constraints: vec![ratchet_off(b"mintable")],
    };
    // New value is [0, 0, 0] — falsy.
    let writes = writes_with(&addr, b"mintable", Some(vec![0, 0, 0]));
    let mut canonical = InMemoryStateView::new();
    canonical.write(&addr, b"mintable", vec![1]); // was on

    // Disabling (truthy → falsy) is allowed.
    assert!(validate_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
}

// ── parse_host_abi tests (P3·Step 20, DB-A58 L2) ─────────────────────────────

use super::parse_host_abi;

/// Build a minimal valid WASM module with a `"lemma.meta"` custom section
/// containing the given JSON payload.
///
/// Reuses the same helper pattern as `wasm_with_meta_section` above (DRY).
fn wasm_with_meta_json(json_bytes: &[u8]) -> Vec<u8> {
    use wasm_encoder::{CustomSection, Module};
    let mut module = Module::new();
    module.section(&CustomSection {
        name: std::borrow::Cow::Borrowed("lemma.meta"),
        data: std::borrow::Cow::Borrowed(json_bytes),
    });
    module.finish()
}

#[test]
fn parse_host_abi_defaults_to_1_for_empty_bytes() {
    // Empty/invalid bytes → no "lemma.meta" section → default 1.
    assert_eq!(parse_host_abi(&[]), 1);
}

#[test]
fn parse_host_abi_defaults_to_1_for_garbage_bytes() {
    // Random garbage → WASM parse error → default 1 (never panics).
    assert_eq!(parse_host_abi(b"not valid wasm at all"), 1);
}

#[test]
fn parse_host_abi_defaults_to_1_when_section_absent() {
    // Valid WASM without "lemma.meta" → default 1 (backward compat).
    let wasm = wasm_without_meta_section();
    assert_eq!(parse_host_abi(&wasm), 1);
}

#[test]
fn parse_host_abi_defaults_to_1_when_field_absent() {
    // Valid WASM with "lemma.meta" but no "host_abi" field → default 1.
    // This is the expected case for contracts compiled before P3·Step 20.
    let json = b"{\"contract\":\"TestToken\",\"compiler\":\"lemma-lang/0.1.0\",\"functions\":[]}";
    let wasm = wasm_with_meta_json(json);
    assert_eq!(parse_host_abi(&wasm), 1);
}

#[test]
fn parse_host_abi_defaults_to_1_for_malformed_json() {
    // Valid WASM with "lemma.meta" containing invalid JSON → default 1.
    let wasm = wasm_with_meta_json(b"not json at all");
    assert_eq!(parse_host_abi(&wasm), 1);
}

#[test]
fn parse_host_abi_reads_correct_value() {
    // Valid WASM with "lemma.meta" containing {"host_abi": 1} → returns 1.
    let json = b"{\"contract\":\"TestToken\",\"compiler\":\"lemma-lang/0.1.0\",\
                  \"functions\":[],\"host_abi\":1}";
    let wasm = wasm_with_meta_json(json);
    assert_eq!(parse_host_abi(&wasm), 1);
}

#[test]
fn parse_host_abi_reads_value_2() {
    // Valid WASM with "lemma.meta" containing {"host_abi": 2} → returns 2.
    // (Even though v2 is not yet supported, the parser must read it correctly
    //  so the deploy gate can reject it with UnsupportedHostAbi.)
    let json = b"{\"contract\":\"TestToken\",\"compiler\":\"lemma-lang/0.1.0\",\
                  \"functions\":[],\"host_abi\":2}";
    let wasm = wasm_with_meta_json(json);
    assert_eq!(parse_host_abi(&wasm), 2);
}

#[test]
fn parse_host_abi_rejects_out_of_range_value_with_default() {
    // Value 9999999999 fits u64 but overflows u32 → u32::try_from fails → default 1.
    // This tests the conservative/safe fallback for out-of-range values.
    let json = b"{\"contract\":\"TestToken\",\"compiler\":\"lemma-lang/0.1.0\",\
                  \"functions\":[],\"host_abi\":9999999999}";
    let wasm = wasm_with_meta_json(json);
    assert_eq!(parse_host_abi(&wasm), 1);
}

#[test]
fn parse_host_abi_defaults_to_1_for_negative_value() {
    // Negative JSON number → as_u64() returns None → default 1.
    let json = b"{\"contract\":\"TestToken\",\"compiler\":\"lemma-lang/0.1.0\",\
                  \"functions\":[],\"host_abi\":-1}";
    let wasm = wasm_with_meta_json(json);
    assert_eq!(parse_host_abi(&wasm), 1);
}

#[test]
fn parse_host_abi_defaults_to_1_for_string_value() {
    // String value for host_abi → as_u64() returns None → default 1.
    let json = b"{\"contract\":\"TestToken\",\"compiler\":\"lemma-lang/0.1.0\",\
                  \"functions\":[],\"host_abi\":\"v1\"}";
    let wasm = wasm_with_meta_json(json);
    assert_eq!(parse_host_abi(&wasm), 1);
}

// ── S3-1: Cross-crate host-ABI version anchor pin test ───────────────────────

#[test]
fn s3_1_host_abi_anchor_emit_leq_max() {
    // Pin test: the compiler's emitted HOST_ABI_VERSION must be ≤ the VM's
    // MAX_SUPPORTED_HOST_ABI. Both now reference lemma_core::CURRENT_HOST_ABI_VERSION,
    // but this test catches any future divergence (e.g. if one side is bumped
    // without the other, or if the anchor is bypassed).
    //
    // See docs/17-VERSIONING_SPEC.md §3.
    let emit_version = lemma_core::CURRENT_HOST_ABI_VERSION;
    let max_supported = crate::MAX_SUPPORTED_HOST_ABI;
    assert!(
        emit_version <= max_supported,
        "S3-1: compiler emit version ({emit_version}) must be ≤ VM max supported ({max_supported})"
    );
}

// ── S3-2: Cross-crate SafetyConstraint mirror round-trip test ────────────────
//
// The compiler (lemma-lang) emits SafetyConstraintMeta (Serialize-only) and the
// VM (lemma-vm) deserializes SafetyConstraint (Serialize+Deserialize). These are
// a deliberate cross-WASM-section mirror (AGENTS §8) kept in sync by hand.
//
// This test pins the wire contract: for every shared variant, serialize the
// emit-side enum → deserialize as the parse-side enum → assert tags+fields match.
// A renamed tag or new variant breaks THIS test, not production.
//
// Note: SafetyConstraint::RatchetBool exists only on the VM side (the compiler
// deleted it per P3 audit subtask 10). It is tested separately for backward
// compat (VM can still deserialize old contracts that embedded it).

/// Serialize a SafetyConstraintMeta (lang-side) to JSON, then deserialize as
/// SafetyConstraint (VM-side) and assert structural equality.
fn assert_mirror_roundtrip(lang_json: &str, expected_vm: &SafetyConstraint) {
    let deserialized: SafetyConstraint = serde_json::from_str(lang_json).unwrap_or_else(|e| {
        panic!("S3-2: lang→vm deserialization failed for JSON: {lang_json}\nerror: {e}")
    });
    assert_eq!(
        &deserialized, expected_vm,
        "S3-2: lang→vm mirror mismatch for JSON: {lang_json}"
    );
}

#[test]
fn s3_2_mirror_roundtrip_ratchet_off() {
    // Lang emits: {"type":"ratchet_off","key":[109,105,110,116,97,98,108,101]}
    // VM must deserialize to SafetyConstraint::RatchetOff { key: b"mintable" }
    use lemma_lang::codegen::metadata::SafetyConstraintMeta;

    let lang_variant = SafetyConstraintMeta::ratchet_off(b"mintable");
    let lang_json = serde_json::to_string(&lang_variant).expect("serialize lang");
    let expected = SafetyConstraint::RatchetOff {
        key: b"mintable".to_vec(),
    };
    assert_mirror_roundtrip(&lang_json, &expected);
}

#[test]
fn s3_2_mirror_roundtrip_fee_cap() {
    // Lang emits: {"type":"fee_cap","fee_keys":[[...],[...]],"max_sum_bps":2500}
    // VM must deserialize to SafetyConstraint::FeeCap { fee_keys, max_sum_bps }
    use lemma_lang::codegen::metadata::SafetyConstraintMeta;

    let lang_variant =
        SafetyConstraintMeta::fee_cap(&[b"fees.burn", b"fees.holders", b"fees.others"], 2500);
    let lang_json = serde_json::to_string(&lang_variant).expect("serialize lang");
    let expected = SafetyConstraint::FeeCap {
        fee_keys: vec![
            b"fees.burn".to_vec(),
            b"fees.holders".to_vec(),
            b"fees.others".to_vec(),
        ],
        max_sum_bps: 2500,
    };
    assert_mirror_roundtrip(&lang_json, &expected);
}

#[test]
fn s3_2_mirror_roundtrip_ratchet_up() {
    // Lang emits: {"type":"ratchet_up","key":[109,97,120,87,97,108,108,101,116]}
    // VM must deserialize to SafetyConstraint::RatchetUp { key: b"maxWallet" }
    use lemma_lang::codegen::metadata::SafetyConstraintMeta;

    let lang_variant = SafetyConstraintMeta::ratchet_up(b"maxWallet");
    let lang_json = serde_json::to_string(&lang_variant).expect("serialize lang");
    let expected = SafetyConstraint::RatchetUp {
        key: b"maxWallet".to_vec(),
    };
    assert_mirror_roundtrip(&lang_json, &expected);
}

#[test]
fn s3_2_mirror_roundtrip_full_manifest() {
    // Serialize a full manifest from the lang side, deserialize as VM SafetyManifest.
    // This catches field-level drift (e.g. "safety_constraints" vs "constraints").
    use lemma_lang::codegen::metadata::SafetyConstraintMeta;

    let lang_constraints = vec![
        SafetyConstraintMeta::ratchet_off(b"mintable"),
        SafetyConstraintMeta::fee_cap(&[b"fees.burn", b"fees.holders"], 2500),
        SafetyConstraintMeta::ratchet_up(b"maxWallet"),
    ];
    let lang_json = serde_json::to_string(&lang_constraints).expect("serialize lang");

    let vm_constraints: Vec<SafetyConstraint> =
        serde_json::from_str(&lang_json).expect("deserialize vm");

    assert_eq!(vm_constraints.len(), 3);
    assert_eq!(
        vm_constraints[0],
        SafetyConstraint::RatchetOff {
            key: b"mintable".to_vec()
        }
    );
    assert_eq!(
        vm_constraints[1],
        SafetyConstraint::FeeCap {
            fee_keys: vec![b"fees.burn".to_vec(), b"fees.holders".to_vec()],
            max_sum_bps: 2500,
        }
    );
    assert_eq!(
        vm_constraints[2],
        SafetyConstraint::RatchetUp {
            key: b"maxWallet".to_vec()
        }
    );
}

#[test]
fn s3_2_ratchet_bool_vm_only_backward_compat() {
    // RatchetBool exists only on the VM side (compiler deleted it per P3 audit
    // subtask 10). Verify the VM can still deserialize it from old contracts.
    let json = r#"{"type":"ratchet_bool","key":[116,114,97,100,105,110,103],"locked_value":[0]}"#;
    let constraint: SafetyConstraint = serde_json::from_str(json)
        .expect("VM must still deserialize RatchetBool for backward compat");
    assert_eq!(
        constraint,
        SafetyConstraint::RatchetBool {
            key: b"trading".to_vec(),
            locked_value: vec![0],
        }
    );
}
