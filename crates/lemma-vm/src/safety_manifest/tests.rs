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

// ── check_safety_invariants tests (P3·Step 18-05) ────────────────────────────

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

    let result = check_safety_invariants(&manifest, &addr, &writes, &canonical);
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    let result = check_safety_invariants(&manifest, &addr, &writes, &canonical);
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    let result = check_safety_invariants(&manifest, &addr, &writes, &canonical);
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    let result = check_safety_invariants(&manifest, &addr, &writes, &canonical);
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    let result = check_safety_invariants(&manifest, &addr, &writes, &canonical);
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    let result = check_safety_invariants(&manifest, &addr, &writes, &canonical);
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    let result = check_safety_invariants(&manifest, &addr, &writes, &canonical);
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

    assert!(check_safety_invariants(&manifest, &addr, &writes, &canonical).is_ok());
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

    assert!(check_safety_invariants(&manifest, &contract_addr, &writes, &canonical).is_ok());
}

// ── Byte helper tests ────────────────────────────────────────────────────────

#[test]
fn bytes_to_u64_handles_empty() {
    assert_eq!(super::bytes_to_u64(&[]), 0);
}

#[test]
fn bytes_to_u64_handles_short_slice() {
    // [100, 0] → 100 in LE
    assert_eq!(super::bytes_to_u64(&[100, 0]), 100);
}

#[test]
fn bytes_to_u64_handles_full_8_bytes() {
    let val: u64 = 123_456_789;
    assert_eq!(super::bytes_to_u64(&val.to_le_bytes()), val);
}

#[test]
fn bytes_to_u64_truncates_long_slice() {
    // More than 8 bytes → only first 8 used.
    let mut bytes = 42u64.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xFF, 0xFF]); // extra bytes
    assert_eq!(super::bytes_to_u64(&bytes), 42);
}

#[test]
fn bytes_to_u128_handles_empty() {
    assert_eq!(super::bytes_to_u128(&[]), 0);
}

#[test]
fn bytes_to_u128_handles_short_slice() {
    assert_eq!(super::bytes_to_u128(&[200, 0]), 200);
}

#[test]
fn bytes_to_u128_handles_full_16_bytes() {
    let val: u128 = 999_999_999_999;
    assert_eq!(super::bytes_to_u128(&val.to_le_bytes()), val);
}

#[test]
fn bytes_to_u128_truncates_long_slice() {
    let mut bytes = 77u128.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0xFF, 0xFF]);
    assert_eq!(super::bytes_to_u128(&bytes), 77);
}
