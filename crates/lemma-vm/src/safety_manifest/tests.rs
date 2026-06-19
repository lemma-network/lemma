//! Tests for safety manifest types and serialization (P3·Step 18).

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
