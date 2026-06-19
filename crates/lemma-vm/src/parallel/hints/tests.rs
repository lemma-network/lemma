//! Tests for `"lemma.meta"` hint parsing and disjointness logic (B5-3 part-b).

use super::*;

// ── JSON parsing helpers ──────────────────────────────────────────────────────

/// Build a minimal `"lemma.meta"` JSON payload for testing.
fn meta_json(functions: &[(&str, &[&str], &[&str], bool)]) -> Vec<u8> {
    let fns: Vec<String> = functions
        .iter()
        .map(|(name, reads, writes, express)| {
            let reads_json = reads
                .iter()
                .map(|r| format!("{{\"Field\":\"{r}\"}}"))
                .collect::<Vec<_>>()
                .join(",");
            let writes_json = writes
                .iter()
                .map(|w| format!("{{\"Field\":\"{w}\"}}"))
                .collect::<Vec<_>>()
                .join(",");
            format!(
                "{{\"name\":\"{name}\",\"reads\":[{reads_json}],\"writes\":[{writes_json}],\
                 \"is_express_eligible\":{express},\"estimated_gas\":200}}"
            )
        })
        .collect();
    format!(
        "{{\"contract\":\"TestContract\",\"compiler\":\"lemma-lang/0.1.0\",\"functions\":[{}]}}",
        fns.join(",")
    )
    .into_bytes()
}

/// Build a `"lemma.meta"` JSON payload with SenderSlot writes (for Express tests).
fn meta_json_sender_slot(fn_name: &str, field: &str) -> Vec<u8> {
    format!(
        "{{\"contract\":\"Token\",\"compiler\":\"lemma-lang/0.1.0\",\"functions\":[\
         {{\"name\":\"{fn_name}\",\
           \"reads\":[{{\"SenderSlot\":\"{field}\"}}],\
           \"writes\":[{{\"SenderSlot\":\"{field}\"}}],\
           \"is_express_eligible\":true,\
           \"estimated_gas\":400}}]}}"
    )
    .into_bytes()
}

/// Build a `"lemma.meta"` JSON payload with a ParamSlot write.
fn meta_json_param_slot(fn_name: &str, field: &str, key: &str) -> Vec<u8> {
    format!(
        "{{\"contract\":\"Token\",\"compiler\":\"lemma-lang/0.1.0\",\"functions\":[\
         {{\"name\":\"{fn_name}\",\
           \"reads\":[],\
           \"writes\":[{{\"ParamSlot\":{{\"field\":\"{field}\",\"key\":\"{key}\"}}}}],\
           \"is_express_eligible\":false,\
           \"estimated_gas\":200}}]}}"
    )
    .into_bytes()
}

// ── parse_hints_from_json ─────────────────────────────────────────────────────

#[test]
fn parse_hints_from_json_returns_none_for_empty_input() {
    assert!(parse_hints_from_json(b"").is_none());
}

#[test]
fn parse_hints_from_json_returns_none_for_invalid_json() {
    assert!(parse_hints_from_json(b"not json").is_none());
}

#[test]
fn parse_hints_from_json_parses_empty_functions_list() {
    let json = b"{\"contract\":\"X\",\"compiler\":\"lemma-lang/0.1.0\",\"functions\":[]}";
    let hints = parse_hints_from_json(json).expect("valid JSON parses");
    assert!(hints.functions.is_empty());
}

#[test]
fn parse_hints_from_json_parses_field_reads_and_writes() {
    let json = meta_json(&[("transfer", &["balances"], &["balances"], false)]);
    let hints = parse_hints_from_json(&json).expect("valid JSON parses");
    let hint = hints.functions.get("transfer").expect("transfer present");
    assert!(hint.reads.contains("Field:balances"));
    assert!(hint.writes.contains("Field:balances"));
    assert!(!hint.is_express_eligible);
}

#[test]
fn parse_hints_from_json_parses_sender_slot_and_express_eligible() {
    let json = meta_json_sender_slot("transfer", "balances");
    let hints = parse_hints_from_json(&json).expect("valid JSON parses");
    let hint = hints.functions.get("transfer").expect("transfer present");
    assert!(hint.reads.contains("SenderSlot:balances"));
    assert!(hint.writes.contains("SenderSlot:balances"));
    assert!(hint.is_express_eligible);
}

#[test]
fn parse_hints_from_json_parses_param_slot() {
    let json = meta_json_param_slot("approve", "allowances", "spender");
    let hints = parse_hints_from_json(&json).expect("valid JSON parses");
    let hint = hints.functions.get("approve").expect("approve present");
    assert!(hint.writes.contains("ParamSlot:allowances:spender"));
}

#[test]
fn parse_hints_from_json_parses_multiple_functions() {
    let json = meta_json(&[
        ("transfer", &["balances"], &["balances"], false),
        ("mint", &[], &["totalSupply", "balances"], false),
        ("pause", &[], &["paused"], false),
    ]);
    let hints = parse_hints_from_json(&json).expect("valid JSON parses");
    assert_eq!(hints.functions.len(), 3);
    assert!(hints.functions.contains_key("transfer"));
    assert!(hints.functions.contains_key("mint"));
    assert!(hints.functions.contains_key("pause"));
}

// ── FunctionHint::is_disjoint_from ───────────────────────────────────────────

#[test]
fn is_disjoint_from_returns_false_for_empty_hints() {
    // Empty hints = "no information" → conservatively assume conflict.
    let a = FunctionHint::default();
    let b = FunctionHint::default();
    assert!(!a.is_disjoint_from(&b));
}

#[test]
fn is_disjoint_from_returns_false_for_shared_write_key() {
    let a = FunctionHint {
        reads: BTreeSet::new(),
        writes: ["Field:balances".to_string()].into(),
        is_express_eligible: false,
    };
    let b = FunctionHint {
        reads: BTreeSet::new(),
        writes: ["Field:balances".to_string()].into(),
        is_express_eligible: false,
    };
    assert!(!a.is_disjoint_from(&b));
}

#[test]
fn is_disjoint_from_returns_false_for_write_read_conflict() {
    // a writes "balances", b reads "balances" → conflict.
    let a = FunctionHint {
        reads: BTreeSet::new(),
        writes: ["Field:balances".to_string()].into(),
        is_express_eligible: false,
    };
    let b = FunctionHint {
        reads: ["Field:balances".to_string()].into(),
        writes: ["Field:totalSupply".to_string()].into(),
        is_express_eligible: false,
    };
    assert!(!a.is_disjoint_from(&b));
}

#[test]
fn is_disjoint_from_returns_true_for_non_overlapping_fields() {
    // a writes "paused", b writes "totalSupply" — no overlap.
    let a = FunctionHint {
        reads: ["Field:paused".to_string()].into(),
        writes: ["Field:paused".to_string()].into(),
        is_express_eligible: false,
    };
    let b = FunctionHint {
        reads: ["Field:totalSupply".to_string()].into(),
        writes: ["Field:totalSupply".to_string()].into(),
        is_express_eligible: false,
    };
    assert!(a.is_disjoint_from(&b));
}

#[test]
fn is_disjoint_from_returns_true_for_distinct_sender_slots() {
    // Two transfer() calls from different senders: SenderSlot:balances for each.
    // The HINT is the same (both write SenderSlot:balances) — so they are NOT
    // disjoint at the hint level (same key string). Disjointness at the
    // per-address level is resolved by the MVCC layer, not the hint layer.
    // This test verifies the hint-level behavior is conservative (not disjoint).
    let a = FunctionHint {
        reads: ["SenderSlot:balances".to_string()].into(),
        writes: ["SenderSlot:balances".to_string()].into(),
        is_express_eligible: true,
    };
    let b = FunctionHint {
        reads: ["SenderSlot:balances".to_string()].into(),
        writes: ["SenderSlot:balances".to_string()].into(),
        is_express_eligible: true,
    };
    // Same key string → not disjoint at hint level (MVCC handles per-address).
    assert!(!a.is_disjoint_from(&b));
}

// ── Express eligibility classification ───────────────────────────────────────

#[test]
fn express_eligible_flag_is_preserved_through_parse() {
    let json = meta_json_sender_slot("transfer", "balances");
    let hints = parse_hints_from_json(&json).expect("parses");
    let hint = hints.functions.get("transfer").expect("present");
    assert!(hint.is_express_eligible);
}

#[test]
fn non_express_eligible_flag_is_preserved_through_parse() {
    let json = meta_json(&[("mint", &[], &["totalSupply"], false)]);
    let hints = parse_hints_from_json(&json).expect("parses");
    let hint = hints.functions.get("mint").expect("present");
    assert!(!hint.is_express_eligible);
}

// ── ContractHints default ─────────────────────────────────────────────────────

#[test]
fn contract_hints_default_has_empty_functions() {
    let hints = ContractHints::default();
    assert!(hints.functions.is_empty());
}
