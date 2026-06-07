use crate::lexer::token::Span;

use super::SafetyError;

fn zero_span() -> Span {
    Span {
        line: 1,
        col: 1,
        offset: 0,
        len: 0,
    }
}

// ─── Display messages are human-readable ─────────────────────────────────────

#[test]
fn display_honeypot_contains_reason() {
    let e = SafetyError::Honeypot {
        reason: "no sell path".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-001"), "missing rule tag: {msg}");
    assert!(msg.contains("no sell path"), "missing reason: {msg}");
}

#[test]
fn display_fee_too_high_shows_bps_values() {
    let e = SafetyError::FeeTooHigh {
        declared: 500,
        found: 800,
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-002"), "missing rule tag: {msg}");
    assert!(msg.contains("800"), "missing found bps: {msg}");
    assert!(msg.contains("500"), "missing declared bps: {msg}");
}

#[test]
fn display_supply_cap_violation_contains_reason() {
    let e = SafetyError::SupplyCapViolation {
        reason: "mint when mintable: false".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-003"), "missing rule tag: {msg}");
    assert!(msg.contains("mint when mintable"), "missing reason: {msg}");
}

#[test]
fn display_state_after_call_shows_function_name() {
    let e = SafetyError::StateAfterCall {
        func: "withdraw".to_string(),
        call_site: zero_span(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-004"), "missing rule tag: {msg}");
    assert!(msg.contains("withdraw"), "missing func name: {msg}");
}

#[test]
fn display_ungoverned_blacklist_shows_function_name() {
    let e = SafetyError::UngovernedBlacklist {
        func: "freezeAddress".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-005"), "missing rule tag: {msg}");
    assert!(msg.contains("freezeAddress"), "missing func name: {msg}");
}

#[test]
fn display_unbounded_approval_contains_reason() {
    let e = SafetyError::UnboundedApproval {
        reason: "no expiry field".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-006"), "missing rule tag: {msg}");
    assert!(msg.contains("no expiry"), "missing reason: {msg}");
}

#[test]
fn display_unsafe_upgrade_contains_reason() {
    let e = SafetyError::UnsafeUpgrade {
        reason: "no governance gate".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-007"), "missing rule tag: {msg}");
    assert!(msg.contains("no governance gate"), "missing reason: {msg}");
}

#[test]
fn display_hook_escape_shows_hook_and_key() {
    let e = SafetyError::HookEscape {
        hook: "onTransfer".to_string(),
        key: "otherContract.balance".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-008"), "missing rule tag: {msg}");
    assert!(msg.contains("onTransfer"), "missing hook name: {msg}");
    assert!(msg.contains("otherContract"), "missing key: {msg}");
}

#[test]
fn display_one_way_gate_shows_function_name() {
    let e = SafetyError::OneWayGate {
        func: "disableTrading".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-009"), "missing rule tag: {msg}");
    assert!(msg.contains("disableTrading"), "missing func name: {msg}");
}

#[test]
fn display_undeclared_restriction_shows_function_name() {
    let e = SafetyError::UndeclaredRestriction {
        func: "transfer".to_string(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-010"), "missing rule tag: {msg}");
    assert!(msg.contains("transfer"), "missing func name: {msg}");
}

#[test]
fn display_unsafe_delegate_contains_rule_tag() {
    let e = SafetyError::UnsafeDelegate {
        call_site: zero_span(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-011"), "missing rule tag: {msg}");
}

#[test]
fn display_unchecked_arithmetic_shows_operator() {
    let e = SafetyError::UncheckedArithmetic {
        op: "+".to_string(),
        span: zero_span(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-012"), "missing rule tag: {msg}");
    assert!(msg.contains('+'), "missing operator: {msg}");
}

#[test]
fn display_missing_ticker_registration_contains_rule_tag() {
    let e = SafetyError::MissingTickerRegistration;
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-013"), "missing rule tag: {msg}");
    assert!(msg.contains("registry.register"), "missing call ref: {msg}");
}

#[test]
fn display_inconclusive_shows_rule_and_reason() {
    let e = SafetyError::Inconclusive {
        rule: "SAFETY-002",
        reason: "non-canonical fee expression".to_string(),
        span: zero_span(),
    };
    let msg = e.to_string();
    assert!(msg.contains("SAFETY-002"), "missing rule: {msg}");
    assert!(msg.contains("non-canonical"), "missing reason: {msg}");
}
