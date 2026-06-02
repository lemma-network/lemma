//! Tests for `shield::error`.

use lemma_core::Address;

use super::ShieldError;

// ── Display formatting ────────────────────────────────────────────────────────

#[test]
fn committee_too_small_displays_have_value() {
    let err = ShieldError::CommitteeTooSmall { have: 2 };
    let msg = err.to_string();
    assert!(msg.contains("W=2"), "expected W=2 in: {msg}");
    assert!(msg.contains("minimum"), "expected 'minimum' in: {msg}");
}

#[test]
fn zero_weight_validator_displays_address() {
    let addr = Address::zero();
    let err = ShieldError::ZeroWeightValidator(addr);
    let msg = err.to_string();
    assert!(
        msg.contains("zero share weight"),
        "expected 'zero share weight' in: {msg}"
    );
}

#[test]
fn domain_too_large_displays_size() {
    let err = ShieldError::DomainTooLarge { size: 70_000 };
    let msg = err.to_string();
    assert!(msg.contains("70000"), "expected size in: {msg}");
    assert!(msg.contains("65535"), "expected max in: {msg}");
}

#[test]
fn fft_domain_failed_displays_size() {
    let err = ShieldError::FftDomainFailed { size: 99 };
    let msg = err.to_string();
    assert!(msg.contains("99"), "expected size in: {msg}");
}

#[test]
fn lagrange_displays_inner_message() {
    let err = ShieldError::Lagrange("x_coord is zero".to_string());
    let msg = err.to_string();
    assert!(
        msg.contains("x_coord is zero"),
        "expected inner msg in: {msg}"
    );
}

// ── PartialEq ─────────────────────────────────────────────────────────────────

#[test]
fn committee_too_small_partial_eq() {
    assert_eq!(
        ShieldError::CommitteeTooSmall { have: 3 },
        ShieldError::CommitteeTooSmall { have: 3 },
    );
    assert_ne!(
        ShieldError::CommitteeTooSmall { have: 3 },
        ShieldError::CommitteeTooSmall { have: 4 },
    );
}

#[test]
fn domain_too_large_partial_eq() {
    assert_eq!(
        ShieldError::DomainTooLarge { size: 100_000 },
        ShieldError::DomainTooLarge { size: 100_000 },
    );
}
