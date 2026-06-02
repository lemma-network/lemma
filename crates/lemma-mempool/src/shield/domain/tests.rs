//! Tests for `shield::domain`.
//!
//! Covers: FFT domain construction, Lagrange cache correctness, determinism,
//! error cases, and the subset Lagrange computation used by combine (S4).

use ark_bls12_381::Fr;
use ark_ff::{One, Zero};

use super::ShieldDomain;
use crate::shield::ShieldError;

// ── Construction ──────────────────────────────────────────────────────────────

#[test]
fn new_w4_minimum_accepts() {
    let d = ShieldDomain::new(4).unwrap();
    assert_eq!(d.share_count(), 4);
}

#[test]
fn new_w1_is_accepted_by_domain() {
    // W=1 is valid for domain construction (though ShieldParams rejects it).
    // Domain tests are independent of ShieldParams minimum.
    let d = ShieldDomain::new(1).unwrap();
    assert_eq!(d.share_count(), 1);
    assert_eq!(d.share_ids(), &[1u16]);
}

#[test]
fn new_w65535_is_accepted_maximum() {
    // W = u16::MAX = 65_535 — the ShareId ceiling.
    let d = ShieldDomain::new(u64::from(u16::MAX)).unwrap();
    assert_eq!(d.share_count(), 65_535);
    assert_eq!(d.share_ids().len(), 65_535);
}

// ── FFT domain size ───────────────────────────────────────────────────────────

#[test]
fn fft_size_is_next_power_of_two() {
    // arkworks rounds up W to the next power of 2.
    assert_eq!(ShieldDomain::new(4).unwrap().fft_size(), 4); // 4 = 2^2, exact
    assert_eq!(ShieldDomain::new(5).unwrap().fft_size(), 8); // 5 → 8 = 2^3
    assert_eq!(ShieldDomain::new(8).unwrap().fft_size(), 8); // 8 = 2^3, exact
    assert_eq!(ShieldDomain::new(9).unwrap().fft_size(), 16); // 9 → 16 = 2^4
    assert_eq!(ShieldDomain::new(100).unwrap().fft_size(), 128); // 100 → 128
}

#[test]
fn fft_size_gte_share_count() {
    for w in [4u64, 7, 10, 31, 32, 33, 100, 1_000] {
        let d = ShieldDomain::new(w).unwrap();
        assert!(
            d.fft_size() as u64 >= d.share_count(),
            "FFT size {} < share count {} for W={w}",
            d.fft_size(),
            d.share_count()
        );
    }
}

// ── Share IDs sequence ────────────────────────────────────────────────────────

#[test]
fn share_ids_are_one_indexed_ascending() {
    let d = ShieldDomain::new(10).unwrap();
    let ids = d.share_ids();
    assert_eq!(ids, &[1u16, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
}

#[test]
fn share_ids_never_contain_zero() {
    // Zero is forbidden (docknetwork SSError: x_coord = 0).
    for w in [1u64, 4, 10, 100] {
        let d = ShieldDomain::new(w).unwrap();
        assert!(
            !d.share_ids().contains(&0),
            "W={w}: share_ids must not contain 0"
        );
    }
}

#[test]
fn share_ids_length_equals_share_count() {
    for w in [4u64, 7, 100, 1_000] {
        let d = ShieldDomain::new(w).unwrap();
        assert_eq!(d.share_ids().len(), w as usize);
    }
}

// ── Lagrange cache (full set) ─────────────────────────────────────────────────

#[test]
fn lambda_full_length_equals_share_count() {
    let d = ShieldDomain::new(10).unwrap();
    // lambda_full is accessed via lambda_at_full; verify all share IDs return Some.
    for id in 1u16..=10 {
        assert!(
            d.lambda_at_full(id).is_some(),
            "lambda_at_full({id}) should be Some"
        );
    }
}

#[test]
fn lambda_at_full_out_of_range_returns_none() {
    let d = ShieldDomain::new(10).unwrap();
    assert!(d.lambda_at_full(0).is_none(), "share_id=0 is out of range");
    assert!(
        d.lambda_at_full(11).is_none(),
        "share_id=11 > W=10 is out of range"
    );
    assert!(
        d.lambda_at_full(u16::MAX).is_none(),
        "share_id=u16::MAX > W=10 is out of range"
    );
}

#[test]
fn lambda_full_sum_is_one_for_complete_set() {
    // Lagrange basis property: Σ_k λ_k(0) = 1 (for complete set, since
    // the interpolating polynomial for f(x)=1 over all points has value 1 at 0).
    // Verified for small W where this identity holds exactly in 𝔽_r.
    let d = ShieldDomain::new(5).unwrap();
    let sum: Fr = (1u16..=5)
        .filter_map(|id| d.lambda_at_full(id))
        .fold(Fr::zero(), |acc, x| acc + x);
    assert_eq!(
        sum,
        Fr::one(),
        "Σ λ_k(0) over complete set must equal 1 in 𝔽_r"
    );
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn same_w_produces_identical_share_ids() {
    let d1 = ShieldDomain::new(100).unwrap();
    let d2 = ShieldDomain::new(100).unwrap();
    assert_eq!(
        d1.share_ids(),
        d2.share_ids(),
        "share_ids must be deterministic"
    );
}

#[test]
fn same_w_produces_identical_lambda_full() {
    let d1 = ShieldDomain::new(10).unwrap();
    let d2 = ShieldDomain::new(10).unwrap();
    // Compare via lambda_at_full for all IDs.
    for id in 1u16..=10 {
        assert_eq!(
            d1.lambda_at_full(id),
            d2.lambda_at_full(id),
            "lambda_at_full({id}) must be deterministic"
        );
    }
}

#[test]
fn different_w_produces_different_lambda() {
    let d10 = ShieldDomain::new(10).unwrap();
    let d11 = ShieldDomain::new(11).unwrap();
    // λ_1(0) over {1..10} ≠ λ_1(0) over {1..11} (more points → different coefficients).
    assert_ne!(
        d10.lambda_at_full(1),
        d11.lambda_at_full(1),
        "different W must produce different Lagrange coefficients"
    );
}

// ── Subset Lagrange (for combine) ─────────────────────────────────────────────

#[test]
fn lagrange_coeffs_for_subset_has_correct_length() {
    let d = ShieldDomain::new(10).unwrap();
    let subset = vec![1u16, 3, 7]; // 3 share IDs out of W=10
    let coeffs = d.lagrange_coeffs_for(subset).unwrap();
    assert_eq!(coeffs.len(), 3);
}

#[test]
fn lagrange_coeffs_for_full_set_matches_lambda_full() {
    let w = 6u64;
    let d = ShieldDomain::new(w).unwrap();
    let all_ids: Vec<u16> = (1u16..=w as u16).collect();
    let coeffs = d.lagrange_coeffs_for(all_ids).unwrap();

    for (i, coeff) in coeffs.iter().enumerate() {
        let id = i as u16 + 1;
        assert_eq!(
            Some(*coeff),
            d.lambda_at_full(id),
            "lagrange_coeffs_for(full) must match lambda_at_full for id={id}"
        );
    }
}

#[test]
fn lagrange_coeffs_for_single_point_is_one() {
    // Lagrange basis for a single point x=k over the set {k} at 0:
    // L_k(0) = (0 - [nothing]) / (nothing) = 1 by convention (empty product = 1).
    let d = ShieldDomain::new(8).unwrap();
    let coeffs = d.lagrange_coeffs_for(vec![5u16]).unwrap();
    assert_eq!(coeffs.len(), 1);
    assert_eq!(coeffs[0], Fr::one(), "single-point Lagrange at 0 must be 1");
}

// ── Error cases ───────────────────────────────────────────────────────────────

#[test]
fn new_w0_domain_construction_behavior() {
    // W=0: domain::new succeeds (arkworks allows size 0/1, or returns None).
    // ShieldCommittee never calls domain::new(0) (CommitteeTooSmall fires first).
    // Just verify it doesn't panic — result may be Ok or DomainTooLarge/FftDomainFailed.
    let _ = ShieldDomain::new(0);
}

#[test]
fn new_w_above_u16_max_is_domain_too_large() {
    assert_eq!(
        ShieldDomain::new(65_536).unwrap_err(),
        ShieldError::DomainTooLarge { size: 65_536 }
    );
    assert_eq!(
        ShieldDomain::new(u64::MAX).unwrap_err(),
        ShieldError::DomainTooLarge { size: u64::MAX }
    );
}
