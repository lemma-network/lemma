//! Tests for `shield::params`.

use super::{
    ShieldParams, DST_H2F, DST_H2G2, HKDF_INFO_AEAD_KEY, HKDF_INFO_NONCE, HKDF_SALT,
    MAX_SHIELD_PAYLOAD_BYTES, WEIGHT_GRANULARITY_DROP,
};
use crate::shield::ShieldError;
use lemma_core::amount::DROPS_PER_LEM;

// ── DST / constant integrity ──────────────────────────────────────────────────

#[test]
fn dst_h2g2_is_frozen_value() {
    assert_eq!(DST_H2G2, b"LEMMA-SHIELD-H2G2-v1");
}

#[test]
fn dst_h2f_is_frozen_value() {
    assert_eq!(DST_H2F, b"LEMMA-SHIELD-H2F-v1");
}

#[test]
fn hkdf_salt_is_frozen_value() {
    assert_eq!(HKDF_SALT, b"LEMMA-SHIELD-HKDF-SALT-v1");
}

#[test]
fn hkdf_info_aead_key_is_frozen_value() {
    assert_eq!(HKDF_INFO_AEAD_KEY, b"LEMMA-SHIELD-AEAD-KEY-v1");
}

#[test]
fn hkdf_info_nonce_is_frozen_value() {
    assert_eq!(HKDF_INFO_NONCE, b"LEMMA-SHIELD-NONCE-v1");
}

#[test]
fn max_shield_payload_bytes_is_4096() {
    assert_eq!(MAX_SHIELD_PAYLOAD_BYTES, 4_096);
}

#[test]
fn weight_granularity_is_one_million_lem() {
    assert_eq!(WEIGHT_GRANULARITY_DROP, 1_000_000 * DROPS_PER_LEM);
}

// ── ShieldParams::for_weight — happy path ────────────────────────────────────

#[test]
fn for_weight_w4_minimum_viable() {
    // W=4: t=⌊4/3⌋−1=0, p=⌊8/3⌋=2
    let p = ShieldParams::for_weight(4).unwrap();
    assert_eq!(p.w, 4);
    assert_eq!(p.t, 0);
    assert_eq!(p.p, 2);
    assert_eq!(p.decrypt_threshold(), 3);
}

#[test]
fn for_weight_w6_clean_divisor() {
    // W=6: t=⌊6/3⌋−1=1, p=⌊12/3⌋=4
    let p = ShieldParams::for_weight(6).unwrap();
    assert_eq!(p.t, 1);
    assert_eq!(p.p, 4);
}

#[test]
fn for_weight_w7_non_divisor() {
    // W=7: t=⌊7/3⌋−1=1, p=⌊14/3⌋=4
    let p = ShieldParams::for_weight(7).unwrap();
    assert_eq!(p.t, 1);
    assert_eq!(p.p, 4);
}

#[test]
fn for_weight_w8_non_divisor_p_bumps() {
    // W=8: t=⌊8/3⌋−1=1, p=⌊16/3⌋=5
    // Verify the overflow-safe p formula: 2*(8/3)+(8%3==2)=2*2+1=5 ✓
    let p = ShieldParams::for_weight(8).unwrap();
    assert_eq!(p.t, 1);
    assert_eq!(p.p, 5);
}

#[test]
fn for_weight_w9_divisor() {
    // W=9: t=2, p=6
    let p = ShieldParams::for_weight(9).unwrap();
    assert_eq!(p.t, 2);
    assert_eq!(p.p, 6);
}

#[test]
fn for_weight_w100_typical_small_testnet() {
    // W=100: t=⌊100/3⌋−1=32, p=⌊200/3⌋=66
    let p = ShieldParams::for_weight(100).unwrap();
    assert_eq!(p.t, 32);
    assert_eq!(p.p, 66);
    assert_eq!(p.decrypt_threshold(), 67);
}

#[test]
fn for_weight_w1000_realistic_mainnet() {
    // W=1000 (100 validators × 10 shares each at 10M-LEM/share)
    // t=⌊1000/3⌋−1=332, p=⌊2000/3⌋=666
    let p = ShieldParams::for_weight(1_000).unwrap();
    assert_eq!(p.t, 332);
    assert_eq!(p.p, 666);
}

#[test]
fn for_weight_p_plus_1_plus_t_equals_w_minus_one_for_divisible() {
    // Structural invariant for W divisible by 3:
    // t = W/3 - 1, p = 2*W/3 → t + p = W - 1 → t + p + 1 = W
    for w in [6u64, 9, 12, 99, 300, 600, 999] {
        let params = ShieldParams::for_weight(w).unwrap();
        assert_eq!(
            params.t + params.p + 1,
            w,
            "t+p+1 should equal W for W={w} (divisible by 3)"
        );
    }
}

#[test]
fn for_weight_decrypt_threshold_exceeds_half_w() {
    // Security property: p+1 > W/2 (majority needed to decrypt).
    // Since p = ⌊2W/3⌋ ≥ W/2 for all W ≥ 1, decrypt_threshold = p+1 > W/2.
    for w in [4u64, 7, 10, 13, 100, 1_000, 10_000] {
        let params = ShieldParams::for_weight(w).unwrap();
        assert!(
            params.decrypt_threshold() * 2 > w,
            "decrypt_threshold={} should exceed W/2 for W={w}",
            params.decrypt_threshold()
        );
    }
}

// ── ShieldParams::for_weight — error cases ────────────────────────────────────

#[test]
fn for_weight_rejects_w0() {
    assert_eq!(
        ShieldParams::for_weight(0).unwrap_err(),
        ShieldError::CommitteeTooSmall { have: 0 }
    );
}

#[test]
fn for_weight_rejects_w1() {
    assert_eq!(
        ShieldParams::for_weight(1).unwrap_err(),
        ShieldError::CommitteeTooSmall { have: 1 }
    );
}

#[test]
fn for_weight_rejects_w2() {
    assert_eq!(
        ShieldParams::for_weight(2).unwrap_err(),
        ShieldError::CommitteeTooSmall { have: 2 }
    );
}

#[test]
fn for_weight_rejects_w3() {
    // W=3 is rejected despite t=0 being technically valid, because the
    // threshold separation is degenerate (decrypt needs all 3 shares).
    assert_eq!(
        ShieldParams::for_weight(3).unwrap_err(),
        ShieldError::CommitteeTooSmall { have: 3 }
    );
}

#[test]
fn for_weight_accepts_w4_boundary() {
    // W=4 is the first accepted value.
    assert!(ShieldParams::for_weight(4).is_ok());
}

// ── ShieldParams fields are consistent ────────────────────────────────────────

#[test]
fn params_fields_are_copy() {
    let p = ShieldParams::for_weight(100).unwrap();
    let q = p; // Copy
    assert_eq!(p, q);
}
