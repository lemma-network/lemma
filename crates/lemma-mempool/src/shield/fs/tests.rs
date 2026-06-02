//! Tests for `shield::fs` — shared Fiat–Shamir + hash-to-curve helpers.
//!
//! Covered:
//! - `expand_challenges_is_deterministic`
//! - `expand_challenges_produces_correct_count`
//! - `expand_challenges_differ_per_index`
//! - `expand_challenges_differ_per_transcript`
//! - `hash_to_g2_with_dst_is_deterministic`
//! - `hash_to_g2_different_dsts_produce_different_points`
//! - `hash_to_g2_different_msgs_produce_different_points`
//! - `hash_to_g2_result_is_in_correct_subgroup`

use super::{expand_challenges, hash_to_g2_with_dst};
use crate::shield::params::{DST_H2G2, DST_PVSS_U1};

// ── expand_challenges ─────────────────────────────────────────────────────────

#[test]
fn expand_challenges_is_deterministic() {
    let tr = b"test-transcript-bytes";
    let a = expand_challenges(tr, 4);
    let b = expand_challenges(tr, 4);
    assert_eq!(
        a, b,
        "same transcript + count must produce identical challenges"
    );
}

#[test]
fn expand_challenges_produces_correct_count() {
    let tr = b"x";
    assert_eq!(expand_challenges(tr, 0).len(), 0, "count=0 → empty vec");
    assert_eq!(expand_challenges(tr, 1).len(), 1);
    assert_eq!(expand_challenges(tr, 5).len(), 5);
}

#[test]
fn expand_challenges_differ_per_index() {
    let tr = b"transcript";
    let cs = expand_challenges(tr, 3);
    assert_ne!(
        cs[0], cs[1],
        "counter 0 and 1 must produce different challenges"
    );
    assert_ne!(
        cs[1], cs[2],
        "counter 1 and 2 must produce different challenges"
    );
}

#[test]
fn expand_challenges_differ_per_transcript() {
    let a = expand_challenges(b"transcript-a", 3);
    let b = expand_challenges(b"transcript-b", 3);
    assert_ne!(
        a, b,
        "different transcripts must produce different challenge sets"
    );
}

// ── hash_to_g2_with_dst ───────────────────────────────────────────────────────

#[test]
fn hash_to_g2_with_dst_is_deterministic() {
    let a = hash_to_g2_with_dst(DST_H2G2, b"msg").unwrap();
    let b = hash_to_g2_with_dst(DST_H2G2, b"msg").unwrap();
    assert_eq!(a, b, "same (dst, msg) must produce identical G2 point");
}

#[test]
fn hash_to_g2_different_dsts_produce_different_points() {
    let a = hash_to_g2_with_dst(DST_H2G2, b"").unwrap();
    let b = hash_to_g2_with_dst(DST_PVSS_U1, b"").unwrap();
    assert_ne!(
        a, b,
        "different DSTs must produce independent points (no hidden dlog)"
    );
}

#[test]
fn hash_to_g2_different_msgs_produce_different_points() {
    let a = hash_to_g2_with_dst(DST_H2G2, b"msg-a").unwrap();
    let b = hash_to_g2_with_dst(DST_H2G2, b"msg-b").unwrap();
    assert_ne!(a, b, "different messages must produce different points");
}

#[test]
fn hash_to_g2_result_is_in_correct_subgroup() {
    let pt = hash_to_g2_with_dst(DST_H2G2, b"subgroup-check").unwrap();
    assert!(
        pt.is_in_correct_subgroup_assuming_on_curve(),
        "hash-to-G2 output must be in the prime-order subgroup"
    );
}
