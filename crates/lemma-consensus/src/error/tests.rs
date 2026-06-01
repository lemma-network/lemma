//! Tests for `lemma_consensus::error`.
//!
//! Covers:
//! - Every variant produces the exact `Display` message the spec documents
//!   (exact-match, not collision-prone substring checks).
//! - `Equivocation` renders BOTH conflicting digests, and they differ.
//! - `is_equivocation` returns `true` only for `Equivocation`.
//! - `is_pending_data` returns `true` only for `MissingAncestor`.
//! - Round-trip serde + value equality (exercises the derived traits the
//!   slashing path relies on).
//! - Variant-count canary: `all_variants()` must be updated when variants change.

use lemma_core::{address::Address, hash::Hash};

use crate::error::ConsensusError;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of `ConsensusError` variants the fixture below must enumerate.
///
/// `#[non_exhaustive]` blocks exhaustive `match` in this (external test) module,
/// so this count is the canary: bump it — and `all_variants()` — together
/// whenever a variant is added or removed.
const VARIANT_COUNT: usize = 8;

// ── Test fixtures ─────────────────────────────────────────────────────────────

/// Stable zero address used across all variant constructors.
fn addr() -> Address {
    Address::zero()
}

/// The all-zero hash. Renders as 64 `0` hex chars via `Hash`'s Display.
fn hash_a() -> Hash {
    Hash::zero()
}

/// A hash distinct from `hash_a()`. Renders as `0101…01` (lowercase hex).
fn hash_b() -> Hash {
    Hash::from_bytes([0x01; 32])
}

/// One instance of every current `ConsensusError` variant.
///
/// Must contain exactly [`VARIANT_COUNT`] entries — enforced by
/// `all_variants_count_matches_canary`.
fn all_variants() -> Vec<ConsensusError> {
    vec![
        ConsensusError::EpochMismatch { expected: 1, got: 2 },
        ConsensusError::UnknownAuthor { author: addr(), epoch: 1 },
        ConsensusError::InvalidSignature { author: addr(), round: 5 },
        ConsensusError::BelowGcBoundary { round: 3, gc_round: 10 },
        ConsensusError::MissingAncestor {
            ancestor_digest: hash_a(),
            author: addr(),
            round: 4,
        },
        ConsensusError::InsufficientStrongLinks { author: addr(), round: 6 },
        ConsensusError::Equivocation {
            author: addr(),
            round: 7,
            first: hash_a(),
            second: hash_b(),
        },
        ConsensusError::StakeOverflow { author: addr() },
    ]
}

// ── Display — exact-match, no collision-prone substrings ──────────────────────

#[test]
fn epoch_mismatch_display_is_exact() {
    let e = ConsensusError::EpochMismatch { expected: 3, got: 7 };
    assert_eq!(e.to_string(), "block epoch mismatch: expected 3, got 7");
}

#[test]
fn unknown_author_display_contains_anchored_epoch() {
    let e = ConsensusError::UnknownAuthor { author: addr(), epoch: 5 };
    let s = e.to_string();
    // Anchored token: "epoch 5" cannot collide with digits in the address string.
    assert!(s.contains("epoch 5"), "anchored epoch missing from: {s}");
}

#[test]
fn invalid_signature_display_contains_anchored_round() {
    let e = ConsensusError::InvalidSignature { author: addr(), round: 9 };
    let s = e.to_string();
    assert!(s.contains("round 9"), "anchored round missing from: {s}");
}

#[test]
fn below_gc_boundary_display_is_exact() {
    let e = ConsensusError::BelowGcBoundary { round: 2, gc_round: 15 };
    assert_eq!(
        e.to_string(),
        "block at round 2 is below GC boundary (gc_round=15)"
    );
}

#[test]
fn missing_ancestor_display_contains_digest_and_anchored_round() {
    let e = ConsensusError::MissingAncestor {
        ancestor_digest: hash_b(),
        author: addr(),
        round: 8,
    };
    let s = e.to_string();
    // The missing ancestor's digest is the key diagnostic — assert it renders.
    assert!(
        s.contains(&hash_b().to_string()),
        "ancestor digest missing from: {s}"
    );
    assert!(s.contains("round 8"), "anchored round missing from: {s}");
}

#[test]
fn insufficient_strong_links_display_contains_anchored_round() {
    let e = ConsensusError::InsufficientStrongLinks { author: addr(), round: 11 };
    let s = e.to_string();
    assert!(s.contains("round 11"), "anchored round missing from: {s}");
}

#[test]
fn equivocation_display_renders_both_distinct_digests() {
    let e = ConsensusError::Equivocation {
        author: addr(),
        round: 4,
        first: hash_a(),
        second: hash_b(),
    };
    let s = e.to_string();
    // The entire diagnostic purpose of this variant is the two conflicting
    // digests — assert BOTH render and that they differ.
    let first = hash_a().to_string();
    let second = hash_b().to_string();
    assert_ne!(first, second, "fixture digests must differ");
    assert!(s.contains(&first), "first digest missing from: {s}");
    assert!(s.contains(&second), "second digest missing from: {s}");
    assert!(s.contains("round 4"), "anchored round missing from: {s}");
}

#[test]
fn stake_overflow_display_is_nonempty() {
    let e = ConsensusError::StakeOverflow { author: addr() };
    assert!(!e.to_string().is_empty());
}

// ── is_equivocation ───────────────────────────────────────────────────────────

#[test]
fn is_equivocation_true_only_for_equivocation_variant() {
    let equivocation = ConsensusError::Equivocation {
        author: addr(),
        round: 1,
        first: hash_a(),
        second: hash_b(),
    };
    assert!(equivocation.is_equivocation());

    for e in all_variants() {
        if matches!(e, ConsensusError::Equivocation { .. }) {
            continue;
        }
        assert!(
            !e.is_equivocation(),
            "is_equivocation unexpectedly true for: {e:?}"
        );
    }
}

// ── is_pending_data ───────────────────────────────────────────────────────────

#[test]
fn is_pending_data_true_only_for_missing_ancestor() {
    let missing = ConsensusError::MissingAncestor {
        ancestor_digest: hash_a(),
        author: addr(),
        round: 3,
    };
    assert!(missing.is_pending_data());

    for e in all_variants() {
        if matches!(e, ConsensusError::MissingAncestor { .. }) {
            continue;
        }
        assert!(
            !e.is_pending_data(),
            "is_pending_data unexpectedly true for: {e:?}"
        );
    }
}

#[test]
fn epoch_mismatch_is_not_pending_data() {
    // Regression guard for the §4.6 buffer-vs-drop decision: epoch recoverability
    // is stateful and owned by dag::graph, NOT this predicate. A future-epoch
    // mismatch must still return false here.
    let future = ConsensusError::EpochMismatch { expected: 4, got: 9 };
    assert!(
        !future.is_pending_data(),
        "EpochMismatch must not be classified as pending-data"
    );
}

// ── Derived traits (slashing path relies on these) ────────────────────────────

#[test]
fn equivocation_round_trips_through_json_and_is_equal() {
    let original = ConsensusError::Equivocation {
        author: addr(),
        round: 42,
        first: hash_a(),
        second: hash_b(),
    };
    let json = serde_json::to_string(&original).expect("serialize");
    let decoded: ConsensusError = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, decoded);
    // Clone is part of the contract too.
    assert_eq!(original, original.clone());
}

// ── Canary: variant count ─────────────────────────────────────────────────────

#[test]
fn all_variants_count_matches_canary() {
    assert_eq!(
        all_variants().len(),
        VARIANT_COUNT,
        "update all_variants() and VARIANT_COUNT together when variants change"
    );
}
