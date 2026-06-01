//! Tests for `lemma_consensus::dag::block`.
//!
//! Covers:
//! - `compute_digest` is deterministic and changes when any body field changes.
//! - Digest explicitly excludes `signature` and `digest` itself.
//! - `DagBlock::new` stores the computed digest.
//! - `verify_digest` detects tampering.
//! - Identity helpers: `reference`, `slot`, `is_genesis_round`.
//! - `DagBlockRef::slot`.
//! - Serde round-trips for `DagBlock`, `DagBlockRef`, `Slot` (network broadcast contract).

use lemma_core::{address::Address, hash::Hash, signature::Signature};

use crate::dag::block::{CommitVote, DagBlock, DagBlockBody, DagBlockRef, Slot, TxBatchRef};

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Deterministic test address: `from_public_key([n; 32])`.
fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

/// Deterministic test hash: all bytes = `n`.
fn hash(n: u8) -> Hash {
    Hash::from_bytes([n; 32])
}

/// A `DagBlockRef` with predictable fields.
fn block_ref(round: u64, author_n: u8, digest_n: u8) -> DagBlockRef {
    DagBlockRef::new(round, addr(author_n), hash(digest_n))
}

/// Minimal unsigned DagBlock for testing digest/identity. Uses `Signature::Unsigned`
/// (the standard lemma-core placeholder for unsigned blocks).
fn test_block() -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round: 5,
            author: addr(1),
            timestamp_ms: 1_000,
            ancestors: vec![block_ref(4, 2, 10), block_ref(4, 3, 11)],
            payload: vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
            commit_votes: vec![CommitVote::new(3, block_ref(3, 1, 9))],
        },
        Signature::Unsigned,
    )
}

/// A DagBlock identical to `test_block()` but with a different `Signature`.
/// Used to assert that digest is signature-independent.
fn test_block_different_signature() -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round: 5,
            author: addr(1),
            timestamp_ms: 1_000,
            ancestors: vec![block_ref(4, 2, 10), block_ref(4, 3, 11)],
            payload: vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
            commit_votes: vec![CommitVote::new(3, block_ref(3, 1, 9))],
        },
        Signature::Classical { bytes: vec![0xAB; 64] },
    )
}

// ── Digest determinism ────────────────────────────────────────────────────────

#[test]
fn compute_digest_is_deterministic_for_same_body() {
    let a = test_block();
    let b = test_block();
    assert_eq!(a.digest, b.digest, "same body must produce same digest");
}

#[test]
fn compute_digest_excludes_signature_field() {
    // Two blocks with identical body but different signatures → same digest.
    // The signature signs the digest; including it would be circular.
    let a = test_block();
    let b = test_block_different_signature();
    assert_eq!(
        a.digest, b.digest,
        "digest must be identical regardless of signature variant"
    );
}

/// Helper: build a block from `test_block()` with one field overridden.
/// Reduces copy-paste in the "digest changes when X changes" tests.
fn block_with(
    epoch: u64, round: u64, author: Address, timestamp_ms: u64,
    ancestors: Vec<DagBlockRef>, payload: Vec<TxBatchRef>,
    commit_votes: Vec<CommitVote>,
) -> DagBlock {
    DagBlock::new(
        DagBlockBody { epoch, round, author, timestamp_ms, ancestors, payload, commit_votes },
        Signature::Unsigned,
    )
}

#[test]
fn compute_digest_changes_when_epoch_changes() {
    let a = test_block();
    let b = block_with(99, 5, addr(1), 1_000,
        vec![block_ref(4, 2, 10), block_ref(4, 3, 11)],
        vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
        vec![CommitVote::new(3, block_ref(3, 1, 9))]);
    assert_ne!(a.digest, b.digest);
}

#[test]
fn compute_digest_changes_when_round_changes() {
    let a = test_block();
    let b = block_with(1, 6, addr(1), 1_000,
        vec![block_ref(4, 2, 10), block_ref(4, 3, 11)],
        vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
        vec![CommitVote::new(3, block_ref(3, 1, 9))]);
    assert_ne!(a.digest, b.digest);
}

#[test]
fn compute_digest_changes_when_author_changes() {
    let a = test_block();
    let b = block_with(1, 5, addr(2), 1_000,
        vec![block_ref(4, 2, 10), block_ref(4, 3, 11)],
        vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
        vec![CommitVote::new(3, block_ref(3, 1, 9))]);
    assert_ne!(a.digest, b.digest);
}

#[test]
fn compute_digest_changes_when_timestamp_changes() {
    let a = test_block();
    let b = block_with(1, 5, addr(1), 9_999,
        vec![block_ref(4, 2, 10), block_ref(4, 3, 11)],
        vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
        vec![CommitVote::new(3, block_ref(3, 1, 9))]);
    assert_ne!(a.digest, b.digest);
}

#[test]
fn compute_digest_changes_when_ancestors_change() {
    let a = test_block();
    let b = block_with(1, 5, addr(1), 1_000,
        vec![block_ref(4, 2, 10)], // one ancestor removed
        vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
        vec![CommitVote::new(3, block_ref(3, 1, 9))]);
    assert_ne!(a.digest, b.digest);
}

#[test]
fn compute_digest_changes_when_payload_changes() {
    let a = test_block();
    let b = block_with(1, 5, addr(1), 1_000,
        vec![block_ref(4, 2, 10), block_ref(4, 3, 11)],
        vec![TxBatchRef { digest: hash(21), author: addr(4), size: 512 }], // digest changed
        vec![CommitVote::new(3, block_ref(3, 1, 9))]);
    assert_ne!(a.digest, b.digest);
}

#[test]
fn compute_digest_changes_when_commit_votes_change() {
    let a = test_block();
    let b = block_with(1, 5, addr(1), 1_000,
        vec![block_ref(4, 2, 10), block_ref(4, 3, 11)],
        vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
        vec![]); // no commit votes
    assert_ne!(a.digest, b.digest);
}

// ── Order-sensitivity (W1) ────────────────────────────────────────────────────
// Ancestors/payload are Vec (ordered). The digest is order-sensitive by
// construction. These tests pin that invariant: permuting the same set without
// changing values must still produce a different digest.

#[test]
fn compute_digest_changes_when_ancestor_order_swapped() {
    // test_block: ancestors = [ref(4,2,10), ref(4,3,11)]
    let a = test_block();
    let b = block_with(1, 5, addr(1), 1_000,
        vec![block_ref(4, 3, 11), block_ref(4, 2, 10)], // same refs, reversed
        vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
        vec![CommitVote::new(3, block_ref(3, 1, 9))]);
    assert_ne!(
        a.digest, b.digest,
        "ancestor order must be reflected in the digest (Vec is ordered, not a set)"
    );
}

#[test]
fn compute_digest_changes_when_payload_order_swapped() {
    let payload_a = TxBatchRef { digest: hash(20), author: addr(4), size: 512 };
    let payload_b = TxBatchRef { digest: hash(21), author: addr(5), size: 256 };
    let a = block_with(1, 5, addr(1), 1_000,
        vec![block_ref(4, 2, 10)],
        vec![payload_a, payload_b],
        vec![]);
    let b = block_with(1, 5, addr(1), 1_000,
        vec![block_ref(4, 2, 10)],
        vec![payload_b, payload_a], // same refs, reversed
        vec![]);
    assert_ne!(
        a.digest, b.digest,
        "payload order must be reflected in the digest"
    );
}

// ── Length-prefix boundary (W2) ───────────────────────────────────────────────
// The length-prefix before each Vec prevents "field concatenation" ambiguity.
// Two blocks that differ only in how content is split between ancestors and
// payload must produce different digests. This pins the claimed invariant in
// the compute_digest doc comment.

#[test]
fn compute_digest_length_prefix_distinguishes_empty_vs_nonempty_fields() {
    // Block A: 2 ancestors, 0 payload entries.
    let a = block_with(1, 5, addr(1), 1_000,
        vec![block_ref(4, 2, 10), block_ref(4, 3, 11)],
        vec![],
        vec![]);
    // Block B: 0 ancestors, 1 payload entry.
    // Despite both having the same *total* field count they differ structurally.
    let b = block_with(1, 5, addr(1), 1_000,
        vec![],
        vec![TxBatchRef { digest: hash(20), author: addr(4), size: 512 }],
        vec![]);
    assert_ne!(
        a.digest, b.digest,
        "length-prefix encoding must distinguish different field boundaries"
    );
}

#[test]
fn compute_digest_empty_ancestors_and_payload_is_valid() {
    // Genesis-like block with no ancestors or payload must still produce a digest.
    let b = block_with(0, 0, addr(1), 0, vec![], vec![], vec![]);
    assert!(!b.digest.is_zero(), "empty-body block must produce nonzero digest");
    assert!(b.verify_digest());
}

// ── verify_digest ─────────────────────────────────────────────────────────────

#[test]
fn verify_digest_true_for_untampered_block() {
    assert!(test_block().verify_digest());
}

#[test]
fn verify_digest_false_when_round_tampered_after_construction() {
    let mut b = test_block();
    b.round = 99; // tamper without recomputing digest
    assert!(
        !b.verify_digest(),
        "verify_digest must detect tampering of the round field"
    );
}

#[test]
fn verify_digest_false_when_author_tampered_after_construction() {
    let mut b = test_block();
    b.author = addr(99);
    assert!(!b.verify_digest());
}

// ── Identity helpers ──────────────────────────────────────────────────────────

#[test]
fn reference_contains_round_author_and_digest() {
    let b = test_block();
    let r = b.reference();
    assert_eq!(r.round, b.round);
    assert_eq!(r.author, b.author);
    assert_eq!(r.digest, b.digest);
}

#[test]
fn slot_returns_round_and_author() {
    let b = test_block();
    let s = b.slot();
    assert_eq!(s.round, b.round);
    assert_eq!(s.author, b.author);
}

#[test]
fn dagblockref_slot_strips_digest() {
    let r = block_ref(7, 3, 42);
    let s = r.slot();
    assert_eq!(s.round, 7);
    assert_eq!(s.author, addr(3));
}

#[test]
fn is_genesis_round_true_at_round_zero() {
    let b = block_with(0, 0, addr(1), 0, vec![], vec![], vec![]);
    assert!(b.is_genesis_round());
}

#[test]
fn is_genesis_round_false_at_nonzero_round() {
    assert!(!test_block().is_genesis_round());
}

// ── Serde round-trips (network broadcast contract) ────────────────────────────

#[test]
fn dagblock_round_trips_through_json() {
    let original = test_block();
    let json = serde_json::to_string(&original).expect("serialize DagBlock");
    let decoded: DagBlock = serde_json::from_str(&json).expect("deserialize DagBlock");
    assert_eq!(original, decoded);
    // Digest must survive round-trip and still verify.
    assert!(decoded.verify_digest());
}

#[test]
fn dagblockref_round_trips_through_json() {
    let original = block_ref(3, 5, 7);
    let json = serde_json::to_string(&original).expect("serialize");
    let decoded: DagBlockRef = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, decoded);
}

#[test]
fn slot_round_trips_through_json() {
    let original = Slot::new(12, addr(7));
    let json = serde_json::to_string(&original).expect("serialize");
    let decoded: Slot = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, decoded);
}
