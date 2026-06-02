//! Tests for `lemma_consensus::commit`.

use lemma_core::{address::Address, hash::Hash};

use crate::{commit::Commit, dag::block::DagBlockRef};

// ── Fixtures ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn hash(n: u8) -> Hash {
    Hash::from_bytes([n; 32])
}

fn lref(round: u64, author_n: u8) -> DagBlockRef {
    DagBlockRef::new(round, addr(author_n), hash(author_n))
}

fn basic_commit(index: u64) -> Commit {
    Commit {
        index,
        previous_digest: Commit::genesis_previous(),
        timestamp_ms: 1_000,
        leader: lref(3, 1),
        blocks: vec![lref(1, 1), lref(1, 2), lref(2, 1)],
    }
}

// ── genesis_previous ──────────────────────────────────────────────────────────

#[test]
fn genesis_previous_is_zero() {
    assert_eq!(Commit::genesis_previous(), Hash::zero());
}

// ── digest ────────────────────────────────────────────────────────────────────

#[test]
fn commit_digest_is_deterministic() {
    let c = basic_commit(1);
    assert_eq!(c.digest(), c.digest());
}

#[test]
fn commit_digest_changes_with_index() {
    let c1 = basic_commit(1);
    let c2 = basic_commit(2);
    assert_ne!(c1.digest(), c2.digest());
}

#[test]
fn commit_digest_changes_with_leader() {
    let mut c1 = basic_commit(1);
    let mut c2 = basic_commit(1);
    c1.leader = lref(3, 1);
    c2.leader = lref(3, 2); // different author
    assert_ne!(c1.digest(), c2.digest());
}

#[test]
fn commit_digest_changes_with_blocks() {
    let mut c1 = basic_commit(1);
    let mut c2 = basic_commit(1);
    c1.blocks = vec![lref(1, 1)];
    c2.blocks = vec![lref(1, 2)];
    assert_ne!(c1.digest(), c2.digest());
}

#[test]
fn commit_digest_changes_with_timestamp() {
    let mut c1 = basic_commit(1);
    let mut c2 = basic_commit(1);
    c1.timestamp_ms = 1_000;
    c2.timestamp_ms = 2_000;
    assert_ne!(c1.digest(), c2.digest());
}

#[test]
fn commit_digest_changes_with_previous_digest() {
    let mut c1 = basic_commit(1);
    let mut c2 = basic_commit(1);
    c1.previous_digest = Hash::zero();
    c2.previous_digest = hash(42);
    assert_ne!(c1.digest(), c2.digest());
}

// ── Commit chain integrity ─────────────────────────────────────────────────────

#[test]
fn commit_chain_links_via_previous_digest() {
    // Commit B's previous_digest must equal Commit A's digest.
    let commit_a = basic_commit(1);
    let commit_b = Commit {
        index: 2,
        previous_digest: commit_a.digest(),
        timestamp_ms: 2_000,
        leader: lref(6, 2),
        blocks: vec![lref(4, 1), lref(5, 2)],
    };
    assert_eq!(
        commit_b.previous_digest,
        commit_a.digest(),
        "commit B must reference commit A's digest"
    );
}

#[test]
fn first_commit_uses_genesis_previous() {
    let c = basic_commit(1);
    assert_eq!(c.previous_digest, Commit::genesis_previous());
}

// ── Empty blocks edge case ────────────────────────────────────────────────────

#[test]
fn commit_digest_with_empty_blocks() {
    let c = Commit {
        index: 1,
        previous_digest: Commit::genesis_previous(),
        timestamp_ms: 0,
        leader: lref(0, 1),
        blocks: vec![],
    };
    // Must not panic; deterministic.
    let d1 = c.digest();
    let d2 = c.digest();
    assert_eq!(d1, d2);
}

#[test]
fn commit_digest_differs_for_empty_vs_nonempty_blocks() {
    let mut c_empty = basic_commit(1);
    c_empty.blocks = vec![];
    let c_nonempty = basic_commit(1);
    assert_ne!(c_empty.digest(), c_nonempty.digest());
}

// ── Serde roundtrip ───────────────────────────────────────────────────────────

#[test]
fn commit_serializes_and_deserializes() {
    let c = basic_commit(1);
    let json = serde_json::to_string(&c).expect("serialize");
    let recovered: Commit = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(c, recovered);
}

#[test]
fn commit_serde_preserves_digest() {
    let c = basic_commit(1);
    let d_before = c.digest();
    let json = serde_json::to_string(&c).unwrap();
    let c2: Commit = serde_json::from_str(&json).unwrap();
    assert_eq!(
        d_before,
        c2.digest(),
        "serde roundtrip must preserve digest"
    );
}
