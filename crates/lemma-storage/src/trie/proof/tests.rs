//! Tests for [`MerkleProof`] generation and verification.
//!
//! Test naming: `{action}_{condition}_{expected_outcome}` per AGENTS.md §11.3.
//! Fixtures: [`open_temp_db`] / [`trie`] shared helpers per §11.2 DRY rule.

use tempfile::tempdir;

use super::super::trie::MerklePatriciaTrie;
use super::*;
use crate::{db::LemmaDb, StorageError};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir: OS should always provide a temp directory");
    let db =
        LemmaDb::open(dir.path()).expect("LemmaDb::open: should succeed on a fresh temp directory");
    (db, dir)
}

fn trie(db: &LemmaDb) -> MerklePatriciaTrie<'_> {
    MerklePatriciaTrie::new(db)
}

/// Build a trie with several keys sharing a common prefix.
fn multi_key_trie(db: &LemmaDb) -> MerklePatriciaTrie<'_> {
    let mut t = trie(db);
    t.insert(b"lem1qaaabbbccc111", b"acc1".to_vec()).unwrap();
    t.insert(b"lem1qaaabbbccc222", b"acc2".to_vec()).unwrap();
    t.insert(b"lem1qaaaxxx", b"acc3".to_vec()).unwrap();
    t.insert(b"lem1qzzz", b"acc4".to_vec()).unwrap();
    t
}

// ── generate_proof: error paths ───────────────────────────────────────────────

#[test]
fn generate_proof_on_empty_trie_returns_invalid_proof() {
    let (db, _dir) = open_temp_db();
    let t = trie(&db);
    let err = t.generate_proof(b"any_key").unwrap_err();
    assert!(
        matches!(err, StorageError::InvalidProof { .. }),
        "empty trie must return InvalidProof, got: {err:?}",
    );
}

// ── generate_proof: inclusion proofs ─────────────────────────────────────────

#[test]
fn generate_proof_single_key_is_inclusion() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    let proof = t.generate_proof(b"key1").unwrap();
    assert_eq!(proof.key, b"key1");
    assert_eq!(proof.value, Some(b"val1".to_vec()));
    assert!(
        !proof.nodes.is_empty(),
        "proof must contain at least one node"
    );
}

#[test]
fn generate_proof_multi_key_each_is_inclusion() {
    let (db, _dir) = open_temp_db();
    let t = multi_key_trie(&db);
    for (key, val) in &[
        (&b"lem1qaaabbbccc111"[..], &b"acc1"[..]),
        (b"lem1qaaabbbccc222", b"acc2"),
        (b"lem1qaaaxxx", b"acc3"),
        (b"lem1qzzz", b"acc4"),
    ] {
        let proof = t.generate_proof(key).unwrap();
        assert_eq!(proof.key, *key);
        assert_eq!(proof.value.as_deref(), Some(*val));
    }
}

#[test]
fn generate_proof_prefix_key_is_inclusion() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"ab", b"short".to_vec()).unwrap();
    t.insert(b"abc", b"long".to_vec()).unwrap();

    let proof_ab = t.generate_proof(b"ab").unwrap();
    let proof_abc = t.generate_proof(b"abc").unwrap();

    assert_eq!(proof_ab.value, Some(b"short".to_vec()));
    assert_eq!(proof_abc.value, Some(b"long".to_vec()));
}

#[test]
fn generate_proof_32_byte_key_is_inclusion() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    let key = [0xABu8; 32];
    let val = b"balance_encoded".to_vec();
    t.insert(&key, val.clone()).unwrap();
    let proof = t.generate_proof(&key).unwrap();
    assert_eq!(proof.value, Some(val));
}

#[test]
fn generate_proof_large_value_is_inclusion() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    let large = vec![0xFFu8; 1024];
    t.insert(b"big_key", large.clone()).unwrap();
    let proof = t.generate_proof(b"big_key").unwrap();
    assert_eq!(proof.value, Some(large));
}

// ── generate_proof: non-inclusion proofs ────────────────────────────────────

#[test]
fn generate_proof_absent_key_is_non_inclusion() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"exists", b"yes".to_vec()).unwrap();
    let proof = t.generate_proof(b"absent").unwrap();
    assert_eq!(proof.key, b"absent");
    assert!(
        proof.value.is_none(),
        "absent key must produce non-inclusion proof"
    );
    assert!(!proof.nodes.is_empty());
}

#[test]
fn generate_proof_prefix_of_existing_key_is_non_inclusion() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"abcdef", b"val".to_vec()).unwrap();
    // "abcd" is a prefix of "abcdef" but was never inserted.
    let proof = t.generate_proof(b"abcd").unwrap();
    assert!(proof.value.is_none());
}

#[test]
fn generate_proof_extension_of_existing_key_is_non_inclusion() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"abc", b"val".to_vec()).unwrap();
    // "abcXXX" is longer than the only key; its leaf path won't match.
    let proof = t.generate_proof(b"abcXXX").unwrap();
    assert!(proof.value.is_none());
}

// ── verify: valid proofs pass ────────────────────────────────────────────────

#[test]
fn verify_inclusion_proof_passes_for_correct_root() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    let root = t.root().unwrap();
    let proof = t.generate_proof(b"key1").unwrap();
    proof.verify(root).expect("valid inclusion proof must pass");
}

#[test]
fn verify_non_inclusion_proof_passes_for_correct_root() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"exists", b"val".to_vec()).unwrap();
    let root = t.root().unwrap();
    let proof = t.generate_proof(b"absent").unwrap();
    proof
        .verify(root)
        .expect("valid non-inclusion proof must pass");
}

#[test]
fn verify_multi_key_all_inclusion_proofs_pass() {
    let (db, _dir) = open_temp_db();
    let t = multi_key_trie(&db);
    let root = t.root().unwrap();
    for key in &[
        &b"lem1qaaabbbccc111"[..],
        b"lem1qaaabbbccc222",
        b"lem1qaaaxxx",
        b"lem1qzzz",
    ] {
        let proof = t.generate_proof(key).unwrap();
        proof
            .verify(root)
            .unwrap_or_else(|e| panic!("proof for {:?} must verify, got: {e:?}", key));
    }
}

#[test]
fn verify_prefix_keys_both_pass() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"ab", b"short".to_vec()).unwrap();
    t.insert(b"abc", b"long".to_vec()).unwrap();
    let root = t.root().unwrap();
    t.generate_proof(b"ab").unwrap().verify(root).unwrap();
    t.generate_proof(b"abc").unwrap().verify(root).unwrap();
}

// ── verify: tampered proofs fail ─────────────────────────────────────────────

#[test]
fn verify_tampered_value_returns_invalid_proof() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    let root = t.root().unwrap();
    let mut proof = t.generate_proof(b"key1").unwrap();
    // Mutate the claimed value.
    proof.value = Some(b"tampered".to_vec());
    let err = proof.verify(root).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::InvalidProof { .. } | StorageError::TrieRootMismatch { .. }
        ),
        "tampered value must fail, got: {err:?}",
    );
}

#[test]
fn verify_wrong_root_returns_trie_root_mismatch() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    let proof = t.generate_proof(b"key1").unwrap();
    // Use a root from a different trie (or just a zeroed hash).
    let wrong_root = lemma_core::Hash::from_bytes([0x00; 32]);
    let err = proof.verify(wrong_root).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::TrieRootMismatch { .. } | StorageError::InvalidProof { .. }
        ),
        "wrong root must fail, got: {err:?}",
    );
}

#[test]
fn verify_truncated_proof_returns_invalid_proof() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"lem1qaaabbbccc111", b"acc1".to_vec()).unwrap();
    t.insert(b"lem1qaaabbbccc222", b"acc2".to_vec()).unwrap();
    let root = t.root().unwrap();
    let mut proof = t.generate_proof(b"lem1qaaabbbccc111").unwrap();
    // Remove the last node (truncate the proof path).
    if proof.nodes.len() > 1 {
        proof.nodes.pop();
    }
    let err = proof.verify(root).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::InvalidProof { .. } | StorageError::TrieRootMismatch { .. }
        ),
        "truncated proof must fail, got: {err:?}",
    );
}

#[test]
fn verify_proof_against_stale_root_fails() {
    // Insert key, save root1, insert another key, save root2.
    // Proof from root1 must fail against root2.
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    let root1 = t.root().unwrap();
    let proof = t.generate_proof(b"key1").unwrap();
    // Insert a second key — root changes.
    t.insert(b"key2", b"val2".to_vec()).unwrap();
    let root2 = t.root().unwrap();
    assert_ne!(root1, root2);
    // Original proof must fail against new root.
    let err = proof.verify(root2).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::TrieRootMismatch { .. } | StorageError::InvalidProof { .. }
        ),
        "stale proof must fail, got: {err:?}",
    );
}

// ── verify: proof determinism ────────────────────────────────────────────────

#[test]
fn generate_proof_same_key_produces_identical_proof_bytes() {
    // The same trie + same key must always produce the same proof.
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    t.insert(b"key2", b"val2".to_vec()).unwrap();

    let proof_a = t.generate_proof(b"key1").unwrap();
    let proof_b = t.generate_proof(b"key1").unwrap();
    assert_eq!(proof_a, proof_b, "same key must produce identical proofs");
}

#[test]
fn generate_proof_node_hashes_are_deterministic() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    let proof = t.generate_proof(b"key1").unwrap();
    // Each node's hash must be stable across two calls.
    for node in &proof.nodes {
        let h1 = node.hash().unwrap();
        let h2 = node.hash().unwrap();
        assert_eq!(h1, h2, "ProofNode::hash() must be deterministic");
    }
}

// ── ProofNode: serialization roundtrip ───────────────────────────────────────

#[test]
fn proof_node_branch_bincode_roundtrip() {
    let node = ProofNode::Branch {
        children: [None; 16],
        value: Some(b"branch_value".to_vec()),
    };
    let encoded = bincode::serialize(&node).unwrap();
    let decoded: ProofNode = bincode::deserialize(&encoded).unwrap();
    assert_eq!(node, decoded);
}

#[test]
fn proof_node_extension_bincode_roundtrip() {
    use crate::trie::node::NibblePath;
    let node = ProofNode::Extension {
        prefix: NibblePath::from_bytes(b"prefix"),
        child: lemma_core::Hash::from_bytes([0xAB; 32]),
    };
    let encoded = bincode::serialize(&node).unwrap();
    let decoded: ProofNode = bincode::deserialize(&encoded).unwrap();
    assert_eq!(node, decoded);
}

#[test]
fn proof_node_leaf_bincode_roundtrip() {
    use crate::trie::node::NibblePath;
    let node = ProofNode::Leaf {
        path: NibblePath::from_bytes(b"leaf_key"),
        value: b"leaf_value".to_vec(),
    };
    let encoded = bincode::serialize(&node).unwrap();
    let decoded: ProofNode = bincode::deserialize(&encoded).unwrap();
    assert_eq!(node, decoded);
}

#[test]
fn merkle_proof_bincode_roundtrip() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    let proof = t.generate_proof(b"key1").unwrap();
    let encoded = bincode::serialize(&proof).unwrap();
    let decoded: MerkleProof = bincode::deserialize(&encoded).unwrap();
    assert_eq!(proof, decoded);
}

// ── TEST-1: Branch-value inclusion (path exhausted at Branch) ────────────────

#[test]
fn generate_proof_branch_value_inclusion_is_some() {
    // "ab" is a strict prefix of "abc" — inserting both forces "ab" to be
    // stored as a Branch value (path exhausted at the Branch that splits them).
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"ab", b"short".to_vec()).unwrap();
    t.insert(b"abc", b"long".to_vec()).unwrap();
    let proof = t.generate_proof(b"ab").unwrap();
    assert_eq!(proof.value, Some(b"short".to_vec()), "ab must be inclusion");
}

#[test]
fn verify_branch_value_inclusion_proof_passes() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"ab", b"short".to_vec()).unwrap();
    t.insert(b"abc", b"long".to_vec()).unwrap();
    let root = t.root().unwrap();
    let proof = t.generate_proof(b"ab").unwrap();
    assert_eq!(proof.value, Some(b"short".to_vec()));
    proof
        .verify(root)
        .expect("branch-value inclusion proof must verify");
}

// ── TEST-2: Single-byte key ───────────────────────────────────────────────────

#[test]
fn verify_single_byte_key_inclusion_proof_passes() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"\x42", b"val".to_vec()).unwrap();
    let root = t.root().unwrap();
    let proof = t.generate_proof(b"\x42").unwrap();
    assert_eq!(proof.value, Some(b"val".to_vec()));
    proof
        .verify(root)
        .expect("single-byte key inclusion proof must verify");
}

#[test]
fn verify_single_byte_key_non_inclusion_proof_passes() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"\x42", b"val".to_vec()).unwrap();
    let root = t.root().unwrap();
    let proof = t.generate_proof(b"\x43").unwrap();
    assert!(proof.value.is_none());
    proof
        .verify(root)
        .expect("single-byte key non-inclusion proof must verify");
}

// ── TEST-3: Empty key ─────────────────────────────────────────────────────────

#[test]
fn verify_empty_key_inclusion_proof_passes() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"", b"root_val".to_vec()).unwrap();
    let root = t.root().unwrap();
    let proof = t.generate_proof(b"").unwrap();
    assert_eq!(proof.value, Some(b"root_val".to_vec()));
    proof
        .verify(root)
        .expect("empty key inclusion proof must verify");
}

#[test]
fn verify_empty_key_non_inclusion_when_absent_passes() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"exists", b"val".to_vec()).unwrap();
    let root = t.root().unwrap();
    // Empty key was never inserted.
    let proof = t.generate_proof(b"").unwrap();
    assert!(proof.value.is_none());
    proof
        .verify(root)
        .expect("empty key non-inclusion proof must verify");
}

// ── TEST-4: Node substitution tamper ─────────────────────────────────────────

#[test]
fn verify_substituted_node_returns_invalid_proof() {
    use crate::trie::node::NibblePath;
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    t.insert(b"key2", b"val2".to_vec()).unwrap();
    let root = t.root().unwrap();
    let mut proof = t.generate_proof(b"key1").unwrap();
    // Replace the last node with a leaf for a different key.
    if let Some(last) = proof.nodes.last_mut() {
        *last = ProofNode::Leaf {
            path: NibblePath::from_bytes(b"key2"),
            value: b"val2".to_vec(),
        };
    }
    let err = proof.verify(root).unwrap_err();
    assert!(
        matches!(
            err,
            StorageError::InvalidProof { .. } | StorageError::TrieRootMismatch { .. }
        ),
        "substituted node must fail verification, got: {err:?}",
    );
}

// ── CQ-1: ProofNode::hash() == TrieNode::hash() for same content ─────────────

#[test]
fn proof_node_hash_matches_trie_node_hash_for_leaf() {
    use crate::trie::node::{NibblePath, TrieNode};
    let trie_leaf = TrieNode::leaf(NibblePath::from_bytes(b"key"), b"val".to_vec());
    let proof_leaf = ProofNode::Leaf {
        path: NibblePath::from_bytes(b"key"),
        value: b"val".to_vec(),
    };
    assert_eq!(
        trie_leaf.hash().unwrap(),
        proof_leaf.hash().unwrap(),
        "ProofNode::Leaf and TrieNode::Leaf must hash identically",
    );
}

#[test]
fn proof_node_hash_matches_trie_node_hash_for_branch() {
    use crate::trie::node::TrieNode;
    let trie_branch = TrieNode::empty_branch();
    let proof_branch = ProofNode::Branch {
        children: [None; 16],
        value: None,
    };
    assert_eq!(
        trie_branch.hash().unwrap(),
        proof_branch.hash().unwrap(),
        "ProofNode::Branch and TrieNode::Branch must hash identically",
    );
}

// ── TEST-6: Byte-level determinism ───────────────────────────────────────────

#[test]
fn generate_proof_same_key_produces_identical_proof_bytes_after_serialization() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"key1", b"val1".to_vec()).unwrap();
    t.insert(b"key2", b"val2".to_vec()).unwrap();
    let proof_a = t.generate_proof(b"key1").unwrap();
    let proof_b = t.generate_proof(b"key1").unwrap();
    let bytes_a =
        bincode::serialize(&proof_a).expect("serialization must not fail for well-formed proof");
    let bytes_b =
        bincode::serialize(&proof_b).expect("serialization must not fail for well-formed proof");
    assert_eq!(
        bytes_a, bytes_b,
        "proof bytes must be identical (consensus determinism)"
    );
}

// ── verify: deep trie ────────────────────────────────────────────────────────

#[test]
fn verify_deep_trie_all_keys_pass() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    // Force deep Extension → Branch → Extension nesting.
    t.insert(b"lem1qaaabbbccc111", b"acc1".to_vec()).unwrap();
    t.insert(b"lem1qaaabbbccc222", b"acc2".to_vec()).unwrap();
    t.insert(b"lem1qaaaxxx", b"acc3".to_vec()).unwrap();
    t.insert(b"lem1qzzz", b"acc4".to_vec()).unwrap();
    t.insert(b"lem1q", b"root_acc".to_vec()).unwrap();
    let root = t.root().unwrap();

    for key in &[
        &b"lem1qaaabbbccc111"[..],
        b"lem1qaaabbbccc222",
        b"lem1qaaaxxx",
        b"lem1qzzz",
        b"lem1q",
    ] {
        let proof = t.generate_proof(key).unwrap();
        proof
            .verify(root)
            .unwrap_or_else(|e| panic!("deep trie proof for {key:?} must verify, got: {e:?}"));
    }
}

#[test]
fn verify_deep_trie_absent_key_non_inclusion_passes() {
    let (db, _dir) = open_temp_db();
    let mut t = trie(&db);
    t.insert(b"lem1qaaabbbccc111", b"acc1".to_vec()).unwrap();
    t.insert(b"lem1qaaabbbccc222", b"acc2".to_vec()).unwrap();
    let root = t.root().unwrap();
    // Key that shares a long prefix but was never inserted.
    let proof = t.generate_proof(b"lem1qaaa").unwrap();
    assert!(proof.value.is_none());
    proof
        .verify(root)
        .expect("deep non-inclusion proof must verify");
}
