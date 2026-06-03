//! Tests for [`batch`] — Batch, BatchStore, resolve_committed_txs.
//!
//! Coverage (per test-coverage.md 100% for consensus-path code):
//! - Batch digest is deterministic for the same author+txs.
//! - Batch digest changes when txs change.
//! - `to_ref()` returns the correct digest, author, and non-zero size.
//! - `serialized_size()` returns `u32` correctly for small batches.
//! - Empty batch (no txs) produces a valid ref.
//! - `resolve_committed_txs` — happy path: all refs pinned → all txs in order.
//! - `resolve_committed_txs` — dedup: same tx in two batches → appears once.
//! - `resolve_committed_txs` — empty payload: block with no refs → no txs.
//! - `resolve_committed_txs` — availability miss: unpinned ref → skipped.
//! - `resolve_committed_txs` — missing DagBlock in DAG → skipped.
//! - `resolve_block_payload` — direct unit test of the inner helper.
//! - Determinism: same commit + same store → same tx list on repeated calls.
//!
//! AGENTS §11: separate tests.rs, `{action}_{outcome}` naming, AAA pattern,
//! shared fixtures (DRY — no copy-pasted setup).

use std::collections::{HashMap, HashSet};

use lemma_consensus::{
    dag::{
        block::{DagBlock, DagBlockBody, DagBlockRef, TxBatchRef},
        graph::Dag,
    },
    Commit,
};
use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    signature::Signature,
    transaction::{Transaction, TxType},
    validator_set::ValidatorSet,
};
use lemma_crypto::{sign_transaction, KeyPair};

use super::{resolve_block_payload, resolve_committed_txs, Batch};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

/// Build a minimal signed `Transaction` with a unique nonce.
fn make_tx(sender_kp: &KeyPair, nonce: u64) -> Transaction {
    let mut tx = Transaction::new(
        Hash::zero(),
        *sender_kp.address(),
        Some(addr(99)),
        nonce,
        1, // chain_id
        Amount::from_drop(0),
        21_000, // gas_limit
        Amount::from_drop(1_000_000_000),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("Transaction::new");
    sign_transaction(&mut tx, sender_kp).expect("sign_transaction");
    tx
}

/// Build an empty `DagBlock` with the given `payload`.
fn make_dag_block(round: u64, author: Address, payload: Vec<TxBatchRef>) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch: 0,
            round,
            author,
            timestamp_ms: 1_000,
            ancestors: vec![],
            payload,
            commit_votes: vec![],
        },
        Signature::Unsigned,
    )
}

/// Build a `Commit` whose `blocks` list contains exactly the given refs.
fn make_commit(blocks: Vec<DagBlockRef>) -> Commit {
    let leader = blocks
        .first()
        .cloned()
        .unwrap_or_else(|| DagBlockRef::new(0, addr(1), Hash::zero()));
    Commit {
        index: 1,
        previous_digest: Hash::zero(),
        timestamp_ms: 2_000_000_000,
        leader,
        blocks,
    }
}

/// Two-validator `ValidatorSet` for test DAG inserts.
///
/// Two members (addr(1) + addr(2)) each with equal stake, matching the
/// multi-validator scenario this test suite exercises (two validators can
/// independently include the same pending tx in their respective batches —
/// dedup ensures it executes only once per commit).
///
/// Round-0 blocks are exempt from the strong-link quorum check (spec §2.1
/// "Genesis-round exemption"), so most tests can insert blocks without setting
/// up ancestor chains. Round-1+ blocks require ancestors.
fn test_vset() -> ValidatorSet {
    use lemma_core::validator::{ConsensusKey, VotingPower};
    use lemma_core::validator_set::Member;
    use std::collections::BTreeMap;

    let mut members = BTreeMap::new();
    for n in [1u8, 2] {
        members.insert(
            addr(n),
            Member {
                consensus_pubkey: ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32]),
                power: VotingPower(lemma_core::amount::Amount::from_drop(1_000_000)),
            },
        );
    }
    ValidatorSet {
        epoch: 0,
        members,
        total_power: lemma_core::amount::Amount::from_drop(2_000_000),
    }
}

/// Insert `block` into `dag` (epoch 0, single-validator committee — sig_ok = true).
fn insert_block(dag: &mut Dag, block: DagBlock) {
    let vset = test_vset();
    // sig_ok = true (Phase 2: self-authored, trusted)
    dag.insert(block, &vset, true).expect("dag.insert");
}

// ── Batch::digest ─────────────────────────────────────────────────────────────

#[test]
fn digest_is_deterministic_for_same_batch() {
    // Arrange
    let kp = KeyPair::generate().expect("keygen");
    let tx = make_tx(&kp, 0);
    let batch = Batch::new(addr(1), vec![tx]);

    // Act
    let d1 = batch.digest().expect("digest 1");
    let d2 = batch.digest().expect("digest 2");

    // Assert
    assert_eq!(d1, d2, "same batch must produce the same digest every time");
}

#[test]
fn digest_changes_when_txs_change() {
    // Arrange
    let kp = KeyPair::generate().expect("keygen");
    let tx0 = make_tx(&kp, 0);
    let tx1 = make_tx(&kp, 1);
    let b0 = Batch::new(addr(1), vec![tx0]);
    let b1 = Batch::new(addr(1), vec![tx1]);

    // Act + Assert
    assert_ne!(
        b0.digest().unwrap(),
        b1.digest().unwrap(),
        "different txs must produce different digests"
    );
}

#[test]
fn digest_changes_when_author_changes() {
    // Arrange
    let kp = KeyPair::generate().expect("keygen");
    let tx = make_tx(&kp, 0);
    let b0 = Batch::new(addr(1), vec![tx.clone()]);
    let b1 = Batch::new(addr(2), vec![tx]);

    // Assert
    assert_ne!(
        b0.digest().unwrap(),
        b1.digest().unwrap(),
        "different author must produce different digest"
    );
}

// ── Batch::to_ref ─────────────────────────────────────────────────────────────

#[test]
fn to_ref_returns_correct_fields() {
    // Arrange
    let kp = KeyPair::generate().expect("keygen");
    let tx = make_tx(&kp, 0);
    let batch = Batch::new(addr(1), vec![tx]);

    // Act
    let r = batch.to_ref().expect("to_ref");

    // Assert
    assert_eq!(
        r.digest,
        batch.digest().unwrap(),
        "ref.digest must match batch.digest"
    );
    assert_eq!(r.author, addr(1), "ref.author must match batch.author");
    assert!(
        r.size > 0,
        "serialized size must be > 0 for non-empty batch"
    );
}

#[test]
fn empty_batch_produces_valid_ref() {
    // Arrange
    let batch = Batch::new(addr(1), vec![]);

    // Act
    let r = batch.to_ref().expect("to_ref on empty batch");

    // Assert
    assert_eq!(r.author, addr(1));
    assert!(
        r.size > 0,
        "even an empty batch has a non-zero JSON envelope"
    );
}

#[test]
fn serialized_size_fits_u32() {
    // Arrange: small batch well within u32::MAX
    let kp = KeyPair::generate().expect("keygen");
    let batch = Batch::new(addr(1), vec![make_tx(&kp, 0)]);

    // Act + Assert
    let sz = batch.serialized_size().expect("serialized_size");
    assert!(sz > 0);
}

// ── resolve_block_payload ─────────────────────────────────────────────────────

#[test]
fn resolve_block_payload_returns_txs_for_pinned_ref() {
    // Arrange
    let kp = KeyPair::generate().expect("keygen");
    let tx = make_tx(&kp, 0);
    let batch = Batch::new(addr(1), vec![tx.clone()]);
    let batch_ref = batch.to_ref().unwrap();

    let mut store: HashMap<Hash, Batch> = HashMap::new();
    store.insert(batch.digest().unwrap(), batch);

    let block = make_dag_block(0, addr(1), vec![batch_ref]);

    let mut seen = HashSet::new();
    let mut out = Vec::new();

    // Act
    resolve_block_payload(&block, &store, &mut seen, &mut out);

    // Assert
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].hash, tx.hash);
}

#[test]
fn resolve_block_payload_skips_unpinned_ref() {
    // Arrange: ref pointing to a batch NOT in the store
    let kp = KeyPair::generate().expect("keygen");
    let batch = Batch::new(addr(1), vec![make_tx(&kp, 0)]);
    let batch_ref = batch.to_ref().unwrap();
    // Note: batch NOT inserted into store.
    let store: HashMap<Hash, Batch> = HashMap::new();

    let block = make_dag_block(0, addr(1), vec![batch_ref]);
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    // Act
    resolve_block_payload(&block, &store, &mut seen, &mut out);

    // Assert: skipped, no panic
    assert!(out.is_empty(), "unpinned ref must be skipped gracefully");
}

#[test]
fn resolve_block_payload_deduplicates_within_single_block() {
    // Arrange: two refs pointing to batches that contain the SAME tx
    let kp = KeyPair::generate().expect("keygen");
    let tx = make_tx(&kp, 0);

    let b0 = Batch::new(addr(1), vec![tx.clone()]);
    let b1 = Batch::new(addr(2), vec![tx.clone()]);
    let r0 = b0.to_ref().unwrap();
    let r1 = b1.to_ref().unwrap();

    let mut store: HashMap<Hash, Batch> = HashMap::new();
    store.insert(b0.digest().unwrap(), b0);
    store.insert(b1.digest().unwrap(), b1);

    let block = make_dag_block(0, addr(1), vec![r0, r1]);
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    // Act
    resolve_block_payload(&block, &store, &mut seen, &mut out);

    // Assert: tx appears exactly once
    assert_eq!(out.len(), 1, "duplicate tx must appear exactly once");
    assert_eq!(out[0].hash, tx.hash);
}

// ── resolve_committed_txs ─────────────────────────────────────────────────────

#[test]
fn resolve_committed_txs_returns_all_txs_in_subdag_order() {
    // Arrange: single validator, single round.
    // One batch at round 0 contains [tx0, tx1] in insertion order.
    // Tests: happy path + that batch tx order is preserved through resolution.
    let mut dag = Dag::new(0);
    let kp = KeyPair::generate().expect("keygen");

    let tx0 = make_tx(&kp, 0);
    let tx1 = make_tx(&kp, 1);

    // Both txs in one batch — order within batch is insertion order.
    let batch = Batch::new(addr(1), vec![tx0.clone(), tx1.clone()]);
    let batch_ref = batch.to_ref().unwrap();

    let block = make_dag_block(0, addr(1), vec![batch_ref]);
    let block_ref = block.reference();
    insert_block(&mut dag, block);

    let mut store: HashMap<Hash, Batch> = HashMap::new();
    store.insert(batch.digest().unwrap(), batch);

    let commit = make_commit(vec![block_ref]);

    // Act
    let txs = resolve_committed_txs(&commit, &dag, &store);

    // Assert: both txs present, in batch-insertion order
    assert_eq!(txs.len(), 2);
    assert_eq!(
        txs[0].hash, tx0.hash,
        "tx0 must come first (insertion order)"
    );
    assert_eq!(txs[1].hash, tx1.hash, "tx1 must come second");
}

#[test]
fn resolve_committed_txs_deduplicates_across_blocks() {
    // Arrange: realistic multi-validator scenario.
    //
    // Two validators (addr(1), addr(2)) both independently include the same
    // pending tx in their round-0 batches — this happens naturally when two
    // validators drain their mempools concurrently (both see the same tx).
    // When Pulse linearizes the sub-DAG, both blocks appear in commit.blocks.
    // resolve_committed_txs must dedup so the tx executes exactly once.
    //
    // Round 0 is exempt from the strong-link quorum check (spec §2.1
    // "Genesis-round exemption: round 0 is exempt from rule 5"), so blocks
    // from both validators can be inserted without ancestor chains.
    let mut dag = Dag::new(0);
    let kp = KeyPair::generate().expect("keygen");
    let tx = make_tx(&kp, 0);

    // Validator 1 batch + block.
    let b_v1 = Batch::new(addr(1), vec![tx.clone()]);
    let r_v1 = b_v1.to_ref().unwrap();
    let block_v1 = make_dag_block(0, addr(1), vec![r_v1]);
    let ref_v1 = block_v1.reference();
    insert_block(&mut dag, block_v1);

    // Validator 2 batch + block — same tx, different batch (different author → different digest).
    let b_v2 = Batch::new(addr(2), vec![tx.clone()]);
    let r_v2 = b_v2.to_ref().unwrap();
    let block_v2 = make_dag_block(0, addr(2), vec![r_v2]);
    let ref_v2 = block_v2.reference();
    insert_block(&mut dag, block_v2);

    let mut store: HashMap<Hash, Batch> = HashMap::new();
    store.insert(b_v1.digest().unwrap(), b_v1);
    store.insert(b_v2.digest().unwrap(), b_v2);

    // commit.blocks in (round ASC, author ASC) order: addr(1) < addr(2).
    let commit = make_commit(vec![ref_v1, ref_v2]);

    // Act
    let txs = resolve_committed_txs(&commit, &dag, &store);

    // Assert: exactly one occurrence; first occurrence (from addr(1)) wins.
    assert_eq!(
        txs.len(),
        1,
        "same tx across two validators must be deduped"
    );
    assert_eq!(txs[0].hash, tx.hash);
}

#[test]
fn resolve_committed_txs_empty_payload_produces_empty_list() {
    // Arrange: DagBlock with no payload refs
    let mut dag = Dag::new(0);
    let block = make_dag_block(0, addr(1), vec![]); // empty payload
    let block_ref = block.reference();
    insert_block(&mut dag, block);

    let store: HashMap<Hash, Batch> = HashMap::new();
    let commit = make_commit(vec![block_ref]);

    // Act
    let txs = resolve_committed_txs(&commit, &dag, &store);

    // Assert
    assert!(txs.is_empty(), "empty payload → zero txs");
}

#[test]
fn resolve_committed_txs_skips_missing_dag_block() {
    // Arrange: commit references a block NOT inserted into the DAG
    let dag = Dag::new(0);
    let phantom_ref = DagBlockRef::new(99, addr(1), Hash::from_bytes([0xAB; 32]));
    let commit = make_commit(vec![phantom_ref]);
    let store: HashMap<Hash, Batch> = HashMap::new();

    // Act
    let txs = resolve_committed_txs(&commit, &dag, &store);

    // Assert: skipped, no panic
    assert!(
        txs.is_empty(),
        "missing DagBlock must be skipped gracefully"
    );
}

#[test]
fn resolve_committed_txs_skips_availability_miss() {
    // Arrange: block in DAG references a batch NOT in the store
    let mut dag = Dag::new(0);
    let kp = KeyPair::generate().expect("keygen");
    let batch = Batch::new(addr(1), vec![make_tx(&kp, 0)]);
    let batch_ref = batch.to_ref().unwrap();
    // Batch NOT pinned in store.
    let store: HashMap<Hash, Batch> = HashMap::new();

    let block = make_dag_block(0, addr(1), vec![batch_ref]);
    let block_ref = block.reference();
    insert_block(&mut dag, block);

    let commit = make_commit(vec![block_ref]);

    // Act
    let txs = resolve_committed_txs(&commit, &dag, &store);

    // Assert: skipped, no panic
    assert!(
        txs.is_empty(),
        "availability miss must be skipped gracefully"
    );
}

#[test]
fn resolve_committed_txs_is_deterministic() {
    // Arrange
    let mut dag = Dag::new(0);
    let kp = KeyPair::generate().expect("keygen");
    let tx = make_tx(&kp, 0);
    let batch = Batch::new(addr(1), vec![tx]);
    let batch_ref = batch.to_ref().unwrap();
    let block = make_dag_block(0, addr(1), vec![batch_ref]);
    let block_ref = block.reference();
    insert_block(&mut dag, block);

    let mut store: HashMap<Hash, Batch> = HashMap::new();
    store.insert(batch.digest().unwrap(), batch);

    let commit = make_commit(vec![block_ref]);

    // Act: call twice with same inputs
    let txs1 = resolve_committed_txs(&commit, &dag, &store);
    let txs2 = resolve_committed_txs(&commit, &dag, &store);

    // Assert: identical outputs
    assert_eq!(txs1.len(), txs2.len());
    for (t1, t2) in txs1.iter().zip(txs2.iter()) {
        assert_eq!(t1.hash, t2.hash, "resolve must be deterministic");
    }
}
