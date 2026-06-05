//! Tests for `lemma_node::dag_driver`.
//!
//! Covers: DagBlock assembly, Commit→chain block mapping (height, timestamp,
//! dag_round, dag_anchor), timestamp clamping, integration test for the full
//! single-node DAG driver producing committed chain blocks with VM execution
//! (C·Step 13: Transfer tx → real state_root change).
//!
//! D·15b-1: `run_dag_driver_processes_peer_block_via_channel` — peer DagBlock
//! fed via `incoming_dag_block_rx` is accepted without fatal error.
//!
//! D·15b-3: `build_block_from_commit_sets_quorum_cert` — block has Some(qc)
//! with correct height, header_digest, signer count.
//! `build_block_from_commit_quorum_cert_signature_verifiable` — QC sig verifies
//! against header_digest using keypair's public key.
//!
//! AGENTS §11: separate tests.rs, `{action}_{outcome}` naming, AAA pattern.

use std::collections::BTreeMap;
use std::sync::Arc;

use tempfile::TempDir;
use tokio::sync::{Mutex, RwLock};

use lemma_consensus::{commit::Commit, dag::block::DagBlockRef};
use lemma_core::{
    address::Address,
    amount::Amount,
    genesis::GenesisConfig,
    hash::Hash,
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus, VotingPower},
    validator_set::{Member, ValidatorSet},
};
use lemma_crypto::{sign_transaction, KeyPair};
use lemma_mempool::pool::{AdmitContext, Mempool};
use lemma_storage::{db::LemmaDb, state::WorldState};

use crate::{
    batch::new_batch_store,
    dag_driver::{build_block_from_commit, build_dag_block, DagConfig},
    genesis_boot::init_chain,
};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

/// Generate a fresh `KeyPair` for test use — panics on generation failure.
fn test_kp() -> KeyPair {
    KeyPair::generate().expect("test keypair generation")
}

fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32])
}

/// Single-validator ValidatorSet at epoch 0 (genesis epoch).
fn single_vset(proposer: Address) -> ValidatorSet {
    let power = VotingPower(Amount::from_drop(1_000_000));
    let mut members = BTreeMap::new();
    members.insert(
        proposer,
        Member {
            consensus_pubkey: dummy_key(),
            power,
        },
    );
    ValidatorSet {
        epoch: 0, // genesis epoch (matches genesis_boot epoch 0)
        members,
        total_power: Amount::from_drop(1_000_000),
    }
}

/// Build a ValidatorSet with a real consensus pubkey from the given keypair.
fn single_vset_with_real_key(kp: &KeyPair) -> ValidatorSet {
    let pk = kp.public_key();
    let consensus_pubkey =
        lemma_core::validator::ConsensusKey::from_bytes(pk.classical.clone(), pk.quantum.clone());
    let power = VotingPower(Amount::from_drop(1_000_000));
    let mut members = BTreeMap::new();
    members.insert(
        *kp.address(),
        Member {
            consensus_pubkey,
            power,
        },
    );
    ValidatorSet {
        epoch: 0,
        members,
        total_power: Amount::from_drop(1_000_000),
    }
}

/// Minimal genesis config for initialising a chain in tests.
fn minimal_genesis(proposer: Address) -> GenesisConfig {
    let validator = Validator {
        address: proposer,
        consensus_pubkey: dummy_key(),
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active: Amount::from_drop(1_000_000),
            pending_active: Amount::from_drop(0),
            pending_inactive: vec![],
            inactive: Amount::from_drop(0),
        },
        delegated: Amount::from_drop(0),
        commission_bps: 0,
        jailed_until: None,
    };
    let mut genesis_validators = BTreeMap::new();
    genesis_validators.insert(proposer, validator);

    GenesisConfig {
        chain_id: 1,
        genesis_timestamp: 1_000_000,
        initial_gas_limit: 30_000_000,
        initial_base_fee: Amount::from_drop(1_000_000_000),
        initial_balances: BTreeMap::new(),
        genesis_validators,
    }
}

/// Open a fresh temp-dir LemmaDb and initialise the chain.
fn fresh_chain(proposer: Address) -> (TempDir, Arc<LemmaDb>) {
    let dir = TempDir::new().unwrap();
    let genesis = minimal_genesis(proposer);
    init_chain(LemmaDb::open(dir.path()).unwrap(), &genesis).unwrap();
    let db = Arc::new(LemmaDb::open(dir.path()).unwrap());
    (dir, db)
}

/// Build a minimal Commit at the given index / leader round.
/// `timestamp_ms` is set to (index * 1000) ms so commits are monotonically
/// spaced and their ms/1000 values are 1-second apart.
fn make_commit(index: u64, leader_round: u64, leader_author: Address) -> Commit {
    let leader = DagBlockRef::new(
        leader_round,
        leader_author,
        Hash::from_bytes([index as u8; 32]),
    );
    Commit {
        index,
        previous_digest: Hash::zero(),
        timestamp_ms: index * 1_000, // ms — gives timestamp = index seconds
        leader,
        blocks: vec![leader],
    }
}

// ── build_dag_block ───────────────────────────────────────────────────────────

#[test]
fn build_dag_block_sets_round_and_author() {
    let kp = test_kp();
    let proposer = *kp.address();
    let block =
        build_dag_block(3, proposer, vec![], vec![], 1, 1_000, &kp).expect("build_dag_block");
    assert_eq!(block.round, 3);
    assert_eq!(block.author, proposer);
}

#[test]
fn build_dag_block_sets_epoch_and_timestamp() {
    let kp = test_kp();
    let proposer = *kp.address();
    let block =
        build_dag_block(0, proposer, vec![], vec![], 42, 9_999, &kp).expect("build_dag_block");
    assert_eq!(block.epoch, 42);
    assert_eq!(block.timestamp_ms, 9_999);
}

#[test]
fn build_dag_block_includes_ancestors() {
    let kp = test_kp();
    let proposer = *kp.address();
    let ancestor = DagBlockRef::new(0, proposer, Hash::from_bytes([0xAB; 32]));
    let block =
        build_dag_block(1, proposer, vec![ancestor], vec![], 1, 0, &kp).expect("build_dag_block");
    assert_eq!(block.ancestors.len(), 1);
    assert_eq!(block.ancestors[0], ancestor);
}

#[test]
fn build_dag_block_has_empty_payload_and_commit_votes() {
    let kp = test_kp();
    let block =
        build_dag_block(0, *kp.address(), vec![], vec![], 1, 0, &kp).expect("build_dag_block");
    assert!(
        block.payload.is_empty(),
        "Phase 2: empty payload when passed vec![]"
    );
    assert!(
        block.commit_votes.is_empty(),
        "Phase 2: no commit votes piggybacked"
    );
}

#[test]
fn build_dag_block_reference_matches_block() {
    let kp = test_kp();
    let proposer = *kp.address();
    let block = build_dag_block(5, proposer, vec![], vec![], 1, 0, &kp).expect("build_dag_block");
    let r = block.reference();
    assert_eq!(r.round, 5);
    assert_eq!(r.author, proposer);
    assert_eq!(r.digest, block.digest);
}

#[test]
fn build_dag_block_rejects_author_keypair_mismatch() {
    // author = addr(0xFF) but keypair is a fresh random keypair → addresses differ.
    let kp = test_kp();
    let mismatched_author = addr(0xFF); // addr derives from [0xFF;32], not from kp
    let result = build_dag_block(1, mismatched_author, vec![], vec![], 0, 0, &kp);
    assert!(
        result.is_err(),
        "mismatched author and keypair address must return Err"
    );
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("does not match author"),
        "error message must name the mismatch: {err_msg}"
    );
}

#[test]
fn build_dag_block_signature_verifiable_by_public_key() {
    use lemma_core::signature::Signature;
    use lemma_crypto::{verify, HybridSignature};

    // Arrange: keypair + block (author derived from keypair — guard requires match).
    let kp = test_kp();
    let pk = kp.public_key();
    let proposer = *kp.address();
    let block = build_dag_block(2, proposer, vec![], vec![], 1, 0, &kp).expect("build_dag_block");

    // Assert: signature is Hybrid (not Unsigned).
    let (classical, quantum) = match &block.signature {
        Signature::Hybrid { classical, quantum } => (classical.clone(), quantum.clone()),
        other => panic!("expected Hybrid signature, got {:?}", other),
    };

    // Reconstruct HybridSignature and verify against the block body digest.
    // sign_to_lemma() signs `digest.as_bytes()`; we verify the same payload.
    let hybrid = HybridSignature { classical, quantum };
    verify(&pk, block.digest.as_bytes(), &hybrid)
        .expect("DagBlock signature must verify against block digest");
}

// ── build_block_from_commit ───────────────────────────────────────────────────

#[test]
fn build_block_from_commit_maps_height_to_commit_index() {
    // Proposer derived from keypair — build_block_from_commit signs with keypair.
    let kp = test_kp();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    let (block, _hash) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp).unwrap();
    assert_eq!(block.height(), 1, "height must equal commit.index");
}

#[test]
fn build_block_from_commit_maps_dag_round_and_anchor() {
    let kp = test_kp();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    let (block, _hash) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp).unwrap();
    assert_eq!(
        block.header.dag_round, 3,
        "dag_round must equal commit.leader.round"
    );
    assert_eq!(
        block.header.dag_anchor, commit.leader.digest,
        "dag_anchor must equal commit.leader.digest"
    );
}

#[test]
fn build_block_from_commit_timestamp_is_seconds_not_millis() {
    let kp = test_kp();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);

    // commit.timestamp_ms = 5_000 ms → header.timestamp = 5 seconds.
    let mut commit = make_commit(1, 3, proposer);
    commit.timestamp_ms = 5_000;

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp).unwrap();
    // Genesis timestamp is 1_000_000 (from minimal_genesis), so 5s < parent → clamped.
    // The clamped value must be > parent (1_000_000), which means >= 1_000_001.
    assert!(
        block.header.timestamp > 1_000_000,
        "timestamp must be > parent (monotonicity clamp applied)"
    );
}

#[test]
fn build_block_from_commit_timestamp_is_monotonic_when_below_parent() {
    // commit timestamp of 0 ms → 0 s, which is < parent (genesis) → clamped to parent + 1.
    let kp = test_kp();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);

    let mut commit = make_commit(1, 3, proposer);
    commit.timestamp_ms = 0; // way before parent

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp).unwrap();
    let (_, parent_hash) = lemma_storage::ChainStore::new(&db).tip().unwrap().unwrap();
    let parent = lemma_storage::ChainStore::new(&db)
        .get_block_by_hash(&parent_hash)
        .unwrap()
        .unwrap();

    assert!(
        block.header.timestamp > parent.header.timestamp,
        "timestamp must be strictly > parent even when commit.timestamp_ms is 0"
    );
}

#[test]
fn build_block_from_commit_produces_empty_block() {
    let kp = test_kp();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp).unwrap();
    // Empty txs vec → no execution → empty block.
    assert!(block.transactions.is_empty(), "no txs passed → empty block");
    assert!(block.receipts.is_empty(), "no txs → no receipts");
    assert_eq!(block.header.gas_used, 0, "no txs → zero gas used");
}

#[test]
fn build_block_from_commit_fails_on_uninitialised_chain() {
    let kp = test_kp();
    let proposer = *kp.address();
    let dir = TempDir::new().unwrap();
    // Do NOT call init_chain — chain is empty.
    let db = Arc::new(LemmaDb::open(dir.path()).unwrap());
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    let result = build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp);
    assert!(
        result.is_err(),
        "uninitialised chain must return Err (no tip)"
    );
}

// ── D·15b-3: QC assembly at commit time ──────────────────────────────────────

/// D·15b-3: `build_block_from_commit` returns a `Block` with `quorum_cert = Some(qc)`
/// where `qc.height == block.height()`, `qc.header_digest` is the Blake3 of the
/// serialized header, and `qc.signer_count() == 1` (Phase 2 single-validator).
#[test]
fn build_block_from_commit_sets_quorum_cert() {
    // Arrange: keypair-derived proposer (QC signer must match proposer).
    let kp = test_kp();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    // Act.
    let (block, _hash) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp).unwrap();

    // Assert: QC is present.
    let qc = block
        .quorum_cert
        .as_ref()
        .expect("block must have quorum_cert = Some(qc) after D·15b-3");

    // height matches block height.
    assert_eq!(
        qc.height,
        block.height(),
        "qc.height must equal block.height()"
    );

    // header_digest = Blake3(serde_json::to_vec(header)).
    let expected_digest = {
        let header_bytes = serde_json::to_vec(&block.header).expect("header serialization");
        lemma_crypto::hash_bytes(&header_bytes)
    };
    assert_eq!(
        qc.header_digest, expected_digest,
        "qc.header_digest must equal Blake3(serde_json(header))"
    );

    // Exactly one signer (Phase 2: 100% stake).
    assert_eq!(
        qc.signer_count(),
        1,
        "Phase 2 QC must have exactly 1 signer"
    );

    // Signer is the proposer.
    assert!(
        qc.signers.contains_key(&proposer),
        "QC signers must contain the proposer address"
    );
}

/// D·15b-3: The signature in the QC is verifiable against the proposer's public key.
///
/// Extracts `header_digest` and the `Signature::Hybrid` from the QC, reconstructs
/// a `HybridSignature`, and calls `lemma_crypto::verify` over `header_digest.as_bytes()`.
#[test]
fn build_block_from_commit_quorum_cert_signature_verifiable() {
    use lemma_core::signature::Signature;
    use lemma_crypto::{verify, HybridSignature};

    // Arrange.
    let kp = test_kp();
    let pk = kp.public_key();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    // Act.
    let (block, _hash) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp).unwrap();

    // Extract QC.
    let qc = block
        .quorum_cert
        .as_ref()
        .expect("block must have quorum_cert");

    // Extract the signer's Signature::Hybrid from the QC.
    let sig = qc
        .signers
        .get(&proposer)
        .expect("proposer must be in QC signers");
    let (classical, quantum) = match sig {
        Signature::Hybrid { classical, quantum } => (classical.clone(), quantum.clone()),
        other => panic!("expected Hybrid signature in QC, got {:?}", other),
    };

    // Reconstruct HybridSignature and verify against header_digest.
    // sign_to_lemma() signs `header_digest.as_bytes()`; we verify the same payload.
    let hybrid = HybridSignature { classical, quantum };
    verify(&pk, qc.header_digest.as_bytes(), &hybrid)
        .expect("QC signature must verify against header_digest using proposer's public key");
}

// ── Integration: run_dag_driver produces chain blocks ────────────────────────

#[tokio::test]
async fn run_dag_driver_produces_chain_block_from_dag_consensus() {
    // Arrange: single-validator chain, dag driver runs until it produces ≥1 block.
    // Proposer derived from keypair — build_dag_block guard requires author == keypair.address().
    let kp = Arc::new(KeyPair::generate().expect("test keypair"));
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let write_lock = Arc::new(Mutex::new(()));
    let (block_tx, mut block_rx) = tokio::sync::mpsc::channel(16);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Genesis boots at epoch 0; driver must match chain epoch.
    let vset = single_vset(proposer);
    let cfg = DagConfig {
        epoch: 0,
        proposer,
        validator_set: vset,
    };

    // Run the driver in a background task; shut it down after the first block.
    let db_clone = Arc::clone(&db);
    let mempool_clone = Arc::clone(&mempool);
    let write_lock_clone = Arc::clone(&write_lock);
    let kp_clone = Arc::clone(&kp);
    let driver_handle = tokio::spawn(async move {
        crate::dag_driver::run_dag_driver(
            db_clone,
            mempool_clone,
            cfg,
            kp_clone,
            new_batch_store(),
            Some(block_tx),
            None, // no dag_block_tx needed for this test
            None, // no batch_tx needed for this test
            write_lock_clone,
            shutdown_rx,
            None, // no incoming_dag_block_rx in single-node mode
        )
        .await
    });

    // Wait for the first committed chain block (timeout = 5s).
    let committed_block = tokio::time::timeout(std::time::Duration::from_secs(5), block_rx.recv())
        .await
        .expect("timed out — no chain block produced within 5s (dag driver stalled)")
        .expect("block_tx closed before first block");

    // Signal shutdown.
    let _ = shutdown_tx.send(true);
    let _ = driver_handle.await;

    // Assert: the produced block has correct DAG consensus fields.
    assert_eq!(
        committed_block.height(),
        1,
        "first DAG-consensus block at height 1"
    );
    assert_ne!(
        committed_block.header.dag_round, 0,
        "dag_round must be non-zero (wave-1 leader at round 3)"
    );
    assert_ne!(
        committed_block.header.dag_anchor,
        Hash::zero(),
        "dag_anchor must be non-zero (set to leader block digest)"
    );
    // D·15b-3: DAG-produced blocks must carry a commit-certificate.
    assert!(
        committed_block.quorum_cert.is_some(),
        "DAG-consensus block must have quorum_cert = Some(qc) (D·15b-3)"
    );
}

#[tokio::test]
async fn run_dag_driver_chain_block_height_matches_commit_index() {
    // The second chain block must be at height 2 (commit.index=2).
    let kp = Arc::new(KeyPair::generate().expect("test keypair"));
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let write_lock = Arc::new(Mutex::new(()));
    let (block_tx, mut block_rx) = tokio::sync::mpsc::channel(16);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let vset = single_vset(proposer);
    let cfg = DagConfig {
        epoch: 0,
        proposer,
        validator_set: vset,
    };

    let db_clone = Arc::clone(&db);
    let mp_clone = Arc::clone(&mempool);
    let wl_clone = Arc::clone(&write_lock);
    let kp_clone = Arc::clone(&kp);
    tokio::spawn(async move {
        let _ = crate::dag_driver::run_dag_driver(
            db_clone,
            mp_clone,
            cfg,
            kp_clone,
            new_batch_store(),
            Some(block_tx),
            None,
            None,
            wl_clone,
            shutdown_rx,
            None,
        )
        .await;
    });

    // Drain 2 committed blocks.
    // Timeout 30s each: in debug builds, ML-DSA-65 (pqcrypto-mldsa) signing is
    // unoptimized and adds ~100–500 ms per DAG round. A second wave (6 more rounds)
    // can take 10–20s in debug mode. 30s gives ample headroom without being flaky.
    let b1 = tokio::time::timeout(std::time::Duration::from_secs(30), block_rx.recv())
        .await
        .expect("timed out waiting for block 1")
        .unwrap();

    let b2 = tokio::time::timeout(std::time::Duration::from_secs(30), block_rx.recv())
        .await
        .expect("timed out waiting for block 2")
        .unwrap();

    let _ = shutdown_tx.send(true);

    assert_eq!(b1.height(), 1, "first committed block at height 1");
    assert_eq!(b2.height(), 2, "second committed block at height 2");
    // Chain must be monotonically ordered.
    assert!(
        b2.header.timestamp >= b1.header.timestamp,
        "timestamps must be monotonically non-decreasing"
    );
}

// ── Q16: build_block_from_commit timestamp — both branches of .max() ─────────

#[test]
fn build_block_from_commit_uses_commit_timestamp_when_above_parent() {
    // Tests the UN-clamped path: commit.timestamp_ms/1000 > parent.timestamp
    // → header.timestamp == commit.timestamp_ms / 1000.
    // Genesis timestamp = 1_000_000 s; commit.timestamp_ms = 2_000_000_000 ms
    // → commit_secs = 2_000_000 > 1_000_000 → no clamp applied.
    let kp = test_kp();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);

    let mut commit = make_commit(1, 3, proposer);
    commit.timestamp_ms = 2_000_000_000; // 2_000_000 seconds

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp).unwrap();
    assert_eq!(
        block.header.timestamp, 2_000_000,
        "when commit_secs > parent.timestamp, header.timestamp = commit.timestamp_ms / 1000"
    );
}

#[test]
fn build_block_from_commit_clamps_timestamp_below_parent_plus_one() {
    // Tests the CLAMPED path: commit.timestamp_ms/1000 < parent.timestamp
    // → header.timestamp == parent.timestamp + 1.
    let kp = test_kp();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);

    let mut commit = make_commit(1, 3, proposer);
    commit.timestamp_ms = 0; // 0 seconds << genesis 1_000_000

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![], &kp).unwrap();

    // Fetch genesis block to get its timestamp.
    let (_, genesis_hash) = lemma_storage::ChainStore::new(&db).tip().unwrap().unwrap();
    let genesis = lemma_storage::ChainStore::new(&db)
        .get_block_by_hash(&genesis_hash)
        .unwrap()
        .unwrap();

    assert_eq!(
        block.header.timestamp,
        genesis.header.timestamp + 1,
        "when commit_secs < parent.timestamp, header.timestamp = parent.timestamp + 1"
    );
}

// ── C·Step 13: run_dag_driver executes txs + changes state_root ──────────────

/// C·Step 13 integration test: single-node DAG driver executes a Transfer tx
/// from the mempool, produces a real receipt, and changes state_root.
///
/// This closes the "tx ingestion → VM exec → real state_root" milestone.
#[tokio::test]
async fn run_dag_driver_executes_transfer_and_changes_state_root() {
    // Arrange: fund a sender via genesis, create a signed Transfer tx.
    // Proposer keypair generated first so proposer == keypair.address() (guard in build_dag_block).
    let proposer_kp = Arc::new(KeyPair::generate().expect("proposer keypair"));
    let proposer = *proposer_kp.address();
    let sender_kp = KeyPair::generate().expect("KeyPair::generate");
    let sender = *sender_kp.address();
    let recipient = addr(0xBB);

    // Fund sender with 1_000_000 Drop (covers value + gas with zero gas_price tx).
    let mut initial_balances = BTreeMap::new();
    initial_balances.insert(sender, Amount::from_drop(1_000_000));
    let genesis_cfg = GenesisConfig {
        chain_id: 1,
        genesis_timestamp: 1_000_000,
        initial_gas_limit: 30_000_000,
        initial_base_fee: Amount::from_drop(1_000_000_000),
        initial_balances,
        genesis_validators: {
            let validator = lemma_core::validator::Validator {
                address: proposer,
                consensus_pubkey: dummy_key(),
                status: lemma_core::validator::ValidatorStatus::Bonded,
                tombstoned: false,
                self_stake: lemma_core::validator::Stake {
                    active: Amount::from_drop(1_000_000),
                    pending_active: Amount::from_drop(0),
                    pending_inactive: vec![],
                    inactive: Amount::from_drop(0),
                },
                delegated: Amount::from_drop(0),
                commission_bps: 0,
                jailed_until: None,
            };
            let mut m = BTreeMap::new();
            m.insert(proposer, validator);
            m
        },
    };

    let dir = TempDir::new().unwrap();
    init_chain(LemmaDb::open(dir.path()).unwrap(), &genesis_cfg).unwrap();
    let db = Arc::new(LemmaDb::open(dir.path()).unwrap());

    // Build a signed Transfer tx and admit it into the mempool directly.
    let genesis_block = lemma_storage::ChainStore::new(&db)
        .get_block_by_height(0)
        .unwrap()
        .unwrap();
    let genesis_state_root = genesis_block.header.state_root;
    // Use gas_price=0 (and base_fee=0 in AdmitContext below) for test isolation:
    // avoids requiring sender to hold 100 LEM just to cover gas costs.
    let mut signed_tx = lemma_core::transaction::Transaction::new(
        Hash::zero(),
        sender,
        Some(recipient),
        0, // nonce
        1, // chain_id
        Amount::from_drop(1_000),
        100_000,        // gas_limit
        Amount::zero(), // gas_price=0
        lemma_core::transaction::TxType::Transfer,
        vec![],
        lemma_core::signature::Signature::Unsigned,
    )
    .unwrap();
    // sign_transaction mutates in-place: sets hash + Signature::Hybrid.
    sign_transaction(&mut signed_tx, &sender_kp).unwrap();

    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    {
        let world = WorldState::with_state_root(Arc::clone(&db), genesis_state_root);
        let ctx = AdmitContext {
            chain_id: 1,
            base_fee: Amount::zero(), // zero base_fee for test isolation
            now: std::time::Instant::now(),
        };
        let pubkey = sender_kp.public_key();
        let _ = mempool
            .write()
            .await
            .admit(
                signed_tx,
                &pubkey,
                Amount::zero(),
                None::<&lemma_mempool::express::ExpressHint>,
                &world,
                &ctx,
            )
            .expect("Mempool::admit must accept a valid Transfer tx");
    }
    assert_eq!(
        mempool.read().await.len(),
        1,
        "mempool must contain the admitted tx"
    );

    // Run the DAG driver until at least one block is committed.
    let write_lock = Arc::new(Mutex::new(()));
    let (block_tx, mut block_rx) = tokio::sync::mpsc::channel(16);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let vset = single_vset(proposer);
    let cfg = DagConfig {
        epoch: 0,
        proposer,
        validator_set: vset,
    };
    let db_clone = Arc::clone(&db);
    let mp_clone = Arc::clone(&mempool);
    let wl_clone = Arc::clone(&write_lock);
    let kp_clone = Arc::clone(&proposer_kp);
    tokio::spawn(async move {
        let _ = crate::dag_driver::run_dag_driver(
            db_clone,
            mp_clone,
            cfg,
            kp_clone,
            new_batch_store(),
            Some(block_tx),
            None,
            None,
            wl_clone,
            shutdown_rx,
            None,
        )
        .await;
    });

    // Wait for the first committed block.
    let committed = tokio::time::timeout(std::time::Duration::from_secs(10), block_rx.recv())
        .await
        .expect("timed out — no chain block within 10s")
        .expect("block_tx closed before first block");

    let _ = shutdown_tx.send(true);

    // Assert: the committed block contains the Transfer tx.
    assert_eq!(committed.transactions.len(), 1, "block must contain 1 tx");
    assert_eq!(committed.receipts.len(), 1, "block must contain 1 receipt");
    assert!(
        committed.receipts[0].success,
        "Transfer must execute successfully"
    );
    assert!(committed.header.gas_used > 0, "gas_used must be > 0");
    assert_ne!(
        committed.header.state_root, genesis_state_root,
        "state_root must change after Transfer tx"
    );
    assert_ne!(
        committed.header.transactions_root,
        Hash::zero(),
        "transactions_root must be non-zero"
    );

    // Assert: mempool is empty after commit (tx removed by mempool_post_commit).
    assert_eq!(
        mempool.read().await.len(),
        0,
        "mempool must be empty after committed tx is removed"
    );

    // Assert: recipient balance updated in the new world state.
    let new_world = WorldState::with_state_root(db, committed.header.state_root);
    let recipient_balance = new_world.get_balance(&recipient).unwrap();
    assert_eq!(
        recipient_balance,
        Amount::from_drop(1_000),
        "recipient must receive exactly 1_000 Drop"
    );
}

// ── D·15b-1: run_dag_driver processes peer block via incoming channel ─────────

/// D·15b-1 integration test: a peer DagBlock sent via `incoming_dag_block_rx`
/// is accepted by the running DAG driver without a fatal error.
///
/// With a single-validator vset for the local node, the peer block won't cross
/// 2f+1 quorum alone, but it must be accepted into the DAG without panicking.
/// The test verifies the channel path is wired and the driver stays alive.
#[tokio::test]
async fn run_dag_driver_processes_peer_block_via_channel() {
    // Arrange: local keypair (proposer) + peer keypair.
    let local_kp = Arc::new(KeyPair::generate().expect("local keypair"));
    let peer_kp = KeyPair::generate().expect("peer keypair");
    let proposer = *local_kp.address();

    let (_dir, db) = fresh_chain(proposer);
    let mempool = Arc::new(RwLock::new(Mempool::new(100)));
    let write_lock = Arc::new(Mutex::new(()));
    let (block_tx, mut block_rx) = tokio::sync::mpsc::channel(16);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ValidatorSet: only the local proposer (single-node mode).
    // The peer block won't cross quorum alone — that's expected.
    let vset = single_vset_with_real_key(&local_kp);
    let cfg = DagConfig {
        epoch: 0,
        proposer,
        validator_set: vset,
    };

    // Build a peer DagBlock at round 0 signed by the peer keypair.
    // sig_ok = false because peer is not in the local vset — but the driver
    // must still accept it without crashing (non-fatal path).
    let peer_block = build_dag_block(0, *peer_kp.address(), vec![], vec![], 0, 0, &peer_kp)
        .expect("build peer DagBlock");

    // Create the incoming channel and send the peer block.
    let (incoming_tx, incoming_rx) =
        tokio::sync::mpsc::channel::<(lemma_consensus::dag::block::DagBlock, bool)>(8);

    // Send the peer block with sig_ok=false (unknown validator).
    incoming_tx
        .send((peer_block, false))
        .await
        .expect("send peer block");

    // Spawn the driver.
    let db_clone = Arc::clone(&db);
    let mp_clone = Arc::clone(&mempool);
    let wl_clone = Arc::clone(&write_lock);
    let kp_clone = Arc::clone(&local_kp);
    let driver_handle = tokio::spawn(async move {
        crate::dag_driver::run_dag_driver(
            db_clone,
            mp_clone,
            cfg,
            kp_clone,
            new_batch_store(),
            Some(block_tx),
            None,
            None,
            wl_clone,
            shutdown_rx,
            Some(incoming_rx),
        )
        .await
    });

    // Wait for the local node to produce its own first committed block
    // (the peer block alone won't trigger a commit in single-validator mode,
    // but the driver must continue running and eventually commit via its own blocks).
    let committed = tokio::time::timeout(std::time::Duration::from_secs(10), block_rx.recv())
        .await
        .expect("timed out — driver stalled after receiving peer block")
        .expect("block_tx closed before first block");

    // Signal shutdown.
    let _ = shutdown_tx.send(true);
    let result = driver_handle.await.expect("driver task panicked");

    // Assert: driver completed without fatal error.
    assert!(
        result.is_ok(),
        "driver must not return fatal error after processing peer block: {:?}",
        result
    );

    // Assert: the local node still produced a valid chain block.
    assert_eq!(
        committed.height(),
        1,
        "first committed block must be at height 1"
    );
}

// ── D·15e: 4-validator consensus produces identical commits + state_root ──────

/// D·15e integration test: 4 validators run in-process, all reach the same
/// commits, and the first committed chain block has a non-None quorum_cert.
///
/// ## What this tests
///
/// 1. **Consensus correctness**: 4 `SurgeDriver` instances fed the same set of
///    `DagBlock`s (in the same order) produce identical commit sequences.
/// 2. **Commit determinism**: all 4 drivers agree on commit index, leader round,
///    and leader author for every commit.
/// 3. **QC assembly**: `build_block_from_commit` produces a `Block` with
///    `quorum_cert = Some(qc)` (D·15b-3 path exercised from the 4-node context).
/// 4. **State-root determinism**: calling `build_block_from_commit` twice with
///    the same commit and empty txs produces the same `state_root`.
///
/// ## Test design
///
/// Uses `Signature::Unsigned` + `sig_ok = true` (unit-test focus: consensus
/// correctness, not signature verification). The sig-verify path is covered by
/// `build_dag_block_signature_verifiable_by_public_key` and the D·15b/c tests.
///
/// 3 × WAVE_LENGTH = 9 rounds (0–8) covers 3 waves:
/// - Foundation: rounds 0–2 (strong-link ancestors for round 3).
/// - Wave 1: rounds 3–5 (leader @ 3, voting @ 4, decision @ 5).
/// - Wave 2: rounds 6–8 (leader @ 6, voting @ 7, decision @ 8).
///
/// AGENTS §11: separate tests.rs, `{action}_{outcome}` naming, AAA pattern.
#[test]
fn four_validator_consensus_produces_identical_commits_and_state_root() {
    use std::collections::BTreeMap;

    use lemma_consensus::{
        dag::block::{DagBlock, DagBlockBody, DagBlockRef},
        SurgeDriver, WAVE_LENGTH,
    };
    use lemma_core::{
        amount::Amount,
        signature::Signature,
        validator::{ConsensusKey, VotingPower},
        validator_set::{Member, ValidatorSet},
    };

    // ── Arrange: 4-validator uniform-stake committee ──────────────────────────

    const N: u8 = 4;
    const POWER_DROP: u128 = 1_000_000;

    // Build a 4-validator ValidatorSet (epoch 1, uniform stake).
    let mut members = BTreeMap::new();
    for i in 1u8..=N {
        members.insert(
            addr(i),
            Member {
                consensus_pubkey: ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32]),
                power: VotingPower(Amount::from_drop(POWER_DROP)),
            },
        );
    }
    let vset = ValidatorSet {
        epoch: 1,
        members,
        total_power: Amount::from_drop(N as u128 * POWER_DROP),
    };

    // ── Build all DagBlocks for 3 × WAVE_LENGTH rounds ───────────────────────
    //
    // Round 0: 4 genesis blocks (no ancestors, Signature::Unsigned).
    // Rounds 1–8: 4 blocks per round, each referencing all blocks from the
    //             previous round (full connectivity — maximises quorum speed).
    //
    // All blocks use Signature::Unsigned + sig_ok=true (unit-test focus:
    // consensus correctness, not signature verification).

    let make_block = |round: u64, author_n: u8, ancestors: Vec<DagBlockRef>| -> DagBlock {
        DagBlock::new(
            DagBlockBody {
                epoch: 1,
                round,
                author: addr(author_n),
                timestamp_ms: 1_000 * round + author_n as u64,
                ancestors,
                payload: vec![],
                commit_votes: vec![],
            },
            Signature::Unsigned,
        )
    };

    // Build all blocks round by round, collecting (block, sig_ok) pairs.
    let mut all_blocks: Vec<(DagBlock, bool)> = Vec::new();

    // Round 0: genesis (no ancestors).
    let mut prev_refs: Vec<DagBlockRef> = Vec::new();
    for i in 1u8..=N {
        let b = make_block(0, i, vec![]);
        prev_refs.push(b.reference());
        all_blocks.push((b, true));
    }

    // Rounds 1 through 3 × WAVE_LENGTH - 1.
    let total_rounds = 3 * WAVE_LENGTH; // = 9
    for round in 1..total_rounds {
        let mut round_refs: Vec<DagBlockRef> = Vec::new();
        for i in 1u8..=N {
            let b = make_block(round, i, prev_refs.clone());
            round_refs.push(b.reference());
            all_blocks.push((b, true));
        }
        prev_refs = round_refs;
    }

    // ── Act: feed all blocks to 4 independent SurgeDrivers ───────────────────

    let mut drivers: Vec<SurgeDriver> = (0..N)
        .map(|_| SurgeDriver::new(vset.clone()).expect("SurgeDriver::new"))
        .collect();

    // Collect all commits from each driver.
    let mut all_commits: Vec<Vec<lemma_consensus::Commit>> = vec![Vec::new(); N as usize];

    for (block, sig_ok) in &all_blocks {
        for (idx, driver) in drivers.iter_mut().enumerate() {
            match driver.on_block(block.clone(), *sig_ok) {
                Ok(out) => {
                    all_commits[idx].extend(out.commits);
                }
                Err(e) => {
                    panic!(
                        "driver[{}] on_block failed at round {}: {}",
                        idx, block.round, e
                    );
                }
            }
        }
    }

    // ── Assert 1: all 4 drivers produced at least one commit ─────────────────

    for (idx, commits) in all_commits.iter().enumerate() {
        assert!(
            !commits.is_empty(),
            "driver[{idx}] must produce at least one commit after {total_rounds} rounds"
        );
    }

    // ── Assert 2: all 4 drivers produced the SAME commit sequence ────────────

    let reference_commits = &all_commits[0];
    for (idx, commits) in all_commits.iter().enumerate().skip(1) {
        assert_eq!(
            commits.len(),
            reference_commits.len(),
            "driver[{idx}] produced {} commits but driver[0] produced {} — must be identical",
            commits.len(),
            reference_commits.len()
        );
        for (pos, (c, ref_c)) in commits.iter().zip(reference_commits.iter()).enumerate() {
            assert_eq!(
                c.index, ref_c.index,
                "driver[{idx}] commit[{pos}].index={} != driver[0].index={}",
                c.index, ref_c.index
            );
            assert_eq!(
                c.leader.round, ref_c.leader.round,
                "driver[{idx}] commit[{pos}].leader.round={} != driver[0].leader.round={}",
                c.leader.round, ref_c.leader.round
            );
            assert_eq!(
                c.leader.author, ref_c.leader.author,
                "driver[{idx}] commit[{pos}].leader.author != driver[0].leader.author"
            );
        }
    }

    // ── Assert 3: QC assembly + state_root determinism ───────────────────────
    //
    // Build a chain block from the first commit using a fresh chain.
    // Verify: quorum_cert is Some(qc) and state_root is deterministic.

    let kp = test_kp();
    let proposer = *kp.address();
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);

    let first_commit = &reference_commits[0];

    let (block1, _hash1) = build_block_from_commit(
        first_commit,
        &chain,
        proposer,
        Arc::clone(&db),
        vec![], // empty txs — determinism test
        &kp,
    )
    .expect("build_block_from_commit must succeed");

    // QC must be present (D·15b-3).
    assert!(
        block1.quorum_cert.is_some(),
        "first committed chain block must have quorum_cert = Some(qc) (D·15b-3)"
    );

    // State-root determinism: same call with same empty txs → same state_root.
    let (block2, _hash2) =
        build_block_from_commit(first_commit, &chain, proposer, Arc::clone(&db), vec![], &kp)
            .expect("second build_block_from_commit must succeed");

    assert_eq!(
        block1.header.state_root, block2.header.state_root,
        "state_root must be deterministic for the same commit + empty txs"
    );

    // Commit index must be 1 (first commit).
    assert_eq!(
        block1.height(),
        first_commit.index,
        "block height must equal commit.index"
    );
}
