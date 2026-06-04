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
    let proposer = addr(1);
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    let (block, _hash) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![]).unwrap();
    assert_eq!(block.height(), 1, "height must equal commit.index");
}

#[test]
fn build_block_from_commit_maps_dag_round_and_anchor() {
    let proposer = addr(1);
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    let (block, _hash) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![]).unwrap();
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
    let proposer = addr(1);
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);

    // commit.timestamp_ms = 5_000 ms → header.timestamp = 5 seconds.
    let mut commit = make_commit(1, 3, proposer);
    commit.timestamp_ms = 5_000;

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![]).unwrap();
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
    let proposer = addr(1);
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);

    let mut commit = make_commit(1, 3, proposer);
    commit.timestamp_ms = 0; // way before parent

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![]).unwrap();
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
    let proposer = addr(1);
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![]).unwrap();
    // Empty txs vec → no execution → empty block.
    assert!(block.transactions.is_empty(), "no txs passed → empty block");
    assert!(block.receipts.is_empty(), "no txs → no receipts");
    assert_eq!(block.header.gas_used, 0, "no txs → zero gas used");
}

#[test]
fn build_block_from_commit_fails_on_uninitialised_chain() {
    let proposer = addr(1);
    let dir = TempDir::new().unwrap();
    // Do NOT call init_chain — chain is empty.
    let db = Arc::new(LemmaDb::open(dir.path()).unwrap());
    let chain = lemma_storage::ChainStore::new(&db);
    let commit = make_commit(1, 3, proposer);

    let result = build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![]);
    assert!(
        result.is_err(),
        "uninitialised chain must return Err (no tip)"
    );
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
    let b1 = tokio::time::timeout(std::time::Duration::from_secs(5), block_rx.recv())
        .await
        .expect("timed out waiting for block 1")
        .unwrap();

    let b2 = tokio::time::timeout(std::time::Duration::from_secs(5), block_rx.recv())
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
    let proposer = addr(1);
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);

    let mut commit = make_commit(1, 3, proposer);
    commit.timestamp_ms = 2_000_000_000; // 2_000_000 seconds

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![]).unwrap();
    assert_eq!(
        block.header.timestamp, 2_000_000,
        "when commit_secs > parent.timestamp, header.timestamp = commit.timestamp_ms / 1000"
    );
}

#[test]
fn build_block_from_commit_clamps_timestamp_below_parent_plus_one() {
    // Tests the CLAMPED path: commit.timestamp_ms/1000 < parent.timestamp
    // → header.timestamp == parent.timestamp + 1.
    let proposer = addr(1);
    let (_dir, db) = fresh_chain(proposer);
    let chain = lemma_storage::ChainStore::new(&db);

    let mut commit = make_commit(1, 3, proposer);
    commit.timestamp_ms = 0; // 0 seconds << genesis 1_000_000

    let (block, _) =
        build_block_from_commit(&commit, &chain, proposer, Arc::clone(&db), vec![]).unwrap();

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
