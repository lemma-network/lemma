//! Tests for [`block_exec`] — execute_committed_block + apply_writes.
//!
//! Covers:
//! - Empty-tx block preserves parent state_root.
//! - Transfer tx updates sender/receiver balances and advances sender nonce.
//! - state_root changes after a balance-changing block.
//! - state_root is deterministic: same txs → same root.
//! - Receipts are returned in block order.
//! - gas_used is summed correctly.
//! - transactions_root is non-zero for non-empty blocks.
//! - Storage writes change state_root (P3·Step 22).
//! - Storage writes are deterministic across DB instances.
//! - Code-only deploy leaves storage_root at Hash::zero().
//! - Storage writes update Account.storage_root to non-zero.
//!
//! AGENTS §11: separate tests.rs, `{action}_{outcome}` naming, AAA pattern.

use std::collections::BTreeMap;
use std::sync::Arc;

use tempfile::TempDir;

use lemma_consensus::{commit::Commit, dag::block::DagBlockRef};
use lemma_core::{
    address::Address,
    amount::Amount,
    block::Block,
    genesis::GenesisConfig,
    hash::Hash,
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus},
};
use lemma_crypto::{sign_transaction, KeyPair};
use lemma_mempool::pool::{AdmitContext, Mempool};
use lemma_storage::{db::LemmaDb, state::WorldState};

use lemma_vm::parallel::mvstate::{StateKey, StateValue};

use crate::{
    block_exec::{apply_writes, execute_committed_block, MAX_TXS_PER_BLOCK},
    genesis_boot::init_chain,
};

// ── Fixtures ──────────────────────────────────────────────────────────────────

const CHAIN_ID: u64 = 1;

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn dummy_consensus_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32])
}

/// Build a minimal GenesisConfig that pre-funds `accounts`.
fn make_genesis(accounts: &[(Address, Amount)]) -> GenesisConfig {
    let proposer = addr(1);
    let validator = Validator {
        address: proposer,
        consensus_pubkey: dummy_consensus_key(),
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

    let mut initial_balances = BTreeMap::new();
    for (address, balance) in accounts {
        initial_balances.insert(*address, *balance);
    }

    GenesisConfig {
        chain_id: CHAIN_ID,
        genesis_timestamp: 1_000_000,
        initial_gas_limit: 30_000_000,
        initial_base_fee: Amount::from_drop(1_000_000_000),
        initial_balances,
        genesis_validators,
    }
}

/// Boot a chain and return (Arc<LemmaDb>, genesis_block, TempDir).
fn boot_chain(accounts: &[(Address, Amount)]) -> (Arc<LemmaDb>, Block, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let genesis = make_genesis(accounts);
    init_chain(LemmaDb::open(dir.path()).expect("LemmaDb::open"), &genesis).expect("init_chain");
    let db = Arc::new(LemmaDb::open(dir.path()).expect("reopen"));
    let chain = lemma_storage::ChainStore::new(&db);
    let genesis_block = chain
        .get_block_by_height(0)
        .expect("get_block_by_height")
        .expect("genesis block");
    (db, genesis_block, dir)
}

/// Build a minimal Commit at `index` / `leader_round`.
fn make_commit(index: u64, leader_round: u64) -> Commit {
    let leader = DagBlockRef::new(leader_round, addr(1), Hash::from_bytes([index as u8; 32]));
    Commit {
        index,
        previous_digest: Hash::zero(),
        timestamp_ms: 2_000_000_000, // 2_000_000 s >> genesis 1_000_000 s → no clamp
        leader,
        blocks: vec![leader],
    }
}

// ── execute_committed_block — empty txs ───────────────────────────────────────

#[test]
fn empty_txs_preserves_parent_state_root() {
    // Arrange: chain with one funded account.
    let (db, genesis, _dir) = boot_chain(&[(addr(10), Amount::from_drop(5_000))]);
    let commit = make_commit(1, 3);

    // Act: execute with no txs.
    let out = execute_committed_block(vec![], &genesis, &commit, addr(1), db)
        .expect("execute_committed_block");

    // Assert: state_root unchanged when no writes occurred.
    assert_eq!(
        out.state_root, genesis.header.state_root,
        "empty tx block must preserve parent state_root"
    );
}

#[test]
fn empty_txs_produces_zero_roots_and_gas() {
    let (db, genesis, _dir) = boot_chain(&[]);
    let commit = make_commit(1, 3);

    let out = execute_committed_block(vec![], &genesis, &commit, addr(1), db)
        .expect("execute_committed_block");

    assert_eq!(out.transactions_root, Hash::zero());
    assert_eq!(out.receipts_root, Hash::zero());
    assert_eq!(out.gas_used, 0);
    assert!(out.txs.is_empty());
    assert!(out.receipts.is_empty());
}

// ── execute_committed_block — Transfer tx ─────────────────────────────────────

/// Build and sign a Transfer transaction from `sender_kp` to `recipient`.
fn make_signed_transfer(
    sender_kp: &KeyPair,
    recipient: Address,
    value: Amount,
    nonce: u64,
    gas_price: Amount,
) -> lemma_core::transaction::Transaction {
    use lemma_core::transaction::{Transaction, TxType};

    // sign_transaction mutates the tx in-place: sets the hash + Signature::Hybrid.
    let mut tx = Transaction::new(
        Hash::zero(), // hash will be set by sign_transaction
        *sender_kp.address(),
        Some(recipient),
        nonce,
        CHAIN_ID,
        value,
        100_000, // gas_limit
        gas_price,
        TxType::Transfer,
        vec![],
        lemma_core::signature::Signature::Unsigned,
    )
    .expect("Transaction::new");

    sign_transaction(&mut tx, sender_kp).expect("sign_transaction");
    tx
}

/// Admit a signed transaction into the mempool via the production admit path.
///
/// Uses `base_fee = Amount::zero()` in the `AdmitContext` so tests don't need
/// the sender to hold 100+ LEM just to cover gas costs (test isolation).
fn admit_to_mempool(
    pool: &mut Mempool,
    tx: lemma_core::transaction::Transaction,
    sender_kp: &KeyPair,
    world: &WorldState,
) {
    use lemma_mempool::express::ExpressHint;

    let ctx = AdmitContext {
        chain_id: CHAIN_ID,
        base_fee: Amount::zero(), // zero base_fee for test isolation
        now: std::time::Instant::now(),
    };
    let pubkey = sender_kp.public_key();
    let _ = pool
        .admit(
            tx,
            &pubkey,
            Amount::zero(), // no staking in Phase 2
            None::<&ExpressHint>,
            world,
            &ctx,
        )
        .expect("Mempool::admit must accept a valid transfer");
}

#[test]
fn transfer_tx_updates_balances_and_advances_nonce() {
    // Arrange: sender starts with 10_000 Drop, recipient starts at 0.
    let sender_kp = KeyPair::generate().expect("KeyPair");
    let sender = *sender_kp.address();
    let recipient = addr(0xBB);

    // Give sender enough balance for both the value (1_000 Drop) and gas.
    let (db, genesis, _dir) = boot_chain(&[(sender, Amount::from_drop(100_000))]);

    // Admit the tx with zero gas_price (test isolation: avoid large gas cost).
    let tx = make_signed_transfer(
        &sender_kp,
        recipient,
        Amount::from_drop(1_000), // transfer 1_000 Drop
        0,                        // nonce 0
        Amount::zero(),           // gas_price=0 (base_fee also 0 in AdmitContext)
    );
    let mut pool = Mempool::new(100);
    {
        let world = WorldState::with_state_root(Arc::clone(&db), genesis.header.state_root);
        admit_to_mempool(&mut pool, tx, &sender_kp, &world);
    }

    let txs = pool
        .pending_by_priority(MAX_TXS_PER_BLOCK)
        .into_iter()
        .cloned()
        .collect();
    let commit = make_commit(1, 3);

    // Act: execute the block.
    let out = execute_committed_block(txs, &genesis, &commit, addr(1), Arc::clone(&db))
        .expect("execute_committed_block");

    // Assert: state_root changed (writes occurred).
    assert_ne!(
        out.state_root, genesis.header.state_root,
        "state_root must change after a Transfer"
    );

    // Assert: new world state reflects the transfer.
    let new_ws = WorldState::with_state_root(db, out.state_root);
    let sender_acct = new_ws
        .get_account(&sender)
        .expect("get_account")
        .expect("sender must exist");
    let recipient_acct = new_ws
        .get_account(&recipient)
        .expect("get_account")
        .expect("recipient must exist after receiving funds");

    // Sender balance reduced by transfer value + gas (gas <= gas_limit).
    assert!(
        sender_acct.balance < Amount::from_drop(100_000),
        "sender balance must decrease after transfer"
    );
    // Recipient received 1_000 Drop.
    assert_eq!(
        recipient_acct.balance,
        Amount::from_drop(1_000),
        "recipient must receive exact transfer value"
    );
    // Sender nonce advanced.
    assert_eq!(sender_acct.nonce, 1, "sender nonce must be 1 after one tx");
}

#[test]
fn transfer_tx_produces_receipt_and_non_zero_roots() {
    let sender_kp = KeyPair::generate().expect("KeyPair");
    let sender = *sender_kp.address();
    let (db, genesis, _dir) = boot_chain(&[(sender, Amount::from_drop(100_000))]);

    let tx = make_signed_transfer(
        &sender_kp,
        addr(0xCC),
        Amount::from_drop(100),
        0,
        Amount::zero(),
    );
    let mut pool = Mempool::new(100);
    {
        let world = WorldState::with_state_root(Arc::clone(&db), genesis.header.state_root);
        admit_to_mempool(&mut pool, tx, &sender_kp, &world);
    }
    let txs = pool
        .pending_by_priority(MAX_TXS_PER_BLOCK)
        .into_iter()
        .cloned()
        .collect();
    let commit = make_commit(1, 3);

    let out = execute_committed_block(txs, &genesis, &commit, addr(1), db)
        .expect("execute_committed_block");

    assert_eq!(out.receipts.len(), 1, "one receipt per tx");
    assert!(out.receipts[0].success, "Transfer must succeed");
    assert!(out.gas_used > 0, "gas_used must be > 0 for an executed tx");
    assert_ne!(
        out.transactions_root,
        Hash::zero(),
        "non-empty tx set → non-zero root"
    );
    assert_ne!(
        out.receipts_root,
        Hash::zero(),
        "non-empty receipts → non-zero root"
    );
}

// ── Determinism oracle ────────────────────────────────────────────────────────

#[test]
fn same_txs_produce_identical_state_root() {
    // Run execute_committed_block twice with identical inputs; roots must match.
    let sender_kp = KeyPair::generate().expect("KeyPair");
    let sender = *sender_kp.address();

    let (db1, genesis1, _dir1) = boot_chain(&[(sender, Amount::from_drop(100_000))]);
    let (db2, genesis2, _dir2) = boot_chain(&[(sender, Amount::from_drop(100_000))]);

    // Identical genesis → identical state_roots.
    assert_eq!(
        genesis1.header.state_root, genesis2.header.state_root,
        "identical genesis configs must produce identical state_root"
    );

    let tx = make_signed_transfer(
        &sender_kp,
        addr(0xDD),
        Amount::from_drop(500),
        0,
        Amount::zero(),
    );

    let make_txs = |world: WorldState, kp: &KeyPair, pool_db: Arc<LemmaDb>| {
        let _ = pool_db; // keep alive
        let mut pool = Mempool::new(100);
        admit_to_mempool(&mut pool, tx.clone(), kp, &world);
        pool.pending_by_priority(MAX_TXS_PER_BLOCK)
            .into_iter()
            .cloned()
            .collect::<Vec<_>>()
    };

    let world1 = WorldState::with_state_root(Arc::clone(&db1), genesis1.header.state_root);
    let txs1 = make_txs(world1, &sender_kp, Arc::clone(&db1));

    let world2 = WorldState::with_state_root(Arc::clone(&db2), genesis2.header.state_root);
    let txs2 = make_txs(world2, &sender_kp, Arc::clone(&db2));

    let commit = make_commit(1, 3);
    let out1 = execute_committed_block(txs1, &genesis1, &commit, addr(1), Arc::clone(&db1))
        .expect("run 1");
    let out2 = execute_committed_block(txs2, &genesis2, &commit, addr(1), Arc::clone(&db2))
        .expect("run 2");

    assert_eq!(
        out1.state_root, out2.state_root,
        "determinism oracle: same inputs must produce identical state_root"
    );
    assert_eq!(
        out1.transactions_root, out2.transactions_root,
        "determinism: transactions_root must be identical"
    );
    assert_eq!(
        out1.gas_used, out2.gas_used,
        "determinism: gas_used must be identical"
    );
}

// ── apply_writes — Storage → state_root commitment (P3·Step 22) ──────────────

/// Helper: set up a contract account (with code) via apply_writes, returning
/// the resulting state_root. Reused by multiple storage tests (AGENTS §2.6).
fn deploy_contract(db: &Arc<LemmaDb>, base_root: Hash, contract: Address) -> Hash {
    let bytecode = b"(module)".to_vec();
    let code_hash = lemma_crypto::hash_bytes(&bytecode);

    let mut writes = BTreeMap::new();
    writes.insert(StateKey::Code(contract), StateValue::Code(Some(bytecode)));
    // Set a non-zero balance so the account is fully populated.
    writes.insert(
        StateKey::Balance(contract),
        StateValue::Balance(Amount::from_drop(1)),
    );

    let root = apply_writes(Arc::clone(db), base_root, &writes).expect("deploy_contract");

    // Sanity: the deployed account has the expected code_hash.
    let world = WorldState::with_state_root(Arc::clone(db), root);
    let acct = world
        .get_account(&contract)
        .expect("get_account")
        .expect("contract must exist after deploy");
    assert_eq!(
        acct.code_hash, code_hash,
        "code_hash must match deployed bytecode"
    );

    root
}

#[test]
fn storage_write_changes_state_root() {
    // Arrange: deploy a contract, then apply a storage write.
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(LemmaDb::open(dir.path()).expect("LemmaDb::open"));
    let contract = addr(0xAA);

    let base_root = deploy_contract(&db, Hash::zero(), contract);

    // Act: apply a storage write for the contract.
    let mut writes = BTreeMap::new();
    writes.insert(
        StateKey::Storage {
            contract,
            key: b"slot_0".to_vec(),
        },
        StateValue::Storage(Some(b"value_0".to_vec())),
    );
    let new_root = apply_writes(Arc::clone(&db), base_root, &writes).expect("apply_writes");

    // Assert: state_root changed — storage write is reflected in the commitment.
    assert_ne!(
        new_root, base_root,
        "state_root must change after a storage write (storage contributes to state_root)"
    );
}

#[test]
fn storage_write_determinism() {
    // Arrange: two independent DB instances, same contract + storage writes.
    let dir1 = TempDir::new().expect("tempdir1");
    let dir2 = TempDir::new().expect("tempdir2");
    let db1 = Arc::new(LemmaDb::open(dir1.path()).expect("LemmaDb::open"));
    let db2 = Arc::new(LemmaDb::open(dir2.path()).expect("LemmaDb::open"));
    let contract = addr(0xBB);

    let base1 = deploy_contract(&db1, Hash::zero(), contract);
    let base2 = deploy_contract(&db2, Hash::zero(), contract);
    assert_eq!(
        base1, base2,
        "identical deploys must produce identical roots"
    );

    // Act: apply the same storage writes to both.
    let mut writes = BTreeMap::new();
    writes.insert(
        StateKey::Storage {
            contract,
            key: b"key_a".to_vec(),
        },
        StateValue::Storage(Some(b"val_a".to_vec())),
    );
    writes.insert(
        StateKey::Storage {
            contract,
            key: b"key_b".to_vec(),
        },
        StateValue::Storage(Some(b"val_b".to_vec())),
    );

    let root1 = apply_writes(Arc::clone(&db1), base1, &writes).expect("apply_writes db1");
    let root2 = apply_writes(Arc::clone(&db2), base2, &writes).expect("apply_writes db2");

    // Assert: both produce the same state_root.
    assert_eq!(
        root1, root2,
        "determinism: same storage writes must produce identical state_root"
    );
}

#[test]
fn empty_storage_contract_has_zero_storage_root() {
    // Arrange: deploy a contract with code but NO storage writes.
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(LemmaDb::open(dir.path()).expect("LemmaDb::open"));
    let contract = addr(0xCC);

    let root = deploy_contract(&db, Hash::zero(), contract);

    // Assert: Account.storage_root is Hash::zero() (no storage trie created).
    let world = WorldState::with_state_root(db, root);
    let acct = world
        .get_account(&contract)
        .expect("get_account")
        .expect("contract must exist");
    assert_eq!(
        acct.storage_root,
        Hash::zero(),
        "contract with no storage writes must have storage_root == Hash::zero()"
    );
}

#[test]
fn storage_write_updates_account_storage_root() {
    // Arrange: deploy a contract, then apply a storage write.
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(LemmaDb::open(dir.path()).expect("LemmaDb::open"));
    let contract = addr(0xDD);

    let base_root = deploy_contract(&db, Hash::zero(), contract);

    // Act: apply a storage write.
    let mut writes = BTreeMap::new();
    writes.insert(
        StateKey::Storage {
            contract,
            key: b"my_slot".to_vec(),
        },
        StateValue::Storage(Some(b"my_value".to_vec())),
    );
    let new_root = apply_writes(Arc::clone(&db), base_root, &writes).expect("apply_writes");

    // Assert: Account.storage_root is now non-zero.
    let world = WorldState::with_state_root(db, new_root);
    let acct = world
        .get_account(&contract)
        .expect("get_account")
        .expect("contract must exist after storage write");
    assert_ne!(
        acct.storage_root,
        Hash::zero(),
        "Account.storage_root must be non-zero after a storage write"
    );
}

// ── Storage deletion tests (CR-W5: cover the tombstone path) ─────────────

#[test]
fn storage_delete_is_deterministic() {
    // Write a slot then delete it on two independent DBs — roots must match.
    let make_root = || {
        let dir = TempDir::new().expect("tempdir");
        let db = Arc::new(LemmaDb::open(dir.path()).expect("LemmaDb::open"));
        let contract = addr(0xE1);

        let base = deploy_contract(&db, Hash::zero(), contract);

        // Write a slot.
        let mut w1 = BTreeMap::new();
        w1.insert(
            StateKey::Storage {
                contract,
                key: b"slot_a".to_vec(),
            },
            StateValue::Storage(Some(b"value_a".to_vec())),
        );
        let after_write = apply_writes(Arc::clone(&db), base, &w1).expect("write");

        // Delete the same slot.
        let mut w2 = BTreeMap::new();
        w2.insert(
            StateKey::Storage {
                contract,
                key: b"slot_a".to_vec(),
            },
            StateValue::Storage(None),
        );
        apply_writes(Arc::clone(&db), after_write, &w2).expect("delete")
    };

    let root_a = make_root();
    let root_b = make_root();
    assert_eq!(
        root_a, root_b,
        "storage write+delete must produce identical state_root across DBs"
    );
}

#[test]
fn storage_delete_then_rewrite_changes_root() {
    // Write slot → delete slot → rewrite slot with different value.
    // The final root should differ from the after-first-write root
    // (different value in the slot).
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(LemmaDb::open(dir.path()).expect("LemmaDb::open"));
    let contract = addr(0xE2);

    let base = deploy_contract(&db, Hash::zero(), contract);

    // Step 1: write "slot_x" = "val_1".
    let mut w1 = BTreeMap::new();
    w1.insert(
        StateKey::Storage {
            contract,
            key: b"slot_x".to_vec(),
        },
        StateValue::Storage(Some(b"val_1".to_vec())),
    );
    let root_after_write = apply_writes(Arc::clone(&db), base, &w1).expect("write");

    // Step 2: delete "slot_x".
    let mut w2 = BTreeMap::new();
    w2.insert(
        StateKey::Storage {
            contract,
            key: b"slot_x".to_vec(),
        },
        StateValue::Storage(None),
    );
    let root_after_delete = apply_writes(Arc::clone(&db), root_after_write, &w2).expect("delete");

    // Delete must change the root (tombstone differs from "val_1").
    assert_ne!(
        root_after_write, root_after_delete,
        "deleting a storage slot must change state_root"
    );

    // Step 3: rewrite "slot_x" = "val_2".
    let mut w3 = BTreeMap::new();
    w3.insert(
        StateKey::Storage {
            contract,
            key: b"slot_x".to_vec(),
        },
        StateValue::Storage(Some(b"val_2".to_vec())),
    );
    let root_after_rewrite =
        apply_writes(Arc::clone(&db), root_after_delete, &w3).expect("rewrite");

    // Rewrite must differ from both delete and original write (different value).
    assert_ne!(
        root_after_rewrite, root_after_delete,
        "rewriting a deleted slot must change state_root"
    );
    assert_ne!(
        root_after_rewrite, root_after_write,
        "rewriting with different value must produce different state_root"
    );
}
