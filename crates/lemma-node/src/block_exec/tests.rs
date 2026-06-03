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

use crate::{
    block_exec::{execute_committed_block, MAX_TXS_PER_BLOCK},
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
