//! Tests for [`genesis_boot`].
//!
//! Covers: happy path, idempotency, empty-balances devnet, invalid config,
//! persistence of block + metadata, and validator-set hash determinism.

use std::{collections::BTreeMap, sync::Arc};

use tempfile::TempDir;

use lemma_core::{
    address::Address,
    amount::{Amount, DROPS_PER_LEM},
    genesis::GenesisConfig,
    hash::Hash,
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus},
    validator_set::ValidatorSet,
};
use lemma_storage::{db::LemmaDb, state::WorldState};

use super::*;

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Open a fresh [`LemmaDb`] in a temporary directory.
/// The [`TempDir`] must be kept alive for the lifetime of the test.
fn open_temp_db() -> (LemmaDb, TempDir) {
    let dir = TempDir::new().expect("TempDir::new must succeed");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed on temp dir");
    (db, dir)
}

/// Deterministic test address derived from a single distinguishing byte.
fn addr(byte: u8) -> Address {
    Address::from_public_key(&[byte; 32])
}

/// 20 000 000 LEM in Drop — the minimum genesis validator stake.
fn validator_stake_drop() -> Amount {
    Amount::from_drop(20_000_000 * DROPS_PER_LEM)
}

/// A genesis-ready Bonded [`Validator`] with `stake` LEM active self-stake.
fn make_validator(byte: u8, active: Amount) -> Validator {
    Validator {
        address: addr(byte),
        consensus_pubkey: ConsensusKey::from_bytes(vec![byte; 32], vec![byte; 32]),
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active,
            pending_active: Amount::zero(),
            pending_inactive: vec![],
            inactive: Amount::zero(),
        },
        delegated: Amount::zero(),
        commission_bps: 0,
        jailed_until: None,
    }
}

/// A minimal but valid [`GenesisConfig`] with one funded account and
/// one bonded validator.
fn minimal_genesis() -> GenesisConfig {
    let mut initial_balances = BTreeMap::new();
    initial_balances.insert(addr(0x01), Amount::from_drop(1_000 * DROPS_PER_LEM));

    let mut genesis_validators = BTreeMap::new();
    genesis_validators.insert(addr(0xA0), make_validator(0xA0, validator_stake_drop()));

    GenesisConfig {
        chain_id: 1,
        genesis_timestamp: 1_700_000_000,
        initial_gas_limit: 30_000_000,
        initial_base_fee: Amount::from_drop(1_000_000_000), // 1 Drip
        initial_balances,
        genesis_validators,
    }
}

/// A devnet genesis with no pre-funded accounts (valid — faucet funds later).
fn devnet_genesis() -> GenesisConfig {
    let mut genesis_validators = BTreeMap::new();
    genesis_validators.insert(addr(0xB0), make_validator(0xB0, validator_stake_drop()));

    GenesisConfig {
        chain_id: 3,
        genesis_timestamp: 0,
        initial_gas_limit: 10_000_000,
        initial_base_fee: Amount::zero(),
        initial_balances: BTreeMap::new(),
        genesis_validators,
    }
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[test]
fn init_chain_returns_initialized_with_correct_account_count() {
    let (db, _dir) = open_temp_db();
    let genesis = minimal_genesis();

    let outcome = init_chain(db, &genesis).expect("init_chain must succeed");

    assert!(
        matches!(outcome, InitOutcome::Initialized { accounts: 1, .. }),
        "expected Initialized {{ accounts: 1 }}, got {outcome:?}",
    );
}

#[test]
fn init_chain_persists_genesis_block_at_height_0() {
    let (db, dir) = open_temp_db();
    let genesis = minimal_genesis();

    let InitOutcome::Initialized { genesis_hash, .. } =
        init_chain(db, &genesis).expect("init_chain must succeed")
    else {
        panic!("expected Initialized");
    };

    // Re-open the same DB and verify the block is there by height.
    let db2 = LemmaDb::open(dir.path()).expect("re-open must succeed");
    let block_bytes = db2
        .get(lemma_storage::db::CF_BLOCKS, &0u64.to_be_bytes())
        .expect("get CF_BLOCKS must succeed")
        .expect("genesis block must be present at height 0");
    assert!(!block_bytes.is_empty());

    // Also verify by hash.
    let by_hash = db2
        .get(lemma_storage::db::CF_BLOCK_HASH, genesis_hash.as_bytes())
        .expect("get CF_BLOCK_HASH must succeed")
        .expect("genesis block must be present by hash");
    assert_eq!(
        block_bytes, by_hash,
        "block stored by height and hash must be identical"
    );
}

#[test]
fn init_chain_writes_latest_height_and_hash_metadata() {
    let (db, dir) = open_temp_db();
    let genesis = minimal_genesis();

    let InitOutcome::Initialized { genesis_hash, .. } =
        init_chain(db, &genesis).expect("init_chain must succeed")
    else {
        panic!("expected Initialized");
    };

    let db2 = LemmaDb::open(dir.path()).expect("re-open must succeed");

    // latest_height == 0 encoded as u64 BE.
    let height_bytes = db2
        .get(lemma_storage::db::CF_METADATA, b"latest_height")
        .expect("get metadata must succeed")
        .expect("latest_height must be present");
    let height = u64::from_be_bytes(height_bytes.try_into().expect("8 bytes"));
    assert_eq!(height, 0);

    // latest_hash == genesis_hash.
    let hash_bytes = db2
        .get(lemma_storage::db::CF_METADATA, b"latest_hash")
        .expect("get metadata must succeed")
        .expect("latest_hash must be present");
    assert_eq!(hash_bytes.as_slice(), genesis_hash.as_bytes());
}

#[test]
fn init_chain_credits_genesis_balance_to_state_trie() {
    let (db, dir) = open_temp_db();
    let genesis = minimal_genesis();

    init_chain(db, &genesis).expect("init_chain must succeed");

    // Re-open and verify account balance via WorldState.
    let db2 = LemmaDb::open(dir.path()).expect("re-open must succeed");

    // Read the state_root from the persisted genesis block header.
    let block_bytes = db2
        .get(lemma_storage::db::CF_BLOCKS, &0u64.to_be_bytes())
        .expect("get CF_BLOCKS must succeed")
        .expect("genesis block must exist");
    // serde_json is used (not bincode) — see chain.rs serialization note.
    let block: lemma_core::block::Block =
        serde_json::from_slice(&block_bytes).expect("block deserialise must succeed");
    let state_root = block.header.state_root;

    let ws = WorldState::with_state_root(Arc::new(db2), state_root);
    let balance = ws
        .get_balance(&addr(0x01))
        .expect("get_balance must succeed");
    assert_eq!(balance, Amount::from_drop(1_000 * DROPS_PER_LEM));
}

// ── Idempotency ───────────────────────────────────────────────────────────────

#[test]
fn init_chain_is_idempotent_second_call_returns_already_initialized() {
    let (db, dir) = open_temp_db();
    let genesis = minimal_genesis();

    init_chain(db, &genesis).expect("first init must succeed");

    // Second call on the same DB path.
    let db2 = LemmaDb::open(dir.path()).expect("re-open must succeed");
    let outcome = init_chain(db2, &genesis).expect("second init must not error");

    assert!(
        matches!(outcome, InitOutcome::AlreadyInitialized { height: 0 }),
        "expected AlreadyInitialized {{ height: 0 }}, got {outcome:?}",
    );
}

#[test]
fn init_chain_idempotent_does_not_overwrite_existing_state() {
    let (db, dir) = open_temp_db();
    let genesis = minimal_genesis();

    let InitOutcome::Initialized {
        genesis_hash: hash1,
        ..
    } = init_chain(db, &genesis).expect("first init must succeed")
    else {
        panic!("expected Initialized");
    };

    // Second call — state must not change.
    let db2 = LemmaDb::open(dir.path()).expect("re-open must succeed");
    init_chain(db2, &genesis).expect("second init must not error");

    // The genesis block at height 0 must still have the original hash.
    let db3 = LemmaDb::open(dir.path()).expect("re-open must succeed");
    let hash_bytes = db3
        .get(lemma_storage::db::CF_METADATA, b"latest_hash")
        .expect("get metadata must succeed")
        .expect("latest_hash must still be present");
    assert_eq!(
        hash_bytes.as_slice(),
        hash1.as_bytes(),
        "hash must be unchanged"
    );
}

// ── Devnet (empty balances) ───────────────────────────────────────────────────

#[test]
fn init_chain_handles_empty_initial_balances_devnet() {
    let (db, _dir) = open_temp_db();
    let genesis = devnet_genesis();

    let outcome = init_chain(db, &genesis).expect("devnet init must succeed");

    // Zero accounts, genesis block still created.
    assert!(
        matches!(outcome, InitOutcome::Initialized { accounts: 0, .. }),
        "expected Initialized {{ accounts: 0 }}, got {outcome:?}",
    );
}

#[test]
fn init_chain_devnet_genesis_block_has_nonzero_state_root() {
    // Since DB-A54 (step 4b in genesis_boot.rs), init_chain always writes
    // the native_lem and registry system accounts, so the state root is
    // non-zero even when initial_balances is empty. The old assertion
    // (state_root.is_zero()) was correct before system accounts were added;
    // this test now verifies the updated invariant.
    let (db, dir) = open_temp_db();
    init_chain(db, &devnet_genesis()).expect("devnet init must succeed");

    let db2 = LemmaDb::open(dir.path()).expect("re-open must succeed");
    let block_bytes = db2
        .get(lemma_storage::db::CF_BLOCKS, &0u64.to_be_bytes())
        .expect("get CF_BLOCKS must succeed")
        .expect("genesis block must exist");
    // serde_json is used (not bincode) — see chain.rs serialization note.
    let block: lemma_core::block::Block =
        serde_json::from_slice(&block_bytes).expect("block deserialise must succeed");
    assert!(
        !block.header.state_root.is_zero(),
        "genesis with system accounts must have non-zero state_root (DB-A54)",
    );
}

// ── Invalid config ────────────────────────────────────────────────────────────

#[test]
fn init_chain_rejects_zero_gas_limit() {
    let (db, _dir) = open_temp_db();
    let mut genesis = minimal_genesis();
    genesis.initial_gas_limit = 0;

    let err = init_chain(db, &genesis).expect_err("zero gas_limit must error");
    assert!(matches!(err, NodeError::Core(_)), "got: {err:?}");
}

#[test]
fn init_chain_rejects_empty_validator_set() {
    let (db, _dir) = open_temp_db();
    let mut genesis = minimal_genesis();
    genesis.genesis_validators.clear();

    let err = init_chain(db, &genesis).expect_err("empty validators must error");
    assert!(matches!(err, NodeError::Core(_)), "got: {err:?}");
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn init_chain_same_genesis_produces_same_hash_across_two_dbs() {
    let genesis = minimal_genesis();

    let (db_a, _dir_a) = open_temp_db();
    let outcome_a = init_chain(db_a, &genesis).expect("init A must succeed");

    let (db_b, _dir_b) = open_temp_db();
    let outcome_b = init_chain(db_b, &genesis).expect("init B must succeed");

    let (hash_a, hash_b) = match (outcome_a, outcome_b) {
        (
            InitOutcome::Initialized {
                genesis_hash: h_a, ..
            },
            InitOutcome::Initialized {
                genesis_hash: h_b, ..
            },
        ) => (h_a, h_b),
        _ => panic!("both must be Initialized"),
    };

    assert_eq!(
        hash_a, hash_b,
        "same genesis must produce identical hash on every node"
    );
}

// ── ValidatorSet::from_active_validators (canonical constructor) ───────────────

#[test]
fn from_active_validators_computes_correct_total_power() {
    // Two active validators with known stake.
    let mut validators = BTreeMap::new();
    validators.insert(addr(0x01), make_validator(0x01, Amount::from_drop(100)));
    validators.insert(addr(0x02), make_validator(0x02, Amount::from_drop(200)));

    let vset = ValidatorSet::from_active_validators(0, &validators)
        .expect("active validators must build without error");

    assert_eq!(vset.total_power, Amount::from_drop(300));
    assert_eq!(vset.members.len(), 2);
    assert_eq!(vset.epoch, 0);
}

#[test]
fn from_active_validators_is_deterministic() {
    // Insert in different orders — BTreeMap reorders by Address, so the output
    // hash must be identical regardless of insertion order (AGENTS §7.1).
    let mut v1 = BTreeMap::new();
    v1.insert(addr(0x02), make_validator(0x02, Amount::from_drop(200)));
    v1.insert(addr(0x01), make_validator(0x01, Amount::from_drop(100)));

    let mut v2 = BTreeMap::new();
    v2.insert(addr(0x01), make_validator(0x01, Amount::from_drop(100)));
    v2.insert(addr(0x02), make_validator(0x02, Amount::from_drop(200)));

    let set1 = ValidatorSet::from_active_validators(0, &v1).expect("v1 must build");
    let set2 = ValidatorSet::from_active_validators(0, &v2).expect("v2 must build");

    assert_eq!(
        set1.hash(),
        set2.hash(),
        "validator set hash must be order-independent"
    );
}

#[test]
fn from_active_validators_excludes_inactive_validators() {
    use lemma_core::validator::ValidatorStatus;
    let mut validators = BTreeMap::new();
    // Active validator.
    validators.insert(addr(0x01), make_validator(0x01, Amount::from_drop(100)));
    // Inactive validator (Unbonded).
    let mut inactive = make_validator(0x02, Amount::from_drop(200));
    inactive.status = ValidatorStatus::Unbonded;
    validators.insert(addr(0x02), inactive);

    let vset = ValidatorSet::from_active_validators(0, &validators)
        .expect("at least one active validator");

    // Only the Bonded validator should be included.
    assert_eq!(vset.members.len(), 1);
    assert_eq!(vset.total_power, Amount::from_drop(100));
}

#[test]
fn from_active_validators_errors_on_empty_active_set() {
    let mut validators = BTreeMap::new();
    let mut inactive = make_validator(0x01, Amount::from_drop(100));
    inactive.status = lemma_core::validator::ValidatorStatus::Unbonded;
    validators.insert(addr(0x01), inactive);

    let err = ValidatorSet::from_active_validators(0, &validators)
        .expect_err("empty active set must error");
    assert!(matches!(
        err,
        lemma_core::error::CoreError::Validator(
            lemma_core::error::ValidatorError::EmptyValidatorSet { .. }
        )
    ));
}

// ── System contract accounts (DB-A54) ─────────────────────────────────────────

/// Helper: read the state trie from a persisted genesis DB and return the
/// [`WorldState`] rooted at the genesis block's `state_root`.
fn open_genesis_state(dir: &tempfile::TempDir) -> WorldState {
    let db2 = LemmaDb::open(dir.path()).expect("re-open must succeed");
    let block_bytes = db2
        .get(lemma_storage::db::CF_BLOCKS, &0u64.to_be_bytes())
        .expect("get CF_BLOCKS must succeed")
        .expect("genesis block must exist");
    let block: lemma_core::block::Block =
        serde_json::from_slice(&block_bytes).expect("block deserialise must succeed");
    WorldState::with_state_root(Arc::new(db2), block.header.state_root)
}

#[test]
fn init_chain_creates_native_lem_system_account_at_genesis() {
    let (db, dir) = open_temp_db();
    init_chain(db, &minimal_genesis()).expect("init_chain must succeed");

    let ws = open_genesis_state(&dir);
    let account = ws
        .get_account(&Address::native_lem())
        .expect("get_account must succeed")
        .expect("native_lem system account must exist after genesis");

    // Protocol-level account: no bytecode, no balance, nonce 0 (DB-A54).
    assert_eq!(
        account.code_hash,
        Hash::zero(),
        "native_lem must have code_hash = Hash::zero()"
    );
    assert!(
        account.balance.is_zero(),
        "native_lem must have zero balance at genesis"
    );
    assert_eq!(account.nonce, 0, "native_lem must have nonce 0 at genesis");
}

#[test]
fn init_chain_creates_registry_system_account_at_genesis() {
    let (db, dir) = open_temp_db();
    init_chain(db, &minimal_genesis()).expect("init_chain must succeed");

    let ws = open_genesis_state(&dir);
    let account = ws
        .get_account(&Address::registry())
        .expect("get_account must succeed")
        .expect("registry system account must exist after genesis");

    // Protocol-level account: no bytecode, no balance, nonce 0 (DB-A54).
    assert_eq!(
        account.code_hash,
        Hash::zero(),
        "registry must have code_hash = Hash::zero()"
    );
    assert!(
        account.balance.is_zero(),
        "registry must have zero balance at genesis"
    );
    assert_eq!(account.nonce, 0, "registry must have nonce 0 at genesis");
}

#[test]
fn init_chain_system_accounts_do_not_affect_user_account_count() {
    // The `accounts` field in InitOutcome::Initialized counts only user
    // allocations from initial_balances — not protocol system accounts.
    let (db, _dir) = open_temp_db();
    let genesis = minimal_genesis(); // 1 user account

    let outcome = init_chain(db, &genesis).expect("init_chain must succeed");

    assert!(
        matches!(outcome, InitOutcome::Initialized { accounts: 1, .. }),
        "system accounts must not inflate the user account count; got {outcome:?}",
    );
}

#[test]
fn init_chain_system_accounts_present_on_devnet_empty_balances() {
    // Even with no user accounts, system contracts must be written.
    let (db, dir) = open_temp_db();
    init_chain(db, &devnet_genesis()).expect("devnet init must succeed");

    let ws = open_genesis_state(&dir);
    assert!(
        ws.get_account(&Address::native_lem())
            .expect("get_account must succeed")
            .is_some(),
        "native_lem must exist even on devnet with no user accounts",
    );
    assert!(
        ws.get_account(&Address::registry())
            .expect("get_account must succeed")
            .is_some(),
        "registry must exist even on devnet with no user accounts",
    );
}
