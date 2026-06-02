//! Integration tests: wallet round-trip + balance query.
//!
//! ## Phase 1 "Integration test: send TX" milestone
//!
//! The 04-BUILD_GUIDE milestone "Integration test: send TX" is deferred:
//! VM execution (Phase 2) is required to process transactions.
//! RPC endpoint (Phase 4) is required to submit transactions.
//! Neither exists in Phase 1.
//!
//! These tests cover what IS available in Phase 1:
//! - Wallet generation and keystore round-trip (address stability across save/reload).
//! - Balance query from a seeded chain database.
//!
//! The "send TX" milestone will be closed in Phase 2/4 with a real tx e2e test
//! exercising `lem_sendTransaction` → mempool admit → VM execution → receipt.

use std::collections::BTreeMap;

use tempfile::TempDir;

use lemma_core::{
    address::{Address, AddressType, HRP_DEVNET},
    amount::{Amount, DROPS_PER_LEM},
    genesis::GenesisConfig,
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus},
};
use lemma_crypto::{KeyPair, KEYSTORE_BYTE_LEN};
use lemma_node::{init_chain, InitOutcome};
use lemma_storage::db::LemmaDb;

// ── wallet round-trip ─────────────────────────────────────────────────────────

/// Generate a keypair, save to disk, reload, verify address is stable.
#[test]
fn wallet_new_and_reload_produces_stable_address() {
    let dir = TempDir::new().expect("TempDir");

    let kp      = KeyPair::generate().expect("generate");
    let addr1   = *kp.address();
    let ks_path = dir.path().join("test.key");

    std::fs::write(&ks_path, kp.to_keystore_bytes()).expect("write keystore");

    let loaded = std::fs::read(&ks_path).expect("read keystore");
    assert_eq!(loaded.len(), KEYSTORE_BYTE_LEN);

    let kp2 = KeyPair::from_keystore_bytes(&loaded).expect("from_keystore_bytes");
    assert_eq!(kp2.address(), &addr1, "address must be stable after save/reload");
}

/// Address from keystore must encode as valid bech32m with devnet prefix.
#[test]
fn keystore_address_encodes_valid_devnet_bech32m() {
    use lemma_core::Address;

    let kp       = KeyPair::generate().expect("generate");
    let ks_bytes = kp.to_keystore_bytes();
    let kp2      = KeyPair::from_keystore_bytes(&ks_bytes).expect("round-trip");
    let addr_str = kp2.address()
        .to_bech32(HRP_DEVNET, AddressType::Regular)
        .expect("to_bech32");

    assert!(addr_str.starts_with("dlem1q"), "got: {addr_str}");

    let (recovered, _, _) = Address::from_bech32(&addr_str).expect("from_bech32");
    assert_eq!(recovered, *kp2.address());
}

/// Restored keypair produces signatures that verify against the original public key.
#[test]
fn restored_keypair_signs_verifiably() {
    use lemma_crypto::verify;

    let kp1 = KeyPair::generate().expect("generate");
    let pk1 = kp1.public_key();
    let ks  = kp1.to_keystore_bytes();
    let kp2 = KeyPair::from_keystore_bytes(&ks).expect("round-trip");
    let sig = kp2.sign(b"integration test message");

    assert!(
        verify(&pk1, b"integration test message", &sig).is_ok(),
        "signature from restored keypair must verify"
    );
}

// ── balance query ─────────────────────────────────────────────────────────────

/// A minimal bonded validator for genesis (20M LEM active stake).
fn dummy_validator(byte: u8) -> Validator {
    Validator {
        address:        Address::from_public_key(&[byte; 32]),
        consensus_pubkey: ConsensusKey::from_bytes(vec![byte; 32], vec![byte; 32]),
        status:         ValidatorStatus::Bonded,
        tombstoned:     false,
        self_stake: Stake {
            active:           Amount::from_drop(20_000_000 * DROPS_PER_LEM),
            pending_active:   Amount::zero(),
            pending_inactive: vec![],
            inactive:         Amount::zero(),
        },
        delegated:      Amount::zero(),
        commission_bps: 0,
        jailed_until:   None,
    }
}

/// Build a minimal GenesisConfig with one funded account and one validator.
fn make_genesis(address: Address, balance: Amount) -> GenesisConfig {
    let mut initial_balances   = BTreeMap::new();
    let mut genesis_validators = BTreeMap::new();
    initial_balances.insert(address, balance);
    let v = dummy_validator(0xA0);
    genesis_validators.insert(v.address, v);

    GenesisConfig {
        chain_id:           1,
        genesis_timestamp:  1_700_000_000,
        initial_gas_limit:  30_000_000,
        initial_base_fee:   Amount::from_drop(1_000_000_000),
        initial_balances,
        genesis_validators,
    }
}

/// Seed a genesis DB with a known account balance and verify the query path.
#[test]
fn balance_query_returns_genesis_amount() {
    let kp      = KeyPair::generate().expect("keypair");
    let address = *kp.address();
    let balance = Amount::from_lem(100).expect("100 LEM");
    let genesis = make_genesis(address, balance);

    let data_dir = TempDir::new().expect("TempDir");
    let db       = LemmaDb::open(data_dir.path()).expect("LemmaDb");
    let outcome  = init_chain(db, &genesis).expect("init_chain");
    assert!(matches!(outcome, InitOutcome::Initialized { .. }));

    // Reopen and query via storage layer (balance.rs logic is private to the binary).
    let db2 = LemmaDb::open(data_dir.path()).expect("reopen DB");
    use lemma_storage::{ChainStore, WorldState};

    let chain = ChainStore::new(&db2);
    assert!(chain.latest_height().expect("height").is_some(), "chain must be initialised");

    // WorldState::new starts with an empty trie — must resume from the stored
    // genesis block's state_root to see persisted accounts.
    let genesis_block = chain.get_block_by_height(0).expect("get").expect("genesis exists");
    let state_root    = genesis_block.header.state_root;
    let result        = WorldState::with_state_root(db2, state_root)
        .get_balance(&address)
        .expect("get_balance");
    assert_eq!(result, balance, "balance must match genesis allocation");
    assert_eq!(result.to_string(), "100 LEM");
}

/// `balance` command rejects a malformed address string.
///
/// Tests the `LemmaCliError::InvalidAddress` path in `dispatch_balance`.
/// Since `dispatch_balance` is private, we exercise the same underlying logic:
/// `Address::from_bech32` on a garbage string.
#[test]
fn balance_rejects_invalid_address_string() {
    use lemma_core::Address;

    let result = Address::from_bech32("not-a-valid-address");
    assert!(result.is_err(), "garbage address must fail bech32m parse");
    // Verify the error is informative (will surface via LemmaCliError::InvalidAddress).
    let err_msg = result.unwrap_err().to_string();
    assert!(!err_msg.is_empty(), "parse error must have a message");
}

/// Uninitialised DB has no tip — confirmed before any balance query.
#[test]
fn uninitialised_db_has_no_chain_tip() {
    use lemma_storage::ChainStore;

    let data_dir = TempDir::new().expect("TempDir");
    let db       = LemmaDb::open(data_dir.path()).expect("LemmaDb");
    let height   = ChainStore::new(&db).latest_height().expect("height");
    assert!(height.is_none(), "uninitialised DB must have no tip");
}

/// Unknown address has zero balance (account does not exist = 0 LEM).
#[test]
fn unknown_address_has_zero_balance() {
    use lemma_core::Address;
    use lemma_storage::{ChainStore, WorldState};

    let kp      = KeyPair::generate().expect("keypair");
    let address = *kp.address();
    let genesis = make_genesis(address, Amount::from_lem(10).expect("10 LEM"));

    let data_dir = TempDir::new().expect("TempDir");
    let db       = LemmaDb::open(data_dir.path()).expect("LemmaDb");
    init_chain(db, &genesis).expect("init_chain");

    let db2   = LemmaDb::open(data_dir.path()).expect("reopen");
    let chain = ChainStore::new(&db2);
    assert!(chain.latest_height().unwrap().is_some());

    let genesis = chain.get_block_by_height(0).unwrap().unwrap();
    let state   = WorldState::with_state_root(db2, genesis.header.state_root);

    // A completely different (unfunded) address should return 0 LEM.
    let unknown = Address::zero();
    let balance = state.get_balance(&unknown).expect("get_balance");
    assert_eq!(balance, Amount::zero(), "unknown address must have zero balance");
    assert_eq!(balance.to_string(), "0 LEM");
}
