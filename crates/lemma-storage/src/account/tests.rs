//! Tests for `lemma_storage::account`.
//!
//! Covers constructors, predicates, Default impl, Copy semantics,
//! field invariants, and bincode serialization round-trips.
//! 100% public API coverage per AGENTS.md §11.1.

use lemma_core::{Amount, Hash};

use super::*;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn zero_account() -> Account {
    Account::default()
}

fn eoa_with_balance(drops: u128) -> Account {
    Account::new_eoa(Amount::from_drop(drops))
}

fn contract_with_code(code_bytes: [u8; 32]) -> Account {
    Account::new_contract(Hash::from_bytes(code_bytes))
}

fn nonzero_code_hash() -> Hash {
    Hash::from_bytes([0xab; 32])
}

fn nonzero_storage_root() -> Hash {
    Hash::from_bytes([0xcd; 32])
}

// ── new_eoa — field invariants ────────────────────────────────────────────────

#[test]
fn new_eoa_sets_nonce_to_zero() {
    assert_eq!(eoa_with_balance(1_000).nonce, 0);
}

#[test]
fn new_eoa_sets_balance_to_given_amount() {
    let acc = eoa_with_balance(500);
    assert_eq!(acc.balance, Amount::from_drop(500));
}

#[test]
fn new_eoa_sets_code_hash_to_zero() {
    assert_eq!(eoa_with_balance(1).code_hash, Hash::zero());
}

#[test]
fn new_eoa_sets_storage_root_to_zero() {
    assert_eq!(eoa_with_balance(1).storage_root, Hash::zero());
}

#[test]
fn new_eoa_sets_staked_to_zero() {
    assert!(eoa_with_balance(1).staked.is_zero());
}

#[test]
fn new_eoa_with_zero_balance_is_valid() {
    // Zero-balance EOA is legal — newly seen address, no LEM yet.
    let acc = Account::new_eoa(Amount::zero());
    assert!(acc.balance.is_zero());
    assert!(acc.is_eoa());
}

// ── new_contract — field invariants ──────────────────────────────────────────

#[test]
fn new_contract_sets_nonce_to_zero() {
    assert_eq!(contract_with_code([0xab; 32]).nonce, 0);
}

#[test]
fn new_contract_sets_code_hash_to_given_value() {
    let expected = nonzero_code_hash();
    let acc = Account::new_contract(expected);
    assert_eq!(acc.code_hash, expected);
}

#[test]
fn new_contract_sets_balance_to_zero() {
    assert!(contract_with_code([0xab; 32]).balance.is_zero());
}

#[test]
fn new_contract_sets_storage_root_to_zero() {
    // Freshly deployed contract has an empty storage trie.
    assert_eq!(contract_with_code([0xab; 32]).storage_root, Hash::zero());
}

#[test]
fn new_contract_sets_staked_to_zero() {
    assert!(contract_with_code([0xab; 32]).staked.is_zero());
}

// ── is_eoa / is_contract ──────────────────────────────────────────────────────

#[test]
fn new_eoa_is_eoa_returns_true() {
    assert!(eoa_with_balance(1_000).is_eoa());
}

#[test]
fn new_eoa_is_contract_returns_false() {
    assert!(!eoa_with_balance(1_000).is_contract());
}

#[test]
fn new_contract_is_contract_returns_true() {
    assert!(contract_with_code([0xab; 32]).is_contract());
}

#[test]
fn new_contract_is_eoa_returns_false() {
    assert!(!contract_with_code([0xab; 32]).is_eoa());
}

#[test]
fn is_eoa_and_is_contract_are_mutually_exclusive_for_eoa() {
    let acc = eoa_with_balance(0);
    assert_ne!(acc.is_eoa(), acc.is_contract());
}

#[test]
fn is_eoa_and_is_contract_are_mutually_exclusive_for_contract() {
    let acc = contract_with_code([0xaa; 32]);
    assert_ne!(acc.is_eoa(), acc.is_contract());
}

#[test]
fn account_with_zero_code_hash_is_eoa() {
    // Directly constructing with zero code_hash must be recognised as EOA.
    let acc = Account {
        nonce: 5,
        balance: Amount::from_drop(100),
        code_hash: Hash::zero(),
        storage_root: Hash::zero(),
        staked: Amount::zero(),
    };
    assert!(acc.is_eoa());
    assert!(!acc.is_contract());
}

#[test]
fn account_with_nonzero_code_hash_is_contract() {
    let acc = Account {
        nonce: 0,
        balance: Amount::zero(),
        code_hash: nonzero_code_hash(),
        storage_root: Hash::zero(),
        staked: Amount::zero(),
    };
    assert!(acc.is_contract());
    assert!(!acc.is_eoa());
}

// ── is_zero_balance ───────────────────────────────────────────────────────────

#[test]
fn is_zero_balance_returns_true_for_zero_balance() {
    assert!(eoa_with_balance(0).is_zero_balance());
}

#[test]
fn is_zero_balance_returns_false_for_nonzero_balance() {
    assert!(!eoa_with_balance(1).is_zero_balance());
}

#[test]
fn is_zero_balance_does_not_consider_staked_field() {
    // An account with zero liquid balance but nonzero staked is zero_balance.
    let acc = Account {
        nonce: 0,
        balance: Amount::zero(),
        code_hash: Hash::zero(),
        storage_root: Hash::zero(),
        staked: Amount::from_drop(1_000),
    };
    assert!(acc.is_zero_balance());
}

// ── Default ───────────────────────────────────────────────────────────────────

#[test]
fn default_nonce_is_zero() {
    assert_eq!(zero_account().nonce, 0);
}

#[test]
fn default_balance_is_zero() {
    assert!(zero_account().balance.is_zero());
}

#[test]
fn default_code_hash_is_zero() {
    assert_eq!(zero_account().code_hash, Hash::zero());
}

#[test]
fn default_storage_root_is_zero() {
    assert_eq!(zero_account().storage_root, Hash::zero());
}

#[test]
fn default_staked_is_zero() {
    assert!(zero_account().staked.is_zero());
}

#[test]
fn default_account_is_eoa() {
    // The zero-state account is always an EOA (no code deployed yet).
    assert!(zero_account().is_eoa());
}

// ── Copy semantics ────────────────────────────────────────────────────────────

#[test]
fn account_copy_produces_equal_value() {
    let original = eoa_with_balance(42);
    let copied = original; // Copy, not move
    assert_eq!(original, copied);
}

#[test]
fn mutating_copy_does_not_affect_original() {
    let original = eoa_with_balance(100);
    let mut copy = original;
    copy.nonce = 99;
    // original must be unchanged
    assert_eq!(original.nonce, 0);
}

// ── PartialEq ─────────────────────────────────────────────────────────────────

#[test]
fn identical_accounts_are_equal() {
    assert_eq!(eoa_with_balance(1_000), eoa_with_balance(1_000));
}

#[test]
fn accounts_with_different_balance_are_not_equal() {
    assert_ne!(eoa_with_balance(1_000), eoa_with_balance(2_000));
}

#[test]
fn accounts_with_different_nonce_are_not_equal() {
    let a = Account {
        nonce: 1,
        ..eoa_with_balance(100)
    };
    let b = Account {
        nonce: 2,
        ..eoa_with_balance(100)
    };
    assert_ne!(a, b);
}

#[test]
fn accounts_with_different_code_hash_are_not_equal() {
    let a = contract_with_code([0xaa; 32]);
    let b = contract_with_code([0xbb; 32]);
    assert_ne!(a, b);
}

#[test]
fn accounts_with_different_storage_root_are_not_equal() {
    let a = Account {
        storage_root: nonzero_code_hash(),
        ..zero_account()
    };
    let b = Account {
        storage_root: nonzero_storage_root(),
        ..zero_account()
    };
    assert_ne!(a, b);
}

#[test]
fn eoa_and_contract_account_are_not_equal() {
    let eoa = eoa_with_balance(0);
    let contract = contract_with_code([0xab; 32]);
    assert_ne!(eoa, contract);
}

// ── Bincode round-trip ────────────────────────────────────────────────────────

#[test]
fn bincode_roundtrip_eoa() {
    let original = eoa_with_balance(1_000_000_000_000_000_000); // 1 LEM
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: Account = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}

#[test]
fn bincode_roundtrip_contract() {
    let code_hash = nonzero_code_hash();
    let storage_root = nonzero_storage_root();
    let original = Account {
        nonce: 7,
        balance: Amount::from_drop(500),
        code_hash,
        storage_root,
        staked: Amount::from_drop(200),
    };
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: Account = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}

#[test]
fn bincode_roundtrip_default_account() {
    // Zero-state account must survive a bincode round-trip.
    let original = Account::default();
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: Account = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}

#[test]
fn bincode_roundtrip_max_balance() {
    // Maximum representable balance — u128::MAX Drop.
    let original = Account::new_eoa(Amount::from_drop(u128::MAX));
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: Account = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}

#[test]
fn bincode_encoded_bytes_are_deterministic() {
    // Same account must always encode to the same bytes — required for
    // Merkle trie hashing (hash(encode(account)) must be stable).
    let acc = eoa_with_balance(42);
    let enc1 = bincode::serialize(&acc).unwrap();
    let enc2 = bincode::serialize(&acc).unwrap();
    assert_eq!(enc1, enc2);
}

#[test]
fn bincode_encoded_size_is_stable() {
    // Pin the encoded byte length so any accidental change to Amount/Hash
    // serde is caught before it silently corrupts all RocksDB data.
    //
    // Default account layout (bincode, all fields are string-serialized):
    //   nonce:        8 bytes (u64 LE)
    //   balance:      8 (len prefix) + 1 ("0") = 9 bytes
    //   code_hash:    8 (len prefix) + 64 (hex) = 72 bytes
    //   storage_root: 8 (len prefix) + 64 (hex) = 72 bytes
    //   staked:       8 (len prefix) + 1 ("0") = 9 bytes
    //   Total: 8 + 9 + 72 + 72 + 9 = 170 bytes
    //
    // If this assertion fails, the on-disk format has changed and a
    // storage migration is required before shipping.
    let acc = Account::default();
    let encoded = bincode::serialize(&acc).expect("serialize must succeed");
    assert_eq!(
        encoded.len(),
        170,
        "encoded size changed — on-disk format may be incompatible with existing data",
    );
}

// ── available_balance ─────────────────────────────────────────────────────────

#[test]
fn available_balance_returns_liquid_balance_only() {
    // An account with both balance and staked: only balance is spendable.
    let acc = Account {
        nonce: 0,
        balance: Amount::from_drop(1_000),
        code_hash: Hash::zero(),
        storage_root: Hash::zero(),
        staked: Amount::from_drop(5_000),
    };
    assert_eq!(acc.available_balance(), Amount::from_drop(1_000));
}

#[test]
fn available_balance_is_zero_when_only_staked_is_nonzero() {
    // Zero liquid balance + large staked → available_balance = 0.
    // Guards against callers using balance + staked for transfer validation.
    let acc = Account {
        nonce: 0,
        balance: Amount::zero(),
        code_hash: Hash::zero(),
        storage_root: Hash::zero(),
        staked: Amount::from_drop(32_000_000_000_000_000_000), // 32 LEM staked
    };
    assert!(acc.available_balance().is_zero());
}

// ── S5: is_zero_balance on contract account ────────────────────────────────────

#[test]
fn is_zero_balance_returns_true_for_contract_with_zero_balance() {
    // A freshly deployed contract has zero balance — is_zero_balance must
    // return true regardless of account type.
    let acc = contract_with_code([0xab; 32]);
    assert!(acc.is_zero_balance());
}

// ── S6: bincode roundtrip for EOA with non-zero staked ────────────────────────

#[test]
fn bincode_roundtrip_eoa_with_staked_balance() {
    // Validator's EOA: liquid balance + staked (real-world mainnet state).
    let original = Account {
        nonce: 42,
        balance: Amount::from_drop(1_000_000),
        code_hash: Hash::zero(),
        storage_root: Hash::zero(),
        staked: Amount::from_drop(32_000_000_000_000_000_000), // 32 LEM
    };
    let encoded = bincode::serialize(&original).expect("serialize must succeed");
    let decoded: Account = bincode::deserialize(&encoded).expect("deserialize must succeed");
    assert_eq!(original, decoded);
}
