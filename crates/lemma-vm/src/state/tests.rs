//! Tests for [`InMemoryStateView`] — covers all `ContractStateView` methods.

use std::collections::BTreeMap;

use lemma_core::{address::Address, amount::Amount};

use crate::state::{ContractStateView, InMemoryStateView};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn test_address(seed: u8) -> Address {
    // Derive a deterministic address from a seed byte via the public-key path.
    // We use a 32-byte array filled with the seed as a "fake" public key.
    Address::from_public_key(&[seed; 32])
}

fn test_amount(drops: u128) -> Amount {
    Amount::from_drop(drops)
}

// ── Storage tests ─────────────────────────────────────────────────────────────

#[test]
fn read_returns_none_for_absent_key() {
    let view = InMemoryStateView::new();
    let addr = test_address(1);
    assert!(view.read(&addr, b"missing").is_none());
}

#[test]
fn write_then_read_returns_stored_value() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.write(&addr, b"key", b"value".to_vec());
    assert_eq!(view.read(&addr, b"key"), Some(b"value".to_vec()));
}

#[test]
fn write_update_overwrites_existing_value() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.write(&addr, b"key", b"first".to_vec());
    view.write(&addr, b"key", b"second".to_vec());
    assert_eq!(view.read(&addr, b"key"), Some(b"second".to_vec()));
}

#[test]
fn delete_removes_existing_key() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.write(&addr, b"key", b"value".to_vec());
    view.delete(&addr, b"key");
    assert!(view.read(&addr, b"key").is_none());
}

#[test]
fn delete_is_idempotent_on_absent_key() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    // Should not panic or error — no-op on absent key.
    view.delete(&addr, b"nonexistent");
    view.delete(&addr, b"nonexistent");
    assert!(view.read(&addr, b"nonexistent").is_none());
}

#[test]
fn exists_returns_false_for_absent_key() {
    let view = InMemoryStateView::new();
    let addr = test_address(1);
    assert!(!view.exists(&addr, b"missing"));
}

#[test]
fn exists_returns_true_after_write() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.write(&addr, b"key", b"v".to_vec());
    assert!(view.exists(&addr, b"key"));
}

#[test]
fn exists_returns_false_after_delete() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.write(&addr, b"key", b"v".to_vec());
    view.delete(&addr, b"key");
    assert!(!view.exists(&addr, b"key"));
}

#[test]
fn storage_is_isolated_per_contract() {
    let mut view = InMemoryStateView::new();
    let addr_a = test_address(1);
    let addr_b = test_address(2);
    view.write(&addr_a, b"key", b"a_value".to_vec());
    // addr_b has no entry for the same key.
    assert!(view.read(&addr_b, b"key").is_none());
    assert!(view.exists(&addr_a, b"key"));
    assert!(!view.exists(&addr_b, b"key"));
}

// ── Balance tests ─────────────────────────────────────────────────────────────

#[test]
fn balance_returns_zero_for_unknown_address() {
    let view = InMemoryStateView::new();
    let addr = test_address(1);
    assert_eq!(view.balance(&addr), Amount::zero());
}

#[test]
fn set_balance_then_balance_returns_stored_amount() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    let amount = test_amount(1_000_000);
    view.set_balance(&addr, amount);
    assert_eq!(view.balance(&addr), amount);
}

#[test]
fn set_balance_overwrites_previous_balance() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.set_balance(&addr, test_amount(100));
    view.set_balance(&addr, test_amount(200));
    assert_eq!(view.balance(&addr), test_amount(200));
}

#[test]
fn set_balance_to_zero_returns_zero() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.set_balance(&addr, test_amount(500));
    view.set_balance(&addr, Amount::zero());
    assert_eq!(view.balance(&addr), Amount::zero());
}

// ── Constructor tests ─────────────────────────────────────────────────────────

#[test]
fn with_balances_seeds_initial_balances() {
    let addr_a = test_address(1);
    let addr_b = test_address(2);
    let mut initial = BTreeMap::new();
    initial.insert(addr_a, test_amount(1_000));
    initial.insert(addr_b, test_amount(2_000));

    let view = InMemoryStateView::with_balances(initial);
    assert_eq!(view.balance(&addr_a), test_amount(1_000));
    assert_eq!(view.balance(&addr_b), test_amount(2_000));
}

#[test]
fn with_balances_has_empty_storage() {
    let addr = test_address(1);
    let mut initial = BTreeMap::new();
    initial.insert(addr, test_amount(100));

    let view = InMemoryStateView::with_balances(initial);
    // Storage is empty even though balance is set.
    assert!(view.read(&addr, b"any_key").is_none());
    assert!(!view.exists(&addr, b"any_key"));
}

#[test]
fn round_trip_write_read_delete_read() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(42);
    let key = b"round_trip_key";
    let value = b"round_trip_value".to_vec();

    // Write → read → delete → read
    view.write(&addr, key, value.clone());
    assert_eq!(view.read(&addr, key), Some(value));
    view.delete(&addr, key);
    assert_eq!(view.read(&addr, key), None);
}

// ── Nonce tests ───────────────────────────────────────────────────────────────

#[test]
fn nonce_returns_zero_for_new_account() {
    let view = InMemoryStateView::new();
    let addr = test_address(1);
    assert_eq!(view.nonce(&addr), 0);
}

#[test]
fn set_nonce_then_nonce_returns_stored_value() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.set_nonce(&addr, 42);
    assert_eq!(view.nonce(&addr), 42);
}

#[test]
fn set_nonce_overwrites_previous_nonce() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.set_nonce(&addr, 5);
    view.set_nonce(&addr, 10);
    assert_eq!(view.nonce(&addr), 10);
}

#[test]
fn nonce_is_isolated_per_account() {
    let mut view = InMemoryStateView::new();
    let addr_a = test_address(1);
    let addr_b = test_address(2);
    view.set_nonce(&addr_a, 7);
    // addr_b nonce is unaffected.
    assert_eq!(view.nonce(&addr_b), 0);
    assert_eq!(view.nonce(&addr_a), 7);
}

// ── Code tests ────────────────────────────────────────────────────────────────

#[test]
fn code_returns_none_for_eoa() {
    let view = InMemoryStateView::new();
    let addr = test_address(1);
    assert!(view.code(&addr).is_none());
}

#[test]
fn set_code_then_code_returns_stored_bytecode() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    let bytecode = b"(module)".to_vec();
    view.set_code(&addr, bytecode.clone());
    assert_eq!(view.code(&addr), Some(bytecode));
}

#[test]
fn set_code_overwrites_previous_bytecode() {
    let mut view = InMemoryStateView::new();
    let addr = test_address(1);
    view.set_code(&addr, b"old".to_vec());
    view.set_code(&addr, b"new".to_vec());
    assert_eq!(view.code(&addr), Some(b"new".to_vec()));
}

#[test]
fn code_is_isolated_per_address() {
    let mut view = InMemoryStateView::new();
    let addr_a = test_address(1);
    let addr_b = test_address(2);
    view.set_code(&addr_a, b"contract_a".to_vec());
    // addr_b has no code.
    assert!(view.code(&addr_b).is_none());
    assert!(view.code(&addr_a).is_some());
}
