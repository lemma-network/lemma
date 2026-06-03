//! Unit tests for the multi-version state store ([`MvState`]).

use super::*;
use lemma_core::address::Address;

/// Build a distinct test address from a single seed byte.
fn addr(seed: u8) -> Address {
    let mut k = [0u8; 32];
    k[0] = seed;
    Address::from_public_key(&k)
}

fn balance_key(seed: u8) -> StateKey {
    StateKey::Balance(addr(seed))
}

#[test]
fn read_empty_store_returns_not_found() {
    let mv = MvState::new();
    assert_eq!(mv.read(&balance_key(1), 0), MvReadResult::NotFound);
}

#[test]
fn read_resolves_highest_write_strictly_below_reader() {
    let mv = MvState::new();
    let key = balance_key(1);
    // txn 0 writes 100, txn 2 writes 300.
    mv.write(
        key.clone(),
        Version::new(0, 0),
        StateValue::Balance(Amount::from_drop(100)),
    );
    mv.write(
        key.clone(),
        Version::new(2, 0),
        StateValue::Balance(Amount::from_drop(300)),
    );

    // Reader txn 2 sees txn 0's write (strictly below 2), NOT its own.
    let r = mv.read(&key, 2);
    assert_eq!(
        r,
        MvReadResult::Value {
            version: Version::new(0, 0),
            value: StateValue::Balance(Amount::from_drop(100)),
        }
    );
}

#[test]
fn read_sees_own_index_excluded_via_shift() {
    let mv = MvState::new();
    let key = balance_key(1);
    // Only txn 5 has written. Reader txn 5 must NOT see it (strictly below).
    mv.write(
        key.clone(),
        Version::new(5, 0),
        StateValue::Balance(Amount::from_drop(50)),
    );
    assert_eq!(mv.read(&key, 5), MvReadResult::NotFound);
    // Reader txn 6 DOES see txn 5's write.
    assert_eq!(
        mv.read(&key, 6),
        MvReadResult::Value {
            version: Version::new(5, 0),
            value: StateValue::Balance(Amount::from_drop(50)),
        }
    );
}

#[test]
fn read_resolves_closest_below_among_many() {
    let mv = MvState::new();
    let key = balance_key(1);
    for idx in [0u32, 1, 2, 3] {
        mv.write(
            key.clone(),
            Version::new(idx, 0),
            StateValue::Balance(Amount::from_drop(u128::from(idx) * 10)),
        );
    }
    // Reader txn 3 sees txn 2 (closest strictly below).
    assert_eq!(
        mv.read(&key, 3),
        MvReadResult::Value {
            version: Version::new(2, 0),
            value: StateValue::Balance(Amount::from_drop(20)),
        }
    );
}

#[test]
fn read_on_estimate_returns_dependency() {
    let mv = MvState::new();
    let key = balance_key(1);
    mv.write(
        key.clone(),
        Version::new(1, 0),
        StateValue::Balance(Amount::from_drop(10)),
    );
    mv.mark_estimate(1, std::slice::from_ref(&key));
    // Reader txn 4 lands on txn 1's estimate → must wait on txn 1.
    assert_eq!(mv.read(&key, 4), MvReadResult::Estimate { blocking_txn: 1 });
}

#[test]
fn write_overwrites_same_slot_with_new_incarnation() {
    let mv = MvState::new();
    let key = balance_key(1);
    mv.write(
        key.clone(),
        Version::new(1, 0),
        StateValue::Balance(Amount::from_drop(10)),
    );
    mv.write(
        key.clone(),
        Version::new(1, 1),
        StateValue::Balance(Amount::from_drop(99)),
    );
    assert_eq!(
        mv.read(&key, 2),
        MvReadResult::Value {
            version: Version::new(1, 1),
            value: StateValue::Balance(Amount::from_drop(99)),
        }
    );
}

#[test]
fn remove_writes_unshadows_lower_write() {
    let mv = MvState::new();
    let key = balance_key(1);
    mv.write(
        key.clone(),
        Version::new(0, 0),
        StateValue::Balance(Amount::from_drop(7)),
    );
    mv.write(
        key.clone(),
        Version::new(2, 0),
        StateValue::Balance(Amount::from_drop(70)),
    );
    mv.remove_writes(2, std::slice::from_ref(&key));
    // Reader txn 3 now falls back to txn 0.
    assert_eq!(
        mv.read(&key, 3),
        MvReadResult::Value {
            version: Version::new(0, 0),
            value: StateValue::Balance(Amount::from_drop(7)),
        }
    );
}

#[test]
fn snapshot_collects_highest_write_per_key_sorted() {
    let mv = MvState::new();
    let k1 = balance_key(1);
    let k2 = balance_key(2);
    mv.write(
        k1.clone(),
        Version::new(0, 0),
        StateValue::Balance(Amount::from_drop(1)),
    );
    mv.write(
        k1.clone(),
        Version::new(3, 0),
        StateValue::Balance(Amount::from_drop(300)),
    );
    mv.write(
        k2.clone(),
        Version::new(1, 0),
        StateValue::Balance(Amount::from_drop(20)),
    );

    let snap = mv.snapshot_committed_into_btreemap();
    assert_eq!(snap.len(), 2);
    assert_eq!(
        snap.get(&k1),
        Some(&StateValue::Balance(Amount::from_drop(300)))
    );
    assert_eq!(
        snap.get(&k2),
        Some(&StateValue::Balance(Amount::from_drop(20)))
    );
}

#[test]
fn state_key_ord_is_deterministic_for_btreemap() {
    // Storage < Balance < Nonce < Code by enum discriminant order.
    let storage = StateKey::Storage {
        contract: addr(1),
        key: vec![0],
    };
    let balance = StateKey::Balance(addr(1));
    assert!(storage < balance);
}
