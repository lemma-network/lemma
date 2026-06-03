//! Unit tests for captured reads and validation.

use super::*;
use lemma_core::{address::Address, amount::Amount};

fn addr(seed: u8) -> Address {
    let mut k = [0u8; 32];
    k[0] = seed;
    Address::from_public_key(&k)
}

fn bal_key(seed: u8) -> StateKey {
    StateKey::Balance(addr(seed))
}

#[test]
fn validate_passes_when_versioned_read_unchanged() {
    let mv = MvState::new();
    let key = bal_key(1);
    mv.write(
        key.clone(),
        Version::new(0, 0),
        StateValue::Balance(Amount::from_drop(100)),
    );

    let mut reads = CapturedReads::new();
    reads.record(
        key.clone(),
        ObservedRead::Versioned {
            version: Version::new(0, 0),
            value: StateValue::Balance(Amount::from_drop(100)),
        },
    );
    // Reader is txn 2 reading txn 0's write.
    assert!(validate(&reads, &mv, 2));
}

#[test]
fn validate_fails_when_lower_txn_overwrites_read_key() {
    let mv = MvState::new();
    let key = bal_key(1);
    mv.write(
        key.clone(),
        Version::new(0, 0),
        StateValue::Balance(Amount::from_drop(100)),
    );

    let mut reads = CapturedReads::new();
    reads.record(
        key.clone(),
        ObservedRead::Versioned {
            version: Version::new(0, 0),
            value: StateValue::Balance(Amount::from_drop(100)),
        },
    );

    // A lower-indexed txn 1 now writes the same key with a different value.
    mv.write(
        key.clone(),
        Version::new(1, 0),
        StateValue::Balance(Amount::from_drop(999)),
    );
    // Reader txn 2 would now resolve to txn 1, not txn 0 → stale.
    assert!(!validate(&reads, &mv, 2));
}

#[test]
fn validate_passes_for_base_fallthrough_still_empty() {
    let mv = MvState::new();
    let key = bal_key(1);
    let mut reads = CapturedReads::new();
    reads.record(key, ObservedRead::BaseFallthrough);
    assert!(validate(&reads, &mv, 3));
}

#[test]
fn validate_fails_when_fallthrough_now_has_lower_write() {
    let mv = MvState::new();
    let key = bal_key(1);
    let mut reads = CapturedReads::new();
    reads.record(key.clone(), ObservedRead::BaseFallthrough);

    mv.write(
        key,
        Version::new(0, 0),
        StateValue::Balance(Amount::from_drop(5)),
    );
    // Reader txn 3 no longer falls through → stale.
    assert!(!validate(&reads, &mv, 3));
}

#[test]
fn validate_fails_when_read_lands_on_estimate() {
    let mv = MvState::new();
    let key = bal_key(1);
    mv.write(
        key.clone(),
        Version::new(0, 0),
        StateValue::Balance(Amount::from_drop(100)),
    );
    let mut reads = CapturedReads::new();
    reads.record(
        key.clone(),
        ObservedRead::Versioned {
            version: Version::new(0, 0),
            value: StateValue::Balance(Amount::from_drop(100)),
        },
    );
    mv.mark_estimate(0, std::slice::from_ref(&key));
    // Resolution now returns Estimate → conservative invalidation.
    assert!(!validate(&reads, &mv, 2));
}

#[test]
fn empty_read_set_always_validates() {
    let mv = MvState::new();
    let reads = CapturedReads::new();
    assert!(reads.is_empty());
    assert!(validate(&reads, &mv, 0));
}
