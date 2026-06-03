//! Unit tests for the [`MvStateView`] MVCC ↔ executor bridge.

use super::*;
use crate::parallel::mvstate::Version;
use crate::state::InMemoryStateView;
use lemma_core::amount::Amount;
use std::sync::Arc;

fn addr(seed: u8) -> Address {
    let mut k = [0u8; 32];
    k[0] = seed;
    Address::from_public_key(&k)
}

#[test]
fn balance_falls_through_to_base_when_no_mvcc_write() {
    let mut base = InMemoryStateView::new();
    base.set_balance(&addr(1), Amount::from_drop(500));
    let mv = Arc::new(MvState::new());

    let view = MvStateView::new(Arc::clone(&mv), Arc::new(base), 0);
    assert_eq!(view.balance(&addr(1)), Amount::from_drop(500));
}

#[test]
fn balance_reads_lower_mvcc_write_over_base() {
    let mut base = InMemoryStateView::new();
    base.set_balance(&addr(1), Amount::from_drop(500));
    let mv = Arc::new(MvState::new());
    mv.write(
        StateKey::Balance(addr(1)),
        Version::new(0, 0),
        StateValue::Balance(Amount::from_drop(900)),
    );

    // Reader txn 2 sees txn 0's MVCC write, not base.
    let view = MvStateView::new(Arc::clone(&mv), Arc::new(base), 2);
    assert_eq!(view.balance(&addr(1)), Amount::from_drop(900));
}

#[test]
fn read_own_buffered_write_takes_precedence() {
    let base = InMemoryStateView::new();
    let mv = Arc::new(MvState::new());
    let mut view = MvStateView::new(mv, Arc::new(base), 1);
    view.set_balance(&addr(1), Amount::from_drop(42));
    assert_eq!(view.balance(&addr(1)), Amount::from_drop(42));
}

#[test]
fn into_parts_extracts_writes_and_reads() {
    let mut base = InMemoryStateView::new();
    base.set_balance(&addr(1), Amount::from_drop(10));
    let mv = Arc::new(MvState::new());
    let mut view = MvStateView::new(mv, Arc::new(base), 0);

    let _ = view.balance(&addr(1)); // records a base fall-through read
    view.set_balance(&addr(2), Amount::from_drop(99)); // buffers a write

    let (writes, reads) = view.into_parts();
    assert_eq!(
        writes.get(&StateKey::Balance(addr(2))),
        Some(&StateValue::Balance(Amount::from_drop(99)))
    );
    assert_eq!(reads.len(), 1);
}

#[test]
fn estimate_read_notes_blocking_txn_and_falls_back_to_base() {
    let mut base = InMemoryStateView::new();
    base.set_balance(&addr(1), Amount::from_drop(7));
    let mv = Arc::new(MvState::new());
    let key = StateKey::Balance(addr(1));
    mv.write(
        key.clone(),
        Version::new(1, 0),
        StateValue::Balance(Amount::from_drop(1000)),
    );
    mv.mark_estimate(1, std::slice::from_ref(&key));

    let view = MvStateView::new(Arc::clone(&mv), Arc::new(base), 3);
    // Falls back to base value while estimate is in flight.
    assert_eq!(view.balance(&addr(1)), Amount::from_drop(7));
    assert_eq!(view.min_blocking_txn(), Some(1));
}

#[test]
fn storage_read_write_round_trip_through_mvview() {
    let base = InMemoryStateView::new();
    let mv = Arc::new(MvState::new());
    let mut view = MvStateView::new(mv, Arc::new(base), 0);
    let c = addr(9);
    view.write(&c, b"k", b"v".to_vec());
    assert_eq!(view.read(&c, b"k"), Some(b"v".to_vec()));
    assert!(view.exists(&c, b"k"));
    view.delete(&c, b"k");
    assert!(!view.exists(&c, b"k"));
}
