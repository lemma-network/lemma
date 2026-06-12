//! Unit tests for the block schedulers (non-proptest; the headline oracle lives
//! in `parallel/tests.rs`).

use super::*;
use crate::gas::GasSchedule;
use crate::runtime::LemmaEngine;
use crate::state::InMemoryStateView;
use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    signature::Signature,
    transaction::{Transaction, TxType},
};
use std::sync::Arc;

fn addr(seed: u8) -> Address {
    let mut k = [0u8; 32];
    k[0] = seed;
    Address::from_public_key(&k)
}

fn executor() -> Executor {
    Executor::new(
        LemmaEngine::new().expect("engine builds"),
        GasSchedule::devnet(),
    )
}

fn block() -> BlockContext {
    BlockContext {
        height: 1,
        timestamp: 1,
        msg_sender: addr(0),
        msg_value: Amount::zero(),
        tx_origin: addr(0),
        // Placeholder — execute_call injects the real contract address (M3 fix).
        contract: addr(0),
    }
}

/// Build a Transfer tx from `from` → `to` of `value` drops, ample gas.
fn transfer(from: u8, to: u8, value: u128) -> Transaction {
    Transaction::new(
        Hash::from_bytes({
            let mut b = [0u8; 32];
            b[0] = from;
            b[1] = to;
            b[2] = (value & 0xff) as u8;
            b
        }),
        addr(from),
        Some(addr(to)),
        0,
        1,
        Amount::from_drop(value),
        1_000_000,
        Amount::from_drip(1).expect("1 drip fits in u128"),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("valid transfer tx")
}

fn seeded_base() -> Arc<InMemoryStateView> {
    let mut base = InMemoryStateView::new();
    for seed in 1u8..=8 {
        base.set_balance(&addr(seed), Amount::from_drop(1_000_000));
    }
    Arc::new(base)
}

#[test]
fn sequential_disjoint_transfers_update_all_balances() {
    let exec = executor();
    let base = seeded_base();
    let txs = vec![transfer(1, 2, 100), transfer(3, 4, 200)];
    let out = SequentialScheduler.execute_block(&exec, &txs, &block(), base);

    assert_eq!(out.receipts.len(), 2);
    assert!(out.receipts.iter().all(|r| r.success));
    assert_eq!(
        out.writes.get(&StateKey::Balance(addr(2))),
        Some(&StateValue::Balance(Amount::from_drop(1_000_100)))
    );
}

#[test]
fn parallel_equals_sequential_for_dependent_chain() {
    // A→B then B→C: B must see A's credit before sending to C.
    let exec = executor();
    let base = seeded_base();
    let txs = vec![transfer(1, 2, 500), transfer(2, 3, 500)];

    let seq = SequentialScheduler.execute_block(&exec, &txs, &block(), Arc::clone(&base));
    let par = ParallelScheduler::new(4).execute_block(&exec, &txs, &block(), base);

    assert_eq!(seq.receipts, par.receipts);
    assert_eq!(seq.writes, par.writes);
}

#[test]
fn parallel_equals_sequential_for_write_write_conflict() {
    // Two txns both credit the same recipient from different senders.
    let exec = executor();
    let base = seeded_base();
    let txs = vec![
        transfer(1, 5, 100),
        transfer(2, 5, 200),
        transfer(3, 5, 300),
    ];

    let seq = SequentialScheduler.execute_block(&exec, &txs, &block(), Arc::clone(&base));
    let par = ParallelScheduler::new(4).execute_block(&exec, &txs, &block(), base);

    assert_eq!(seq.receipts, par.receipts);
    assert_eq!(seq.writes, par.writes);
    // Recipient 5 received 100+200+300 on top of its seed.
    assert_eq!(
        par.writes.get(&StateKey::Balance(addr(5))),
        Some(&StateValue::Balance(Amount::from_drop(1_000_600)))
    );
}

#[test]
fn sequential_is_deterministic_across_runs() {
    let exec = executor();
    let base = seeded_base();
    let txs = vec![transfer(1, 2, 10), transfer(2, 3, 5), transfer(3, 1, 1)];
    let a = SequentialScheduler.execute_block(&exec, &txs, &block(), Arc::clone(&base));
    let b = SequentialScheduler.execute_block(&exec, &txs, &block(), base);
    assert_eq!(a, b);
}

#[test]
fn parallel_single_tx_falls_back_to_sequential() {
    let exec = executor();
    let base = seeded_base();
    let txs = vec![transfer(1, 2, 42)];
    let seq = SequentialScheduler.execute_block(&exec, &txs, &block(), Arc::clone(&base));
    let par = ParallelScheduler::new(8).execute_block(&exec, &txs, &block(), base);
    assert_eq!(seq, par);
}

#[test]
fn parallel_empty_block_is_empty_output() {
    let exec = executor();
    let base = seeded_base();
    let out = ParallelScheduler::new(4).execute_block(&exec, &[], &block(), base);
    assert!(out.receipts.is_empty());
    assert!(out.writes.is_empty());
}

#[test]
fn parallel_transitive_chain_forces_reexec_and_matches_sequential() {
    // A strict transitive chain 1→2→3→4→5: each txn's recipient is the next
    // txn's sender, so EVERY txn (except the first) reads a balance a lower txn
    // writes. With many workers, higher txns execute speculatively against the
    // base (estimate/stale), get invalidated at commit, and re-execute against
    // the committed prefix. This deterministically drives the abort + estimate
    // + commit-time re-execution path. The result MUST equal sequential.
    let exec = executor();
    let base = seeded_base();
    let txs = vec![
        transfer(1, 2, 400),
        transfer(2, 3, 300),
        transfer(3, 4, 200),
        transfer(4, 5, 100),
    ];

    let seq = SequentialScheduler.execute_block(&exec, &txs, &block(), Arc::clone(&base));
    // Use more workers than txns to maximize speculative contention.
    let par = ParallelScheduler::new(8).execute_block(&exec, &txs, &block(), base);

    assert_eq!(seq.receipts, par.receipts, "receipts must match sequential");
    assert_eq!(seq.writes, par.writes, "final writes must match sequential");
    // All transfers succeed (each sender has enough after receiving).
    assert!(par.receipts.iter().all(|r| r.success));
}

#[test]
fn parallel_chain_with_insufficient_funds_midway_matches_sequential() {
    // Account 6 starts with seed 1_000_000; tx0 drains most of it, so a later
    // txn from 6 that needs more than the post-drain balance must FAIL — and
    // it must fail IDENTICALLY in parallel and sequential (the failed receipt
    // and unchanged-balance must match exactly across both schedulers).
    let exec = executor();
    let base = seeded_base();
    let txs = vec![
        transfer(6, 7, 999_999), // drains 6 to ~1
        transfer(6, 8, 500_000), // 6 now lacks funds → must fail
    ];

    let seq = SequentialScheduler.execute_block(&exec, &txs, &block(), Arc::clone(&base));
    let par = ParallelScheduler::new(8).execute_block(&exec, &txs, &block(), base);

    assert_eq!(seq.receipts, par.receipts);
    assert_eq!(seq.writes, par.writes);
    assert!(seq.receipts[0].success, "first drain succeeds");
    assert!(
        !seq.receipts[1].success,
        "second transfer fails (insufficient)"
    );
}
