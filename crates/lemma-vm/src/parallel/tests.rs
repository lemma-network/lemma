//! # The Flux determinism oracle (08-EXECUTION_SPEC §6)
//!
//! The headline correctness property of B5: for ANY ordered block,
//! [`ParallelScheduler`] produces output IDENTICAL to [`SequentialScheduler`] —
//! same receipts per `txn_idx` AND same final committed writes. If the proptest
//! below ever fails, the parallel implementation is WRONG (non-negotiable).
//!
//! Blocks are built from `Transfer` transactions (no WASM): the B4 transfer
//! path is deterministic and fast, exercising overlapping and disjoint account
//! conflicts — the exact contention the scheduler must serialize correctly.
//!
//! ## B5-3b hint tests
//!
//! Additional tests verify that:
//! - Blocks execute correctly with `hints = None` (conservative mode).
//! - `tx_is_express_eligible` correctly classifies transactions from hints.
//! - Blocks with hinted contracts (is_express_eligible = true) classify correctly.

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
use proptest::prelude::*;
use std::collections::BTreeMap;
use std::sync::Arc;

// ── Fixtures ────────────────────────────────────────────────────────────────

/// Number of pre-seeded accounts the generated blocks transfer between.
const NUM_ACCOUNTS: u8 = 6;
/// Starting balance (in Drop) for every seeded account.
const SEED_BALANCE: u128 = 1_000_000;

fn addr(seed: u8) -> Address {
    let mut k = [0u8; 32];
    k[0] = seed.wrapping_add(1); // avoid the all-zero key
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

fn seeded_base() -> Arc<InMemoryStateView> {
    let mut base = InMemoryStateView::new();
    for seed in 0..NUM_ACCOUNTS {
        base.set_balance(&addr(seed), Amount::from_drop(SEED_BALANCE));
    }
    Arc::new(base)
}

/// Build a Transfer tx with a hash unique to `(seq, from, to, value)`.
fn transfer(seq: u32, from: u8, to: u8, value: u128) -> Transaction {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(&seq.to_be_bytes());
    h[4] = from;
    h[5] = to;
    h[6..22].copy_from_slice(&value.to_be_bytes());
    Transaction::new(
        Hash::from_bytes(h),
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

// ── proptest strategy ───────────────────────────────────────────────────────

/// A single generated transfer: (from_account, to_account, value).
fn arb_transfer() -> impl Strategy<Value = (u8, u8, u128)> {
    (0..NUM_ACCOUNTS, 0..NUM_ACCOUNTS, 0u128..(SEED_BALANCE / 4))
}

/// A random block of 0..=24 transfers among the seeded accounts.
fn arb_block() -> impl Strategy<Value = Vec<(u8, u8, u128)>> {
    prop::collection::vec(arb_transfer(), 0..=24)
}

/// Materialize a generated block into concrete transactions.
fn build_txs(spec: &[(u8, u8, u128)]) -> Vec<Transaction> {
    spec.iter()
        .enumerate()
        .map(|(i, (from, to, value))| transfer(i as u32, *from, *to, *value))
        .collect()
}

// ── THE ORACLE ──────────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// parallel result == sequential result (receipts + final writes).
    #[test]
    fn parallel_result_equals_sequential_result(spec in arb_block()) {
        let exec = executor();
        let base = seeded_base();
        let txs = build_txs(&spec);
        let blk = block();

        let seq = SequentialScheduler.execute_block(&exec, &txs, &blk, Arc::clone(&base));
        let par = ParallelScheduler::new(4).execute_block(&exec, &txs, &blk, base);

        prop_assert_eq!(seq.receipts, par.receipts, "receipts must match");
        prop_assert_eq!(seq.writes, par.writes, "writes must match");
    }
}

// ── Hand-built conflict cases ────────────────────────────────────────────────

#[test]
fn read_after_write_chain_serializes_correctly() {
    // 0→1 (all), then 1→2 (all): tx1 must observe tx0's credit.
    let exec = executor();
    let base = seeded_base();
    let txs = vec![
        transfer(0, 0, 1, SEED_BALANCE),
        transfer(1, 1, 2, SEED_BALANCE),
    ];
    let blk = block();

    let seq = execute_block_sequential(&exec, &txs, &blk, Arc::clone(&base));
    let par = execute_block_parallel(&exec, &txs, &blk, base, FluxConfig { num_workers: 4 }, None);

    assert_eq!(seq.receipts, par.receipts);
    assert_eq!(seq.writes, par.writes);
    // Account 2 ends with 2× seed; account 0 and 1 end with 0.
    assert_eq!(
        par.writes.get(&StateKey::Balance(addr(2))),
        Some(&StateValue::Balance(Amount::from_drop(SEED_BALANCE * 2)))
    );
}

#[test]
fn insufficient_funds_failure_matches_sequential() {
    // tx0 drains account 0; tx1 from account 0 must then fail (insufficient).
    let exec = executor();
    let base = seeded_base();
    let txs = vec![transfer(0, 0, 1, SEED_BALANCE), transfer(1, 0, 2, 1)];
    let blk = block();

    let seq = execute_block_sequential(&exec, &txs, &blk, Arc::clone(&base));
    let par = execute_block_parallel(&exec, &txs, &blk, base, FluxConfig { num_workers: 4 }, None);

    assert_eq!(seq.receipts, par.receipts);
    assert_eq!(seq.writes, par.writes);
    // tx1 reverted (success=false) — it saw the drained balance.
    assert!(!par.receipts[1].success);
}

#[test]
fn high_contention_hotspot_recipient_is_deterministic() {
    // Many senders all credit account 0 — maximal write-write contention.
    let exec = executor();
    let base = seeded_base();
    let txs: Vec<Transaction> = (1..NUM_ACCOUNTS)
        .map(|s| transfer(u32::from(s), s, 0, 1000))
        .collect();
    let blk = block();

    let seq = execute_block_sequential(&exec, &txs, &blk, Arc::clone(&base));
    let par = execute_block_parallel(&exec, &txs, &blk, base, FluxConfig { num_workers: 8 }, None);

    assert_eq!(seq.receipts, par.receipts);
    assert_eq!(seq.writes, par.writes);
}

// ── B5-3b: hint-based Express eligibility tests ──────────────────────────────

/// Build a minimal `ContractHints` with one Express-eligible function.
fn express_eligible_hints(contract: Address, fn_name: &str) -> HintMap {
    let hint = FunctionHint {
        reads: ["SenderSlot:balances".to_string()].into(),
        writes: ["SenderSlot:balances".to_string()].into(),
        is_express_eligible: true,
    };
    let mut functions = BTreeMap::new();
    functions.insert(fn_name.to_string(), hint);
    let contract_hints = ContractHints { functions };
    let mut map = BTreeMap::new();
    map.insert(contract, contract_hints);
    map
}

/// Build a minimal `ContractHints` with one non-Express-eligible function.
fn non_express_hints(contract: Address, fn_name: &str) -> HintMap {
    let hint = FunctionHint {
        reads: ["Field:totalSupply".to_string()].into(),
        writes: ["Field:totalSupply".to_string()].into(),
        is_express_eligible: false,
    };
    let mut functions = BTreeMap::new();
    functions.insert(fn_name.to_string(), hint);
    let contract_hints = ContractHints { functions };
    let mut map = BTreeMap::new();
    map.insert(contract, contract_hints);
    map
}

/// Build a ContractCall transaction targeting `contract`.
///
/// Uses a 4-byte selector `[0xde, 0xad, 0xbe, 0xef]` to satisfy the
/// `ContractCall` calldata requirement (at least 4 bytes for a function selector).
fn contract_call(seq: u32, from: u8, contract: Address) -> Transaction {
    let mut h = [0u8; 32];
    h[0..4].copy_from_slice(&seq.to_be_bytes());
    h[4] = from;
    h[5] = 0xcc; // marker for contract call
                 // ContractCall requires non-empty calldata (at least 4-byte selector).
    let calldata = vec![0xde, 0xad, 0xbe, 0xef];
    Transaction::new(
        Hash::from_bytes(h),
        addr(from),
        Some(contract),
        0,
        1,
        Amount::zero(),
        1_000_000,
        Amount::from_drip(1).expect("1 drip fits"),
        TxType::ContractCall,
        calldata,
        Signature::Unsigned,
    )
    .expect("valid contract call tx")
}

#[test]
fn block_without_hints_executes_correctly_same_as_sequential() {
    // Acceptance criterion 3: without hints, behavior identical to current.
    let exec = executor();
    let base = seeded_base();
    let txs = vec![
        transfer(0, 0, 1, 1000),
        transfer(1, 2, 3, 500),
        transfer(2, 4, 5, 200),
    ];
    let blk = block();

    let seq = execute_block_sequential(&exec, &txs, &blk, Arc::clone(&base));
    let par = execute_block_parallel(&exec, &txs, &blk, base, FluxConfig { num_workers: 4 }, None);

    // Results must be identical regardless of hints.
    assert_eq!(seq.receipts, par.receipts);
    assert_eq!(seq.writes, par.writes);
}

#[test]
fn tx_is_express_eligible_returns_false_without_hints() {
    // Acceptance criterion 3: no hints → conservative (not Express-eligible).
    let tx = transfer(0, 0, 1, 100);
    assert!(!tx_is_express_eligible(&tx, None));
}

#[test]
fn tx_is_express_eligible_returns_false_for_transfer_tx() {
    // Transfer txns are never Express-eligible (not ContractCall).
    let contract = addr(7);
    let hints = express_eligible_hints(contract, "transfer");
    let tx = transfer(0, 0, 1, 100); // TxType::Transfer, not ContractCall
    assert!(!tx_is_express_eligible(&tx, Some(&hints)));
}

#[test]
fn tx_is_express_eligible_returns_false_when_contract_not_in_hints() {
    // Contract not in hint map → conservative (not Express-eligible).
    let contract = addr(7);
    let other_contract = addr(8);
    let hints = express_eligible_hints(contract, "transfer");
    let tx = contract_call(0, 0, other_contract);
    assert!(!tx_is_express_eligible(&tx, Some(&hints)));
}

#[test]
fn tx_is_express_eligible_returns_true_for_hinted_express_contract() {
    // Acceptance criterion 4: with hints, Express-eligible txns classified correctly.
    let contract = addr(7);
    let hints = express_eligible_hints(contract, "transfer");
    let tx = contract_call(0, 0, contract);
    assert!(tx_is_express_eligible(&tx, Some(&hints)));
}

#[test]
fn tx_is_express_eligible_returns_false_for_non_express_contract() {
    // Contract in hint map but no Express-eligible function → not eligible.
    let contract = addr(7);
    let hints = non_express_hints(contract, "mint");
    let tx = contract_call(0, 0, contract);
    assert!(!tx_is_express_eligible(&tx, Some(&hints)));
}

#[test]
fn block_with_hinted_contracts_executes_correctly() {
    // Acceptance criterion 5: block with hinted contracts (is_express_eligible = true)
    // executes correctly — same result as sequential.
    let exec = executor();
    let base = seeded_base();
    let contract = addr(7);
    let hints = express_eligible_hints(contract, "transfer");
    let txs = vec![transfer(0, 0, 1, 1000), transfer(1, 2, 3, 500)];
    let blk = block();

    let seq = execute_block_sequential(&exec, &txs, &blk, Arc::clone(&base));
    let par = execute_block_parallel(
        &exec,
        &txs,
        &blk,
        base,
        FluxConfig { num_workers: 4 },
        Some(&hints),
    );

    // Correctness: results identical regardless of hints.
    assert_eq!(seq.receipts, par.receipts);
    assert_eq!(seq.writes, par.writes);
}

#[test]
fn hint_map_with_multiple_contracts_classifies_correctly() {
    // Multiple contracts in hint map: only the matching one is Express-eligible.
    let contract_a = addr(7);
    let contract_b = addr(8);

    let hint_a = FunctionHint {
        reads: ["SenderSlot:balances".to_string()].into(),
        writes: ["SenderSlot:balances".to_string()].into(),
        is_express_eligible: true,
    };
    let hint_b = FunctionHint {
        reads: ["Field:totalSupply".to_string()].into(),
        writes: ["Field:totalSupply".to_string()].into(),
        is_express_eligible: false,
    };

    let mut hints: HintMap = BTreeMap::new();
    hints.insert(
        contract_a,
        ContractHints {
            functions: [("transfer".to_string(), hint_a)].into(),
        },
    );
    hints.insert(
        contract_b,
        ContractHints {
            functions: [("mint".to_string(), hint_b)].into(),
        },
    );

    let tx_a = contract_call(0, 0, contract_a);
    let tx_b = contract_call(1, 1, contract_b);

    assert!(tx_is_express_eligible(&tx_a, Some(&hints)));
    assert!(!tx_is_express_eligible(&tx_b, Some(&hints)));
}
