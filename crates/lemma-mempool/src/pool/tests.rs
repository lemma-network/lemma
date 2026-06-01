//! Tests for `lemma_mempool::pool` — the core Mempool orchestrator.
//!
//! Coverage target: all state transitions (AGENTS.md §11.1):
//!   - Valid input → correct new state.
//!   - Invalid input → error, pool state unchanged.
//!   - Edge cases: capacity boundary, RBF threshold, nonce gap.
//!   - Retrieval ordering, maintenance, Express classification.
//!
//! Uses real `KeyPair`, `WorldState` (tempfile RocksDB), and `sign_transaction`
//! — the same pattern as `validation/tests.rs`.

use std::time::Instant;

use tempfile::TempDir;

use lemma_core::{
    amount::Amount,
    hash::Hash,
    transaction::{Transaction, TxType},
    Address, Signature,
};
use lemma_crypto::{sign_transaction, KeyPair};
use lemma_storage::{account::Account, LemmaDb, WorldState};

use crate::{
    error::MempoolError,
    express::ExpressHint,
    pool::{AdmitContext, AdmitOutcome, Mempool, DEFAULT_CAPACITY, MIN_REPLACE_BUMP_BPS},
    rate_limit::RateLimiter,
};

// ── Test helpers ──────────────────────────────────────────────────────────────

const CHAIN_ID: u64 = 1;
const GAS_LIMIT: u64 = 1_000_000;

/// Open a fresh `WorldState` backed by a temp RocksDB directory.
/// Returns `(WorldState, TempDir)` — keep `TempDir` alive for the test duration.
fn empty_world_state() -> (WorldState, TempDir) {
    let dir = TempDir::new().expect("tempdir must be created");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb must open on fresh tempdir");
    (WorldState::new(db), dir)
}

/// Fund `address` with `balance` Drop in `state`.
fn fund(state: &mut WorldState, address: &Address, balance: Amount) {
    let account = Account::new_eoa(balance);
    state.put_account(address, &account).expect("put_account must succeed");
}

/// Build and sign a minimal `Transfer` transaction.
fn signed_transfer(kp: &KeyPair, nonce: u64, gas_price: Amount) -> Transaction {
    let mut tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::zero()),
        nonce,
        CHAIN_ID,
        Amount::zero(),
        GAS_LIMIT,
        gas_price,
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("test transaction must be valid");
    sign_transaction(&mut tx, kp).expect("signing must succeed");
    tx
}

/// Build and sign a `Stake` transaction.
///
/// Stake is admitted at ALL circuit-breaker tiers (including Emergency), so it
/// is the right type for capacity-eviction tests that run at 100% pool load.
fn signed_stake(kp: &KeyPair, nonce: u64, gas_price: Amount, validator: Address) -> Transaction {
    let mut tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(validator),
        nonce,
        CHAIN_ID,
        Amount::zero(),
        GAS_LIMIT,
        gas_price,
        TxType::Stake,
        vec![],
        Signature::Unsigned,
    )
    .expect("test stake transaction must be valid");
    sign_transaction(&mut tx, kp).expect("signing must succeed");
    tx
}

/// Build and sign a `ContractCall` transaction (for circuit-breaker tests).
fn signed_contract_call(kp: &KeyPair, nonce: u64, gas_price: Amount, to: Address) -> Transaction {
    let mut tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(to),
        nonce,
        CHAIN_ID,
        Amount::zero(),
        GAS_LIMIT,
        gas_price,
        TxType::ContractCall,
        vec![0x00, 0x01, 0x02, 0x03], // minimal calldata (non-empty required)
        Signature::Unsigned,
    )
    .expect("test contract call must be valid");
    sign_transaction(&mut tx, kp).expect("signing must succeed");
    tx
}

/// Standard admit call (no stake, no Express hint, zero base fee, Instant::now()).
fn admit(pool: &mut Mempool, tx: Transaction, kp: &KeyPair, state: &WorldState) -> Result<AdmitOutcome, MempoolError> {
    let ctx = AdmitContext { chain_id: CHAIN_ID, base_fee: Amount::zero(), now: Instant::now() };
    pool.admit(tx, &kp.public_key(), Amount::zero(), None, state, &ctx)
}

/// Admit with an Express hint.
fn admit_with_hint(pool: &mut Mempool, tx: Transaction, kp: &KeyPair, state: &WorldState, hint: &ExpressHint) -> Result<AdmitOutcome, MempoolError> {
    let ctx = AdmitContext { chain_id: CHAIN_ID, base_fee: Amount::zero(), now: Instant::now() };
    pool.admit(tx, &kp.public_key(), Amount::zero(), Some(hint), state, &ctx)
}

/// Admit with an explicit gas base fee.
fn admit_with_base_fee(pool: &mut Mempool, tx: Transaction, kp: &KeyPair, state: &WorldState, base_fee: Amount) -> Result<AdmitOutcome, MempoolError> {
    let ctx = AdmitContext { chain_id: CHAIN_ID, base_fee, now: Instant::now() };
    pool.admit(tx, &kp.public_key(), Amount::zero(), None, state, &ctx)
}


/// Sufficient funding for most tests: covers gas_limit × gas_price + value.
fn rich() -> Amount {
    Amount::from_drop(1_000_000_000_000_000_000) // 1 LEM
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[test]
fn admit_inserts_transaction_and_returns_inserted() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));

    let outcome = admit(&mut pool, tx.clone(), &kp, &state).expect("admit must succeed");

    assert_eq!(outcome, AdmitOutcome::Inserted);
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(tx.hash));
}

#[test]
fn admit_inserted_entry_accessible_via_get() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let hash = tx.hash;

    let _ = admit(&mut pool, tx, &kp, &state).expect("admit must succeed");

    let entry = pool.get(hash).expect("entry must be present after admit");
    assert_eq!(entry.tx.hash, hash);
}

#[test]
fn admit_two_different_senders_both_inserted() {
    let (mut state, _dir) = empty_world_state();
    let kp1 = KeyPair::generate().expect("KeyPair::generate must succeed");
    let kp2 = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp1.address(), rich());
    fund(&mut state, kp2.address(), rich());
    let mut pool = Mempool::new(10);

    let tx1 = signed_transfer(&kp1, 0, Amount::from_drop(1_000));
    let tx2 = signed_transfer(&kp2, 0, Amount::from_drop(1_000));
    let _ = admit(&mut pool, tx1, &kp1, &state).expect("tx1 must be admitted");
    let _ = admit(&mut pool, tx2, &kp2, &state).expect("tx2 must be admitted");

    assert_eq!(pool.len(), 2);
}

#[test]
fn admit_same_sender_different_nonces_both_inserted() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);

    let tx0 = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let tx1 = signed_transfer(&kp, 1, Amount::from_drop(1_000));
    let _ = admit(&mut pool, tx0, &kp, &state).expect("nonce-0 must be admitted");
    let _ = admit(&mut pool, tx1, &kp, &state).expect("nonce-1 must be admitted");

    assert_eq!(pool.len(), 2);
}

// ── Replace-by-fee (RBF) ──────────────────────────────────────────────────────

#[test]
fn admit_replace_by_fee_accepted_when_price_above_minimum_bump() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);

    let old_price = Amount::from_drop(1_000);
    let tx_old = signed_transfer(&kp, 0, old_price);
    let old_hash = tx_old.hash;
    let _ = admit(&mut pool, tx_old, &kp, &state).expect("old tx must be admitted");

    // New price: old × (10_000 + MIN_REPLACE_BUMP_BPS) / 10_000 = 1_000 × 1.10 = 1_100.
    let new_price = Amount::from_drop(1_100);
    let tx_new = signed_transfer(&kp, 0, new_price);
    let new_hash = tx_new.hash;
    let outcome = admit(&mut pool, tx_new, &kp, &state).expect("replacement must be accepted");

    assert_eq!(outcome, AdmitOutcome::Replaced { replaced_hash: old_hash });
    assert_eq!(pool.len(), 1, "old tx evicted, new tx inserted");
    assert!(pool.contains(new_hash));
    assert!(!pool.contains(old_hash));
}

#[test]
fn admit_replace_by_fee_rejected_when_price_below_minimum_bump() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);

    let old_price = Amount::from_drop(1_000);
    let tx_old = signed_transfer(&kp, 0, old_price);
    let old_hash = tx_old.hash;
    let _ = admit(&mut pool, tx_old, &kp, &state).expect("old tx must be admitted");

    // New price just below the 10% bump threshold: 1_099 < 1_100.
    let tx_new = signed_transfer(&kp, 0, Amount::from_drop(1_099));
    let err = admit(&mut pool, tx_new, &kp, &state)
        .expect_err("replacement with insufficient bump must be rejected");

    assert!(
        matches!(err, MempoolError::ReplacementUnderpriced { min_bump_bps, .. }
            if min_bump_bps == MIN_REPLACE_BUMP_BPS),
        "expected ReplacementUnderpriced, got {err:?}"
    );
    // Pool unchanged: old tx still present.
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(old_hash));
}

#[test]
fn admit_rbf_rejection_leaves_pool_state_unchanged() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);

    let tx_old = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let old_hash = tx_old.hash;
    let _ = admit(&mut pool, tx_old, &kp, &state).expect("first admit");

    let tx_bad = signed_transfer(&kp, 0, Amount::from_drop(500)); // lower price
    let _ = admit(&mut pool, tx_bad, &kp, &state).expect_err("must fail");

    // Unchanged: still 1 tx, old hash still present.
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(old_hash));
}

// ── Capacity eviction ─────────────────────────────────────────────────────────

#[test]
fn admit_evicts_lowest_priority_when_pool_is_full_and_incoming_beats_it() {
    // Use Stake (admitted at ALL tiers including Emergency) so the circuit
    // breaker does not block the incoming tx when the pool is at 100% load.
    let (mut state, _dir) = empty_world_state();
    let kp_low = KeyPair::generate().expect("KeyPair::generate must succeed");
    let kp_high = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp_low.address(), rich());
    fund(&mut state, kp_high.address(), rich());
    let validator = Address::zero();

    let mut pool = Mempool::new(1); // capacity = 1

    // Insert low-priority Stake tx.
    let tx_low = signed_stake(&kp_low, 0, Amount::from_drop(100), validator);
    let low_hash = tx_low.hash;
    let _ = admit(&mut pool, tx_low, &kp_low, &state).expect("low-priority tx must fit");
    assert_eq!(pool.len(), 1);

    // Admit higher-priority Stake tx: must evict the low-priority one.
    let tx_high = signed_stake(&kp_high, 0, Amount::from_drop(200), validator);
    let high_hash = tx_high.hash;
    let outcome = admit(&mut pool, tx_high, &kp_high, &state)
        .expect("high-priority Stake must evict low");

    assert_eq!(outcome, AdmitOutcome::Inserted);
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(high_hash));
    assert!(!pool.contains(low_hash));
}

#[test]
fn admit_returns_pool_full_when_incoming_priority_does_not_beat_minimum() {
    // Use Stake so the circuit breaker (Emergency at 100% load) does not
    // reject the incoming tx before the PoolFull check runs.
    let (mut state, _dir) = empty_world_state();
    let kp1 = KeyPair::generate().expect("KeyPair::generate must succeed");
    let kp2 = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp1.address(), rich());
    fund(&mut state, kp2.address(), rich());
    let validator = Address::zero();

    let mut pool = Mempool::new(1);

    let tx_existing = signed_stake(&kp1, 0, Amount::from_drop(1_000), validator);
    let existing_hash = tx_existing.hash;
    let _ = admit(&mut pool, tx_existing, &kp1, &state).expect("first tx must fit");

    // Incoming has lower priority than existing → PoolFull (not eviction).
    let tx_low = signed_stake(&kp2, 0, Amount::from_drop(500), validator);
    let err = admit(&mut pool, tx_low, &kp2, &state)
        .expect_err("lower-priority Stake must be rejected when full");

    assert!(
        matches!(err, MempoolError::PoolFull { capacity: 1, .. }),
        "expected PoolFull, got {err:?}"
    );
    assert_eq!(pool.len(), 1);
    assert!(pool.contains(existing_hash));
}

#[test]
fn admit_pool_full_rejection_leaves_pool_state_unchanged() {
    let (mut state, _dir) = empty_world_state();
    let kp1 = KeyPair::generate().expect("KeyPair::generate must succeed");
    let kp2 = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp1.address(), rich());
    fund(&mut state, kp2.address(), rich());
    let validator = Address::zero();

    let mut pool = Mempool::new(1);
    let tx_existing = signed_stake(&kp1, 0, Amount::from_drop(1_000), validator);
    let existing_hash = tx_existing.hash;
    let _ = admit(&mut pool, tx_existing, &kp1, &state).expect("first tx fits");

    let tx_low = signed_stake(&kp2, 0, Amount::from_drop(100), validator);
    let _ = admit(&mut pool, tx_low, &kp2, &state).expect_err("must fail");

    assert_eq!(pool.len(), 1);
    assert!(pool.contains(existing_hash));
}

// ── Rate limiting ─────────────────────────────────────────────────────────────

#[test]
fn admit_returns_rate_limited_when_bucket_exhausted() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());

    // 1-token bucket with negligible refill — second submission is rate-limited.
    let mut pool = Mempool::with_rate_limiter(10, RateLimiter::new(1.0, 0.001));

    let tx0 = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let _ = admit(&mut pool, tx0, &kp, &state).expect("first tx must pass");

    let tx1 = signed_transfer(&kp, 1, Amount::from_drop(1_000));
    let err = admit(&mut pool, tx1, &kp, &state)
        .expect_err("second tx must be rate-limited");

    assert!(
        matches!(err, MempoolError::RateLimited { sender, .. } if sender == *kp.address()),
        "expected RateLimited, got {err:?}"
    );
    // Pool unchanged: only the first tx is present.
    assert_eq!(pool.len(), 1);
}

// ── Circuit breaker ───────────────────────────────────────────────────────────

#[test]
fn admit_returns_circuit_breaker_rejected_when_tier_excludes_type() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());

    // Capacity = 1 so pool load = 100% → Emergency tier → only Stake/Unstake.
    let mut pool = Mempool::new(1);

    // Fill the pool to trigger Emergency tier.
    let kp_filler = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp_filler.address(), rich());
    let tx_filler = signed_transfer(&kp_filler, 0, Amount::from_drop(100));
    let _ = admit(&mut pool, tx_filler, &kp_filler, &state).expect("filler must fit");

    // Now pool is 100% full (Emergency tier). ContractCall is not admitted.
    let contract = Address::zero();
    let tx_call = signed_contract_call(&kp, 0, Amount::from_drop(1_000), contract);
    let err = admit(&mut pool, tx_call, &kp, &state)
        .expect_err("ContractCall must be rejected in Emergency tier");

    assert!(
        matches!(err, MempoolError::CircuitBreakerRejected { .. }),
        "expected CircuitBreakerRejected, got {err:?}"
    );
}

// ── Validation error propagation ──────────────────────────────────────────────

#[test]
fn admit_propagates_validation_error_for_unfunded_account() {
    let (state, _dir) = empty_world_state(); // no funding
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    let mut pool = Mempool::new(10);

    // Gas limit × gas_price = 1_000_000 × 1_000 Drop = too much for zero balance.
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let err = admit(&mut pool, tx, &kp, &state)
        .expect_err("unfunded account must fail validation");

    assert!(
        matches!(err, MempoolError::InsufficientBalance { .. }),
        "expected InsufficientBalance, got {err:?}"
    );
    assert_eq!(pool.len(), 0, "pool must be unchanged on validation error");
}

#[test]
fn admit_propagates_gas_price_too_low_when_below_base_fee() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);

    let tx = signed_transfer(&kp, 0, Amount::from_drop(500));
    let base_fee = Amount::from_drop(1_000); // higher than gas_price

    let err = admit_with_base_fee(&mut pool, tx, &kp, &state, base_fee)
        .expect_err("gas below base fee must fail");

    assert!(
        matches!(err, MempoolError::GasPriceTooLow { .. }),
        "expected GasPriceTooLow, got {err:?}"
    );
    assert_eq!(pool.len(), 0);
}

// ── Remove ────────────────────────────────────────────────────────────────────

#[test]
fn remove_existing_returns_pool_entry_and_decrements_len() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let hash = tx.hash;
    let _ = admit(&mut pool, tx, &kp, &state).expect("admit");

    let entry = pool.remove(hash).expect("remove must return entry");

    assert_eq!(entry.tx.hash, hash);
    assert_eq!(pool.len(), 0);
    assert!(!pool.contains(hash));
}

#[test]
fn remove_nonexistent_returns_none_and_leaves_pool_unchanged() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let _ = admit(&mut pool, tx, &kp, &state).expect("admit");

    let result = pool.remove(Hash::zero()); // hash not in pool

    assert!(result.is_none());
    assert_eq!(pool.len(), 1, "pool unchanged after failed remove");
}

#[test]
fn remove_twice_second_call_returns_none() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let hash = tx.hash;
    let _ = admit(&mut pool, tx, &kp, &state).expect("admit");

    pool.remove(hash).expect("first remove");
    assert!(pool.remove(hash).is_none(), "second remove must return None");
}

// ── Query predicates ──────────────────────────────────────────────────────────

#[test]
fn contains_returns_true_for_admitted_tx_and_false_for_unknown() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let hash = tx.hash;
    let _ = admit(&mut pool, tx, &kp, &state).expect("admit");

    assert!(pool.contains(hash));
    assert!(!pool.contains(Hash::zero()));
}

#[test]
fn is_empty_and_len_track_pool_size() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);

    assert!(pool.is_empty());
    assert_eq!(pool.len(), 0);

    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let hash = tx.hash;
    let _ = admit(&mut pool, tx, &kp, &state).expect("admit");

    assert!(!pool.is_empty());
    assert_eq!(pool.len(), 1);

    pool.remove(hash);
    assert!(pool.is_empty());
}

#[test]
fn is_full_returns_true_at_capacity() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(1);

    assert!(!pool.is_full());
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let _ = admit(&mut pool, tx, &kp, &state).expect("admit");
    assert!(pool.is_full());
}

#[test]
fn capacity_returns_configured_value() {
    assert_eq!(Mempool::new(42).capacity(), 42);
    assert_eq!(Mempool::new(DEFAULT_CAPACITY).capacity(), DEFAULT_CAPACITY);
}

// ── Priority ordering ─────────────────────────────────────────────────────────

#[test]
fn pending_by_priority_returns_highest_priority_first() {
    let (mut state, _dir) = empty_world_state();
    let kp1 = KeyPair::generate().expect("KeyPair::generate must succeed");
    let kp2 = KeyPair::generate().expect("KeyPair::generate must succeed");
    let kp3 = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp1.address(), rich());
    fund(&mut state, kp2.address(), rich());
    fund(&mut state, kp3.address(), rich());
    let mut pool = Mempool::new(10);

    let tx_low = signed_transfer(&kp1, 0, Amount::from_drop(100));
    let tx_mid = signed_transfer(&kp2, 0, Amount::from_drop(500));
    let tx_high = signed_transfer(&kp3, 0, Amount::from_drop(1_000));
    let high_hash = tx_high.hash;
    let mid_hash = tx_mid.hash;
    let low_hash = tx_low.hash;

    let _ = admit(&mut pool, tx_low, &kp1, &state).expect("admit low");
    let _ = admit(&mut pool, tx_mid, &kp2, &state).expect("admit mid");
    let _ = admit(&mut pool, tx_high, &kp3, &state).expect("admit high");

    let ordered = pool.pending_by_priority(10);
    assert_eq!(ordered.len(), 3);
    assert_eq!(ordered[0].hash, high_hash);
    assert_eq!(ordered[1].hash, mid_hash);
    assert_eq!(ordered[2].hash, low_hash);
}

#[test]
fn pending_by_priority_respects_limit() {
    let (mut state, _dir) = empty_world_state();
    let kps: Vec<KeyPair> = (0..5).map(|_| KeyPair::generate().expect("KeyPair::generate must succeed")).collect();
    for kp in &kps {
        fund(&mut state, kp.address(), rich());
    }
    let mut pool = Mempool::new(10);
    for (i, kp) in kps.iter().enumerate() {
        let price = Amount::from_drop((i as u128 + 1) * 100);
        let tx = signed_transfer(kp, 0, price);
        let _ = admit(&mut pool, tx, kp, &state).expect("admit");
    }

    let ordered = pool.pending_by_priority(3);
    assert_eq!(ordered.len(), 3);
    // First three should be the highest-priority (prices 500, 400, 300).
    assert!(ordered[0].gas_price >= ordered[1].gas_price);
    assert!(ordered[1].gas_price >= ordered[2].gas_price);
}

#[test]
fn pending_by_priority_empty_pool_returns_empty_vec() {
    let pool = Mempool::new(10);
    assert!(pool.pending_by_priority(10).is_empty());
}

// ── Express classification ────────────────────────────────────────────────────

#[test]
fn admit_stores_eligible_express_classification_when_hint_provided() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let hash = tx.hash;
    let hint = ExpressHint::eligible();

    let _ = admit_with_hint(&mut pool, tx, &kp, &state, &hint).expect("admit with hint");

    let entry = pool.get(hash).expect("entry must exist");
    assert!(
        entry.express.is_eligible(),
        "Transfer + eligible hint must be Express-eligible"
    );
}

#[test]
fn admit_stores_fallback_express_classification_when_no_hint() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let hash = tx.hash;

    let _ = admit(&mut pool, tx, &kp, &state).expect("admit without hint");

    let entry = pool.get(hash).expect("entry must exist");
    assert!(
        !entry.express.is_eligible(),
        "No hint → MissingHint → not Express-eligible"
    );
}

// ── Block-tick maintenance ─────────────────────────────────────────────────────

#[test]
fn on_new_block_does_not_remove_recently_admitted_entries() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000));
    let hash = tx.hash;
    let _ = admit(&mut pool, tx, &kp, &state).expect("admit");

    pool.on_new_block(Instant::now());

    // Pending entry is unaffected by the block tick (it's still unconfirmed).
    assert!(pool.contains(hash));
    assert_eq!(pool.len(), 1);
}

// ── Local fee market ──────────────────────────────────────────────────────────

#[test]
fn local_base_fee_returns_global_base_for_untracked_contract() {
    let pool = Mempool::new(10);
    let contract = Address::zero();
    let global = 1_000u64;

    assert_eq!(pool.local_base_fee(&contract, global), global);
}

#[test]
fn tracked_contracts_is_zero_initially() {
    assert_eq!(Mempool::new(10).tracked_contracts(), 0);
}

// ── RBF min-price edge case ───────────────────────────────────────────────────

#[test]
fn admit_rbf_accepted_at_exactly_minimum_bump_price() {
    let (mut state, _dir) = empty_world_state();
    let kp = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp.address(), rich());
    let mut pool = Mempool::new(10);

    let old_price = Amount::from_drop(1_000);
    let tx_old = signed_transfer(&kp, 0, old_price);
    let old_hash = tx_old.hash;
    let _ = admit(&mut pool, tx_old, &kp, &state).expect("first admit");

    // Exactly at the 10% bump: 1_000 × 11_000 / 10_000 = 1_100.
    let tx_new = signed_transfer(&kp, 0, Amount::from_drop(1_100));
    let new_hash = tx_new.hash;
    let _ = admit(&mut pool, tx_new, &kp, &state).expect("exact-bump replacement must be accepted");

    assert!(pool.contains(new_hash));
    assert!(!pool.contains(old_hash));
}

// ── Seq / FIFO tiebreak ───────────────────────────────────────────────────────

#[test]
fn pending_by_priority_equal_priority_is_lifo_ordered() {
    // Two txs with identical gas_price (= identical priority, no stake).
    // Equal-priority tiebreak is LIFO: higher seq = higher BTreeMap key = first
    // in reverse iteration = second-inserted comes out first.
    // This is documented in pool.rs ("LIFO tiebreak … favors fresher fee signals").
    let (mut state, _dir) = empty_world_state();
    let kp1 = KeyPair::generate().expect("KeyPair::generate must succeed");
    let kp2 = KeyPair::generate().expect("KeyPair::generate must succeed");
    fund(&mut state, kp1.address(), rich());
    fund(&mut state, kp2.address(), rich());
    let mut pool = Mempool::new(10);
    let price = Amount::from_drop(1_000);

    let tx_first = signed_transfer(&kp1, 0, price);
    let first_hash = tx_first.hash;
    let _ = admit(&mut pool, tx_first, &kp1, &state).expect("first");

    let tx_second = signed_transfer(&kp2, 0, price);
    let second_hash = tx_second.hash;
    let _ = admit(&mut pool, tx_second, &kp2, &state).expect("second");

    let ordered = pool.pending_by_priority(10);

    assert_eq!(ordered.len(), 2);
    // LIFO: second-inserted (higher seq) comes first in the result.
    assert_eq!(
        ordered[0].hash, second_hash,
        "LIFO: last-inserted must appear first among equal-priority entries"
    );
    assert_eq!(
        ordered[1].hash, first_hash,
        "LIFO: first-inserted must appear second among equal-priority entries"
    );
}
