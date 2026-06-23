//! Tests for `lemma_mempool::validation`.
//!
//! Uses real `KeyPair`, `WorldState` (tempfile RocksDB), and
//! `sign_transaction` so every test exercises the production code path.
//!
//! Covers:
//! - Happy path: a properly signed, funded transaction passes.
//! - Every rejection branch (one test per `MempoolError` variant that
//!   `validate_transaction` can return).
//! - Arithmetic edge cases: overflow in cost calculation.
//! - Account-not-found handled as zero nonce/balance.

use std::sync::Arc;

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
    validation::{validate_transaction, ValidationContext, MAX_NONCE_GAP, MAX_TX_SIZE},
};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Open a fresh `WorldState` backed by a temp RocksDB directory.
/// Returns `(WorldState, TempDir)` — keep `TempDir` alive for the test.
fn empty_world_state() -> (WorldState, TempDir) {
    let dir = TempDir::new().expect("tempdir must be created");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open must succeed on a fresh tempdir");
    (WorldState::new(Arc::new(db)), dir)
}

/// A `ValidationContext` with `chain_id = 1` and zero base fee.
fn default_ctx() -> ValidationContext {
    ValidationContext {
        chain_id: 1,
        base_fee: Amount::zero(),
    }
}

/// Build a minimal signed `Transfer` transaction.
///
/// `nonce`, `value`, `gas_price` are parameters so individual tests can
/// vary them without re-creating a full transaction from scratch.
fn signed_transfer(
    kp: &KeyPair,
    nonce: u64,
    gas_price: Amount,
    value: Amount,
    chain_id: u64,
) -> Transaction {
    let to = Address::zero();
    let mut tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(to),
        nonce,
        chain_id,
        value,
        1_000_000,
        gas_price,
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("test transaction construction must succeed");
    sign_transaction(&mut tx, kp).expect("signing must succeed");
    tx
}

/// Fund `address` with `balance` Drop in `state`.
fn fund(state: &mut WorldState, address: &Address, balance: Amount) {
    let account = Account::new_eoa(balance);
    state
        .put_account(address, &account)
        .expect("put_account must succeed in test");
}

// ── Happy path ────────────────────────────────────────────────────────────────

#[test]
fn validate_accepts_valid_signed_funded_transaction() {
    let kp = KeyPair::generate().expect("keygen");
    let (mut state, _dir) = empty_world_state();
    // Fund the sender with 1 LEM (10^18 Drop) — more than enough for gas + value.
    fund(
        &mut state,
        kp.address(),
        Amount::from_lem(1).expect("1 LEM"),
    );
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000), Amount::zero(), 1);
    assert!(validate_transaction(&tx, &kp.public_key(), &state, &default_ctx()).is_ok());
}

#[test]
fn validate_accepts_transaction_for_new_account_with_balance() {
    // A brand-new account (not in state) treated as nonce=0, balance=0.
    // With no balance, it can only pass if value=0 and gas cost=0.
    let kp = KeyPair::generate().expect("keygen");
    let (state, _dir) = empty_world_state();
    // gas_price=0 and value=0 => cost=0, so balance=0 is sufficient.
    let tx = signed_transfer(&kp, 0, Amount::zero(), Amount::zero(), 1);
    assert!(
        validate_transaction(&tx, &kp.public_key(), &state, &default_ctx()).is_ok(),
        "zero-cost tx on a new account must pass"
    );
}

// ── Step 1: gas_limit = 0 ─────────────────────────────────────────────────────

#[test]
fn validate_rejects_zero_gas_limit() {
    let kp = KeyPair::generate().expect("keygen");
    let (state, _dir) = empty_world_state();
    // Transaction::new itself rejects gas_limit=0, so we build the struct
    // directly (all fields are pub) to test that the *mempool* also rejects it.
    // sign_transaction works regardless of gas_limit value.
    let mut tx = Transaction {
        hash: Hash::zero(),
        sender: *kp.address(),
        to: Some(Address::zero()),
        nonce: 0,
        chain_id: 1,
        value: Amount::zero(),
        gas_limit: 0,
        gas_price: Amount::zero(),
        tx_type: TxType::Transfer,
        data: vec![],
        signature: Signature::Unsigned,
        session_key: None,
        owner_cosignature: None,
    };
    sign_transaction(&mut tx, &kp).expect("signing must succeed with gas_limit=0");
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("must reject zero gas_limit");
    assert!(
        matches!(err, MempoolError::ZeroGasLimit { .. }),
        "unexpected err: {err}"
    );
}

// ── Step 2: chain_id mismatch ─────────────────────────────────────────────────

#[test]
fn validate_rejects_wrong_chain_id() {
    let kp = KeyPair::generate().expect("keygen");
    let (state, _dir) = empty_world_state();
    // Sign for chain 99; node expects chain 1.
    let tx = signed_transfer(&kp, 0, Amount::zero(), Amount::zero(), 99);
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("must reject wrong chain_id");
    assert!(
        matches!(
            err,
            MempoolError::ChainIdMismatch {
                tx_chain_id: 99,
                expected_chain_id: 1,
                ..
            }
        ),
        "unexpected err: {err}"
    );
}

// ── Step 3: size cap ──────────────────────────────────────────────────────────

#[test]
fn validate_rejects_oversized_transaction() {
    let kp = KeyPair::generate().expect("keygen");
    let (state, _dir) = empty_world_state();
    // Attach data that will push the serialized size well over MAX_TX_SIZE.
    let mut tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::zero()),
        0,
        1,
        Amount::zero(),
        1_000_000,
        Amount::zero(),
        TxType::ContractCall,
        vec![0xAB; MAX_TX_SIZE + 1],
        Signature::Unsigned,
    )
    .expect("construction must succeed");
    sign_transaction(&mut tx, &kp).expect("signing must succeed");
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("must reject oversized transaction");
    assert!(
        matches!(err, MempoolError::TransactionTooLarge { .. }),
        "unexpected err: {err}"
    );
}

// ── Step 4: pubkey/address mismatch ──────────────────────────────────────────

#[test]
fn validate_rejects_pubkey_not_matching_sender() {
    let kp_real = KeyPair::generate().expect("keygen real");
    let kp_attacker = KeyPair::generate().expect("keygen attacker");
    let (state, _dir) = empty_world_state();
    // tx.sender = kp_real's address, but we supply kp_attacker's pubkey.
    let tx = signed_transfer(&kp_real, 0, Amount::zero(), Amount::zero(), 1);
    let err = validate_transaction(&tx, &kp_attacker.public_key(), &state, &default_ctx())
        .expect_err("must reject pubkey/address mismatch");
    assert!(
        matches!(err, MempoolError::InvalidSignature { .. }),
        "unexpected err: {err}"
    );
}

// ── Step 5: invalid signature ─────────────────────────────────────────────────

#[test]
fn validate_rejects_unsigned_transaction() {
    let kp = KeyPair::generate().expect("keygen");
    let (state, _dir) = empty_world_state();
    // Build a tx with Signature::Unsigned — do NOT call sign_transaction.
    let tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::zero()),
        0,
        1,
        Amount::zero(),
        1_000_000,
        Amount::zero(),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("construction must succeed");
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("must reject unsigned transaction");
    assert!(
        matches!(err, MempoolError::InvalidSignature { .. }),
        "unexpected err: {err}"
    );
}

#[test]
fn validate_rejects_tampered_signature() {
    let kp = KeyPair::generate().expect("keygen");
    let (state, _dir) = empty_world_state();
    let mut tx = signed_transfer(&kp, 0, Amount::zero(), Amount::zero(), 1);
    // Corrupt the classical signature bytes.
    if let Signature::Hybrid {
        ref mut classical, ..
    } = tx.signature
    {
        if let Some(b) = classical.first_mut() {
            *b = b.wrapping_add(1);
        }
    }
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("must reject tampered signature");
    assert!(
        matches!(err, MempoolError::InvalidSignature { .. }),
        "unexpected err: {err}"
    );
}

// ── Step 6: nonce too low ─────────────────────────────────────────────────────

#[test]
fn validate_rejects_stale_nonce() {
    let kp = KeyPair::generate().expect("keygen");
    let (mut state, _dir) = empty_world_state();
    // Account already has nonce=5 on chain.
    let mut account = Account::new_eoa(Amount::from_lem(1).expect("1 LEM"));
    account.nonce = 5;
    state
        .put_account(kp.address(), &account)
        .expect("put_account");
    // Tx nonce=3 < account nonce=5 → stale.
    let tx = signed_transfer(&kp, 3, Amount::zero(), Amount::zero(), 1);
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("must reject stale nonce");
    assert!(
        matches!(
            err,
            MempoolError::NonceTooLow {
                tx_nonce: 3,
                account_nonce: 5,
                ..
            }
        ),
        "unexpected err: {err}"
    );
}

// ── Step 7: nonce gap too large ───────────────────────────────────────────────

#[test]
fn validate_rejects_nonce_gap_exceeding_max() {
    let kp = KeyPair::generate().expect("keygen");
    let (mut state, _dir) = empty_world_state();
    fund(
        &mut state,
        kp.address(),
        Amount::from_lem(1).expect("1 LEM"),
    );
    // account nonce=0, tx nonce=MAX_NONCE_GAP+1 → gap too large.
    let far_nonce = MAX_NONCE_GAP + 1;
    let tx = signed_transfer(&kp, far_nonce, Amount::zero(), Amount::zero(), 1);
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("must reject nonce gap > MAX_NONCE_GAP");
    assert!(
        matches!(
            err,
            MempoolError::NonceGapTooLarge {
                max_gap: MAX_NONCE_GAP,
                ..
            }
        ),
        "unexpected err: {err}"
    );
}

#[test]
fn validate_accepts_nonce_at_exact_max_gap() {
    let kp = KeyPair::generate().expect("keygen");
    let (mut state, _dir) = empty_world_state();
    // Fund generously so balance doesn't fail.
    fund(
        &mut state,
        kp.address(),
        Amount::from_lem(100).expect("100 LEM"),
    );
    // nonce = MAX_NONCE_GAP is exactly the boundary — must be accepted.
    let tx = signed_transfer(&kp, MAX_NONCE_GAP, Amount::zero(), Amount::zero(), 1);
    assert!(
        validate_transaction(&tx, &kp.public_key(), &state, &default_ctx()).is_ok(),
        "nonce at exactly MAX_NONCE_GAP must be accepted"
    );
}

// ── Step 8: insufficient balance ─────────────────────────────────────────────

#[test]
fn validate_rejects_insufficient_balance_for_gas() {
    let kp = KeyPair::generate().expect("keygen");
    let (mut state, _dir) = empty_world_state();
    // Fund with only 999 Drop; gas_price=1_000 × gas_limit=1 = 1_000 Drop needed.
    fund(&mut state, kp.address(), Amount::from_drop(999));
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1_000), Amount::zero(), 1);
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("must reject when balance < gas cost");
    assert!(
        matches!(err, MempoolError::InsufficientBalance { .. }),
        "unexpected err: {err}"
    );
}

#[test]
fn validate_rejects_insufficient_balance_for_value() {
    let kp = KeyPair::generate().expect("keygen");
    let (mut state, _dir) = empty_world_state();
    // Fund with 500 Drop, send 1_000 Drop value (gas_price=0 so cost = value).
    fund(&mut state, kp.address(), Amount::from_drop(500));
    let tx = signed_transfer(&kp, 0, Amount::zero(), Amount::from_drop(1_000), 1);
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("must reject when balance < value");
    assert!(
        matches!(err, MempoolError::InsufficientBalance { .. }),
        "unexpected err: {err}"
    );
}

#[test]
fn validate_rejects_balance_overflow_as_insufficient() {
    let kp = KeyPair::generate().expect("keygen");
    let (mut state, _dir) = empty_world_state();
    // u128::MAX gas_price causes overflow in gas_cost; treated as InsufficientBalance.
    fund(&mut state, kp.address(), Amount::from_drop(u128::MAX));
    let mut tx = Transaction::new(
        Hash::zero(),
        *kp.address(),
        Some(Address::zero()),
        0,
        1,
        Amount::zero(),
        2,                                    // gas_limit = 2
        Amount::from_drop(u128::MAX / 2 + 1), // gas_price s.t. 2 × gas_price overflows
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("construction must succeed");
    sign_transaction(&mut tx, &kp).expect("signing must succeed");
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("overflow must yield InsufficientBalance, not panic");
    assert!(
        matches!(err, MempoolError::InsufficientBalance { .. }),
        "unexpected err: {err}"
    );
}

// ── Step 9: gas price below base fee ─────────────────────────────────────────

#[test]
fn validate_rejects_gas_price_below_base_fee() {
    let kp = KeyPair::generate().expect("keygen");
    let (mut state, _dir) = empty_world_state();
    fund(
        &mut state,
        kp.address(),
        Amount::from_lem(1).expect("1 LEM"),
    );
    let tx = signed_transfer(&kp, 0, Amount::from_drop(100), Amount::zero(), 1);
    // Base fee = 500 > gas_price = 100.
    let ctx = ValidationContext {
        chain_id: 1,
        base_fee: Amount::from_drop(500),
    };
    let err = validate_transaction(&tx, &kp.public_key(), &state, &ctx)
        .expect_err("must reject gas_price < base_fee");
    assert!(
        matches!(
            err,
            MempoolError::GasPriceTooLow {
                provided: 100,
                base_fee: 500,
                ..
            }
        ),
        "unexpected err: {err}"
    );
}

#[test]
fn validate_accepts_gas_price_exactly_at_base_fee() {
    let kp = KeyPair::generate().expect("keygen");
    let (mut state, _dir) = empty_world_state();
    fund(
        &mut state,
        kp.address(),
        Amount::from_lem(1).expect("1 LEM"),
    );
    let tx = signed_transfer(&kp, 0, Amount::from_drop(500), Amount::zero(), 1);
    let ctx = ValidationContext {
        chain_id: 1,
        base_fee: Amount::from_drop(500),
    };
    assert!(
        validate_transaction(&tx, &kp.public_key(), &state, &ctx).is_ok(),
        "gas_price == base_fee must be accepted"
    );
}

// ── Account-not-found edge cases ──────────────────────────────────────────────

#[test]
fn validate_treats_missing_account_as_zero_nonce_and_balance() {
    let kp = KeyPair::generate().expect("keygen");
    let (state, _dir) = empty_world_state(); // sender not in state
                                             // nonce=0, value=0, gas_price=0 → total cost=0 → zero balance is enough.
    let tx = signed_transfer(&kp, 0, Amount::zero(), Amount::zero(), 1);
    assert!(
        validate_transaction(&tx, &kp.public_key(), &state, &default_ctx()).is_ok(),
        "zero-cost tx on missing account must pass"
    );
}

#[test]
fn validate_rejects_missing_account_with_nonzero_cost() {
    let kp = KeyPair::generate().expect("keygen");
    let (state, _dir) = empty_world_state(); // sender not in state
    let tx = signed_transfer(&kp, 0, Amount::from_drop(1), Amount::zero(), 1);
    let err = validate_transaction(&tx, &kp.public_key(), &state, &default_ctx())
        .expect_err("missing account with nonzero cost must fail balance check");
    assert!(
        matches!(err, MempoolError::InsufficientBalance { available: 0, .. }),
        "unexpected err: {err}"
    );
}
