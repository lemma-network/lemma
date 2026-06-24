//! Tests for [`WorldStateView`].
//!
//! Verifies that `ContractStateView` reads delegate correctly to the committed
//! world state (balance, nonce, storage) and that the view is correctly rooted
//! at the given `state_root`.
//!
//! AGENTS §11: separate tests.rs, `{action}_{outcome}` naming, AAA pattern.

use std::sync::Arc;

use tempfile::TempDir;

use lemma_core::{address::Address, amount::Amount, hash::Hash};
use lemma_storage::{account::Account, db::LemmaDb, state::WorldState};
use lemma_vm::state::ContractStateView;

use super::WorldStateView;

// ── Fixtures ──────────────────────────────────────────────────────────────────

/// Open a fresh tempdir database, write accounts, return (Arc<LemmaDb>, state_root, TempDir).
fn seeded_db(accounts: &[(Address, Amount)]) -> (Arc<LemmaDb>, Hash, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(LemmaDb::open(dir.path()).expect("LemmaDb::open"));
    let mut ws = WorldState::new(Arc::clone(&db));
    for (addr, balance) in accounts {
        ws.put_account(addr, &Account::new_eoa(*balance))
            .expect("put_account");
    }
    let root = ws.state_root().unwrap_or(Hash::zero());
    (db, root, dir)
}

/// Commit a contract to world state exactly as `apply_one_write`'s deploy path
/// does (CF_CODE bytecode + account stamped with `code_hash`), then return the
/// committed `(Arc<LemmaDb>, state_root, TempDir)`.
///
/// The returned state root is what a later block (N+1) would root a fresh
/// [`WorldStateView`] at — the cross-block resolution path that the V-1 bug
/// (`code()` returning `None`) silently broke.
fn deployed_db(contract: &Address, bytecode: &[u8]) -> (Arc<LemmaDb>, Hash, TempDir) {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(LemmaDb::open(dir.path()).expect("LemmaDb::open"));
    let mut ws = WorldState::new(Arc::clone(&db));

    // Mirror apply_one_write (block_exec.rs): hash → CF_CODE → stamp account.
    let code_hash = lemma_crypto::hash_bytes(bytecode);
    ws.put_code(&code_hash, bytecode).expect("put_code");
    ws.put_account(contract, &Account::new_contract(code_hash))
        .expect("put_account");

    let root = ws.state_root().unwrap_or(Hash::zero());
    (db, root, dir)
}

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

// ── balance ───────────────────────────────────────────────────────────────────

#[test]
fn balance_returns_seeded_value() {
    let a = addr(1);
    let (db, root, _dir) = seeded_db(&[(a, Amount::from_drop(1_000))]);
    let view = WorldStateView::new(db, root);

    assert_eq!(view.balance(&a), Amount::from_drop(1_000));
}

#[test]
fn balance_returns_zero_for_unknown_address() {
    let (db, root, _dir) = seeded_db(&[]);
    let view = WorldStateView::new(db, root);

    assert_eq!(view.balance(&addr(0xFF)), Amount::zero());
}

#[test]
fn balance_returns_zero_on_empty_state_root() {
    let dir = TempDir::new().expect("tempdir");
    let db = Arc::new(LemmaDb::open(dir.path()).expect("LemmaDb::open"));
    // Hash::zero() → WorldState::new (empty trie)
    let view = WorldStateView::new(db, Hash::zero());

    assert_eq!(view.balance(&addr(1)), Amount::zero());
}

// ── nonce ─────────────────────────────────────────────────────────────────────

#[test]
fn nonce_returns_zero_for_new_account() {
    let a = addr(2);
    let (db, root, _dir) = seeded_db(&[(a, Amount::from_drop(500))]);
    let view = WorldStateView::new(db, root);

    // Account::new_eoa starts with nonce = 0.
    assert_eq!(view.nonce(&a), 0);
}

#[test]
fn nonce_returns_zero_for_unknown_address() {
    let (db, root, _dir) = seeded_db(&[]);
    let view = WorldStateView::new(db, root);

    assert_eq!(view.nonce(&addr(0xAB)), 0);
}

// ── code ──────────────────────────────────────────────────────────────────────

#[test]
fn code_returns_none_for_eoa() {
    let a = addr(3);
    let (db, root, _dir) = seeded_db(&[(a, Amount::from_drop(1))]);
    let view = WorldStateView::new(db, root);

    // An EOA has a zero code_hash → code() returns None (fast path, no CF_CODE
    // lookup). Only contract accounts (non-zero code_hash) resolve bytecode.
    assert!(view.code(&a).is_none());
}

#[test]
fn code_resolves_committed_bytecode_for_contract() {
    // V-1 regression: a contract deployed in block N must be callable in block
    // N+1. We commit the contract (CF_CODE + account.code_hash) and then resolve
    // its bytecode through a *freshly constructed* WorldStateView rooted at the
    // committed state_root — exactly the cross-block path that returned None.
    let c = addr(0x42);
    let bytecode = b"\x00asm\x01\x00\x00\x00".to_vec(); // minimal WASM header bytes
    let (db, root, _dir) = deployed_db(&c, &bytecode);

    // Separate view instance — models block N+1 reading block N's committed state.
    let view = WorldStateView::new(db, root);

    assert_eq!(
        view.code(&c),
        Some(bytecode),
        "code() must resolve committed bytecode via account.code_hash → CF_CODE"
    );
}

#[test]
fn code_returns_none_for_unknown_address() {
    // An address never written has no account → no code_hash → None (graceful,
    // no panic) even when the view is rooted at a non-empty state.
    let c = addr(0x42);
    let (db, root, _dir) = deployed_db(&c, b"\x00asm\x01\x00\x00\x00");
    let view = WorldStateView::new(db, root);

    assert!(view.code(&addr(0x99)).is_none());
}

#[test]
fn has_code_hash_true_for_committed_bytecode() {
    // Companion to code(): the content-addressed CF_CODE presence check used by
    // deploy-dedup must also see the committed bytecode across a fresh view.
    let c = addr(0x42);
    let bytecode = b"\x00asm\x01\x00\x00\x00".to_vec();
    let code_hash = lemma_crypto::hash_bytes(&bytecode);
    let (db, root, _dir) = deployed_db(&c, &bytecode);
    let view = WorldStateView::new(db, root);

    assert!(view.has_code_hash(&code_hash));
    assert!(!view.has_code_hash(&Hash::zero()));
}

// ── storage read ──────────────────────────────────────────────────────────────

#[test]
fn read_returns_none_for_empty_storage() {
    let a = addr(4);
    let (db, root, _dir) = seeded_db(&[(a, Amount::from_drop(100))]);
    let view = WorldStateView::new(db, root);

    // No storage slots written for this contract → None.
    assert!(view.read(&a, b"some_key").is_none());
}

#[test]
fn exists_returns_false_for_empty_storage() {
    let a = addr(5);
    let (db, root, _dir) = seeded_db(&[(a, Amount::from_drop(100))]);
    let view = WorldStateView::new(db, root);

    assert!(!view.exists(&a, b"missing_slot"));
}

// ── multiple accounts ─────────────────────────────────────────────────────────

#[test]
fn balance_is_correct_for_multiple_accounts() {
    let a = addr(10);
    let b = addr(11);
    let (db, root, _dir) =
        seeded_db(&[(a, Amount::from_drop(1_000)), (b, Amount::from_drop(2_000))]);
    let view = WorldStateView::new(db, root);

    assert_eq!(view.balance(&a), Amount::from_drop(1_000));
    assert_eq!(view.balance(&b), Amount::from_drop(2_000));
    // Third account not in trie → zero.
    assert_eq!(view.balance(&addr(12)), Amount::zero());
}
