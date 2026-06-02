//! Tests for [`WorldState`].
//!
//! Test naming: `{action}_{condition}_{expected_outcome}` per AGENTS.md §11.3.
//! Fixtures: shared helpers per AGENTS.md §11.2 (DRY in tests).

use tempfile::tempdir;

use super::*;
use crate::{db::LemmaDb, Account};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_db() -> (LemmaDb, tempfile::TempDir) {
    let dir = tempdir().expect("tempdir: OS should always provide a temp directory");
    let db =
        LemmaDb::open(dir.path()).expect("LemmaDb::open: should succeed on a fresh temp directory");
    (db, dir)
}

fn world_state() -> (WorldState, tempfile::TempDir) {
    let (db, dir) = open_db();
    (WorldState::new(db), dir)
}

fn addr(byte: u8) -> Address {
    // Derive a deterministic test address from a fake public key.
    // Each distinct `byte` produces a distinct address.
    Address::from_public_key(&[byte; 32])
}

fn slot(byte: u8) -> Hash {
    Hash::from_bytes([byte; 32])
}

fn account_with_balance(drops: u128) -> Account {
    Account::new_eoa(Amount::from_drop(drops))
}

// ── Construction ──────────────────────────────────────────────────────────────

#[test]
fn new_world_state_has_no_state_root() {
    let (ws, _dir) = world_state();
    assert!(
        ws.state_root().is_none(),
        "fresh WorldState must have no root"
    );
}

#[test]
fn with_state_root_preserves_root() {
    let (db, _dir) = open_db();
    let root = Hash::from_bytes([0xAB; 32]);
    let ws = WorldState::with_state_root(db, root);
    assert_eq!(ws.state_root(), Some(root));
}

#[test]
fn commit_on_empty_state_returns_error() {
    let (ws, _dir) = world_state();
    assert!(
        ws.commit().is_err(),
        "commit on empty state must return an error",
    );
}

// ── Account CRUD ──────────────────────────────────────────────────────────────

#[test]
fn get_account_on_absent_address_returns_none() {
    let (ws, _dir) = world_state();
    let result = ws
        .get_account(&addr(0x01))
        .expect("get_account must not error");
    assert!(result.is_none(), "absent address must return None");
}

#[test]
fn put_then_get_account_returns_same_account() {
    let (mut ws, _dir) = world_state();
    let address = addr(0x01);
    let account = account_with_balance(1_000_000);
    ws.put_account(&address, &account)
        .expect("put_account must succeed");
    let got = ws
        .get_account(&address)
        .expect("get_account must not error");
    assert_eq!(got, Some(account));
}

#[test]
fn put_account_updates_state_root() {
    let (mut ws, _dir) = world_state();
    assert!(ws.state_root().is_none());
    ws.put_account(&addr(0x01), &account_with_balance(100))
        .expect("put_account must succeed");
    assert!(
        ws.state_root().is_some(),
        "state_root must be set after put_account"
    );
}

#[test]
fn put_account_twice_overwrites_value() {
    let (mut ws, _dir) = world_state();
    let address = addr(0x01);
    ws.put_account(&address, &account_with_balance(100))
        .expect("first put must succeed");
    let updated = account_with_balance(999);
    ws.put_account(&address, &updated)
        .expect("second put must succeed");
    let got = ws.get_account(&address).expect("get must succeed");
    assert_eq!(got, Some(updated));
}

#[test]
fn multiple_accounts_all_retrievable() {
    let (mut ws, _dir) = world_state();
    let accounts = vec![
        (addr(0x01), account_with_balance(100)),
        (addr(0x02), account_with_balance(200)),
        (addr(0x03), account_with_balance(300)),
    ];
    for (a, acc) in &accounts {
        ws.put_account(a, acc).expect("put must succeed");
    }
    for (a, expected) in &accounts {
        let got = ws.get_account(a).expect("get must succeed");
        assert_eq!(got.as_ref(), Some(expected));
    }
}

#[test]
fn get_account_on_empty_state_returns_none() {
    // Even with no state root, get_account must return None gracefully.
    let (ws, _dir) = world_state();
    let result = ws
        .get_account(&addr(0xFF))
        .expect("get_account must not error on empty state");
    assert!(result.is_none());
}

// ── Account convenience ───────────────────────────────────────────────────────

#[test]
fn get_balance_on_absent_address_returns_zero() {
    let (ws, _dir) = world_state();
    let balance = ws
        .get_balance(&addr(0x01))
        .expect("get_balance must not error");
    assert_eq!(balance, Amount::zero());
}

#[test]
fn get_balance_returns_account_balance() {
    let (mut ws, _dir) = world_state();
    let address = addr(0x01);
    ws.put_account(&address, &account_with_balance(42_000))
        .expect("put must succeed");
    let balance = ws.get_balance(&address).expect("get_balance must succeed");
    assert_eq!(balance, Amount::from_drop(42_000));
}

#[test]
fn get_nonce_on_absent_address_returns_zero() {
    let (ws, _dir) = world_state();
    let nonce = ws.get_nonce(&addr(0x01)).expect("get_nonce must not error");
    assert_eq!(nonce, 0u64);
}

#[test]
fn get_nonce_returns_account_nonce() {
    let (mut ws, _dir) = world_state();
    let address = addr(0x01);
    let mut account = account_with_balance(0);
    account.nonce = 7;
    ws.put_account(&address, &account)
        .expect("put must succeed");
    assert_eq!(ws.get_nonce(&address).expect("get_nonce must succeed"), 7);
}

#[test]
fn increment_nonce_on_absent_creates_account_with_nonce_one() {
    let (mut ws, _dir) = world_state();
    let address = addr(0x01);
    ws.increment_nonce(&address)
        .expect("increment_nonce must succeed");
    let account = ws
        .get_account(&address)
        .expect("get_account must succeed")
        .expect("account must exist after increment_nonce");
    assert_eq!(account.nonce, 1);
}

#[test]
fn increment_nonce_increments_existing_account() {
    let (mut ws, _dir) = world_state();
    let address = addr(0x01);
    let mut account = account_with_balance(500);
    account.nonce = 4;
    ws.put_account(&address, &account)
        .expect("put must succeed");
    ws.increment_nonce(&address)
        .expect("increment must succeed");
    let got = ws.get_account(&address).expect("get must succeed").unwrap();
    assert_eq!(got.nonce, 5);
    // Balance must be preserved.
    assert_eq!(got.balance, Amount::from_drop(500));
}

// ── Contract storage ──────────────────────────────────────────────────────────

#[test]
fn get_storage_on_absent_slot_returns_none() {
    let (ws, _dir) = world_state();
    let result = ws
        .get_storage(&addr(0x01), &slot(0x01))
        .expect("get_storage must not error");
    assert!(result.is_none());
}

#[test]
fn put_then_get_storage_returns_same_value() {
    let (mut ws, _dir) = world_state();
    ws.put_storage(&addr(0x01), &slot(0x01), b"stored_value")
        .expect("put_storage must succeed");
    let got = ws
        .get_storage(&addr(0x01), &slot(0x01))
        .expect("get_storage must succeed");
    assert_eq!(got, Some(b"stored_value".to_vec()));
}

#[test]
fn storage_slots_are_isolated_per_address() {
    let (mut ws, _dir) = world_state();
    ws.put_storage(&addr(0x01), &slot(0x01), b"addr1_slot1")
        .expect("put addr1 must succeed");
    ws.put_storage(&addr(0x02), &slot(0x01), b"addr2_slot1")
        .expect("put addr2 must succeed");
    assert_eq!(
        ws.get_storage(&addr(0x01), &slot(0x01))
            .expect("get addr1 must succeed"),
        Some(b"addr1_slot1".to_vec()),
    );
    assert_eq!(
        ws.get_storage(&addr(0x02), &slot(0x01))
            .expect("get addr2 must succeed"),
        Some(b"addr2_slot1".to_vec()),
    );
}

#[test]
fn storage_slots_are_isolated_per_slot() {
    let (mut ws, _dir) = world_state();
    ws.put_storage(&addr(0x01), &slot(0xAA), b"slotAA")
        .expect("put slotAA must succeed");
    ws.put_storage(&addr(0x01), &slot(0xBB), b"slotBB")
        .expect("put slotBB must succeed");
    assert_eq!(
        ws.get_storage(&addr(0x01), &slot(0xAA))
            .expect("get slotAA must succeed"),
        Some(b"slotAA".to_vec()),
    );
    assert_eq!(
        ws.get_storage(&addr(0x01), &slot(0xBB))
            .expect("get slotBB must succeed"),
        Some(b"slotBB".to_vec()),
    );
}

#[test]
fn delete_storage_removes_slot() {
    let (mut ws, _dir) = world_state();
    ws.put_storage(&addr(0x01), &slot(0x01), b"value")
        .expect("put must succeed");
    ws.delete_storage(&addr(0x01), &slot(0x01))
        .expect("delete must succeed");
    let got = ws
        .get_storage(&addr(0x01), &slot(0x01))
        .expect("get must succeed");
    assert!(got.is_none(), "slot must be absent after delete");
}

#[test]
fn delete_nonexistent_storage_slot_is_ok() {
    let (mut ws, _dir) = world_state();
    // Deleting a slot that was never written must not error.
    ws.delete_storage(&addr(0x01), &slot(0x99))
        .expect("delete of nonexistent slot must succeed");
}

// ── State root + commit ───────────────────────────────────────────────────────

#[test]
fn commit_after_put_returns_state_root() {
    let (mut ws, _dir) = world_state();
    ws.put_account(&addr(0x01), &account_with_balance(1))
        .expect("put must succeed");
    let root = ws.commit().expect("commit must succeed after put");
    assert_eq!(ws.state_root(), Some(root));
}

#[test]
fn state_root_changes_when_account_changes() {
    let (mut ws, _dir) = world_state();
    ws.put_account(&addr(0x01), &account_with_balance(100))
        .expect("put must succeed");
    let root1 = ws.state_root().unwrap();
    ws.put_account(&addr(0x01), &account_with_balance(200))
        .expect("second put must succeed");
    let root2 = ws.state_root().unwrap();
    assert_ne!(root1, root2, "state root must change when account changes");
}

#[test]
fn state_root_is_deterministic_for_same_accounts() {
    // Same set of accounts, inserted in the same order → same root.
    let (mut ws1, _dir1) = world_state();
    ws1.put_account(&addr(0x01), &account_with_balance(100))
        .expect("ws1 put addr1 must succeed");
    ws1.put_account(&addr(0x02), &account_with_balance(200))
        .expect("ws1 put addr2 must succeed");
    let root1 = ws1.state_root().expect("ws1 must have a root");

    let (mut ws2, _dir2) = world_state();
    ws2.put_account(&addr(0x01), &account_with_balance(100))
        .expect("ws2 put addr1 must succeed");
    ws2.put_account(&addr(0x02), &account_with_balance(200))
        .expect("ws2 put addr2 must succeed");
    let root2 = ws2.state_root().expect("ws2 must have a root");

    assert_eq!(
        root1, root2,
        "identical accounts must produce the same state root"
    );
}

// ── Proof ─────────────────────────────────────────────────────────────────────

#[test]
fn generate_account_proof_on_empty_state_returns_error() {
    let (ws, _dir) = world_state();
    assert!(
        ws.generate_account_proof(&addr(0x01)).is_err(),
        "proof on empty state must fail",
    );
}

#[test]
fn generate_account_proof_inclusion_verifies() {
    let (mut ws, _dir) = world_state();
    ws.put_account(&addr(0x01), &account_with_balance(999))
        .expect("put must succeed");
    let root = ws.state_root().unwrap();
    let proof = ws
        .generate_account_proof(&addr(0x01))
        .expect("proof generation must succeed");
    assert!(
        proof.value.is_some(),
        "existing account must produce inclusion proof"
    );
    proof.verify(root).expect("inclusion proof must verify");
}

#[test]
fn generate_account_proof_non_inclusion_verifies() {
    let (mut ws, _dir) = world_state();
    ws.put_account(&addr(0x01), &account_with_balance(999))
        .expect("put must succeed");
    let root = ws.state_root().unwrap();
    // addr(0x02) was never inserted.
    let proof = ws
        .generate_account_proof(&addr(0x02))
        .expect("proof generation must succeed");
    assert!(
        proof.value.is_none(),
        "absent account must produce non-inclusion proof"
    );
    proof.verify(root).expect("non-inclusion proof must verify");
}

// ── Edge cases ────────────────────────────────────────────────────────────────

#[test]
fn zero_address_account_roundtrip() {
    let (mut ws, _dir) = world_state();
    let zero = Address::zero();
    ws.put_account(&zero, &account_with_balance(0))
        .expect("put at zero address must succeed");
    let got = ws.get_account(&zero).expect("get must succeed");
    assert!(got.is_some(), "zero-address account must be retrievable");
}

#[test]
fn contract_account_roundtrip() {
    let (mut ws, _dir) = world_state();
    let address = addr(0xCC);
    let contract = Account::new_contract(Hash::from_bytes([0xDE; 32]));
    ws.put_account(&address, &contract)
        .expect("put contract must succeed");
    let got = ws.get_account(&address).expect("get must succeed").unwrap();
    assert!(got.is_contract(), "retrieved account must be a contract");
    assert_eq!(got.code_hash, contract.code_hash);
}

// ── TEST-1: nonce overflow ────────────────────────────────────────────────────

#[test]
fn increment_nonce_at_u64_max_returns_error() {
    // SEC-1: saturating_add was replaced with checked_add to prevent a silent
    // nonce overflow that would create a replay attack surface.
    let (mut ws, _dir) = world_state();
    let address = addr(0x01);
    let mut account = account_with_balance(0);
    account.nonce = u64::MAX;
    ws.put_account(&address, &account)
        .expect("put must succeed");
    let result = ws.increment_nonce(&address);
    assert!(
        result.is_err(),
        "increment_nonce at u64::MAX must return Err, not silently saturate",
    );
}

// ── TEST-2: with_state_root roundtrip ────────────────────────────────────────

#[test]
fn with_state_root_get_account_returns_persisted_account() {
    // Write an account, capture the root, then resume from that root on the
    // same DB path and verify the account is still readable.
    // RocksDB holds a file lock per process — we must drop the first WorldState
    // (and its LemmaDb) before reopening the same path.
    let dir = tempdir().expect("tempdir must succeed");
    let address = addr(0x42);
    let account = account_with_balance(12_345);
    let root = {
        let db = LemmaDb::open(dir.path()).expect("first open must succeed");
        let mut ws = WorldState::new(db);
        ws.put_account(&address, &account)
            .expect("put must succeed");
        ws.commit().expect("commit must succeed")
        // ws (and its LemmaDb) drops here — RocksDB lock released
    };
    // Reopen the same path and resume from the captured root.
    let db2 = LemmaDb::open(dir.path()).expect("reopen after first close must succeed");
    let ws2 = WorldState::with_state_root(db2, root);
    let got = ws2
        .get_account(&address)
        .expect("get must succeed on resumed state");
    assert_eq!(
        got,
        Some(account),
        "resumed WorldState must return the persisted account"
    );
}

// ── TEST-3: put_storage with empty value ─────────────────────────────────────

#[test]
fn put_storage_empty_value_is_distinct_from_absent() {
    // Doc contract: "Writing an empty value is valid (not the same as deletion)".
    let (mut ws, _dir) = world_state();
    ws.put_storage(&addr(0x01), &slot(0x01), b"")
        .expect("put with empty value must succeed");
    let got = ws
        .get_storage(&addr(0x01), &slot(0x01))
        .expect("get must succeed");
    // Empty slice is present, not None — distinct from a missing slot.
    assert_eq!(
        got,
        Some(vec![]),
        "empty value must be stored, not treated as absent"
    );
}

// ── TEST-4: delete then put storage (re-insert after delete) ─────────────────

#[test]
fn delete_then_put_storage_restores_slot() {
    let (mut ws, _dir) = world_state();
    ws.put_storage(&addr(0x01), &slot(0x01), b"original")
        .expect("initial put must succeed");
    ws.delete_storage(&addr(0x01), &slot(0x01))
        .expect("delete must succeed");
    ws.put_storage(&addr(0x01), &slot(0x01), b"restored")
        .expect("re-insert after delete must succeed");
    let got = ws
        .get_storage(&addr(0x01), &slot(0x01))
        .expect("get after re-insert must succeed");
    assert_eq!(
        got,
        Some(b"restored".to_vec()),
        "re-inserted value must be readable"
    );
}

// ── Edge cases (continued) ───────────────────────────────────────────────────

#[test]
fn storage_key_collision_different_addresses_same_slot() {
    // Prove the composite key design isolates (addr1, slotX) from (addr2, slotX).
    let (mut ws, _dir) = world_state();
    let s = slot(0x42);
    ws.put_storage(&addr(0x11), &s, b"val_11")
        .expect("put addr 0x11 must succeed");
    ws.put_storage(&addr(0x22), &s, b"val_22")
        .expect("put addr 0x22 must succeed");
    assert_eq!(
        ws.get_storage(&addr(0x11), &s)
            .expect("get addr 0x11 must succeed"),
        Some(b"val_11".to_vec()),
    );
    assert_eq!(
        ws.get_storage(&addr(0x22), &s)
            .expect("get addr 0x22 must succeed"),
        Some(b"val_22".to_vec()),
    );
}

// ── into_db ───────────────────────────────────────────────────────────────────

#[test]
fn into_db_returns_underlying_db_after_account_writes() {
    // Arrange: write an account then reclaim the DB handle.
    let (db, _dir) = open_db();
    let mut ws = WorldState::new(db);
    ws.put_account(&addr(0xAB), &account_with_balance(1_000))
        .expect("put_account must succeed");
    let root = ws.state_root();

    // Act: consume WorldState, recover the DB.
    let db = ws.into_db();

    // Assert: the DB is still functional — we can open a new WorldState on
    // the recovered handle and read the account we wrote earlier.
    let ws2 = WorldState::with_state_root(db, root.expect("root must be Some after put"));
    let acct = ws2
        .get_account(&addr(0xAB))
        .expect("get_account must succeed")
        .expect("account must exist");
    assert_eq!(acct.balance, Amount::from_drop(1_000));
}

#[test]
fn into_db_on_empty_state_returns_functional_db() {
    // Arrange: no accounts written.
    let (db, _dir) = open_db();
    let ws = WorldState::new(db);
    assert!(ws.state_root().is_none());

    // Act: reclaim DB without any writes.
    let db = ws.into_db();

    // Assert: DB is still functional for direct metadata writes.
    db.put(crate::db::CF_METADATA, b"test_key", b"test_val")
        .expect("put to metadata CF must succeed");
    let val = db
        .get(crate::db::CF_METADATA, b"test_key")
        .expect("get from metadata CF must succeed");
    assert_eq!(val, Some(b"test_val".to_vec()));
}
