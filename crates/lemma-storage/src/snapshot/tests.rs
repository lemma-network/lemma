//! Tests for [`SnapshotManager`] and [`SnapshotMetadata`].
//!
//! Test naming: `{action}_{condition}_{expected_outcome}` per AGENTS.md §11.3.
//! Fixtures: shared helpers per AGENTS.md §11.2 DRY rule.

use std::path::Path;
use std::sync::Arc;

use tempfile::tempdir;

use super::*;
use crate::{db::LemmaDb, state::WorldState, Account, StorageError};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_db(dir: &Path) -> LemmaDb {
    LemmaDb::open(dir).expect("LemmaDb::open must succeed on a fresh temp directory")
}

fn manager(dir: &Path) -> SnapshotManager {
    SnapshotManager::new(dir, 3).expect("SnapshotManager::new must succeed")
}

fn meta(height: u64) -> SnapshotMetadata {
    SnapshotMetadata::new(height, lemma_core::Hash::from_bytes([height as u8; 32]))
}

// ── LemmaDb::create_checkpoint ────────────────────────────────────────────────

#[test]
fn create_checkpoint_produces_openable_db_directory() {
    let db_dir = tempdir().expect("tempdir must succeed");
    let ckpt_dir = tempdir().expect("tempdir for checkpoint must succeed");
    let db = open_db(db_dir.path());

    // Checkpoint the fresh (empty) database.
    db.create_checkpoint(ckpt_dir.path().join("ckpt"))
        .expect("create_checkpoint must succeed");

    // The resulting directory must be openable as a LemmaDb.
    let _db2 = LemmaDb::open(ckpt_dir.path().join("ckpt"))
        .expect("checkpoint directory must be openable as LemmaDb");
}

#[test]
fn create_checkpoint_captures_written_data() {
    use lemma_core::{Address, Amount};

    let db_dir = tempdir().expect("tempdir must succeed");
    let ckpt_dir = tempdir().expect("tempdir for checkpoint must succeed");

    // Write an account, then checkpoint.
    let state_root = {
        let db = open_db(db_dir.path());
        let mut ws = WorldState::new(Arc::new(db));
        let addr = Address::from_public_key(&[0x42u8; 32]);
        let account = Account::new_eoa(Amount::from_drop(9999));
        ws.put_account(&addr, &account).expect("put must succeed");
        ws.commit().expect("commit must succeed")
    };

    // Reopen DB and take checkpoint.
    {
        let db = open_db(db_dir.path());
        db.create_checkpoint(ckpt_dir.path().join("ckpt"))
            .expect("create_checkpoint must succeed");
    }

    // Open checkpoint and verify the account is readable.
    let ckpt_db = open_db(&ckpt_dir.path().join("ckpt"));
    let ws = WorldState::with_state_root(Arc::new(ckpt_db), state_root);
    let addr = lemma_core::Address::from_public_key(&[0x42u8; 32]);
    let got = ws.get_account(&addr).expect("get_account must succeed");
    assert!(got.is_some(), "checkpoint must capture the written account");
}

// ── SnapshotMetadata ──────────────────────────────────────────────────────────

#[test]
fn snapshot_metadata_new_sets_height_and_state_root() {
    let root = lemma_core::Hash::from_bytes([0xAB; 32]);
    let m = SnapshotMetadata::new(42, root);
    assert_eq!(m.height, 42);
    assert_eq!(m.state_root, root);
}

#[test]
fn snapshot_metadata_json_roundtrip() {
    let m = meta(1000);
    let json = serde_json::to_string(&m).expect("serialisation must succeed");
    let decoded: SnapshotMetadata =
        serde_json::from_str(&json).expect("deserialisation must succeed");
    assert_eq!(m, decoded);
}

// ── SnapshotManager::new ──────────────────────────────────────────────────────

#[test]
fn new_creates_snapshot_directory_if_missing() {
    let base = tempdir().expect("tempdir must succeed");
    let snap_dir = base.path().join("snapshots");
    assert!(!snap_dir.exists(), "directory must not exist before new()");
    SnapshotManager::new(&snap_dir, 3).expect("SnapshotManager::new must create the directory");
    assert!(
        snap_dir.is_dir(),
        "SnapshotManager::new must create the directory"
    );
}

#[test]
fn new_succeeds_if_directory_already_exists() {
    let base = tempdir().expect("tempdir must succeed");
    std::fs::create_dir(base.path().join("snapshots")).expect("mkdir must succeed");
    SnapshotManager::new(base.path().join("snapshots"), 3)
        .expect("SnapshotManager::new must succeed on existing directory");
}

// ── SnapshotManager::create_snapshot ─────────────────────────────────────────

#[test]
fn create_snapshot_returns_valid_path() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    let mgr = manager(snap_dir.path());

    let path = mgr
        .create_snapshot(&db, &meta(1000))
        .expect("create_snapshot must succeed");

    assert!(path.is_dir(), "returned path must be a directory");
    assert!(
        path.join("metadata.json").is_file(),
        "metadata.json must exist in snapshot directory",
    );
}

#[test]
fn create_snapshot_checkpoint_is_openable() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    let mgr = manager(snap_dir.path());

    let path = mgr
        .create_snapshot(&db, &meta(500))
        .expect("create_snapshot must succeed");

    let _db2 = LemmaDb::open(&path).expect("snapshot directory must be openable as LemmaDb");
}

#[test]
fn create_snapshot_overwrites_existing_snapshot_at_same_height() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    let mgr = manager(snap_dir.path());

    // First snapshot at height 100.
    let m1 = SnapshotMetadata {
        height: 100,
        state_root: lemma_core::Hash::from_bytes([0x01; 32]),
        timestamp: 1000,
    };
    mgr.create_snapshot(&db, &m1)
        .expect("first create must succeed");

    // Second snapshot at same height — different state_root.
    let m2 = SnapshotMetadata {
        height: 100,
        state_root: lemma_core::Hash::from_bytes([0x02; 32]),
        timestamp: 2000,
    };
    mgr.create_snapshot(&db, &m2)
        .expect("second create must succeed");

    // The metadata must reflect the second write.
    let loaded = mgr
        .snapshot_metadata(100)
        .expect("snapshot_metadata must succeed")
        .expect("snapshot must exist");
    assert_eq!(loaded.state_root, m2.state_root);
}

// ── SnapshotManager::list_snapshots ──────────────────────────────────────────

#[test]
fn list_snapshots_on_empty_dir_returns_empty() {
    let snap_dir = tempdir().expect("tempdir must succeed");
    let mgr = manager(snap_dir.path());
    let list = mgr
        .list_snapshots()
        .expect("list must succeed on empty dir");
    assert!(list.is_empty());
}

#[test]
fn list_snapshots_returns_all_sorted_newest_first() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    // max_snapshots=0 to avoid pruning during this test.
    let mgr = SnapshotManager::new(snap_dir.path(), 0).expect("new must succeed");

    mgr.create_snapshot(&db, &meta(1000))
        .expect("create 1000 must succeed");
    mgr.create_snapshot(&db, &meta(2000))
        .expect("create 2000 must succeed");
    mgr.create_snapshot(&db, &meta(500))
        .expect("create 500 must succeed");

    let list = mgr.list_snapshots().expect("list must succeed");
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].height, 2000, "newest first");
    assert_eq!(list[1].height, 1000);
    assert_eq!(list[2].height, 500, "oldest last");
}

// ── SnapshotManager::latest_snapshot ─────────────────────────────────────────

#[test]
fn latest_snapshot_on_empty_dir_returns_none() {
    let snap_dir = tempdir().expect("tempdir must succeed");
    let mgr = manager(snap_dir.path());
    let latest = mgr.latest_snapshot().expect("latest must succeed");
    assert!(latest.is_none());
}

#[test]
fn latest_snapshot_returns_highest_height() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    let mgr = SnapshotManager::new(snap_dir.path(), 0).expect("new must succeed");

    mgr.create_snapshot(&db, &meta(100))
        .expect("create 100 must succeed");
    mgr.create_snapshot(&db, &meta(300))
        .expect("create 300 must succeed");
    mgr.create_snapshot(&db, &meta(200))
        .expect("create 200 must succeed");

    let latest = mgr
        .latest_snapshot()
        .expect("latest must succeed")
        .expect("must be Some");
    assert_eq!(latest.height, 300);
}

// ── SnapshotManager::snapshot_metadata / restore_path ────────────────────────

#[test]
fn snapshot_metadata_returns_none_for_nonexistent_height() {
    let snap_dir = tempdir().expect("tempdir must succeed");
    let mgr = manager(snap_dir.path());
    let result = mgr.snapshot_metadata(9999).expect("must not error");
    assert!(result.is_none());
}

#[test]
fn snapshot_metadata_returns_correct_data_for_existing_height() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    let mgr = manager(snap_dir.path());
    let m = meta(42);

    mgr.create_snapshot(&db, &m).expect("create must succeed");

    let loaded = mgr
        .snapshot_metadata(42)
        .expect("must not error")
        .expect("must be Some");
    assert_eq!(loaded.height, m.height);
    assert_eq!(loaded.state_root, m.state_root);
}

#[test]
fn restore_path_points_to_openable_db() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    let mgr = manager(snap_dir.path());

    mgr.create_snapshot(&db, &meta(777))
        .expect("create must succeed");

    let path = mgr
        .restore_path(777)
        .expect("restore_path must succeed for existing snapshot");
    let _db2 = LemmaDb::open(&path).expect("restore_path must point to an openable LemmaDb");
}

#[test]
fn restore_path_for_nonexistent_height_returns_error() {
    let snap_dir = tempdir().expect("tempdir must succeed");
    let mgr = manager(snap_dir.path());
    let result = mgr.restore_path(9999);
    assert!(
        matches!(result, Err(StorageError::RestoreFailed { .. })),
        "restore_path for nonexistent height must return RestoreFailed, got: {result:?}",
    );
}

// ── T1: Writes after checkpoint are NOT visible in the checkpoint ─────────────

#[test]
fn create_checkpoint_excludes_writes_made_after_checkpoint() {
    use lemma_core::{Address, Amount};

    let db_dir = tempdir().expect("tempdir for db must succeed");
    let ckpt_dir = tempdir().expect("tempdir for checkpoint must succeed");

    let addr_before = Address::from_public_key(&[0x01u8; 32]);
    let addr_after = Address::from_public_key(&[0x02u8; 32]);

    // Write addr_before, commit, take checkpoint, then write addr_after.
    let state_root = {
        let db = open_db(db_dir.path());
        let mut ws = WorldState::new(Arc::new(db));
        ws.put_account(&addr_before, &Account::new_eoa(Amount::from_drop(1)))
            .expect("put addr_before must succeed");
        ws.commit().expect("commit must succeed")
    };

    let ckpt_path = ckpt_dir.path().join("ckpt");
    {
        let db = open_db(db_dir.path());
        db.create_checkpoint(&ckpt_path)
            .expect("checkpoint must succeed");
        // Write addr_after AFTER the checkpoint — must not appear in checkpoint.
        let mut ws = WorldState::with_state_root(Arc::new(db), state_root);
        ws.put_account(&addr_after, &Account::new_eoa(Amount::from_drop(2)))
            .expect("put addr_after must succeed");
    }

    let ckpt_db = open_db(&ckpt_path);
    let ws = WorldState::with_state_root(Arc::new(ckpt_db), state_root);
    assert!(
        ws.get_account(&addr_before)
            .expect("get must succeed")
            .is_some(),
        "checkpoint must contain writes made BEFORE checkpoint",
    );
    assert!(
        ws.get_account(&addr_after)
            .expect("get must succeed")
            .is_none(),
        "checkpoint must NOT contain writes made AFTER checkpoint",
    );
}

// ── T2: list_snapshots skips orphaned dirs (missing metadata.json) ────────────

#[test]
fn list_snapshots_skips_directory_with_missing_metadata_json() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    let mgr = SnapshotManager::new(snap_dir.path(), 0).expect("new must succeed");

    // Create a valid snapshot at height 100.
    mgr.create_snapshot(&db, &meta(100))
        .expect("create must succeed");

    // Manually create a snapshot directory at height 200 with no metadata.json
    // (simulates a crash mid-write before metadata was written).
    let orphan = snap_dir.path().join("snapshot_000000000200");
    std::fs::create_dir(&orphan).expect("mkdir must succeed");

    // list_snapshots must return only the valid snapshot, silently skipping orphan.
    let list = mgr.list_snapshots().expect("list must succeed");
    assert_eq!(
        list.len(),
        1,
        "orphaned directory without metadata.json must be skipped"
    );
    assert_eq!(list[0].height, 100);
}

// ── T3: prune with exactly max_snapshots (boundary — nothing pruned) ──────────

#[test]
fn prune_with_exactly_max_snapshots_removes_nothing() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    // Use max_snapshots=0 to prevent auto-pruning during creates.
    let mgr_no_prune = SnapshotManager::new(snap_dir.path(), 0).expect("new must succeed");
    mgr_no_prune
        .create_snapshot(&db, &meta(100))
        .expect("create 100 must succeed");
    mgr_no_prune
        .create_snapshot(&db, &meta(200))
        .expect("create 200 must succeed");
    mgr_no_prune
        .create_snapshot(&db, &meta(300))
        .expect("create 300 must succeed");

    // Now prune with max_snapshots=3 — exactly 3 exist, so nothing should be removed.
    let mgr3 = SnapshotManager::new(snap_dir.path(), 3).expect("new must succeed");
    let removed = mgr3.prune().expect("prune must succeed");
    assert_eq!(
        removed, 0,
        "exactly max_snapshots snapshots exist — nothing should be pruned"
    );
    assert_eq!(mgr3.list_snapshots().expect("list must succeed").len(), 3);
}

// ── SnapshotManager::prune ────────────────────────────────────────────────────

#[test]
fn prune_removes_oldest_beyond_max() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    // max_snapshots=2: only keep the 2 newest.
    let mgr = SnapshotManager::new(snap_dir.path(), 2).expect("new must succeed");

    mgr.create_snapshot(&db, &meta(100))
        .expect("create 100 must succeed");
    mgr.create_snapshot(&db, &meta(200))
        .expect("create 200 must succeed");
    mgr.create_snapshot(&db, &meta(300))
        .expect("create 300 must succeed");

    // After the third create, prune runs automatically. Only 200 and 300 remain.
    let list = mgr.list_snapshots().expect("list must succeed");
    assert_eq!(list.len(), 2, "only 2 snapshots must remain after pruning");
    let heights: Vec<u64> = list.iter().map(|m| m.height).collect();
    assert!(heights.contains(&300), "height 300 must be kept");
    assert!(heights.contains(&200), "height 200 must be kept");
    assert!(!heights.contains(&100), "height 100 must be pruned");
}

#[test]
fn prune_on_empty_dir_returns_zero_removed() {
    let snap_dir = tempdir().expect("tempdir must succeed");
    let mgr = manager(snap_dir.path());
    let removed = mgr.prune().expect("prune must succeed on empty dir");
    assert_eq!(removed, 0);
}

#[test]
fn prune_with_max_zero_removes_nothing() {
    let db_dir = tempdir().expect("tempdir for db must succeed");
    let snap_dir = tempdir().expect("tempdir for snapshots must succeed");
    let db = open_db(db_dir.path());
    let mgr = SnapshotManager::new(snap_dir.path(), 0).expect("new must succeed");

    mgr.create_snapshot(&db, &meta(100))
        .expect("create must succeed");
    mgr.create_snapshot(&db, &meta(200))
        .expect("create must succeed");
    mgr.create_snapshot(&db, &meta(300))
        .expect("create must succeed");

    let removed = mgr.prune().expect("prune with max=0 must succeed");
    assert_eq!(
        removed, 0,
        "max_snapshots=0 means unlimited — nothing pruned"
    );
    assert_eq!(mgr.list_snapshots().expect("list must succeed").len(), 3);
}
