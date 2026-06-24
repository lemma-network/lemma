//! Tests for [`sync`].
//!
//! Covers:
//! - [`StructuralVerifier`]: valid block, bad height, bad parent_hash,
//!   bad hash (tampered bytes), intra-block invalid, height overflow guard.
//! - [`CertifiedVerifier`]: valid QC passes, invalid sig rejected, empty
//!   signers rejected, None QC accepted (Phase-1 compat), structural
//!   failures still rejected.
//! - [`SyncTracker`]: gap detection, chunked requests, watermark
//!   idempotency, `on_tip_advanced`.
//! - [`apply_synced_block`]: apply success, stale-tip double-check,
//!   verify-error propagation, sequential apply of a range.
//! - [`compute_block_hash`]: consistency with producer convention.

use std::collections::BTreeMap;
use std::sync::Arc;

use tempfile::TempDir;
use tokio::sync::Mutex;

use lemma_core::{
    address::Address,
    amount::Amount,
    block::Block,
    hash::Hash,
    header::BlockHeader,
    signature::Signature,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
    QuorumCert,
};
use lemma_crypto::KeyPair;
use lemma_storage::{chain::ChainStore, db::LemmaDb};

use super::*;

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn open_temp_db() -> (LemmaDb, TempDir) {
    let dir = TempDir::new().expect("TempDir");
    let db = LemmaDb::open(dir.path()).expect("LemmaDb::open");
    (db, dir)
}

fn make_block(height: u64, parent_hash: Hash) -> Block {
    let vh = Hash::from_bytes([0xBB; 32]);
    let h = BlockHeader::new(
        height,
        1_700_000_000 + height,
        parent_hash,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        vh,
        vh,
        30_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("header");
    Block::new(h, vec![], vec![], None).expect("block")
}

/// Seed `n` blocks (heights 0..n) and return the hash of the last one.
fn seed_n_blocks(db: &LemmaDb, n: u64) -> Hash {
    let mut prev = Hash::zero();
    for h in 0..n {
        let block = make_block(h, prev);
        let hash = compute_block_hash(&block).expect("hash");
        ChainStore::new(db)
            .put_block(&block, hash)
            .expect("put_block");
        prev = hash;
    }
    prev
}

fn verifier() -> StructuralVerifier {
    StructuralVerifier
}

// ── CertifiedVerifier helpers ─────────────────────────────────────────────────

/// Build a single-member `ValidatorSet` from a `KeyPair`.
///
/// The member has 100% stake (trivially satisfies 2f+1 for single-validator).
fn make_single_vset(kp: &KeyPair) -> ValidatorSet {
    let pk = kp.public_key();
    let addr = *kp.address();
    let power = VotingPower(Amount::from_drop(100));
    let mut members = BTreeMap::new();
    members.insert(
        addr,
        Member {
            consensus_pubkey: ConsensusKey::from_bytes(pk.classical.clone(), pk.quantum.clone()),
            power,
        },
    );
    ValidatorSet {
        epoch: 0,
        members,
        total_power: Amount::from_drop(100),
    }
}

/// Build a block with a valid QuorumCert signed by `kp`.
///
/// The QC covers the canonical `BlockHeader::digest()` — the same digest as
/// `build_block_from_commit` (D·15b-3; docs/12-NETWORK_SYNC_SPEC §3.2).
fn make_block_with_valid_qc(height: u64, parent_hash: Hash, kp: &KeyPair) -> Block {
    let vh = Hash::from_bytes([0xBB; 32]);
    let header = BlockHeader::new(
        height,
        1_700_000_000 + height,
        parent_hash,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        vh,
        vh,
        30_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("header");

    // Compute header_digest the same way build_block_from_commit does:
    // the canonical BlockHeader::digest() (docs/12-NETWORK_SYNC_SPEC §3.2).
    let header_digest = header.digest();

    // Sign the digest with the keypair.
    let sig = kp.sign_to_lemma(header_digest.as_bytes());

    let mut signers = BTreeMap::new();
    signers.insert(*kp.address(), sig);
    let qc = QuorumCert::new(height, header_digest, signers);

    Block::new(header, vec![], vec![], Some(qc)).expect("block")
}

// ── compute_block_hash ────────────────────────────────────────────────────────

#[test]
fn compute_block_hash_is_deterministic() {
    let block = make_block(1, Hash::zero());
    let hash_a = compute_block_hash(&block).expect("hash");
    let hash_b = compute_block_hash(&block).expect("hash");
    assert_eq!(hash_a, hash_b);
}

#[test]
fn compute_block_hash_differs_for_different_heights() {
    let a = compute_block_hash(&make_block(1, Hash::zero())).expect("a");
    let b = compute_block_hash(&make_block(2, Hash::zero())).expect("b");
    assert_ne!(a, b);
}

// ── StructuralVerifier ────────────────────────────────────────────────────────

#[test]
fn verify_accepts_valid_sequential_block() {
    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    let block1 = make_block(1, g_hash);
    let result = verifier().verify(&block1, g_hash, 0);
    assert!(result.is_ok(), "valid block must pass: {result:?}");
}

#[test]
fn verify_rejects_wrong_height() {
    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    // Block at height 3 — wrong, expected 1.
    let block3 = make_block(3, g_hash);
    let err = verifier()
        .verify(&block3, g_hash, 0)
        .expect_err("must fail");
    assert!(
        matches!(err, VerifyError::HeightMismatch { expected: 1, .. }),
        "got: {err}"
    );
}

#[test]
fn verify_rejects_wrong_parent_hash() {
    let wrong_prev = Hash::from_bytes([0xDE; 32]);
    let real_prev = Hash::from_bytes([0xAD; 32]);
    // Block claims parent = wrong_prev, but local tip has real_prev.
    let block1 = make_block(1, wrong_prev);
    let err = verifier()
        .verify(&block1, real_prev, 0)
        .expect_err("must fail");
    assert!(
        matches!(err, VerifyError::ParentHashMismatch { expected, .. } if expected == real_prev),
        "got: {err}"
    );
}

#[test]
fn verify_returns_correct_hash() {
    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    let block1 = make_block(1, g_hash);
    let expected_hash = compute_block_hash(&block1).expect("expected");
    let result_hash = verifier().verify(&block1, g_hash, 0).expect("verify");
    assert_eq!(
        result_hash, expected_hash,
        "returned hash must match canonical hash"
    );
}

#[test]
fn verify_rejects_height_overflow() {
    let block = make_block(0, Hash::zero()); // height doesn't matter here
    let err = verifier()
        .verify(&block, Hash::zero(), u64::MAX)
        .expect_err("must fail");
    assert!(
        matches!(
            err,
            VerifyError::HeightOverflow {
                prev_height: u64::MAX
            }
        ),
        "got: {err}"
    );
}

// ── CertifiedVerifier ─────────────────────────────────────────────────────────

#[test]
fn certified_verifier_accepts_block_with_valid_qc() {
    // Build a block with a real QC signed by the keypair.
    // CertifiedVerifier with matching vset must accept it.
    let kp = KeyPair::generate().expect("keygen");
    let vset = make_single_vset(&kp);
    let cv = CertifiedVerifier::new(vset);

    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    let block1 = make_block_with_valid_qc(1, g_hash, &kp);

    let result = cv.verify(&block1, g_hash, 0);
    assert!(result.is_ok(), "valid QC must pass: {result:?}");
}

#[test]
fn certified_verifier_rejects_block_with_invalid_qc_sig() {
    // Build a block with a valid QC, then tamper the signature bytes.
    let kp = KeyPair::generate().expect("keygen");
    let vset = make_single_vset(&kp);
    let cv = CertifiedVerifier::new(vset);

    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");

    // Build a valid block first, then tamper the QC signature.
    let valid_block = make_block_with_valid_qc(1, g_hash, &kp);
    let mut qc = valid_block.quorum_cert.clone().expect("qc must be Some");

    // Tamper: replace the signer's signature with garbage bytes.
    let addr = *kp.address();
    qc.signers.insert(
        addr,
        Signature::Hybrid {
            classical: vec![0xFF; 64],
            quantum: vec![0xFF; 3309],
        },
    );

    let vh = Hash::from_bytes([0xBB; 32]);
    let header = BlockHeader::new(
        1,
        1_700_000_001,
        g_hash,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        vh,
        vh,
        30_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("header");
    let tampered_block = Block::new(header, vec![], vec![], Some(qc)).expect("block");

    let err = cv
        .verify(&tampered_block, g_hash, 0)
        .expect_err("tampered sig must fail");
    assert!(
        matches!(err, VerifyError::QuorumCertInvalid { .. }),
        "tampered sig must → QuorumCertInvalid, got: {err}"
    );
}

#[test]
fn certified_verifier_rejects_block_with_empty_signers() {
    // A block with Some(QuorumCert) but zero signers → InsufficientQuorum.
    let kp = KeyPair::generate().expect("keygen");
    let vset = make_single_vset(&kp);
    let cv = CertifiedVerifier::new(vset);

    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");

    let vh = Hash::from_bytes([0xBB; 32]);
    let header = BlockHeader::new(
        1,
        1_700_000_001,
        g_hash,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        vh,
        vh,
        30_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("header");

    // Compute the correct header_digest so the cert passes digest check.
    let header_digest = header.digest();

    // Empty signers — no stake accumulated.
    let qc = QuorumCert::new(1, header_digest, BTreeMap::new());
    let block = Block::new(header, vec![], vec![], Some(qc)).expect("block");

    let err = cv
        .verify(&block, g_hash, 0)
        .expect_err("empty signers must fail");
    assert!(
        matches!(err, VerifyError::QuorumCertInvalid { .. }),
        "empty signers must → QuorumCertInvalid (InsufficientQuorum), got: {err}"
    );
}

#[test]
fn certified_verifier_accepts_block_with_no_qc() {
    // Phase-1 compat: block with quorum_cert: None must be accepted.
    let kp = KeyPair::generate().expect("keygen");
    let vset = make_single_vset(&kp);
    let cv = CertifiedVerifier::new(vset);

    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    // make_block produces quorum_cert: None.
    let block1 = make_block(1, g_hash);

    let result = cv.verify(&block1, g_hash, 0);
    assert!(
        result.is_ok(),
        "None QC must be accepted (Phase-1 compat): {result:?}"
    );
}

#[test]
fn certified_verifier_still_rejects_structurally_invalid_block() {
    // A block with a valid QC but wrong parent_hash must still fail structural check.
    let kp = KeyPair::generate().expect("keygen");
    let vset = make_single_vset(&kp);
    let cv = CertifiedVerifier::new(vset);

    let real_prev = Hash::from_bytes([0xAD; 32]);
    let wrong_prev = Hash::from_bytes([0xDE; 32]);

    // Build block with wrong parent_hash (structural failure).
    let block1 = make_block_with_valid_qc(1, wrong_prev, &kp);

    let err = cv
        .verify(&block1, real_prev, 0)
        .expect_err("wrong parent_hash must fail");
    assert!(
        matches!(err, VerifyError::ParentHashMismatch { expected, .. } if expected == real_prev),
        "structural check must fire before QC check, got: {err}"
    );
}

// ── ApplyOutcome::Stale ───────────────────────────────────────────────────────

#[tokio::test]
async fn apply_synced_block_returns_stale_when_tip_advances_under_lock() {
    // Test the double-check pattern in apply_synced_block:
    //   Step 1 (outside lock): read tip = 0, verify block1 → OK
    //   Step 3 (inside lock):  re-read tip = 1 (producer won race) → Stale
    //
    // We hold the write-lock before spawning apply_synced_block.
    // The task executes: reads tip=0, verifies OK, then tries to acquire the
    // lock — blocks because the test holds it.
    // While the task waits, the test writes block1 (advancing tip to 1) and
    // releases the lock. The task wakes up, re-checks tip=1 ≠ prev=0 → Stale.
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 1); // genesis (tip = 0)
    let db = Arc::new(db);
    let lock = Arc::new(Mutex::new(()));

    let tip_hash = ChainStore::new(&db).tip().unwrap().unwrap().1;
    let block1 = make_block(1, tip_hash);
    let hash1 = compute_block_hash(&block1).expect("hash1");

    // Acquire lock BEFORE spawning apply — task will block at step 3.
    let guard = lock.lock().await;

    let db2 = Arc::clone(&db);
    let lock2 = Arc::clone(&lock);
    let block2 = block1.clone();
    let task = tokio::spawn(async move {
        apply_synced_block(&block2, &db2, &lock2, &StructuralVerifier).await
    });

    // Yield so the task runs steps 1-2 (sync) and then blocks at lock.lock().await.
    tokio::task::yield_now().await;

    // Now advance the tip while holding the lock (simulate producer winning race).
    ChainStore::new(&db)
        .put_block(&block1, hash1)
        .expect("producer write");

    // Release lock — task wakes up, re-reads tip=1 ≠ prev_height=0 → Stale.
    drop(guard);

    let outcome = task
        .await
        .expect("task must not panic")
        .expect("must not error");
    assert_eq!(
        outcome,
        ApplyOutcome::Stale,
        "must be Stale when tip advanced under lock"
    );
    assert_eq!(ChainStore::new(&db).latest_height().unwrap().unwrap(), 1);
}

// ── SyncTracker ───────────────────────────────────────────────────────────────

#[test]
fn tracker_no_request_when_at_tip() {
    let mut t = SyncTracker::new();
    t.observe(5, libp2p::PeerId::random());
    // local_tip == highest_seen → no gap.
    assert!(t.next_request(5, 256).is_none());
}

#[test]
fn tracker_no_request_when_one_ahead() {
    // highest_seen = local_tip + 1 exactly → not a gap (the block might arrive
    // immediately via gossip and be applied directly).
    let mut t = SyncTracker::new();
    t.observe(5, libp2p::PeerId::random());
    assert!(
        t.next_request(4, 256).is_none(),
        "exactly +1 is not a range-sync gap"
    );
}

#[test]
fn tracker_requests_range_when_gap_detected() {
    let mut t = SyncTracker::new();
    t.observe(10, libp2p::PeerId::random());
    // local_tip = 2, highest_seen = 10 → gap at 3..=10
    let req = t.next_request(2, 256).expect("must produce request");
    assert_eq!(req, (3, 10));
}

#[test]
fn tracker_clamps_to_max_range() {
    let mut t = SyncTracker::new();
    t.observe(1000, libp2p::PeerId::random());
    // max_range = 256 → request at most 256 blocks
    let req = t.next_request(0, 256).expect("must produce request");
    assert_eq!(req.0, 1);
    assert_eq!(req.1, 256, "must clamp to max_range");
}

#[test]
fn tracker_does_not_re_request_inflight_range() {
    let mut t = SyncTracker::new();
    t.observe(10, libp2p::PeerId::random());
    t.next_request(2, 256); // issues request for 3..=10
                            // Second call: same gap, same highest_seen — must not re-issue.
    assert!(
        t.next_request(2, 256).is_none(),
        "must not re-request already-in-flight range"
    );
}

#[test]
fn tracker_on_tip_advanced_clears_watermark() {
    let mut t = SyncTracker::new();
    t.observe(10, libp2p::PeerId::random());
    t.next_request(2, 256); // requested_up_to = 10
                            // Tip advances to 10 (all blocks applied).
    t.on_tip_advanced(10);
    // New higher block arrives at 15.
    t.observe(15, libp2p::PeerId::random());
    // Now can request again.
    let req = t.next_request(10, 256).expect("must produce new request");
    assert_eq!(req, (11, 15));
}

#[test]
fn tracker_chunked_requests_advance_watermark() {
    let mut t = SyncTracker::new();
    t.observe(500, libp2p::PeerId::random());
    // First chunk: max_range = 100 → requests 1..=100
    let r1 = t.next_request(0, 100).expect("chunk 1");
    assert_eq!(r1, (1, 100));
    // Tip advances to 100, reset.
    t.on_tip_advanced(100);
    // Second chunk: requests 101..=200
    let r2 = t.next_request(100, 100).expect("chunk 2");
    assert_eq!(r2, (101, 200));
}

// ── SyncTracker: short-served chunk ──────────────────────────────────────────

#[test]
fn tracker_retries_after_partial_response_via_on_tip_advanced() {
    // Simulate: gap is 1..=300, max_range=256.
    // First chunk: request 1..=256.
    // Partial response: only 1..=100 served (peer had a gap at 101).
    // Tip advances to 100 via on_tip_advanced.
    // next_request should issue 101..=256 (still within the original requested
    // watermark), then after on_tip_advanced(256) → 257..=300.
    let mut t = SyncTracker::new();
    let peer = libp2p::PeerId::random();
    t.observe(300, peer);

    // Chunk 1 requested: 1..=256.
    let r1 = t.next_request(0, 256).expect("chunk 1");
    assert_eq!(r1, (1, 256));

    // Partial: only 1..=100 applied. requested_up_to stays 256.
    // next_request(100, 256): highest_seen(300) > requested_up_to(256) → issue 101..=256.
    t.on_tip_advanced(100);
    let r2 = t.next_request(100, 256).expect("retry of remainder");
    assert_eq!(
        r2,
        (101, 300),
        "must retry remaining gap after partial response"
    );
}

// ── apply_synced_block ────────────────────────────────────────────────────────

#[tokio::test]
async fn apply_synced_block_applies_valid_block() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 1); // genesis at height 0
    let db = Arc::new(db);
    let lock = Arc::new(Mutex::new(()));

    let tip_hash = ChainStore::new(&db).tip().unwrap().unwrap().1;
    let block1 = make_block(1, tip_hash);

    let outcome = apply_synced_block(&block1, &db, &lock, &verifier())
        .await
        .expect("apply must succeed");

    assert!(
        matches!(outcome, ApplyOutcome::Applied { height: 1, .. }),
        "got: {outcome:?}"
    );
    assert_eq!(ChainStore::new(&db).latest_height().unwrap().unwrap(), 1);
}

#[tokio::test]
async fn apply_synced_block_returns_verify_error_on_bad_parent() {
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 1);
    let db = Arc::new(db);
    let lock = Arc::new(Mutex::new(()));

    // Wrong parent_hash.
    let block1 = make_block(1, Hash::from_bytes([0xFF; 32]));
    let err = apply_synced_block(&block1, &db, &lock, &verifier())
        .await
        .expect_err("must error on bad parent");
    assert!(matches!(err, NodeError::Verify(_)), "got: {err}");
    // Tip must not advance.
    assert_eq!(ChainStore::new(&db).latest_height().unwrap().unwrap(), 0);
}

#[tokio::test]
async fn apply_synced_block_returns_no_tip_on_uninitialised_chain() {
    let (db, _dir) = open_temp_db();
    let db = Arc::new(db);
    let lock = Arc::new(Mutex::new(()));
    let block = make_block(1, Hash::zero());
    let outcome = apply_synced_block(&block, &db, &lock, &verifier())
        .await
        .expect("must not error");
    assert_eq!(outcome, ApplyOutcome::NoTip);
}

#[tokio::test]
async fn apply_synced_block_sequential_range_syncs_correctly() {
    // Simulate syncing blocks 1..=5 in order — mirrors a range-response apply.
    let (db_src, _dir_src) = open_temp_db();
    let (db_dst, _dir_dst) = open_temp_db();

    // Source: seed 6 blocks (0..5).
    seed_n_blocks(&db_src, 6);
    // Destination: only genesis (height 0).
    seed_n_blocks(&db_dst, 1);

    let db_dst = Arc::new(db_dst);
    let lock = Arc::new(Mutex::new(()));

    for h in 1u64..=5 {
        let block = ChainStore::new(&db_src)
            .get_block_by_height(h)
            .expect("get")
            .expect("block must exist in source");

        let outcome = apply_synced_block(&block, &db_dst, &lock, &verifier())
            .await
            .expect("apply must succeed");

        assert!(
            matches!(outcome, ApplyOutcome::Applied { height, .. } if height == h),
            "height {h}: got {outcome:?}"
        );
    }

    assert_eq!(
        ChainStore::new(&db_dst).latest_height().unwrap().unwrap(),
        5,
        "destination must be fully synced"
    );
}

#[tokio::test]
async fn apply_synced_block_returns_invalid_qc_on_bad_cert() {
    // CertifiedVerifier: a block with an invalid QC must return NodeError::InvalidQC.
    let (db, _dir) = open_temp_db();
    seed_n_blocks(&db, 1); // genesis at height 0
    let db = Arc::new(db);
    let lock = Arc::new(Mutex::new(()));

    let kp = KeyPair::generate().expect("keygen");
    let vset = make_single_vset(&kp);
    let cv = CertifiedVerifier::new(vset);

    let tip_hash = ChainStore::new(&db).tip().unwrap().unwrap().1;

    // Build a block with a QC that has empty signers (InsufficientQuorum).
    let vh = Hash::from_bytes([0xBB; 32]);
    let header = BlockHeader::new(
        1,
        1_700_000_001,
        tip_hash,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        vh,
        vh,
        30_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("header");
    let header_digest = header.digest();
    let qc = QuorumCert::new(1, header_digest, BTreeMap::new());
    let block = Block::new(header, vec![], vec![], Some(qc)).expect("block");

    let err = apply_synced_block(&block, &db, &lock, &cv)
        .await
        .expect_err("invalid QC must error");
    assert!(
        matches!(err, NodeError::InvalidQC(_)),
        "must be NodeError::InvalidQC, got: {err}"
    );
    // Tip must not advance.
    assert_eq!(ChainStore::new(&db).latest_height().unwrap().unwrap(), 0);
}

// ── Protocol version detection (docs/17-VERSIONING_SPEC §7.3) ────────────────

/// Build a block with a specific `protocol_version` for detection tests.
fn make_block_with_protocol_version(
    height: u64,
    parent_hash: Hash,
    protocol_version: u32,
) -> Block {
    let vh = Hash::from_bytes([0xBB; 32]);
    let h = BlockHeader::new(
        height,
        1_700_000_000 + height,
        parent_hash,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        protocol_version,
        0,
        Hash::zero(),
        vh,
        vh,
        30_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("header");
    Block::new(h, vec![], vec![], None).expect("block")
}

#[test]
fn structural_verifier_rejects_too_new_protocol_version() {
    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    // Block with protocol_version = 99 — far beyond MAX_SUPPORTED.
    let block = make_block_with_protocol_version(1, g_hash, 99);
    let err = verifier()
        .verify(&block, g_hash, 0)
        .expect_err("must reject too-new protocol version");
    assert!(
        matches!(
            err,
            VerifyError::UnsupportedProtocolVersion { seen: 99, max: 1 }
        ),
        "got: {err}"
    );
}

#[test]
fn structural_verifier_accepts_current_protocol_version() {
    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    // Block with protocol_version = 1 (current MAX_SUPPORTED).
    let block = make_block_with_protocol_version(1, g_hash, 1);
    let result = verifier().verify(&block, g_hash, 0);
    assert!(
        result.is_ok(),
        "current protocol version must be accepted: {result:?}"
    );
}

#[test]
fn structural_verifier_accepts_lower_protocol_version() {
    // When MAX = 1, protocol_version = 1 is the lowest valid value.
    // This test proves lower-or-equal acceptance (trivially, since 1 <= 1).
    let genesis = make_block(0, Hash::zero());
    let g_hash = compute_block_hash(&genesis).expect("g_hash");
    let block = make_block_with_protocol_version(1, g_hash, 1);
    let result = verifier().verify(&block, g_hash, 0);
    assert!(
        result.is_ok(),
        "protocol_version <= MAX must be accepted: {result:?}"
    );
}

#[test]
fn protocol_version_check_precedes_other_structural_checks() {
    // Block is too-new AND has a wrong parent_hash + wrong height.
    // Check 0 must win — proves detection is unconditionally first (§7.3).
    let block = make_block_with_protocol_version(42, Hash::from_bytes([0xEE; 32]), 99);
    let err = verifier()
        .verify(&block, Hash::zero(), 5) // deliberately wrong prev_hash/height
        .expect_err("must reject");
    assert!(
        matches!(
            err,
            VerifyError::UnsupportedProtocolVersion { seen: 99, max: 1 }
        ),
        "version check must precede parent/height checks; got: {err}"
    );
}
