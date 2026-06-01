//! Tests for `lemma_consensus::dag::graph`.
//!
//! Integration-level tests: insert outcomes, suspension, epoch buffering,
//! GC, ancestor queries, cascade unsuspension, equivocation detection.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    signature::Signature,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};

use crate::{
    dag::block::{DagBlock, DagBlockBody, DagBlockRef},
    dag::graph::{Dag, InsertOutcome, MAX_NEXT_EPOCH_BUFFER, MAX_SUSPENDED},
    error::ConsensusError,
};

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}


fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32])
}

/// 4-validator equal-stake committee (total = 40, quorum = 3 of 4 @ 30 stake).
fn vset_4() -> ValidatorSet {
    let power = VotingPower(Amount::from_drop(10));
    let mut members = BTreeMap::new();
    for n in 1u8..=4 {
        members.insert(addr(n), Member { consensus_pubkey: dummy_key(), power });
    }
    ValidatorSet { epoch: 1, members, total_power: Amount::from_drop(40) }
}

/// Create a DagBlock at the given round with the provided ancestor refs.
fn make_round_block(round: u64, author_n: u8, ancestors: Vec<DagBlockRef>) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch: 1,
            round,
            author: addr(author_n),
            timestamp_ms: 0,
            ancestors,
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    )
}

/// Insert n genesis blocks and return them (with actual computed digests).
///
/// Use the returned blocks' `.reference()` values as ancestor refs in
/// round-1 blocks — `hash(n)` digests do NOT match `compute_digest(...)`.
fn insert_genesis_set(dag: &mut Dag, vset: &ValidatorSet, n: u8) -> Vec<DagBlock> {
    (1..=n)
        .map(|i| {
            let b = genesis_block(i);
            assert_eq!(dag.insert(b.clone(), vset, true).unwrap(), InsertOutcome::Accepted);
            b
        })
        .collect()
}

/// Genesis-round block (no ancestors required, exempt from rule 5).
fn genesis_block(author_n: u8) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch: 1, round: 0, author: addr(author_n), timestamp_ms: 0,
            ancestors: vec![], payload: vec![], commit_votes: vec![],
        },
        Signature::Unsigned,
    )
}

/// Insert n genesis blocks (authors 1..=n) into dag, all accepted.
fn seed_genesis(dag: &mut Dag, vset: &ValidatorSet, n: u8) {
    for i in 1..=n {
        let b = genesis_block(i);
        assert_eq!(dag.insert(b, vset, true).unwrap(), InsertOutcome::Accepted);
    }
}

// ── Basic insert ──────────────────────────────────────────────────────────────

#[test]
fn insert_genesis_block_accepted() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    let block = genesis_block(1);
    assert_eq!(dag.insert(block, &vset, true).unwrap(), InsertOutcome::Accepted);
    assert_eq!(dag.len(), 1);
}

#[test]
fn insert_duplicate_block_returns_accepted_idempotent() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    let block = genesis_block(1);
    dag.insert(block.clone(), &vset, true).unwrap();
    // Second insert of same block = idempotent
    assert_eq!(dag.insert(block, &vset, true).unwrap(), InsertOutcome::Accepted);
    assert_eq!(dag.len(), 1); // still only 1 block
}

// ── Rule 1: epoch ─────────────────────────────────────────────────────────────

#[test]
fn insert_past_epoch_rejected_with_epoch_mismatch() {
    let vset = vset_4();
    let mut dag = Dag::new(2); // dag epoch=2
    let block = DagBlock::new(
        DagBlockBody { epoch: 1, round: 0, author: addr(1), timestamp_ms: 0,
            ancestors: vec![], payload: vec![], commit_votes: vec![] },
        Signature::Unsigned,
    );
    let err = dag.insert(block, &vset, true).unwrap_err();
    assert!(matches!(err, ConsensusError::EpochMismatch { expected: 2, got: 1 }));
}

#[test]
fn insert_next_epoch_block_buffered() {
    let mut vset = vset_4(); // epoch=1
    vset.epoch = 1;
    let mut dag = Dag::new(1);
    let block = DagBlock::new(
        DagBlockBody { epoch: 2, round: 0, author: addr(1), timestamp_ms: 0,
            ancestors: vec![], payload: vec![], commit_votes: vec![] },
        Signature::Unsigned,
    );
    assert_eq!(dag.insert(block, &vset, true).unwrap(), InsertOutcome::NextEpochBuffered);
    assert_eq!(dag.len(), 0); // not in accepted store
}

#[test]
fn insert_far_future_epoch_rejected() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    let block = DagBlock::new(
        DagBlockBody { epoch: 5, round: 0, author: addr(1), timestamp_ms: 0,
            ancestors: vec![], payload: vec![], commit_votes: vec![] },
        Signature::Unsigned,
    );
    let err = dag.insert(block, &vset, true).unwrap_err();
    assert!(matches!(err, ConsensusError::EpochMismatch { expected: 1, got: 5 }));
}

// ── Rule 2: author / sig ──────────────────────────────────────────────────────

#[test]
fn insert_unknown_author_rejected() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    // addr(9) not in vset_4
    let block = DagBlock::new(
        DagBlockBody { epoch: 1, round: 0, author: addr(9), timestamp_ms: 0,
            ancestors: vec![], payload: vec![], commit_votes: vec![] },
        Signature::Unsigned,
    );
    let err = dag.insert(block, &vset, true).unwrap_err();
    assert!(matches!(err, ConsensusError::UnknownAuthor { .. }));
}

#[test]
fn insert_bad_signature_rejected() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    let block = genesis_block(1);
    let err = dag.insert(block, &vset, false).unwrap_err(); // sig_ok = false
    assert!(matches!(err, ConsensusError::InvalidSignature { .. }));
}

// ── Rule 3: GC ────────────────────────────────────────────────────────────────

#[test]
fn insert_block_below_gc_boundary_rejected() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    // Push committed round high enough so gc_round > 0
    dag.set_last_committed_round(50); // gc_round = 50 - 30 = 20
    let block = DagBlock::new(
        DagBlockBody { epoch: 1, round: 10, author: addr(1), timestamp_ms: 0,
            ancestors: vec![], payload: vec![], commit_votes: vec![] },
        Signature::Unsigned,
    );
    let err = dag.insert(block, &vset, true).unwrap_err();
    assert!(matches!(err, ConsensusError::BelowGcBoundary { round: 10, gc_round: 20 }));
}

// ── Rule 4: suspension ────────────────────────────────────────────────────────

#[test]
fn insert_block_with_missing_ancestor_suspended() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    // Create genesis blocks to get real digests, but don't insert yet.
    let g: Vec<DagBlock> = (1u8..=3).map(genesis_block).collect();
    // Build round-1 block with REAL ancestor refs (not hash(n) placeholders).
    let block = make_round_block(1, 4, g.iter().map(|b| b.reference()).collect());
    assert_eq!(dag.insert(block, &vset, true).unwrap(), InsertOutcome::Suspended);
    assert_eq!(dag.len(), 0); // not in accepted store
}

#[test]
fn insert_ancestor_after_suspension_unsuspends_block() {
    let vset = vset_4();
    let mut dag = Dag::new(1);

    // Create genesis blocks FIRST to capture their real digests.
    let g: Vec<DagBlock> = (1u8..=3).map(genesis_block).collect();
    let g_refs: Vec<DagBlockRef> = g.iter().map(|b| b.reference()).collect();

    // Build round-1 block referencing real genesis refs (ancestors not in DAG yet).
    let round1 = make_round_block(1, 4, g_refs);
    let round1_ref = round1.reference();
    assert_eq!(dag.insert(round1, &vset, true).unwrap(), InsertOutcome::Suspended);

    // Now insert the 3 missing ancestors — round-1 block auto-unsuspends.
    for gb in g {
        dag.insert(gb, &vset, true).unwrap();
    }

    assert!(dag.contains(&round1_ref), "block should be accepted after ancestors arrive");
    assert_eq!(dag.len(), 4); // 3 genesis + 1 promoted
}

#[test]
fn cascade_unsuspension_when_chain_of_dependencies_arrives() {
    let vset = vset_4();
    let mut dag = Dag::new(1);

    // Pre-compute all block refs before any insertion.
    let g: Vec<DagBlock> = (1u8..=3).map(genesis_block).collect();
    let g_refs: Vec<DagBlockRef> = g.iter().map(|b| b.reference()).collect();

    // Round-1 blocks: r1 (author 4), sib1 (author 1), sib2 (author 2).
    // All depend on genesis blocks g1/g2/g3.
    let r1 = make_round_block(1, 4, g_refs.clone());
    let sib1 = make_round_block(1, 1, g_refs.clone());
    let sib2 = make_round_block(1, 2, g_refs.clone());
    let (r1_ref, sib1_ref, sib2_ref) = (r1.reference(), sib1.reference(), sib2.reference());

    // Round-2 block: depends on r1, sib1, sib2 at round 1.
    let r2 = make_round_block(2, 3, vec![r1_ref, sib1_ref, sib2_ref]);
    let r2_ref = r2.reference();

    // Insert all blocks BEFORE any ancestors exist → all suspended.
    for b in [r1, sib1, sib2, r2] {
        dag.insert(b, &vset, true).unwrap();
    }
    assert_eq!(dag.len(), 0, "nothing accepted yet");

    // Insert genesis blocks → cascade: genesis → r1/sib1/sib2 → r2.
    for gb in g {
        dag.insert(gb, &vset, true).unwrap();
    }

    assert!(dag.contains(&r1_ref),   "r1 must be cascade-accepted");
    assert!(dag.contains(&sib1_ref), "sib1 must be cascade-accepted");
    assert!(dag.contains(&sib2_ref), "sib2 must be cascade-accepted");
    assert!(dag.contains(&r2_ref),   "r2 must be cascade-accepted");
    assert_eq!(dag.len(), 7); // 3 genesis + r1 + sib1 + sib2 + r2
}

// ── Rule 5: strong-link quorum ────────────────────────────────────────────────

#[test]
fn insert_insufficient_strong_links_rejected_after_ancestors_present() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    // Use insert_genesis_set to get real DagBlock refs with actual compute_digest values.
    let genesis = insert_genesis_set(&mut dag, &vset, 4);

    // Only 2 of 4 strong links at round 0 → 20 stake < quorum (need >20).
    let weak = make_round_block(1, 4, vec![genesis[0].reference(), genesis[1].reference()]);
    let err = dag.insert(weak, &vset, true).unwrap_err();
    assert!(matches!(err, ConsensusError::InsufficientStrongLinks { .. }));
}

#[test]
fn insert_genesis_round_accepted_without_strong_links() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    // Round 0, no ancestors needed.
    assert_eq!(dag.insert(genesis_block(1), &vset, true).unwrap(), InsertOutcome::Accepted);
}

// ── Rule 6: equivocation ──────────────────────────────────────────────────────

#[test]
fn insert_equivocating_block_returns_equivocation_outcome() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    let block_a = genesis_block(1);
    dag.insert(block_a.clone(), &vset, true).unwrap();

    // Same slot, different body → equivocation.
    let block_b = DagBlock::new(
        DagBlockBody { epoch: 1, round: 0, author: addr(1), timestamp_ms: 999,
            ancestors: vec![], payload: vec![], commit_votes: vec![] },
        Signature::Unsigned,
    );
    let outcome = dag.insert(block_b.clone(), &vset, true).unwrap();
    assert!(matches!(outcome, InsertOutcome::Equivocation { .. }));

    if let InsertOutcome::Equivocation { first, second, .. } = outcome {
        assert_eq!(first, block_a.digest);
        assert_eq!(second, block_b.digest);
        assert_ne!(first, second);
    }
    // Equivocating block NOT in DAG.
    assert!(!dag.contains(&block_b.reference()));
}

// ── Ancestor queries ──────────────────────────────────────────────────────────

#[test]
fn block_at_slot_returns_ref_of_accepted_block() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    let block = genesis_block(2);
    let expected_ref = block.reference();
    dag.insert(block, &vset, true).unwrap();
    let slot = crate::dag::block::Slot::new(0, addr(2));
    assert_eq!(dag.block_at_slot(slot), Some(expected_ref));
}

#[test]
fn block_at_slot_returns_none_for_unknown_slot() {
    let dag = Dag::new(1);
    let slot = crate::dag::block::Slot::new(99, addr(1));
    assert_eq!(dag.block_at_slot(slot), None);
}

#[test]
fn blocks_at_round_returns_all_accepted_at_round() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    for n in 1u8..=3 {
        dag.insert(genesis_block(n), &vset, true).unwrap();
    }
    let count = dag.blocks_at_round(0).count();
    assert_eq!(count, 3);
}

#[test]
fn contains_true_for_accepted_false_for_absent() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    let block = genesis_block(1);
    let r = block.reference();
    assert!(!dag.contains(&r));
    dag.insert(block, &vset, true).unwrap();
    assert!(dag.contains(&r));
}

#[test]
fn highest_accepted_round_tracks_maximum() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    assert_eq!(dag.highest_accepted_round(), 0);

    // Insert genesis blocks and use their real refs for round-1 block.
    let genesis = insert_genesis_set(&mut dag, &vset, 3);
    assert_eq!(dag.highest_accepted_round(), 0);

    let r1 = make_round_block(1, 4, genesis.iter().map(|b| b.reference()).collect());
    dag.insert(r1, &vset, true).unwrap();
    assert_eq!(dag.highest_accepted_round(), 1);
}

// ── GC ────────────────────────────────────────────────────────────────────────

#[test]
fn gc_round_computed_from_last_committed_and_gc_depth() {
    let dag = Dag::new(1);
    assert_eq!(dag.gc_round(), 0); // 0.saturating_sub(30) = 0
    let mut dag2 = Dag::new(1);
    dag2.set_last_committed_round(50);
    assert_eq!(dag2.gc_round(), 20); // 50 - 30
}

#[test]
fn set_last_committed_round_drops_old_blocks() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    let b = genesis_block(1);
    let r = b.reference();
    dag.insert(b, &vset, true).unwrap();
    assert!(dag.contains(&r));

    // Push gc_round past round 0 → block should be GC'd.
    dag.set_last_committed_round(35); // gc_round = 35 - 30 = 5 > 0
    assert!(!dag.contains(&r), "round-0 block should be GC'd after set_last_committed_round(35)");
    assert_eq!(dag.len(), 0);
}

#[test]
fn set_last_committed_round_is_monotonic() {
    let vset = vset_4();
    let mut dag = Dag::new(1);
    seed_genesis(&mut dag, &vset, 3);
    dag.set_last_committed_round(50);
    let len_after = dag.len();
    // Calling with lower value should be ignored.
    dag.set_last_committed_round(10);
    assert_eq!(dag.len(), len_after); // no change
}

// ── Epoch advance ─────────────────────────────────────────────────────────────

#[test]
fn advance_epoch_returns_buffered_blocks_and_clears_buffer() {
    let mut vset = vset_4();
    vset.epoch = 1;
    let mut dag = Dag::new(1);

    // Buffer a next-epoch block.
    let next_epoch_block = DagBlock::new(
        DagBlockBody { epoch: 2, round: 0, author: addr(1), timestamp_ms: 0,
            ancestors: vec![], payload: vec![], commit_votes: vec![] },
        Signature::Unsigned,
    );
    dag.insert(next_epoch_block.clone(), &vset, true).unwrap();

    // Advance epoch.
    let returned = dag.advance_epoch(2);
    assert_eq!(returned.len(), 1);
    assert_eq!(returned[0].digest, next_epoch_block.digest);
    assert_eq!(dag.epoch(), 2);

    // Buffer should be cleared.
    let returned_again = dag.advance_epoch(3);
    assert_eq!(returned_again.len(), 0);
}

#[test]
fn advance_epoch_wrong_epoch_number_returns_empty() {
    let mut dag = Dag::new(1);
    let returned = dag.advance_epoch(3); // not epoch+1
    assert!(returned.is_empty());
    assert_eq!(dag.epoch(), 1); // unchanged
}

// ── Buffer size limits and Dropped outcome ────────────────────────────────────

#[test]
fn next_epoch_buffer_bounded_returns_dropped_when_full() {
    let mut vset = vset_4();
    vset.epoch = 1;
    let mut dag = Dag::new(1);

    // Fill the buffer with MAX_NEXT_EPOCH_BUFFER distinct blocks.
    let mut buffered_count = 0usize;
    for i in 0usize..(MAX_NEXT_EPOCH_BUFFER + 10) {
        let block = DagBlock::new(
            DagBlockBody { epoch: 2, round: 0, author: addr((i % 4) as u8 + 1),
                timestamp_ms: i as u64, ancestors: vec![], payload: vec![], commit_votes: vec![] },
            Signature::Unsigned,
        );
        match dag.insert(block, &vset, true).unwrap() {
            InsertOutcome::NextEpochBuffered => buffered_count += 1,
            InsertOutcome::Dropped => {}
            other => panic!("unexpected: {other:?}"),
        }
    }
    // Exactly MAX_NEXT_EPOCH_BUFFER blocks were buffered; the rest were Dropped.
    assert_eq!(buffered_count, MAX_NEXT_EPOCH_BUFFER);
    let drained = dag.advance_epoch(2);
    assert_eq!(drained.len(), MAX_NEXT_EPOCH_BUFFER);
}

#[test]
fn suspended_buffer_bounded_returns_dropped_when_full() {
    let vset = vset_4();
    let mut dag = Dag::new(1);

    // Fabricate MAX_SUSPENDED + 1 blocks each missing a unique ancestor.
    // Use genesis blocks as "missing ancestors" by referencing non-inserted blocks.
    // Each suspended block needs unique ancestry (different digest) → use timestamp.
    let fake_ancestor = |i: usize| {
        let b = DagBlock::new(
            DagBlockBody { epoch: 1, round: 0, author: addr(1), timestamp_ms: i as u64,
                ancestors: vec![], payload: vec![], commit_votes: vec![] },
            Signature::Unsigned,
        );
        b.reference()
    };

    let mut suspended_count = 0usize;
    for i in 0usize..(MAX_SUSPENDED + 5) {
        let block = DagBlock::new(
            DagBlockBody { epoch: 1, round: 1, author: addr(2), timestamp_ms: i as u64,
                ancestors: vec![fake_ancestor(i)], payload: vec![], commit_votes: vec![] },
            Signature::Unsigned,
        );
        match dag.insert(block, &vset, true).unwrap() {
            InsertOutcome::Suspended => suspended_count += 1,
            InsertOutcome::Dropped => {}
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert_eq!(suspended_count, MAX_SUSPENDED);
}

// ── C1: GC evicts suspended blocks with unreachable ancestors ─────────────────

#[test]
fn gc_evicts_suspended_block_whose_ancestor_is_below_gc_boundary() {
    let vset = vset_4();
    let mut dag = Dag::new(1);

    // A missing ancestor at a NON-genesis round (round 2). Genesis round (0) is
    // GC-exempt, so we must use a higher round to exercise the C1 eviction path.
    let missing_ancestor = DagBlock::new(
        DagBlockBody { epoch: 1, round: 2, author: addr(1), timestamp_ms: 0,
            ancestors: vec![], payload: vec![], commit_votes: vec![] },
        Signature::Unsigned,
    );
    let missing_ref = missing_ancestor.reference();

    // Block at round 6 depends on the missing round-2 ancestor → suspended.
    let waiting = make_round_block(6, 4, vec![missing_ref]);
    assert_eq!(dag.insert(waiting, &vset, true).unwrap(), InsertOutcome::Suspended);
    assert_eq!(dag.suspended_count(), 1, "block should be suspended");

    // Advance committed round so gc_round = 4: the round-2 ancestor is now below
    // the GC frontier and can NEVER be inserted (rule 3 rejects round <= 4).
    // The round-6 suspended block is ABOVE gc_round (6 > 4), so it survives the
    // round-below-GC check — it must be evicted by the ancestor-below-GC check (C1).
    dag.set_last_committed_round(34); // gc_round = 34 - 30 = 4

    assert_eq!(
        dag.suspended_count(),
        0,
        "suspended block with unreachable ancestor must be evicted (C1)"
    );
}

// ── C2: equivocation during try_unsuspend is surfaced via drain_equivocations ─

#[test]
fn equivocation_during_cascade_unsuspend_queued_in_pending() {
    let vset = vset_4();
    let mut dag = Dag::new(1);

    // Two conflicting blocks at the same slot (round 1, author 4) with different bodies.
    let g: Vec<DagBlock> = (1u8..=3).map(genesis_block).collect();
    let g_refs: Vec<DagBlockRef> = g.iter().map(|b| b.reference()).collect();

    // Block A at slot (1, addr(4)): ancestors = g1, g2, g3.
    let block_a = make_round_block(1, 4, g_refs.clone());
    // Block B at same slot: different body (different timestamp → different digest).
    let block_b = DagBlock::new(
        DagBlockBody { epoch: 1, round: 1, author: addr(4), timestamp_ms: 9999,
            ancestors: g_refs.clone(), payload: vec![], commit_votes: vec![] },
        Signature::Unsigned,
    );
    assert_ne!(block_a.digest, block_b.digest, "must be distinct digests");

    // Suspend both blocks (genesis not in DAG yet).
    dag.insert(block_a, &vset, true).unwrap();
    dag.insert(block_b, &vset, true).unwrap();
    assert_eq!(dag.drain_equivocations().len(), 0); // nothing yet

    // Insert genesis → cascade tries to unsuspend both A and B.
    // First to be promoted succeeds; second triggers equivocation.
    for gb in g {
        dag.insert(gb, &vset, true).unwrap();
    }

    let equivocations = dag.drain_equivocations();
    assert_eq!(equivocations.len(), 1, "one equivocation must be surfaced");
    assert!(
        matches!(equivocations[0], InsertOutcome::Equivocation { .. }),
        "must be Equivocation variant"
    );
    // Buffer is cleared after drain.
    assert_eq!(dag.drain_equivocations().len(), 0);
}
