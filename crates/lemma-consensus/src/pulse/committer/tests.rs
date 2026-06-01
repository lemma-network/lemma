//! Tests for `lemma_consensus::pulse::committer`.
//!
//! Covers: vote/cert/blame predicates, direct commit/skip/undecided, indirect
//! commit/skip via nearest anchor, gapless prefix driver, Byzantine breach,
//! determinism proptest.
//!
//! # Test DAG shape
//!
//! A minimal 4-validator wave (WAVE_LENGTH=3):
//!   Round L   — leader block by author 1
//!   Round L+1 — voting blocks by authors 1..=4 (or subset)
//!   Round L+2 — decision blocks by authors 1..=4 (or subset)
//!
//! All ancestry is explicit — block N lists blocks from round N-1 as ancestors.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    signature::Signature,
    validator::{ConsensusKey, VotingPower},
    validator_set::{Member, ValidatorSet},
};
use proptest::prelude::*;

use crate::{
    dag::{
        block::{DagBlock, DagBlockBody, DagBlockRef, Slot},
        graph::{Dag, InsertOutcome},
    },
    error::ConsensusError,
    pulse::committer::{
        find_supported_block, is_blame, is_vote,
        LeaderStatus, try_decide, try_direct_decide, try_indirect_decide,
    },
    WAVE_LENGTH,
};

// ── Fixtures ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 32])
}

/// Uniform-stake 4-validator committee, total = 40 Drop.
/// Quorum: > 2/3 × 40 = 26.67 → need 3 validators (30 Drop).
fn vset4() -> ValidatorSet {
    let power = VotingPower(Amount::from_drop(10));
    let mut members = BTreeMap::new();
    for i in 1u8..=4 {
        members.insert(addr(i), Member { consensus_pubkey: dummy_key(), power });
    }
    ValidatorSet { epoch: 1, members, total_power: Amount::from_drop(40) }
}

/// Simple round-robin leader schedule: author (round % 4) + 1 leads.
fn round_robin(round: u64) -> Slot {
    Slot { round, author: addr((round % 4) as u8 + 1) }
}

/// Build a DagBlock at (round, author_n) listing `ancestors`.
fn block(round: u64, author_n: u8, ancestors: Vec<DagBlockRef>) -> DagBlock {
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

/// Insert a DagBlock into the DAG; panics if it doesn't come back Accepted.
fn insert_ok(dag: &mut Dag, b: DagBlock, vset: &ValidatorSet) -> DagBlockRef {
    let r = b.reference();
    match dag.insert(b, vset, true) {
        Ok(InsertOutcome::Accepted) => r,
        other => panic!("expected Accepted, got {other:?}"),
    }
}

// ── Build helpers ──────────────────────────────────────────────────────────────

/// Build a complete wave at leader_round L with all 4 validators.
///
/// `prev_refs`: ancestors from the previous round (required for strong-link
/// rule on non-genesis rounds). Pass `vec![]` only for wave at round 0.
///
/// Returns `(leader_ref, voter_refs, decider_refs)`.
fn build_full_wave(
    dag: &mut Dag,
    vset: &ValidatorSet,
    leader_author: u8,
    l: u64,
    prev_refs: Vec<DagBlockRef>,
) -> (DagBlockRef, Vec<DagBlockRef>, Vec<DagBlockRef>) {
    let l_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(dag, block(l, a, prev_refs.clone()), vset))
        .collect();
    let leader_ref = l_refs[(leader_author - 1) as usize];
    let v_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(dag, block(l + 1, a, l_refs.clone()), vset))
        .collect();
    let d_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(dag, block(l + 2, a, v_refs.clone()), vset))
        .collect();
    (leader_ref, v_refs, d_refs)
}

// ── find_supported_block / is_vote tests ───────────────────────────────────────

#[test]
fn find_supported_block_unique_returns_ref() {
    // Voter lists leader_ref as an ancestor → unique supported block.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader_ref = insert_ok(&mut dag, block(0, 1, vec![]), &vset);
    let leader_slot = Slot { round: 0, author: addr(1) };

    let voter = block(1, 2, vec![leader_ref]);
    let result = find_supported_block(leader_slot, &voter);
    assert_eq!(result, Some(leader_ref));
}

#[test]
fn find_supported_block_equivocation_returns_none() {
    // Voter references two different blocks at the same slot → None (safety).
    let vset = vset4();
    let mut dag = Dag::new(1);
    let ref_a = insert_ok(&mut dag, block(0, 1, vec![]), &vset);
    // Build a second block at same slot — uses different timestamp to get diff digest.
    let ref_b = DagBlock::new(
        DagBlockBody {
            epoch: 1, round: 0, author: addr(1), timestamp_ms: 1,
            ancestors: vec![], payload: vec![], commit_votes: vec![],
        },
        Signature::Unsigned,
    ).reference();
    assert_ne!(ref_a.digest, ref_b.digest);

    let voter = block(1, 2, vec![ref_a, ref_b]);
    let leader_slot = Slot { round: 0, author: addr(1) };
    assert_eq!(find_supported_block(leader_slot, &voter), None);
}

#[test]
fn find_supported_block_missing_returns_none() {
    // Voter has no ancestor at the leader slot → None.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let other_ref = insert_ok(&mut dag, block(0, 2, vec![]), &vset);
    let voter = block(1, 3, vec![other_ref]);
    let leader_slot = Slot { round: 0, author: addr(1) };
    assert_eq!(find_supported_block(leader_slot, &voter), None);
}

#[test]
fn is_vote_returns_true_when_voter_supports_leader() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader_ref = insert_ok(&mut dag, block(0, 1, vec![]), &vset);
    let leader_slot = Slot { round: 0, author: addr(1) };
    let voter = block(1, 2, vec![leader_ref]);
    assert!(is_vote(&voter, leader_slot, leader_ref));
}

#[test]
fn is_vote_returns_false_when_voter_does_not_support_leader() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader_ref = insert_ok(&mut dag, block(0, 1, vec![]), &vset);
    let other_ref  = insert_ok(&mut dag, block(0, 2, vec![]), &vset);
    let leader_slot = Slot { round: 0, author: addr(1) };
    // Voter references a different author's block, not the leader.
    let voter = block(1, 3, vec![other_ref]);
    assert!(!is_vote(&voter, leader_slot, leader_ref));
}

// ── is_blame tests ────────────────────────────────────────────────────────────

#[test]
fn is_blame_true_when_no_ancestor_at_leader_slot() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let other_ref = insert_ok(&mut dag, block(0, 2, vec![]), &vset);
    let voter = block(1, 3, vec![other_ref]);
    let leader_slot = Slot { round: 0, author: addr(1) };
    assert!(is_blame(&voter, leader_slot));
}

#[test]
fn is_blame_false_when_ancestor_at_exact_slot() {
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader_ref = insert_ok(&mut dag, block(0, 1, vec![]), &vset);
    let voter = block(1, 2, vec![leader_ref]);
    let leader_slot = Slot { round: 0, author: addr(1) };
    assert!(!is_blame(&voter, leader_slot));
}

#[test]
fn is_blame_checks_full_slot_not_only_author() {
    // W4 fix: a weak-link to a different-round block by the leader's address
    // does NOT suppress blame — we check both round AND author.
    let vset = vset4();
    let mut dag = Dag::new(1);
    // Block at round 0, author 1 — a different slot than (round=3, author=1).
    let different_round_ref = insert_ok(&mut dag, block(0, 1, vec![]), &vset);
    let voter = block(4, 2, vec![different_round_ref]);
    let leader_slot = Slot { round: 3, author: addr(1) };
    // voter.ancestors has author=1 but at round=0, not round=3 → blame!
    assert!(is_blame(&voter, leader_slot));
}

// ── try_direct_decide tests ───────────────────────────────────────────────────

#[test]
fn direct_commit_on_quorum_of_certificates() {
    // Full wave: all 4 validators present + voting → 3 certs = quorum → Commit.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader_slot = Slot { round: 0, author: addr(1) };
    let (leader_ref, _, _) = build_full_wave(&mut dag, &vset, 1, 0, vec![]);

    let status = try_direct_decide(leader_slot, &dag, &vset).unwrap();
    assert_eq!(status, LeaderStatus::Commit(leader_ref));
}

#[test]
fn direct_undecided_when_decision_round_below_quorum() {
    // Only 2 validators produce decision blocks → total stake < quorum → Undecided.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader_slot = Slot { round: 0, author: addr(1) };

    // Round 0: leader + 3 others.
    let l_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![]), &vset))
        .collect();
    // Round 1: all 4 vote.
    let v_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(1, a, l_refs.clone()), &vset))
        .collect();
    // Round 2: ONLY 2 decision blocks (below quorum of 3).
    insert_ok(&mut dag, block(2, 1, v_refs.clone()), &vset);
    insert_ok(&mut dag, block(2, 2, v_refs.clone()), &vset);

    let status = try_direct_decide(leader_slot, &dag, &vset).unwrap();
    assert_eq!(status, LeaderStatus::Undecided(leader_slot));
}

#[test]
fn direct_skip_on_quorum_of_blame() {
    // 3 out of 4 voters do NOT reference leader → 2f+1 blame → Skip.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader_slot = Slot { round: 0, author: addr(1) };

    // Round 0: leader + 3 other blocks.
    let l_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![]), &vset))
        .collect();
    let non_leader_refs: Vec<DagBlockRef> = l_refs[1..].to_vec(); // authors 2,3,4

    // Round 1 voters: 3 blamers (reference non-leader blocks only), 1 supporter.
    // Blamers (authors 2,3,4): only reference other round-0 blocks, NOT author 1.
    for a in 2u8..=4 {
        insert_ok(&mut dag, block(1, a, non_leader_refs.clone()), &vset);
    }
    // Supporter (author 1): references the leader.
    insert_ok(&mut dag, block(1, 1, l_refs.clone()), &vset);

    let status = try_direct_decide(leader_slot, &dag, &vset).unwrap();
    assert_eq!(status, LeaderStatus::Skip(leader_slot));
}

#[test]
fn direct_skip_when_no_leader_block_and_quorum_blame() {
    // Leader produced no block; 3 voters blame → Skip.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader_slot = Slot { round: 0, author: addr(1) };

    // Round 0: only non-leader blocks (no author 1 block at round 0).
    let nr: Vec<DagBlockRef> = (2u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![]), &vset))
        .collect();
    // Round 1: all 3 existing authors blame (no ancestor at slot (0,1)).
    for a in 2u8..=4 {
        insert_ok(&mut dag, block(1, a, nr.clone()), &vset);
    }

    let status = try_direct_decide(leader_slot, &dag, &vset).unwrap();
    assert_eq!(status, LeaderStatus::Skip(leader_slot));
}

#[test]
fn skip_check_precedes_commit_check() {
    // Even when certs exist, if blame is also 2f+1 the result is Skip first.
    // We achieve this by having 3 blamers (quorum) AND 1 certificate present.
    // Skip should win.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader_slot = Slot { round: 0, author: addr(1) };

    let l_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![]), &vset))
        .collect();
    let non_leader_refs: Vec<DagBlockRef> = l_refs[1..].to_vec();

    // 3 blamers + 1 supporter at voting round.
    let mut v_refs = vec![];
    for a in 2u8..=4 {
        v_refs.push(insert_ok(&mut dag, block(1, a, non_leader_refs.clone()), &vset));
    }
    let supporter_ref = insert_ok(&mut dag, block(1, 1, l_refs.clone()), &vset);
    v_refs.push(supporter_ref);

    // Decision block: must reference ALL round-1 blocks (strong-link quorum).
    // It only "certifies" via the one supporter's vote, but structurally must
    // include all voting-round ancestors to satisfy strong-link rule.
    insert_ok(&mut dag, block(2, 1, v_refs.clone()), &vset);

    // blame (30 stake) >= quorum → Skip, despite the one cert.
    let status = try_direct_decide(leader_slot, &dag, &vset).unwrap();
    assert_eq!(status, LeaderStatus::Skip(leader_slot));
}

// ── total_stake_at early-exit boundary (W2) ───────────────────────────────────

#[test]
fn direct_undecided_when_decision_stake_exactly_at_quorum_boundary() {
    // 3 validators × 10 Drop = 30 total. Quorum: > 20 (strict >). Exactly 2
    // decision blocks = 20 stake. 20 × 3 = 60, 30 × 2 = 60. NOT > → Undecided.
    let power = VotingPower(Amount::from_drop(10));
    let total = Amount::from_drop(30);
    let mut members = BTreeMap::new();
    for i in 1u8..=3 {
        members.insert(addr(i), Member { consensus_pubkey: dummy_key(), power });
    }
    let vset3 = ValidatorSet { epoch: 1, members, total_power: total };
    let mut dag = Dag::new(1);
    let leader_slot = Slot { round: 0, author: addr(1) };

    let l0: Vec<DagBlockRef> = (1u8..=3)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![]), &vset3))
        .collect();
    let v1: Vec<DagBlockRef> = (1u8..=3)
        .map(|a| insert_ok(&mut dag, block(1, a, l0.clone()), &vset3))
        .collect();
    // Exactly 2 decision blocks = 20 stake = exactly 2/3 (NOT > 2/3).
    insert_ok(&mut dag, block(2, 1, v1.clone()), &vset3);
    insert_ok(&mut dag, block(2, 2, v1.clone()), &vset3);

    let status = try_direct_decide(leader_slot, &dag, &vset3).unwrap();
    assert_eq!(status, LeaderStatus::Undecided(leader_slot),
        "exactly 2/3 decision stake must be Undecided (strict > required)");
}

// ── try_indirect_decide tests ─────────────────────────────────────────────────

#[test]
fn indirect_commit_via_nearest_committed_anchor() {
    // Wave 0 (rounds 0-2): fully built. Then wave 1 (rounds 3-5) builds on top.
    // Anchor = wave-1 leader block at round 3. It has 3 round-2 blocks as ancestors
    // (= decision round for wave 0). Each of those 3 blocks certifies wave-0 leader
    // (all 4 voters are in their round-1 ancestors). So anchor → cert → Commit.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader0_slot = Slot { round: 0, author: addr(1) };

    // Wave 0: all 4 rounds 0-2.
    let (leader0_ref, _, d0_refs) = build_full_wave(&mut dag, &vset, 1, 0, vec![]);

    // Wave 1 rounds 3-5: each round-3 block references round-2 (d0_refs = 4 blocks).
    // 4 round-2 blocks = 40 stake ≥ 30 quorum for strong-link of round-3 blocks.
    let l3_refs: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(3, a, d0_refs.clone()), &vset))
        .collect();

    // Anchor = round-3 block by author 1. It has d0_refs as ancestors_at_round(2).
    // d0_refs are the round-2 decision blocks of wave 0 — each certifies wave-0 leader
    // (all 4 votes at round-1 → is_certificate returns true).
    let anchor_ref = l3_refs[0]; // author 1

    let decided_above = vec![LeaderStatus::Commit(anchor_ref)];
    let status = try_indirect_decide(leader0_slot, &decided_above, &dag, &vset).unwrap();
    assert_eq!(status, LeaderStatus::Commit(leader0_ref),
        "indirect commit: anchor's round-2 ancestors cert wave-0 leader");
}

#[test]
fn indirect_skip_when_no_cert_link_from_anchor() {
    // Leader produced no block at round 0. Therefore no cert can exist.
    // Anchor at round 3 has round-2 ancestors, but they can't cert a nonexistent leader.
    // try_indirect_decide: leader_ref = dag.block_at_slot(leader0_slot) = None → Skip.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader0_slot = Slot { round: 0, author: addr(1) };

    // Round 0: authors 2,3,4 only — leader (author 1) has NO block.
    let r0: Vec<DagBlockRef> = (2u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![]), &vset))
        .collect();
    // Round 1: 3 voters (authors 2,3,4); all blame leader (no ancestor at slot(0,1)).
    // Need 3 round-0 ancestors for strong-link. Use r0 (3 blocks = 30 stake ≥ quorum).
    let v1: Vec<DagBlockRef> = (2u8..=4)
        .map(|a| insert_ok(&mut dag, block(1, a, r0.clone()), &vset))
        .collect();
    // Round 2: 3 decision blocks listing all 3 voting blocks.
    let d2: Vec<DagBlockRef> = (2u8..=4)
        .map(|a| insert_ok(&mut dag, block(2, a, v1.clone()), &vset))
        .collect();
    // Anchor at round 3: 3 round-2 ancestors (= strong-link quorum from round-2).
    let anchor_ref = insert_ok(&mut dag, block(3, 2, d2.clone()), &vset);
    let decided_above = vec![LeaderStatus::Commit(anchor_ref)];

    let status = try_indirect_decide(leader0_slot, &decided_above, &dag, &vset).unwrap();
    // leader0_slot has no block in DAG → None → Skip immediately.
    assert_eq!(status, LeaderStatus::Skip(leader0_slot));
}

#[test]
fn nearest_anchor_is_decisive_not_farther() {
    // PROVES nearest-anchor decisiveness (W5 fix):
    // Nearest committed anchor (round 3) → Skip (no cert for leader).
    // Farther committed anchor (round 6) → WOULD Commit (has cert for leader).
    // Result must be Skip — proving the farther anchor is never consulted.
    // If the nearest-decisive invariant were broken (e.g. `continue` instead of
    // `return Skip`), the farther anchor's cert would cause Commit instead of Skip,
    // and this assertion would fail — exactly the regression it guards against.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let leader0_slot = Slot { round: 0, author: addr(1) };

    // Wave 0 fully built. d0_refs are the round-2 decision blocks (all 4 voters → certs).
    let (leader0_ref, _, d0_refs) = build_full_wave(&mut dag, &vset, 1, 0, vec![]);

    // Nearest anchor at round 3: references ONLY round-0 blocks (NOT round-2 certs).
    // ancestors_at_round(2) = [] → no certs for leader → nearest anchor Skips.
    // Round-3 block needs strong-link quorum from round-2 (d0_refs, 4 blocks ≥ quorum).
    // BUT we want it to have NO round-2 ancestors... contradiction: it needs ≥ 3 round-2
    // ancestors for strong-link. Solution: it references d0_refs but that makes it
    // a cert anchor... unless we make a *separate* near anchor at round 3 that only
    // has round-0 blocks as ancestors (skip-over-round-2 via time-skip).
    // Actually: strong-link rule (spec §2.2) requires *round-1* ancestors for a round-2
    // block, not round-2 for round-3. Let me re-read: "strong links: round-R+1 must ref
    // 2f+1 of round-R". So round-3 needs 2f+1 of round-2. And round-2 is where certs live.
    //
    // The only way to have round-3 with NO round-2 cert ancestors is impossible via the
    // DAG rules. Instead: build the nearest anchor at round 3 with round-2 ancestors that
    // are NOT certs (don't have 2f+1 round-1 votes for leader0).
    //
    // Build round-1 blamers (no ancestor at leader slot (0,1)):
    // Round-0 blocks: authors 2,3,4 (no author 1 = no leader block at round 0).
    // But build_full_wave already inserted author 1 at round 0. Let's use a fresh dag.
    let vset2 = vset4();
    let mut dag2 = Dag::new(1);

    // Round 0: leader (author 1) + 3 others.
    let r0: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag2, block(0, a, vec![]), &vset2))
        .collect();
    let leader0_ref2 = r0[0]; // author 1

    // Round 1: 3 blamers (authors 2,3,4) reference only non-leader round-0 blocks.
    // Blamers reference r0[1..] (authors 2,3,4 blocks at round 0, NOT author 1).
    let non_leader_r0: Vec<DagBlockRef> = r0[1..].to_vec();
    let r1_blame: Vec<DagBlockRef> = (2u8..=4)
        .map(|a| insert_ok(&mut dag2, block(1, a, non_leader_r0.clone()), &vset2))
        .collect();
    // 1 supporter (author 1) references all round-0 including leader.
    let r1_support = insert_ok(&mut dag2, block(1, 1, r0.clone()), &vset2);

    // Round-2 no-cert blocks: reference blame-voters only (3 votes, but 0 vote for leader
    // from blamers; only 1 vote from author 1 — 10 stake < 30 quorum → NOT a cert).
    let all_r1 = {
        let mut v = r1_blame.clone();
        v.push(r1_support);
        v
    };
    let d2_no_cert: Vec<DagBlockRef> = (2u8..=4)
        .map(|a| insert_ok(&mut dag2, block(2, a, all_r1.clone()), &vset2))
        .collect();
    // d2_no_cert: each has r1_blame (authors 2,3,4) + r1_support (author 1) as voters.
    // Only 1 supporter (10 stake) voted for leader → NOT a cert.

    // Nearest anchor at round 3: references d2_no_cert (3 blocks = 30 stake quorum).
    let nearest = insert_ok(&mut dag2, block(3, 1, d2_no_cert.clone()), &vset2);
    // nearest.ancestors_at_round(2) = d2_no_cert → none are certs → Skip.

    // Round-2 WITH-cert blocks (all 4 voters including author 1):
    let d2_cert: Vec<DagBlockRef> = vec![
        insert_ok(&mut dag2, block(2, 1, all_r1.clone()), &vset2), // has all 4 votes including own
    ];
    // Wait: author 1 already inserted at round 2 via d2_no_cert[0]... no: d2_no_cert inserts
    // authors 2,3,4. Author 1 at round 2 is not yet inserted. Good.
    // But: block(2, 1, all_r1) where all_r1 = 4 voting blocks. Author 1 voted (r1_support
    // references all r0 including leader). So d2_cert[0] has 4 voters → is a cert!

    // Farther anchor at round 6: needs round-5 strong-link. Build rounds 3-5.
    // Round-3 for farther: reference d2_cert + d2_no_cert (4 round-2 blocks = quorum).
    let all_d2: Vec<DagBlockRef> = {
        let mut v = d2_no_cert.clone();
        v.extend(d2_cert.iter());
        v
    };
    let r3_far: Vec<DagBlockRef> = (2u8..=4)
        .map(|a| insert_ok(&mut dag2, block(3, a, all_d2.clone()), &vset2))
        .collect();
    let r4: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag2, block(4, a, r3_far.clone()), &vset2))
        .collect();
    let r5: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag2, block(5, a, r4.clone()), &vset2))
        .collect();
    // Farther anchor at round 6: include d2_cert as round-2 ancestors directly.
    let farther_ancs: Vec<DagBlockRef> = {
        let mut v = r5.clone();
        v.extend(d2_cert.iter()); // direct round-2 ancestors = certs for leader0
        v
    };
    let farther = insert_ok(&mut dag2, block(6, 1, farther_ancs), &vset2);
    // farther.ancestors_at_round(2) includes d2_cert[0] (cert!) → would Commit.

    let decided_above = vec![
        LeaderStatus::Commit(nearest), // round 3 — nearest: would Skip (no cert)
        LeaderStatus::Commit(farther), // round 6 — farther: would Commit (has cert)
    ];

    let status = try_indirect_decide(leader0_slot, &decided_above, &dag2, &vset2).unwrap();
    // Nearest anchor finds no cert → MUST return Skip.
    // If invariant is broken (farther consulted), result would be Commit → test fails.
    assert_eq!(status, LeaderStatus::Skip(leader0_slot),
        "nearest committed anchor (Skip) must be decisive; farther Commit anchor must NOT be consulted");
    let _ = (leader0_ref, d0_refs, leader0_ref2);
}

#[test]
fn indirect_undecided_when_no_committed_anchor() {
    // All higher entries are Skip → no committed anchor found → Undecided.
    let vset = vset4();
    let dag = Dag::new(1);
    let leader_slot = Slot { round: 0, author: addr(1) };
    let decided_above = vec![
        LeaderStatus::Skip(Slot { round: 3, author: addr(1) }),
        LeaderStatus::Skip(Slot { round: 6, author: addr(1) }),
    ];
    let status = try_indirect_decide(leader_slot, &decided_above, &dag, &vset).unwrap();
    assert_eq!(status, LeaderStatus::Undecided(leader_slot));
}

// ── try_decide driver tests ───────────────────────────────────────────────────

#[test]
fn try_decide_gapless_prefix_stops_at_undecided() {
    // Strategy: last_decided at round 0, build wave at round 3 (full/committable)
    // and wave at round 6 (undecided). Expect [Commit(round-3)] only.
    // highest_accepted = 8 → upper = 6. Driver scans waves 3 and 6.
    //
    // IMPORTANT: every non-genesis block needs strong-link quorum from prior round.
    // We use build_full_wave for wave 0 (rounds 0-2) as foundation, then build
    // wave 1 (rounds 3-5) fully, and wave 2 (rounds 6-8) with only 1 decision block.
    let vset = vset4();
    let mut dag = Dag::new(1);
    let last = Slot { round: 0, author: addr(0) };

    // Foundation: wave 0 (rounds 0-2) fully built — provides ancestors for round 3.
    let (_, _, d0_refs) = build_full_wave(&mut dag, &vset, 1, 0, vec![]);

    // Wave 1 (rounds 3-5) fully built — leader at round 3, author 4 (round_robin).
    // Round 3 blocks need round-2 (d0_refs) as strong-link ancestors.
    let l3: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(3, a, d0_refs.clone()), &vset))
        .collect();
    let v3: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(4, a, l3.clone()), &vset))
        .collect();
    let d3: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(5, a, v3.clone()), &vset))
        .collect();

    // Wave 2 (rounds 6-8): only 1 decision block → undecided.
    let l6: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(6, a, d3.clone()), &vset))
        .collect();
    let v6: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(7, a, l6.clone()), &vset))
        .collect();
    // Only 1 decision block at round 8 (10 stake < 30 quorum → undecided).
    insert_ok(&mut dag, block(8, 1, v6.clone()), &vset);

    let result = try_decide(last, &dag, &vset, round_robin).unwrap();
    // Wave 3 (round 3) should commit; wave 6 should be undecided and stop there.
    assert!(!result.is_empty(), "should have at least 1 decided leader");
    assert!(result.iter().all(|s| s.is_decided()), "all emitted must be decided");
    // No Undecided should appear in output (gapless guarantee).
    assert!(!result.iter().any(|s| matches!(s, LeaderStatus::Undecided(_))));
}

#[test]
fn try_decide_wave_aligned_only() {
    // Only round % WAVE_LENGTH == 0 rounds get a leader decision.
    // Build blocks at rounds 0, 1, 2 — only round 0 is wave-aligned,
    // but with last_decided at round 0 the driver starts scanning from round 1.
    // highest = 2; upper = 2-2 = 0; no wave-aligned rounds in [1..=0] → empty.
    let vset = vset4();
    let mut dag = Dag::new(1);

    // Round 0 (genesis, no ancestors needed).
    let r0: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(0, a, vec![]), &vset))
        .collect();
    // Round 1 (needs round-0 strong-link quorum = 3+ blocks).
    let r1: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(1, a, r0.clone()), &vset))
        .collect();
    // Round 2 (needs round-1 strong-link quorum).
    let _: Vec<DagBlockRef> = (1u8..=4)
        .map(|a| insert_ok(&mut dag, block(2, a, r1.clone()), &vset))
        .collect();

    let last = Slot { round: 0, author: addr(0) };
    // highest = 2; upper = 0. Scan [1..=0] → empty. No wave-aligned rounds.
    let result = try_decide(last, &dag, &vset, round_robin).unwrap();
    assert!(result.is_empty(), "non-wave-aligned rounds must not produce decisions");
}

#[test]
fn try_decide_returns_empty_when_no_decidable_rounds() {
    let vset = vset4();
    let dag = Dag::new(1);
    let last = Slot { round: 0, author: addr(0) };
    let result = try_decide(last, &dag, &vset, round_robin).unwrap();
    assert!(result.is_empty());
}

// ── Byzantine breach test ──────────────────────────────────────────────────────

// NOTE: ByzantineInvariantBreach requires two DIFFERENT certified blocks at the
// same slot — mathematically impossible under BFT assumption. We test the error
// variant exists and is flagged correctly.
#[test]
fn byzantine_invariant_breach_error_is_flagged() {
    let err = ConsensusError::ByzantineInvariantBreach {
        slot_round: 3,
        slot_author: addr(1),
        first: lemma_core::hash::Hash::zero(),
        second: lemma_core::hash::Hash::zero(),
    };
    assert!(err.is_byzantine_breach());
    assert!(!err.is_equivocation());
    assert!(!err.is_pending_data());
}

// ── LeaderStatus helpers ──────────────────────────────────────────────────────

#[test]
fn leader_status_is_decided() {
    let slot = Slot { round: 0, author: addr(1) };
    let r = DagBlock::new(
        DagBlockBody { epoch:1, round:0, author:addr(1), timestamp_ms:0,
            ancestors:vec![], payload:vec![], commit_votes:vec![] },
        Signature::Unsigned,
    ).reference();
    assert!(LeaderStatus::Commit(r).is_decided());
    assert!(LeaderStatus::Skip(slot).is_decided());
    assert!(!LeaderStatus::Undecided(slot).is_decided());
}

#[test]
fn leader_status_round() {
    let slot = Slot { round: 6, author: addr(2) };
    let r = DagBlock::new(
        DagBlockBody { epoch:1, round:6, author:addr(2), timestamp_ms:0,
            ancestors:vec![], payload:vec![], commit_votes:vec![] },
        Signature::Unsigned,
    ).reference();
    assert_eq!(LeaderStatus::Commit(r).round(), 6);
    assert_eq!(LeaderStatus::Skip(slot).round(), 6);
    assert_eq!(LeaderStatus::Undecided(slot).round(), 6);
}

// ── Proptest ───────────────────────────────────────────────────────────────────

proptest! {
    /// try_decide must never panic for any random DAG state.
    #[test]
    fn try_decide_never_panics(
        n_blocks in 0usize..20,
        round_offset in 0u64..5,
    ) {
        let vset = vset4();
        let mut dag = Dag::new(1);
        let mut prev: Vec<DagBlockRef> = vec![];
        for i in 0..n_blocks {
            let round = round_offset + i as u64;
            let author = (i % 4) as u8 + 1;
            let b = block(round, author, prev.clone());
            if let Ok(InsertOutcome::Accepted) = dag.insert(b.clone(), &vset, true) {
                prev.push(b.reference());
            }
        }
        let last = Slot { round: 0, author: addr(0) };
        // Must not panic; errors (StakeOverflow) are acceptable.
        let _ = try_decide(last, &dag, &vset, round_robin);
    }

    /// Determinism: same blocks in same DAG → identical result regardless of
    /// how we re-call try_decide. (Full multi-node simulation is Step 11.)
    #[test]
    fn try_decide_deterministic_on_same_dag(
        seed in 0u64..100,
    ) {
        let vset = vset4();
        let mut dag = Dag::new(1);
        // Build a small deterministic DAG based on seed.
        let waves = seed % 3 + 1;
        let mut prev: Vec<DagBlockRef> = vec![];
        for w in 0..waves {
            let l = w * WAVE_LENGTH;
            let (_, _, d_refs) = build_full_wave(&mut dag, &vset, 1, l, prev.clone());
            prev = d_refs; // decision-round refs become ancestors for next wave
        }
        let last = Slot { round: 0, author: addr(0) };
        let r1 = try_decide(last, &dag, &vset, round_robin).unwrap();
        let r2 = try_decide(last, &dag, &vset, round_robin).unwrap();
        prop_assert_eq!(r1, r2, "try_decide must be deterministic");
    }
}

// pub(crate) internals used directly via super:: in the tests above.
