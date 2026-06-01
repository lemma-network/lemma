//! Tests for `lemma_consensus::epoch` — `advance_epoch` (B1).
//!
//! ## Coverage (spec §10 mandatory + additional)
//!
//! - Aptos bug-class: settle expired pending_inactive BEFORE committee hash.
//! - `advance_epoch` never panics (checked arithmetic throughout).
//! - Deterministic: same input → same ValidatorSet(N+1) + same hash.
//! - `pending_active → active` at boundary, NOT mid-epoch.
//! - `Bonded → Unbonded` direct transition is impossible (stake stays slashable).
//! - Eligibility re-check: `active >= min_stake` required to seat.
//! - Tombstoned / jailed validators excluded from next committee.
//! - Reputation-driven `LeaderSwapTable` recomputed each epoch.
//! - `next_validators_hash` matches `ValidatorSet(N+1).hash()` exactly.
//! - `EmptyNextCommittee` returned, not panicked, when no eligible validators.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    validator::{ConsensusKey, Stake, UnbondingEntry, Validator, ValidatorStatus},
    validator_set::{Member, ValidatorSet},
    Epoch, DROPS_PER_LEM,
};

use crate::{
    commit::Commit,
    dag::block::DagBlockRef,
    epoch::{advance_epoch, EpochError, EpochOutput, GENESIS_MIN_VALIDATOR_STAKE_DROP},
    rewards::compute_epoch_inflation,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn lem(n: u64) -> Amount {
    Amount::from_drop(n as u128 * DROPS_PER_LEM)
}

fn min_stake() -> Amount {
    Amount::from_drop(GENESIS_MIN_VALIDATOR_STAKE_DROP)
}

/// Build a Validator with the given active self-stake in LEM and status.
fn make_validator(addr_byte: u8, status: ValidatorStatus, active_lem: u64) -> Validator {
    Validator {
        address: addr(addr_byte),
        consensus_pubkey: ConsensusKey::from_bytes(vec![addr_byte; 32], vec![addr_byte; 32]),
        status,
        tombstoned: false,
        self_stake: Stake {
            active:           lem(active_lem),
            pending_active:   Amount::zero(),
            pending_inactive: Vec::new(),
            inactive:         Amount::zero(),
        },
        delegated: Amount::zero(),
        commission_bps: 0,
        jailed_until: None,
    }
}

/// Build a BTreeMap of validators (addr_byte, status, active LEM).
fn make_validators(specs: &[(u8, ValidatorStatus, u64)]) -> BTreeMap<Address, Validator> {
    specs
        .iter()
        .map(|&(b, status, lem_amount)| {
            let v = make_validator(b, status, lem_amount);
            (v.address, v)
        })
        .collect()
}

/// Build a genesis Epoch from a validator map (all Bonded validators form the set).
fn make_epoch(number: u64, validators: &BTreeMap<Address, Validator>) -> Epoch {
    let members: BTreeMap<_, _> = validators
        .iter()
        .filter(|(_, v)| v.is_active())
        .map(|(a, v)| {
            (*a, Member {
                consensus_pubkey: v.consensus_pubkey.clone(),
                power: v.voting_power().expect("test validator power"),
            })
        })
        .collect();
    let total_power = members
        .values()
        .fold(Amount::zero(), |acc, m| acc.checked_add(m.power.as_amount()).unwrap());
    Epoch {
        number,
        start_height: 0,
        start_timestamp: 0,
        validators: ValidatorSet { epoch: number, members, total_power },
    }
}

/// Run `advance_epoch` with zero total supply (→ zero inflation) and no commits.
///
/// `total_supply = Amount::zero()` means inflation = 0 → RewardOutcome{0,0} →
/// no stake changes from rewards. All B1 assertions on stake/status remain valid.
fn run_advance(
    epoch: &Epoch,
    validators: &mut BTreeMap<Address, Validator>,
    block_time: u64,
) -> Result<EpochOutput, EpochError> {
    advance_epoch(epoch, validators, &[], Amount::zero(), block_time, 100, min_stake())
}

// ── advance_epoch — epoch numbering ──────────────────────────────────────────

#[test]
fn new_epoch_number_is_current_plus_one() {
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 25_000_000)]);
    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert_eq!(out.epoch.number, 1);
}

#[test]
fn start_height_is_boundary_block_height_plus_one() {
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 25_000_000)]);
    let epoch = make_epoch(0, &vs);
    let out = advance_epoch(
        &epoch, &mut vs, &[], Amount::zero(), 1_000, 42, min_stake(),
    ).unwrap();
    assert_eq!(out.epoch.start_height, 43, "start_height = boundary_height + 1");
}

// ── Step 3a: Aptos bug-class guard ───────────────────────────────────────────

/// spec §10: "advance_epoch settles expired pending_inactive BEFORE hashing
/// the committee" (the Aptos bug-class negative test).
#[test]
fn expired_pending_inactive_excluded_from_next_committee_power() {
    let large = lem(30_000_000); // above min_stake
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 30_000_000)]);

    // Add an unbonding entry that expires exactly at block_time = 1_000.
    vs.get_mut(&addr(1)).unwrap().self_stake.pending_inactive.push(UnbondingEntry {
        initial_balance: large,
        start_height: 0,
        complete_time: 1_000,
        on_hold: false,
    });

    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap();

    // Expired entry must be in `inactive`, NOT in the new committee's power.
    let v = vs.get(&addr(1)).unwrap();
    assert!(v.self_stake.pending_inactive.is_empty(), "entry must have been settled");
    assert_eq!(v.self_stake.inactive, large, "matured amount must be in inactive");

    // Committee power = only active stake (the expired entry does NOT count).
    let member = out.epoch.validators.members.get(&addr(1)).unwrap();
    assert_eq!(
        member.power.as_amount(),
        lem(30_000_000),
        "power must equal only active stake, not the expired pending_inactive"
    );
}

#[test]
fn on_hold_entry_not_expired_even_at_complete_time() {
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 25_000_000)]);
    vs.get_mut(&addr(1)).unwrap().self_stake.pending_inactive.push(UnbondingEntry {
        initial_balance: lem(5_000_000),
        start_height: 0,
        complete_time: 500, // would normally expire at block_time 500
        on_hold: true,       // but frozen — slash evidence pending
    });
    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap(); // block_time > complete_time
    let v = vs.get(&addr(1)).unwrap();
    assert_eq!(v.self_stake.pending_inactive.len(), 1, "on_hold entry must NOT be settled");
    assert!(v.self_stake.inactive.is_zero(), "nothing should move to inactive");
    let _ = out; // epoch transition still succeeded
}

// ── Step 3b: pending_active activation ───────────────────────────────────────

/// spec §10: "A power-affecting request mid-epoch does NOT change voting power
/// until the boundary; applied exactly at advance_epoch."
#[test]
fn pending_active_becomes_active_at_boundary() {
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 25_000_000)]);
    // Add pending_active stake (simulates mid-epoch bond request).
    vs.get_mut(&addr(1)).unwrap().self_stake.pending_active = lem(5_000_000);
    // Before boundary: active still 25M, pending_active = 5M.
    assert_eq!(vs[&addr(1)].self_stake.active, lem(25_000_000));

    let epoch = make_epoch(0, &vs);
    let _out = run_advance(&epoch, &mut vs, 1_000).unwrap();

    // After boundary: active = 30M, pending_active = 0.
    let v = vs.get(&addr(1)).unwrap();
    assert_eq!(v.self_stake.active, lem(30_000_000), "pending_active must be merged into active");
    assert!(v.self_stake.pending_active.is_zero(), "pending_active must be zeroed");
}

// ── Step 4: validator status transitions ─────────────────────────────────────

/// spec §10: "Bonded → Unbonded direct transition is rejected."
/// The only path is Bonded → Unbonding → Unbonded.
#[test]
fn bonded_to_unbonded_direct_is_impossible() {
    // Set up a Bonded validator with active = 0 (somehow dropped below min).
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 0)]);
    let epoch = make_epoch(0, &vs);
    // Manually add a second validator so the committee isn't empty.
    let v2 = make_validator(2, ValidatorStatus::Bonded, 25_000_000);
    vs.insert(v2.address, v2);
    let _out = run_advance(&epoch, &mut vs, 1_000).unwrap();

    // Validator 1 (active=0) must become Unbonding, NOT Unbonded.
    let v1 = &vs[&addr(1)];
    assert_eq!(v1.status, ValidatorStatus::Unbonding,
        "Bonded→Unbonded direct must be forbidden; must pass through Unbonding");
}

/// spec §10: "Eligibility re-check: pending_active validator joins only if
/// active >= min_stake after settlement."
#[test]
fn unbonded_with_enough_stake_becomes_bonded() {
    // Start Unbonded with pending_active that activates to above min.
    let mut v = make_validator(1, ValidatorStatus::Unbonded, 0);
    v.self_stake.pending_active = min_stake(); // exactly min_stake
    let mut vs = BTreeMap::new();
    vs.insert(v.address, v);
    // Need at least one Bonded validator to seed the epoch.
    let v2 = make_validator(2, ValidatorStatus::Bonded, 25_000_000);
    vs.insert(v2.address, v2);
    let epoch = make_epoch(0, &vs);
    let _out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert_eq!(vs[&addr(1)].status, ValidatorStatus::Bonded,
        "Unbonded validator with active >= min_stake must become Bonded");
}

#[test]
fn unbonded_below_min_stake_stays_unbonded() {
    let mut v = make_validator(1, ValidatorStatus::Unbonded, 0);
    v.self_stake.pending_active = lem(1); // 1 LEM << 20M min_stake
    let mut vs = BTreeMap::new();
    vs.insert(v.address, v);
    let v2 = make_validator(2, ValidatorStatus::Bonded, 25_000_000);
    vs.insert(v2.address, v2);
    let epoch = make_epoch(0, &vs);
    let _out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert_eq!(vs[&addr(1)].status, ValidatorStatus::Unbonded,
        "Unbonded validator below min_stake must remain Unbonded");
}

#[test]
fn bonded_below_min_stake_becomes_unbonding() {
    // Validator whose active stake is already below min.
    let mut vs = make_validators(&[
        (1, ValidatorStatus::Bonded, 1),          // 1 LEM << min
        (2, ValidatorStatus::Bonded, 25_000_000), // anchor validator
    ]);
    let epoch = make_epoch(0, &vs);
    let _out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert_eq!(vs[&addr(1)].status, ValidatorStatus::Unbonding,
        "Bonded validator with active < min_stake must move to Unbonding");
}

#[test]
fn unbonding_fully_unwound_becomes_unbonded() {
    // Validator with no active stake and no pending_inactive → fully unwound.
    let mut v = make_validator(1, ValidatorStatus::Unbonding, 0);
    v.self_stake.pending_inactive = vec![]; // nothing left
    let mut vs = BTreeMap::new();
    vs.insert(v.address, v);
    let v2 = make_validator(2, ValidatorStatus::Bonded, 25_000_000);
    vs.insert(v2.address, v2);
    let epoch = make_epoch(0, &vs);
    let _out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert_eq!(vs[&addr(1)].status, ValidatorStatus::Unbonded,
        "Unbonding with no stake left must become Unbonded");
}

#[test]
fn jailed_validator_unjailed_at_boundary() {
    let mut v = make_validator(1, ValidatorStatus::Bonded, 25_000_000);
    v.jailed_until = Some(500); // jail expires before block_time 1_000
    let mut vs = BTreeMap::new();
    vs.insert(v.address, v);
    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert!(vs[&addr(1)].jailed_until.is_none(), "jail must be cleared at boundary");
    // Unjailed Bonded validator with enough stake is in the new committee.
    assert!(out.epoch.validators.members.contains_key(&addr(1)));
}

// ── Step 5: ValidatorSet exclusions ──────────────────────────────────────────

#[test]
fn tombstoned_validator_excluded_from_next_set() {
    let mut v = make_validator(1, ValidatorStatus::Bonded, 25_000_000);
    v.tombstoned = true;
    let mut vs = BTreeMap::new();
    vs.insert(v.address, v);
    let v2 = make_validator(2, ValidatorStatus::Bonded, 25_000_000);
    vs.insert(v2.address, v2);
    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert!(!out.epoch.validators.members.contains_key(&addr(1)),
        "tombstoned validator must not appear in next ValidatorSet");
}

#[test]
fn still_jailed_validator_excluded_from_next_set() {
    let mut v = make_validator(1, ValidatorStatus::Bonded, 25_000_000);
    v.jailed_until = Some(2_000); // jail expires AFTER block_time 1_000
    let mut vs = BTreeMap::new();
    vs.insert(v.address, v);
    let v2 = make_validator(2, ValidatorStatus::Bonded, 25_000_000);
    vs.insert(v2.address, v2);
    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert!(!out.epoch.validators.members.contains_key(&addr(1)),
        "still-jailed validator must not appear in next ValidatorSet");
}

#[test]
fn empty_next_committee_returns_err_not_panic() {
    // All validators are tombstoned → no eligible committee.
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 25_000_000)]);
    vs.get_mut(&addr(1)).unwrap().tombstoned = true;
    let epoch = make_epoch(0, &vs);
    let result = run_advance(&epoch, &mut vs, 1_000);
    assert!(
        matches!(result, Err(EpochError::EmptyNextCommittee { next_epoch: 1 })),
        "empty committee must return Err, not panic"
    );
}

/// Boundary test: `active == min_stake` exactly must stay Bonded (`>=` not `>`).
#[test]
fn bonded_at_exactly_min_stake_stays_bonded() {
    // 20_000_000 LEM == min_stake: the `active < min_stake` drop must NOT fire.
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 20_000_000)]);
    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert_eq!(vs[&addr(1)].status, ValidatorStatus::Bonded,
        "active == min_stake must stay Bonded (>= boundary, not >)");
    assert!(out.epoch.validators.members.contains_key(&addr(1)),
        "validator at exactly min_stake must be in the next committee");
}

// ── Steps 5 + 9: hash correctness ────────────────────────────────────────────

/// spec §10: "next_validators_hash == ValidatorSet(N+1).hash() exactly."
#[test]
fn next_validators_hash_matches_committee_hash() {
    let mut vs = make_validators(&[
        (1, ValidatorStatus::Bonded, 25_000_000),
        (2, ValidatorStatus::Bonded, 30_000_000),
    ]);
    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    assert_eq!(
        out.next_validators_hash,
        out.epoch.validators.hash(),
        "next_validators_hash must equal ValidatorSet(N+1).hash()"
    );
}

/// spec §10: "Two nodes given identical inputs produce identical ValidatorSet(N+1)
/// and next_validators_hash."
#[test]
fn deterministic_same_input_same_output() {
    let make = || {
        let mut vs = make_validators(&[
            (1, ValidatorStatus::Bonded, 25_000_000),
            (2, ValidatorStatus::Bonded, 30_000_000),
        ]);
        let epoch = make_epoch(0, &vs);
        let out = run_advance(&epoch, &mut vs, 1_000).unwrap();
        out.next_validators_hash
    };
    assert_eq!(make(), make(), "advance_epoch must be deterministic");
}

// ── Step 6: reputation-driven swap ───────────────────────────────────────────

/// spec §10 + spec 07 §6: reputation recompute produces a different leader
/// schedule than a run with no commits (identity swap).
///
/// With unequal scores (addr(3) scored, others zero), the swap table is
/// non-identity → at least one `elect_leader(round)` result differs.
/// With all scores equal (no commits), the swap table is identity → same
/// round-robin for all rounds. The two runs must produce different schedules.
#[test]
fn reputation_recompute_produces_non_identity_schedule_when_scores_differ() {
    let make_vs = || make_validators(&[
        (0, ValidatorStatus::Bonded, 25_000_000),
        (1, ValidatorStatus::Bonded, 25_000_000),
        (2, ValidatorStatus::Bonded, 25_000_000),
        (3, ValidatorStatus::Bonded, 25_000_000),
    ]);

    // addr(3) gets 3 blocks (best rep); others get 0.
    let a3 = addr(3);
    let commits: Vec<Commit> = (1..=3)
        .map(|i| Commit {
            index: i,
            previous_digest: Hash::zero(),
            timestamp_ms: 0,
            leader: DagBlockRef::new(i, a3, Hash::zero()),
            blocks: vec![DagBlockRef::new(i, a3, Hash::zero())],
        })
        .collect();

    // Run WITH reputation — swap table should be non-identity.
    let mut vs1 = make_vs();
    let epoch1 = make_epoch(0, &vs1);
    let out_rep = advance_epoch(
        &epoch1, &mut vs1, &commits, Amount::zero(), 1_000, 100, min_stake(),
    ).unwrap();

    // Run WITHOUT reputation — all scores 0 → equal-score guard → identity.
    let mut vs2 = make_vs();
    let epoch2 = make_epoch(0, &vs2);
    let out_no = advance_epoch(
        &epoch2, &mut vs2, &[], Amount::zero(), 1_000, 100, min_stake(),
    ).unwrap();

    // With unequal scores, at least one leader election must differ.
    let any_different = (0..4_u64).any(|r| {
        out_rep.leader_schedule.elect_leader(r) != out_no.leader_schedule.elect_leader(r)
    });
    assert!(any_different,
        "unequal reputation scores must produce a different leader schedule vs no-commits");
}

// ── Delegated stake counts toward power ──────────────────────────────────────

#[test]
fn delegated_stake_included_in_voting_power() {
    let mut v = make_validator(1, ValidatorStatus::Bonded, 20_000_000);
    v.delegated = lem(5_000_000); // total = 25M
    let mut vs = BTreeMap::new();
    vs.insert(v.address, v);
    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap();
    let power = out.epoch.validators.members[&addr(1)].power;
    assert_eq!(power.as_amount(), lem(25_000_000),
        "voting power must include delegated stake");
}

// ── B2: Reward integration tests ─────────────────────────────────────────────

/// Inflation is computed and credited before stake settlement.
/// Validator active stake must increase by ~minted amount after advance_epoch.
#[test]
fn advance_epoch_nonzero_supply_credits_inflation_to_active_stake() {
    let supply = Amount::from_drop(1_000_000_000 * DROPS_PER_LEM); // 1B LEM
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 25_000_000)]);
    let initial_active = vs[&addr(1)].self_stake.active;
    let epoch = make_epoch(0, &vs);

    let out = advance_epoch(
        &epoch, &mut vs, &[], supply, 1_000, 100, min_stake(),
    ).unwrap();

    let new_active = vs[&addr(1)].self_stake.active;
    assert!(
        new_active > initial_active,
        "active stake must grow after inflation: initial={:?} new={:?}",
        initial_active, new_active
    );
    // The credited amount equals the minted inflation (single validator gets all).
    let credited = new_active.checked_sub(initial_active).unwrap();
    assert_eq!(
        credited.checked_add(out.burned_remainder).unwrap(),
        out.minted,
        "credited + burned_remainder must equal minted (invariant)"
    );
}

/// EpochOutput.minted matches compute_epoch_inflation output exactly.
#[test]
fn advance_epoch_minted_matches_compute_epoch_inflation() {
    let supply = Amount::from_drop(1_000_000_000 * DROPS_PER_LEM); // 1B LEM
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 25_000_000)]);
    let epoch = make_epoch(0, &vs); // epoch 0

    let out = advance_epoch(
        &epoch, &mut vs, &[], supply, 1_000, 100, min_stake(),
    ).unwrap();

    // advance_epoch closes epoch 0 → next_number = 1;
    // compute_epoch_inflation uses current.number (0) for the rate.
    let expected_minted = compute_epoch_inflation(supply, 0).unwrap();
    assert_eq!(out.minted, expected_minted,
        "EpochOutput.minted must equal compute_epoch_inflation(supply, epoch 0)");
}

/// With zero total supply, minted = 0 and burned_remainder = 0.
#[test]
fn advance_epoch_zero_supply_gives_zero_minted_zero_remainder() {
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 25_000_000)]);
    let epoch = make_epoch(0, &vs);
    let out = run_advance(&epoch, &mut vs, 1_000).unwrap(); // uses Amount::zero() supply

    assert!(out.minted.is_zero(), "zero supply → zero minted");
    assert!(out.burned_remainder.is_zero(), "zero supply → zero burned_remainder");
}

/// Reward is distributed BEFORE stake settlement — auto-compounds into next epoch power.
/// Reward credited to active → affects ValidatorSet(N+1) voting power.
#[test]
fn advance_epoch_reward_compounds_into_next_epoch_power() {
    let supply = Amount::from_drop(1_000_000_000 * DROPS_PER_LEM); // 1B LEM

    // One validator with exactly min_stake — would be at the eligibility edge.
    let mut vs = make_validators(&[(1, ValidatorStatus::Bonded, 20_000_000)]);
    let epoch = make_epoch(0, &vs);

    let out_with_rewards = advance_epoch(
        &epoch, &mut vs, &[], supply, 1_000, 100, min_stake(),
    ).unwrap();

    // The next committee's power must include the reward (it was credited before step 5).
    let power_with = out_with_rewards.epoch.validators.members[&addr(1)].power.as_amount();

    // Run again without rewards (zero supply) for comparison.
    let mut vs2 = make_validators(&[(1, ValidatorStatus::Bonded, 20_000_000)]);
    let epoch2 = make_epoch(0, &vs2);
    let out_no_rewards = run_advance(&epoch2, &mut vs2, 1_000).unwrap();
    let power_without = out_no_rewards.epoch.validators.members[&addr(1)].power.as_amount();

    assert!(
        power_with > power_without,
        "next-epoch power must be higher when inflation is credited before committee recompute"
    );
}
