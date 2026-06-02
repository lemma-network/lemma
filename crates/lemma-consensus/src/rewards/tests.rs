//! Tests for `lemma_consensus::rewards` — inflation + distribution (B2, spec §7).
//!
//! ## Coverage
//!
//! - **Inflation**: correct rate per year (Yr1–Yr6+), floor clamp, epoch→year
//!   boundary exactness, zero supply, round-down semantics.
//! - **Distribution**: proportional shares, remainder invariant (Σ + remainder = pool),
//!   single-validator, empty active set, zero pool, determinism, no-panic large supply.
//! - **Integration**: self_stake.active credited correctly, commission v1 note.

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::{Amount, DROPS_PER_DRIP, DROPS_PER_LEM},
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus, VotingPower},
    validator_set::{Member, ValidatorSet},
};

use crate::rewards::{
    compute_epoch_inflation, distribute_rewards, RewardOutcome, EPOCHS_PER_YEAR,
    INFLATION_SCHEDULE_BPS,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn lem(n: u128) -> Amount {
    Amount::from_drop(n * DROPS_PER_LEM)
}

fn drip(n: u128) -> Amount {
    Amount::from_drop(n * DROPS_PER_DRIP)
}

/// Build a minimal ValidatorSet for `distribute_rewards` tests.
///
/// `members`: list of (addr_byte, power_in_lem).
fn make_vset(members: &[(u8, u128)]) -> ValidatorSet {
    let map: BTreeMap<_, _> = members
        .iter()
        .map(|&(b, p)| {
            let power = VotingPower(lem(p));
            (
                addr(b),
                Member {
                    consensus_pubkey: dummy_key(b),
                    power,
                },
            )
        })
        .collect();
    let total_power = map.values().fold(Amount::zero(), |acc, m| {
        acc.checked_add(m.power.as_amount()).unwrap()
    });
    ValidatorSet {
        epoch: 0,
        members: map,
        total_power,
    }
}

/// Build a validator map matching a vset (for distribute_rewards mutations).
fn make_validators_for_vset(members: &[(u8, u128)]) -> BTreeMap<Address, Validator> {
    members
        .iter()
        .map(|&(b, p)| {
            let v = Validator {
                address: addr(b),
                consensus_pubkey: dummy_key(b),
                status: ValidatorStatus::Bonded,
                tombstoned: false,
                self_stake: Stake {
                    active: lem(p),
                    pending_active: Amount::zero(),
                    pending_inactive: Vec::new(),
                    inactive: Amount::zero(),
                },
                delegated: Amount::zero(),
                commission_bps: 0,
                jailed_until: None,
            };
            (v.address, v)
        })
        .collect()
}

fn dummy_key(b: u8) -> ConsensusKey {
    ConsensusKey::from_bytes(vec![b; 32], vec![b; 32])
}

/// Verify the `distributed + burned_remainder == pool` invariant.
fn assert_pool_invariant(outcome: &RewardOutcome, pool: Amount) {
    let reconstructed = outcome
        .distributed
        .checked_add(outcome.burned_remainder)
        .unwrap();
    assert_eq!(
        reconstructed, pool,
        "invariant violated: distributed + burned_remainder != pool"
    );
}

// ── compute_epoch_inflation: rate schedule ────────────────────────────────────

/// Helper: check inflation rate for a given epoch against expected bps.
fn check_inflation_rate(epoch: u64, expected_bps: u32) {
    // Use 1 LEM supply for easy ratio math.
    let supply = lem(1_000_000_000); // 1B LEM
    let minted = compute_epoch_inflation(supply, epoch).unwrap();
    // Expected per-epoch amount: supply × bps / 10_000 / 365 (integer, round down)
    let expected = supply
        .checked_mul(u128::from(expected_bps))
        .unwrap()
        .checked_div(10_000)
        .unwrap()
        .checked_div(u128::from(EPOCHS_PER_YEAR))
        .unwrap();
    assert_eq!(
        minted, expected,
        "epoch {epoch}: wrong inflation (expected {expected_bps} bps)"
    );
}

#[test]
fn inflation_year_1_rate_is_200_bps_per_epoch() {
    // Epoch 0 → year 0 → 2.00% = 200 bps.
    check_inflation_rate(0, INFLATION_SCHEDULE_BPS[0]);
}

#[test]
fn inflation_epoch_364_is_still_year_1() {
    // epoch 364 / 365 = 0 → still year 1.
    check_inflation_rate(364, INFLATION_SCHEDULE_BPS[0]);
}

#[test]
fn inflation_epoch_365_is_year_2() {
    // epoch 365 / 365 = 1 → year 2 → 1.70% = 170 bps.
    check_inflation_rate(365, INFLATION_SCHEDULE_BPS[1]);
}

#[test]
fn inflation_year_2_rate_is_170_bps_per_epoch() {
    check_inflation_rate(365, INFLATION_SCHEDULE_BPS[1]);
}

#[test]
fn inflation_year_3_rate_is_140_bps_per_epoch() {
    check_inflation_rate(365 * 2, INFLATION_SCHEDULE_BPS[2]);
}

#[test]
fn inflation_year_4_rate_is_120_bps_per_epoch() {
    check_inflation_rate(365 * 3, INFLATION_SCHEDULE_BPS[3]);
}

#[test]
fn inflation_year_5_rate_is_100_bps_per_epoch() {
    check_inflation_rate(365 * 4, INFLATION_SCHEDULE_BPS[4]);
}

#[test]
fn inflation_year_6_rate_is_80_bps_floor() {
    check_inflation_rate(365 * 5, INFLATION_SCHEDULE_BPS[5]);
}

#[test]
fn inflation_floor_applies_beyond_year_6() {
    // Year 10, year 50 — all should hit the 0.8% floor (index 5).
    check_inflation_rate(365 * 9, INFLATION_SCHEDULE_BPS[5]);
    check_inflation_rate(365 * 49, INFLATION_SCHEDULE_BPS[5]);
}

#[test]
fn inflation_zero_supply_yields_zero() {
    let minted = compute_epoch_inflation(Amount::zero(), 0).unwrap();
    assert!(minted.is_zero(), "zero supply must produce zero inflation");
}

#[test]
fn inflation_rounds_down_not_up() {
    // 1 LEM supply at 200 bps / 365: 1e18 × 200 / 10000 / 365 = 547945205...
    // Integer division rounds down. Verify no rounding-up artifact.
    let supply = lem(1); // 1 LEM = 1e18 Drop
    let minted = compute_epoch_inflation(supply, 0).unwrap();
    // Hand-compute: 1e18 × 200 / 10_000 / 365 = 547_945_205_479_452 Drop (truncated)
    let expected_drop: u128 = 1_000_000_000_000_000_000u128 * 200 / 10_000 / 365;
    assert_eq!(minted.as_drop(), expected_drop);
}

#[test]
fn inflation_1b_lem_year1_approximately_54794_lem_per_epoch() {
    // 1B LEM at 2%/yr: 1B × 0.02 / 365 ≈ 54,794.52 LEM/epoch → truncated.
    let supply = lem(1_000_000_000);
    let minted = compute_epoch_inflation(supply, 0).unwrap();
    // Expected: 1e27 × 200 / 10_000 / 365 = 54_794_520_547_945_205_479_452 Drop
    //         ≈ 54_794.52 LEM (truncated to 54_794 LEM + some drops)
    let lem_part = minted.as_drop() / DROPS_PER_LEM;
    assert_eq!(
        lem_part, 54_794,
        "~54,794 LEM per epoch for 1B supply at 2%/yr"
    );
}

// ── distribute_rewards: single validator ─────────────────────────────────────

#[test]
fn distribute_single_validator_gets_pool_rounded_to_drip() {
    let pool = drip(1_000); // 1000 Drip (exactly divisible)
    let vset = make_vset(&[(1, 20_000_000)]);
    let mut vs = make_validators_for_vset(&[(1, 20_000_000)]);

    let outcome = distribute_rewards(&mut vs, &vset, pool).unwrap();

    // Single validator → 100% of pool (before Drip rounding).
    // pool_drip = 1_000, power_drip = total_power_drip → share = pool_drip × 1 / 1 = 1_000 Drip
    assert_eq!(
        outcome.distributed, pool,
        "single validator should receive full pool"
    );
    assert!(
        outcome.burned_remainder.is_zero(),
        "no remainder with exact Drip pool"
    );
    assert_pool_invariant(&outcome, pool);
}

#[test]
fn distribute_credits_to_self_stake_active() {
    let pool = drip(1_000);
    let initial_active = lem(20_000_000);
    let vset = make_vset(&[(1, 20_000_000)]);
    let mut vs = make_validators_for_vset(&[(1, 20_000_000)]);

    // Outcome unused here — this test asserts the mutation to self_stake.active.
    let _ = distribute_rewards(&mut vs, &vset, pool).unwrap();

    let new_active = vs[&addr(1)].self_stake.active;
    assert_eq!(
        new_active,
        initial_active.checked_add(pool).unwrap(),
        "reward must be credited to self_stake.active (auto-compound)"
    );
}

#[test]
fn distribute_zero_pool_yields_zero_distributed_zero_remainder() {
    let vset = make_vset(&[(1, 20_000_000)]);
    let mut vs = make_validators_for_vset(&[(1, 20_000_000)]);

    let outcome = distribute_rewards(&mut vs, &vset, Amount::zero()).unwrap();

    assert!(outcome.distributed.is_zero());
    assert!(outcome.burned_remainder.is_zero());
    assert_pool_invariant(&outcome, Amount::zero());
}

// ── distribute_rewards: two validators ───────────────────────────────────────

#[test]
fn distribute_two_validators_equal_power_get_equal_shares() {
    // Both validators have 20M LEM power → each gets ~50% of pool.
    let pool = drip(2_000); // 2000 Drip
    let vset = make_vset(&[(1, 20_000_000), (2, 20_000_000)]);
    let mut vs = make_validators_for_vset(&[(1, 20_000_000), (2, 20_000_000)]);

    let outcome = distribute_rewards(&mut vs, &vset, pool).unwrap();

    let share1 = vs[&addr(1)]
        .self_stake
        .active
        .checked_sub(lem(20_000_000))
        .unwrap();
    let share2 = vs[&addr(2)]
        .self_stake
        .active
        .checked_sub(lem(20_000_000))
        .unwrap();
    assert_eq!(share1, share2, "equal power → equal shares");
    assert_pool_invariant(&outcome, pool);
}

#[test]
fn distribute_two_validators_unequal_power_proportional_shares() {
    // Validator 1 has 3× the power of validator 2.
    // pool = 4000 Drip → v1 gets 3000, v2 gets 1000 (exact).
    let pool = drip(4_000);
    let vset = make_vset(&[(1, 30_000_000), (2, 10_000_000)]);
    let mut vs = make_validators_for_vset(&[(1, 30_000_000), (2, 10_000_000)]);

    let outcome = distribute_rewards(&mut vs, &vset, pool).unwrap();

    let share1 = vs[&addr(1)]
        .self_stake
        .active
        .checked_sub(lem(30_000_000))
        .unwrap();
    let share2 = vs[&addr(2)]
        .self_stake
        .active
        .checked_sub(lem(10_000_000))
        .unwrap();

    // 3:1 ratio — shares must reflect proportional power
    // share1/share2 == 3 (when pool divides evenly)
    assert_eq!(
        share1.as_drop() / share2.as_drop(),
        3,
        "validator with 3× power must receive 3× the reward"
    );
    assert_pool_invariant(&outcome, pool);
}

// ── distribute_rewards: remainder / invariant ─────────────────────────────────

#[test]
fn distribute_sum_invariant_distributed_plus_remainder_equals_pool() {
    // Use a pool that does NOT divide evenly into Drip amounts for two validators.
    // 1 LEM + 1 Drop (not Drip-aligned).
    let pool = lem(1).checked_add(Amount::from_drop(1)).unwrap();
    let vset = make_vset(&[(1, 20_000_000), (2, 30_000_000)]);
    let mut vs = make_validators_for_vset(&[(1, 20_000_000), (2, 30_000_000)]);

    let outcome = distribute_rewards(&mut vs, &vset, pool).unwrap();
    assert_pool_invariant(&outcome, pool);
}

#[test]
fn distribute_remainder_is_less_than_validators_times_drops_per_drip() {
    // Remainder must be < #validators × DROPS_PER_DRIP (spec §7 / DB-5).
    let pool = lem(100);
    let vset = make_vset(&[(1, 20_000_000), (2, 30_000_000)]);
    let mut vs = make_validators_for_vset(&[(1, 20_000_000), (2, 30_000_000)]);

    let outcome = distribute_rewards(&mut vs, &vset, pool).unwrap();
    let max_remainder = 2 * DROPS_PER_DRIP; // 2 validators × 1 Drip each
    assert!(
        outcome.burned_remainder.as_drop() < max_remainder,
        "burned_remainder {} must be < {} (2 validators × DROPS_PER_DRIP)",
        outcome.burned_remainder.as_drop(),
        max_remainder,
    );
}

// ── distribute_rewards: empty active set ─────────────────────────────────────

#[test]
fn distribute_empty_vset_burns_entire_pool() {
    let pool = drip(500);
    let empty_vset = ValidatorSet {
        epoch: 0,
        members: BTreeMap::new(),
        total_power: Amount::zero(),
    };
    let mut vs: BTreeMap<Address, Validator> = BTreeMap::new();

    let outcome = distribute_rewards(&mut vs, &empty_vset, pool).unwrap();

    assert!(
        outcome.distributed.is_zero(),
        "no validators → nothing distributed"
    );
    assert_eq!(
        outcome.burned_remainder, pool,
        "entire pool must be burned as remainder"
    );
    assert_pool_invariant(&outcome, pool);
}

// ── distribute_rewards: determinism ──────────────────────────────────────────

#[test]
fn distribute_deterministic_same_input_same_output() {
    let pool = drip(99_999);
    let specs = &[(1u8, 20_000_000u128), (2, 30_000_000), (3, 10_000_000)];

    let run = || {
        let vset = make_vset(specs);
        let mut vs = make_validators_for_vset(specs);
        // Outcome unused — this test asserts determinism via the mutated balances.
        let _ = distribute_rewards(&mut vs, &vset, pool).unwrap();
        // Return all active balances (sorted by address — BTreeMap order).
        vs.values()
            .map(|v| v.self_stake.active.as_drop())
            .collect::<Vec<_>>()
    };

    assert_eq!(run(), run(), "distribute_rewards must be deterministic");
}

// ── distribute_rewards: production-scale no-panic ────────────────────────────

#[test]
fn distribute_no_panic_large_supply_and_power() {
    // Simulates a single validator holding all 1B LEM.
    // This is the worst-case for pool_drip × power_drip overflow.
    // At 1B LEM, 2%/yr: pool ≈ 5.5×10²² Drop; power = 1×10²⁷ Drop.
    // In Drip units: product ≈ 5.5×10¹³ × 10¹⁸ = 5.5×10³¹ < u128::MAX (DB-4).
    let supply = lem(1_000_000_000); // 1B LEM
    let pool = compute_epoch_inflation(supply, 0).expect("inflation must not overflow");
    let vset = make_vset(&[(1, 1_000_000_000)]);
    let mut vs = make_validators_for_vset(&[(1, 1_000_000_000)]);

    let outcome = distribute_rewards(&mut vs, &vset, pool)
        .expect("distribution must not overflow for 1B-LEM worst case");
    assert_pool_invariant(&outcome, pool);
}

// ── commission v1 note ────────────────────────────────────────────────────────

#[test]
fn distribute_commission_bps_nonzero_does_not_affect_self_only_v1() {
    // With no delegators (F1 = Phase 3), commission_bps is a no-op.
    // Validator 1 has 50% commission but gets same reward as validator 2 with 0%.
    let pool = drip(2_000);
    let vset = make_vset(&[(1, 20_000_000), (2, 20_000_000)]);
    let mut vs = make_validators_for_vset(&[(1, 20_000_000), (2, 20_000_000)]);
    // Set nonzero commission on validator 1.
    vs.get_mut(&addr(1)).unwrap().commission_bps = 5_000; // 50%

    let _outcome = distribute_rewards(&mut vs, &vset, pool).unwrap();

    // Both validators have equal power → equal shares (commission doesn't split
    // anything yet in v1, where delegated == 0 for all).
    let share1 = vs[&addr(1)]
        .self_stake
        .active
        .checked_sub(lem(20_000_000))
        .unwrap();
    let share2 = vs[&addr(2)]
        .self_stake
        .active
        .checked_sub(lem(20_000_000))
        .unwrap();
    assert_eq!(
        share1, share2,
        "commission_bps is a v1 no-op (no delegators); both validators earn equal shares"
    );
}
