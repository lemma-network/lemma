//! Tests for `lemma_mempool::qos`.
//!
//! Covers:
//! - Base behavior: zero/nonzero stake, gas_price dominance.
//! - Stake bonus arithmetic: linear scaling, sub-unit truncation, cap boundary.
//! - Monotonicity: priority increases with gas_price and with stake (up to cap).
//! - Saturation: u128::MAX inputs never panic or wrap.
//! - Ordering guarantees: stake tie-break and gas tie-break.

use lemma_core::{amount::DROPS_PER_LEM, Amount};

use crate::qos::{
    priority_score, saturating_u128_to_u64, stake_bonus, MAX_STAKE_BONUS, STAKE_UNIT,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// 1 LEM in Drop.
fn one_lem() -> Amount {
    Amount::from_drop(DROPS_PER_LEM)
}

/// `n` LEM in Drop.
fn lem(n: u128) -> Amount {
    Amount::from_drop(DROPS_PER_LEM * n)
}

// ── stake_bonus — unit tests ──────────────────────────────────────────────────

#[test]
fn stake_bonus_zero_stake_returns_zero() {
    assert_eq!(stake_bonus(Amount::zero()), 0);
}

#[test]
fn stake_bonus_one_unit_returns_one() {
    // Exactly STAKE_UNIT Drop → bonus == 1.
    assert_eq!(stake_bonus(Amount::from_drop(STAKE_UNIT)), 1);
}

#[test]
fn stake_bonus_two_units_returns_two() {
    assert_eq!(stake_bonus(Amount::from_drop(STAKE_UNIT * 2)), 2);
}

#[test]
fn stake_bonus_sub_unit_returns_zero() {
    // Sub-unit stake earns no bonus (integer division truncates).
    assert_eq!(stake_bonus(Amount::from_drop(STAKE_UNIT - 1)), 0);
}

#[test]
fn stake_bonus_one_drop_below_two_units_returns_one() {
    // 1.999 units (STAKE_UNIT * 2 - 1) truncates to bonus 1 — verifies
    // that truncation works at a non-zero quotient, not just at zero.
    assert_eq!(stake_bonus(Amount::from_drop(STAKE_UNIT * 2 - 1)), 1);
}

#[test]
fn stake_bonus_at_cap_boundary_returns_max() {
    // Exactly MAX_STAKE_BONUS × STAKE_UNIT → bonus == MAX_STAKE_BONUS.
    let cap_stake = Amount::from_drop(MAX_STAKE_BONUS as u128 * STAKE_UNIT);
    assert_eq!(stake_bonus(cap_stake), MAX_STAKE_BONUS);
}

#[test]
fn stake_bonus_above_cap_returns_max() {
    // 10× over the cap still returns MAX_STAKE_BONUS, not more.
    let whale_stake = Amount::from_drop(MAX_STAKE_BONUS as u128 * STAKE_UNIT * 10);
    assert_eq!(stake_bonus(whale_stake), MAX_STAKE_BONUS);
}

#[test]
fn stake_bonus_max_u128_does_not_panic() {
    // u128::MAX stake → saturates, returns MAX_STAKE_BONUS.
    let p = stake_bonus(Amount::from_drop(u128::MAX));
    assert_eq!(
        p, MAX_STAKE_BONUS,
        "u128::MAX stake must saturate to cap, got {p}"
    );
}

// ── saturating_u128_to_u64 — unit tests ──────────────────────────────────────

#[test]
fn saturating_cast_zero_returns_zero() {
    assert_eq!(saturating_u128_to_u64(0), 0);
}

#[test]
fn saturating_cast_u64_max_returns_u64_max() {
    assert_eq!(saturating_u128_to_u64(u64::MAX as u128), u64::MAX);
}

#[test]
fn saturating_cast_above_u64_max_returns_u64_max() {
    assert_eq!(saturating_u128_to_u64(u64::MAX as u128 + 1), u64::MAX);
}

#[test]
fn saturating_cast_u128_max_returns_u64_max() {
    assert_eq!(saturating_u128_to_u64(u128::MAX), u64::MAX);
}

// ── priority_score — base behavior ───────────────────────────────────────────

#[test]
fn priority_zero_gas_zero_stake_is_zero() {
    assert_eq!(priority_score(Amount::zero(), Amount::zero()), 0);
}

#[test]
fn priority_zero_stake_equals_gas_component() {
    // With no stake, priority == gas_price in Drop (as long as it fits u64).
    let gas = Amount::from_drop(1_000_000);
    assert_eq!(priority_score(gas, Amount::zero()), 1_000_000);
}

#[test]
fn priority_one_lem_stake_adds_one_bonus() {
    let gas = Amount::from_drop(1_000);
    let p = priority_score(gas, one_lem());
    assert_eq!(p, 1_001, "1 LEM stake should add exactly 1 bonus");
}

#[test]
fn priority_two_lem_stake_adds_two_bonus() {
    let gas = Amount::from_drop(500);
    let p = priority_score(gas, lem(2));
    assert_eq!(p, 502);
}

#[test]
fn priority_sub_unit_stake_adds_no_bonus() {
    let gas = Amount::from_drop(1_000);
    let p_no_stake = priority_score(gas, Amount::zero());
    let p_sub_unit = priority_score(gas, Amount::from_drop(STAKE_UNIT - 1));
    assert_eq!(p_no_stake, p_sub_unit, "sub-unit stake must add no bonus");
}

// ── Monotonicity ──────────────────────────────────────────────────────────────

#[test]
fn priority_higher_gas_price_yields_higher_priority() {
    let stake = one_lem();
    let low = priority_score(Amount::from_drop(100), stake);
    let high = priority_score(Amount::from_drop(200), stake);
    assert!(high > low, "higher gas_price must yield higher priority");
}

#[test]
fn priority_higher_stake_yields_higher_or_equal_priority() {
    let gas = Amount::from_drop(1_000);
    let less = priority_score(gas, lem(1));
    let more = priority_score(gas, lem(2));
    assert!(more >= less, "higher stake must not yield lower priority");
}

#[test]
fn priority_stake_at_cap_not_higher_than_above_cap() {
    let gas = Amount::from_drop(1_000);
    let at_cap = priority_score(gas, Amount::from_drop(MAX_STAKE_BONUS as u128 * STAKE_UNIT));
    let above_cap = priority_score(
        gas,
        Amount::from_drop(MAX_STAKE_BONUS as u128 * STAKE_UNIT * 2),
    );
    assert_eq!(
        at_cap, above_cap,
        "above-cap stake must not increase priority beyond cap"
    );
}

// ── Ordering guarantees ───────────────────────────────────────────────────────

#[test]
fn priority_same_gas_staked_ranks_higher_than_unstaked() {
    let gas = Amount::from_drop(1_000);
    let unstaked = priority_score(gas, Amount::zero());
    let staked = priority_score(gas, one_lem());
    assert!(
        staked > unstaked,
        "staked account must rank higher when gas_price is equal"
    );
}

#[test]
fn priority_same_stake_higher_gas_price_wins() {
    let stake = lem(10);
    let low_gas = priority_score(Amount::from_drop(100), stake);
    let high_gas = priority_score(Amount::from_drop(200), stake);
    assert!(
        high_gas > low_gas,
        "higher gas_price must win when stake is equal"
    );
}

#[test]
fn priority_high_gas_can_outweigh_stake_bonus() {
    // A high-gas unstaked tx should beat a low-gas maxed-stake tx.
    //
    // Whale total = gas(1) + MAX_STAKE_BONUS = 1_000_001.
    // To strictly beat it, unstaked needs gas > 1_000_001, i.e. at least 1_000_002.
    // Using MAX_STAKE_BONUS + 2 = 1_000_002 for clarity.
    let unstaked_high_gas = priority_score(
        Amount::from_drop(MAX_STAKE_BONUS as u128 + 2),
        Amount::zero(),
    );
    let whale_low_gas = priority_score(
        Amount::from_drop(1),
        Amount::from_drop(MAX_STAKE_BONUS as u128 * STAKE_UNIT),
    );
    assert!(
        unstaked_high_gas > whale_low_gas,
        "gas_price {unstaked_high_gas} must beat whale {whale_low_gas}"
    );
}

// ── Saturation — no panic ─────────────────────────────────────────────────────

#[test]
fn priority_u128_max_gas_does_not_panic() {
    let p = priority_score(Amount::from_drop(u128::MAX), Amount::zero());
    assert_eq!(p, u64::MAX, "u128::MAX gas must saturate to u64::MAX");
}

#[test]
fn priority_u128_max_stake_does_not_panic() {
    let p = priority_score(Amount::zero(), Amount::from_drop(u128::MAX));
    assert_eq!(
        p, MAX_STAKE_BONUS,
        "u128::MAX stake must saturate to MAX_STAKE_BONUS"
    );
}

#[test]
fn priority_both_u128_max_does_not_panic() {
    // Both at max → gas saturates to u64::MAX, bonus to MAX_STAKE_BONUS.
    // saturating_add(u64::MAX, MAX_STAKE_BONUS) = u64::MAX.
    let p = priority_score(Amount::from_drop(u128::MAX), Amount::from_drop(u128::MAX));
    assert_eq!(p, u64::MAX, "both u128::MAX must saturate to u64::MAX");
}

#[test]
fn priority_near_u64_max_gas_plus_bonus_saturates() {
    // gas near u64::MAX + any bonus should saturate, not wrap.
    let gas_near_max = Amount::from_drop(u64::MAX as u128 - 1);
    let p = priority_score(gas_near_max, one_lem());
    assert_eq!(
        p,
        u64::MAX,
        "near-max gas + bonus must saturate to u64::MAX"
    );
}
