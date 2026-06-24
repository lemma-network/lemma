//! Tests for `lemma_consensus::fee` — Burn Fee Model (Step 10).
//!
//! ## Coverage strategy
//!
//! - `calculate_base_fee`: unchanged/increase/decrease branches, max-change cap
//!   (±12.5%), min-delta floor (1 Drop), MIN_BASE_FEE clamp, genesis-zero ramp,
//!   overflow error, determinism.
//! - `distribute_fee`: burned/tip split, invariant `burned+tip==price×gas`,
//!   zero-tip case, gas_price-below-base error, zero gas, overflow.
//! - Proptest: `calculate_base_fee` never returns below MIN_BASE_FEE; `distribute_fee`
//!   sum invariant for valid inputs.

use lemma_core::{
    address::Address, amount::Amount, error::AmountError, hash::Hash, header::BlockHeader,
};

use crate::fee::{calculate_base_fee, distribute_fee, FeeDistribution, MIN_BASE_FEE_DROP};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// 1 Drip in Drop units (= MIN_BASE_FEE_DROP).
const ONE_DRIP: u128 = 1_000_000_000;

fn drip(n: u128) -> Amount {
    Amount::from_drop(n * ONE_DRIP)
}

fn drop_(n: u128) -> Amount {
    Amount::from_drop(n)
}

/// Construct a minimal valid `BlockHeader` with the given gas parameters.
///
/// All non-gas fields are set to their zero/empty sentinel values — this is
/// acceptable for fee calculation, which only reads `base_fee`, `gas_limit`,
/// and `gas_used`.
fn gas_header(gas_limit: u64, gas_used: u64, base_fee: Amount) -> BlockHeader {
    BlockHeader {
        height: 1,
        timestamp: 1_000,
        parent_hash: Hash::zero(),
        transactions_root: Hash::zero(),
        state_root: Hash::zero(),
        receipts_root: Hash::zero(),
        proposer: Address::zero(),
        epoch: 0,
        protocol_version: 1,
        dag_round: 0,
        dag_anchor: Hash::zero(),
        validators_hash: Hash::zero(),
        next_validators_hash: Hash::zero(),
        gas_limit,
        gas_used,
        base_fee,
        extra_data: vec![],
    }
}

// ── calculate_base_fee — branch tests ────────────────────────────────────────

#[test]
fn unchanged_when_gas_used_equals_target() {
    // gas_used == gas_limit/2 → no change (above MIN_BASE_FEE).
    let parent = gas_header(20_000_000, 10_000_000, drip(8));
    assert_eq!(calculate_base_fee(&parent).unwrap(), drip(8));
}

#[test]
fn increases_when_above_target() {
    // gas_limit=20M, gas_used=15M, target=10M, base_fee=8 Drip.
    // delta = 8e9 × 5_000_000 / 10_000_000 / 8 = 500_000_000 Drop (0.5 Drip).
    // new_fee = 8.5 Drip.
    let parent = gas_header(20_000_000, 15_000_000, drip(8));
    let expected = Amount::from_drop(8_500_000_000);
    assert_eq!(calculate_base_fee(&parent).unwrap(), expected);
}

#[test]
fn decreases_when_below_target() {
    // gas_limit=20M, gas_used=5M, target=10M, base_fee=8 Drip.
    // delta = 8e9 × 5_000_000 / 10_000_000 / 8 = 500_000_000 Drop (0.5 Drip).
    // new_fee = 7.5 Drip.
    let parent = gas_header(20_000_000, 5_000_000, drip(8));
    let expected = Amount::from_drop(7_500_000_000);
    assert_eq!(calculate_base_fee(&parent).unwrap(), expected);
}

#[test]
fn max_increase_at_full_block() {
    // gas_used == gas_limit (100% full).
    // delta = base_fee × target / target / 8 = base_fee / 8 (max delta).
    // 8 Drip / 8 = 1 Drip → new_fee = 9 Drip.
    let parent = gas_header(20_000_000, 20_000_000, drip(8));
    assert_eq!(calculate_base_fee(&parent).unwrap(), drip(9));
}

#[test]
fn max_decrease_at_empty_block() {
    // gas_used == 0 (empty block).
    // delta = base_fee / 8 = 1 Drip → new_fee = 7 Drip.
    let parent = gas_header(20_000_000, 0, drip(8));
    assert_eq!(calculate_base_fee(&parent).unwrap(), drip(7));
}

#[test]
fn increase_capped_at_12_5_percent() {
    // Full block: max increase = 12.5% of base_fee.
    let base = drip(1000); // 1000 Drip
    let parent = gas_header(20_000_000, 20_000_000, base);
    let next = calculate_base_fee(&parent).unwrap();
    // delta = 1000 Drip / 8 = 125 Drip → new = 1125 Drip
    assert_eq!(next, drip(1125));
    // Verify: increase ≤ 12.5% of original
    let increase = next.as_drop() - base.as_drop();
    assert!(
        increase * 8 <= base.as_drop(),
        "increase exceeded 12.5% cap"
    );
}

#[test]
fn decrease_capped_at_12_5_percent() {
    // Empty block: max decrease = 12.5% of base_fee.
    let base = drip(1000);
    let parent = gas_header(20_000_000, 0, base);
    let next = calculate_base_fee(&parent).unwrap();
    // delta = 125 Drip → new = 875 Drip
    assert_eq!(next, drip(875));
    let decrease = base.as_drop() - next.as_drop();
    assert!(
        decrease * 8 <= base.as_drop(),
        "decrease exceeded 12.5% cap"
    );
}

#[test]
fn min_delta_1_drop_when_formula_truncates_to_zero() {
    // Need delta = base_fee × gas_diff / target / 8 to truncate to 0.
    // Use gas_limit = 5_000_000_000 → target = 2_500_000_000, gas_diff = 1.
    // delta = 2e9 × 1 / 2_500_000_000 / 8 = 0 (2e9 < 2.5e9, integer truncation).
    // min-delta floor: delta = 1 Drop → new_fee = 2_000_000_001 Drop.
    // (Above MIN_BASE_FEE, so clamp does not interfere.)
    let gas_limit = 5_000_000_000_u64;
    let target = gas_limit / 2;
    let parent = gas_header(gas_limit, target + 1, drip(2));
    let next = calculate_base_fee(&parent).unwrap();
    assert_eq!(
        next,
        Amount::from_drop(2 * ONE_DRIP + 1),
        "min-delta must ensure at least 1 Drop increase when delta truncates to 0"
    );
}

#[test]
fn decrease_from_below_floor_clamps_up_to_min_base_fee() {
    // base_fee = 0.5 Drip = 500_000_000 Drop (already below MIN_BASE_FEE floor).
    // Empty block: delta = 500_000_000 / 8 = 62_500_000 Drop.
    // new_fee_drop = 500_000_000 - 62_500_000 = 437_500_000 Drop.
    // Clamp: max(437_500_000, 1_000_000_000) = 1_000_000_000 = MIN_BASE_FEE.
    // Verifies the clamp is the final operation (applied even when starting below floor).
    let parent = gas_header(20_000_000, 0, drop_(500_000_000));
    let next = calculate_base_fee(&parent).unwrap();
    assert_eq!(
        next.as_drop(),
        MIN_BASE_FEE_DROP,
        "decrease starting below floor must clamp UP to MIN_BASE_FEE"
    );
}

#[test]
fn clamps_to_min_base_fee_when_decrease_would_go_below() {
    // base_fee = 1 Drip (floor), empty block.
    // delta = 1e9 / 8 = 125_000_000 Drop → would-be new = 875_000_000 Drop.
    // Clamp: max(875_000_000, 1_000_000_000) = 1_000_000_000 = 1 Drip.
    let parent = gas_header(20_000_000, 0, drip(1));
    let next = calculate_base_fee(&parent).unwrap();
    assert_eq!(next, drip(1), "fee must not drop below MIN_BASE_FEE");
}

#[test]
fn genesis_zero_base_fee_ramps_to_min_base_fee() {
    // initial_base_fee = 0 (genesis devnet start). Any utilization → MIN_BASE_FEE.
    let parent = gas_header(20_000_000, 10_000_000, Amount::zero()); // at target
    let next = calculate_base_fee(&parent).unwrap();
    assert_eq!(
        next.as_drop(),
        MIN_BASE_FEE_DROP,
        "genesis base_fee=0 must clamp to MIN_BASE_FEE at block 1"
    );
}

#[test]
fn genesis_zero_base_fee_above_target_ramps_to_min() {
    // genesis base_fee=0, above target: delta = 0 * anything = 0, delta.max(1)=1
    // → 0+1=1 Drop, clamped to MIN_BASE_FEE.
    let parent = gas_header(20_000_000, 15_000_000, Amount::zero());
    let next = calculate_base_fee(&parent).unwrap();
    assert_eq!(next.as_drop(), MIN_BASE_FEE_DROP);
}

#[test]
fn overflow_returns_err_not_panic() {
    // base_fee = u128::MAX, gas_used > target → checked_mul overflows → Err.
    let parent = gas_header(20_000_000, 20_000_000, Amount::from_drop(u128::MAX));
    let result = calculate_base_fee(&parent);
    assert!(
        matches!(result, Err(AmountError::Overflow { .. })),
        "overflow must return Err, not panic"
    );
}

#[test]
fn gas_limit_one_returns_parent_fee_clamped() {
    // gas_limit = 1 → target = 0 → early return with clamp.
    let parent = gas_header(1, 0, drip(5));
    assert_eq!(calculate_base_fee(&parent).unwrap(), drip(5));
    // With base_fee below MIN:
    let parent2 = gas_header(1, 0, Amount::zero());
    assert_eq!(
        calculate_base_fee(&parent2).unwrap().as_drop(),
        MIN_BASE_FEE_DROP
    );
}

#[test]
fn calculate_base_fee_is_deterministic() {
    let parent = gas_header(20_000_000, 15_000_000, drip(8));
    assert_eq!(
        calculate_base_fee(&parent).unwrap(),
        calculate_base_fee(&parent).unwrap(),
    );
}

// ── distribute_fee ────────────────────────────────────────────────────────────

#[test]
fn burns_base_fee_times_gas_used() {
    // burned = 5 Drip × 21_000 = 105_000 Drip.
    let result = distribute_fee(21_000, drip(5), drip(8)).unwrap();
    assert_eq!(result.burned, drip(105_000));
}

#[test]
fn tip_is_price_minus_base_times_gas_used() {
    // to_proposer = (8-5) Drip × 21_000 = 63_000 Drip.
    let result = distribute_fee(21_000, drip(5), drip(8)).unwrap();
    assert_eq!(result.to_proposer, drip(63_000));
}

#[test]
fn zero_tip_when_gas_price_equals_base_fee() {
    // gas_price == base_fee → tip = 0.
    let result = distribute_fee(21_000, drip(5), drip(5)).unwrap();
    assert_eq!(result.to_proposer, Amount::zero());
    assert_eq!(result.burned, drip(105_000));
}

#[test]
fn gas_price_below_base_returns_err() {
    // gas_price < base_fee → AmountError::Underflow (D10d).
    let result = distribute_fee(21_000, drip(5), drip(4));
    assert!(
        matches!(result, Err(AmountError::Underflow { .. })),
        "gas_price below base_fee must return Underflow error"
    );
}

#[test]
fn zero_gas_used_gives_zero_fees() {
    let result = distribute_fee(0, drip(5), drip(8)).unwrap();
    assert_eq!(result.burned, Amount::zero());
    assert_eq!(result.to_proposer, Amount::zero());
}

/// Invariant: `burned + to_proposer == gas_price × gas_used` (no rounding loss).
#[test]
fn burned_plus_tip_equals_total_charged() {
    let gas_used = 21_000u64;
    let base_fee = drip(5);
    let gas_price = drip(8);
    let FeeDistribution {
        burned,
        to_proposer,
    } = distribute_fee(gas_used, base_fee, gas_price).unwrap();

    let total = burned.checked_add(to_proposer).unwrap();
    let expected = gas_price.checked_mul(gas_used as u128).unwrap();
    assert_eq!(
        total, expected,
        "burned + to_proposer must equal gas_price × gas_used exactly"
    );
}

#[test]
fn distribute_fee_overflow_returns_err() {
    // base_fee = u128::MAX / 2, gas_used = 3 → burned overflows.
    let base = Amount::from_drop(u128::MAX / 2 + 1);
    let price = Amount::from_drop(u128::MAX);
    let result = distribute_fee(3, base, price);
    assert!(matches!(result, Err(AmountError::Overflow { .. })));
}

// ── Proptest invariants ────────────────────────────────────────────────────────

#[cfg(test)]
mod prop {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Base fee never falls below MIN_BASE_FEE_DROP for any valid parent header.
        #[test]
        fn base_fee_never_below_min(
            gas_limit in 2u64..30_000_000,
            gas_used_frac in 0u64..=100,          // as percentage of gas_limit
            base_fee_drop in 0u128..=10_000_000_000_000u128, // up to 10_000 Drip
        ) {
            let gas_used = (gas_limit as u128 * gas_used_frac as u128 / 100) as u64;
            let parent = gas_header(gas_limit, gas_used, Amount::from_drop(base_fee_drop));
            if let Ok(next) = calculate_base_fee(&parent) {
                prop_assert!(
                    next.as_drop() >= MIN_BASE_FEE_DROP,
                    "next={} < MIN_BASE_FEE={}",
                    next.as_drop(),
                    MIN_BASE_FEE_DROP,
                );
            }
            // If Err (overflow), that's also acceptable — no panic.
        }

        /// `burned + to_proposer == gas_price × gas_used` for all valid inputs.
        #[test]
        fn distribute_sum_invariant(
            gas_used in 0u64..10_000_000,
            base_drip in 1u128..=1_000_000u128,
            tip_drip  in 0u128..=1_000_000u128,
        ) {
            let base_fee  = Amount::from_drop(base_drip * 1_000_000_000);
            let gas_price = Amount::from_drop((base_drip + tip_drip) * 1_000_000_000);
            if let Ok(FeeDistribution { burned, to_proposer }) =
                distribute_fee(gas_used, base_fee, gas_price)
            {
                if let Ok(total) = burned.checked_add(to_proposer) {
                    if let Ok(expected) = gas_price.checked_mul(gas_used as u128) {
                        prop_assert_eq!(total, expected);
                    }
                }
            }
        }

        /// `calculate_base_fee` is a pure function: same input → same output.
        #[test]
        fn calculate_is_deterministic(
            gas_limit in 2u64..30_000_000,
            gas_used  in 0u64..30_000_000,
            base_fee_drop in 0u128..=10_000_000_000_000u128,
        ) {
            let gas_used = gas_used.min(gas_limit);
            let parent = gas_header(gas_limit, gas_used, Amount::from_drop(base_fee_drop));
            let r1 = calculate_base_fee(&parent);
            let r2 = calculate_base_fee(&parent);
            match (r1, r2) {
                (Ok(a), Ok(b)) => prop_assert_eq!(a, b),
                (Err(_), Err(_)) => {} // both error identically
                _ => prop_assert!(false, "results must agree (both Ok or both Err)"),
            }
        }
    }
}
