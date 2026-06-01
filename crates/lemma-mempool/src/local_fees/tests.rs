//! Tests for [`LocalFeeMarket`].

use super::{
    LocalFeeMarket, DECAY_DEN, HIGH_DEMAND_THRESHOLD, MAX_SURCHARGE_MULTIPLIER, SCALE_FACTOR,
};
use lemma_core::Address;

// ── Shared fixtures ───────────────────────────────────────────────────────────

/// Construct a distinct test address from a single-byte seed.
///
/// Uses `Address::from_public_key` with a 32-byte all-`n` key — deterministic,
/// requires no crypto, gives 256 distinct addresses for test isolation.
fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

/// Build a market whose `contract` EMA is exactly `target_ema` after one tick.
///
/// Relies on the steady-state-from-zero property: recording
/// `target_ema × DECAY_DEN` transactions in a single block and ticking once
/// yields `ema = (0 × DECAY_NUM + target_ema × DECAY_DEN) / DECAY_DEN = target_ema`.
///
/// Panics (in tests only) if `target_ema × DECAY_DEN` would overflow `u64`.
/// In practice all test values are far below that limit.
fn market_at_ema(contract: Address, target_ema: u64) -> LocalFeeMarket {
    let count = target_ema
        .checked_mul(DECAY_DEN)
        .expect("test helper: target_ema × DECAY_DEN overflows u64");
    let mut m = LocalFeeMarket::new();
    for _ in 0..count {
        m.record(&contract);
    }
    m.tick();
    m
}

// ── Construction ──────────────────────────────────────────────────────────────

#[test]
fn new_market_has_no_tracked_contracts() {
    let m = LocalFeeMarket::new();
    assert_eq!(m.tracked_contracts(), 0);
}

// ── contract_load ─────────────────────────────────────────────────────────────

#[test]
fn contract_load_returns_zero_for_untracked_contract() {
    let m = LocalFeeMarket::new();
    assert_eq!(m.contract_load(&addr(1)), 0);
}

#[test]
fn contract_load_returns_zero_before_first_tick() {
    // record() increments current_block_count only; contract_load reads the EMA
    // (committed after tick). Load is 0 until tick is called.
    let mut m = LocalFeeMarket::new();
    m.record(&addr(1));
    assert_eq!(m.contract_load(&addr(1)), 0);
}

#[test]
fn contract_load_returns_ema_after_tick() {
    let contract = addr(1);
    let m = market_at_ema(contract, 200);
    assert_eq!(m.contract_load(&contract), 200);
}

// ── local_base_fee — below threshold (no surcharge) ──────────────────────────

#[test]
fn local_base_fee_returns_global_base_for_untracked_contract() {
    let m = LocalFeeMarket::new();
    assert_eq!(m.local_base_fee(&addr(1), 1_000), 1_000);
}

#[test]
fn local_base_fee_returns_global_base_at_threshold_exactly() {
    // Condition is ema <= HIGH_DEMAND_THRESHOLD — threshold itself is not surcharged.
    let contract = addr(1);
    let m = market_at_ema(contract, HIGH_DEMAND_THRESHOLD);
    assert_eq!(m.local_base_fee(&contract, 1_000), 1_000);
}

#[test]
fn local_base_fee_returns_global_base_one_below_threshold() {
    let contract = addr(1);
    let m = market_at_ema(contract, HIGH_DEMAND_THRESHOLD - 1);
    assert_eq!(m.local_base_fee(&contract, 1_000), 1_000);
}

#[test]
fn global_base_zero_returns_zero_regardless_of_load() {
    // Saturating multiply: 0 × anything = 0. Hot contracts still return 0 if
    // the global base is 0 (e.g. a devnet/testnet with zero base fee).
    let contract = addr(1);
    let m = market_at_ema(contract, HIGH_DEMAND_THRESHOLD + SCALE_FACTOR);
    assert_eq!(m.local_base_fee(&contract, 0), 0);
}

// ── local_base_fee — above threshold (surcharge) ─────────────────────────────

#[test]
fn local_base_fee_applies_surcharge_one_above_threshold() {
    // ema = 101: multiplier = 1 + 101/100 = 1 + 1 = 2 → fee = 2 × global_base.
    let contract = addr(1);
    let m = market_at_ema(contract, HIGH_DEMAND_THRESHOLD + 1);
    assert!(
        m.local_base_fee(&contract, 1_000) > 1_000,
        "surcharge must exceed global_base when ema is above threshold"
    );
}

#[test]
fn local_base_fee_exact_multiplier_at_one_scale_factor_above_threshold() {
    // At ema = threshold + SCALE_FACTOR, excess = SCALE_FACTOR, so the
    // continuous formula gives exactly multiplier = (SF + SF) / SF = 2×.
    // (Symbolic — independent of the concrete THRESHOLD/SCALE_FACTOR values.)
    let contract = addr(1);
    let ema = HIGH_DEMAND_THRESHOLD + SCALE_FACTOR;
    let m = market_at_ema(contract, ema);
    let excess = ema - HIGH_DEMAND_THRESHOLD; // == SCALE_FACTOR
    let expected_fee = 1_000u64 * (SCALE_FACTOR + excess) / SCALE_FACTOR; // == 2000
    assert_eq!(m.local_base_fee(&contract, 1_000), expected_fee);
    assert_eq!(expected_fee, 2_000, "multiplier must be exactly 2× here");
}

#[test]
fn surcharge_is_continuous_no_cliff_at_threshold() {
    // Core Level-1 property: no step-function cliff at the threshold.
    // The old step-function jumped 1× → 2× at ema = THRESHOLD + 1.
    // The continuous formula must produce only a tiny, smooth increase.
    let contract = addr(1);
    let at_threshold = market_at_ema(contract, HIGH_DEMAND_THRESHOLD);
    let one_above = market_at_ema(contract, HIGH_DEMAND_THRESHOLD + 1);
    let global_base = 1_000u64;

    let fee_at = at_threshold.local_base_fee(&contract, global_base);
    let fee_above = one_above.local_base_fee(&contract, global_base);

    // At threshold: exactly global_base (excess = 0 → multiplier = 1.0×).
    assert_eq!(fee_at, global_base);

    // One above: excess = 1 → fee = global_base × (SCALE_FACTOR + 1) / SCALE_FACTOR.
    // Symbolic so it survives constant changes. With SCALE_FACTOR = 400 this is
    // 1000 × 401 / 400 = 1002 — a tiny, smooth rise, NOT the old 100% step jump.
    let expected_above = global_base * (SCALE_FACTOR + 1) / SCALE_FACTOR;
    assert_eq!(fee_above, expected_above);
    // The single-tx-above-threshold surcharge must be well under 1% — proving
    // continuity (the old step-function jumped to 2000, i.e. +100%).
    assert!(
        fee_above < global_base + global_base / SCALE_FACTOR + 1,
        "continuous surcharge at threshold+1 must be a sub-percent rise; got {fee_above}"
    );
}

#[test]
fn surcharge_multiplier_increases_with_load() {
    let contract = addr(1);
    let low = market_at_ema(contract, HIGH_DEMAND_THRESHOLD + 1);
    let high = market_at_ema(contract, HIGH_DEMAND_THRESHOLD + SCALE_FACTOR * 3);
    assert!(
        high.local_base_fee(&contract, 1_000) > low.local_base_fee(&contract, 1_000),
        "higher EMA load must produce a higher fee"
    );
}

#[test]
fn surcharge_caps_at_max_surcharge_multiplier() {
    // Extreme load: well above where the multiplier cap kicks in. The cap is
    // reached at excess = SCALE_FACTOR × (MAX-1); we use MAX × SCALE_FACTOR × 10,
    // comfortably past it, to confirm the fee clamps to MAX_SURCHARGE_MULTIPLIER.
    let contract = addr(1);
    let extreme_load = MAX_SURCHARGE_MULTIPLIER
        .checked_mul(SCALE_FACTOR)
        .and_then(|v| v.checked_mul(10))
        .expect("test value must not overflow");
    let m = market_at_ema(contract, extreme_load);
    assert_eq!(
        m.local_base_fee(&contract, 1_000),
        1_000 * MAX_SURCHARGE_MULTIPLIER,
        "fee must be capped at MAX_SURCHARGE_MULTIPLIER × global_base"
    );
}

// ── Isolation — core WHITEPAPER claim ─────────────────────────────────────────

#[test]
fn hot_contract_does_not_affect_cold_contract() {
    // WHITEPAPER §4: "Other contracts and simple transfers remain unaffected."
    let hot = addr(1);
    let cold = addr(2);
    let global_base = 1_000u64;

    // Push `hot` well above threshold.
    let mut m = LocalFeeMarket::new();
    for _ in 0..(HIGH_DEMAND_THRESHOLD + SCALE_FACTOR) * DECAY_DEN {
        m.record(&hot);
    }
    m.tick();

    assert_eq!(
        m.local_base_fee(&cold, global_base),
        global_base,
        "cold contract must pay exactly global_base regardless of hot contract load"
    );
    assert!(
        m.local_base_fee(&hot, global_base) > global_base,
        "hot contract must pay above global_base"
    );
}

#[test]
fn untracked_address_always_pays_global_base() {
    // An EOA (transfer recipient) never accumulates contract load.
    let hot_contract = addr(1);
    let unrelated_eoa = addr(99);
    let m = market_at_ema(hot_contract, HIGH_DEMAND_THRESHOLD + SCALE_FACTOR);
    assert_eq!(m.local_base_fee(&unrelated_eoa, 500), 500);
}

#[test]
fn multiple_hot_contracts_tracked_independently() {
    let a = addr(1);
    let b = addr(2);
    let global_base = 1_000u64;

    // Different load levels: b has 3× more load than a above threshold.
    let mut m = LocalFeeMarket::new();
    for _ in 0..(HIGH_DEMAND_THRESHOLD + SCALE_FACTOR) * DECAY_DEN {
        m.record(&a);
    }
    for _ in 0..(HIGH_DEMAND_THRESHOLD + SCALE_FACTOR * 3) * DECAY_DEN {
        m.record(&b);
    }
    m.tick();

    let fee_a = m.local_base_fee(&a, global_base);
    let fee_b = m.local_base_fee(&b, global_base);
    assert!(fee_a > global_base, "contract a must be surcharged");
    assert!(
        fee_b >= fee_a,
        "higher-load contract b must pay >= contract a's fee"
    );
}

// ── record ────────────────────────────────────────────────────────────────────

#[test]
fn record_creates_tracking_entry() {
    let mut m = LocalFeeMarket::new();
    m.record(&addr(1));
    assert_eq!(m.tracked_contracts(), 1);
}

#[test]
fn multiple_records_same_block_below_decay_den_round_to_zero_ema() {
    // Integer EMA: (0 × 7 + count) / 8. For count < DECAY_DEN, result is 0.
    // This is expected — a contract needs to sustain ≥ DECAY_DEN txs/block to
    // register a non-zero EMA, preventing single-transaction noise from
    // affecting the fee signal.
    let contract = addr(1);
    let mut m = LocalFeeMarket::new();
    for _ in 0..(DECAY_DEN - 1) {
        m.record(&contract);
    }
    m.tick();
    assert_eq!(m.contract_load(&contract), 0);
}

#[test]
fn record_minimum_count_for_nonzero_ema_after_one_tick() {
    // Exactly DECAY_DEN records → ema = DECAY_DEN / DECAY_DEN = 1.
    let contract = addr(1);
    let mut m = LocalFeeMarket::new();
    for _ in 0..DECAY_DEN {
        m.record(&contract);
    }
    m.tick();
    assert_eq!(m.contract_load(&contract), 1);
}

// ── tick ──────────────────────────────────────────────────────────────────────

#[test]
fn tick_applies_ema_decay_formula_correctly() {
    // Step 1: 8 records → tick → ema = (0×7 + 8)/8 = 1.
    // Step 2: 0 records → tick → ema = (1×7 + 0)/8 = 0 (integer truncation).
    let contract = addr(1);
    let mut m = LocalFeeMarket::new();
    for _ in 0..DECAY_DEN {
        m.record(&contract);
    }
    m.tick();
    assert_eq!(m.contract_load(&contract), 1, "after first tick: ema should be 1");
    m.tick();
    assert_eq!(
        m.contract_load(&contract),
        0,
        "after second tick (no records): 1×7/8 = 0 in integer arithmetic"
    );
}

#[test]
fn tick_with_constant_input_approaches_steady_state() {
    // With a constant rate of 800 txs/block, the EMA converges to 800.
    // After 40 ticks the EMA should be ≥ 790 (within ~1.3% of steady state).
    let contract = addr(1);
    let mut m = LocalFeeMarket::new();
    let rate = 800u64;
    for _ in 0..40 {
        for _ in 0..rate {
            m.record(&contract);
        }
        m.tick();
    }
    let ema = m.contract_load(&contract);
    assert!(
        (790..=800).contains(&ema),
        "EMA should converge to ~800 after 40 ticks at 800 tx/block; got {ema}"
    );
}

#[test]
fn tick_without_activity_decays_load_to_zero() {
    // After enough idle ticks, any EMA decays to zero.
    let contract = addr(1);
    let mut m = market_at_ema(contract, 200);
    for _ in 0..100 {
        m.tick();
    }
    assert_eq!(m.contract_load(&contract), 0, "EMA must decay to 0 after idle blocks");
}

#[test]
fn tick_resets_current_block_count() {
    // After tick, the in-progress count for the next block starts at 0.
    // Verify: tick twice with no new records → second tick uses count=0.
    let contract = addr(1);
    let mut m = LocalFeeMarket::new();
    for _ in 0..DECAY_DEN {
        m.record(&contract);
    }
    m.tick(); // ema = 1
    m.tick(); // ema = 1×7/8 = 0 (count was reset to 0 after first tick)
    assert_eq!(m.contract_load(&contract), 0);
}

#[test]
fn tick_tracks_multiple_contracts_independently() {
    // Two contracts at different rates produce independent EMAs.
    let a = addr(1);
    let b = addr(2);
    let mut m = LocalFeeMarket::new();
    for _ in 0..800 {
        m.record(&a);
    } // ema_a = 800/8 = 100
    for _ in 0..1_600 {
        m.record(&b);
    } // ema_b = 1600/8 = 200
    m.tick();
    assert_eq!(m.contract_load(&a), 100);
    assert_eq!(m.contract_load(&b), 200);
}

// ── prune_idle ────────────────────────────────────────────────────────────────

#[test]
fn prune_idle_removes_contracts_with_zero_ema_and_zero_count() {
    let contract = addr(1);
    let mut m = market_at_ema(contract, 1);
    // Decay EMA to zero.
    for _ in 0..100 {
        m.tick();
    }
    assert_eq!(m.contract_load(&contract), 0);
    m.prune_idle();
    assert_eq!(m.tracked_contracts(), 0, "idle contract must be pruned");
}

#[test]
fn prune_idle_keeps_contracts_with_nonzero_ema() {
    let contract = addr(1);
    let mut m = market_at_ema(contract, HIGH_DEMAND_THRESHOLD);
    m.prune_idle();
    assert_eq!(m.tracked_contracts(), 1, "active contract must not be pruned");
}

#[test]
fn prune_idle_keeps_contracts_with_pending_current_count() {
    // EMA is still 0 (no tick yet), but current_block_count > 0.
    // The contract is active and must not be pruned.
    let mut m = LocalFeeMarket::new();
    m.record(&addr(1));
    m.prune_idle();
    assert_eq!(m.tracked_contracts(), 1, "contract with pending count must not be pruned");
}

// ── tracked_contracts ─────────────────────────────────────────────────────────

#[test]
fn tracked_contracts_increments_per_distinct_contract() {
    let mut m = LocalFeeMarket::new();
    m.record(&addr(1));
    m.record(&addr(2));
    m.record(&addr(3));
    assert_eq!(m.tracked_contracts(), 3);
}

#[test]
fn tracked_contracts_does_not_double_count_repeated_records() {
    let mut m = LocalFeeMarket::new();
    let contract = addr(1);
    for _ in 0..100 {
        m.record(&contract);
    }
    assert_eq!(m.tracked_contracts(), 1, "many records to same contract = 1 entry");
}

// ── Overflow / edge cases ─────────────────────────────────────────────────────

#[test]
fn saturating_prevents_overflow_with_extreme_global_base() {
    // global_base = u64::MAX, multiplier > 1 → saturating_mul clamps to u64::MAX.
    let contract = addr(1);
    let m = market_at_ema(contract, HIGH_DEMAND_THRESHOLD + SCALE_FACTOR);
    let fee = m.local_base_fee(&contract, u64::MAX);
    assert_eq!(fee, u64::MAX, "overflow must clamp to u64::MAX, not wrap");
}

#[test]
fn ema_tick_does_not_panic_on_extreme_current_block_count() {
    // A flood of 1M records must not cause tick() to panic.
    let contract = addr(1);
    let mut m = LocalFeeMarket::new();
    for _ in 0..1_000_000u32 {
        m.record(&contract);
    }
    m.tick(); // must not panic
    assert!(m.contract_load(&contract) > 0, "EMA must reflect the high count");
}
