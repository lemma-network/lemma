//! Tests for `lemma_consensus::slashing` — common slash mechanics (B3a, spec §5.1).
//!
//! ## Coverage
//!
//! - **Constants**: DOUBLE_SIGN_SLASH_BPS=500, DOWNTIME=100, SHARE_WITHHOLDING=1000,
//!   EVIDENCE_MAX_AGE=UNBONDING_PERIOD.
//! - **Active deduction**: correct fraction, capped at zero when active < intended.
//! - **Pending-inactive filtering**: post-infraction entries slashed by same fraction;
//!   pre-infraction entries untouched; `inactive` always untouched.
//! - **Invariants**: never-negative, total_burned = from_active + from_pending.
//! - **Edge cases**: zero power, zero active, all-post-infraction, mixed entries,
//!   fraction = 0, fraction = MAX (100%), fraction > MAX → reject.
//! - **Determinism**: same input → same output.

use lemma_core::{
    address::Address,
    amount::{Amount, DROPS_PER_LEM},
    validator::{ConsensusKey, Stake, UnbondingEntry, Validator, ValidatorStatus},
};

use crate::{
    epoch::{UNBONDING_PERIOD_SECONDS},
    slashing::{
        slash, SlashError, DOUBLE_SIGN_SLASH_BPS, DOWNTIME_SLASH_BPS,
        EVIDENCE_MAX_AGE_SECONDS, MAX_FRACTION_BPS, SHARE_WITHHOLDING_SLASH_BPS,
    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn lem(n: u128) -> Amount {
    Amount::from_drop(n * DROPS_PER_LEM)
}

fn dummy_key(b: u8) -> ConsensusKey {
    ConsensusKey::from_bytes(vec![b; 32], vec![b; 32])
}

/// Build a validator with the given active stake and no pending/inactive.
fn make_active_validator(active_lem: u128) -> Validator {
    Validator {
        address: addr(1),
        consensus_pubkey: dummy_key(1),
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active: lem(active_lem),
            pending_active: Amount::zero(),
            pending_inactive: Vec::new(),
            inactive: Amount::zero(),
        },
        delegated: Amount::zero(),
        commission_bps: 0,
        jailed_until: None,
    }
}

/// Build an `UnbondingEntry` with the given start_height and balance (in LEM).
fn entry(start_height: u64, balance_lem: u128) -> UnbondingEntry {
    UnbondingEntry {
        initial_balance: lem(balance_lem),
        start_height,
        complete_time: 9_999_999,
        on_hold: false,
    }
}

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn double_sign_slash_bps_is_500() {
    assert_eq!(DOUBLE_SIGN_SLASH_BPS, 500, "double-sign = 5% (500 bps)");
}

#[test]
fn downtime_slash_bps_is_100() {
    assert_eq!(DOWNTIME_SLASH_BPS, 100, "downtime = 1% (100 bps)");
}

#[test]
fn share_withholding_slash_bps_is_1000() {
    assert_eq!(SHARE_WITHHOLDING_SLASH_BPS, 1_000, "share-withholding = 10% (1000 bps)");
}

#[test]
fn evidence_max_age_equals_unbonding_period() {
    assert_eq!(
        EVIDENCE_MAX_AGE_SECONDS, UNBONDING_PERIOD_SECONDS,
        "EVIDENCE_MAX_AGE must equal UNBONDING_PERIOD (14 days — spec §5.3)"
    );
}

// ── Active stake deduction ────────────────────────────────────────────────────

#[test]
fn slash_deducts_correct_fraction_from_active() {
    // 20M LEM active, 5% slash = 1M LEM burned.
    let mut v = make_active_validator(20_000_000);
    let power = lem(20_000_000);
    let burned = slash(&mut v, 0, power, DOUBLE_SIGN_SLASH_BPS).unwrap();

    let expected = lem(1_000_000); // 5% of 20M
    assert_eq!(burned, expected, "5% of 20M LEM = 1M LEM burned");
    assert_eq!(
        v.self_stake.active,
        lem(19_000_000),
        "active must be reduced by 1M LEM"
    );
}

#[test]
fn slash_downtime_deducts_one_percent() {
    // 10M LEM active, 1% slash = 100K LEM.
    let mut v = make_active_validator(10_000_000);
    let power = lem(10_000_000);
    let burned = slash(&mut v, 0, power, DOWNTIME_SLASH_BPS).unwrap();

    assert_eq!(burned, lem(100_000), "1% of 10M = 100K LEM burned");
    assert_eq!(v.self_stake.active, lem(9_900_000));
}

#[test]
fn slash_active_capped_at_zero_when_active_less_than_intended() {
    // Active = 1M, power = 20M (validator unstaked since infraction).
    // Slash 5% of 20M = 1M, but only 1M active → takes all of active.
    let mut v = make_active_validator(1_000_000);
    let power = lem(20_000_000);
    let burned = slash(&mut v, 0, power, DOUBLE_SIGN_SLASH_BPS).unwrap();

    assert_eq!(burned, lem(1_000_000), "capped at all available active");
    assert!(v.self_stake.active.is_zero(), "active must be fully drained");
}

#[test]
fn slash_zero_power_gives_zero_burned() {
    let mut v = make_active_validator(20_000_000);
    let burned = slash(&mut v, 0, Amount::zero(), DOUBLE_SIGN_SLASH_BPS).unwrap();

    assert!(burned.is_zero(), "zero power → zero slash");
    assert_eq!(v.self_stake.active, lem(20_000_000), "active unchanged");
}

#[test]
fn slash_zero_active_gives_zero_from_active() {
    // Active = 0; still no panic, still correct.
    let mut v = make_active_validator(0);
    let power = lem(20_000_000);
    let burned = slash(&mut v, 0, power, DOUBLE_SIGN_SLASH_BPS).unwrap();

    // from_active = 0 (active=0), from_pending = 0 (no entries).
    assert!(burned.is_zero());
    assert!(v.self_stake.active.is_zero());
}

// ── Pending-inactive filtering ────────────────────────────────────────────────

#[test]
fn slash_post_infraction_pending_inactive_slashed_by_same_fraction() {
    // Infraction at height 100. Entry started at height 200 → post-infraction → slash.
    let mut v = make_active_validator(20_000_000);
    v.self_stake.pending_inactive = vec![entry(200, 5_000_000)]; // 5M post-infraction
    let power = lem(25_000_000); // active + pending

    let burned = slash(&mut v, 100, power, DOUBLE_SIGN_SLASH_BPS).unwrap(); // 5%

    // from_active = 5% of 25M = 1.25M, from_pending = 5% of 5M = 250K
    let expected_active_slash = lem(1_250_000);
    let expected_entry_slash = lem(250_000);
    assert_eq!(burned, expected_active_slash.checked_add(expected_entry_slash).unwrap());
    assert_eq!(
        v.self_stake.pending_inactive[0].initial_balance,
        lem(4_750_000), // 5M - 5% = 4.75M
        "post-infraction entry must be reduced by the same fraction"
    );
}

#[test]
fn slash_pre_infraction_pending_inactive_untouched() {
    // Infraction at height 100. Entry started at height 50 → pre-infraction → untouched.
    let mut v = make_active_validator(20_000_000);
    v.self_stake.pending_inactive = vec![entry(50, 5_000_000)]; // pre-infraction
    let power = lem(20_000_000);

    let burned = slash(&mut v, 100, power, DOUBLE_SIGN_SLASH_BPS).unwrap();

    // Only active slashed; pre-infraction entry untouched.
    assert_eq!(burned, lem(1_000_000), "only active slashed (5% of 20M)");
    assert_eq!(
        v.self_stake.pending_inactive[0].initial_balance,
        lem(5_000_000),
        "pre-infraction entry initial_balance must be untouched"
    );
}

#[test]
fn slash_entry_at_infraction_height_boundary_is_pre_infraction() {
    // start_height == infraction_height: the ">" predicate means this is NOT slashed.
    let mut v = make_active_validator(10_000_000);
    v.self_stake.pending_inactive = vec![entry(100, 3_000_000)]; // exactly at height 100
    let power = lem(10_000_000);

    slash(&mut v, 100, power, DOUBLE_SIGN_SLASH_BPS).unwrap();

    assert_eq!(
        v.self_stake.pending_inactive[0].initial_balance,
        lem(3_000_000),
        "entry at exactly infraction_height is pre-infraction (> not >=)"
    );
}

#[test]
fn slash_inactive_stake_never_touched() {
    let mut v = make_active_validator(10_000_000);
    v.self_stake.inactive = lem(50_000_000); // mature — untouchable
    let power = lem(10_000_000);

    slash(&mut v, 0, power, DOUBLE_SIGN_SLASH_BPS).unwrap();

    assert_eq!(
        v.self_stake.inactive,
        lem(50_000_000),
        "inactive (fully matured) stake must never be slashed"
    );
}

#[test]
fn slash_mixed_pre_and_post_infraction_entries() {
    // Two entries: one pre, one post. Only post should be slashed.
    let mut v = make_active_validator(20_000_000);
    v.self_stake.pending_inactive = vec![
        entry(50, 4_000_000),  // pre-infraction (height 50 ≤ 100)
        entry(150, 6_000_000), // post-infraction (height 150 > 100)
    ];
    let power = lem(20_000_000);

    slash(&mut v, 100, power, DOUBLE_SIGN_SLASH_BPS).unwrap(); // 5%

    assert_eq!(
        v.self_stake.pending_inactive[0].initial_balance,
        lem(4_000_000),
        "pre-infraction entry untouched"
    );
    assert_eq!(
        v.self_stake.pending_inactive[1].initial_balance,
        lem(5_700_000), // 6M - 5% = 5.7M
        "post-infraction entry reduced by 5%"
    );
}

#[test]
fn slash_all_post_infraction_entries_are_slashed() {
    // Three post-infraction entries; all should be slashed.
    let mut v = make_active_validator(0);
    v.self_stake.pending_inactive = vec![
        entry(101, 3_000_000),
        entry(102, 2_000_000),
        entry(103, 5_000_000),
    ];
    let power = lem(10_000_000);

    let burned = slash(&mut v, 100, power, DOUBLE_SIGN_SLASH_BPS).unwrap(); // 5%

    // 5% of each: 150K + 100K + 250K = 500K burned from pending
    // from_active = 0 (active=0 < intended 500K), so from_active = 0
    let expected = lem(150_000) // 5% of 3M
        .checked_add(lem(100_000)).unwrap()  // 5% of 2M
        .checked_add(lem(250_000)).unwrap(); // 5% of 5M
    assert_eq!(burned, expected, "all post-infraction entries slashed by 5%");
}

// ── Invariants ────────────────────────────────────────────────────────────────

#[test]
fn slash_total_burned_equals_from_active_plus_from_pending() {
    let mut v = make_active_validator(20_000_000);
    v.self_stake.pending_inactive = vec![
        entry(50, 3_000_000),  // pre-infraction: skip
        entry(150, 5_000_000), // post-infraction: slash
    ];
    let initial_active = v.self_stake.active;
    let initial_pending = v.self_stake.pending_inactive[1].initial_balance;
    let power = lem(25_000_000);

    let burned = slash(&mut v, 100, power, DOUBLE_SIGN_SLASH_BPS).unwrap();

    let deducted_from_active = initial_active
        .checked_sub(v.self_stake.active)
        .unwrap();
    let deducted_from_pending = initial_pending
        .checked_sub(v.self_stake.pending_inactive[1].initial_balance)
        .unwrap();
    let expected_burned = deducted_from_active.checked_add(deducted_from_pending).unwrap();

    assert_eq!(
        burned, expected_burned,
        "total_burned must equal sum of all actual deductions"
    );
}

#[test]
fn slash_active_never_goes_negative() {
    // Extremely large power >> active. Must not panic or produce negative.
    let mut v = make_active_validator(100);
    let enormous_power = Amount::from_drop(u128::MAX / 10_001); // near u128::MAX / max_bps
    let burned = slash(&mut v, 0, enormous_power, MAX_FRACTION_BPS).unwrap();

    assert!(v.self_stake.active.is_zero(), "active capped at zero — never negative");
    assert_eq!(burned, lem(100), "burned = only what was available (100 LEM)");
}

// ── Fraction edge cases ───────────────────────────────────────────────────────

#[test]
fn slash_fraction_zero_deducts_nothing() {
    let mut v = make_active_validator(10_000_000);
    let initial = v.self_stake.active;
    let burned = slash(&mut v, 0, lem(10_000_000), 0).unwrap();

    assert!(burned.is_zero(), "0 bps slash → zero burned");
    assert_eq!(v.self_stake.active, initial, "active unchanged");
}

#[test]
fn slash_fraction_max_100_percent_zeroes_active_and_entries() {
    // 100% slash of a validator with active + one post-infraction entry.
    let mut v = make_active_validator(10_000_000);
    v.self_stake.pending_inactive = vec![entry(200, 5_000_000)];
    let power = lem(10_000_000); // we slash 100% of power from active

    let burned = slash(&mut v, 100, power, MAX_FRACTION_BPS).unwrap(); // 100%

    // intended = 10M. from_active = 10M (exact). entry: 100% of 5M = 5M.
    assert!(v.self_stake.active.is_zero(), "active zeroed at 100% slash");
    assert!(
        v.self_stake.pending_inactive[0].initial_balance.is_zero(),
        "post-infraction entry zeroed at 100% slash"
    );
    assert_eq!(
        burned,
        lem(15_000_000), // 10M from active + 5M from pending
        "100% slash burns active + post-infraction pending"
    );
}

#[test]
fn slash_rejects_fraction_above_max() {
    let mut v = make_active_validator(10_000_000);
    let result = slash(&mut v, 0, lem(10_000_000), MAX_FRACTION_BPS + 1);

    assert!(
        matches!(result, Err(SlashError::InvalidFraction { fraction_bps: 10_001 })),
        "fraction > MAX_FRACTION_BPS must return InvalidFraction"
    );
    // No state mutation must have occurred.
    assert_eq!(
        v.self_stake.active,
        lem(10_000_000),
        "active must be unchanged after rejection"
    );
}

// ── Error paths: state unchanged ─────────────────────────────────────────────

#[test]
fn slash_compute_overflow_returns_err_and_leaves_state_unchanged() {
    // Trigger ComputeOverflow: power × MAX_FRACTION_BPS must overflow u128.
    // power > u128::MAX / 10_000 ≈ 3.4×10³⁴ — use u128::MAX / 100 to be safe.
    let mut v = make_active_validator(5_000_000);
    let initial_active = v.self_stake.active;
    let enormous_power = Amount::from_drop(u128::MAX / 100); // × 10_000 overflows

    let result = slash(&mut v, 0, enormous_power, MAX_FRACTION_BPS);

    assert!(
        matches!(result, Err(SlashError::ComputeOverflow { .. })),
        "must return ComputeOverflow, not panic"
    );
    // Atomicity guarantee: state must be byte-for-byte unchanged.
    assert_eq!(
        v.self_stake.active, initial_active,
        "active must be unchanged after ComputeOverflow (compute-then-commit)"
    );
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn slash_deterministic_same_input_same_output() {
    let make = || {
        let mut v = make_active_validator(20_000_000);
        v.self_stake.pending_inactive = vec![
            entry(50, 2_000_000),
            entry(150, 3_000_000),
        ];
        slash(&mut v, 100, lem(23_000_000), DOUBLE_SIGN_SLASH_BPS).unwrap();
        (
            v.self_stake.active.as_drop(),
            v.self_stake.pending_inactive[0].initial_balance.as_drop(),
            v.self_stake.pending_inactive[1].initial_balance.as_drop(),
        )
    };

    assert_eq!(make(), make(), "slash must be deterministic");
}
