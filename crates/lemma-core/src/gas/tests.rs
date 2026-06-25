use super::*;

// ── Gas arithmetic ────────────────────────────────────────────────────────────

#[test]
fn gas_checked_add_returns_sum() {
    let a = Gas::new(100);
    let b = Gas::new(200);
    assert_eq!(a.checked_add(b), Some(Gas::new(300)));
}

#[test]
fn gas_checked_add_returns_none_on_overflow() {
    let a = Gas::new(u64::MAX);
    let b = Gas::new(1);
    assert_eq!(a.checked_add(b), None);
}

#[test]
fn gas_checked_sub_returns_difference() {
    let a = Gas::new(300);
    let b = Gas::new(100);
    assert_eq!(a.checked_sub(b), Some(Gas::new(200)));
}

#[test]
fn gas_checked_sub_returns_none_on_underflow() {
    let a = Gas::new(50);
    let b = Gas::new(100);
    assert_eq!(a.checked_sub(b), None);
}

#[test]
fn gas_saturating_sub_clamps_to_zero() {
    let a = Gas::new(10);
    let b = Gas::new(100);
    assert_eq!(a.saturating_sub(b), Gas::ZERO);
}

#[test]
fn gas_forwardable_applies_63_64_rule() {
    // 64 gas → forward 63 (64 − 64/64 = 64 − 1 = 63)
    assert_eq!(Gas::new(64).forwardable(), Gas::new(63));
    // 128 gas → forward 126 (128 − 128/64 = 128 − 2 = 126)
    assert_eq!(Gas::new(128).forwardable(), Gas::new(126));
    // 0 gas → forward 0
    assert_eq!(Gas::ZERO.forwardable(), Gas::ZERO);
}

#[test]
fn gas_display_shows_inner_value() {
    assert_eq!(format!("{}", Gas::new(42)), "42");
}

// ── GasSchedule ───────────────────────────────────────────────────────────────

#[test]
fn gas_schedule_devnet_tx_base_is_21000() {
    let schedule = GasSchedule::devnet();
    assert_eq!(schedule.tx_base, Gas::new(21_000));
}

#[test]
fn gas_schedule_devnet_storage_read_cold_is_2100() {
    let schedule = GasSchedule::devnet();
    assert_eq!(schedule.storage_read_cold, Gas::new(2_100));
}

#[test]
fn gas_schedule_devnet_deploy_base_is_32000() {
    let schedule = GasSchedule::devnet();
    assert_eq!(schedule.deploy_base, Gas::new(32_000));
}

#[test]
fn gas_schedule_devnet_verify_mldsa65_is_10x_ed25519() {
    let schedule = GasSchedule::devnet();
    assert_eq!(
        schedule.verify_mldsa65.as_u64(),
        schedule.verify_ed25519.as_u64() * 10
    );
}
