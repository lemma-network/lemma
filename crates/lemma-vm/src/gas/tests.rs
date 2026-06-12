//! Tests for `gas` — Gas type, GasSchedule, GasMeter/FuelMeter, gas_used.
//!
//! | Test | Covers |
//! |------|--------|
//! | `gas_zero_constant_is_zero` | Gas::ZERO == Gas(0) |
//! | `gas_forwardable_of_64_is_63` | 63/64 rule: 64−1=63 |
//! | `gas_forwardable_is_63_64_of_remaining` | 63/64 rule: general cases |
//! | `gas_forwardable_of_zero_is_zero` | edge: forwardable(0)=0 |
//! | `gas_forwardable_of_one_is_one` | edge: 1−0=1 (integer div) |
//! | `gas_checked_add_succeeds_in_range` | normal addition |
//! | `gas_checked_add_overflows_returns_none` | u64 overflow → None |
//! | `gas_checked_sub_succeeds` | normal subtraction |
//! | `gas_checked_sub_underflows_returns_none` | underflow → None |
//! | `gas_saturating_sub_clamps_to_zero` | saturating sub edge |
//! | `devnet_schedule_has_no_zero_costs` | DoS guard: no free ops |
//! | `devnet_schedule_write_create_more_expensive_than_update` | ordering |
//! | `devnet_schedule_storage_read_cold_more_expensive_than_warm` | ordering |
//! | `devnet_schedule_mldsa_more_expensive_than_ed25519` | post-quantum cost |
//! | `charge_reduces_remaining_by_cost` | happy path |
//! | `charge_with_exact_budget_succeeds` | boundary: exactly budget |
//! | `charge_returns_out_of_gas_when_exhausted` | OOG case |
//! | `charge_does_not_mutate_on_out_of_gas` | CRITICAL settlement safety |
//! | `charge_per_byte_correct_for_known_input` | base + per_byte × len |
//! | `charge_per_byte_zero_len_charges_only_base` | len=0 edge case |
//! | `charge_per_byte_out_of_gas_on_large_len` | overflow → OOG |
//! | `forwardable_matches_gas_type_forwardable` | trait default == Gas::forwardable |
//! | `refund_accumulates_correctly` | multiple refunds sum |
//! | `capped_refund_cannot_exceed_half_remaining` | EIP-3529 cap |
//! | `capped_refund_with_small_accumulator_not_capped` | below cap |
//! | `gas_used_returns_difference` | initial - remaining |
//! | `gas_used_returns_none_when_remaining_exceeds_initial` | caller bug guard |

use super::*;
use crate::error::VmError;

// ── Gas type ──────────────────────────────────────────────────────────────────

#[test]
fn gas_zero_constant_is_zero() {
    assert_eq!(Gas::ZERO, Gas(0));
    assert_eq!(Gas::ZERO.as_u64(), 0);
}

#[test]
fn gas_forwardable_of_64_is_63() {
    // 64 − 64/64 = 64 − 1 = 63
    assert_eq!(Gas(64).forwardable(), Gas(63));
}

#[test]
fn gas_forwardable_is_63_64_of_remaining() {
    // 128 − 128/64 = 128 − 2 = 126
    assert_eq!(Gas(128).forwardable(), Gas(126));
    // 640_000 − 640_000/64 = 640_000 − 10_000 = 630_000
    assert_eq!(Gas(640_000).forwardable(), Gas(630_000));
    // 1 − 1/64 = 1 − 0 = 1 (integer division)
    assert_eq!(Gas(1).forwardable(), Gas(1));
}

#[test]
fn gas_forwardable_of_zero_is_zero() {
    assert_eq!(Gas(0).forwardable(), Gas(0));
}

#[test]
fn gas_forwardable_of_one_is_one() {
    // 1/64 = 0 in integer division → 1 − 0 = 1
    assert_eq!(Gas(1).forwardable(), Gas(1));
}

#[test]
fn gas_checked_add_succeeds_in_range() {
    assert_eq!(Gas(100).checked_add(Gas(200)), Some(Gas(300)));
    assert_eq!(Gas(0).checked_add(Gas(0)), Some(Gas(0)));
}

#[test]
fn gas_checked_add_overflows_returns_none() {
    assert_eq!(Gas(u64::MAX).checked_add(Gas(1)), None);
}

#[test]
fn gas_checked_sub_succeeds() {
    assert_eq!(Gas(500).checked_sub(Gas(300)), Some(Gas(200)));
    assert_eq!(Gas(100).checked_sub(Gas(100)), Some(Gas(0)));
}

#[test]
fn gas_checked_sub_underflows_returns_none() {
    assert_eq!(Gas(50).checked_sub(Gas(100)), None);
    assert_eq!(Gas(0).checked_sub(Gas(1)), None);
}

#[test]
fn gas_saturating_sub_clamps_to_zero() {
    assert_eq!(Gas(50).saturating_sub(Gas(100)), Gas(0));
    assert_eq!(Gas(100).saturating_sub(Gas(50)), Gas(50));
    assert_eq!(Gas(0).saturating_sub(Gas(1)), Gas(0));
}

// ── GasSchedule ──────────────────────────────────────────────────────────────

#[test]
fn devnet_schedule_has_no_zero_costs() {
    // Zero cost = free host function = DoS vector (spec §3.1 principle 5).
    // Exhaustive destructure — adding a field to GasSchedule MUST update this
    // test (compile error), preventing silent zero-cost gaps (I-1 CR finding).
    let GasSchedule {
        tx_base,
        tx_calldata_per_byte,
        storage_read_cold,
        storage_read_warm,
        storage_write_create,
        storage_write_update,
        storage_delete,
        storage_delete_refund,
        call_base,
        call_value_transfer,
        hash_blake3_base,
        hash_blake3_per_byte,
        hash_keccak256_base,
        hash_keccak256_per_byte,
        verify_ed25519,
        verify_mldsa65,
        emit_event_base,
        emit_event_per_byte,
        deploy_base,
        deploy_per_byte,
        memory_grow_per_page,
        context_query,
    } = GasSchedule::devnet();

    for (name, cost) in [
        ("tx_base", tx_base),
        ("tx_calldata_per_byte", tx_calldata_per_byte),
        ("storage_read_cold", storage_read_cold),
        ("storage_read_warm", storage_read_warm),
        ("storage_write_create", storage_write_create),
        ("storage_write_update", storage_write_update),
        ("storage_delete", storage_delete),
        ("storage_delete_refund", storage_delete_refund),
        ("call_base", call_base),
        ("call_value_transfer", call_value_transfer),
        ("hash_blake3_base", hash_blake3_base),
        ("hash_blake3_per_byte", hash_blake3_per_byte),
        ("hash_keccak256_base", hash_keccak256_base),
        ("hash_keccak256_per_byte", hash_keccak256_per_byte),
        ("verify_ed25519", verify_ed25519),
        ("verify_mldsa65", verify_mldsa65),
        ("emit_event_base", emit_event_base),
        ("emit_event_per_byte", emit_event_per_byte),
        ("deploy_base", deploy_base),
        ("deploy_per_byte", deploy_per_byte),
        ("memory_grow_per_page", memory_grow_per_page),
        ("context_query", context_query),
    ] {
        assert!(
            cost > Gas::ZERO,
            "{name} must not be zero — free ops are a DoS vector"
        );
    }
}

#[test]
fn devnet_schedule_storage_read_cold_more_expensive_than_warm() {
    // Cold = disk lookup; warm = in-memory cache (EIP-2929 principle).
    let s = GasSchedule::devnet();
    assert!(
        s.storage_read_cold > s.storage_read_warm,
        "cold read must cost more than warm read"
    );
}

#[test]
fn devnet_schedule_delete_refund_less_than_delete_cost() {
    // Economic invariant: refund must be strictly less than the delete cost,
    // else deletion is profitable (gas-token abuse — spec §3.1 principle 6,
    // EIP-3529). The cap at capped_refund() is the second line of defence;
    // this test is the first (schedule-level guard).
    let s = GasSchedule::devnet();
    assert!(
        s.storage_delete_refund < s.storage_delete,
        "delete refund ({}) must be < delete cost ({}) — else deletion is profitable",
        s.storage_delete_refund,
        s.storage_delete,
    );
}

#[test]
fn devnet_schedule_mldsa_more_expensive_than_ed25519() {
    // ML-DSA-65 (post-quantum) is ~10× heavier than Ed25519.
    let s = GasSchedule::devnet();
    assert!(
        s.verify_mldsa65 > s.verify_ed25519,
        "ML-DSA-65 verification must cost more than Ed25519"
    );
}

// ── FuelMeter / GasMeter ─────────────────────────────────────────────────────

#[test]
fn charge_reduces_remaining_by_cost() {
    let mut meter = FuelMeter::new(Gas(1_000));
    meter.charge(Gas(300)).unwrap();
    assert_eq!(meter.remaining(), Gas(700));
}

#[test]
fn charge_with_exact_budget_succeeds() {
    let mut meter = FuelMeter::new(Gas(100));
    assert!(meter.charge(Gas(100)).is_ok());
    assert_eq!(meter.remaining(), Gas(0));
}

#[test]
fn charge_returns_out_of_gas_when_exhausted() {
    let mut meter = FuelMeter::new(Gas(10));
    let result = meter.charge(Gas(100));
    assert!(
        matches!(result, Err(VmError::OutOfGas)),
        "expected OutOfGas, got {result:?}"
    );
}

#[test]
fn charge_does_not_mutate_on_out_of_gas() {
    // CRITICAL SETTLEMENT SAFETY: if charge returns Err, remaining is unchanged.
    // A partial mutation here would leave validator state divergent.
    let mut meter = FuelMeter::new(Gas(10));
    let before = meter.remaining();
    let result = meter.charge(Gas(100)); // way over budget
    assert!(matches!(result, Err(VmError::OutOfGas)));
    assert_eq!(
        meter.remaining(),
        before,
        "remaining MUST be unchanged on OutOfGas — compute-then-commit violated"
    );
}

#[test]
fn charge_per_byte_correct_for_known_input() {
    // base=100, per_byte=10, len=5 → total=150
    let mut meter = FuelMeter::new(Gas(1_000));
    meter.charge_per_byte(Gas(100), Gas(10), 5).unwrap();
    assert_eq!(meter.remaining(), Gas(850));
}

#[test]
fn charge_per_byte_zero_len_charges_only_base() {
    let mut meter = FuelMeter::new(Gas(1_000));
    meter.charge_per_byte(Gas(200), Gas(50), 0).unwrap();
    assert_eq!(meter.remaining(), Gas(800));
}

#[test]
fn charge_per_byte_out_of_gas_on_large_len() {
    // per_byte=u64::MAX, len=2 → byte_cost overflows u64 → OutOfGas
    let mut meter = FuelMeter::new(Gas(u64::MAX));
    let result = meter.charge_per_byte(Gas(0), Gas(u64::MAX), 2);
    assert!(
        matches!(result, Err(VmError::OutOfGas)),
        "overflow in per_byte × len must map to OutOfGas, got {result:?}"
    );
}

#[test]
fn forwardable_matches_gas_type_forwardable() {
    // The trait default must delegate to Gas::forwardable, not diverge.
    let meter = FuelMeter::new(Gas(640_000));
    assert_eq!(meter.forwardable(), Gas(640_000).forwardable());
    assert_eq!(meter.forwardable(), Gas(630_000));
}

#[test]
fn refund_accumulates_correctly() {
    let mut meter = FuelMeter::new(Gas(10_000));
    meter.refund(Gas(100));
    meter.refund(Gas(200));
    meter.refund(Gas(50));
    assert_eq!(meter.accumulated_refund(), Gas(350));
}

#[test]
fn capped_refund_cannot_exceed_half_remaining() {
    let mut meter = FuelMeter::new(Gas(1_000));
    // Spend 600, leaving 400 remaining.
    meter.charge(Gas(600)).unwrap();
    assert_eq!(meter.remaining(), Gas(400));
    // Accumulate a large refund — cap = 400/2 = 200.
    meter.refund(Gas(1_000));
    assert_eq!(
        meter.capped_refund(),
        Gas(200),
        "capped refund must not exceed remaining/2"
    );
}

#[test]
fn capped_refund_with_small_accumulator_not_capped() {
    let mut meter = FuelMeter::new(Gas(10_000));
    // 9_800 remaining, cap = 4_900. Refund = 100 < cap → not capped.
    meter.charge(Gas(200)).unwrap();
    meter.refund(Gas(100));
    assert_eq!(meter.capped_refund(), Gas(100));
}

// ── gas_used ─────────────────────────────────────────────────────────────────

#[test]
fn gas_used_returns_difference() {
    assert_eq!(gas_used(Gas(1_000), Gas(600)), Some(Gas(400)));
    assert_eq!(gas_used(Gas(100), Gas(100)), Some(Gas(0)));
}

#[test]
fn gas_used_returns_none_when_remaining_exceeds_initial() {
    // Indicates a caller bug — meter was somehow replenished.
    assert_eq!(gas_used(Gas(100), Gas(200)), None);
}
