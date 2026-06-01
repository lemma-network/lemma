//! Tests for `lemma_consensus::slashing::liveness` — downtime §5.5 (B3c, spec §10).
//!
//! ## Coverage
//!
//! - **Window mechanics**: rotation, missed_count update, O(1) per-block.
//! - **Breach detection**: fires when missed > max; does NOT fire when missed == max.
//! - **No double-fire**: second consecutive call at same height does not fire again.
//! - **Reset**: clean state after breach; no re-slash on rebond.
//! - **apply_downtime**: 1% slash + jail + window reset; no change on slash error.
//! - **Constants**: SIGNED_BLOCKS_WINDOW, MAX_MISSED_BLOCKS, DOWNTIME_JAIL_DURATION.
//! - **Determinism**: same input sequence → same output.

use lemma_core::{
    address::Address,
    amount::{Amount, DROPS_PER_LEM},
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus},
};

use crate::slashing::{
    liveness::{
        apply_downtime, DowntimeBreach, SignedBlocksWindow, DOWNTIME_JAIL_DURATION_SECONDS,
        MAX_MISSED_BLOCKS, SIGNED_BLOCKS_WINDOW,
    },
    DOWNTIME_SLASH_BPS,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn lem(n: u128) -> Amount {
    Amount::from_drop(n * DROPS_PER_LEM)
}

fn make_validator(active_lem: u128) -> Validator {
    Validator {
        address: addr(1),
        consensus_pubkey: ConsensusKey::from_bytes(vec![1; 32], vec![1; 32]),
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

/// Build a small window (size=10, max_missed=5) for fast tests.
fn small_window() -> SignedBlocksWindow {
    SignedBlocksWindow::new(10, 5)
}

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn signed_blocks_window_is_345600() {
    assert_eq!(SIGNED_BLOCKS_WINDOW, 345_600, "window = 48h at 0.5s/block");
}

#[test]
fn max_missed_blocks_is_half_the_window() {
    assert_eq!(MAX_MISSED_BLOCKS, SIGNED_BLOCKS_WINDOW / 2);
}

#[test]
fn downtime_jail_duration_is_one_epoch() {
    assert_eq!(DOWNTIME_JAIL_DURATION_SECONDS, 86_400, "jail = 24h (one epoch)");
}

#[test]
fn downtime_slash_bps_is_100() {
    assert_eq!(DOWNTIME_SLASH_BPS, 100, "downtime = 1%");
}

// ── Window construction ───────────────────────────────────────────────────────

#[test]
fn new_window_starts_clean() {
    let w = small_window();
    assert_eq!(w.missed_count(), 0, "fresh window has 0 missed blocks");
    assert_eq!(w.window_size(), 10);
}

// ── record_block: basic mechanics ────────────────────────────────────────────

#[test]
fn recording_signed_blocks_produces_no_breach() {
    let mut w = small_window();
    for h in 0..10 {
        let breach = w.record_block(h, true);
        assert!(breach.is_none(), "all signed → no breach");
    }
    assert_eq!(w.missed_count(), 0);
}

#[test]
fn recording_missed_block_increments_missed_count() {
    let mut w = small_window();
    w.record_block(0, false); // miss
    assert_eq!(w.missed_count(), 1);
}

#[test]
fn recording_signed_then_missed_in_same_slot_decrements_count() {
    // Window size = 10. Block 0 is signed; block 10 wraps to same slot.
    let mut w = small_window();
    w.record_block(0, false); // slot 0 = missed; missed_count = 1
    w.record_block(10, true); // slot 0 overwritten with signed; missed_count = 0
    assert_eq!(w.missed_count(), 0);
}

#[test]
fn recording_missed_then_signed_in_same_slot_increments_count() {
    let mut w = small_window();
    w.record_block(0, true);  // slot 0 = signed
    w.record_block(10, false); // slot 0 overwritten with missed; missed_count = 1
    assert_eq!(w.missed_count(), 1);
}

// ── Breach detection ──────────────────────────────────────────────────────────

#[test]
fn no_breach_when_missed_equals_max() {
    // miss exactly max_missed (5); threshold is >, not >=.
    let mut w = small_window();
    for h in 0..5 {
        let b = w.record_block(h, false);
        assert!(b.is_none(), "at exactly max_missed, no breach yet");
    }
    assert_eq!(w.missed_count(), 5);
}

#[test]
fn breach_fires_when_missed_exceeds_max() {
    let mut w = small_window(); // max_missed = 5
    for h in 0..5 {
        w.record_block(h, false);
    }
    // 6th miss pushes missed_count to 6 > 5 → breach
    let breach = w.record_block(5, false);
    assert!(breach.is_some(), "6 missed > 5 max → breach");
    assert_eq!(breach.unwrap().breach_height, 5);
}

#[test]
fn breach_carries_correct_height() {
    let mut w = small_window();
    for h in 0..6 {
        w.record_block(h, false);
    }
    // The 6th miss (height 5) triggers the breach.
    // Re-build to get the breach return value cleanly.
    let mut w2 = small_window();
    for h in 0..5 {
        w2.record_block(h, false);
    }
    let breach = w2.record_block(5, false).unwrap();
    assert_eq!(breach.breach_height, 5, "breach height = block that pushed over threshold");
}

// ── No double-fire ────────────────────────────────────────────────────────────

#[test]
fn breach_does_not_fire_twice_at_same_height() {
    let mut w = small_window();
    // Fill beyond max.
    for h in 0..6 {
        w.record_block(h, false);
    }
    // Simulated: same height called again (shouldn't happen in practice but must be safe).
    let second = w.record_block(5, false);
    assert!(
        second.is_none(),
        "breach must not fire twice for the same height"
    );
}

#[test]
fn breach_can_fire_again_at_different_height_after_still_breaching() {
    // After a breach at height 5, a new missed block at height 6 can fire again
    // because height 6 ≠ last_breach_height (5).
    let mut w = small_window();
    for h in 0..6 {
        w.record_block(h, false);
    }
    // Height 5 already breached. Height 6 also missed (still > max_missed=5).
    // The slot for height 6 is 6%10=6, which was previously signed → missed_count goes to 7.
    let breach_at_6 = w.record_block(6, false);
    assert!(
        breach_at_6.is_some(),
        "a new height can breach again if still over threshold"
    );
    assert_eq!(breach_at_6.unwrap().breach_height, 6);
}

// ── Reset ─────────────────────────────────────────────────────────────────────

#[test]
fn reset_clears_missed_count() {
    let mut w = small_window();
    for h in 0..6 {
        w.record_block(h, false);
    }
    w.reset();
    assert_eq!(w.missed_count(), 0, "reset must zero missed_count");
}

#[test]
fn reset_prevents_re_breach_immediately_after() {
    let mut w = small_window();
    for h in 0..6 {
        w.record_block(h, false);
    }
    w.reset();
    // One more missed after reset should not breach (count = 1, max = 5).
    let breach = w.record_block(100, false);
    assert!(breach.is_none(), "after reset, single miss must not breach");
}

#[test]
fn reset_clears_last_breach_height() {
    // After reset, a re-accumulated breach fires — last_breach_height cleared.
    let mut w = small_window();
    for h in 0..6 {
        w.record_block(h, false);
    }
    w.reset();
    // Re-accumulate 6 misses — should breach again (last_breach_height cleared).
    for h in 100..105 {
        w.record_block(h, false);
    }
    let new_breach = w.record_block(105, false);
    assert!(
        new_breach.is_some(),
        "re-accumulated breach after reset must fire"
    );
}

// ── apply_downtime ────────────────────────────────────────────────────────────

#[test]
fn apply_downtime_slashes_one_percent() {
    let mut v = make_validator(20_000_000);
    let mut w = small_window();
    let breach = DowntimeBreach { breach_height: 100 };
    let power = lem(20_000_000);
    let block_time = 500_000;

    let burned = apply_downtime(&mut v, breach, power, block_time, &mut w).unwrap();

    assert_eq!(burned, lem(200_000), "1% of 20M = 200K LEM burned");
    assert_eq!(v.self_stake.active, lem(19_800_000), "active reduced by 200K");
}

#[test]
fn apply_downtime_jails_validator_for_one_epoch() {
    let mut v = make_validator(10_000_000);
    let mut w = small_window();
    let breach = DowntimeBreach { breach_height: 100 };
    let block_time = 1_000_000;

    apply_downtime(&mut v, breach, lem(10_000_000), block_time, &mut w).unwrap();

    let expected_jail = block_time + DOWNTIME_JAIL_DURATION_SECONDS;
    assert_eq!(
        v.jailed_until,
        Some(expected_jail),
        "validator jailed for DOWNTIME_JAIL_DURATION_SECONDS after breach"
    );
}

#[test]
fn apply_downtime_resets_window() {
    let mut v = make_validator(10_000_000);
    let mut w = small_window();
    // Fill window past threshold.
    for h in 0..6 {
        w.record_block(h, false);
    }
    assert!(w.missed_count() > 5, "pre-condition: window is in breach");

    let breach = DowntimeBreach { breach_height: 5 };
    apply_downtime(&mut v, breach, lem(10_000_000), 0, &mut w).unwrap();

    assert_eq!(w.missed_count(), 0, "window must be reset after apply_downtime");
}

#[test]
fn apply_downtime_does_not_tombstone() {
    let mut v = make_validator(10_000_000);
    let mut w = small_window();
    let breach = DowntimeBreach { breach_height: 1 };
    apply_downtime(&mut v, breach, lem(10_000_000), 0, &mut w).unwrap();
    assert!(!v.tombstoned, "downtime → finite jail only, never tombstone");
}

#[test]
fn apply_downtime_leaves_state_unchanged_on_slash_error() {
    // Trigger SlashError::ComputeOverflow by passing enormous power.
    let mut v = make_validator(5_000_000);
    let initial_active = v.self_stake.active;
    let initial_jailed = v.jailed_until;
    let mut w = small_window();
    // Fill window so missed_count is believable.
    for h in 0..6 {
        w.record_block(h, false);
    }
    let initial_missed = w.missed_count();
    let breach = DowntimeBreach { breach_height: 5 };

    // Trigger ComputeOverflow: power × DOWNTIME_SLASH_BPS (100) must overflow u128.
    // Requires power > u128::MAX / 100 → use u128::MAX / 100 + 1.
    let enormous_power = Amount::from_drop(u128::MAX / 100 + 1);
    let result = apply_downtime(&mut v, breach, enormous_power, 999, &mut w);

    assert!(result.is_err(), "must return Err on slash failure");
    assert_eq!(v.self_stake.active, initial_active, "active unchanged on error");
    assert_eq!(v.jailed_until, initial_jailed, "jail unchanged on error (atomicity)");
    assert_eq!(w.missed_count(), initial_missed, "window unchanged on error (atomicity)");
}

// ── Determinism ───────────────────────────────────────────────────────────────

#[test]
fn window_record_deterministic_same_sequence_same_state() {
    let run = || {
        let mut w = SignedBlocksWindow::new(10, 5);
        let sequence = [true, false, true, false, false, true, false, false, false, false];
        for (h, &signed) in sequence.iter().enumerate() {
            w.record_block(h as u64, signed);
        }
        (w.missed_count(), w.window_size())
    };
    assert_eq!(run(), run(), "window must be deterministic");
}

#[test]
fn apply_downtime_deterministic() {
    let run = || {
        let mut v = make_validator(20_000_000);
        let mut w = small_window();
        let breach = DowntimeBreach { breach_height: 5 };
        let burned = apply_downtime(&mut v, breach, lem(20_000_000), 100_000, &mut w).unwrap();
        (burned.as_drop(), v.self_stake.active.as_drop(), v.jailed_until)
    };
    assert_eq!(run(), run(), "apply_downtime must be deterministic");
}
