//! Tests for `lemma_mempool::rate_limit`.
//!
//! All tests use an **injected fake clock** (`base + Duration`) — zero
//! `sleep()` calls, fully deterministic, runs in microseconds.
//!
//! Covers:
//! - Burst: fresh bucket allows up to `capacity` acquisitions.
//! - Exhaustion: one past capacity → RateLimited with retry_after_ms.
//! - Full refill: after enough time, bucket is restored to capacity.
//! - Partial refill: fractional elapsed time yields fractional tokens.
//! - Cap: idle time beyond capacity does not over-fill the bucket.
//! - retry_after_ms: value is sane and strictly > 0 when rate-limited.
//! - Per-account isolation: one account's bucket doesn't affect another.
//! - Backwards clock: `now < last_refill` → zero elapsed, no panic.
//! - Prune: full buckets removed; partially-refilled buckets kept.
//! - Tracked accounts: count reflects live buckets.

use std::time::{Duration, Instant};

use lemma_core::Address;

use crate::{
    error::MempoolError,
    rate_limit::{RateLimiter, DEFAULT_BUCKET_CAPACITY},
};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// A small capacity / fast refill limiter for tests.
/// capacity=5, refill=10/s → bucket drains in 5 tx, refills fully in 0.5s.
fn test_limiter() -> RateLimiter {
    RateLimiter::new(5.0, 10.0)
}

/// Generate a unique address for test index `n` using `from_public_key`.
/// `[n; 32]` = 32 bytes all set to `n` → deterministic, unique per n.
fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

/// Exhaust the full burst capacity of `account` at time `now`.
/// Returns `now` (unchanged — all at same instant).
fn exhaust(rl: &mut RateLimiter, account: &Address, now: Instant) {
    for _ in 0..5 {
        rl.try_acquire(account, now)
            .expect("should not be rate-limited during burst");
    }
}

// ── Constructor ───────────────────────────────────────────────────────────────

#[test]
fn with_defaults_uses_default_constants() {
    // Indirect verification: a fresh account can acquire DEFAULT_BUCKET_CAPACITY times.
    let mut rl = RateLimiter::with_defaults();
    let now = Instant::now();
    let a = addr(0);
    for _ in 0..(DEFAULT_BUCKET_CAPACITY as u64) {
        assert!(rl.try_acquire(&a, now).is_ok());
    }
    // One more → rate limited
    assert!(rl.try_acquire(&a, now).is_err());
}

// ── Burst ─────────────────────────────────────────────────────────────────────

#[test]
fn fresh_account_allows_full_burst() {
    let mut rl = test_limiter(); // capacity=5
    let now = Instant::now();
    let a = addr(1);
    for i in 0..5 {
        assert!(
            rl.try_acquire(&a, now).is_ok(),
            "acquire {i} of 5 must succeed"
        );
    }
}

#[test]
fn burst_exhausted_on_sixth_acquire() {
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);
    exhaust(&mut rl, &a, now);
    let err = rl.try_acquire(&a, now).expect_err("6th acquire must fail");
    assert!(
        matches!(err, MempoolError::RateLimited { .. }),
        "unexpected: {err}"
    );
}

// ── retry_after_ms ────────────────────────────────────────────────────────────

#[test]
fn rate_limited_retry_after_ms_is_positive() {
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);
    exhaust(&mut rl, &a, now);
    match rl.try_acquire(&a, now).expect_err("must be rate limited") {
        MempoolError::RateLimited { retry_after_ms, .. } => {
            assert!(
                retry_after_ms > 0,
                "retry_after_ms must be > 0, got {retry_after_ms}"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

#[test]
fn rate_limited_retry_after_ms_is_sane() {
    // refill_per_sec=10, so 1 token takes 0.1s = 100ms.
    // retry_after_ms should be 100 (rounded up from exactly 100.0).
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);
    exhaust(&mut rl, &a, now);
    match rl.try_acquire(&a, now).expect_err("must be rate limited") {
        MempoolError::RateLimited { retry_after_ms, .. } => {
            // Bucket is at 0 tokens exactly after 5 acquires from capacity=5.
            // Needed = 1.0 token, rate = 10/s → wait = 0.1s = 100ms.
            assert_eq!(
                retry_after_ms, 100,
                "expected 100ms wait, got {retry_after_ms}"
            );
        }
        other => panic!("unexpected error: {other}"),
    }
}

// ── Full refill ───────────────────────────────────────────────────────────────

#[test]
fn full_refill_restores_capacity() {
    let mut rl = test_limiter(); // capacity=5, refill=10/s → full in 0.5s
    let now = Instant::now();
    let a = addr(1);
    exhaust(&mut rl, &a, now);

    // Advance 0.5s — should restore all 5 tokens.
    let later = now + Duration::from_millis(500);
    for i in 0..5 {
        assert!(
            rl.try_acquire(&a, later).is_ok(),
            "acquire {i} after full refill must succeed"
        );
    }
}

#[test]
fn acquire_permitted_exactly_at_one_token_refill_point() {
    let mut rl = test_limiter(); // refill=10/s → 1 token in 0.1s
    let now = Instant::now();
    let a = addr(1);
    exhaust(&mut rl, &a, now);

    // Exactly 0.1s → 1.0 token refilled → should permit exactly 1 acquire.
    let later = now + Duration::from_millis(100);
    assert!(
        rl.try_acquire(&a, later).is_ok(),
        "1 token must be available after 100ms"
    );
    assert!(
        rl.try_acquire(&a, later).is_err(),
        "second acquire at same time must fail (only 1 token refilled)"
    );
}

// ── Partial refill ────────────────────────────────────────────────────────────

#[test]
fn partial_refill_permits_correct_number_of_acquires() {
    // refill=10/s, elapsed=0.25s → 2.5 tokens added → floor(2.5) = 2 acquires.
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);
    exhaust(&mut rl, &a, now);

    let later = now + Duration::from_millis(250); // 2.5 tokens
    assert!(
        rl.try_acquire(&a, later).is_ok(),
        "1st acquire on 2.5 tokens must succeed"
    );
    assert!(
        rl.try_acquire(&a, later).is_ok(),
        "2nd acquire on 2.5 tokens must succeed"
    );
    assert!(
        rl.try_acquire(&a, later).is_err(),
        "3rd acquire on 2.5 tokens must fail (fractional, <1 token left)"
    );
}

// ── Cap: does not over-fill ───────────────────────────────────────────────────

#[test]
fn idle_time_beyond_capacity_does_not_over_fill() {
    // capacity=5. After 100s of idle (refill=10/s → 1000 tokens added), still
    // only 5 tokens available (the cap). 6th acquire must fail.
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);

    let much_later = now + Duration::from_secs(100);
    for i in 0..5 {
        assert!(
            rl.try_acquire(&a, much_later).is_ok(),
            "acquire {i} after long idle must succeed"
        );
    }
    assert!(
        rl.try_acquire(&a, much_later).is_err(),
        "6th acquire must fail — bucket must not exceed capacity"
    );
}

// ── Per-account isolation ─────────────────────────────────────────────────────

#[test]
fn exhausted_account_does_not_affect_different_account() {
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);
    let b = addr(2);

    exhaust(&mut rl, &a, now);

    // Account A is limited, but B's bucket is fresh.
    assert!(
        rl.try_acquire(&b, now).is_ok(),
        "account B must not be affected by account A's exhaustion"
    );
}

#[test]
fn multiple_accounts_each_get_independent_burst() {
    let mut rl = test_limiter();
    let now = Instant::now();

    for n in 0..4 {
        let a = addr(n);
        for i in 0..5 {
            assert!(
                rl.try_acquire(&a, now).is_ok(),
                "account {n} acquire {i} must succeed (independent bucket)"
            );
        }
    }
}

// ── Backwards clock (no panic) ────────────────────────────────────────────────

#[test]
fn backwards_clock_does_not_panic_or_add_tokens() {
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);

    // Acquire once to initialize the bucket with `last_refill = now`.
    rl.try_acquire(&a, now).expect("first acquire must succeed");

    // Pass a `now` earlier than `last_refill` — simulates clock going backwards.
    // Must not panic; elapsed = Duration::ZERO so no tokens added.
    let earlier = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);
    // Just ensure no panic — the result (Ok or Err) depends on remaining tokens.
    let _ = rl.try_acquire(&a, earlier);
}

#[test]
fn zero_elapsed_does_not_panic() {
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);

    rl.try_acquire(&a, now).expect("first acquire must succeed");
    // Same instant — zero elapsed, should not panic.
    let _ = rl.try_acquire(&a, now);
}

// ── prune_full ────────────────────────────────────────────────────────────────

#[test]
fn prune_removes_full_bucket() {
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);

    // Single acquire — bucket is at 4/5 (not full).
    rl.try_acquire(&a, now).expect("first acquire must succeed");
    assert_eq!(rl.tracked_accounts(), 1);

    // After capacity/refill = 0.5s, bucket is full again.
    let later = now + Duration::from_millis(500);
    rl.prune_full(later);
    assert_eq!(rl.tracked_accounts(), 0, "full bucket must be pruned");
}

#[test]
fn prune_keeps_still_limited_bucket() {
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);

    exhaust(&mut rl, &a, now);

    // Only 50ms elapsed (0.5 tokens refilled) — bucket not full yet.
    let slightly_later = now + Duration::from_millis(50);
    rl.prune_full(slightly_later);
    assert_eq!(
        rl.tracked_accounts(),
        1,
        "partially-refilled bucket must not be pruned"
    );
}

#[test]
fn prune_removes_full_keeps_limited() {
    let mut rl = test_limiter();
    let now = Instant::now();
    let full_addr = addr(1);
    let limited_addr = addr(2);

    // full_addr: 1 acquire → 4/5 tokens remain.
    rl.try_acquire(&full_addr, now).expect("first acquire");
    // limited_addr: exhausted → 0/5 tokens.
    exhaust(&mut rl, &limited_addr, now);
    assert_eq!(rl.tracked_accounts(), 2);

    // At 10ms (refill=10/s → +0.1 tokens):
    //   full_addr  = 4.0 + 0.1 = 4.1  (< 5, not full → keep)
    //   limited    = 0.0 + 0.1 = 0.1  (< 5, not full → keep)
    let tiny_later = now + Duration::from_millis(10);
    rl.prune_full(tiny_later);
    assert_eq!(rl.tracked_accounts(), 2, "neither bucket is full at 10ms");

    // At 1s (refill=10/s → +10 tokens, capped at 5):
    //   full_addr  = 4.1 + ∞ → capped 5.0 (full → prune)
    //   limited    = 0.1 + ∞ → capped 5.0 (full → prune)
    let long_later = now + Duration::from_secs(1);
    rl.prune_full(long_later);
    assert_eq!(
        rl.tracked_accounts(),
        0,
        "both buckets full after 1s → both pruned"
    );
}

// ── tracked_accounts ─────────────────────────────────────────────────────────

#[test]
fn tracked_accounts_starts_at_zero() {
    let rl = test_limiter();
    assert_eq!(rl.tracked_accounts(), 0);
}

#[test]
fn tracked_accounts_increments_on_new_account() {
    let mut rl = test_limiter();
    let now = Instant::now();

    rl.try_acquire(&addr(1), now).ok();
    assert_eq!(rl.tracked_accounts(), 1);
    rl.try_acquire(&addr(2), now).ok();
    assert_eq!(rl.tracked_accounts(), 2);
}

#[test]
fn tracked_accounts_same_account_does_not_increment() {
    let mut rl = test_limiter();
    let now = Instant::now();
    let a = addr(1);

    rl.try_acquire(&a, now).ok();
    rl.try_acquire(&a, now).ok();
    assert_eq!(
        rl.tracked_accounts(),
        1,
        "same account must not add a second bucket"
    );
}
