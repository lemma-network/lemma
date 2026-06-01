//! Per-account rate limiting for `lemma-mempool`.
//!
//! Implements a **token-bucket** algorithm: each account has a bucket of tokens
//! that refills at a steady rate. Each transaction submission consumes one
//! token. A depleted bucket rejects submissions until enough tokens accumulate.
//!
//! # Why token-bucket?
//!
//! Token buckets allow **burst tolerance** (up to `capacity` tokens) while
//! enforcing a **sustained rate** (`refill_per_sec` tx/s). A fixed-window
//! counter would reject an account that sends 5 tx in the first half-second and
//! then waits — token buckets handle that gracefully.
//!
//! # Time injection — why this module differs from `peer.rs`
//!
//! `peer.rs` uses `Instant::now()` internally for `last_seen` timestamps —
//! those are **passive metadata** (display/logging), so testability is not a
//! concern. Rate limiting is different: `try_acquire` makes an **active logical
//! decision** based on elapsed time (how many tokens have refilled?), and that
//! decision must be tested at precise boundaries (partial refill, exact cap,
//! zero elapsed).
//!
//! `try_acquire` therefore takes an **explicit `now: Instant`** parameter:
//! - Production callers pass `Instant::now()` — zero change in behaviour.
//! - Tests pass a fake clock — deterministic, instant, no `sleep()` needed.
//!
//! This follows `code-quality.md` "explicit dependencies (dependency
//! injection)" and `test-coverage.md` "fast and reliable: no flaky tests,
//! deterministic".
//!
//! # Memory bound
//!
//! Buckets for accounts that stop submitting would accumulate indefinitely.
//! [`RateLimiter::prune_full`] removes buckets that are back to full capacity —
//! call it periodically (e.g. once per block) to bound memory usage.

use std::{
    collections::HashMap,
    time::Instant,
};

use lemma_core::Address;

use crate::error::MempoolError;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Default maximum burst size: number of tokens a fresh bucket holds.
///
/// An account that has been idle accumulates up to this many tokens, allowing
/// a short burst of `DEFAULT_BUCKET_CAPACITY` transactions before rate-limiting
/// kicks in.
pub const DEFAULT_BUCKET_CAPACITY: f64 = 20.0;

/// Default sustained submission rate: tokens refilled per second.
///
/// After exhausting the burst, an account can submit at this rate indefinitely.
/// At 5 tx/s, a fully-drained bucket recovers completely in 4 seconds.
pub const DEFAULT_REFILL_PER_SEC: f64 = 5.0;

// ── TokenBucket ───────────────────────────────────────────────────────────────

/// A single account's token bucket.
///
/// # f64 for token count
///
/// Token count is `f64` (not integer) to support **smooth fractional refill**:
/// a 0.5s elapsed at 5 tx/s should yield exactly 2.5 new tokens. With integer
/// tokens, partial seconds would be lost, making the sustained rate jagged.
///
/// `f64` is safe here because:
/// - Rate limiting is **local-only** (spec §1.1) — never enters consensus,
///   never hashed, never committed to a block.
/// - `f64` arithmetic is forbidden in consensus/state paths (AGENTS.md §7.1)
///   because it is platform-dependent. For a local sorting/admission decision,
///   platform variance of ±ε is acceptable.
///
/// This is a documented exception analogous to `qos.rs` using saturating
/// arithmetic instead of `checked_*` for a sort key.
#[derive(Debug, Clone)]
struct TokenBucket {
    /// Current token count. Range: `[0.0, capacity]`.
    tokens: f64,
    /// Wall-clock time of the last refill calculation.
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a full bucket (starts at `capacity`).
    fn new(capacity: f64, now: Instant) -> Self {
        Self { tokens: capacity, last_refill: now }
    }

    /// Refill tokens based on elapsed time, then attempt to consume one.
    ///
    /// Returns `Ok(())` if a token was consumed, or the milliseconds until
    /// the next token becomes available via `retry_after_ms`.
    ///
    /// `now` must be ≥ `self.last_refill` in normal operation. If `now` is
    /// earlier (clock skew, injected test value going backwards),
    /// `saturating_duration_since` yields `Duration::ZERO` — no tokens are
    /// added, no panic.
    fn try_consume(&mut self, capacity: f64, refill_per_sec: f64, now: Instant) -> Result<(), u64> {
        // Refill — saturating so backwards clock doesn't panic.
        let elapsed_secs = now
            .saturating_duration_since(self.last_refill)
            .as_secs_f64();
        self.tokens = (self.tokens + elapsed_secs * refill_per_sec).min(capacity);
        // Update last_refill on EVERY call, including rejected ones. This is
        // correct: fractional refills compose additively, so N rapid calls with
        // small elapsed == one call with large elapsed. Do NOT skip this on Err.
        self.last_refill = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Compute how long until one token accumulates.
            let needed = 1.0 - self.tokens;
            let wait_secs = needed / refill_per_sec;
            // Convert to ms, rounding up, clamping to u64::MAX.
            // 1.8446744e19 = 2^64 (nearest f64 above u64::MAX) used as the
            // saturation guard to avoid clippy::cast_precision_loss on `u64::MAX as f64`.
            #[allow(clippy::cast_possible_truncation)]
            let retry_ms = (wait_secs * 1_000.0).ceil().min(1.844_674_407_370_955_2e19_f64) as u64;
            Err(retry_ms)
        }
    }

    /// Returns `true` if this bucket is at full capacity (no longer limited).
    fn is_full(&self, capacity: f64) -> bool {
        self.tokens >= capacity
    }
}

// ── RateLimiter ───────────────────────────────────────────────────────────────

/// Per-account token-bucket rate limiter.
///
/// Each account gets its own [`TokenBucket`]. New accounts start with a full
/// bucket (maximum burst). Buckets are created on first submission and pruned
/// when full (via [`prune_full`]).
///
/// # Thread safety
///
/// `RateLimiter` is not `Sync`. The pool layer wraps it in
/// `Arc<RwLock<RateLimiter>>` for concurrent access (04-BUILD_GUIDE §10).
///
/// [`prune_full`]: RateLimiter::prune_full
pub struct RateLimiter {
    // HashMap (not BTreeMap): iteration order is never observed — `retain`
    // is order-independent and lookups are by key. Local-only admission
    // heuristic, no determinism concern (spec §1.1, AGENTS.md §7.1).
    buckets: HashMap<Address, TokenBucket>,
    /// Maximum tokens per bucket (burst size).
    capacity: f64,
    /// Tokens added per second of idle time.
    refill_per_sec: f64,
}

impl RateLimiter {
    /// Create a `RateLimiter` with explicit `capacity` and `refill_per_sec`.
    ///
    /// # Panics
    ///
    /// Panics in debug if `capacity <= 0.0` or `refill_per_sec <= 0.0` —
    /// zero or negative values would make rate limiting permanently block
    /// all submissions. In release both are silently clamped to `1.0` so
    /// the limiter degrades to "1 token, 1/s refill" rather than becoming
    /// pathological (e.g. a `MIN_POSITIVE` refill would yield a
    /// `retry_after_ms` near `u64::MAX`).
    #[must_use]
    pub fn new(capacity: f64, refill_per_sec: f64) -> Self {
        debug_assert!(capacity > 0.0, "capacity must be > 0");
        debug_assert!(refill_per_sec > 0.0, "refill_per_sec must be > 0");
        Self {
            buckets: HashMap::new(),
            capacity: capacity.max(1.0),
            refill_per_sec: refill_per_sec.max(1.0),
        }
    }

    /// Create a `RateLimiter` with [`DEFAULT_BUCKET_CAPACITY`] and
    /// [`DEFAULT_REFILL_PER_SEC`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DEFAULT_BUCKET_CAPACITY, DEFAULT_REFILL_PER_SEC)
    }

    /// Attempt to consume one rate-limit token for `account` at time `now`.
    ///
    /// Returns `Ok(())` if the submission is permitted, or
    /// `Err(MempoolError::RateLimited { retry_after_ms })` if the bucket is
    /// exhausted.
    ///
    /// New accounts start with a full bucket — their first `capacity`
    /// submissions are always permitted.
    ///
    /// # Production usage
    ///
    /// Production callers (e.g. `pool.rs`) pass `Instant::now()` as `now`.
    /// Test callers pass a fake clock for deterministic, sleep-free tests.
    pub fn try_acquire(
        &mut self,
        account: &Address,
        now: Instant,
    ) -> Result<(), MempoolError> {
        let capacity = self.capacity;
        let refill_per_sec = self.refill_per_sec;

        let bucket = self
            .buckets
            .entry(*account)
            .or_insert_with(|| TokenBucket::new(capacity, now));

        bucket.try_consume(capacity, refill_per_sec, now).map_err(|retry_after_ms| {
            MempoolError::RateLimited { sender: *account, retry_after_ms }
        })
    }

    /// Remove buckets that have returned to full capacity.
    ///
    /// Call periodically (e.g. once per block) to prevent unbounded memory
    /// growth from accounts that submitted transactions and then went idle.
    ///
    /// Buckets for accounts that are still rate-limited are preserved.
    pub fn prune_full(&mut self, now: Instant) {
        let capacity = self.capacity;
        let refill_per_sec = self.refill_per_sec;

        self.buckets.retain(|_, bucket| {
            // Refill the bucket to get the current state, then check fullness.
            let elapsed = now.saturating_duration_since(bucket.last_refill).as_secs_f64();
            bucket.tokens = (bucket.tokens + elapsed * refill_per_sec).min(capacity);
            bucket.last_refill = now;
            !bucket.is_full(capacity)
        });
    }

    /// Number of accounts currently tracked (for metrics and tests).
    #[must_use]
    pub fn tracked_accounts(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests;
