//! # Jail and tombstone state transitions (spec §5.2, §5.5)
//!
//! These are **write-only** state transitions — they SET `jailed_until` and
//! `tombstoned` on a [`Validator`]. Clearing (unjailing) happens at the epoch
//! boundary in `epoch::transition::update_validator_status`, which checks
//! `jailed_until ≤ block_time` and clears the field.
//!
//! ## Separation of concerns
//!
//! `tombstone` and `jail` do NOT call `slash`. The caller is expected to
//! call `slash` first (to burn the stake), then call the appropriate state
//! transition. This keeps arithmetic and state transitions as separate,
//! independently-testable functions (AGENTS.md §3.1).

use lemma_core::validator::Validator;

// ── tombstone ─────────────────────────────────────────────────────────────────

/// Permanently ban a validator from re-bonding (spec §5.2 — double-sign).
///
/// Sets `validator.tombstoned = true`. A tombstoned validator:
/// - Cannot re-bond regardless of status or stake.
/// - Retains its last `ValidatorStatus` for audit purposes.
/// - Is excluded from `ValidatorSet(N+1)` by `build_next_validator_set`
///   (which checks `Validator::is_active`, which returns `false` when tombstoned).
///
/// **Idempotent** — calling on an already-tombstoned validator is a no-op.
///
/// # Does NOT slash
///
/// The caller must call [`super::slash`] before (or after) this function.
/// Separating slash arithmetic from tombstone state keeps both focused.
pub fn tombstone(validator: &mut Validator) {
    validator.tombstoned = true;
}

// ── jail ──────────────────────────────────────────────────────────────────────

/// Jail a validator until a consensus timestamp (spec §5.5 — downtime/share-withholding).
///
/// Sets `validator.jailed_until = Some(until_time)` where `until_time` is a
/// consensus `block.time` (seconds) — **never set from `SystemTime`**
/// (AGENTS.md §7.1). The jailed validator:
/// - Is excluded from `ValidatorSet(N+1)` while `jailed_until > current_block_time`.
/// - Is unjailed automatically at the next epoch boundary when
///   `update_validator_status` sees `block_time >= jailed_until`.
///
/// **Idempotent** — re-jailing extends the sentence to whichever is longer
/// (the new `until_time` replaces the old if longer, keeps old if already longer).
/// This prevents a second infraction from inadvertently reducing an existing sentence.
///
/// **Not tombstone** — jail is a finite liveness penalty, not a permanent ban.
/// Use [`tombstone`] for double-sign (equivocation).
///
/// # Does NOT slash
///
/// The caller must call [`super::slash`] before (or after) this function.
pub fn jail(validator: &mut Validator, until_time: u64) {
    // Take the maximum of the current sentence and the new one.
    // This prevents a second (lighter) offense from clearing an existing (heavier) sentence.
    validator.jailed_until = Some(match validator.jailed_until {
        Some(existing) => existing.max(until_time),
        None => until_time,
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
