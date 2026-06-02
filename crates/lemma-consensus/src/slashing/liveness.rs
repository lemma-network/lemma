//! # Downtime detection — sliding-window bit-array (spec §5.5)
//!
//! Implements `docs/13-VALIDATOR_EPOCH_SPEC §5.5`: a Cosmos-style
//! **sliding-window bit-array** that tracks which of the last
//! [`SIGNED_BLOCKS_WINDOW`] blocks a validator signed. When missed blocks
//! exceed [`MAX_MISSED_BLOCKS`], a [`DowntimeBreach`] is produced.
//!
//! ## Design decisions (B3-3)
//!
//! **Bit-array over cumulative-missed-time**: O(1) per block, deterministic,
//! battle-tested in Cosmos. The window is sized so that `SIGNED_BLOCKS_WINDOW
//! × BLOCK_TIME_SECONDS ≈ 48 h`, matching spec "48h offline ⇒ 1%".
//!
//! ## Parameters (consensus-ground)
//!
//! At Lemma's target ~0.5 s/block:
//! - `SIGNED_BLOCKS_WINDOW = 345_600` → `345_600 × 0.5 s = 172_800 s = 48 h`.
//! - `MAX_MISSED_BLOCKS = 172_800` (50% threshold — validator must sign at
//!   least 50% of blocks; missing >50% over 48 h ≡ ">48h offline" §5.5).
//!
//! These are **injectable** in tests via [`SignedBlocksWindow::new`]; the
//! constants represent the protocol defaults.
//!
//! ## `DOWNTIME_JAIL_DURATION_SECONDS`
//!
//! After slashing, the validator is jailed until
//! `block_time + DOWNTIME_JAIL_DURATION_SECONDS` (spec §5.5: "finite jail").
//! Set to 24 h (one epoch) — enough time to fix the issue without permanent harm.
//!
//! ## Determinism
//!
//! All operations are pure functions of their inputs. No `SystemTime`. No floats.
//! The bit-array is a `Vec<bool>` indexed by `height % window_size` — any two
//! nodes with identical window contents and the same `record_block` call sequence
//! produce identical breach results.

use lemma_core::{amount::Amount, validator::Validator};

use super::{slash, SlashError, DOWNTIME_SLASH_BPS};
use crate::slashing::jail::jail;

// ── Protocol constants ────────────────────────────────────────────────────────

/// Number of blocks in the signed-blocks sliding window (protocol default).
///
/// At ~0.5 s/block: `345_600 × 0.5 s = 172_800 s = 48 h` — matches spec §5.5
/// "> 48h offline ⇒ 1% slash". This is the window that rotates; a block at
/// height `h` occupies slot `h % SIGNED_BLOCKS_WINDOW`.
pub const SIGNED_BLOCKS_WINDOW: u64 = 345_600;

/// Maximum blocks a validator may miss within the sliding window before jail (protocol default).
///
/// `MAX_MISSED_BLOCKS = SIGNED_BLOCKS_WINDOW / 2` (50% miss threshold).
/// A validator must sign at least 50% of the last `SIGNED_BLOCKS_WINDOW` blocks.
/// Missing more than half is treated as effectively offline for > 48 h.
pub const MAX_MISSED_BLOCKS: u64 = SIGNED_BLOCKS_WINDOW / 2;

/// Duration of the downtime jail sentence in consensus seconds (spec §5.5).
///
/// 24 hours (one epoch) — enough time to restart a crashed validator without
/// a permanent tombstone. Set from `block_time + DOWNTIME_JAIL_DURATION_SECONDS`.
pub const DOWNTIME_JAIL_DURATION_SECONDS: u64 = 24 * 60 * 60; // 86_400 s

/// Duration of the share-withholding jail sentence in consensus seconds (spec §5.4).
///
/// Share-withholding is a liveness fault ("finite jail, not tombstone" — 13 §5.4).
/// The spec does not specify a separate duration; one epoch (24 h) matches the
/// same one-epoch-scoped liveness semantics as downtime (§5.5). Defined as a
/// separate named constant so a future spec revision can diverge independently
/// without modifying the orchestrator. Currently equal to `DOWNTIME_JAIL_DURATION_SECONDS`.
pub const SHARE_WITHHOLDING_JAIL_DURATION_SECONDS: u64 = DOWNTIME_JAIL_DURATION_SECONDS;

// ── SignedBlocksWindow ────────────────────────────────────────────────────────

/// Sliding-window bit-array for per-validator downtime tracking (spec §5.5).
///
/// Tracks which of the last `window_size` blocks the validator signed. The
/// window rotates: block at height `h` occupies slot `h % window_size`.
/// When the slot is overwritten, the old value is removed from `missed_count`.
///
/// **O(1) per block** — no iteration over history, no allocation after init.
///
/// ## Usage
///
/// ```ignore
/// let mut window = SignedBlocksWindow::new(SIGNED_BLOCKS_WINDOW, MAX_MISSED_BLOCKS);
/// // For every block the validator was expected to sign:
/// if let Some(breach) = window.record_block(height, signed) {
///     // Validator breached the downtime threshold — apply slash.
/// }
/// ```
#[derive(Debug, Clone)]
pub struct SignedBlocksWindow {
    /// Circular bit-array: `true` = signed, `false` = missed.
    bits: Vec<bool>,
    /// Current missed-block count in the window.
    missed_count: u64,
    /// Maximum allowed missed blocks before a breach.
    max_missed: u64,
    /// Block height at which the last breach was detected (to prevent double-fire).
    ///
    /// Reset to `None` by [`reset`]. A breach fires at most once per window
    /// cycle.
    last_breach_height: Option<u64>,
}

impl SignedBlocksWindow {
    /// Create a new window with all blocks marked as signed (clean start).
    ///
    /// ## Parameters
    ///
    /// - `window_size` — number of blocks to track (must be > 0; use
    ///   [`SIGNED_BLOCKS_WINDOW`] for the protocol default).
    /// - `max_missed` — maximum missed blocks before breach (use
    ///   [`MAX_MISSED_BLOCKS`] for the protocol default).
    ///
    /// # Panics
    ///
    /// Panics if `window_size == 0` (division by zero in slot calculation).
    /// This is a programmer error — callers must pass a positive window size.
    #[must_use]
    pub fn new(window_size: u64, max_missed: u64) -> Self {
        assert!(
            window_size > 0,
            "SignedBlocksWindow: window_size must be > 0"
        );
        Self {
            bits: vec![true; window_size as usize], // initialise: all blocks signed
            missed_count: 0,
            max_missed,
            last_breach_height: None,
        }
    }

    /// Record whether the validator signed the block at `height`.
    ///
    /// Rotates the window by overwriting the slot `height % window_size`.
    /// If the replaced entry was missed and the new one is signed (or vice
    /// versa), `missed_count` is updated atomically.
    ///
    /// Returns `Some(DowntimeBreach)` if the missed count exceeds `max_missed`
    /// **and** this height has not already been breach-reported (prevents
    /// multiple reports for the same sustained outage). Returns `None` otherwise.
    ///
    /// ## Determinism
    ///
    /// Pure: same sequence of calls → same result. No walltime.
    pub fn record_block(&mut self, height: u64, signed: bool) -> Option<DowntimeBreach> {
        let slot = (height % self.bits.len() as u64) as usize;
        let previously_signed = self.bits[slot];

        // Update missed count for the slot being overwritten.
        match (previously_signed, signed) {
            (true, false) => self.missed_count += 1, // was signed, now missed
            (false, true) => self.missed_count = self.missed_count.saturating_sub(1), // was missed, now signed
            _ => {}                                                                   // no change
        }
        self.bits[slot] = signed;

        // Fire breach if threshold exceeded AND not already fired for this height.
        if self.missed_count > self.max_missed && self.last_breach_height != Some(height) {
            self.last_breach_height = Some(height);
            return Some(DowntimeBreach {
                breach_height: height,
            });
        }
        None
    }

    /// Reset the window and breach-tracking after a downtime slash (spec §5.5).
    ///
    /// Spec: "reset the window so the validator isn't immediately re-slashed on
    /// rebonding." After applying the slash, reset restores a clean state.
    pub fn reset(&mut self) {
        self.bits.fill(true); // mark all blocks as signed (clean window)
        self.missed_count = 0;
        self.last_breach_height = None;
    }

    /// Current number of missed blocks in the window (for testing/monitoring).
    #[must_use]
    pub fn missed_count(&self) -> u64 {
        self.missed_count
    }

    /// Window size (for testing).
    #[must_use]
    pub fn window_size(&self) -> u64 {
        self.bits.len() as u64
    }
}

// ── DowntimeBreach ────────────────────────────────────────────────────────────

/// A breach of the downtime threshold — triggers slash + jail (spec §5.5).
///
/// Produced by [`SignedBlocksWindow::record_block`] when
/// `missed_count > max_missed`. The caller passes this to [`apply_downtime`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DowntimeBreach {
    /// The block height at which the threshold was breached.
    ///
    /// Used as the slash `infraction_height` (spec §5.5: "window-breach height
    /// at which `MissedBlocksCounter > maxMissed`").
    pub breach_height: u64,
}

// ── apply_downtime ────────────────────────────────────────────────────────────

/// Apply a downtime breach: slash 1%, jail, reset window (spec §5.5).
///
/// Must be called after receiving a [`DowntimeBreach`] from
/// [`SignedBlocksWindow::record_block`]. Does NOT re-verify the breach —
/// assumes the caller checked the breach is valid.
///
/// ## Effects
///
/// 1. Slash **1%** of `validator_power` from `validator.self_stake` (active
///    first, then post-breach `pending_inactive` entries).
/// 2. **Jail** the validator until `block_time + DOWNTIME_JAIL_DURATION_SECONDS`
///    (spec §5.5: "finite jail, no tombstone").
/// 3. **Reset** the sliding window (so rebonding starts clean).
///
/// Returns the total amount burned (caller reduces total supply).
///
/// ## Atomicity
///
/// `slash` is compute-then-commit; if it fails, `jail` and `reset` are NOT
/// called and validator state is unchanged.
///
/// ## Power injection (B3-1)
///
/// `validator_power` comes from the node binary — the current voting power
/// of the validator at the breach height.
///
/// # Errors
///
/// [`SlashError`] if slash computation fails (practically unreachable for
/// realistic supply values).
pub fn apply_downtime(
    validator: &mut Validator,
    breach: DowntimeBreach,
    validator_power: Amount,
    block_time: u64,
    window: &mut SignedBlocksWindow,
) -> Result<Amount, SlashError> {
    // Slash 1% — compute-then-commit atomic (mod.rs).
    let burned = slash(
        validator,
        breach.breach_height,
        validator_power,
        DOWNTIME_SLASH_BPS,
    )?;
    // Finite jail — only reached if slash succeeded.
    jail(validator, block_time + DOWNTIME_JAIL_DURATION_SECONDS);
    // Reset window — validator gets a clean slate after the penalty.
    window.reset();
    Ok(burned)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
