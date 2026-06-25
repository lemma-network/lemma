//! # Gas Metering (08-EXECUTION_SPEC §2.2, §3)
//!
//! Gas tracks the cost of contract execution so validators are compensated
//! and infinite loops are bounded.
//!
//! ## Primitives
//!
//! | Primitive | Role |
//! |-----------|------|
//! | [`Gas`]         | Newtype over `u64` — re-exported from `lemma-core` |
//! | [`GasSchedule`] | Named cost constants — re-exported from `lemma-core` |
//! | [`GasMeter`]    | Trait: charge, refund, remaining, 63/64 forwarding |
//! | [`FuelMeter`]   | Standalone impl — wired to wasmtime `Store` fuel in B3 |
//! | [`gas_used`]    | `initial - remaining` helper |
//!
//! ## Key rules (08-EXECUTION_SPEC §3.1)
//!
//! 1. **Charge BEFORE execute** — meter up front; OOG traps before side effects.
//! 2. **No free host functions** — every host call has a cost (else DoS).
//! 3. **Compute-then-commit** — if `charge` returns `Err`, `remaining` is unchanged.
//! 4. **63/64 forwarding** — on cross-contract calls, forward at most
//!    `remaining − remaining/64` (EIP-150; guarantees caller retains cleanup gas).
//! 5. **Checked arithmetic** — all gas math uses `checked_*` (AGENTS §7.4).
//! 6. **Capped refunds** — storage-deletion refunds are capped at `remaining/2`
//!    (EIP-3529 model; prevents gas-token abuse).
//!
//! ## Migration note (P4·Step 4)
//!
//! `Gas` and `GasSchedule` were moved to `lemma-core` so that `lemma-rpc`
//! (fee estimation) and `lemma-mempool` (base-fee checks) share ONE schedule
//! without depending on `lemma-vm` (AGENTS §2.4). They are re-exported here
//! for backward compatibility — all existing callers in `lemma-vm` and
//! `lemma-node` continue to work without changes.

// Re-export Gas and GasSchedule from lemma-core (AGENTS §2.4 — shared utilities
// live in lemma-core; re-exported here for backward compatibility).
pub use lemma_core::gas::{Gas, GasSchedule};

use crate::error::VmError;

// ── GasMeter trait ────────────────────────────────────────────────────────────

/// Interface for tracking and charging gas during contract execution.
///
/// ## Contract (08-EXECUTION-SPEC §3.1)
///
/// - Charge BEFORE the side-effect — OOG traps before any mutation.
/// - Never panic on OOG — return `Err(VmError::OutOfGas)`.
/// - If `charge` returns `Err`, `remaining` MUST be unchanged
///   (compute-then-commit pattern).
/// - All arithmetic is checked (AGENTS §7.4).
pub trait GasMeter {
    /// Charge a flat gas cost. Returns `Err(OutOfGas)` if the budget is
    /// exhausted. If `Err`, `remaining` is unchanged (atomicity guarantee).
    fn charge(&mut self, cost: Gas) -> Result<(), VmError>;

    /// Charge `base + per_byte × len`. Returns `Err(OutOfGas)` on exhaustion
    /// or arithmetic overflow of `per_byte × len` (overflow = can't afford it).
    fn charge_per_byte(&mut self, base: Gas, per_byte: Gas, len: usize) -> Result<(), VmError> {
        // Checked multiplication: per_byte × len. Overflow → OOG.
        let byte_cost = per_byte
            .0
            .checked_mul(len as u64)
            .ok_or(VmError::OutOfGas)?;
        // Checked addition: base + byte_cost. Overflow → OOG.
        let total = base.checked_add(Gas(byte_cost)).ok_or(VmError::OutOfGas)?;
        self.charge(total)
    }

    /// Remaining gas budget.
    fn remaining(&self) -> Gas;

    /// Gas forwardable to a sub-call: `remaining − remaining/64` (EIP-150).
    /// Default impl delegates to [`Gas::forwardable`] — override only if needed.
    fn forwardable(&self) -> Gas {
        self.remaining().forwardable()
    }

    /// Credit a refund (e.g. storage deletion). Accumulated refunds are capped
    /// at commit via [`FuelMeter::capped_refund`]. Never panics.
    fn refund(&mut self, amount: Gas);

    /// Total refunds accumulated so far (before the cap is applied at commit).
    fn accumulated_refund(&self) -> Gas;
}

// ── FuelMeter ─────────────────────────────────────────────────────────────────

/// Standalone gas meter backed by an in-memory counter.
///
/// In B3, this will be complemented by a `CallerMeter` that syncs charges
/// to wasmtime fuel via `Caller::set_fuel` so raw-compute fuel and
/// explicit host-function charges stay in step.
///
/// For B2 (and B3 host-function unit tests), `FuelMeter` is sufficient.
pub struct FuelMeter {
    remaining: Gas,
    refund_accumulator: Gas,
}

impl FuelMeter {
    /// Create a `FuelMeter` with the given gas budget.
    pub fn new(budget: Gas) -> Self {
        Self {
            remaining: budget,
            refund_accumulator: Gas::ZERO,
        }
    }

    /// Set the remaining gas to `gas`. Used by the linker's sync-wrap pattern to
    /// sync wasmtime Store fuel → FuelMeter → trait method → FuelMeter → Store fuel.
    /// This does NOT increase the budget — it replaces the current remaining value.
    ///
    /// # Safety invariant
    ///
    /// The caller MUST ensure `gas <= initial budget` (enforced by Store fuel cap).
    pub fn set_remaining(&mut self, gas: Gas) {
        self.remaining = gas;
    }

    /// Capped refund applicable at commit time.
    ///
    /// Cap = `remaining / 2` (EIP-3529 model — prevents gas-token abuse by
    /// bounding the effective discount on any single transaction).
    ///
    /// Cannot overflow: `remaining/2 ≤ u64::MAX/2`; `.min()` returns the
    /// smaller of two `u64` values.
    pub fn capped_refund(&self) -> Gas {
        let cap = Gas(self.remaining.0 / 2);
        Gas(self.refund_accumulator.0.min(cap.0))
    }
}

impl GasMeter for FuelMeter {
    fn charge(&mut self, cost: Gas) -> Result<(), VmError> {
        // Compute-then-commit: compute the new remaining FIRST.
        // Only update self.remaining if Ok — leaves it unchanged on Err.
        let new_remaining = self.remaining.checked_sub(cost).ok_or(VmError::OutOfGas)?;
        self.remaining = new_remaining;
        Ok(())
    }

    fn remaining(&self) -> Gas {
        self.remaining
    }

    fn refund(&mut self, amount: Gas) {
        // Saturating add — silently clamps at u64::MAX; never panics.
        // Overflow is theoretical: refund_accumulator > u64::MAX requires
        // issuing more refunds than there are gas units — impossible in practice.
        self.refund_accumulator = Gas(self.refund_accumulator.0.saturating_add(amount.0));
    }

    fn accumulated_refund(&self) -> Gas {
        self.refund_accumulator
    }
}

// ── gas_used ──────────────────────────────────────────────────────────────────

/// Compute gas consumed by a transaction: `initial_budget − remaining`.
///
/// Returns `None` if `remaining > initial` (indicates a caller bug — the meter
/// was somehow replenished beyond its starting budget). The executor treats this
/// as `gas_used = 0` and logs a warning rather than panicking.
pub fn gas_used(initial: Gas, remaining: Gas) -> Option<Gas> {
    initial.checked_sub(remaining)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
