//! # Safety manifest types for runtime honeypot invariant enforcement
//!
//! Defines [`SafetyManifest`] and [`SafetyConstraint`] — the runtime
//! counterpart of the Lem compiler's static safety analysis.
//!
//! ## How it works
//!
//! The Lem compiler embeds a `SafetyManifest` (JSON) in the `"lemma.meta"`
//! WASM custom section alongside the existing [`crate::parallel::ContractHints`].
//! At deploy/call time the VM reads the manifest and enforces post-execution
//! invariants: any transaction that violates a constraint is **reverted**
//! (honeypot prevention).
//!
//! ## Constraint variants
//!
//! | Variant | Spec rule | Invariant |
//! |---------|-----------|-----------|
//! | [`SafetyConstraint::RatchetBool`] | SAFETY-009 runtime pair | One-way boolean gate: may unlock but never re-lock |
//! | [`SafetyConstraint::RatchetOff`] | SAFETY-009 runtime pair | Capability flag: may disable but never re-enable |
//! | [`SafetyConstraint::FeeCap`] | SAFETY-002 runtime pair | Sum of fee components ≤ declared cap |
//! | [`SafetyConstraint::RatchetUp`] | SAFETY-023 runtime pair | Value may only increase, never decrease |
//!
//! ## Backward compatibility
//!
//! Contracts compiled before this feature have no manifest in `"lemma.meta"`.
//! [`SafetyManifest::default()`] returns an empty constraints vector, so the
//! VM treats legacy contracts as having zero runtime constraints — no behavior
//! change for existing deployments.
//!
//! See `09-SAFETY_ANALYZER_SPEC` SAFETY-001 (runtime pair), `decisions-log DB-A51`.

use serde::{Deserialize, Serialize};

/// A single safety constraint extracted by the compiler and embedded in `"lemma.meta"`.
///
/// The VM reads these at deploy/call to enforce post-execution invariants:
/// any transaction that violates a constraint → REVERT (honeypot prevention).
///
/// Uses `#[serde(tag = "type")]` for internally-tagged JSON representation,
/// producing clean, readable output like `{"type": "ratchet_bool", "key": [...], ...}`.
///
/// See `09-SAFETY_ANALYZER_SPEC` SAFETY-001 (runtime pair), `decisions-log DB-A51`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SafetyConstraint {
    /// One-way boolean gate: storage key may transition TO `unlocked_value` but
    /// never BACK to `locked_value`. E.g. `tradingEnabled` can be set to `true`
    /// but never flipped back to `false` (SAFETY-009 runtime pair).
    #[serde(rename = "ratchet_bool")]
    RatchetBool {
        /// Storage key prefix identifying this field.
        key: Vec<u8>,
        /// The value that BLOCKS transfers (the "locked" / honeypot state).
        /// A write changing the field TO this value → violation.
        locked_value: Vec<u8>,
    },

    /// Ratchet-off capability flag: may transition from enabled (true/1) to
    /// disabled (false/0) but never back. E.g. `mintable: true → false` is
    /// allowed; `mintable: false → true` is blocked.
    #[serde(rename = "ratchet_off")]
    RatchetOff {
        /// Storage key prefix identifying this capability flag.
        key: Vec<u8>,
    },

    /// Fee cap: the sum of fee component storage values must not exceed a cap.
    /// E.g. `fees.burn + fees.holders + fees.others ≤ maxFeePercent` (SAFETY-002 runtime pair).
    #[serde(rename = "fee_cap")]
    FeeCap {
        /// Storage key prefixes for each fee component field.
        fee_keys: Vec<Vec<u8>>,
        /// Maximum allowed sum in basis points (bps).
        max_sum_bps: u16,
    },

    /// Ratchet-up: storage value may only increase, never decrease.
    /// E.g. `maxWallet` can be raised (loosened) but never lowered (SAFETY-023 runtime pair).
    #[serde(rename = "ratchet_up")]
    RatchetUp {
        /// Storage key prefix identifying this field.
        key: Vec<u8>,
    },
}

/// Safety manifest embedded in the `"lemma.meta"` WASM custom section.
///
/// Contains all safety constraints the VM must enforce post-execution.
/// An empty `constraints` vector means no constraints (backward compatible —
/// contracts compiled before Step 18 have no manifest).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyManifest {
    /// All safety constraints the VM must enforce post-execution.
    pub constraints: Vec<SafetyConstraint>,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
