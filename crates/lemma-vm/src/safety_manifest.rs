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

use std::collections::BTreeMap;

use lemma_core::address::Address;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::VmError;
use crate::state::ContractStateView;

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

// ── WASM custom section parser ────────────────────────────────────────────────

/// Parse a [`SafetyManifest`] from raw WASM bytecode.
///
/// Reads the `"lemma.meta"` custom section and extracts the `safety_constraints`
/// array. Returns [`SafetyManifest::default()`] (empty constraints) if:
/// - The custom section is absent (pre-Step-18 contracts).
/// - The JSON is malformed (defensive — don't crash on corrupt metadata).
/// - The `safety_constraints` field is absent (non-token contracts).
///
/// This reuses [`crate::parallel::hints::find_lemma_meta_section`] to locate
/// the custom section (DRY — AGENTS §2), then deserializes via the shared
/// [`crate::parallel::hints::RawContractMetadata`] type which already includes
/// the `safety_constraints` field.
///
/// ## Backward compatibility
///
/// Contracts compiled before P3·Step 18 have no `safety_constraints` in their
/// `"lemma.meta"` JSON. The field is `Option<Vec<SafetyConstraint>>` with
/// `#[serde(default)]`, so it deserializes as `None` → empty manifest.
///
/// ## No-panic guarantee (AGENTS §7.2)
///
/// This function never panics. All error paths return the default (empty)
/// manifest with a warning log. A corrupt or absent manifest is treated as
/// "no constraints" — the contract runs without runtime invariant enforcement.
pub fn parse_safety_manifest(wasm_bytes: &[u8]) -> SafetyManifest {
    // Reuse the same custom section finder from hints.rs (DRY — AGENTS §2).
    let Some(payload) = crate::parallel::hints::find_lemma_meta_section(wasm_bytes) else {
        // No "lemma.meta" section — pre-Step-18 contract or non-Lem bytecode.
        return SafetyManifest::default();
    };

    // Deserialize the full metadata payload (same struct as hints parser).
    let raw: crate::parallel::hints::RawContractMetadata = match serde_json::from_slice(&payload) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                error = %e,
                "safety_manifest: JSON parse failed — treating as empty manifest"
            );
            return SafetyManifest::default();
        }
    };

    // Extract safety_constraints if present.
    match raw.safety_constraints {
        Some(constraints) => SafetyManifest { constraints },
        None => SafetyManifest::default(),
    }
}

// ── Host-ABI version parser (P3·Step 20, DB-A58 L2) ──────────────────────────

/// Parse the host-ABI version from a WASM module's `"lemma.meta"` custom section.
///
/// Returns `1` (the initial ABI) when:
/// - the `"lemma.meta"` section is absent (pre-Step-20 compiled contract),
/// - the `"host_abi"` field is missing from the JSON,
/// - the JSON is malformed,
/// - or the value is out of `u32` range.
///
/// This default ensures backward compatibility: contracts compiled before
/// P3·Step 20 (which do not embed `host_abi`) continue to work with ABI v1.
///
/// Reuses [`crate::parallel::hints::find_lemma_meta_section`] to locate the
/// custom section (DRY — AGENTS §2.4). No panic — all error paths return 1.
///
/// See `docs/17-VERSIONING_SPEC.md §3.2` and `DB-A58 L2`.
pub(crate) fn parse_host_abi(wasm_bytes: &[u8]) -> u32 {
    let Some(payload) = crate::parallel::hints::find_lemma_meta_section(wasm_bytes) else {
        // No "lemma.meta" section — pre-Step-20 contract or non-Lem bytecode.
        return 1;
    };
    let Ok(obj) = serde_json::from_slice::<serde_json::Value>(&payload) else {
        // Malformed JSON — fail-safe default (old contracts expected to lack this field).
        return 1;
    };
    obj.get("host_abi")
        .and_then(|v| v.as_u64())
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(1)
}

// ── Byte-value interpretation helpers ─────────────────────────────────────────

/// Format a storage key as a hex string for error messages.
///
/// Produces `0x<hex>` for binary keys, or the raw UTF-8 string if the key is
/// valid UTF-8 (more readable for keys like `"tradingEnabled"`).
fn format_key_hex(key: &[u8]) -> String {
    match std::str::from_utf8(key) {
        Ok(s) => format!("\"{s}\""),
        Err(_) => {
            // Manual hex encoding — avoids adding `hex` crate dependency.
            let mut hex = String::with_capacity(2 + key.len() * 2);
            hex.push_str("0x");
            for byte in key {
                use std::fmt::Write;
                let _ = write!(hex, "{byte:02x}");
            }
            hex
        }
    }
}

/// Interpret a byte slice as a little-endian `u64` (zero-padded if < 8 bytes).
///
/// Returns 0 for empty slices. Returns `Err(HoneypotInvariantViolation)` if
/// `bytes.len() > 8` — an oversized encoding is anomalous and must be rejected
/// rather than silently truncated (C4 fix, AGENTS §7.2).
///
/// Used for fee-cap BPS values which are small integers.
fn bytes_to_u64(bytes: &[u8]) -> Result<u64, VmError> {
    if bytes.len() > 8 {
        return Err(VmError::HoneypotInvariantViolation {
            reason: format!(
                "storage value has {} bytes, expected ≤8 for u64 comparison",
                bytes.len()
            ),
        });
    }
    let mut buf = [0u8; 8];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(u64::from_le_bytes(buf))
}

/// Interpret a byte slice as a little-endian `u128` (zero-padded if < 16 bytes).
///
/// Returns 0 for empty slices. Returns `Err(HoneypotInvariantViolation)` if
/// `bytes.len() > 16` — an oversized encoding is anomalous and must be rejected
/// rather than silently truncated (C4 fix, AGENTS §7.2).
///
/// Used for ratchet-up comparisons where values may be large token amounts.
fn bytes_to_u128(bytes: &[u8]) -> Result<u128, VmError> {
    if bytes.len() > 16 {
        return Err(VmError::HoneypotInvariantViolation {
            reason: format!(
                "storage value has {} bytes, expected ≤16 for u128 comparison",
                bytes.len()
            ),
        });
    }
    let mut buf = [0u8; 16];
    buf[..bytes.len()].copy_from_slice(bytes);
    Ok(u128::from_le_bytes(buf))
}

// ── Post-execution invariant check ───────────────────────────────────────────

/// Check whether the scratch state-diff violates any safety constraint.
///
/// Called in `settle()` after execution success, before commit. If any constraint
/// is violated, returns `Err(VmError::HoneypotInvariantViolation)` and the
/// transaction must be reverted (scratch discarded).
///
/// ## Contract address
///
/// The `contract_addr` identifies which contract's storage namespace to check.
/// Only storage writes to `(contract_addr, key)` are inspected.
///
/// ## Canonical state read-through
///
/// For ratchet checks, the old value is read from `canonical` (the state before
/// this transaction). If a key has no prior value (new field), the check is skipped
/// (the field didn't exist before, so there's no ratchet violation).
///
/// ## Determinism
///
/// All comparisons are byte-level. `BTreeMap` iteration is deterministic.
/// No floats, no `HashMap` (AGENTS §7.1).
///
/// ## No-panic guarantee (AGENTS §7.2)
///
/// This function never panics. All conversions use safe byte-level ops.
/// Returns `Ok(())` for empty manifests (backward compat).
pub(crate) fn check_safety_invariants<S: ContractStateView>(
    manifest: &SafetyManifest,
    contract_addr: &Address,
    storage_writes: &BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>>,
    canonical: &S,
) -> Result<(), VmError> {
    for constraint in &manifest.constraints {
        match constraint {
            SafetyConstraint::RatchetBool { key, locked_value } => {
                check_ratchet_bool(contract_addr, key, locked_value, storage_writes, canonical)?;
            }
            SafetyConstraint::RatchetOff { key } => {
                check_ratchet_off(contract_addr, key, storage_writes, canonical)?;
            }
            SafetyConstraint::FeeCap {
                fee_keys,
                max_sum_bps,
            } => {
                check_fee_cap(
                    contract_addr,
                    fee_keys,
                    *max_sum_bps,
                    storage_writes,
                    canonical,
                )?;
            }
            SafetyConstraint::RatchetUp { key } => {
                check_ratchet_up(contract_addr, key, storage_writes, canonical)?;
            }
        }
    }
    Ok(())
}

/// RatchetBool: a boolean gate may unlock but never re-lock.
///
/// A write changing the field TO `locked_value` when the old value was different
/// (i.e. was unlocked) is a violation. New fields (no prior value) and fields
/// already at `locked_value` are not violations.
fn check_ratchet_bool<S: ContractStateView>(
    contract_addr: &Address,
    key: &[u8],
    locked_value: &[u8],
    storage_writes: &BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>>,
    canonical: &S,
) -> Result<(), VmError> {
    let lookup_key = (*contract_addr, key.to_vec());
    let Some(write_opt) = storage_writes.get(&lookup_key) else {
        // Key not written this tx — no violation.
        return Ok(());
    };
    let Some(new_value) = write_opt else {
        // Key deleted this tx — not a ratchet-bool violation (deletion ≠ locking).
        return Ok(());
    };
    // Only check if the new value IS the locked value.
    if new_value.as_slice() != locked_value {
        return Ok(());
    }
    // New value is the locked value — check old value.
    let old_value = canonical.read(contract_addr, key);
    match old_value {
        Some(ref old) if old.as_slice() == locked_value => {
            // Was already locked — no state change, no violation.
            Ok(())
        }
        Some(_) => {
            // Was unlocked, now locking → violation.
            Err(VmError::HoneypotInvariantViolation {
                reason: format!(
                    "ratchet_bool: field {} set to locked value",
                    format_key_hex(key)
                ),
            })
        }
        None => {
            // Field didn't exist before — new field, no ratchet violation.
            Ok(())
        }
    }
}

/// RatchetOff: a capability flag may disable but never re-enable.
///
/// Boolean interpretation (W2 fix — normalized, not single-byte-only):
/// - "truthy" = any byte is non-zero (enabled/on).
/// - "falsy"  = all bytes are zero, or empty/absent (disabled/off).
///
/// A write changing from falsy (off) to truthy (on) is a violation (re-enabling).
fn check_ratchet_off<S: ContractStateView>(
    contract_addr: &Address,
    key: &[u8],
    storage_writes: &BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>>,
    canonical: &S,
) -> Result<(), VmError> {
    let lookup_key = (*contract_addr, key.to_vec());
    let Some(write_opt) = storage_writes.get(&lookup_key) else {
        return Ok(());
    };
    let Some(new_value) = write_opt else {
        // Deleted — not a re-enable (deletion = falsy).
        return Ok(());
    };
    // Only check if the new value is truthy (re-enabling attempt).
    if !is_truthy(new_value) {
        return Ok(());
    }
    // New value is truthy (on) — check if old value was falsy (off).
    let old_value = canonical.read(contract_addr, key);
    match old_value {
        Some(ref old) if !is_truthy(old) => {
            // Was off (falsy), now turning back on (truthy) → violation.
            Err(VmError::HoneypotInvariantViolation {
                reason: format!(
                    "ratchet_off: capability flag {} re-enabled",
                    format_key_hex(key)
                ),
            })
        }
        _ => {
            // Was on (truthy), didn't exist, or some other truthy value → no violation.
            Ok(())
        }
    }
}

/// Interpret a byte slice as a boolean: truthy if any byte is non-zero.
///
/// Empty slices are falsy (no bytes → no non-zero byte).
/// Used by `check_ratchet_off` for normalized boolean interpretation (W2 fix).
fn is_truthy(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b != 0)
}

/// FeeCap: the sum of fee component values must not exceed a cap.
///
/// If ANY fee key was written this tx, re-evaluate the sum of ALL fee keys
/// (using scratch values for written keys, canonical for unwritten keys).
/// If the sum exceeds `max_sum_bps`, it's a violation.
fn check_fee_cap<S: ContractStateView>(
    contract_addr: &Address,
    fee_keys: &[Vec<u8>],
    max_sum_bps: u16,
    storage_writes: &BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>>,
    canonical: &S,
) -> Result<(), VmError> {
    // Check if ANY fee key was written this tx.
    let any_written = fee_keys.iter().any(|fk| {
        let lookup = (*contract_addr, fk.clone());
        storage_writes.contains_key(&lookup)
    });
    if !any_written {
        return Ok(());
    }

    // At least one fee key was written — compute the sum of all fee values.
    let mut sum: u64 = 0;
    for fk in fee_keys {
        let lookup = (*contract_addr, fk.clone());
        // Use scratch value if written, else canonical.
        let value_bytes = match storage_writes.get(&lookup) {
            Some(Some(v)) => v.as_slice(),
            Some(None) => {
                // Deleted — treat as 0.
                &[]
            }
            None => {
                // Not written this tx — read from canonical.
                if let Some(ref canonical_val) = canonical.read(contract_addr, fk) {
                    // Need to handle the borrow: convert to u64 immediately.
                    // C4 fix: reject oversized encodings instead of truncating.
                    sum = sum.saturating_add(bytes_to_u64(canonical_val)?);
                    continue;
                }
                // Not in canonical either — treat as 0.
                &[]
            }
        };
        // C4 fix: reject oversized encodings instead of truncating.
        sum = sum.saturating_add(bytes_to_u64(value_bytes)?);
    }

    if sum > u64::from(max_sum_bps) {
        return Err(VmError::HoneypotInvariantViolation {
            reason: format!("fee_cap: fee sum {sum} exceeds cap {max_sum_bps} bps"),
        });
    }
    Ok(())
}

/// RatchetUp: a value may only increase, never decrease.
///
/// If the new value (little-endian u128) is less than the old value, it's a
/// violation. New fields (no prior value) are not violations.
fn check_ratchet_up<S: ContractStateView>(
    contract_addr: &Address,
    key: &[u8],
    storage_writes: &BTreeMap<(Address, Vec<u8>), Option<Vec<u8>>>,
    canonical: &S,
) -> Result<(), VmError> {
    let lookup_key = (*contract_addr, key.to_vec());
    let Some(write_opt) = storage_writes.get(&lookup_key) else {
        return Ok(());
    };
    let Some(new_value) = write_opt else {
        // Deleted — interpret as setting to 0. Check if old value existed.
        let old_value = canonical.read(contract_addr, key);
        if let Some(ref old) = old_value {
            // C4 fix: reject oversized encodings instead of truncating.
            let old_num = bytes_to_u128(old)?;
            if old_num > 0 {
                return Err(VmError::HoneypotInvariantViolation {
                    reason: format!(
                        "ratchet_up: field {} decreased from {old_num} to 0 (deleted)",
                        format_key_hex(key)
                    ),
                });
            }
        }
        return Ok(());
    };
    // Key was written with a value — check against old.
    let old_value = canonical.read(contract_addr, key);
    match old_value {
        Some(ref old) => {
            // C4 fix: reject oversized encodings instead of truncating.
            let old_num = bytes_to_u128(old)?;
            let new_num = bytes_to_u128(new_value)?;
            if new_num < old_num {
                Err(VmError::HoneypotInvariantViolation {
                    reason: format!(
                        "ratchet_up: field {} decreased from {old_num} to {new_num}",
                        format_key_hex(key)
                    ),
                })
            } else {
                Ok(())
            }
        }
        None => {
            // New field — no ratchet violation.
            Ok(())
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
