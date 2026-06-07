//! Safety analyzer driver.
//!
//! [`analyze_safety`] runs all SAFETY-001…013 rules against a [`TypedContract`]
//! and collects every violation before returning.
//!
//! ## Rule modules
//!
//! ```text
//! rules/
//!   reentrancy.rs  — SAFETY-004
//!   integer.rs     — SAFETY-012
//!   hooks.rs       — SAFETY-008
//!   delegate.rs    — SAFETY-011
//!   fee_cap.rs     — SAFETY-002  (4e)
//!   supply_cap.rs  — SAFETY-003  (4e)
//!   approvals.rs   — SAFETY-006  (4e)
//!   ticker.rs      — SAFETY-013  (4e)
//!   blacklist.rs   — SAFETY-005  (4f)
//!   one_way_gate.rs — SAFETY-009 (4f)
//!   upgrade.rs     — SAFETY-007  (4f)
//!   declared.rs    — SAFETY-010  (4f)
//!   honeypot.rs    — SAFETY-001  (4f)
//! ```

use crate::type_checker::typed_contract::TypedContract;

use super::error::SafetyError;
use super::rules;

/// Analyze a contract for compile-time safety violations (SAFETY-001…013).
///
/// Runs all enabled rules and **collects every violation** before returning
/// (`Err(violations)` is never fail-fast — the developer sees all problems in
/// one compilation attempt).
///
/// Returns `Ok(())` if no violations are found.
///
/// ## Rule coverage
///
/// **Batch 1 (4d)**: SAFETY-004, SAFETY-012, SAFETY-008, SAFETY-011 — active.
/// Batch 2 (4e) and Batch 3 (4f) rules are pending.
///
/// ## Caller
///
/// Not yet wired into the compilation pipeline — wired in 4g after all rules
/// are proven via tests and CodeReviewer-approved.
pub fn analyze_safety(contract: &TypedContract<'_>) -> Result<(), Vec<SafetyError>> {
    let mut violations: Vec<SafetyError> = Vec::new();

    // Batch 1 (4d): CFG/structural rules — decidable-exact.
    violations.extend(rules::reentrancy::check(contract)); // SAFETY-004
    violations.extend(rules::integer::check(contract)); // SAFETY-012
    violations.extend(rules::hooks::check(contract)); // SAFETY-008
    violations.extend(rules::delegate::check(contract)); // SAFETY-011

    // Batch 2 (4e): fee/supply/approval/ticker — pending.
    // Batch 3 (4f): honeypot/blacklist/gate/upgrade/declared — pending.

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
