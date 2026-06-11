//! Safety analyzer driver.
//!
//! [`analyze_safety`] runs all active SAFETY rules against a [`TypedContract`]
//! and collects every violation before returning.
//!
//! ## Rule modules
//!
//! ```text
//! rules/
//!   reentrancy.rs   — SAFETY-004
//!   integer.rs      — SAFETY-012
//!   hooks.rs        — SAFETY-008
//!   delegate.rs     — SAFETY-011
//!   fee_cap.rs      — SAFETY-002  (4e; reworked to DB-A41 model in 4f-tax)
//!   supply_cap.rs   — SAFETY-003  (4e)
//!   approvals.rs    — SAFETY-006  (4e)
//!   blacklist.rs    — SAFETY-005  (4f)
//!   one_way_gate.rs — SAFETY-009  (4f)
//!   upgrade.rs      — SAFETY-007  (4f)
//!   declared.rs     — SAFETY-010  (4f)
//!   honeypot.rs     — SAFETY-001  (4f)
//!   tax.rs          — SAFETY-020/021/022  (4f-tax, TaxToken fee-model rules)
//! ```
//!
//! Note: SAFETY-013 (ticker registration) retired per decision DB-A48 —
//! registration is auto-injected by codegen for all token standards.

use crate::type_checker::typed_contract::TypedContract;

use super::error::SafetyError;
use super::rules;

/// Analyze a contract for compile-time safety violations (SAFETY-001…022).
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
/// **Batch 2 (4e)**: SAFETY-002 (reworked to DB-A41 in 4f-tax), SAFETY-003, SAFETY-006 — active.
/// **Batch 3 (4f)**: SAFETY-007, SAFETY-009, SAFETY-005, SAFETY-001, SAFETY-010 — active.
/// **Batch 3 (4f-tax)**: SAFETY-020, SAFETY-021, SAFETY-022 (TaxToken fee-model) — active.
/// SAFETY-013 retired per decision DB-A48 (auto-injected by codegen).
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

    // Batch 2 (4e): config-driven + structural rules.
    // SAFETY-002 reworked to DB-A41 model in 4f-tax (no more hook scan).
    violations.extend(rules::fee_cap::check(contract)); // SAFETY-002
    violations.extend(rules::supply_cap::check(contract)); // SAFETY-003
    violations.extend(rules::approvals::check(contract)); // SAFETY-006

    // Batch 3 (4f): authority/declaration rules.
    violations.extend(rules::upgrade::check(contract)); // SAFETY-007
    violations.extend(rules::one_way_gate::check(contract)); // SAFETY-009
    violations.extend(rules::blacklist::check(contract)); // SAFETY-005
    violations.extend(rules::honeypot::check(contract)); // SAFETY-001
    violations.extend(rules::declared::check(contract)); // SAFETY-010

    // Batch 3 (4f-tax): TaxToken fee-model rules.
    // Returns empty Vec immediately for non-TaxToken contracts.
    violations.extend(rules::tax::check(contract)); // SAFETY-020/021/022

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
