//! SAFETY-006 — Approval Bounds rule.
//!
//! Verifies that any `approve` function in a contract requires a time-bounded
//! expiry parameter, preventing infinite approvals.
//!
//! ## Scope (4e)
//!
//! Checks functions named exactly `"approve"` for the presence of an `expiry`,
//! `deadline`, or `expires` parameter.  If no `approve` function exists, the
//! rule passes (not applicable).
//!
//! ## Scoping decision: MAX-sentinel check deferred to 4f
//!
//! Checking for `approve(spender, Amount::MAX)` requires resolving the type
//! and knowing the max sentinel value for the type — type-system knowledge not
//! yet plumbed through.  Scoped out.  The expiry check is the primary
//! protection for 4e.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-006`.

use crate::analyzer::error::SafetyError;
use crate::type_checker::typed_contract::TypedContract;

/// Check a contract for SAFETY-006 unbounded approval violations.
///
/// Returns [`SafetyError::UnboundedApproval`] for each `approve` function
/// that lacks an expiry parameter.  Returns an empty `Vec` if the contract
/// is clean or has no `approve` function.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        // Only inspect functions named exactly "approve".
        if func.name != "approve" {
            continue;
        }

        // Check for an expiry/deadline/expires parameter.
        let has_expiry = func
            .params
            .iter()
            .any(|p| p.name == "expiry" || p.name == "deadline" || p.name == "expires");

        if !has_expiry {
            violations.push(SafetyError::UnboundedApproval {
                reason: "approve function has no expiry or deadline parameter \
                         (all approvals must be time-bounded)"
                    .to_owned(),
            });
        }
    }

    violations
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
