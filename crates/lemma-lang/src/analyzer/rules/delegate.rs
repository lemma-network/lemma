//! SAFETY-011 — Delegate Restriction rule.
//!
//! Detects external calls where the receiver is a state field
//! (`self.<field>.<method>(...)`), which would execute arbitrary external code
//! through a runtime-chosen delegate target (the proxy/upgradeable pattern).
//!
//! ## Scope and known over-approximation
//!
//! Spec §3 SAFETY-011 permits calls to "a statically-known, immutable library
//! address from `@std`." This implementation does **not** carve out the `@std`
//! allow-list — any `self.<field>.<method>()` is flagged regardless of whether
//! the field holds an immutable `@std` library address. This is **sound** (never
//! allows a dynamic delegate through) but produces a false positive for the
//! legitimate `@std` immutable library pattern. The allow-list is tracked as a
//! living-notes item to add in 4f or a dedicated cleanup step.
//!
//! ## `Expr::New` is intentionally exempt
//!
//! `new Contract(...)` deploys a new contract instance — it does **not** execute
//! code in the caller's storage context (no delegatecall semantics). It is
//! already caught by SAFETY-004 (reentrancy — the deployment leaves the contract
//! boundary) and by SAFETY-010 (undeclared restriction, if needed). Flagging it
//! here would be a false positive for a legitimate operation.
//!
//! **Foundation**: focused AST walk via [`crate::visit::Visitor`] — CFG
//! `ext_calls` does not preserve receiver information, so we walk the AST
//! directly.  See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-011`.

use crate::analyzer::error::SafetyError;
use crate::parser::Expr;
use crate::type_checker::typed_contract::TypedContract;
use crate::visit::{walk_expr, Visitor};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-011 unsafe delegate violations.
///
/// Returns one [`SafetyError::UnsafeDelegate`] per call site where the callee
/// receiver is a state field (`self.<field>.<method>(...)`).
/// Returns an empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut checker = DelegateChecker {
        violations: Vec::new(),
    };
    for func in contract.functions() {
        if let Some(body) = func.body {
            checker.visit_stmts(body);
        }
    }
    checker.violations
}

// ─── Visitor impl ─────────────────────────────────────────────────────────────

/// Accumulates SAFETY-011 delegate call violations.
struct DelegateChecker {
    violations: Vec<SafetyError>,
}

impl Visitor for DelegateChecker {
    fn visit_expr(&mut self, expr: &Expr) {
        if let Expr::Call { callee, span, .. } = expr {
            if is_self_field_call(callee) {
                self.violations
                    .push(SafetyError::UnsafeDelegate { call_site: *span });
            }
        }
        walk_expr(self, expr);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` if `callee` matches the delegate pattern:
/// `self.<stateField>.<method>` — i.e., a member access on a member of `self`.
///
/// Pattern:
/// ```text
/// callee = Expr::Member(receiver, method, _)
/// receiver = Expr::Member(Expr::Ident("self", _), field, _)
/// ```
///
/// Note: `self.method()` (receiver is `Expr::Ident("self")`) is an INTERNAL
/// call and is NOT flagged — only `self.<field>.<method>()` is the delegate
/// pattern.
fn is_self_field_call(callee: &Expr) -> bool {
    if let Expr::Member(receiver, _, _) = callee {
        if let Expr::Member(obj, _, _) = receiver.as_ref() {
            return matches!(obj.as_ref(), Expr::Ident(name, _) if name == "self");
        }
    }
    false
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
