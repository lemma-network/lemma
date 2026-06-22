//! SAFETY-011 — Delegate Restriction rule.
//!
//! Detects external calls where the receiver is a state field
//! (`self.<field>.<method>(...)`), which would execute arbitrary external code
//! through a runtime-chosen delegate target (the proxy/upgradeable pattern).
//!
//! ## Collection method allow-list
//!
//! Known collection methods (`get`, `set`, `add`, `remove`, `has`, `delete`,
//! `keys`, `values`, `entries`, `size`, etc.) are whitelisted —
//! `self.balances.get(addr)` is a collection read, not a delegate call.
//! Non-whitelisted `self.<field>.<method>()` patterns are still flagged.
//! See `03-LANGUAGE_SPEC §11` for the full collection type API.
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
///
/// ## Scope limitation (delegate-call-gate-1)
///
/// NOTE: SAFETY-011 currently catches `self.<field>.<method>()` proxy patterns.
/// It does NOT yet enforce `#[allowDelegate]` on `Address::delegateCall()` built-in
/// calls (i.e. `addr.delegateCall(data)` where `addr` is a local variable or param,
/// not a state field). Spec §16 requires `#[allowDelegate]` annotation on the
/// enclosing function for any delegateCall usage.
///
/// See living-notes Technical Debt: **delegate-call-gate-1**.
/// Fix: add a SAFETY-011b rule arm in this file that detects
/// `Expr::Call` where callee is `Expr::Member(_, "delegateCall")` and the
/// receiver is NOT `self.<field>` (those are already caught above), then checks
/// for `#[allowDelegate]` annotation on the enclosing function.
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

/// Known safe collection methods that are NOT delegate calls.
///
/// These are standard `Map`/`Set`/`Array`/`FastMap` operations on state fields.
/// A call like `self.balances.get(addr)` is a collection read, not a delegate.
/// See `03-LANGUAGE_SPEC §11` for collection types and their methods.
const COLLECTION_METHODS: &[&str] = &[
    // Map / FastMap methods (§11 "Map", "FastMap & Set")
    "get",
    "getOr",
    "set",
    "has",
    "delete",
    "keys",
    "values",
    "entries",
    "filter",
    "mapValues",
    // Set methods (§11 "FastMap & Set")
    "add",
    "remove",
    "intersection",
    "union",
    "difference",
    // Array methods (§11 "Array")
    "push",
    "pop",
    "insert",
    "removeAt",
    "clear",
    "first",
    "last",
    "map",
    "reduce",
    "find",
    "findIndex",
    "some",
    "every",
    "count",
    "sum",
    "max",
    "min",
    "sort",
    "sortBy",
    "reverse",
    "slice",
    "concat",
    "contains",
    "indexOf",
    "enumerate",
    "zip",
    "flatten",
    "chunk",
];

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
///
/// Collection methods (e.g. `get`, `set`, `add`, `has`) are exempt — they are
/// standard `Map`/`Set`/`Array` operations, not delegate calls.
fn is_self_field_call(callee: &Expr) -> bool {
    if let Expr::Member(receiver, method, _) = callee {
        if let Expr::Member(obj, _, _) = receiver.as_ref() {
            if matches!(obj.as_ref(), Expr::Ident(name, _) if name == "self") {
                // Known collection operations are NOT delegate calls.
                return !COLLECTION_METHODS.contains(&method.as_str());
            }
        }
    }
    false
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
