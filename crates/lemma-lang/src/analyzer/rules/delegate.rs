//! SAFETY-011 — Delegate Restriction rule.
//!
//! Two enforcement arms, both rejecting "execution of code from an address
//! chosen at runtime in the caller's storage context"
//! (`09-SAFETY_ANALYZER_SPEC §3 SAFETY-011`):
//!
//! 1. **SAFETY-011 (proxy pattern)** — external calls where the receiver is a
//!    state field (`self.<field>.<method>(...)`), a runtime-chosen delegate
//!    target (the proxy/upgradeable pattern). Always rejected
//!    ([`SafetyError::UnsafeDelegate`]).
//!
//! 2. **SAFETY-011b (`delegateCall` built-in gate)** — the explicit
//!    `addr.delegateCall(calldata)` built-in (where `addr` is a local/param,
//!    not a state field). `delegateCall` executes the callee's code in the
//!    *caller's* storage context — the single most dangerous primitive. Spec
//!    `03-LANGUAGE_SPEC §16` requires the enclosing function to opt in via
//!    `#[allowDelegate]`; absent that annotation it is rejected
//!    ([`SafetyError::UngatedDelegateCall`]).
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

/// The annotation that opts a function into the `delegateCall` built-in
/// (`03-LANGUAGE_SPEC §16`).  Recognized in both `#[allowDelegate]` and
/// `@allowDelegate` form (both parse to `Annotation { name: "allowDelegate" }`).
const ALLOW_DELEGATE_ANNOTATION: &str = "allowDelegate";

/// The built-in `Address` method that delegates execution into the caller's
/// storage context (`03-LANGUAGE_SPEC §16`).
const DELEGATE_CALL_METHOD: &str = "delegateCall";

/// Check a contract for SAFETY-011 unsafe-delegate violations (both arms).
///
/// Returns:
/// - one [`SafetyError::UnsafeDelegate`] per `self.<field>.<method>(...)` proxy
///   call site (SAFETY-011), and
/// - one [`SafetyError::UngatedDelegateCall`] per explicit
///   `addr.delegateCall(data)` built-in call site in a function NOT annotated
///   `#[allowDelegate]` (SAFETY-011b).
///
/// Returns an empty `Vec` if the contract is clean.
///
/// The `#[allowDelegate]` gate is evaluated per enclosing function — the
/// annotation is read from each [`crate::type_checker::typed_contract::ContractFunction`]
/// before its body is walked.  See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-011`.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut checker = DelegateChecker {
        violations: Vec::new(),
        current_fn: "",
        allows_delegate: false,
    };
    for func in contract.functions() {
        if let Some(body) = func.body {
            checker.current_fn = func.name;
            checker.allows_delegate = func
                .annotations
                .iter()
                .any(|a| a.name == ALLOW_DELEGATE_ANNOTATION);
            checker.visit_stmts(body);
        }
    }
    checker.violations
}

// ─── Visitor impl ─────────────────────────────────────────────────────────────

/// Accumulates SAFETY-011 / SAFETY-011b delegate violations.
///
/// `current_fn` / `allows_delegate` carry the enclosing-function context needed
/// by the SAFETY-011b gate; they are reset per function in [`check`].
struct DelegateChecker<'a> {
    violations: Vec<SafetyError>,
    /// Name of the function whose body is currently being walked.
    current_fn: &'a str,
    /// Whether the enclosing function carries `#[allowDelegate]`.
    allows_delegate: bool,
}

impl Visitor for DelegateChecker<'_> {
    fn visit_expr(&mut self, expr: &Expr) {
        if let Expr::Call { callee, span, .. } = expr {
            // SAFETY-011 — runtime-chosen proxy target via a state field.
            if is_self_field_call(callee) {
                self.violations
                    .push(SafetyError::UnsafeDelegate { call_site: *span });
            }
            // SAFETY-011b — explicit `addr.delegateCall(data)` built-in on a
            // non-`self.<field>` receiver requires `#[allowDelegate]`.  (The
            // `self.<field>.delegateCall` shape is already rejected by the arm
            // above, so it is excluded here to avoid a double report.)
            else if is_ungated_delegate_call(callee) && !self.allows_delegate {
                self.violations.push(SafetyError::UngatedDelegateCall {
                    func: self.current_fn.to_string(),
                    call_site: *span,
                });
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

/// Returns `true` if `callee` is the explicit `delegateCall` built-in invoked on
/// a receiver that is NOT `self.<field>` (those are already handled by
/// [`is_self_field_call`]).
///
/// Pattern (SAFETY-011b):
/// ```text
/// callee   = Expr::Member(receiver, "delegateCall", _)
/// receiver ≠ self.<field>          // i.e. a local var / param, e.g. `library`
/// ```
///
/// This is the explicit `addr.delegateCall(calldata)` form recognized by the
/// type checker (`infer.rs` — `Address` built-in method) and lowered by codegen
/// to host fn 16. Spec §16 requires `#[allowDelegate]` on the enclosing function;
/// the caller emits [`SafetyError::UngatedDelegateCall`] when that annotation is
/// absent.
fn is_ungated_delegate_call(callee: &Expr) -> bool {
    if let Expr::Member(receiver, method, _) = callee {
        if method == DELEGATE_CALL_METHOD {
            // Exclude the `self.<field>.delegateCall` shape — already SAFETY-011.
            return !is_self_field_receiver(receiver);
        }
    }
    false
}

/// Returns `true` if `receiver` is the `self.<field>` access pattern
/// (`Expr::Member(Expr::Ident("self"), field, _)`).
///
/// Used to keep SAFETY-011 (proxy pattern) and SAFETY-011b (built-in gate)
/// mutually exclusive — a `self.<field>.delegateCall(...)` site is reported once,
/// by SAFETY-011.
fn is_self_field_receiver(receiver: &Expr) -> bool {
    matches!(
        receiver,
        Expr::Member(obj, _, _) if matches!(obj.as_ref(), Expr::Ident(name, _) if name == "self")
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
