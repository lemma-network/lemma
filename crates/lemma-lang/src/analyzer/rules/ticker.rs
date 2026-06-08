//! SAFETY-013 — Ticker Registration rule.
//!
//! Verifies that every `token` contract calls `registry.register(ticker, self)`
//! on an **unconditional** path through its `init` constructor.
//!
//! ## Why unconditional?
//!
//! A `registry.register` call inside an `if` block is conditional and can be
//! bypassed — the spec requires it to be on the "unconditional path through
//! the constructor."  Top-level statements in the `init` body are always
//! executed sequentially → unconditional.
//!
//! ## Scope (4e)
//!
//! Applies to `is_token()` contracts only.  Plain contracts implementing
//! `IToken` (via `implements IToken`) are a 4f extension using the
//! `implements()` accessor added in this step.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-013`.

use crate::analyzer::error::SafetyError;
use crate::parser::{Expr, Stmt};
use crate::type_checker::typed_contract::TypedContract;

/// Check a contract for SAFETY-013 ticker registration violations.
///
/// Returns [`SafetyError::MissingTickerRegistration`] if the token contract
/// has no `init` function or if `registry.register` is not called
/// unconditionally at the top level of `init`.
/// Returns an empty `Vec` if the contract is clean or is not a token.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    // Rule applies only to token contracts.
    if !contract.is_token() {
        return Vec::new();
    }

    // Find the `init` constructor.
    let init_fn = contract.functions().into_iter().find(|f| f.name == "init");

    let Some(init) = init_fn else {
        // No constructor at all → register can't happen.
        return vec![SafetyError::MissingTickerRegistration];
    };

    let Some(body) = init.body else {
        // Interface-style signature with no body → no register call.
        return vec![SafetyError::MissingTickerRegistration];
    };

    // Walk ONLY the top-level statements of init.body (non-recursive).
    // A register call inside an if/for/loop/match is conditional → not unconditional.
    if top_level_has_registry_register(body) {
        Vec::new()
    } else {
        vec![SafetyError::MissingTickerRegistration]
    }
}

// ─── Top-level register detection ────────────────────────────────────────────

/// Returns `true` if `stmts` contains an unconditional `registry.register(...)`
/// call at the top level (not inside any branch or loop).
///
/// Matches:
/// - `Stmt::Expr(Expr::Call { callee: Expr::Member(Expr::Ident("registry"), "register", _), .. }, _)`
/// - `Stmt::Let { expr: Expr::Call { callee: Expr::Member(Expr::Ident("registry"), "register", _), .. }, .. }`
fn top_level_has_registry_register(stmts: &[Stmt]) -> bool {
    for stmt in stmts {
        match stmt {
            Stmt::Expr(expr, _) => {
                if is_registry_register_call(expr) {
                    return true;
                }
            }
            Stmt::Let { expr, .. } => {
                if is_registry_register_call(expr) {
                    return true;
                }
            }
            Stmt::Assign { value, .. } if is_registry_register_call(value) => {
                return true;
            }
            // Do NOT recurse into if/for/while/loop/match — those are conditional.
            _ => {}
        }
    }
    false
}

/// Returns `true` if `expr` is `registry.register(...)`.
///
/// The call is: `Expr::Call { callee: Expr::Member(Expr::Ident("registry", _), "register", _), .. }`.
fn is_registry_register_call(expr: &Expr) -> bool {
    match expr {
        Expr::Call { callee, .. } => is_registry_register_member(callee),
        _ => false,
    }
}

/// Returns `true` if `expr` is `registry.register` (a member access).
fn is_registry_register_member(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Member(obj, method, _)
            if method == "register" && matches!(obj.as_ref(), Expr::Ident(name, _) if name == "registry")
    )
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
