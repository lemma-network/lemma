//! SAFETY-011 — Delegate Restriction rule.
//!
//! Detects external calls where the receiver is a state field
//! (`self.<field>.<method>(...)`), which would execute arbitrary external code
//! through a runtime-chosen delegate target.
//!
//! **Foundation**: focused AST walk — CFG `ext_calls` does not preserve receiver
//! information, so we walk the AST directly.
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-011`.

use crate::analyzer::error::SafetyError;
use crate::parser::{CallArg, Expr, ForIter, MatchBody, Stmt};
use crate::type_checker::typed_contract::TypedContract;

/// Check a contract for SAFETY-011 unsafe delegate violations.
///
/// Returns one [`SafetyError::UnsafeDelegate`] per call site where the callee
/// receiver is a state field (`self.<field>.<method>(...)`).
/// Returns an empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        if let Some(body) = func.body {
            find_delegate_calls(body, &mut violations);
        }
    }

    violations
}

/// Walk all statements and their sub-expressions, collecting delegate call sites.
fn find_delegate_calls(stmts: &[Stmt], violations: &mut Vec<SafetyError>) {
    for stmt in stmts {
        walk_stmt(stmt, violations);
    }
}

/// Walk a single statement, recursing into sub-expressions and nested blocks.
fn walk_stmt(stmt: &Stmt, violations: &mut Vec<SafetyError>) {
    match stmt {
        Stmt::Let { expr, .. } => walk_expr(expr, violations),
        Stmt::Const(c) => walk_expr(&c.value, violations),
        Stmt::Assign { target, value, .. } => {
            walk_expr(target, violations);
            walk_expr(value, violations);
        }
        Stmt::Return(Some(e), _) => walk_expr(e, violations),
        Stmt::Emit { fields, .. } => {
            for (_, e) in fields {
                walk_expr(e, violations);
            }
        }
        Stmt::If {
            cond, then, else_, ..
        } => {
            walk_expr(cond, violations);
            find_delegate_calls(then, violations);
            if let Some(else_body) = else_ {
                find_delegate_calls(else_body, violations);
            }
        }
        Stmt::While { cond, body, .. } => {
            walk_expr(cond, violations);
            find_delegate_calls(body, violations);
        }
        Stmt::For { iter, body, .. } => {
            match iter {
                ForIter::Of(e) => walk_expr(e, violations),
                ForIter::In(start, _, end, _) => {
                    walk_expr(start, violations);
                    walk_expr(end, violations);
                }
            }
            find_delegate_calls(body, violations);
        }
        Stmt::Loop { body, .. } => find_delegate_calls(body, violations),
        Stmt::Match { expr, arms, .. } => {
            walk_expr(expr, violations);
            for arm in arms {
                if let Some(g) = &arm.guard {
                    walk_expr(g, violations);
                }
                match &arm.body {
                    MatchBody::Expr(e) => walk_expr(e, violations),
                    MatchBody::Block(stmts) => find_delegate_calls(stmts, violations),
                }
            }
        }
        Stmt::Try {
            body, catch_body, ..
        } => {
            find_delegate_calls(body, violations);
            find_delegate_calls(catch_body, violations);
        }
        Stmt::Unchecked(body, _) => find_delegate_calls(body, violations),
        Stmt::Assert { cond, msg, .. } => {
            walk_expr(cond, violations);
            if let Some(m) = msg {
                walk_expr(m, violations);
            }
        }
        Stmt::Revert { msg: Some(m), .. } => walk_expr(m, violations),
        Stmt::Expr(e, _) => walk_expr(e, violations),
        _ => {}
    }
}

/// Walk an expression, detecting delegate call patterns and recursing into
/// all sub-expressions.
fn walk_expr(expr: &Expr, violations: &mut Vec<SafetyError>) {
    match expr {
        Expr::Call {
            callee, args, span, ..
        } => {
            // Check if this call is a delegate pattern: self.<field>.<method>(...)
            if is_self_field_call(callee) {
                violations.push(SafetyError::UnsafeDelegate { call_site: *span });
            }
            // Always recurse into callee and args to catch nested delegate calls.
            walk_expr(callee, violations);
            for arg in args {
                let e = match arg {
                    CallArg::Positional(e) | CallArg::Named(_, e) => e,
                };
                walk_expr(e, violations);
            }
        }
        Expr::New { args, .. } => {
            for arg in args {
                let e = match arg {
                    CallArg::Positional(e) | CallArg::Named(_, e) => e,
                };
                walk_expr(e, violations);
            }
        }
        Expr::Member(base, _, _) => walk_expr(base, violations),
        Expr::Index(base, idx, _) => {
            walk_expr(base, violations);
            walk_expr(idx, violations);
        }
        Expr::Unary(_, inner, _) | Expr::Try_(inner, _) => walk_expr(inner, violations),
        Expr::Binary(_, l, r, _) => {
            walk_expr(l, violations);
            walk_expr(r, violations);
        }
        Expr::Ternary {
            cond, then, else_, ..
        } => {
            walk_expr(cond, violations);
            walk_expr(then, violations);
            walk_expr(else_, violations);
        }
        Expr::Nullish(l, r, _) => {
            walk_expr(l, violations);
            walk_expr(r, violations);
        }
        Expr::Cast { expr, .. } => walk_expr(expr, violations),
        Expr::Assign_(target, _, val, _) => {
            walk_expr(target, violations);
            walk_expr(val, violations);
        }
        Expr::If_ {
            cond, then, else_, ..
        } => {
            walk_expr(cond, violations);
            find_delegate_calls(then, violations);
            if let Some(else_body) = else_ {
                find_delegate_calls(else_body, violations);
            }
        }
        Expr::Match_(scrutinee, arms, _) => {
            walk_expr(scrutinee, violations);
            for arm in arms {
                if let Some(g) = &arm.guard {
                    walk_expr(g, violations);
                }
                match &arm.body {
                    MatchBody::Expr(e) => walk_expr(e, violations),
                    MatchBody::Block(stmts) => find_delegate_calls(stmts, violations),
                }
            }
        }
        // Literal / Ident / Tuple / Array / Struct_ / Lambda / Template:
        // no sub-calls to inspect.
        _ => {}
    }
}

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
