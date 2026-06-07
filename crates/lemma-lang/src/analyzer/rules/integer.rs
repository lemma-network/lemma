//! SAFETY-012 — Integer Safety rule.
//!
//! Detects unchecked arithmetic (`+`, `-`, `*`) inside `unchecked {}` blocks
//! that flows into a state field assignment (`self.field = ...`).
//!
//! **Foundation**: direct AST walk — no CFG needed.
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-012`.

use crate::analyzer::error::SafetyError;
use crate::parser::{BinaryOp, Expr, MatchBody, Stmt};
use crate::type_checker::typed_contract::TypedContract;

/// Check a contract for SAFETY-012 unchecked arithmetic violations.
///
/// Returns one [`SafetyError::UncheckedArithmetic`] per violating assignment.
/// Returns an empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        if let Some(body) = func.body {
            check_stmts_for_unchecked(body, &mut violations);
        }
    }

    violations
}

/// Recursively scan statements for `Stmt::Unchecked` blocks, then inspect
/// their contents for arithmetic assignments to state fields.
fn check_stmts_for_unchecked(stmts: &[Stmt], violations: &mut Vec<SafetyError>) {
    for stmt in stmts {
        match stmt {
            Stmt::Unchecked(inner, _) => {
                find_unchecked_arithmetic(inner, violations);
            }
            // Recurse into nested control flow to find unchecked blocks inside.
            Stmt::If { then, else_, .. } => {
                check_stmts_for_unchecked(then, violations);
                if let Some(else_body) = else_ {
                    check_stmts_for_unchecked(else_body, violations);
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                check_stmts_for_unchecked(body, violations);
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    match &arm.body {
                        MatchBody::Block(stmts) => {
                            check_stmts_for_unchecked(stmts, violations);
                        }
                        MatchBody::Expr(_) => {}
                    }
                }
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                check_stmts_for_unchecked(body, violations);
                check_stmts_for_unchecked(catch_body, violations);
            }
            _ => {}
        }
    }
}

/// Inside an `unchecked {}` block: flag any assignment to a state field that
/// uses raw arithmetic (`+`, `-`, `*`) in the value expression.
fn find_unchecked_arithmetic(stmts: &[Stmt], violations: &mut Vec<SafetyError>) {
    for stmt in stmts {
        match stmt {
            Stmt::Assign {
                target,
                value,
                span,
                ..
            } => {
                if is_state_write(target) {
                    if let Some(op_str) = first_arithmetic_op(value) {
                        violations.push(SafetyError::UncheckedArithmetic {
                            op: op_str.to_owned(),
                            span: *span,
                        });
                    }
                }
            }
            // Nested control flow inside unchecked also applies.
            Stmt::If { then, else_, .. } => {
                find_unchecked_arithmetic(then, violations);
                if let Some(else_body) = else_ {
                    find_unchecked_arithmetic(else_body, violations);
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                find_unchecked_arithmetic(body, violations);
            }
            _ => {}
        }
    }
}

/// Returns `true` if `expr` is a state-field write target:
/// `self.field` or `self.map[k]`.
fn is_state_write(expr: &Expr) -> bool {
    match expr {
        // self.field = ...
        Expr::Member(obj, _, _) => is_self(obj),
        // self.map[k] = ...
        Expr::Index(base, _, _) => {
            if let Expr::Member(obj, _, _) = base.as_ref() {
                is_self(obj)
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Returns `true` if `expr` is the identifier `self`.
fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

/// Walk an expression tree and return the string representation of the first
/// raw arithmetic operator (`+`, `-`, `*`) found, or `None` if none exists.
fn first_arithmetic_op(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::Binary(op, lhs, rhs, _) => {
            match op {
                BinaryOp::Add => Some("+"),
                BinaryOp::Sub => Some("-"),
                BinaryOp::Mul => Some("*"),
                // Non-arithmetic binary op — recurse into operands.
                _ => first_arithmetic_op(lhs).or_else(|| first_arithmetic_op(rhs)),
            }
        }
        Expr::Unary(_, inner, _) => first_arithmetic_op(inner),
        Expr::Member(base, _, _) => first_arithmetic_op(base),
        Expr::Index(base, idx, _) => first_arithmetic_op(base).or_else(|| first_arithmetic_op(idx)),
        Expr::Cast { expr, .. } => first_arithmetic_op(expr),
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
