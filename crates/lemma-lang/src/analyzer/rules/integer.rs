//! SAFETY-012 — Integer Safety rule.
//!
//! Detects unchecked arithmetic (`+`, `-`, `*`) inside `unchecked {}` blocks
//! that flows into a state field assignment (`self.field = ...`).
//!
//! ## Scope: deliberate over-approximation
//!
//! Spec §3 SAFETY-012 scopes the prohibition to arithmetic flowing into
//! "value-bearing quantities" (balances, `totalSupply`, value transfers).
//! This implementation flags unchecked arithmetic on **any** state field, not
//! just value-bearing ones. For example, `unchecked { self.nonceCounter = ... }`
//! is flagged even though `nonceCounter` is not a token amount.
//!
//! This is **sound** (no false negatives — every value-bearing field is a state
//! field). The false-positive rate on non-value fields is the known trade-off,
//! intentional for 4d. Narrowing to value-bearing fields requires value-path
//! taint from `dataflow::taint_propagate` — tracked as a living-notes item to
//! refine in 4e when taint consumers are added.
//!
//! ## Gap-closure (P3·Step 4e.5)
//!
//! The previous implementation of `find_unchecked_arithmetic` missed
//! `Stmt::Match`, `Stmt::Try`, and nested `Stmt::Unchecked` variants inside
//! unchecked blocks, producing false negatives for patterns like:
//!
//! ```text
//! unchecked {
//!     match val { _ => self.x = self.x + val }  // was missed
//!     try { self.x = self.x + val } catch e { }   // was missed
//! }
//! ```
//!
//! Both are now caught automatically because the canonical
//! [`crate::visit::Visitor`] traversal covers every `Stmt` variant.
//!
//! **Foundation**: direct AST walk via [`crate::visit::Visitor`].
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-012`.

use crate::analyzer::error::SafetyError;
use crate::analyzer::util::is_self;
use crate::parser::{BinaryOp, Expr, Stmt};
use crate::type_checker::typed_contract::TypedContract;
use crate::visit::{walk_expr, walk_stmt, Visitor};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-012 unchecked arithmetic violations.
///
/// Returns one [`SafetyError::UncheckedArithmetic`] per violating assignment.
/// Returns an empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut scanner = UncheckedScanner {
        violations: Vec::new(),
    };
    for func in contract.functions() {
        if let Some(body) = func.body {
            scanner.visit_stmts(body);
        }
    }
    scanner.violations
}

// ─── UncheckedScanner: locate unchecked blocks ───────────────────────────────

/// Scans the function body for `Stmt::Unchecked` blocks at any nesting depth,
/// then delegates to [`ArithChecker`] for each block's contents.
///
/// Does not do arithmetic checking itself — only structural traversal to find
/// unchecked blocks.  Canonical recursion via [`walk_stmt`] covers all
/// control-flow variants including `Match`/`Try`/nested `Unchecked`.
struct UncheckedScanner {
    violations: Vec<SafetyError>,
}

impl Visitor for UncheckedScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Unchecked(inner, _) = stmt {
            // Switch to ArithChecker for the unchecked body.
            let mut checker = ArithChecker {
                violations: Vec::new(),
            };
            checker.visit_stmts(inner);
            self.violations.extend(checker.violations);
            // Do NOT call walk_stmt here — inner is already fully traversed
            // by ArithChecker.  A nested `unchecked` inside `inner` is handled
            // by ArithChecker's own visit_stmt (which switches again).
        } else {
            walk_stmt(self, stmt);
        }
    }
}

// ─── ArithChecker: detect violations inside unchecked bodies ─────────────────

/// Checks statements inside an `unchecked {}` body for raw arithmetic writes
/// to state fields.  Also handles nested `unchecked` blocks by recursing.
///
/// The canonical [`walk_stmt`] covers `Match`, `Try`, and all other
/// control-flow variants — these were the false-negative paths in the prior
/// implementation.
struct ArithChecker {
    violations: Vec<SafetyError>,
}

impl Visitor for ArithChecker {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign {
                target,
                value,
                span,
                ..
            } => {
                if is_state_write(target) {
                    if let Some(op_str) = first_arithmetic_op(value) {
                        self.violations.push(SafetyError::UncheckedArithmetic {
                            op: op_str.to_owned(),
                            span: *span,
                        });
                    }
                }
            }
            // A nested `unchecked {}` inside an unchecked body: re-enter
            // ArithChecker for its contents (still inside unchecked scope).
            Stmt::Unchecked(inner, _) => {
                let mut inner_checker = ArithChecker {
                    violations: Vec::new(),
                };
                inner_checker.visit_stmts(inner);
                self.violations.extend(inner_checker.violations);
                return; // inner already fully traversed
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }
    fn visit_expr(&mut self, expr: &Expr) {
        // Detect expression-position assignment: `self.field = self.field + val`
        if let Expr::Assign_(target, _, value, span) = expr {
            if is_state_write(target) {
                if let Some(op_str) = first_arithmetic_op(value) {
                    self.violations.push(SafetyError::UncheckedArithmetic {
                        op: op_str.to_owned(),
                        span: *span,
                    });
                }
            }
        }
        walk_expr(self, expr);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` if `expr` is a state-field write target:
/// `self.field` or `self.map[k]`.
fn is_state_write(expr: &Expr) -> bool {
    match expr {
        Expr::Member(obj, _, _) => is_self(obj),
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

/// Walk an expression tree and return the string representation of the first
/// raw arithmetic operator (`+`, `-`, `*`) found, or `None` if none exists.
fn first_arithmetic_op(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::Binary(op, lhs, rhs, _) => match op {
            BinaryOp::Add => Some("+"),
            BinaryOp::Sub => Some("-"),
            BinaryOp::Mul => Some("*"),
            // Non-arithmetic binary op — recurse into operands.
            _ => first_arithmetic_op(lhs).or_else(|| first_arithmetic_op(rhs)),
        },
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
