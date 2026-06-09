//! Canonical AST visitor for `Stmt` / `Expr` trees.
//!
//! # Design
//!
//! Every SAFETY-rule walker and WF-007/015 checker implements [`Visitor`].
//! The two free functions [`walk_stmt`] and [`walk_expr`] provide the
//! **one canonical traversal** of the AST — correct, complete, and shared
//! (AGENTS §2 DRY).
//!
//! # Usage
//!
//! Implement [`Visitor`] on a struct that accumulates results.  Override
//! [`Visitor::visit_stmt`] and/or [`Visitor::visit_expr`] to intercept nodes;
//! call [`walk_stmt`] / [`walk_expr`] to continue the structural recursion:
//!
//! ```ignore
//! struct CallCounter { count: usize }
//!
//! impl Visitor for CallCounter {
//!     fn visit_expr(&mut self, expr: &Expr) {
//!         if matches!(expr, Expr::Call { .. }) {
//!             self.count += 1;
//!         }
//!         walk_expr(self, expr); // continue recursion
//!     }
//! }
//! ```
//!
//! # Lambda scope
//!
//! `Expr::Lambda` bodies are **not descended into** — a lambda is a separate
//! function scope whose effects must be validated independently.  This matches
//! the policy in `cfg.rs` and `wellformed`.
//!
//! # Coverage
//!
//! Every `Stmt` variant: `Let`, `Const`, `Assign`, `If`, `Match`, `For`,
//! `While`, `Loop`, `Return`, `Break`, `Continue`, `Emit`, `Assert`,
//! `Revert`, `Try`, `Unchecked`, `Placeholder`, `Expr`.
//!
//! Every `Expr` variant that carries sub-expressions: `Call` (incl. opts),
//! `New` (incl. opts), `Assign_`, `Member`, `Index`, `Unary`, `Try_`,
//! `Binary`, `Ternary`, `Nullish`, `Cast`, `If_`, `Match_`, `Tuple`,
//! `Array`, `Struct_`, `Template`.  Leaf variants (`Literal`, `Ident`) and
//! separate-scope variants (`Lambda`) produce no further descent.

use crate::parser::ast::TemplateExprSegment;
use crate::parser::{CallArg, Expr, ForIter, MatchBody, Stmt};

// ─── Visitor trait ────────────────────────────────────────────────────────────

/// Canonical depth-first visitor over [`Stmt`] / [`Expr`] trees.
///
/// Default implementations of [`visit_stmt`] and [`visit_expr`] delegate to
/// [`walk_stmt`] / [`walk_expr`], which provide the complete structural
/// traversal.  Override either method to intercept nodes; call the appropriate
/// free function to continue recursion.
pub(crate) trait Visitor: Sized {
    /// Called at each statement. Default: full structural recursion via [`walk_stmt`].
    ///
    /// Override to intercept statement nodes.  Call `walk_stmt(self, stmt)` to
    /// continue recursion into children.
    fn visit_stmt(&mut self, stmt: &Stmt) {
        walk_stmt(self, stmt);
    }

    /// Visit each statement in `stmts`, calling [`visit_stmt`] for each.
    fn visit_stmts(&mut self, stmts: &[Stmt]) {
        for s in stmts {
            self.visit_stmt(s);
        }
    }

    /// Called at each expression. Default: full structural recursion via [`walk_expr`].
    ///
    /// Override to intercept expression nodes.  Call `walk_expr(self, expr)` to
    /// continue recursion into sub-expressions.
    fn visit_expr(&mut self, expr: &Expr) {
        walk_expr(self, expr);
    }
}

// ─── walk_stmt ────────────────────────────────────────────────────────────────

/// Canonical structural traversal for a single statement.
///
/// Recurses into all sub-statements and sub-expressions via `v.visit_stmt` /
/// `v.visit_expr`.  Rules call this from their [`Visitor::visit_stmt`] override
/// to continue recursion after taking their own action.
pub(crate) fn walk_stmt<V: Visitor>(v: &mut V, stmt: &Stmt) {
    match stmt {
        Stmt::Let { expr, .. } => v.visit_expr(expr),
        Stmt::Const(c) => v.visit_expr(&c.value),
        Stmt::Assign { target, value, .. } => {
            v.visit_expr(target);
            v.visit_expr(value);
        }
        Stmt::Return(Some(e), _) => v.visit_expr(e),
        Stmt::Emit { fields, .. } => {
            for (_, e) in fields {
                v.visit_expr(e);
            }
        }
        Stmt::If {
            cond, then, else_, ..
        } => {
            v.visit_expr(cond);
            v.visit_stmts(then);
            for b in else_.iter() {
                v.visit_stmts(b);
            }
        }
        Stmt::While { cond, body, .. } => {
            v.visit_expr(cond);
            v.visit_stmts(body);
        }
        Stmt::For { iter, body, .. } => {
            match iter {
                ForIter::Of(e) => v.visit_expr(e),
                ForIter::In(start, _, end, _) => {
                    v.visit_expr(start);
                    v.visit_expr(end);
                }
            }
            v.visit_stmts(body);
        }
        Stmt::Loop { body, .. } => v.visit_stmts(body),
        Stmt::Match { expr, arms, .. } => {
            v.visit_expr(expr);
            for arm in arms {
                if let Some(g) = &arm.guard {
                    v.visit_expr(g);
                }
                match &arm.body {
                    MatchBody::Expr(e) => v.visit_expr(e),
                    MatchBody::Block(stmts) => v.visit_stmts(stmts),
                }
            }
        }
        Stmt::Try {
            body, catch_body, ..
        } => {
            v.visit_stmts(body);
            v.visit_stmts(catch_body);
        }
        Stmt::Unchecked(body, _) => v.visit_stmts(body),
        Stmt::Assert { cond, msg, .. } => {
            v.visit_expr(cond);
            if let Some(m) = msg {
                v.visit_expr(m);
            }
        }
        Stmt::Revert { msg: Some(m), .. } => v.visit_expr(m),
        Stmt::Expr(e, _) => v.visit_expr(e),
        // Break / Continue / Return(None) / Placeholder: no sub-expressions.
        _ => {}
    }
}

// ─── walk_expr ────────────────────────────────────────────────────────────────

/// Canonical structural traversal for a single expression.
///
/// Recurses into all sub-expressions via `v.visit_expr` and descends into
/// statement bodies carried by `Expr::If_` and `Expr::Match_` via
/// `v.visit_stmts`.  Rules call this from their [`Visitor::visit_expr`] override
/// to continue recursion after taking their own action.
///
/// `Expr::Lambda` is **not descended into** (separate scope).
pub(crate) fn walk_expr<V: Visitor>(v: &mut V, expr: &Expr) {
    match expr {
        Expr::Call {
            callee, opts, args, ..
        } => {
            v.visit_expr(callee);
            if let Some(o) = opts {
                if let Some(val) = &o.value {
                    v.visit_expr(val);
                }
                if let Some(gas) = &o.gas {
                    v.visit_expr(gas);
                }
                if let Some(salt) = &o.salt {
                    v.visit_expr(salt);
                }
            }
            for arg in args {
                let e = match arg {
                    CallArg::Positional(e) | CallArg::Named(_, e) => e,
                };
                v.visit_expr(e);
            }
        }
        Expr::New { opts, args, .. } => {
            if let Some(o) = opts {
                if let Some(val) = &o.value {
                    v.visit_expr(val);
                }
                if let Some(gas) = &o.gas {
                    v.visit_expr(gas);
                }
                if let Some(salt) = &o.salt {
                    v.visit_expr(salt);
                }
            }
            for arg in args {
                let e = match arg {
                    CallArg::Positional(e) | CallArg::Named(_, e) => e,
                };
                v.visit_expr(e);
            }
        }
        Expr::Assign_(target, _, val, _) => {
            v.visit_expr(target);
            v.visit_expr(val);
        }
        Expr::Member(base, _, _) => v.visit_expr(base),
        Expr::Index(base, idx, _) => {
            v.visit_expr(base);
            v.visit_expr(idx);
        }
        Expr::Unary(_, inner, _) | Expr::Try_(inner, _) => v.visit_expr(inner),
        Expr::Binary(_, l, r, _) => {
            v.visit_expr(l);
            v.visit_expr(r);
        }
        Expr::Ternary {
            cond, then, else_, ..
        } => {
            v.visit_expr(cond);
            v.visit_expr(then);
            v.visit_expr(else_);
        }
        Expr::Nullish(l, r, _) => {
            v.visit_expr(l);
            v.visit_expr(r);
        }
        Expr::Cast { expr, .. } => v.visit_expr(expr),
        Expr::If_ {
            cond, then, else_, ..
        } => {
            v.visit_expr(cond);
            v.visit_stmts(then);
            for b in else_.iter() {
                v.visit_stmts(b);
            }
        }
        Expr::Match_(scrutinee, arms, _) => {
            v.visit_expr(scrutinee);
            for arm in arms {
                if let Some(g) = &arm.guard {
                    v.visit_expr(g);
                }
                match &arm.body {
                    MatchBody::Expr(e) => v.visit_expr(e),
                    MatchBody::Block(stmts) => v.visit_stmts(stmts),
                }
            }
        }
        Expr::Tuple(elems, _) | Expr::Array(elems, _) => {
            for e in elems {
                v.visit_expr(e);
            }
        }
        Expr::Struct_ { fields, spread, .. } => {
            for (_, e) in fields {
                v.visit_expr(e);
            }
            if let Some(s) = spread {
                v.visit_expr(s);
            }
        }
        Expr::Template(segments, _) => {
            for seg in segments {
                if let TemplateExprSegment::Interpolation(e) = seg {
                    v.visit_expr(e);
                }
            }
        }
        // Lambda: separate function scope — do NOT descend.
        // Literal / Ident: leaf nodes with no sub-expressions.
        _ => {}
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
