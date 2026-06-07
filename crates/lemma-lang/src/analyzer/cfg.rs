//! Control-flow graph, call-graph, and external-call analysis.
//!
//! ## Purpose
//!
//! Foundational analyses computed once per function and reused by multiple
//! SAFETY rules and the Step 5 state-access analyzer (spec §2, §6):
//!
//! - **`CallGraph`** (`build_call_graph`): intra-contract call edges
//!   `fn_name → {callee1, callee2, …}` (self-method + free-fn calls only).
//! - **`Ext(f)`** (`ext_calls`): call sites that leave the contract.
//! - **`CfgNode` sequence** (`cfg_nodes`): ordered `StateWrite`/`ExternalCall`
//!   nodes for SAFETY-004 state-after-call analysis.
//!
//! ## Single-walk design (AGENTS §2 DRY)
//!
//! All three analyses are collected in **one pass** over the function body via
//! [`FnWalk`] and [`walk_function`].  Public functions delegate to it and
//! extract the relevant part; SAFETY rules that need multiple analyses can call
//! `walk_function` directly to avoid redundant walks.
//!
//! ## What counts as an "external call"?
//!
//! Any call whose callee is **not** a `self` method (spec §2):
//! - `Expr::Call { callee: Member(non_self_obj, method) }` — method on another
//!   contract instance.
//! - `Expr::New { .. }` — contract deployment (leaves current context).

use std::collections::{BTreeMap, BTreeSet};

use crate::lexer::token::Span;
use crate::parser::{CallArg, Expr, ForIter, MatchBody, Stmt};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};

// ─── Public types ─────────────────────────────────────────────────────────────

/// Intra-contract call graph: function name → internal callees.
pub type CallGraph = BTreeMap<String, BTreeSet<String>>;

/// A single external call site in a function body.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExtCall {
    /// Human-readable description of the callee (e.g. `"<external>.transfer"`).
    pub callee_desc: String,
    /// Source location of the call expression.
    pub span: Span,
}

/// A node in the linearised control-flow graph, tagged with its state effect.
///
/// Branches are expanded (all paths merged) so the sequence is a sound
/// over-approximation for SAFETY-004 state-after-call analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CfgNode {
    /// A write to a contract state field (`self.field = …` / `self.map[k] = …`).
    StateWrite {
        /// The state field name (e.g. `"balances"`).
        key: String,
        /// Source location of the assignment.
        span: Span,
    },
    /// A call that leaves the contract boundary.
    ExternalCall {
        /// Source location of the call expression.
        span: Span,
    },
    /// An intra-contract call (to a `self` method or a free function in the
    /// same compilation unit).
    ///
    /// Emitted in the ordered CFG node sequence so that SAFETY-004 can detect
    /// reentrancy via indirection: `external_call → self.helper()` where
    /// `helper` transitively writes state is a CEI violation.
    InternalCall {
        /// The callee name (method name for `self.method(…)`, function name
        /// for a bare `fn_name(…)` call).
        callee: String,
        /// Source location of the call expression.
        span: Span,
    },
}

// ─── FnWalk — single-pass collection result ───────────────────────────────────

/// All analysis results collected in one walk of a function body.
///
/// Callers may need only one of the three fields; the single walk pays the
/// traversal cost once regardless (AGENTS §2 DRY — no per-analysis rewalk).
#[derive(Debug, Default)]
pub(crate) struct FnWalk {
    /// Internal callees (for call-graph edges).
    pub internal_calls: BTreeSet<String>,
    /// External call sites (for `Ext(f)`).
    pub ext_calls: BTreeSet<ExtCall>,
    /// Ordered CFG nodes (for state-effect analysis).
    pub cfg_nodes: Vec<CfgNode>,
}

/// Walk a function body and collect all analysis results in one pass.
#[must_use]
pub(crate) fn walk_function(func: &ContractFunction<'_>) -> FnWalk {
    let mut acc = FnWalk::default();
    if let Some(body) = func.body {
        walk_stmts(body, &mut acc);
    }
    acc
}

/// Walk a bare statement slice and collect all analysis results in one pass.
///
/// Equivalent to [`walk_function`] but operates on a statement slice directly —
/// used by SAFETY-004 to analyse loop bodies independently from their
/// enclosing function (back-edge detection).
#[must_use]
pub(crate) fn walk_stmts_fn_walk(stmts: &[Stmt]) -> FnWalk {
    let mut acc = FnWalk::default();
    walk_stmts(stmts, &mut acc);
    acc
}

// ─── Public analysis functions ────────────────────────────────────────────────

/// Build the intra-contract call graph for all functions in a contract.
///
/// Consumed by `dataflow::state_write_reachability` (4c) and by the
/// SAFETY-004 reentrancy rule (4d) for transitive-write detection.
#[must_use]
pub fn build_call_graph(contract: &TypedContract<'_>) -> CallGraph {
    contract
        .functions()
        .into_iter()
        .map(|f| (f.name.to_owned(), walk_function(&f).internal_calls))
        .collect()
}

/// Compute `Ext(f)` — all external call sites in function `f`.
#[must_use]
pub fn ext_calls(func: &ContractFunction<'_>) -> BTreeSet<ExtCall> {
    walk_function(func).ext_calls
}

/// Ordered CFG nodes for `f` — used by SAFETY-004 state-after-call analysis.
#[must_use]
pub fn cfg_nodes(func: &ContractFunction<'_>) -> Vec<CfgNode> {
    walk_function(func).cfg_nodes
}

// ─── Walk: statements ─────────────────────────────────────────────────────────

fn walk_stmts(stmts: &[Stmt], acc: &mut FnWalk) {
    for s in stmts {
        walk_stmt(s, acc);
    }
}

fn walk_stmt(stmt: &Stmt, acc: &mut FnWalk) {
    match stmt {
        Stmt::Let { expr, .. } => walk_expr(expr, acc),
        Stmt::Const(c) => walk_expr(&c.value, acc),
        Stmt::Assign {
            target,
            value,
            span,
            ..
        } => {
            if let Some(key) = state_write_key(target) {
                acc.cfg_nodes.push(CfgNode::StateWrite { key, span: *span });
            }
            walk_expr(target, acc);
            walk_expr(value, acc);
        }
        Stmt::Return(Some(e), _) => walk_expr(e, acc),
        Stmt::Emit { fields, .. } => {
            for (_, e) in fields {
                walk_expr(e, acc);
            }
        }
        Stmt::If {
            cond, then, else_, ..
        } => {
            walk_expr(cond, acc);
            walk_stmts(then, acc);
            for b in else_.iter() {
                walk_stmts(b, acc);
            }
        }
        Stmt::While { cond, body, .. } => {
            walk_expr(cond, acc);
            walk_stmts(body, acc);
        }
        Stmt::For { iter, body, .. } => {
            match iter {
                ForIter::Of(e) => walk_expr(e, acc),
                ForIter::In(start, _, end, _) => {
                    walk_expr(start, acc);
                    walk_expr(end, acc);
                }
            }
            walk_stmts(body, acc);
        }
        Stmt::Loop { body, .. } => walk_stmts(body, acc),
        Stmt::Match { expr, arms, .. } => {
            walk_expr(expr, acc);
            for arm in arms {
                if let Some(g) = &arm.guard {
                    walk_expr(g, acc);
                }
                match &arm.body {
                    MatchBody::Expr(e) => walk_expr(e, acc),
                    MatchBody::Block(stmts) => walk_stmts(stmts, acc),
                }
            }
        }
        Stmt::Try {
            body, catch_body, ..
        } => {
            walk_stmts(body, acc);
            walk_stmts(catch_body, acc);
        }
        Stmt::Unchecked(body, _) => walk_stmts(body, acc),
        Stmt::Assert { cond, msg, .. } => {
            walk_expr(cond, acc);
            if let Some(m) = msg {
                walk_expr(m, acc);
            }
        }
        Stmt::Revert { msg: Some(m), .. } => walk_expr(m, acc),
        Stmt::Expr(e, _) => walk_expr(e, acc),
        // Break / Continue / Return(None) / Placeholder carry no sub-expressions.
        _ => {}
    }
}

// ─── Walk: expressions ────────────────────────────────────────────────────────

fn walk_expr(expr: &Expr, acc: &mut FnWalk) {
    match expr {
        Expr::Call {
            callee,
            opts: _,
            args,
            span,
        } => {
            match callee.as_ref() {
                // self.method(…) — internal call
                Expr::Member(obj, method, _) if is_self(obj) => {
                    acc.internal_calls.insert(method.clone());
                    // Also emit an ordered InternalCall node so SAFETY-004 can
                    // detect reentrancy-via-indirection (call-then-state-writing-helper).
                    acc.cfg_nodes.push(CfgNode::InternalCall {
                        callee: method.clone(),
                        span: *span,
                    });
                }
                // External method call on another contract instance
                Expr::Member(obj, method, _) if !is_self(obj) => {
                    acc.ext_calls.insert(ExtCall {
                        callee_desc: format!("<external>.{method}"),
                        span: *span,
                    });
                    acc.cfg_nodes.push(CfgNode::ExternalCall { span: *span });
                }
                // Free function call — internal if name matches a fn in same contract
                Expr::Ident(name, _) => {
                    acc.internal_calls.insert(name.clone());
                    // Same ordered-node emit as for self.method() — see note above.
                    acc.cfg_nodes.push(CfgNode::InternalCall {
                        callee: name.clone(),
                        span: *span,
                    });
                }
                _ => {}
            }
            walk_expr(callee, acc);
            for arg in args {
                let e = match arg {
                    CallArg::Positional(e) | CallArg::Named(_, e) => e,
                };
                walk_expr(e, acc);
            }
        }
        Expr::New { args, span, .. } => {
            // new Contract(…) — deployment leaves current contract context.
            acc.ext_calls.insert(ExtCall {
                callee_desc: "new <Contract>".to_owned(),
                span: *span,
            });
            acc.cfg_nodes.push(CfgNode::ExternalCall { span: *span });
            for arg in args {
                let e = match arg {
                    CallArg::Positional(e) | CallArg::Named(_, e) => e,
                };
                walk_expr(e, acc);
            }
        }
        // State write in expression-assignment form: self.field = …
        Expr::Assign_(target, _, val, span) => {
            if let Some(key) = state_write_key(target) {
                acc.cfg_nodes.push(CfgNode::StateWrite { key, span: *span });
            }
            walk_expr(target, acc);
            walk_expr(val, acc);
        }
        Expr::Member(base, _, _) => walk_expr(base, acc),
        Expr::Index(base, idx, _) => {
            walk_expr(base, acc);
            walk_expr(idx, acc);
        }
        Expr::Unary(_, inner, _) | Expr::Try_(inner, _) => walk_expr(inner, acc),
        Expr::Binary(_, l, r, _) => {
            walk_expr(l, acc);
            walk_expr(r, acc);
        }
        Expr::Ternary {
            cond, then, else_, ..
        } => {
            walk_expr(cond, acc);
            walk_expr(then, acc);
            walk_expr(else_, acc);
        }
        Expr::Nullish(l, r, _) => {
            walk_expr(l, acc);
            walk_expr(r, acc);
        }
        Expr::Cast { expr, .. } => walk_expr(expr, acc),
        Expr::If_ {
            cond, then, else_, ..
        } => {
            walk_expr(cond, acc);
            walk_stmts(then, acc);
            for b in else_.iter() {
                walk_stmts(b, acc);
            }
        }
        Expr::Match_(expr, arms, _) => {
            walk_expr(expr, acc);
            for arm in arms {
                if let Some(g) = &arm.guard {
                    walk_expr(g, acc);
                }
                match &arm.body {
                    MatchBody::Expr(e) => walk_expr(e, acc),
                    MatchBody::Block(stmts) => walk_stmts(stmts, acc),
                }
            }
        }
        // Literal / Ident / Tuple / Array / Struct_ / Lambda / Template:
        // no sub-calls or state writes to collect.
        _ => {}
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` if the expression is the identifier `self`.
fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

/// If `expr` is a state-write target (`self.field` or `self.map[k]`), return
/// the field/map name; otherwise return `None`.
fn state_write_key(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Member(obj, field, _) if is_self(obj) => Some(field.clone()),
        Expr::Index(base, _, _) => {
            if let Expr::Member(obj, field, _) = base.as_ref() {
                if is_self(obj) {
                    return Some(field.clone());
                }
            }
            None
        }
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
