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
//! The traversal itself is provided by [`crate::visit::Visitor`] — `FnWalk`
//! implements it, overriding only the nodes that carry calls or state writes.
//!
//! ## What counts as an "external call"?
//!
//! Any call whose callee is **not** a `self` method (spec §2):
//! - `Expr::Call { callee: Member(non_self_obj, method) }` — method on another
//!   contract instance.
//! - `Expr::New { .. }` — contract deployment (leaves current context).

use std::collections::{BTreeMap, BTreeSet};

use crate::lexer::token::Span;
use crate::parser::{Expr, Stmt};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_expr, walk_stmt, Visitor};

use super::util::is_self;

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
///
/// Implements [`crate::visit::Visitor`]: only the nodes that carry calls or
/// state writes are intercepted; all structural recursion delegates to the
/// canonical [`walk_stmt`] / [`walk_expr`].
#[derive(Debug, Default)]
pub(crate) struct FnWalk {
    /// Internal callees (for call-graph edges).
    pub internal_calls: BTreeSet<String>,
    /// External call sites (for `Ext(f)`).
    pub ext_calls: BTreeSet<ExtCall>,
    /// Ordered CFG nodes (for state-effect analysis).
    pub cfg_nodes: Vec<CfgNode>,
}

impl Visitor for FnWalk {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        // Detect state writes via statement-level assignment.
        if let Stmt::Assign { target, span, .. } = stmt {
            if let Some(key) = state_write_key(target) {
                self.cfg_nodes
                    .push(CfgNode::StateWrite { key, span: *span });
            }
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Call { callee, span, .. } => {
                match callee.as_ref() {
                    // self.method(…) — internal call
                    Expr::Member(obj, method, _) if is_self(obj) => {
                        self.internal_calls.insert(method.clone());
                        // Emit an ordered InternalCall node so SAFETY-004 can
                        // detect reentrancy-via-indirection.
                        self.cfg_nodes.push(CfgNode::InternalCall {
                            callee: method.clone(),
                            span: *span,
                        });
                    }
                    // External method call on another contract instance.
                    Expr::Member(_, method, _) => {
                        self.ext_calls.insert(ExtCall {
                            callee_desc: format!("<external>.{method}"),
                            span: *span,
                        });
                        self.cfg_nodes.push(CfgNode::ExternalCall { span: *span });
                    }
                    // Free function call — treated as internal.
                    Expr::Ident(name, _) => {
                        self.internal_calls.insert(name.clone());
                        self.cfg_nodes.push(CfgNode::InternalCall {
                            callee: name.clone(),
                            span: *span,
                        });
                    }
                    _ => {}
                }
            }
            Expr::New { span, .. } => {
                // new Contract(…) — deployment leaves current contract context.
                self.ext_calls.insert(ExtCall {
                    callee_desc: "new <Contract>".to_owned(),
                    span: *span,
                });
                self.cfg_nodes.push(CfgNode::ExternalCall { span: *span });
            }
            // State write in expression-assignment form: self.field = …
            Expr::Assign_(target, _, _, span) => {
                if let Some(key) = state_write_key(target) {
                    self.cfg_nodes
                        .push(CfgNode::StateWrite { key, span: *span });
                }
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

// ─── Walk API (unchanged public surface) ─────────────────────────────────────

/// Walk a function body and collect all analysis results in one pass.
#[must_use]
pub(crate) fn walk_function(func: &ContractFunction<'_>) -> FnWalk {
    let mut acc = FnWalk::default();
    if let Some(body) = func.body {
        acc.visit_stmts(body);
    }
    acc
}

/// Walk a bare statement slice and collect all analysis results in one pass.
///
/// Equivalent to [`walk_function`] but operates on a statement slice directly —
/// used by SAFETY-004 to analyse loop bodies independently from their
/// enclosing function (back-edge detection).
#[must_use]
pub(crate) fn walk_stmts_fn_walk(stmts: &[crate::parser::Stmt]) -> FnWalk {
    let mut acc = FnWalk::default();
    acc.visit_stmts(stmts);
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

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
