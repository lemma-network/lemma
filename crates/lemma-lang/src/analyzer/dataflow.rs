//! Dataflow analyses: taint propagation and state-write reachability.
//!
//! Both analyses consume the pre-computed call graph from [`super::cfg`];
//! neither rebuilds the call graph internally (AGENTS §2 DRY).
//!
//! ## Analyses
//!
//! - **[`taint_propagate`]**: for each function, the set of locally-named
//!   variables that carry untrusted (tainted) values.  Consumed by rules that
//!   check whether external input reaches a sensitive operation without a
//!   dominating guard (SAFETY-002/003/005).
//!
//! - **[`state_write_reachability`]**: for each `state {}` field, the set of
//!   function names that can transitively write to it.  Consumed by SAFETY-003
//!   (totalSupply mint sites), SAFETY-002 (fee-rate field writers), and
//!   SAFETY-005/009 (restriction-flag writers).
//!
//! - **[`restriction_fields`]**: the set of `state {}` fields read on a transfer
//!   path to **deny** a transfer (`assert`/`if-revert` gating conditions).  The
//!   "restriction link" of spec §6.  Consumed by SAFETY-005 (blacklist
//!   governance): a field read to deny + written with a parameter key must be
//!   GOVERNANCE-gated.
//!
//! ## Sharing with Step 5
//!
//! Both analyses are `pub(crate)` and reused by the state-access analyzer
//! (P3·Step 5) as specified in 09-SAFETY_ANALYZER_SPEC §6.
//!
//! ## Usage
//!
//! ```ignore
//! let cg    = build_call_graph(&contract);
//! let taint = taint_propagate(&contract, &cg);
//! let reach = state_write_reachability(&contract, &cg);
//! ```
// ── Justified `dead_code` (entire module): all pub(crate) APIs are called by
// the SAFETY-rule modules (4d–4f) and the state-access analyzer (Step 5).
// No production caller outside tests is wired until 4d ships.
// Remove this allow once 4d lands.
#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::parser::{Expr, ForIter, MatchBody, Pattern, Stmt};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_stmt, Visitor};

use super::cfg::{walk_function, CallGraph, CfgNode};
use super::util::{block_contains_revert, is_self};

// ─── TaintOrigin / TaintedVar ────────────────────────────────────────────────

/// How a variable acquired taint (untrusted data).
///
/// `Ord` is derived for deterministic `BTreeSet` iteration (AGENTS §7.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TaintOrigin {
    /// Function parameter — any caller could be untrusted.
    Param,
    /// Bound directly to the return value of an external call.
    ExternalCallReturn,
}

/// A named variable in a function that carries tainted (potentially
/// attacker-controlled) data.
///
/// `Ord` derives lexicographically on `(name, origin)` — deterministic per
/// AGENTS §7.1.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TaintedVar {
    /// Variable or parameter name.
    pub(crate) name: String,
    /// How this variable acquired taint.
    pub(crate) origin: TaintOrigin,
}

impl TaintedVar {
    /// Convenience ctor: parameter taint.
    pub(crate) fn param(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            origin: TaintOrigin::Param,
        }
    }
    /// Convenience ctor: external-call-return taint.
    pub(crate) fn ext_return(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            origin: TaintOrigin::ExternalCallReturn,
        }
    }
}

// ─── taint_propagate ─────────────────────────────────────────────────────────

/// Compute the taint set for every function in a contract.
///
/// **Taint sources** (per-function seeds):
/// 1. All function parameters — any caller could be untrusted.
/// 2. `let`-bound locals whose RHS is a direct external call:
///    `let x = ext.method(…)` → `x` acquires `ExternalCallReturn` taint.
///
/// **Seed coverage note (flow-insensitive model):** `for`-loop pattern
/// bindings (e.g. `for x of ext.call() { … }`), `catch` variables, and
/// re-assignment of ext-call results (`x = ext.call()` after `let x = 0`)
/// are **not** seeded in this foundational layer.  Rule modules 4d–4f add
/// the precision they need; SEED gaps are tracked in `living-notes.md`.
///
/// **Cross-function propagation** (conservative over-approximation):
/// If A calls internal function B and A has any tainted variables, all of B's
/// parameters are marked tainted (a tainted value *could* be passed as any
/// argument).  Taint sets grow monotonically over a finite variable universe,
/// so the worklist fixpoint always terminates — including on cyclic call graphs
/// (mutual recursion, self-recursion).
///
/// Pre-condition: `call_graph` must be built with
/// [`super::cfg::build_call_graph`].
#[must_use]
pub(crate) fn taint_propagate(
    contract: &TypedContract<'_>,
    call_graph: &CallGraph,
) -> BTreeMap<String, BTreeSet<TaintedVar>> {
    // Phase 1: per-function seeds (params + let=ext-call bindings).
    let mut result: BTreeMap<String, BTreeSet<TaintedVar>> = contract
        .functions()
        .into_iter()
        .map(|f| (f.name.to_owned(), taint_seeds(&f)))
        .collect();

    // Param-name table for cross-function propagation.
    let param_names: BTreeMap<String, Vec<String>> = contract
        .functions()
        .into_iter()
        .map(|f| {
            let names: Vec<String> = f.params.iter().map(|p| p.name.clone()).collect();
            (f.name.to_owned(), names)
        })
        .collect();

    // Phase 2: fixpoint — seed worklist with functions that have tainted locals.
    let mut worklist: VecDeque<String> = result
        .iter()
        .filter(|(_, t)| !t.is_empty())
        .map(|(n, _)| n.clone())
        .collect();

    while let Some(caller) = worklist.pop_front() {
        if result.get(&caller).is_none_or(BTreeSet::is_empty) {
            continue;
        }
        let Some(callees) = call_graph.get(&caller) else {
            continue;
        };
        for callee in callees {
            let Some(params) = param_names.get(callee) else {
                continue;
            };
            let entry = result.entry(callee.clone()).or_default();
            let before = entry.len();
            for p in params {
                entry.insert(TaintedVar::param(p.as_str()));
            }
            if entry.len() > before {
                worklist.push_back(callee.clone());
            }
        }
    }

    result
}

// ─── state_write_reachability ─────────────────────────────────────────────────

/// Compute which functions can transitively write each `state {}` field.
///
/// Returns `BTreeMap<field_name, BTreeSet<function_name>>`:
/// - **Direct**: `self.field = …` / `self.field[k] = …` extracted from the CFG
///   via [`walk_function`] (one pass per function; no separate re-walk).
/// - **Transitive**: if A calls B (internal) and B writes field F, A is also in
///   F's writer set — closed via a fixpoint (changed flag; terminates because
///   write sets grow monotonically over the finite declared-field universe).
///
/// Pre-condition: `call_graph` must be built with
/// [`super::cfg::build_call_graph`].
#[must_use]
pub(crate) fn state_write_reachability(
    contract: &TypedContract<'_>,
    call_graph: &CallGraph,
) -> BTreeMap<String, BTreeSet<String>> {
    // Step 1: direct writes per function.
    let direct: BTreeMap<String, BTreeSet<String>> = contract
        .functions()
        .into_iter()
        .map(|f| (f.name.to_owned(), direct_state_writes(&f)))
        .collect();

    // Step 2: transitive closure over internal call edges.
    let fn_writes = transitive_writes(direct, call_graph);

    // Step 3: invert — field → {fns that can reach a write to it}.
    let mut result: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (fn_name, fields) in &fn_writes {
        for field in fields {
            result
                .entry(field.clone())
                .or_default()
                .insert(fn_name.clone());
        }
    }
    result
}

// ─── restriction_fields ───────────────────────────────────────────────────────

/// Compute the set of `state {}` field names that are read on a **transfer
/// path** in a position that gates a transfer **denial** (a `revert`/`assert`).
///
/// This is the "restriction link" analysis (spec §6, `dataflow.rs` —
/// "restriction links") consumed by **SAFETY-005** (blacklist governance): a
/// state field read to deny a transfer is a *restriction field*; SAFETY-005
/// then checks that every function which writes such a field with a
/// parameter-specified key is GOVERNANCE-gated, not `@onlyOwner`.
///
/// ## Transfer path (entry surface)
///
/// A function is on the transfer path if it is named `transfer` /
/// `transferFrom`, or is annotated `#[onTransfer]` / `@onTransfer`.  (Functions
/// transitively reachable from these are covered by the writer/CFG analyses in
/// the consuming rule; this analysis identifies the *fields read to deny*,
/// which the spec locates on the transfer entry itself.)
///
/// ## Denial position (what counts as "read to deny")
///
/// Lem has no `require`; a denial is expressed as either:
/// - `assert(<cond reading self.field>)` — [`Stmt::Assert`], or
/// - `if (<cond reading self.field>) { … revert … }` — an [`Stmt::If`] whose
///   `then`/`else` body contains a [`Stmt::Revert`].
///
/// A `self.<field>` or `self.<field>[key]` read anywhere inside such a gating
/// condition marks `<field>` as a restriction field.
///
/// ## Soundness
///
/// Over-approximation in the **detection** direction (any field read in a
/// gating condition is flagged) — sound for SAFETY-005, which rejects on a
/// flagged field being owner-settable.  A blacklist hidden behind a non-`assert`
/// / non-`if-revert` denial (e.g. an external checker) is out of scope here and
/// is forced into the open by SAFETY-010 instead.
#[must_use]
pub(crate) fn restriction_fields(contract: &TypedContract<'_>) -> BTreeSet<String> {
    let mut fields = BTreeSet::new();
    for func in contract.functions() {
        if !is_transfer_path_fn(&func) {
            continue;
        }
        let Some(body) = func.body else {
            continue;
        };
        let mut scanner = DenialFieldScanner {
            fields: &mut fields,
        };
        scanner.visit_stmts(body);
    }
    fields
}

/// Returns `true` if `func` is a transfer-path entry (`transfer`/`transferFrom`
/// by name, or annotated `#[onTransfer]`).
fn is_transfer_path_fn(func: &ContractFunction<'_>) -> bool {
    func.name == "transfer"
        || func.name == "transferFrom"
        || func.annotations.iter().any(|a| a.name == "onTransfer")
}

/// Visitor that records `self.<field>` reads occurring inside transfer-denial
/// conditions (`assert` conditions, and `if` conditions whose branch reverts).
struct DenialFieldScanner<'a> {
    fields: &'a mut BTreeSet<String>,
}

impl Visitor for DenialFieldScanner<'_> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            // `assert(<cond>)` — every self.field read in <cond> gates a denial.
            Stmt::Assert { cond, .. } => {
                collect_self_field_reads(cond, self.fields);
            }
            // `if (<cond>) { … revert … }` / `else { … revert … }` — if either
            // branch can revert, the condition's self.field reads gate a denial.
            Stmt::If {
                cond, then, else_, ..
            } => {
                let then_reverts = block_contains_revert(then);
                let else_reverts = else_.as_ref().is_some_and(|b| block_contains_revert(b));
                if then_reverts || else_reverts {
                    collect_self_field_reads(cond, self.fields);
                }
            }
            _ => {}
        }
        // Continue canonical recursion (nested control flow, expression bodies).
        walk_stmt(self, stmt);
    }
}

/// Collect the field names of every `self.<field>` / `self.<field>[key]` read
/// in `expr` into `out`.
fn collect_self_field_reads(expr: &Expr, out: &mut BTreeSet<String>) {
    match expr {
        // self.field
        Expr::Member(obj, field, _) if is_self(obj) => {
            out.insert(field.clone());
        }
        // self.field[key] — the base is Member(self, field); also recurse key.
        Expr::Index(base, idx, _) => {
            if let Expr::Member(obj, field, _) = base.as_ref() {
                if is_self(obj) {
                    out.insert(field.clone());
                }
            }
            collect_self_field_reads(base, out);
            collect_self_field_reads(idx, out);
        }
        Expr::Member(base, _, _) => collect_self_field_reads(base, out),
        Expr::Unary(_, inner, _) | Expr::Try_(inner, _) | Expr::Cast { expr: inner, .. } => {
            collect_self_field_reads(inner, out);
        }
        Expr::Binary(_, l, r, _) | Expr::Nullish(l, r, _) => {
            collect_self_field_reads(l, out);
            collect_self_field_reads(r, out);
        }
        Expr::Ternary {
            cond, then, else_, ..
        } => {
            collect_self_field_reads(cond, out);
            collect_self_field_reads(then, out);
            collect_self_field_reads(else_, out);
        }
        Expr::Call { callee, args, .. } => {
            collect_self_field_reads(callee, out);
            for arg in args {
                let e = match arg {
                    crate::parser::CallArg::Positional(e) | crate::parser::CallArg::Named(_, e) => {
                        e
                    }
                };
                collect_self_field_reads(e, out);
            }
        }
        // Literals, Ident, and other forms carry no self.field read of interest.
        _ => {}
    }
}

// ─── Private helpers ─────────────────────────────────────────────────────────

/// Per-function taint seeds: all params + `let x = ext.call()` bindings.
fn taint_seeds(func: &ContractFunction<'_>) -> BTreeSet<TaintedVar> {
    let mut seeds = BTreeSet::new();
    for p in func.params {
        seeds.insert(TaintedVar::param(p.name.as_str()));
    }
    if let Some(body) = func.body {
        collect_ext_bindings(body, &mut seeds);
    }
    seeds
}

/// Walk `stmts` and add `let x = ext.call()` names as `ExternalCallReturn`-tainted.
fn collect_ext_bindings(stmts: &[Stmt], out: &mut BTreeSet<TaintedVar>) {
    for stmt in stmts {
        match stmt {
            Stmt::Let { pattern, expr, .. } => {
                if is_ext_call(expr) {
                    collect_pattern_idents(pattern, out);
                }
                collect_ext_bindings_in_expr(expr, out);
            }
            Stmt::If {
                cond, then, else_, ..
            } => {
                collect_ext_bindings_in_expr(cond, out);
                collect_ext_bindings(then, out);
                if let Some(b) = else_ {
                    collect_ext_bindings(b, out);
                }
            }
            Stmt::While { cond, body, .. } => {
                collect_ext_bindings_in_expr(cond, out);
                collect_ext_bindings(body, out);
            }
            Stmt::For { iter, body, .. } => {
                match iter {
                    ForIter::Of(e) => collect_ext_bindings_in_expr(e, out),
                    ForIter::In(s, _, e, _) => {
                        collect_ext_bindings_in_expr(s, out);
                        collect_ext_bindings_in_expr(e, out);
                    }
                }
                collect_ext_bindings(body, out);
            }
            Stmt::Loop { body, .. } => collect_ext_bindings(body, out),
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    match &arm.body {
                        MatchBody::Block(stmts) => collect_ext_bindings(stmts, out),
                        MatchBody::Expr(e) => collect_ext_bindings_in_expr(e, out),
                    }
                }
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                collect_ext_bindings(body, out);
                collect_ext_bindings(catch_body, out);
            }
            Stmt::Unchecked(body, _) => collect_ext_bindings(body, out),
            Stmt::Expr(e, _) => collect_ext_bindings_in_expr(e, out),
            // Return/Break/Continue/Emit/Assert/Revert/Const/Assign/Placeholder:
            // none introduce let-bindings of ext-call results.
            _ => {}
        }
    }
}

/// Recurse into expression-level statement blocks (`if_`, `match_` expressions).
///
/// Only `Expr::If_` and `Expr::Match_` carry embedded statement lists where
/// let-bindings can appear; all other expressions are leaves here.
fn collect_ext_bindings_in_expr(expr: &Expr, out: &mut BTreeSet<TaintedVar>) {
    match expr {
        Expr::If_ {
            cond, then, else_, ..
        } => {
            collect_ext_bindings_in_expr(cond, out);
            collect_ext_bindings(then, out);
            if let Some(b) = else_ {
                collect_ext_bindings(b, out);
            }
        }
        Expr::Match_(e, arms, _) => {
            collect_ext_bindings_in_expr(e, out);
            for arm in arms {
                match &arm.body {
                    MatchBody::Block(stmts) => collect_ext_bindings(stmts, out),
                    MatchBody::Expr(e2) => collect_ext_bindings_in_expr(e2, out),
                }
            }
        }
        _ => {}
    }
}

/// Returns `true` if `expr` is a method call on a non-`self` receiver or a
/// `new <Contract>(…)` deployment — i.e., a call that leaves the contract.
fn is_ext_call(expr: &Expr) -> bool {
    match expr {
        Expr::Call { callee, .. } => matches!(
            callee.as_ref(),
            Expr::Member(obj, _, _)
                if !matches!(obj.as_ref(), Expr::Ident(n, _) if n == "self")
        ),
        Expr::New { .. } => true,
        _ => false,
    }
}

/// Collect all `Pattern::Ident` leaves into `out` as `ExternalCallReturn`-tainted.
///
/// Handles nested patterns (tuple, struct, enum variant) recursively.
/// `Wildcard`, `Literal`, and `Rest` patterns bind nothing.
fn collect_pattern_idents(pattern: &Pattern, out: &mut BTreeSet<TaintedVar>) {
    match pattern {
        Pattern::Ident(name, _) => {
            out.insert(TaintedVar::ext_return(name.as_str()));
        }
        Pattern::Tuple(pats, _) => {
            for p in pats {
                collect_pattern_idents(p, out);
            }
        }
        Pattern::Struct_ { fields, .. } => {
            for (_, p) in fields {
                collect_pattern_idents(p, out);
            }
        }
        Pattern::EnumVariant {
            inner: Some(pats), ..
        } => {
            for p in pats {
                collect_pattern_idents(p, out);
            }
        }
        // Wildcard(_), Literal(..), Rest(_), EnumVariant(None): bind nothing.
        _ => {}
    }
}

/// Collect the set of state fields directly written by `func` using one CFG
/// walk via [`walk_function`] (AGENTS §2 DRY — no separate re-walk).
fn direct_state_writes(func: &ContractFunction<'_>) -> BTreeSet<String> {
    walk_function(func)
        .cfg_nodes
        .into_iter()
        .filter_map(|n| match n {
            CfgNode::StateWrite { key, .. } => Some(key),
            _ => None,
        })
        .collect()
}

/// Transitive closure: for each call edge A → B, propagate B's write set into A.
///
/// Terminates because write sets grow monotonically over the finite `state {}`
/// field universe.  Self-recursion (A → A) converges in one iteration.
fn transitive_writes(
    mut fn_writes: BTreeMap<String, BTreeSet<String>>,
    call_graph: &CallGraph,
) -> BTreeMap<String, BTreeSet<String>> {
    let mut changed = true;
    while changed {
        changed = false;
        for (fn_name, callees) in call_graph {
            for callee in callees {
                let callee_w = fn_writes.get(callee).cloned().unwrap_or_default();
                if callee_w.is_empty() {
                    continue;
                }
                let caller_w = fn_writes.entry(fn_name.clone()).or_default();
                let before = caller_w.len();
                caller_w.extend(callee_w);
                if caller_w.len() > before {
                    changed = true;
                }
            }
        }
    }
    fn_writes
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
