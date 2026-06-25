//! Dataflow analyses: state-write reachability and restriction-field detection.
//!
//! Both analyses consume the pre-computed call graph from [`super::cfg`];
//! neither rebuilds the call graph internally (AGENTS §2 DRY).
//!
//! ## Analyses
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
//! let reach = state_write_reachability(&contract, &cg);
//! let deny  = restriction_fields(&contract);
//! ```
//!
//! ## Deleted: taint_propagate (P3 audit subtask 10)
//!
//! The taint-propagation machinery (`TaintOrigin`, `TaintedVar`,
//! `taint_propagate` + helpers) was deleted as dead code (AGENTS §1.3).
//! Its consumer (SAFETY-012 value-taint narrowing — scope unchecked-arithmetic
//! to value-bearing fields) never materialized despite Steps 5/7 completing.
//! The current over-approximation in `rules/integer.rs` is SOUND (flags all
//! state fields, not just value-bearing ones — no false-accept).  If narrowing
//! is wanted later, assign a P4 Track·Step and rebuild from the spec.

use std::collections::{BTreeMap, BTreeSet};

use crate::parser::{Expr, Stmt};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_stmt, Visitor};

use super::cfg::{walk_function, CallGraph, CfgNode};
use super::util::{block_contains_revert, is_self, is_transfer_path_entry};

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
        if !is_transfer_path_entry(&func) {
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
