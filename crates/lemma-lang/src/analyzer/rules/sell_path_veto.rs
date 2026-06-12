//! SAFETY-025 — Sell-Path External Veto rule.
//!
//! Prevents an external contract owner from having revert-veto power over token
//! sells.  If an external call on the sell/transfer path can revert, the external
//! contract's owner can block all sells by making their contract revert — a hidden
//! honeypot lever that SAFETY-001/009 cannot see (those only inspect internal levers).
//!
//! ## True property (spec §3-quinquies SAFETY-025)
//!
//! "The sell path may not block a transfer due to an external call reverting."
//!
//! ## Enforced (decidable over-approximation)
//!
//! Any external call on the sell path (`transfer` / `transferFrom` / `#[onTransfer]`
//! and their transitive callees) that is **not** wrapped in `try { … } catch { … }`
//! ⇒ reject (`SellPathExternalVeto`).  A try-wrapped call cannot propagate a revert
//! from the callee.
//!
//! External calls already forbidden by SAFETY-008 (hook external calls) are covered
//! there; SAFETY-025 covers the non-hook transfer path.
//!
//! ## Relationship to SAFETY-010
//!
//! SAFETY-010 requires such calls to be *declared* in `config {}`.
//! SAFETY-025 further requires they cannot have *revert veto*.
//! Both rules apply and complement each other.
//!
//! ## Detection boundary
//!
//! Uses `build_call_graph` + transitive closure to find all functions reachable
//! from the transfer path.  For each such function, scans the body for external
//! calls that are NOT inside a `Stmt::Try` body.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3-quinquies SAFETY-025`.

use std::collections::BTreeSet;

use crate::analyzer::cfg::{build_call_graph, ext_calls};
use crate::analyzer::error::SafetyError;
use crate::parser::Stmt;
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_stmt, Visitor};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-025 sell-path external-veto violations.
///
/// Returns one [`SafetyError::SellPathExternalVeto`] per transfer-path function
/// that makes an external call not wrapped in `try { … } catch { … }`.
/// Returns an empty `Vec` when safe.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // Build the intra-contract call graph once.
    let call_graph = build_call_graph(contract);

    // Seed: direct transfer-path entry functions.
    let transfer_entries: BTreeSet<String> = contract
        .functions()
        .into_iter()
        .filter(|f| is_transfer_path_fn(f.name, f.annotations))
        .map(|f| f.name.to_owned())
        .collect();

    // Expand to all transitive callees of the transfer path.
    let transfer_reachable = transitive_callees(&transfer_entries, &call_graph);

    for func in contract.functions() {
        if !transfer_reachable.contains(func.name) {
            continue;
        }

        // Skip if this function has no external calls at all — fast path.
        if ext_calls(&func).is_empty() {
            continue;
        }

        // Check whether every external call in this function is try-wrapped.
        let func_name = func.name.to_owned();
        if has_unwrapped_external_call(func) {
            violations.push(SafetyError::SellPathExternalVeto { func: func_name });
        }
    }

    violations
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` if `name` / `annotations` identify a transfer-path entry.
fn is_transfer_path_fn(name: &str, annotations: &[crate::parser::Annotation]) -> bool {
    name == "transfer"
        || name == "transferFrom"
        || annotations.iter().any(|a| a.name == "onTransfer")
}

/// Compute the transitive closure of `seed` over forward call edges.
///
/// Returns the set of all functions reachable from any seed function
/// (including the seeds themselves).
fn transitive_callees(
    seed: &BTreeSet<String>,
    call_graph: &std::collections::BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut reachable = seed.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for (caller, callees) in call_graph {
            if reachable.contains(caller) {
                for callee in callees {
                    if reachable.insert(callee.clone()) {
                        changed = true;
                    }
                }
            }
        }
    }
    reachable
}

/// Returns `true` if `func` contains at least one external call that is NOT
/// wrapped inside a `Stmt::Try` body.
///
/// Strategy: collect all external-call spans from `ext_calls`, then collect
/// all external-call spans that ARE inside a `Stmt::Try` body.  If any
/// external-call span is not in the try-wrapped set, the function is unsafe.
fn has_unwrapped_external_call(func: ContractFunction<'_>) -> bool {
    let Some(body) = func.body else {
        return false;
    };

    // Collect all external-call spans in the function.
    let all_ext = ext_calls(&func);
    if all_ext.is_empty() {
        return false;
    }

    // Collect spans of external calls that are inside a Stmt::Try body.
    let mut try_scanner = TryWrappedExtCallScanner {
        wrapped_spans: BTreeSet::new(),
    };
    try_scanner.visit_stmts(body);

    // If any external call span is NOT in the try-wrapped set → unwrapped call exists.
    all_ext
        .iter()
        .any(|ec| !try_scanner.wrapped_spans.contains(&ec.span))
}

// ─── Visitor ──────────────────────────────────────────────────────────────────

/// Visitor that collects the spans of all external calls that appear inside
/// the `body` of a `Stmt::Try` block (at any nesting depth within that body).
///
/// An external call is "try-wrapped" if it is reachable only through the `body`
/// of at least one enclosing `Stmt::Try`.  Calls in the `catch_body` are NOT
/// considered wrapped (the catch handler runs after the revert, not before).
struct TryWrappedExtCallScanner {
    /// Spans of external calls that are inside a try body.
    wrapped_spans: BTreeSet<crate::lexer::token::Span>,
}

impl Visitor for TryWrappedExtCallScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Try { body, .. } = stmt {
            // Collect all external-call spans inside this try body.
            let mut inner = TryBodyExtCallCollector {
                spans: BTreeSet::new(),
            };
            inner.visit_stmts(body);
            self.wrapped_spans.extend(inner.spans);
            // Do NOT recurse into catch_body — calls there are not "wrapped"
            // in the sense that they cannot prevent the original revert.
            // Do recurse into the try body for nested try blocks.
            for s in body {
                self.visit_stmt(s);
            }
        } else {
            walk_stmt(self, stmt);
        }
    }
}

/// Visitor that collects spans of all external calls in a statement slice.
///
/// Used by [`TryWrappedExtCallScanner`] to enumerate external calls inside a
/// try body.  Recurses into all nested control flow.
struct TryBodyExtCallCollector {
    spans: BTreeSet<crate::lexer::token::Span>,
}

impl Visitor for TryBodyExtCallCollector {
    fn visit_expr(&mut self, expr: &crate::parser::Expr) {
        use crate::analyzer::util::is_self;
        use crate::visit::walk_expr;

        match expr {
            crate::parser::Expr::Call { callee, span, .. } => {
                // External call: method call on a non-self receiver.
                if let crate::parser::Expr::Member(obj, _, _) = callee.as_ref() {
                    if !is_self(obj) {
                        self.spans.insert(*span);
                    }
                }
            }
            crate::parser::Expr::New { span, .. } => {
                // new Contract(…) — deployment leaves current contract context.
                self.spans.insert(*span);
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
