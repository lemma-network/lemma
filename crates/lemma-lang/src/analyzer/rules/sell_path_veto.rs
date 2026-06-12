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
//! External calls inside complex control flow (if/match/for/while/loop) that are
//! not try-wrapped → `Inconclusive` (spec §3-quinquies: "reject-on-doubt").
//! External calls at the top level of a function body that are not try-wrapped
//! → `SellPathExternalVeto`.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3-quinquies SAFETY-025`.

use std::collections::BTreeSet;

use crate::analyzer::cfg::{build_call_graph, ext_calls};
use crate::analyzer::error::SafetyError;
use crate::analyzer::util::is_transfer_path_entry;
use crate::lexer::token::Span;
use crate::parser::{MatchBody, Stmt};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_stmt, Visitor};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-025 sell-path external-veto violations.
///
/// Returns [`SafetyError::SellPathExternalVeto`] for each transfer-path function
/// that makes an unwrapped top-level external call, and
/// [`SafetyError::Inconclusive`] for external calls inside control flow that
/// cannot be statically proven try-wrapped.
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
        .filter(|f| is_transfer_path_entry(f))
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

        // Classify each unwrapped external call as a violation or Inconclusive.
        let func_name = func.name.to_owned();
        violations.extend(classify_unwrapped_calls(func, &func_name));
    }

    violations
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

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

/// Classify unwrapped external calls in `func` into violations and Inconclusive.
///
/// Strategy (M2 fix — uses `ext_calls()` as the canonical source of truth):
/// 1. Get all external-call spans via `ext_calls(&func)` (canonical detection).
/// 2. Walk the function body with [`ExtCallContextScanner`] to classify each
///    call span as: `Protected` (inside try body), `ControlFlow` (inside
///    if/match/for/while/loop but not try), or `TopLevel` (neither).
/// 3. For each external-call span:
///    - `Protected` → safe (skip).
///    - `ControlFlow` → `Inconclusive` (spec §3-quinquies reject-on-doubt).
///    - `TopLevel` → `SellPathExternalVeto`.
///
/// Emits at most one `Inconclusive` per function (one is sufficient to reject).
fn classify_unwrapped_calls(func: ContractFunction<'_>, func_name: &str) -> Vec<SafetyError> {
    let Some(body) = func.body else {
        return Vec::new();
    };

    // Canonical source of truth for external-call spans (M2: no re-detection).
    let all_ext = ext_calls(&func);
    if all_ext.is_empty() {
        return Vec::new();
    }

    // Walk the body to classify each call span by its context.
    let mut scanner = ExtCallContextScanner::default();
    scanner.visit_stmts(body);

    let mut violations = Vec::new();
    let mut emitted_inconclusive = false;

    for ec in &all_ext {
        if scanner.protected_spans.contains(&ec.span) {
            // Try-wrapped → safe.
            continue;
        }
        if scanner.control_flow_spans.contains(&ec.span) {
            // Inside control flow but not try-wrapped → Inconclusive.
            // Emit at most one per function (one is sufficient to reject).
            if !emitted_inconclusive {
                violations.push(SafetyError::Inconclusive {
                    rule: "SAFETY-025",
                    reason: format!(
                        "`{func_name}` has an external call inside control flow that \
                         cannot be statically proven try-wrapped — \
                         wrap in try/catch or move outside control flow"
                    ),
                    span: ec.span,
                });
                emitted_inconclusive = true;
            }
        } else {
            // Top-level unwrapped external call → definite violation.
            violations.push(SafetyError::SellPathExternalVeto {
                func: func_name.to_owned(),
            });
            // One SellPathExternalVeto per function is sufficient.
            break;
        }
    }

    violations
}

// ─── Visitor ──────────────────────────────────────────────────────────────────

/// Visitor that classifies call spans by their context within a function body.
///
/// Tracks two sets of spans:
/// - `protected_spans`: call spans inside a `Stmt::Try` body (try-wrapped).
/// - `control_flow_spans`: call spans inside if/match/for/while/loop but NOT
///   inside a try body.
///
/// The caller intersects these sets with `ext_calls()` spans to determine
/// which external calls are protected, which are in control flow, and which
/// are at the top level.
///
/// ## C1a fix
///
/// `Stmt::Try` catch bodies are NOT descended — calls in the catch handler are
/// not try-protected (the catch runs after the revert, not before).
///
/// ## M2 fix
///
/// Collects ALL call spans (not just external ones) — the caller intersects
/// with `ext_calls()` to determine which are external.  This removes the
/// duplication of external-call detection logic from this visitor.
#[derive(Default)]
struct ExtCallContextScanner {
    /// Spans of all call expressions inside try bodies (protected).
    protected_spans: BTreeSet<Span>,
    /// Spans of all call expressions inside control flow but not try bodies.
    control_flow_spans: BTreeSet<Span>,
    /// Whether we are currently inside a control-flow block (not a try body).
    inside_control_flow: bool,
}

impl Visitor for ExtCallContextScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            // Try block: collect all call spans from the try body into protected_spans.
            // C1a fix: do NOT recurse into catch_body — calls there are not protected.
            // Note: nested Stmt::Try inside the try body is handled by the recursive
            // visit_stmts call (which will again skip catch_body).
            Stmt::Try { body, .. } => {
                // Temporarily clear inside_control_flow for the try body —
                // calls inside a try body are protected regardless of outer context.
                let saved_cf = self.inside_control_flow;
                self.inside_control_flow = false;

                // Collect all call spans from the try body.
                let mut try_collector = TryBodyCallCollector {
                    spans: BTreeSet::new(),
                };
                try_collector.visit_stmts(body);
                self.protected_spans.extend(try_collector.spans);

                // Recurse into the try body for nested try/control-flow blocks.
                self.visit_stmts(body);

                self.inside_control_flow = saved_cf;
                // Do NOT recurse into catch_body (C1a fix).
            }

            // Control-flow statements: recurse with inside_control_flow = true.
            Stmt::If { then, else_, .. } => {
                let saved_cf = self.inside_control_flow;
                self.inside_control_flow = true;
                self.visit_stmts(then);
                for b in else_.iter() {
                    self.visit_stmts(b);
                }
                self.inside_control_flow = saved_cf;
            }
            Stmt::Match { arms, .. } => {
                let saved_cf = self.inside_control_flow;
                self.inside_control_flow = true;
                for arm in arms {
                    match &arm.body {
                        MatchBody::Block(stmts) => self.visit_stmts(stmts),
                        MatchBody::Expr(_) => {}
                    }
                }
                self.inside_control_flow = saved_cf;
            }
            Stmt::For { body, .. } | Stmt::While { body, .. } | Stmt::Loop { body, .. } => {
                let saved_cf = self.inside_control_flow;
                self.inside_control_flow = true;
                self.visit_stmts(body);
                self.inside_control_flow = saved_cf;
            }

            // All other statements: recurse normally.
            _ => walk_stmt(self, stmt),
        }
    }

    fn visit_expr(&mut self, expr: &crate::parser::Expr) {
        use crate::visit::walk_expr;
        // Collect call spans into the appropriate set based on current context.
        // The caller intersects with ext_calls() to filter to external calls only.
        // Top-level calls are neither protected nor control-flow —
        // they are identified by absence from both sets.
        match expr {
            crate::parser::Expr::Call { span, .. } | crate::parser::Expr::New { span, .. }
                if self.inside_control_flow =>
            {
                self.control_flow_spans.insert(*span);
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

/// Visitor that collects spans of ALL call expressions inside a statement slice.
///
/// Used by [`ExtCallContextScanner`] to enumerate call spans inside a try body.
///
/// **C1a fix**: overrides `visit_stmt` to skip `catch_body` of nested `Stmt::Try` —
/// calls in the catch handler are NOT try-protected.
///
/// **M2 fix**: collects ALL call spans (not just external ones) — the caller
/// intersects with `ext_calls()` to determine which are external.
struct TryBodyCallCollector {
    spans: BTreeSet<Span>,
}

impl Visitor for TryBodyCallCollector {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Try { body, .. } = stmt {
            // Recurse into the try body ONLY — not catch_body.
            // C1a: calls in catch_body are not "try-protected" against revert-veto.
            self.visit_stmts(body);
        } else {
            walk_stmt(self, stmt);
        }
    }

    fn visit_expr(&mut self, expr: &crate::parser::Expr) {
        use crate::visit::walk_expr;
        match expr {
            crate::parser::Expr::Call { span, .. } | crate::parser::Expr::New { span, .. } => {
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
