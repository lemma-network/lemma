//! SAFETY-004 — State-Before-Call (Reentrancy) rule.
//!
//! Detects CEI (checks-effects-interactions) violations: any control-flow path
//! through a function where a state mutation occurs *after* an external call.
//!
//! ## What counts as a state mutation
//!
//! - A direct `StateWrite` CFG node in the function body.
//! - An `InternalCall` node to a callee that *transitively* writes state
//!   (via `dataflow::state_write_reachability` — the foundation from 4c).
//!   Closing the "one-hop helper" evasion: `ext.call(); self.applyDebit(amount)`
//!   is a violation even though `applyDebit`'s write doesn't appear in the
//!   caller's direct CFG nodes.
//!
//! ## Loop back-edge detection
//!
//! A loop body that contains **both** an external call **and** any state mutation
//! (in any order within the body) is flagged as a violation. The back-edge of
//! the loop always creates a write-after-call path across iterations, even if
//! within one iteration the write precedes the call.
//!
//! ## No `@nonReentrant` exemption
//!
//! CEI ordering is required unconditionally — `@nonReentrant` does not exempt.
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-004`.

use std::collections::BTreeSet;

use crate::analyzer::cfg::{self, CfgNode};
use crate::analyzer::dataflow::state_write_reachability;
use crate::analyzer::error::SafetyError;
use crate::lexer::token::Span;
use crate::parser::{MatchBody, Stmt};
use crate::type_checker::typed_contract::TypedContract;

/// Check a contract for SAFETY-004 reentrancy violations.
///
/// Returns one [`SafetyError::StateAfterCall`] per violating function (the
/// first violation per function — one is enough to reject it). Returns an
/// empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // Build transitive state-write reachability once for the whole contract.
    // This identifies every function that can, directly or transitively, write
    // any state field — the foundation for detecting reentrancy-via-indirection.
    let call_graph = cfg::build_call_graph(contract);
    let write_reach = state_write_reachability(contract, &call_graph);
    // Union of all function names that reach a state write by any path.
    let transitive_writers: BTreeSet<String> = write_reach.values().flatten().cloned().collect();

    for func in contract.functions() {
        // (a) Loop back-edge check: any loop body that contains both an external
        //     call and a state mutation is a reentrancy risk regardless of
        //     ordering within one iteration (the back-edge creates the violation).
        if let Some(body) = func.body {
            if let Some(call_site) = loop_reentrancy_call_site(body, &transitive_writers) {
                violations.push(SafetyError::StateAfterCall {
                    func: func.name.to_owned(),
                    call_site,
                });
                continue; // one violation per function is sufficient
            }
        }

        // (b) Linear scan over the ordered CFG node sequence.
        //     After an ExternalCall, any StateWrite or InternalCall to a
        //     transitive state-writing callee is a CEI violation.
        let nodes = cfg::cfg_nodes(&func);
        let mut first_ext_call: Option<Span> = None;

        'scan: for node in &nodes {
            match node {
                CfgNode::ExternalCall { span } => {
                    // Record the first external call site.
                    if first_ext_call.is_none() {
                        first_ext_call = Some(*span);
                    }
                }
                CfgNode::StateWrite { .. } => {
                    if let Some(call_site) = first_ext_call {
                        violations.push(SafetyError::StateAfterCall {
                            func: func.name.to_owned(),
                            call_site,
                        });
                        break 'scan;
                    }
                }
                CfgNode::InternalCall { callee, .. } => {
                    if let Some(call_site) = first_ext_call {
                        if transitive_writers.contains(callee.as_str()) {
                            // Callee transitively writes state — CEI violation
                            // via one level of indirection.
                            violations.push(SafetyError::StateAfterCall {
                                func: func.name.to_owned(),
                                call_site,
                            });
                            break 'scan;
                        }
                    }
                }
            }
        }
    }

    violations
}

// ─── Loop back-edge helpers ───────────────────────────────────────────────────

/// Scan `stmts` for any loop body that contains both an external call and a
/// state mutation (direct write or call to a state-writing function).
///
/// Returns the external-call [`Span`] from the first such loop found, or
/// `None` if the statements contain no such loop.
///
/// Recurses into non-loop control-flow (`if`/`match`/`try`/`unchecked`) to
/// catch loops nested inside other constructs.
fn loop_reentrancy_call_site(
    stmts: &[Stmt],
    transitive_writers: &BTreeSet<String>,
) -> Option<Span> {
    for stmt in stmts {
        match stmt {
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                // Check whether this loop body has both an external call and a
                // state mutation in any ordering (back-edge creates violation).
                if let Some(s) = loop_body_violation_span(body, transitive_writers) {
                    return Some(s);
                }
                // Recurse into the loop body for nested loops.
                if let Some(s) = loop_reentrancy_call_site(body, transitive_writers) {
                    return Some(s);
                }
            }
            // Recurse into non-loop control-flow to find nested loops.
            Stmt::If { then, else_, .. } => {
                if let Some(s) = loop_reentrancy_call_site(then, transitive_writers) {
                    return Some(s);
                }
                for b in else_.iter() {
                    if let Some(s) = loop_reentrancy_call_site(b, transitive_writers) {
                        return Some(s);
                    }
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let MatchBody::Block(body) = &arm.body {
                        if let Some(s) = loop_reentrancy_call_site(body, transitive_writers) {
                            return Some(s);
                        }
                    }
                }
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                if let Some(s) = loop_reentrancy_call_site(body, transitive_writers) {
                    return Some(s);
                }
                if let Some(s) = loop_reentrancy_call_site(catch_body, transitive_writers) {
                    return Some(s);
                }
            }
            Stmt::Unchecked(body, _) => {
                if let Some(s) = loop_reentrancy_call_site(body, transitive_writers) {
                    return Some(s);
                }
            }
            _ => {}
        }
    }
    None
}

/// Walk `body` (a loop body) and return the external-call span if the body
/// contains both an external call and a state mutation in any order.
///
/// Uses [`cfg::walk_stmts_fn_walk`] for a single, DRY traversal.
fn loop_body_violation_span(body: &[Stmt], transitive_writers: &BTreeSet<String>) -> Option<Span> {
    let walk = cfg::walk_stmts_fn_walk(body);

    // Find the first external call span in the loop body.
    let call_site = walk.cfg_nodes.iter().find_map(|n| match n {
        CfgNode::ExternalCall { span } => Some(*span),
        _ => None,
    })?;

    // Check whether the loop body also contains any state mutation.
    let has_mutation = walk.cfg_nodes.iter().any(|n| match n {
        CfgNode::StateWrite { .. } => true,
        CfgNode::InternalCall { callee, .. } => transitive_writers.contains(callee.as_str()),
        CfgNode::ExternalCall { .. } => false,
    });

    if has_mutation {
        Some(call_site)
    } else {
        None
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
