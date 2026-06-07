//! SAFETY-004 — State-Before-Call (Reentrancy) rule.
//!
//! Detects any function where a `StateWrite` CFG node is reachable after an
//! `ExternalCall` CFG node on any control-flow path (checks-effects-interactions
//! violation).
//!
//! **No `@nonReentrant` exemption** — CEI ordering is required unconditionally.
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-004`.

use crate::analyzer::cfg::{self, CfgNode};
use crate::analyzer::error::SafetyError;
use crate::type_checker::typed_contract::TypedContract;

/// Check a contract for SAFETY-004 reentrancy violations.
///
/// Returns one [`SafetyError::StateAfterCall`] per violating function (the
/// first violation found in each function — one is enough to reject it).
/// Returns an empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        let nodes = cfg::cfg_nodes(&func);
        let mut seen_ext_call = None;

        for node in &nodes {
            match node {
                CfgNode::ExternalCall { span } => {
                    // Record the first external call site seen.
                    if seen_ext_call.is_none() {
                        seen_ext_call = Some(*span);
                    }
                }
                CfgNode::StateWrite { .. } => {
                    if let Some(call_site) = seen_ext_call {
                        // State written after an external call — CEI violation.
                        violations.push(SafetyError::StateAfterCall {
                            func: func.name.to_owned(),
                            call_site,
                        });
                        // One violation per function is sufficient.
                        break;
                    }
                }
            }
        }
    }

    violations
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
