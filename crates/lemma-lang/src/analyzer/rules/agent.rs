//! SAFETY-014…019 — Agent-safety rules (Warden / Agent Layer).
//!
//! These six rules make *contracts* safe for agents to call, complementing
//! Warden which makes *accounts* safe at runtime.
//! See `docs/09-SAFETY_ANALYZER_SPEC §3-bis` for full definitions.
//!
//! ## Rule status (Batch 1 — P3·Step 11)
//!
//! | Rule | Status |
//! |------|--------|
//! | SAFETY-014 | ⬜ Stub — Batch 2 |
//! | SAFETY-015 | ✅ Implemented |
//! | SAFETY-016 | ✅ Implemented |
//! | SAFETY-017 | ⬜ Stub — Batch 2 |
//! | SAFETY-018 | ⬜ Stub — Batch 3 |
//! | SAFETY-019 | ⬜ Stub — Batch 3 |
//!
//! ## DRY note
//!
//! Each rule is a separate private function called from the public [`check`]
//! entry point. The `authset` module provides `auth_set` / `requires_owner_only`
//! for guard analysis (DRY — do not re-implement guard detection here).

use crate::analyzer::authset::{auth_set, requires_owner_only};
use crate::analyzer::error::SafetyError;
use crate::parser::Expr;
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_expr, Visitor};

// ── Policy-mutation function name patterns ────────────────────────────────────
//
// A function is a "policy-mutation" function if its name matches one of these
// patterns. This is a name-based heuristic (declaration-forcing): developers
// MUST use these canonical names for policy grant/revoke functions.
// The pattern list is exhaustive per the Warden design (14-AGENT_LAYER §4.1).
const POLICY_MUTATION_NAMES: &[&str] = &[
    "grantAgent",
    "revokeAgent",
    "updateAgentPolicy",
    "setAgentPolicy",
    "grantAgentPolicy",
    "extendAgentPolicy",
];

// ── Grant function name patterns (for SAFETY-016) ────────────────────────────
//
// A call is a "grant call" if the callee name matches one of these patterns.
// Same rationale as POLICY_MUTATION_NAMES.
const GRANT_CALL_NAMES: &[&str] = &["grantAgent", "grantAgentPolicy"];

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-014..019 agent-safety violations.
///
/// Returns all violations found. Returns an empty `Vec` if the contract is
/// clean or has no agent-annotated functions.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations: Vec<SafetyError> = Vec::new();

    // SAFETY-014 — agent-callable bounded effects (Batch 2).
    // violations.extend(check_014_agent_callable_bounded_effects(contract));

    // SAFETY-015 — policy-mutation owner-gating.
    violations.extend(check_015_policy_mutation_owner_gating(contract));

    // SAFETY-016 — no agent re-grant.
    violations.extend(check_016_no_agent_re_grant(contract));

    // SAFETY-017 — kill-switch honored (Batch 2).
    // violations.extend(check_017_kill_switch_honored(contract));

    // SAFETY-018 — co-sign threshold integrity (Batch 3).
    // violations.extend(check_018_cosign_threshold_integrity(contract));

    // SAFETY-019 — deterministic anomaly inputs (Batch 3).
    // violations.extend(check_019_deterministic_anomaly_inputs(contract));

    violations
}

// ─── SAFETY-015 — Policy-mutation owner-gating ────────────────────────────────

/// Check that every policy-mutation function (grantAgent, revokeAgent, etc.)
/// is gated by `@onlyOwner`.
///
/// A session-key-reachable path to a policy-mutation function allows an agent
/// to widen its own authority — the exact escalation SAFETY-015 prevents.
///
/// ## Detection
///
/// We use the `POLICY_MUTATION_NAMES` allow-list: a function whose name matches
/// any entry is treated as a policy-mutation function and must have `@onlyOwner`
/// (verified via `authset::requires_owner_only`).
///
/// ## Honest limit
///
/// Name-based detection misses policy mutations through non-standard names.
/// This is by design (declaration-forcing): contracts with non-standard policy
/// functions must be audited manually. Warden's runtime check provides the
/// defence-in-depth layer.
fn check_015_policy_mutation_owner_gating(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    contract
        .functions()
        .into_iter()
        .filter(|func| is_policy_mutation(func.name))
        .filter(|func| !requires_owner_only(&auth_set(func)))
        .map(|func| SafetyError::AgentPolicySelfEscalation {
            func: func.name.to_owned(),
        })
        .collect()
}

/// Returns `true` if `name` matches a canonical policy-mutation function name.
fn is_policy_mutation(name: &str) -> bool {
    POLICY_MUTATION_NAMES.contains(&name)
}

// ─── SAFETY-016 — No agent re-grant ───────────────────────────────────────────

/// Check that no `@agentCallable` function's body calls a grant function.
///
/// A session key reaching `grantAgent` (or equivalent) could create a new
/// agent with equal or greater authority — authority laundering through
/// nested agents (delegation chains), which SAFETY-016 prevents.
///
/// ## Detection
///
/// Walk the body of every `@agentCallable` function for call expressions where
/// the callee matches `GRANT_CALL_NAMES`. Uses the `GrantCallVisitor`.
fn check_016_no_agent_re_grant(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    contract
        .functions()
        .into_iter()
        .filter(|func| is_agent_callable(func))
        .flat_map(|func| {
            let mut visitor = GrantCallVisitor {
                caller: func.name.to_owned(),
                violations: Vec::new(),
            };
            if let Some(body) = func.body {
                visitor.visit_stmts(body);
            }
            visitor.violations
        })
        .collect()
}

/// Returns `true` if the function carries `@agentCallable` annotation.
fn is_agent_callable(func: &ContractFunction<'_>) -> bool {
    func.annotations
        .iter()
        .any(|ann| ann.name == "agentCallable")
}

// ─── Visitors ─────────────────────────────────────────────────────────────────

/// AST visitor that detects `grantAgent` (and equivalent) calls in a function body.
struct GrantCallVisitor {
    /// Name of the enclosing `@agentCallable` function.
    caller: String,
    /// Accumulated violations.
    violations: Vec<SafetyError>,
}

impl Visitor for GrantCallVisitor {
    fn visit_expr(&mut self, expr: &Expr) {
        // Detect `grantAgent(...)` and equivalent direct-call forms.
        // Call expressions in Lem:
        //   - `Expr::Call { callee: box Expr::Ident(name, _), .. }` for bare calls
        //   - `Expr::Call { callee: box Expr::Member(_, method, _), .. }` for method calls
        if let Expr::Call { callee, .. } = expr {
            if let Some(name) = extract_call_name(callee) {
                if GRANT_CALL_NAMES.contains(&name.as_str()) {
                    self.violations.push(SafetyError::AgentReGrant {
                        caller: self.caller.clone(),
                        callee: name,
                    });
                }
            }
        }
        walk_expr(self, expr);
    }
}

/// Extract the function/method name from a call callee expression.
///
/// Handles:
/// - `Expr::Ident(name, _)` → `Some(name.clone())`
/// - `Expr::Member(_, method, _)` → `Some(method.clone())`
/// - Other forms → `None`
fn extract_call_name(callee: &Expr) -> Option<String> {
    match callee {
        Expr::Ident(name, _) => Some(name.clone()),
        Expr::Member(_, method, _) => Some(method.clone()),
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
