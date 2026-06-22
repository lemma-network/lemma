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
//! | SAFETY-015 | 🔨 Reachability check via call graph |
//! | SAFETY-016 | 🔨 Reachability check via call graph |
//! | SAFETY-017 | ⬜ Stub — Batch 2 |
//! | SAFETY-018 | ⬜ Stub — Batch 3 |
//! | SAFETY-019 | ⬜ Stub — Batch 3 |
//!
//! SAFETY-015/016 use intra-contract call graph reachability (`cfg::build_call_graph`)
//! to catch transitive paths, not just direct-declaration checks. This matches the spec
//! requirement: "a session-key-reachable path to it ⇒ reject" (09-SAFETY_ANALYZER_SPEC
//! §3-bis SAFETY-015/016).
//!
//! ## DRY note
//!
//! Each rule is a separate private function called from the public [`check`]
//! entry point. The `authset` module provides `auth_set` / `requires_owner_only`
//! for guard analysis (DRY — do not re-implement guard detection here).

use std::collections::BTreeSet;

use crate::analyzer::authset::{auth_set, requires_owner_only};
use crate::analyzer::cfg::build_call_graph;
use crate::analyzer::error::SafetyError;
use crate::parser::Expr;
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_expr, Visitor};

// ── Policy-mutation function name patterns ────────────────────────────────────
//
// A function is a "policy-mutation" function if its name matches one of these
// patterns. This is a declaration-forcing heuristic: developers MUST use these
// canonical names for any function that creates, widens, or narrows an AgentPolicy.
//
// Completeness verified against 14-AGENT_LAYER:
//   §2.1 core grant/revoke  → grantAgent, revokeAgent
//   §2.1 top-up/adjust      → updateAgentPolicy, setAgentPolicy, extendAgentPolicy, grantAgentPolicy
//   §2.3 extension setters  → setRefillPerEpoch, setActiveWindow, setCosignThreshold,
//                             setAutoRevoke, updateCategories (all widen/adjust the policy)
//   §2.4 kill switch        → setAgentsPaused, pauseAgents, unpauseAgents (owner kill-switch)
//   §7   KYA tier           → setKyaTier, updateKyaTier (widening reputation gate)
//
// Non-canonical names are an honest limit: manually audited contracts accepted.
// Warden runtime provides defence-in-depth for missed names.
const POLICY_MUTATION_NAMES: &[&str] = &[
    // Core grant/revoke (§2.1)
    "grantAgent",
    "revokeAgent",
    "updateAgentPolicy",
    "setAgentPolicy",
    "grantAgentPolicy",
    "extendAgentPolicy",
    // Extension setters (§2.3) — all widen/adjust policy, must be owner-only
    "setRefillPerEpoch",
    "setActiveWindow",
    "setCosignThreshold",
    "setAutoRevoke",
    "updateCategories",
    // Kill switch (§2.4)
    "setAgentsPaused",
    "pauseAgents",
    "unpauseAgents",
    // KYA tier (§7)
    "setKyaTier",
    "updateKyaTier",
];

// ── Grant function name patterns (for SAFETY-016) ────────────────────────────
//
// A call is a "grant call" if the callee name matches one of these patterns.
// Subset of POLICY_MUTATION_NAMES: only those that CREATE a new agent grant
// (i.e. increase authority, not merely adjust or revoke).
const GRANT_CALL_NAMES: &[&str] = &["grantAgent", "grantAgentPolicy", "extendAgentPolicy"];

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

/// Check that no `@agentCallable` function can transitively reach a
/// policy-mutation function that is not owner-gated.
///
/// Spec requirement (09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-015):
/// > "a session-key-reachable path to it ⇒ reject"
///
/// ## Detection
///
/// 1. Build the intra-contract call graph.
/// 2. Collect all functions not gated by `@onlyOwner` that match
///    `POLICY_MUTATION_NAMES` — these are ungated policy-mutation functions.
/// 3. For each `@agentCallable` entry, compute its transitive callees.
/// 4. If any ungated policy-mutation function is in the transitive closure
///    → `AgentPolicySelfEscalation`.
///
/// ## `init` exclusion
///
/// `TypedContract::functions()` excludes `init` by design — init runs at
/// deploy time under the owner's key and is not reachable by session keys.
/// It is safe to exclude it here; no special handling is needed.
///
/// ## Honest limit
///
/// Name-based detection covers the canonical policy-mutation surface defined in
/// `POLICY_MUTATION_NAMES` (see §2.1/§2.3/§2.4/§7 of 14-AGENT_LAYER).
/// Non-canonical names escape static analysis — Warden runtime is the backstop.
fn check_015_policy_mutation_owner_gating(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let call_graph = build_call_graph(contract);

    // Collect all policy-mutation functions that are NOT owner-gated.
    let ungated_policy_fns: BTreeSet<String> = contract
        .functions()
        .into_iter()
        .filter(|func| is_policy_mutation(func.name))
        .filter(|func| !requires_owner_only(&auth_set(func)))
        .map(|func| func.name.to_owned())
        .collect();

    if ungated_policy_fns.is_empty() {
        return Vec::new();
    }

    // For each @agentCallable entry, check if any ungated policy-mutation
    // function is transitively reachable.
    let mut violations = Vec::new();
    for entry in contract.functions().into_iter().filter(|f| is_agent_callable(f)) {
        let reachable = transitive_callees(entry.name, &call_graph);
        for ungated in &ungated_policy_fns {
            if reachable.contains(ungated.as_str()) {
                violations.push(SafetyError::AgentPolicySelfEscalation {
                    func: ungated.clone(),
                });
            }
        }
    }

    // Also flag direct declarations: an ungated policy-mutation function is
    // itself dangerous even without a known @agentCallable entry leading to it
    // (another entry may be added later, and the function is already a liability).
    for ungated in &ungated_policy_fns {
        if !violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentPolicySelfEscalation { func } if func == ungated))
        {
            violations.push(SafetyError::AgentPolicySelfEscalation {
                func: ungated.clone(),
            });
        }
    }

    violations
}

/// Returns `true` if `name` matches a canonical policy-mutation function name.
fn is_policy_mutation(name: &str) -> bool {
    POLICY_MUTATION_NAMES.contains(&name)
}

// ─── SAFETY-016 — No agent re-grant ───────────────────────────────────────────

/// Check that no `@agentCallable` function can transitively reach a grant call.
///
/// Spec requirement (09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-016):
/// > "A `grantAgent`-class call reachable from a session-key path ⇒ reject."
///
/// ## Detection
///
/// 1. Build the intra-contract call graph.
/// 2. For each `@agentCallable` entry, compute its transitive callees.
/// 3. For each function in the transitive closure, walk its body for calls
///    matching `GRANT_CALL_NAMES` → `AgentReGrant { caller: entry, callee }`.
///
/// Walking bodies of ALL transitively reachable functions (not just the direct
/// body of the `@agentCallable` fn) catches one-hop and deeper indirections.
///
/// ## Lambda boundary note
///
/// The `Visitor` does not descend into lambda bodies (`walk_expr` skips them
/// per the documented visitor policy). A grant call inside a lambda inside an
/// `@agentCallable` function is not detected. This is an accepted limitation —
/// lambdas are independently scoped and Warden runtime guards the boundary.
fn check_016_no_agent_re_grant(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let call_graph = build_call_graph(contract);

    // Build a lookup: function name → ContractFunction
    let fn_map: std::collections::BTreeMap<&str, _> = contract
        .functions()
        .into_iter()
        .map(|f| (f.name, f))
        .collect();

    let mut violations = Vec::new();

    for entry in contract.functions().into_iter().filter(|f| is_agent_callable(f)) {
        // Include the entry itself + all transitively reachable functions.
        let mut to_check: BTreeSet<String> = transitive_callees(entry.name, &call_graph);
        to_check.insert(entry.name.to_owned());

        for fn_name in &to_check {
            if let Some(func) = fn_map.get(fn_name.as_str()) {
                let mut visitor = GrantCallVisitor {
                    caller: entry.name.to_owned(),
                    violations: Vec::new(),
                };
                if let Some(body) = func.body {
                    visitor.visit_stmts(body);
                }
                violations.extend(visitor.violations);
            }
        }
    }

    violations
}

/// Returns `true` if the function carries `@agentCallable` annotation.
fn is_agent_callable(func: &ContractFunction<'_>) -> bool {
    func.annotations
        .iter()
        .any(|ann| ann.name == "agentCallable")
}

// ─── Call-graph reachability ──────────────────────────────────────────────────

/// Compute the set of all function names transitively reachable from `start`
/// in the intra-contract call graph, **excluding `start` itself**.
///
/// Uses BFS with cycle-detection to handle mutual recursion correctly.
/// The returned set never contains `start` — callers add it if needed.
///
/// # Complexity
///
/// O(V + E) where V = number of functions, E = number of call edges.
/// For contracts (typically < 50 functions) this is negligible.
fn transitive_callees<'g>(
    start: &str,
    call_graph: &'g crate::analyzer::cfg::CallGraph,
) -> BTreeSet<String> {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut worklist: std::collections::VecDeque<String> =
        std::collections::VecDeque::new();

    // Seed with direct callees of start.
    if let Some(direct) = call_graph.get(start) {
        for callee in direct {
            if callee != start {
                worklist.push_back(callee.clone());
            }
        }
    }

    while let Some(fn_name) = worklist.pop_front() {
        if visited.contains(&fn_name) {
            continue; // Already processed — cycle or diamond convergence.
        }
        visited.insert(fn_name.clone());
        if let Some(callees) = call_graph.get(fn_name.as_str()) {
            for callee in callees {
                if !visited.contains(callee) {
                    worklist.push_back(callee.clone());
                }
            }
        }
    }

    visited
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
