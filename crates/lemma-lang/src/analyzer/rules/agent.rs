//! SAFETY-014…019 — Agent-safety rules (Warden / Agent Layer).
//!
//! These six rules make *contracts* safe for agents to call, complementing
//! Warden which makes *accounts* safe at runtime.
//! See `docs/09-SAFETY_ANALYZER_SPEC §3-bis` for full definitions.
//!
//! ## Rule status (Batch 2 — P3·Step 11)
//!
//! | Rule | Status |
//! |------|--------|
//! | SAFETY-014 | ✅ Declaration-forcing: maxValueOut required; loop-transfer rejected |
//! | SAFETY-015 | ✅ Reachability check via call graph |
//! | SAFETY-016 | ✅ Reachability check via call graph |
//! | SAFETY-017 | ✅ Declaration-forcing: agent-state access without @agentCallable rejected |
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
use crate::parser::AnnotationArg;
use crate::parser::Expr;
use crate::parser::Literal;
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

// ── Transfer call name patterns (for SAFETY-014) ─────────────────────────────
//
// A call is a "transfer call" if the callee name matches one of these patterns.
// These are the canonical value-outflow operations in Lem contracts.
// Completeness verified against 14-AGENT_LAYER §4.1 and 03-LANGUAGE_SPEC §26:
//   transfer / transferFrom — LToken standard (IToken)
//   send / sendValue        — native LEM transfer helpers
//   call                    — raw call with value (rawCall with value field)
//
// Honest limit: non-canonical transfer wrappers escape static analysis.
// Warden runtime provides defence-in-depth for missed names.
const TRANSFER_CALL_NAMES: &[&str] = &[
    "transfer",
    "transferFrom",
    "send",
    "sendValue",
    "call", // rawCall with value
];

// ── Agent-policy state field names (for SAFETY-017) ──────────────────────────
//
// A function accesses "agent-policy state" if it reads or writes a `self.field`
// where `field` matches one of these names. These are the canonical Warden-managed
// state fields defined in 14-AGENT_LAYER §2 and §2.4.
//
// A function that accesses these fields WITHOUT `@agentCallable` is a hand-rolled
// agent entry that bypasses the compiler-emitted Warden gate → `AgentGateBypassed`.
//
// Honest limit: non-canonical field names escape static analysis.
// Warden runtime provides defence-in-depth for missed names.
// Canonical contract-storage field names for agent-policy state.
// Naming convention pinned here (not in 14-AGENT_LAYER §2 which defines the
// *policy value* struct, not the contract storage identifiers).
// TODO(spec): add a decisions-log entry declaring these as the canonical names.
const AGENT_STATE_FIELDS: &[&str] = &[
    // Core policy storage (14-AGENT_LAYER §2.1)
    "agentPolicies",
    "agentPolicy",
    // Kill-switch state (14-AGENT_LAYER §2.4)
    "agents_paused",
    "agentsPaused",
    // Budget tracking (14-AGENT_LAYER §2.2) — mutable counters Warden writes.
    // Mutating these directly bypasses the Warden accounting gate.
    "agentBudgets",
    "agentBudget",
    "spentTotal",
    "spent_total",
    "spentThisEpoch",
    "spent_this_epoch",
    // Session key registry (14-AGENT_LAYER §2)
    "sessionKeys",
    "sessionKey",
];

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-014..019 agent-safety violations.
///
/// Returns all violations found. Returns an empty `Vec` if the contract is
/// clean or has no agent-annotated functions.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations: Vec<SafetyError> = Vec::new();

    // SAFETY-014 — agent-callable bounded effects.
    violations.extend(check_014_agent_callable_bounded_effects(contract));

    // SAFETY-015 — policy-mutation owner-gating.
    violations.extend(check_015_policy_mutation_owner_gating(contract));

    // SAFETY-016 — no agent re-grant.
    violations.extend(check_016_no_agent_re_grant(contract));

    // SAFETY-017 — kill-switch honored.
    violations.extend(check_017_kill_switch_honored(contract));

    // SAFETY-018 — co-sign threshold integrity (Batch 3).
    // violations.extend(check_018_cosign_threshold_integrity(contract));

    // SAFETY-019 — deterministic anomaly inputs (Batch 3).
    // violations.extend(check_019_deterministic_anomaly_inputs(contract));

    violations
}

// ─── SAFETY-014 — Agent-callable bounded effects ──────────────────────────────

/// Check that every `@agentCallable` function has a statically bounded value outflow.
///
/// Spec requirement (09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-014):
/// > "a function annotated `@agentCallable(maxValueOut: <cap>)` must have value
/// > outflow the analyzer can prove ≤ the declared cap — no unbounded transfer,
/// > no loop-driven payout without a declared bound. Unprovable ⇒ reject."
///
/// ## Detection strategy (declaration-forcing, MVP)
///
/// Step 1 — Annotation check: does `@agentCallable` carry a valid `maxValueOut` named arg?
/// - Missing `maxValueOut` → `AgentOutflowUnbounded { reason: "missing maxValueOut argument" }`
/// - `maxValueOut` is not a numeric literal → `AgentOutflowUnbounded`
/// - `maxValueOut: 0` with any transfer in the body → `AgentOutflowUnbounded`
///   (a 0 cap with outflow is internally contradictory — spec §214)
///
/// Step 2 — Transfer-in-loop check: does the function body (or any transitive
/// callee) contain a transfer call inside a `while`, `for`, or `loop` body?
/// - Transfer in a loop → `AgentOutflowUnbounded { reason: "transfer call inside loop" }`
///
/// Step 3 — Transfer calls outside loops with a valid positive `maxValueOut` cap → clean.
/// The Warden runtime enforces the declared cap at execution time.
///
/// ## Transitive check
///
/// The check runs `OutflowVisitor` over the entry's direct body **and** every
/// transitively reachable function body. This catches the drain-through-helper
/// pattern: `@agentCallable fn pay() { drain() }` where `drain()` has a loop
/// with a transfer call.
///
/// ## Honest limit
///
/// Declaration-forcing: the analyzer trusts the declared `maxValueOut` cap for
/// non-loop transfer patterns. Multi-hop outflow through *external* contracts is
/// not statically bounded here — that slips to Tier 2 (runtime-scored via Warden).
fn check_014_agent_callable_bounded_effects(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let call_graph = build_call_graph(contract);

    // Build a lookup: function name → ContractFunction (for transitive body walking).
    let fn_map: std::collections::BTreeMap<&str, _> = contract
        .functions()
        .into_iter()
        .map(|f| (f.name, f))
        .collect();

    let mut violations = Vec::new();

    for func in contract
        .functions()
        .into_iter()
        .filter(|f| is_agent_callable(f))
    {
        // Find the @agentCallable annotation (guaranteed present by is_agent_callable).
        let Some(ann) = func.annotations.iter().find(|a| a.name == "agentCallable") else {
            continue; // is_agent_callable already verified presence — logically unreachable
        };

        // Step 1: verify @agentCallable carries a valid maxValueOut.
        let annotation_ok = match extract_max_value_out(ann) {
            MaxValueOutResult::Missing => {
                violations.push(SafetyError::AgentOutflowUnbounded {
                    func: func.name.to_owned(),
                    reason: "missing maxValueOut argument — @agentCallable requires \
                             maxValueOut: <cap>"
                        .to_owned(),
                });
                false // Still check body for loop-transfer violations.
            }
            MaxValueOutResult::NotNumericLiteral => {
                violations.push(SafetyError::AgentOutflowUnbounded {
                    func: func.name.to_owned(),
                    reason: "maxValueOut must be a named numeric literal \
                             (positional args not accepted)"
                        .to_owned(),
                });
                false
            }
            MaxValueOutResult::ZeroCap => {
                // Zero cap is valid syntax but contradictory with any transfer:
                // Warden will reject every outflow tx at runtime — checked below.
                true // Mark as "zero cap" — body check will catch it if transfer present.
            }
            MaxValueOutResult::Valid => true,
        };

        // Step 2: scan the entry body + all transitive callees for loop+transfer violations.
        // For ZeroCap entries we also flag ANY transfer (loop or not) since the declared cap
        // is 0 — a transfer with a 0 cap is internally contradictory.
        let is_zero_cap = matches!(extract_max_value_out(ann), MaxValueOutResult::ZeroCap);
        let _ = annotation_ok; // Used for early-return logic above; body check always runs.

        // Collect the entry + all transitive callees to walk.
        let mut to_walk: BTreeSet<String> = transitive_callees(func.name, &call_graph);
        to_walk.insert(func.name.to_owned());

        for fn_name in &to_walk {
            if let Some(callee_func) = fn_map.get(fn_name.as_str()) {
                if let Some(body) = callee_func.body {
                    let mut visitor = OutflowVisitor {
                        func: func.name.to_owned(), // Report the entry name, not the callee
                        violations: Vec::new(),
                        in_loop: false,
                        flag_any_transfer: is_zero_cap,
                    };
                    visitor.visit_stmts(body);
                    violations.extend(visitor.violations);
                }
            }
        }
    }

    violations
}

/// Result of extracting the `maxValueOut` argument from `@agentCallable`.
enum MaxValueOutResult {
    /// `@agentCallable` has no `maxValueOut` named argument (includes positional-only args).
    Missing,
    /// `maxValueOut` is present but is not a numeric literal (e.g. an identifier).
    NotNumericLiteral,
    /// `maxValueOut: 0` — declared zero cap. Contradictory if the function performs any
    /// transfer (flagged by caller as `AgentOutflowUnbounded`).
    ZeroCap,
    /// `maxValueOut` is a valid positive numeric literal.
    Valid,
}

/// Extract and validate the `maxValueOut` named argument from an `@agentCallable` annotation.
///
/// Takes the already-found `@agentCallable` `Annotation` directly (DRY: caller
/// already filtered on `is_agent_callable`, no redundant re-scan of annotations).
///
/// Returns:
/// - `Missing` — no `maxValueOut` named arg (bare `@agentCallable` or positional-only)
/// - `NotNumericLiteral` — `maxValueOut` present but not an integer literal
/// - `ZeroCap` — `maxValueOut: 0` (valid syntax, contradictory with outflow — caller handles)
/// - `Valid` — `maxValueOut` is a positive numeric literal
fn extract_max_value_out(ann: &crate::parser::Annotation) -> MaxValueOutResult {
    // Look for a Named("maxValueOut", expr) argument.
    // Positional args (e.g. @agentCallable(1000)) are not accepted — named form is required
    // (declaration-forcing: forces developers to be explicit about the cap semantics).
    let max_value_arg = ann.args.iter().find_map(|arg| {
        if let AnnotationArg::Named(key, expr) = arg {
            if key == "maxValueOut" {
                return Some(expr);
            }
        }
        None
    });

    let Some(expr) = max_value_arg else {
        return MaxValueOutResult::Missing;
    };

    // The value must be a numeric literal: Int, IntTyped, or Hex.
    // Float, Bool, Str, Ident, etc. are not valid caps.
    match expr {
        Expr::Literal(Literal::Int(0), _) => MaxValueOutResult::ZeroCap,
        Expr::Literal(Literal::Int(_), _)
        | Expr::Literal(Literal::IntTyped { .. }, _)
        | Expr::Literal(Literal::Hex(_), _) => MaxValueOutResult::Valid,
        _ => MaxValueOutResult::NotNumericLiteral,
    }
}

// ─── SAFETY-017 — Kill-switch honored ─────────────────────────────────────────

/// Check that no function accesses agent-policy state without the `@agentCallable`
/// annotation (which is the compiler-emitted Warden gate).
///
/// Spec requirement (09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-017):
/// > "every `@agentCallable` entry must be dominated by the Warden gate (the
/// > compiler emits the gate; a contract cannot define an agent-reachable path
/// > that skips it). A hand-rolled agent entry that does not route through
/// > Warden ⇒ reject (`AgentGateBypassed`)."
///
/// ## Detection strategy (declaration-forcing, MVP)
///
/// A function that reads or writes agent-policy state fields (e.g. `self.agentPolicies`,
/// `self.agents_paused`, `self.sessionKeys`) is an agent-entry candidate. If it does
/// NOT carry `@agentCallable`, it is a hand-rolled entry that bypasses the Warden gate.
///
/// Exclusion: functions gated by `@onlyOwner` are legitimate admin functions that
/// manage agent state (e.g. `pauseAgents`, `grantAgent`). These are not flagged —
/// they are owner-only and cannot be reached by session keys.
///
/// **Read-only accessors**: a `view` function that reads agent state (e.g. `getPolicy()`)
/// is ALSO flagged. This is intentional: any contract function that touches agent-policy
/// state — even read-only — must be explicitly gated as either `@agentCallable` (if
/// session-key-reachable) or `@onlyOwner` (if admin-only). This forces developers to
/// declare the access level; Warden then enforces it at runtime. Ungated read accessors
/// are rare in practice and carry low blast radius, but the conservative posture prevents
/// information-leakage patterns on session-key-accessible paths.
///
/// If `ContractFunction::mutability` is exposed in a future version, `view`/`pure`
/// functions could be exempted from this check — but for now all ungated agent-state
/// accesses are flagged uniformly.
///
/// ## Honest limit
///
/// Name-based field detection covers the canonical agent-policy state surface
/// defined in `AGENT_STATE_FIELDS`. Non-canonical field names escape static
/// analysis — Warden runtime is the backstop.
fn check_017_kill_switch_honored(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    contract
        .functions()
        .into_iter()
        // Not already annotated as @agentCallable (those are the correct entries).
        .filter(|func| !is_agent_callable(func))
        // Not owner-only admin functions (legitimate managers of agent state).
        .filter(|func| !requires_owner_only(&auth_set(func)))
        // Accesses agent-policy state fields — a hand-rolled agent entry.
        .filter(|func| accesses_agent_state(func))
        .map(|func| SafetyError::AgentGateBypassed {
            func: func.name.to_owned(),
        })
        .collect()
}

/// Returns `true` if the function body reads or writes any agent-policy state field
/// via `self.<field>` where `<field>` is in `AGENT_STATE_FIELDS`.
fn accesses_agent_state(func: &ContractFunction<'_>) -> bool {
    let Some(body) = func.body else {
        return false;
    };
    let mut visitor = AgentStateVisitor { found: false };
    visitor.visit_stmts(body);
    visitor.found
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
    for entry in contract
        .functions()
        .into_iter()
        .filter(|f| is_agent_callable(f))
    {
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
        if !violations.iter().any(
            |v| matches!(v, SafetyError::AgentPolicySelfEscalation { func } if func == ungated),
        ) {
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

    for entry in contract
        .functions()
        .into_iter()
        .filter(|f| is_agent_callable(f))
    {
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
fn transitive_callees(
    start: &str,
    call_graph: &crate::analyzer::cfg::CallGraph,
) -> BTreeSet<String> {
    let mut visited: BTreeSet<String> = BTreeSet::new();
    let mut worklist: std::collections::VecDeque<String> = std::collections::VecDeque::new();

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

/// AST visitor that detects transfer calls inside loop bodies (SAFETY-014).
///
/// Tracks loop nesting depth via `in_loop`. When a transfer call is found
/// inside a loop, it pushes an `AgentOutflowUnbounded` violation.
///
/// ## Loop detection
///
/// The canonical `walk_stmt` already descends into loop bodies via
/// `visit_stmts`. To track loop context, we override `visit_stmt` to set
/// `in_loop = true` before recursing into `While`, `For`, and `Loop` bodies,
/// then restore the previous value after (handles nested loops correctly).
struct OutflowVisitor {
    /// Name of the enclosing `@agentCallable` function.
    func: String,
    /// Accumulated violations.
    violations: Vec<SafetyError>,
    /// Whether the current traversal position is inside a loop body.
    in_loop: bool,
    /// If `true`, flag ANY transfer call (used when `maxValueOut: 0` — zero cap
    /// is contradictory with any outflow, not just loop-driven outflow).
    flag_any_transfer: bool,
}

impl Visitor for OutflowVisitor {
    fn visit_stmt(&mut self, stmt: &crate::parser::Stmt) {
        // For loop-introducing statements, set in_loop before recursing into
        // the body, then restore. This correctly handles nested loops.
        match stmt {
            crate::parser::Stmt::While { cond, body, .. } => {
                // Visit the condition outside the loop context (it's not the body).
                self.visit_expr(cond);
                let prev = self.in_loop;
                self.in_loop = true;
                self.visit_stmts(body);
                self.in_loop = prev;
            }
            crate::parser::Stmt::For { iter, body, .. } => {
                // Visit the iterator expression outside the loop context.
                match iter {
                    crate::parser::ForIter::Of(e) => self.visit_expr(e),
                    crate::parser::ForIter::In(start, _, end, _) => {
                        self.visit_expr(start);
                        self.visit_expr(end);
                    }
                }
                let prev = self.in_loop;
                self.in_loop = true;
                self.visit_stmts(body);
                self.in_loop = prev;
            }
            crate::parser::Stmt::Loop { body, .. } => {
                let prev = self.in_loop;
                self.in_loop = true;
                self.visit_stmts(body);
                self.in_loop = prev;
            }
            // All other statements: use the canonical walk_stmt traversal.
            other => crate::visit::walk_stmt(self, other),
        }
    }

    fn visit_expr(&mut self, expr: &Expr) {
        // Detect transfer calls.
        // Flagging conditions:
        //   1. Always: when `flag_any_transfer` is set (maxValueOut: 0 is contradictory
        //      with any transfer — even a single one declared with a 0 cap).
        //   2. In-loop only: otherwise, only flag transfers inside loops (a single transfer
        //      with a positive declared cap is accepted; Warden enforces the cap at runtime).
        if let Expr::Call { callee, .. } = expr {
            if let Some(name) = extract_call_name(callee) {
                if TRANSFER_CALL_NAMES.contains(&name.as_str())
                    && (self.in_loop || self.flag_any_transfer)
                {
                    let reason = if self.flag_any_transfer && !self.in_loop {
                        "declared maxValueOut: 0 but function performs a transfer — \
                         0 cap is contradictory with outflow"
                    } else {
                        "transfer call inside loop — outflow is potentially unbounded"
                    };
                    self.violations.push(SafetyError::AgentOutflowUnbounded {
                        func: self.func.clone(),
                        reason: reason.to_owned(),
                    });
                }
            }
        }
        walk_expr(self, expr);
    }
}

/// AST visitor that detects `self.<agent_state_field>` member accesses (SAFETY-017).
///
/// Flags any read or write of a canonical agent-policy state field via `self`.
/// Short-circuits on first match to avoid redundant work.
struct AgentStateVisitor {
    /// Whether any agent-policy state field access was found.
    found: bool,
}

impl Visitor for AgentStateVisitor {
    fn visit_expr(&mut self, expr: &Expr) {
        // Short-circuit: once found, no need to continue traversal.
        if self.found {
            return;
        }
        // Detect `self.<field>` where field is in AGENT_STATE_FIELDS.
        // In the Lem AST: `Expr::Member(box Expr::Ident("self", _), field, _)`.
        if let Expr::Member(base, field, _) = expr {
            if let Expr::Ident(name, _) = base.as_ref() {
                if name == "self" && AGENT_STATE_FIELDS.contains(&field.as_str()) {
                    self.found = true;
                    return;
                }
            }
        }
        walk_expr(self, expr);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
