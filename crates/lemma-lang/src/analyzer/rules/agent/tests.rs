//! Tests for SAFETY-014..017 — Agent-safety rules (Batch 1 + Batch 2).
//!
//! ## Coverage
//!
//! - SAFETY-014: @agentCallable functions must declare maxValueOut; no loop-driven transfers.
//! - SAFETY-015: policy-mutation functions must be @onlyOwner-gated.
//! - SAFETY-016: @agentCallable functions must not call grant functions.
//! - SAFETY-017: functions accessing agent-policy state must carry @agentCallable.
//!
//! ## Test helper
//!
//! Uses the canonical `typed_ast` helper from `delegate/tests.rs` — same
//! pipeline: tokenize → parse → check_skip_wf.

use crate::analyzer::error::SafetyError;
use crate::{parse, tokenize};

use super::check as agent_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── SAFETY-015 tests ─────────────────────────────────────────────────────────

#[test]
fn safety015_owner_gated_grant_is_clean() {
    // grantAgent with @onlyOwner — must pass SAFETY-015.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address }
init(owner: Address) {
self.owner = owner
}
@onlyOwner
pub fn grantAgent(agent: Address) {
let _ = agent
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    let policy_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AgentPolicySelfEscalation { .. }))
        .collect();
    assert!(
        policy_violations.is_empty(),
        "grantAgent with @onlyOwner must pass SAFETY-015; got {violations:?}"
    );
}

#[test]
fn safety015_ungated_grant_emits_policy_self_escalation() {
    // grantAgent without @onlyOwner — must emit AgentPolicySelfEscalation.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address }
init(owner: Address) {
self.owner = owner
}
pub fn grantAgent(agent: Address) {
let _ = agent
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentPolicySelfEscalation { func, .. } if func == "grantAgent")),
        "ungated grantAgent must emit AgentPolicySelfEscalation; got {violations:?}"
    );
}

#[test]
fn safety015_revoke_without_owner_gate_is_flagged() {
    // revokeAgent without @onlyOwner — must emit AgentPolicySelfEscalation.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address }
init(owner: Address) {
self.owner = owner
}
pub fn revokeAgent(agent: Address) {
let _ = agent
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentPolicySelfEscalation { func, .. } if func == "revokeAgent")),
        "ungated revokeAgent must emit AgentPolicySelfEscalation; got {violations:?}"
    );
}

#[test]
fn safety015_non_policy_fn_not_flagged() {
    // A regular public function without @onlyOwner — must NOT be flagged by SAFETY-015.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
pub fn deposit(amount: u128) {
self.bal = self.bal + amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    let policy_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AgentPolicySelfEscalation { .. }))
        .collect();
    assert!(
        policy_violations.is_empty(),
        "non-policy function must not be flagged by SAFETY-015; got {violations:?}"
    );
}

// ─── SAFETY-016 tests ─────────────────────────────────────────────────────────

#[test]
fn safety016_agent_callable_without_grant_is_clean() {
    // @agentCallable function that does NOT call grantAgent — must pass SAFETY-016.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
@agentCallable
pub fn withdraw(amount: u128) {
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    let regrant_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AgentReGrant { .. }))
        .collect();
    assert!(
        regrant_violations.is_empty(),
        "@agentCallable without grant call must pass SAFETY-016; got {violations:?}"
    );
}

#[test]
fn safety016_agent_callable_with_grant_emits_re_grant() {
    // @agentCallable function that calls grantAgent — must emit AgentReGrant.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address }
init(owner: Address) {
self.owner = owner
}
@onlyOwner
pub fn grantAgent(agent: Address) {
let _ = agent
}
@agentCallable
pub fn agentEntry(newAgent: Address) {
let _ = self.grantAgent(newAgent)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentReGrant { caller, callee }
                if caller == "agentEntry" && callee == "grantAgent")),
        "@agentCallable calling grantAgent must emit AgentReGrant; got {violations:?}"
    );
}

#[test]
fn safety016_non_agent_fn_with_grant_is_not_flagged() {
    // A non-@agentCallable function calling grantAgent — must NOT be flagged by SAFETY-016.
    // (SAFETY-015 may flag it for missing @onlyOwner, but SAFETY-016 must not.)
    let ast = typed_ast(
        r#"contract C {
state { owner: Address }
init(owner: Address) {
self.owner = owner
}
@onlyOwner
pub fn grantAgent(agent: Address) {
let _ = agent
}
@onlyOwner
pub fn adminSetup(agent: Address) {
let _ = self.grantAgent(agent)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    let regrant_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AgentReGrant { .. }))
        .collect();
    assert!(
        regrant_violations.is_empty(),
        "non-@agentCallable function calling grantAgent must not emit AgentReGrant; got {violations:?}"
    );
}

#[test]
fn safety016_agent_callable_method_call_grant_is_flagged() {
    // @agentCallable calling grantAgentPolicy as a method call — must emit AgentReGrant.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address }
init(owner: Address) {
self.owner = owner
}
@onlyOwner
pub fn grantAgentPolicy(agent: Address) {
let _ = agent
}
@agentCallable
pub fn agentAction(agent: Address) {
let _ = self.grantAgentPolicy(agent)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentReGrant { caller, callee }
                if caller == "agentAction" && callee == "grantAgentPolicy")),
        "@agentCallable calling grantAgentPolicy must emit AgentReGrant; got {violations:?}"
    );
}

// ─── MF-4: Reachability + Ident arm tests (CR Gate 1 fixes) ──────────────────

#[test]
fn safety015_indirect_policy_mutation_via_agent_path_is_flagged() {
    // @agentCallable → helper() → grantAgent (without @onlyOwner).
    // SAFETY-015 must detect this via transitive reachability (not just direct body).
    let ast = typed_ast(
        r#"contract C {
state { owner: Address }
init(owner: Address) {
self.owner = owner
}
pub fn grantAgent(agent: Address) {
let _ = agent
}
fn helper(agent: Address) {
let _ = self.grantAgent(agent)
}
@agentCallable
pub fn agentEntry(agent: Address) {
let _ = self.helper(agent)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentPolicySelfEscalation { func, .. } if func == "grantAgent")),
        "transitive policy mutation via @agentCallable must emit AgentPolicySelfEscalation; got {violations:?}"
    );
}

#[test]
fn safety016_transitive_grant_via_helper_is_flagged() {
    // @agentCallable → helper() → grantAgent.
    // SAFETY-016 must detect this via transitive reachability.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address }
init(owner: Address) {
self.owner = owner
}
@onlyOwner
pub fn grantAgent(agent: Address) {
let _ = agent
}
fn doGrant(agent: Address) {
let _ = self.grantAgent(agent)
}
@agentCallable
pub fn agentEntry(agent: Address) {
let _ = self.doGrant(agent)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::AgentReGrant { caller, .. } if caller == "agentEntry")
        ),
        "transitive re-grant via helper must emit AgentReGrant; got {violations:?}"
    );
}

#[test]
fn safety016_bare_grant_call_ident_arm_is_flagged() {
    // `grantAgent(agent)` — bare Ident call (not self.grantAgent), exercises Ident arm
    // of extract_call_name.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address }
init(owner: Address) {
self.owner = owner
}
pub fn grantAgent(agent: Address) {
let _ = agent
}
@agentCallable
pub fn agentEntry(agent: Address) {
let _ = grantAgent(agent)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentReGrant { caller, callee }
                if caller == "agentEntry" && callee == "grantAgent")),
        "bare grantAgent(agent) call (Ident arm) must emit AgentReGrant; got {violations:?}"
    );
}

// ─── SAFETY-014 tests ─────────────────────────────────────────────────────────

#[test]
fn safety014_agent_callable_without_transfer_is_clean() {
    // @agentCallable(maxValueOut: 1000) with no transfer calls — must pass SAFETY-014.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
@agentCallable(maxValueOut: 1000)
pub fn deposit(amount: u128) {
self.bal = self.bal + amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    let outflow_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AgentOutflowUnbounded { .. }))
        .collect();
    assert!(
        outflow_violations.is_empty(),
        "@agentCallable with maxValueOut and no transfer must pass SAFETY-014; got {violations:?}"
    );
}

#[test]
fn safety014_missing_max_value_out_emits_unbounded() {
    // @agentCallable without maxValueOut argument — must emit AgentOutflowUnbounded.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
@agentCallable
pub fn withdraw(amount: u128) {
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::AgentOutflowUnbounded { func, reason }
                if func == "withdraw" && reason.contains("missing maxValueOut"))
        ),
        "@agentCallable without maxValueOut must emit AgentOutflowUnbounded; got {violations:?}"
    );
}

#[test]
fn safety014_transfer_in_loop_emits_unbounded() {
    // @agentCallable(maxValueOut: 500) with a transfer call inside a while loop
    // — must emit AgentOutflowUnbounded (loop-driven payout is unbounded).
    // `transfer` is defined as a contract function so the type-checker accepts it.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0, count: u128 = 0 }
pub fn transfer(to: Address, amount: u128) {
self.bal = self.bal - amount
}
@agentCallable(maxValueOut: 500)
pub fn batchPay(n: u128, to: Address) {
while (self.count < n) {
let _ = self.transfer(to, 100)
self.count = self.count + 1
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::AgentOutflowUnbounded { func, reason }
                if func == "batchPay" && reason.contains("loop"))
        ),
        "transfer inside while loop must emit AgentOutflowUnbounded; got {violations:?}"
    );
}

#[test]
fn safety014_transfer_outside_loop_with_cap_is_clean() {
    // @agentCallable(maxValueOut: 500) with a single transfer call (not in a loop)
    // — must pass SAFETY-014 (declaration-forcing: cap declared, single call accepted).
    // `transfer` is defined as a contract function so the type-checker accepts it.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
pub fn transfer(to: Address, amount: u128) {
self.bal = self.bal - amount
}
@agentCallable(maxValueOut: 500)
pub fn pay(to: Address, amount: u128) {
let _ = self.transfer(to, amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    let outflow_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AgentOutflowUnbounded { .. }))
        .collect();
    assert!(
        outflow_violations.is_empty(),
        "single transfer with maxValueOut cap must pass SAFETY-014; got {violations:?}"
    );
}

#[test]
fn safety014_non_literal_max_value_out_emits_unbounded() {
    // @agentCallable(maxValueOut: "big") — string literal is not a numeric literal.
    // Must emit AgentOutflowUnbounded (maxValueOut must be a numeric literal).
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
@agentCallable(maxValueOut: "big")
pub fn withdraw(amount: u128) {
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::AgentOutflowUnbounded { func, reason }
                if func == "withdraw" && reason.contains("numeric literal"))
        ),
        "non-numeric maxValueOut must emit AgentOutflowUnbounded; got {violations:?}"
    );
}

// ─── SAFETY-017 tests ─────────────────────────────────────────────────────────

#[test]
fn safety017_agent_callable_accessing_policy_state_is_clean() {
    // @agentCallable function that reads self.agentPolicies — must pass SAFETY-017
    // (it IS annotated, so it routes through the Warden gate).
    let ast = typed_ast(
        r#"contract C {
state { agentPolicies: u128 = 0 }
@agentCallable(maxValueOut: 0)
pub fn checkPolicy() -> u128 {
return self.agentPolicies
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    let gate_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AgentGateBypassed { .. }))
        .collect();
    assert!(
        gate_violations.is_empty(),
        "@agentCallable fn accessing agentPolicies must pass SAFETY-017; got {violations:?}"
    );
}

#[test]
fn safety017_ungated_fn_reading_agent_policies_is_flagged() {
    // A public function (no @agentCallable, no @onlyOwner) that reads self.agentPolicies
    // — must emit AgentGateBypassed (hand-rolled agent entry bypasses Warden gate).
    let ast = typed_ast(
        r#"contract C {
state { agentPolicies: u128 = 0 }
pub fn getPolicy() -> u128 {
return self.agentPolicies
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentGateBypassed { func } if func == "getPolicy")),
        "ungated fn reading agentPolicies must emit AgentGateBypassed; got {violations:?}"
    );
}

#[test]
fn safety017_owner_gated_fn_reading_agent_state_is_clean() {
    // @onlyOwner function that reads self.agents_paused — must pass SAFETY-017.
    // Owner-only admin functions are legitimate managers of agent state.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address, agents_paused: bool = false }
init(owner: Address) {
self.owner = owner
}
@onlyOwner
pub fn pauseAgents() {
self.agents_paused = true
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    let gate_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AgentGateBypassed { .. }))
        .collect();
    assert!(
        gate_violations.is_empty(),
        "@onlyOwner fn accessing agents_paused must pass SAFETY-017; got {violations:?}"
    );
}

#[test]
fn safety017_fn_without_agent_state_access_is_clean() {
    // A regular public function that does NOT access any agent-policy state field
    // — must pass SAFETY-017 (no agent-state access, no bypass).
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
pub fn deposit(amount: u128) {
self.bal = self.bal + amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    let gate_violations: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AgentGateBypassed { .. }))
        .collect();
    assert!(
        gate_violations.is_empty(),
        "fn without agent-state access must pass SAFETY-017; got {violations:?}"
    );
}

#[test]
fn safety017_fn_reading_agents_paused_without_annotation_is_flagged() {
    // A public function (no @agentCallable, no @onlyOwner) that reads self.agents_paused
    // — must emit AgentGateBypassed.
    let ast = typed_ast(
        r#"contract C {
state { agents_paused: bool = false }
pub fn isPaused() -> bool {
return self.agents_paused
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentGateBypassed { func } if func == "isPaused")),
        "ungated fn reading agents_paused must emit AgentGateBypassed; got {violations:?}"
    );
}

// ─── CR Gate 2 MF-1/MF-2/MF-3/TG tests ──────────────────────────────────────

#[test]
fn safety014_transitive_loop_transfer_is_flagged() {
    // TG-1 / MF-1: @agentCallable → helper() → loop with transfer.
    // The transitive loop+transfer must be detected.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
fn drain(to: Address) {
for i in 0..10 {
let _ = self.transfer(to, 1)
let _ = i
}
}
@agentCallable(maxValueOut: 100)
pub fn pay(to: Address) {
let _ = self.drain(to)
}
pub fn transfer(to: Address, amount: u128) -> bool {
let _ = to
let _ = amount
return true
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations.iter().any(|v| matches!(v, SafetyError::AgentOutflowUnbounded { func, .. } if func == "pay")),
        "transitive loop+transfer via helper must emit AgentOutflowUnbounded; got {violations:?}"
    );
}

#[test]
fn safety014_positional_arg_rejects_with_missing_named_arg() {
    // TG-2 / SF-1: @agentCallable(1000) — positional arg, not named maxValueOut.
    // Must emit AgentOutflowUnbounded (named form required).
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 = 0 }
@agentCallable(1000)
pub fn withdraw(amount: u128) {
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations.iter().any(|v| matches!(v, SafetyError::AgentOutflowUnbounded { func, .. } if func == "withdraw")),
        "positional @agentCallable arg must emit AgentOutflowUnbounded (named form required); got {violations:?}"
    );
}

#[test]
fn safety014_zero_cap_with_transfer_is_flagged() {
    // TG-3 / MF-2: maxValueOut: 0 + transfer call — contradictory (0 cap but performs outflow).
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
@agentCallable(maxValueOut: 0)
pub fn pay(to: Address, amount: u128) {
let _ = self.transfer(to, amount)
}
pub fn transfer(to: Address, amount: u128) -> bool {
let _ = to
let _ = amount
return true
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations.iter().any(|v| matches!(v, SafetyError::AgentOutflowUnbounded { func, reason }
            if func == "pay" && reason.contains("0 cap"))),
        "maxValueOut: 0 with transfer must emit AgentOutflowUnbounded; got {violations:?}"
    );
}

#[test]
fn safety014_for_loop_with_transfer_is_flagged() {
    // TG-4 / SF-3: for loop (Stmt::For) with transfer — must be flagged.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
@agentCallable(maxValueOut: 100)
pub fn payMany(to: Address) {
for i in 0..10 {
let _ = self.transfer(to, 1)
}
}
pub fn transfer(to: Address, amount: u128) -> bool {
let _ = to
let _ = amount
return true
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = agent_check(&contracts[0]);
    assert!(
        violations.iter().any(|v| matches!(v, SafetyError::AgentOutflowUnbounded { func, .. } if func == "payMany")),
        "for-loop with transfer must emit AgentOutflowUnbounded; got {violations:?}"
    );
}
