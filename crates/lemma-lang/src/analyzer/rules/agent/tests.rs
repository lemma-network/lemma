//! Tests for SAFETY-015 and SAFETY-016 — Agent-safety rules (Batch 1).
//!
//! ## Coverage
//!
//! - SAFETY-015: policy-mutation functions must be @onlyOwner-gated.
//! - SAFETY-016: @agentCallable functions must not call grant functions.
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
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AgentReGrant { caller, .. } if caller == "agentEntry")),
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
