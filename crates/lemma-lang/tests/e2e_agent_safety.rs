//! E2E integration tests — P3·Step 11 agent-safety rules (SAFETY-014..019).
//!
//! These tests exercise the full `tokenize → parse → check` pipeline against
//! complete agent contracts, proving the acceptance criterion:
//! **"SAFETY-014..019 detect violations in realistic agent contracts"**.
//!
//! ## Layout
//!
//! - `e2e_clean_*` — positive: realistic agent contracts that MUST pass all rules.
//! - `e2e_unsafe_*` — negative: contracts with deliberate violations that MUST be caught.
//! - `e2e_regrant_*` — re-grant detection via transitive call graph.
//!
//! ## Pipeline note
//!
//! Uses the public `check` function (full WF + type-check + safety pipeline).
//! For positive tests, `check` must return `Ok(TypedAst)`.
//! For negative tests, `check` returns `Err(LangError::Safety(violations))` —
//! we extract the violations from the error and assert on them.

use lemma_lang::analyzer::error::SafetyError;
use lemma_lang::error::LangError;
use lemma_lang::{check, parse, tokenize};

// ─── Pipeline helpers ─────────────────────────────────────────────────────────

/// Run the full pipeline and expect success. Panics if any stage fails.
#[allow(clippy::result_large_err)]
fn expect_clean(src: &str) -> lemma_lang::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check (type + WF + safety)")
}

/// Run the full pipeline and expect safety violations. Panics if the pipeline
/// succeeds or fails with a non-Safety error.
#[allow(clippy::result_large_err)]
fn expect_violations(src: &str) -> Vec<SafetyError> {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    match check(ast) {
        Err(LangError::Safety(violations)) => violations,
        Ok(_) => panic!("expected safety violations but pipeline succeeded"),
        Err(other) => panic!("expected Safety error but got: {other:?}"),
    }
}

// ─── E2E Test 1: Clean agent contract ─────────────────────────────────────────

#[test]
fn e2e_clean_agent_contract_passes_all_rules() {
    // A complete, well-formed agent contract:
    // - @agentCallable(maxValueOut: 100) with a single transfer (not in a loop)
    // - @onlyOwner grantAgent (owner-gated policy mutation)
    // - No re-grant from agent-callable path
    // - No agent-state access without @agentCallable
    // - @cosignRequired fn with self.owner access (owner co-sign verified)
    // - @anomalyGuard fn reading only on-chain state (deterministic)
    //
    // Expected: full pipeline returns Ok(TypedAst).
    let _ = expect_clean(
        r#"contract AgentWallet {
state {
owner: Address
bal: u128 = 0
agentPolicies: u128 = 0
}
init(owner: Address) {
self.owner = owner
}
@onlyOwner
pub fn grantAgent(agent: Address) {
let _ = agent
self.agentPolicies = 1
}
pub fn transfer(to: Address, amount: u128) {
self.bal = self.bal - amount
let _ = to
}
@agentCallable(maxValueOut: 100)
pub fn agentPay(to: Address, amount: u128) {
let _ = self.transfer(to, amount)
}
@cosignRequired
pub fn cosignedAction(amount: u128) {
let ownerAddr = self.owner
let _ = ownerAddr
let _ = amount
}
@anomalyGuard
pub fn checkAnomaly() -> bool {
return self.bal > 10000
}
}"#,
    );
}

// ─── E2E Test 2: Unsafe agent contract — multiple violations ──────────────────

#[test]
fn e2e_unsafe_agent_contract_emits_multiple_violations() {
    // A contract with deliberate SAFETY-014 and SAFETY-015 violations:
    // - @agentCallable without maxValueOut (SAFETY-014)
    // - grantAgent without @onlyOwner (SAFETY-015)
    //
    // Expected: pipeline returns Err(LangError::Safety) with both violations.
    let violations = expect_violations(
        r#"contract UnsafeAgent {
state {
owner: Address
bal: u128 = 0
}
init(owner: Address) {
self.owner = owner
}
pub fn grantAgent(agent: Address) {
let _ = agent
}
@agentCallable
pub fn agentWithdraw(amount: u128) {
self.bal = self.bal - amount
}
}"#,
    );

    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::AgentOutflowUnbounded { func, .. } if func == "agentWithdraw")
        ),
        "SAFETY-014 AgentOutflowUnbounded must be present; got {violations:?}"
    );
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::AgentPolicySelfEscalation { func, .. } if func == "grantAgent")
        ),
        "SAFETY-015 AgentPolicySelfEscalation must be present; got {violations:?}"
    );
}

// ─── E2E Test 3: Re-grant detection via transitive call graph ─────────────────

#[test]
fn e2e_regrant_via_helper_is_detected() {
    // @agentCallable → helper() → grantAgent.
    // SAFETY-016 must detect the transitive re-grant path.
    //
    // Expected: pipeline returns Err(LangError::Safety) with AgentReGrant.
    let violations = expect_violations(
        r#"contract ReGrantAgent {
state {
owner: Address
}
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
@agentCallable(maxValueOut: 0)
pub fn agentEntry(agent: Address) {
let _ = self.doGrant(agent)
}
}"#,
    );

    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::AgentReGrant { caller, .. } if caller == "agentEntry")
        ),
        "SAFETY-016 AgentReGrant must be present for transitive re-grant; got {violations:?}"
    );
}

// ─── E2E Test 4: SAFETY-018 co-sign forgeability ─────────────────────────────

#[test]
fn e2e_cosign_forgeable_contract_is_rejected() {
    // A contract with a @cosignRequired function that does NOT verify against
    // the owner key — the co-sign is forgeable.
    //
    // Expected: pipeline returns Err(LangError::Safety) with AgentCosignForgeable.
    let violations = expect_violations(
        r#"contract ForgeableCosign {
state {
owner: Address
bal: u128 = 0
}
init(owner: Address) {
self.owner = owner
}
@cosignRequired
pub fn cosignedAction(amount: u128) {
self.bal = self.bal + amount
}
}"#,
    );

    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::AgentCosignForgeable { func } if func == "cosignedAction")
        ),
        "SAFETY-018 AgentCosignForgeable must be present; got {violations:?}"
    );
}

// ─── E2E Test 5: SAFETY-019 non-deterministic anomaly predicate ───────────────

#[test]
fn e2e_anomaly_predicate_with_external_call_is_rejected() {
    // A contract with an anomaly predicate (named checkAnomaly) that makes an
    // external call — the predicate is non-deterministic.
    //
    // Expected: pipeline returns Err(LangError::Safety) with AgentAnomalyNonDeterministic.
    let violations = expect_violations(
        r#"contract NonDetAnomaly {
state {
owner: Address
oracle: Address
}
init(owner: Address, oracle: Address) {
self.owner = owner
self.oracle = oracle
}
pub fn checkAnomaly() -> bool {
let price = oracle.getPrice()
return price > 1000
}
}"#,
    );

    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::AgentAnomalyNonDeterministic { func, .. } if func == "checkAnomaly")
        ),
        "SAFETY-019 AgentAnomalyNonDeterministic must be present; got {violations:?}"
    );
}
