//! SAFETY-007 — Upgrade Safety.
//!
//! Prevents silent/unsafe upgrades (swapping logic to drain holders).
//!
//! ## Authority model (spec §13, `09 §3 SAFETY-007`)
//!
//! Lemma's upgrade model is **capability-flag based**, not Ethereum-style proxy
//! delegation.  `config.upgradeable: bool` (RATCHET-OFF, §24.4) is the declared
//! opt-in.  Per spec §13, **upgrade is a holder-harming operation** (grouped with
//! blacklist / disable-trading / raise-fees) and must therefore be gated by the
//! `GOVERNANCE` role (`@onlyRole("GOVERNANCE")`), **never** merely `@onlyOwner`.
//!
//! ## What this rule enforces (decidable, compile-time)
//!
//! When `config.upgradeable == true`, any function that can mutate the contract's
//! **upgrade-capability state** (the `upgradeable` lever) must resolve to the
//! `GOVERNANCE` role.  An `@onlyOwner` (or unguarded) upgrade-capability lever ⇒
//! `UnsafeUpgrade` — this catches the headline "ownerless instant upgrade".
//!
//! Structurally identical to SAFETY-005 (blacklist writer → governance) and
//! SAFETY-009 (trading-flag writer → governance): identify the harm-op writer,
//! require GOVERNANCE auth.  Uses the built `state_write_reachability` +
//! `auth_set` foundations.
//!
//! ## What is Tier-2 / runtime (NOT compile-time, per spec §3-007)
//!
//! The spec's clause 2 (storage-layout prefix-compatibility) requires the
//! **prior deployed version's** layout, which does not exist at single-contract
//! compile time — it is a deploy-time VM check.  The `timelock >=
//! MIN_UPGRADE_TIMELOCK` magnitude is, per spec §3-007 line 157, "**enforced by
//! the VM at execution**" (13-VALIDATOR_EPOCH_SPEC governance).  The RATCHET-OFF
//! enforcement of the `upgradeable` flag itself is runtime (§24.4).  These are
//! correctly attributed to Tier-2 / runtime and are **not** faked here
//! (soundness obligation, spec §5.1).
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-007`, `03-LANGUAGE_SPEC §13`.

use crate::analyzer::authset::{auth_set, requires_governance};
use crate::analyzer::dataflow::state_write_reachability;
use crate::parser::ConfigValue;
use crate::type_checker::typed_contract::TypedContract;

use super::super::cfg::build_call_graph;
use crate::analyzer::error::SafetyError;

/// The state field name that backs the `upgradeable` capability.
///
/// In Lemma's capability model the upgrade lever is the `upgradeable` flag
/// itself; a function that writes it is the upgrade-capability mutator.
const UPGRADE_CAPABILITY_FIELD: &str = "upgradeable";

/// Check a contract for SAFETY-007 upgrade-safety violations.
///
/// Fires only when `config.upgradeable == true`.  Returns
/// [`SafetyError::UnsafeUpgrade`] for each upgrade-capability lever that is not
/// `GOVERNANCE`-gated.  Returns an empty `Vec` when the contract is safe (or not
/// upgradeable).
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // Rule only applies to contracts that opt into upgradeability.
    if !is_upgradeable(contract) {
        return violations;
    }

    // Find every function that can (transitively) write the upgrade-capability
    // state field.  These are the upgrade-capability levers.
    let call_graph = build_call_graph(contract);
    let reach = state_write_reachability(contract, &call_graph);
    let Some(levers) = reach.get(UPGRADE_CAPABILITY_FIELD) else {
        // No function writes the upgrade capability — nothing to gate.
        return violations;
    };

    // Each lever must resolve to GOVERNANCE; @onlyOwner / unguarded ⇒ violation.
    for func in contract.functions() {
        if !levers.contains(func.name) {
            continue;
        }
        let guards = auth_set(&func);
        if !requires_governance(&guards) {
            violations.push(SafetyError::UnsafeUpgrade {
                reason: format!(
                    "`{}` can mutate the upgrade capability but is not gated by \
                     @onlyRole(\"GOVERNANCE\") — upgrade is a holder-harming operation \
                     and requires governance, not @onlyOwner",
                    func.name
                ),
            });
        }
    }

    violations
}

/// Returns `true` if the contract declares `upgradeable: true` in `config {}`.
fn is_upgradeable(contract: &TypedContract<'_>) -> bool {
    let Some(config) = contract.config() else {
        return false;
    };
    config
        .iter()
        .find(|e| e.key == "upgradeable")
        .is_some_and(|e| matches!(e.value, ConfigValue::Bool(true)))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
