//! SAFETY-008 — Hook Sandboxing rule.
//!
//! Spec §3 SAFETY-008 has **two** clauses:
//! 1. `Ext(hook) = ∅` — no external calls from a hook.
//! 2. State-access set ⊆ own-contract's `state {}` keys.
//!
//! **Clause 1 is enforced here** via `cfg::ext_calls(func)`.
//!
//! **Clause 2 is trivially satisfied** in single-contract analysis: every
//! `CfgNode::StateWrite` recorded by `cfg::walk_function` is, by construction,
//! a write to the same contract's state (cross-contract state writes appear as
//! external calls, not as `StateWrite` nodes). There is no false negative — a
//! hook writing another contract's state can only do so via an external call,
//! which clause 1 catches. Clause 2 becomes non-trivial in Phase 4 multi-
//! contract analysis; it is tracked as a living-notes item.
//!
//! **Foundation**: `cfg::ext_calls(func)`.
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-008`.

use crate::analyzer::cfg;
use crate::analyzer::error::SafetyError;
use crate::type_checker::typed_contract::TypedContract;

/// Check a contract for SAFETY-008 hook escape violations.
///
/// Returns one [`SafetyError::HookEscape`] per external call site found in
/// any `#[onTransfer]`-annotated function.
/// Returns an empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        // Only inspect functions annotated with #[onTransfer].
        if !func.annotations.iter().any(|a| a.name == "onTransfer") {
            continue;
        }

        // Any external call from a hook is a violation.
        let ext = cfg::ext_calls(&func);
        for call in &ext {
            violations.push(SafetyError::HookEscape {
                hook: func.name.to_owned(),
                key: call.callee_desc.clone(),
            });
        }
    }

    violations
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
