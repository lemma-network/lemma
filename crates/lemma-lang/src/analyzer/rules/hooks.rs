//! SAFETY-008 — Hook Sandboxing rule.
//!
//! Detects `#[onTransfer]` hooks that make external calls.
//! Transfer hooks must have `Ext(hook) = ∅` — they may only access own-contract
//! state and must not call out to other contracts.
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
