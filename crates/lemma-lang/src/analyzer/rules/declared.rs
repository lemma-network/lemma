//! SAFETY-010 — Declared Restrictions (force undecidable cases into the open).
//!
//! Prevents *undeclared* transfer restrictions — the catch-all that makes the
//! undecidable residue **visible** instead of silent.
//!
//! ## True property (spec §3-010)
//!
//! "Any condition that can cause a transfer to revert is declared in `config {}`."
//!
//! ## Enforced (declaration-forcing, decidable on the declaration) — option A
//!
//! The **external-call clause** (the rule's headline purpose, spec §3-010): an
//! **external call on the transfer path** (`transfer` / `transferFrom` /
//! `#[onTransfer]`) is only allowed if the contract declares `externalChecker:
//! <addr>` in `config {}`.  An undeclared external call on the transfer path ⇒
//! `UndeclaredRestriction` — the external dependence is hidden from wallets,
//! explorers, and the runtime score otherwise.
//!
//! This converts "undecidable + hidden" (an external contract that may block a
//! sell) into "undecidable + **declared** + monitored" — exactly the rule's
//! stated purpose.  Detection uses `cfg::ext_calls` (4b), already built.
//!
//! ## Scope (option A) — the state-field-gated-revert clause is covered elsewhere
//!
//! Spec §3-010 also requires state-field-gated transfer reverts to map to a
//! declared restriction key (`pausable`, `blacklistGovernance`, `maxWallet`,
//! `fees`).  In Lemma's model that clause is **largely already
//! enforced** by the sibling rules:
//! - an owner-only blacklist field ⇒ SAFETY-005,
//! - a one-way trading gate ⇒ SAFETY-009,
//! - a fee on the transfer path ⇒ SAFETY-002.
//!
//! The residual field→config-key mapping (e.g. a `paused` read requiring
//! `pausable: true`) needs a per-field-name convention that is not yet pinned in
//! the language; it is tracked as a follow-up (P3-rule-6).  The external-call
//! clause is the decidable, non-fragile core and is the part with no other
//! bearer — so it is built here.
//!
//! ## Detection boundary: direct-only ext-call (transitive slips to Tier 2)
//!
//! [`ext_calls`] inspects each transfer-path function's **own body** — it is
//! **direct-only**, not transitive.  A transfer that delegates the external call
//! to an internal helper (`transfer(){ self.helper() } helper(){ self.ext.call()
//! }`) is **not** flagged statically here; the hidden external dependence slips
//! to the **Tier-2 runtime sell-success-rate score** (the rule's by-design
//! backstop, spec §3-010).  Tightening to a transitive closure (via
//! `cfg::build_call_graph`, as SAFETY-005 does for writers — the machinery
//! already ships) is tracked as `P3-rule-7`.  NB: SAFETY-005's
//! `state_write_reachability` IS transitive while this ext-call check is not —
//! that asymmetry is intentional-for-now, not parity.
//!
//! ## Slips to Tier 2 (by design, spec §3-010)
//!
//! Once `externalChecker` is declared, the external dependence is honestly
//! surfaced; the **runtime score** tracks whether that checker actually blocks
//! sells.  The rule converts hidden-undecidable into declared-monitored — it does
//! not (and cannot) decide what the external contract does.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-010`.

use crate::analyzer::cfg::ext_calls;
use crate::analyzer::util::is_transfer_path_entry;
use crate::parser::ConfigValue;
use crate::type_checker::typed_contract::TypedContract;

use crate::analyzer::error::SafetyError;

/// Check a contract for SAFETY-010 undeclared-restriction violations.
///
/// Returns one [`SafetyError::UndeclaredRestriction`] per transfer-path function
/// that makes an external call without the contract declaring `externalChecker`
/// in `config {}`.  Returns an empty `Vec` when safe.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // If the contract declares an external checker, transfer-path external calls
    // are explicitly surfaced — nothing to flag.
    if declares_external_checker(contract) {
        return violations;
    }

    for func in contract.functions() {
        if !is_transfer_path_entry(&func) {
            continue;
        }
        // An external call on the transfer path with no declared externalChecker
        // is a silent external dependence.
        if !ext_calls(&func).is_empty() {
            violations.push(SafetyError::UndeclaredRestriction {
                func: func.name.to_owned(),
            });
        }
    }

    violations
}

/// Returns `true` if `config {}` declares a non-empty `externalChecker` address.
fn declares_external_checker(contract: &TypedContract<'_>) -> bool {
    let Some(config) = contract.config() else {
        return false;
    };
    config
        .iter()
        .find(|e| e.key == "externalChecker")
        .is_some_and(|e| matches!(&e.value, ConfigValue::Str(s) if !s.is_empty()))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
