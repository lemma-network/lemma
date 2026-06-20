//! SAFETY-001 — Anti-Honeypot (disposal-path existence).
//!
//! Prevents buyable-but-not-sellable tokens (the classic honeypot).  Lemma's
//! headline anti-scam guarantee.  **Fires unconditionally for all token
//! contracts** — anti-honeypot is a protocol invariant, not an opt-in flag
//! (DB-A57).
//!
//! ## True property (UNDECIDABLE)
//!
//! "Every address that can acquire the token can also dispose of it."  Equivalent
//! to halting in general (a sell path may be obfuscated arbitrarily).
//!
//! ## Lemma's model (spec §24.1) — what this rule actually enforces
//!
//! Unlike Ethereum, Lemma tokens have **no separate buy/sell function**: a single
//! `transfer` / `transferFrom` handles both (buy vs sell is `isPair(from)||isPair(
//! to)` — a transfer to/from a registered LP pair, §24.1).  The anti-honeypot
//! property is therefore enforced as **disposal-path accessibility symmetry**:
//! for every token contract, the disposal path (`transfer` / `transferFrom`) must
//! be **access-unrestricted** (anyone who holds can sell) and no
//! balance-decreasing public entry may be access-restricted while a
//! balance-mutating entry is public.
//!
//! ## Enforced (decidable over-approximation — §24.1 realization)
//!
//! For all token contracts, the **disposal path must exist and be public**:
//! `transfer` (and `transferFrom` if present) must be declared and
//! access-unrestricted (`Auth` has no `@onlyOwner` / `@onlyRole`).  A missing or
//! owner/role-gated `transfer` ⇒ `Honeypot` (holders cannot freely sell).  In the
//! §24.1 single-transfer model this *is* the decidable honeypot surface: the one
//! transfer entry handles every buy and sell, so an accessible-to-all `transfer`
//! means anyone who holds can dispose.
//!
//! ## Why NOT a "balance-mutator guard-symmetry" check (soundness)
//!
//! A naive "any restricted `pub` balance-mutator alongside a public one ⇒
//! honeypot" check is **unsound (false-positive)**: it would reject a legitimate
//! `@onlyOwner mint(to, amount)` — restricting *acquisition* is normal and never
//! blocks a sell (spec §3-001 step 1 vs step 2: only *disposal* mutations —
//! `balances[msg.sender]` *decrease* + value-out — matter).  Distinguishing a
//! restricted acquisition lever (`mint`, fine) from a restricted disposal lever
//! (a separate `@onlyOwner sell()`, a honeypot) requires **balance-direction
//! `EffAuth` analysis** (the literal §3-001 step-3 form, option A).  That is
//! deliberately **out of scope** and is Tier-2 residue here — a separate
//! hand-written `@onlyOwner sell()` function (non-canonical in the §24.1 model)
//! slips to the runtime sell-success-rate score + SAFETY-010, rather than being
//! flagged by an unsound direction-blind heuristic.
//!
//! ## Cross-rule (not re-implemented here)
//!
//! - **One-way trading gate** blocking sells ⇒ caught by SAFETY-009 independently.
//! - **Owner-only blacklist** blocking a sell ⇒ caught by SAFETY-005.
//! - **Sell fee ≥ 100%** ⇒ caught by SAFETY-002.
//!
//! Those rules' violations already reject the contract; this rule adds the
//! disposal-path existence + access check that is its unique contribution
//! (spec §3-001 step 3 "ties to SAFETY-009").
//!
//! ## Tier-2 residue (per spec §3-001)
//!
//! Obfuscated arithmetic that conditionally reverts on the sell path, and sell
//! paths that call an external upgradeable contract, are **undecidable** and slip
//! to Tier 2 (runtime sell-success-rate score) + SAFETY-010 declaration-forcing.
//! Full per-mutation balance-direction `EffAuth` symmetry (the literal §3-001
//! step-3 form) is the deeper analysis; the §24.1 single-transfer model makes the
//! disposal-path accessibility check the decidable core.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-001`, `03-LANGUAGE_SPEC §24.1`.

use crate::analyzer::authset::{auth_set, is_access_unrestricted};
use crate::type_checker::typed_contract::TypedContract;

use crate::analyzer::error::SafetyError;

/// Check a contract for SAFETY-001 anti-honeypot violations.
///
/// Anti-honeypot is a protocol invariant — fires unconditionally for all token
/// contracts (DB-A57).  Returns [`SafetyError::Honeypot`] for a missing or
/// restricted disposal path.  Returns an empty `Vec` when safe or when the
/// contract is not a token.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // Anti-honeypot is a protocol invariant — fires unconditionally for all
    // token contracts (DB-A57). No opt-in flag.
    if !contract.is_token() {
        return violations;
    }

    let functions = contract.functions();

    // Check 1: a public disposal path (`transfer`) must exist and be unrestricted.
    let transfer = functions.iter().find(|f| f.name == "transfer");
    match transfer {
        None => {
            violations.push(SafetyError::Honeypot {
                reason: "token has no `transfer` function — holders have no \
                         disposal path (SAFETY-001)"
                    .to_owned(),
            });
        }
        Some(f) => {
            if !is_access_unrestricted(&auth_set(f)) {
                violations.push(SafetyError::Honeypot {
                    reason: "`transfer` is access-restricted — holders cannot \
                             freely dispose (SAFETY-001)"
                        .to_owned(),
                });
            }
        }
    }
    // `transferFrom`, if present, must likewise be unrestricted.
    if let Some(f) = functions.iter().find(|f| f.name == "transferFrom") {
        if !is_access_unrestricted(&auth_set(f)) {
            violations.push(SafetyError::Honeypot {
                reason: "`transferFrom` is access-restricted — delegated \
                         disposal path is gated (SAFETY-001)"
                    .to_owned(),
            });
        }
    }

    violations
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
