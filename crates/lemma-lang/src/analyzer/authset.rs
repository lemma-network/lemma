//! Authorization-set analysis — `Auth(f)`.
//!
//! ## Purpose
//!
//! Foundational analysis consumed by multiple SAFETY rules:
//!
//! - **`Auth(f)`** (`auth_set`): the guard set declared directly on function `f`
//!   via `@`-annotations (`@onlyOwner`, `@onlyRole("GOVERNANCE")`, etc.).
//!
//! ## Canonical guard set (spec §2)
//!
//! ```text
//! @onlyOwner             → Guard::OnlyOwner
//! @onlyRole("GOVERNANCE")→ Guard::OnlyRole("GOVERNANCE")   ← "requires governance"
//! @onlyRole("OPERATOR")  → Guard::OnlyRole("OPERATOR")
//! @whenNotPaused         → Guard::WhenNotPaused
//! @whenPaused            → Guard::WhenPaused
//! @nonReentrant          → Guard::NonReentrant
//! ```
//!
//! "Requires governance" in the spec always means `@onlyRole("GOVERNANCE")` — **not**
//! `@onlyOwner` and not a separate `@governance` annotation (spec §2 note).

use std::collections::BTreeSet;

use crate::parser::{AnnotationArg, Expr, Literal};
use crate::type_checker::typed_contract::ContractFunction;

// ─── Guard ────────────────────────────────────────────────────────────────────

/// A single authorization guard as parsed from a function annotation.
///
/// Guards are ordered (`Ord`) for deterministic `BTreeSet` iteration
/// (AGENTS §7.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Guard {
    /// `@onlyOwner` — restricted to the deploying address.
    OnlyOwner,
    /// `@onlyRole("ROLE")` — restricted to holders of the named role.
    OnlyRole(String),
    /// `@whenNotPaused` — allowed only while the contract is not paused.
    WhenNotPaused,
    /// `@whenPaused` — allowed only while the contract is paused.
    WhenPaused,
    /// `@nonReentrant` — reentrancy guard.
    NonReentrant,
}

// ─── Auth(f) ──────────────────────────────────────────────────────────────────

/// Parse `Auth(f)` — the guard set declared directly on function `f`.
///
/// Recognises `@`-form annotations only (per spec §2 note: `@`-form = guards).
/// Unknown annotations are silently ignored (forward-compatible).
#[must_use]
pub fn auth_set(func: &ContractFunction<'_>) -> BTreeSet<Guard> {
    let mut guards = BTreeSet::new();
    for ann in func.annotations {
        match ann.name.as_str() {
            "onlyOwner" => {
                guards.insert(Guard::OnlyOwner);
            }
            "onlyRole" => {
                // @onlyRole("ROLE") — first positional arg is the role name string.
                if let Some(AnnotationArg::Positional(Expr::Literal(Literal::Str(role), _))) =
                    ann.args.first()
                {
                    guards.insert(Guard::OnlyRole(role.clone()));
                }
            }
            "whenNotPaused" => {
                guards.insert(Guard::WhenNotPaused);
            }
            "whenPaused" => {
                guards.insert(Guard::WhenPaused);
            }
            "nonReentrant" => {
                guards.insert(Guard::NonReentrant);
            }
            _ => {}
        }
    }
    guards
}

// ─── Deleted: compute_eff_auth + all_auth_sets (P3 audit subtask 10) ─────────
//
// `compute_eff_auth` and `all_auth_sets` were deleted as dead code (AGENTS §1.3).
// Their consumer (SAFETY-001 EffAuth balance-direction symmetry, P3-rule-5)
// never materialized despite Steps 5/7 completing.  The 4f rules (005/007/009)
// use direct `auth_set` with self-contained transitive closures, which is sound
// for their queries.  If EffAuth symmetry is wanted later, assign a P4
// Track·Step and rebuild from the spec.

// ─── Guard predicates ─────────────────────────────────────────────────────────

/// Returns `true` if the guard set requires the `GOVERNANCE` role.
///
/// Per spec §2: "requires governance" means `@onlyRole("GOVERNANCE")`,
/// never `@onlyOwner`.
#[must_use]
pub fn requires_governance(guards: &BTreeSet<Guard>) -> bool {
    guards.contains(&Guard::OnlyRole("GOVERNANCE".to_owned()))
}

/// Returns `true` if the guard set requires owner-only access.
///
/// Part of the guard-predicate trio (`requires_governance` /
/// `requires_owner_only` / `is_access_unrestricted`).
///
/// Consumers:
/// - `check_own3a_missing_required_trait` in `rules/launch.rs` (P3-own-3 a)
///
/// Note: the renounced-owner skip in SAFETY-005/009 was reverted per spec §2.1
/// ("static rule remains conservative regardless of renounce").  The deferred
/// P3-own-3(c) consumer (Address.burn recognition) is tracked as
/// TODO(4f-launch/step6) in `rules/launch.rs`.
#[must_use]
pub fn requires_owner_only(guards: &BTreeSet<Guard>) -> bool {
    guards.contains(&Guard::OnlyOwner)
}

/// Returns `true` if the guard set has **no access-restriction** guards.
///
/// Access-restriction guards are `OnlyOwner` and `OnlyRole`.  `WhenNotPaused`,
/// `WhenPaused`, and `NonReentrant` are operational guards, not access
/// restrictions, and do **not** count toward being "restricted."
///
/// Used by SAFETY-001/009 to detect publicly callable state-mutating functions.
#[must_use]
pub fn is_access_unrestricted(guards: &BTreeSet<Guard>) -> bool {
    !guards.contains(&Guard::OnlyOwner) && !guards.iter().any(|g| matches!(g, Guard::OnlyRole(_)))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
