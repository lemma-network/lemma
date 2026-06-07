//! Authorization-set analysis — `Auth(f)` and `EffAuth`.
//
// Justified `dead_code` (entire module): all pub(crate) APIs are called by the
// SAFETY-rule modules (4d–4f) and by `authset/tests.rs`.  The rule modules do
// not exist yet; no production caller outside tests is wired until 4d.
// Remove this allow once 4d lands (the first rule caller will suppress it).
#![allow(dead_code)]
//!
//! ## Purpose
//!
//! Foundational analysis consumed by multiple SAFETY rules:
//!
//! - **`Auth(f)`** (`auth_set`): the guard set declared directly on function `f`
//!   via `@`-annotations (`@onlyOwner`, `@onlyRole("GOVERNANCE")`, etc.).
//! - **`EffAuth(f, entry)`** (`compute_eff_auth`): the *effective* guard set
//!   when `f` is reached from a `pub` entry function.  This is the union of
//!   `Auth(entry)` and the `Auth` of every internal function on the call path
//!   from `entry` to `f`.  Used by SAFETY-001/005/007/009.
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

use std::collections::{BTreeMap, BTreeSet};

use crate::parser::{AnnotationArg, Expr, Literal};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};

use super::cfg::CallGraph;

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

// ─── EffAuth ──────────────────────────────────────────────────────────────────

/// Compute effective guard sets for all functions reachable from a single
/// `pub` entry function.
///
/// `EffAuth(callee, entry)` = `Auth(entry)` ∪ `Auth(fn1)` ∪ … ∪ `Auth(callee)`
/// for every internal function on the call path from `entry` to `callee`.
///
/// ## Multi-path semantics (soundness)
///
/// When a callee is reachable via **multiple paths** (e.g. a diamond call graph:
/// `entry → A → helper` and `entry → B → helper`), the effective guard set is
/// the **intersection** of per-path sets — the weakest guarantee across all
/// paths.  This is the sound conservative value for "is this mutation
/// adequately guarded?" queries (SAFETY-001/002/009): if any path to the node
/// is unguarded, the node is reachable without the guard.
///
/// ## Algorithm
///
/// Monotone fixpoint iteration over a worklist.  The guard-set lattice is
/// ordered by ⊆; the merge operator is ∩ (meet).  Since intersection is
/// monotonically decreasing and guard sets are finite, the algorithm always
/// terminates.  Cycles (recursion) are handled naturally: a function is
/// re-added to the worklist only when its guard set shrinks.
#[must_use]
pub fn compute_eff_auth(
    entry_fn: &str,
    fn_guards: &BTreeMap<String, BTreeSet<Guard>>,
    call_graph: &CallGraph,
) -> BTreeMap<String, BTreeSet<Guard>> {
    let mut result: BTreeMap<String, BTreeSet<Guard>> = BTreeMap::new();
    // Worklist: (fn_name, accumulated_guards_from_caller)
    let mut worklist: std::collections::VecDeque<(String, BTreeSet<Guard>)> =
        std::collections::VecDeque::new();

    let entry_own = fn_guards.get(entry_fn).cloned().unwrap_or_default();
    worklist.push_back((entry_fn.to_owned(), entry_own));

    while let Some((fn_name, incoming)) = worklist.pop_front() {
        // EffAuth at fn_name = incoming (from caller) ∪ own guards.
        let own = fn_guards.get(&fn_name).cloned().unwrap_or_default();
        let new_guards: BTreeSet<Guard> = incoming.union(&own).cloned().collect();

        let changed = match result.get(&fn_name) {
            None => {
                result.insert(fn_name.clone(), new_guards.clone());
                true
            }
            Some(existing) => {
                // Multi-path merge: intersect to get weakest guarantee.
                // If any path carries fewer guards, the intersection shrinks.
                let merged: BTreeSet<Guard> = existing.intersection(&new_guards).cloned().collect();
                if &merged == existing {
                    false // Fixpoint reached for this function.
                } else {
                    result.insert(fn_name.clone(), merged);
                    true
                }
            }
        };

        // Re-queue callees only when the effective guard set changed.
        // Self-recursion terminates: the second visit yields merged == existing
        // (intersecting a set with itself), so `changed` is false and no
        // re-queue happens — fixpoint reached.
        if changed {
            if let Some(callees) = call_graph.get(&fn_name) {
                let fn_eff = result.get(&fn_name).cloned().unwrap_or_default();
                for callee in callees {
                    worklist.push_back((callee.clone(), fn_eff.clone()));
                }
            }
        }
    }
    result
}

/// Collect `Auth(f)` for every function in a contract.
///
/// Convenience wrapper used by `compute_eff_auth` callers.
#[must_use]
pub fn all_auth_sets(contract: &TypedContract<'_>) -> BTreeMap<String, BTreeSet<Guard>> {
    contract
        .functions()
        .into_iter()
        .map(|f| (f.name.to_owned(), auth_set(&f)))
        .collect()
}

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
