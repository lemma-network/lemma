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
/// Uses BFS over the call graph; cycles are handled by tracking visited nodes.
/// Returns `BTreeMap<fn_name, effective_guards>` for every reachable function.
#[must_use]
pub fn compute_eff_auth(
    entry_fn: &str,
    fn_guards: &BTreeMap<String, BTreeSet<Guard>>,
    call_graph: &CallGraph,
) -> BTreeMap<String, BTreeSet<Guard>> {
    let mut result: BTreeMap<String, BTreeSet<Guard>> = BTreeMap::new();
    let mut visited: BTreeSet<String> = BTreeSet::new();
    // Queue: (fn_name, accumulated_guards_so_far)
    let mut queue: Vec<(String, BTreeSet<Guard>)> = Vec::new();

    let entry_guards = fn_guards.get(entry_fn).cloned().unwrap_or_default();
    queue.push((entry_fn.to_owned(), entry_guards));

    while let Some((fn_name, accumulated)) = queue.pop() {
        if !visited.insert(fn_name.clone()) {
            continue; // Already processed — cycle guard.
        }
        result.insert(fn_name.clone(), accumulated.clone());

        if let Some(callees) = call_graph.get(&fn_name) {
            for callee in callees {
                if !visited.contains(callee) {
                    // EffAuth(callee) = accumulated ∪ Auth(callee)
                    let mut callee_guards = accumulated.clone();
                    if let Some(own) = fn_guards.get(callee) {
                        callee_guards.extend(own.iter().cloned());
                    }
                    queue.push((callee.clone(), callee_guards));
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

/// Returns `true` if the guard set is completely open (no access restrictions).
#[must_use]
pub fn is_unguarded(guards: &BTreeSet<Guard>) -> bool {
    !guards.contains(&Guard::OnlyOwner) && !guards.iter().any(|g| matches!(g, Guard::OnlyRole(_)))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
