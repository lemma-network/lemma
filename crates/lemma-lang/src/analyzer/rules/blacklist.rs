//! SAFETY-005 — Blacklist Governance.
//!
//! Prevents owner-only address freezing (a censorship/rug lever).
//!
//! ## True property (spec §3-005)
//!
//! "Any function that can block a specific address's transfers requires
//! governance, not a single owner."
//!
//! ## Enforced (decidable-exact over annotations)
//!
//! 1. **Restriction fields** (`restriction_fields`, 4f-0): `state` fields read on
//!    the transfer path to *deny* a transfer.
//! 2. **Blacklist fields**: a restriction field that is written **param-keyed**
//!    by any function — `self.<field>[param] = …` (Map index), `self.<field>.set(
//!    param, …)` (Map set), or `self.<field>.add(param)` (Set add), where `param`
//!    is one of the writing function's parameters (a caller-chosen key ⇒ a
//!    per-address blacklist).
//! 3. **Levers (transitive)**: every function that can **transitively** write a
//!    blacklist field (via `state_write_reachability`, mirroring SAFETY-007).
//!    This catches an `@onlyOwner` public entry that freezes via an internal
//!    helper — the owner entry is the real authority lever.
//! 4. **Governance check**: each lever's `Auth(f)` must resolve to the
//!    `GOVERNANCE` role.  `@onlyOwner` / unguarded ⇒ `UngovernedBlacklist`.
//!
//! ## Soundness boundary (documented, not faked)
//!
//! The param-key linkage is detected at the **write site** (the function whose
//! own parameter is the key).  A blacklist that launders the caller address
//! through a `state` field before using it as the key
//! (`ban(addr){ self.pending = addr } / commit(){ frozen[self.pending] = true }`)
//! requires inter-procedural field-taint and is **not** caught here — it slips to
//! SAFETY-010 (the field write `frozen[self.pending]` still makes `frozen` a
//! reachable restriction write, and the transitive lever check gates `commit`'s
//! reachers if `commit` itself is param-keyed; the pure field-laundered form is a
//! known boundary, tracked for the Step-5 state-access taint pass).
//!
//! ## Distinction from SAFETY-009 (one-way gates)
//!
//! SAFETY-009 polices a **global** boolean gate (`tradingEnabled`) being flipped
//! back to blocking.  SAFETY-005 polices a **per-address** restriction
//! (`frozen[addr]`) keyed by a function parameter — who can freeze a *specific*
//! address.  A field may trigger both rules independently.
//!
//! ## Soundness
//!
//! Decidable-exact over annotations.  A blacklist implemented via an external
//! contract slips to SAFETY-010 (declaration-forcing).  Reuses
//! `restriction_fields` (4f-0) + `auth_set`/`requires_governance` (4b).
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-005`.

use std::collections::{BTreeMap, BTreeSet};

use crate::analyzer::authset::{auth_set, requires_governance};
use crate::analyzer::cfg::build_call_graph;
use crate::analyzer::dataflow::restriction_fields;
use crate::parser::{CallArg, Expr, Stmt};
use crate::type_checker::typed_contract::TypedContract;
use crate::visit::{walk_expr, walk_stmt, Visitor};

use crate::analyzer::error::SafetyError;

/// Check a contract for SAFETY-005 blacklist-governance violations.
///
/// Returns one [`SafetyError::UngovernedBlacklist`] per function that can
/// (transitively) freeze a parameter-specified address without GOVERNANCE
/// authority.  Returns an empty `Vec` when safe.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    let restriction = restriction_fields(contract);
    if restriction.is_empty() {
        return violations;
    }

    // Step 1: per-function DIRECT param-keyed blacklist writers.
    //
    // NOTE: we do NOT use `state_write_reachability` here — `cfg::state_write_key`
    // only recognises `self.f = …` / `self.f[k] = …` assignment targets and is
    // BLIND to collection-method mutations (`self.f.set(k,v)` / `self.f.add(t)`),
    // which are exactly the blacklist write forms (spec §13).  So we detect the
    // direct param-keyed writers ourselves (this scanner sees `.set`/`.add`) and
    // close transitively over the call graph below.  (The cfg blind spot is
    // tracked as debt — it also affects SAFETY-003/004/007.)
    let direct: BTreeSet<String> = direct_param_keyed_writers(contract, &restriction);
    if direct.is_empty() {
        return violations;
    }

    // Step 2: levers = direct writers + every function that transitively calls a
    // lever (the @onlyOwner public entry that freezes via an internal helper).
    let call_graph = build_call_graph(contract);
    let levers = transitive_callers(&direct, &call_graph);

    // Step 3: each lever must be GOVERNANCE-gated.
    for func in contract.functions() {
        if !levers.contains(func.name) {
            continue;
        }
        let guards = auth_set(&func);
        if !requires_governance(&guards) {
            violations.push(SafetyError::UngovernedBlacklist {
                func: func.name.to_owned(),
            });
        }
    }

    violations
}

/// Functions that **directly** write a restriction field with a param key.
fn direct_param_keyed_writers(
    contract: &TypedContract<'_>,
    restriction: &BTreeSet<String>,
) -> BTreeSet<String> {
    let mut writers = BTreeSet::new();
    for func in contract.functions() {
        let Some(body) = func.body else {
            continue;
        };
        let params: BTreeSet<&str> = func.params.iter().map(|p| p.name.as_str()).collect();
        let mut found = false;
        let mut scanner = ParamKeyedWriteScanner {
            restriction,
            params: &params,
            found: &mut found,
        };
        scanner.visit_stmts(body);
        if found {
            writers.insert(func.name.to_owned());
        }
    }
    writers
}

/// Compute the transitive closure of `seed` over reversed call edges: a function
/// is included if it is a seed or it (transitively) calls a seed.
///
/// `call_graph[caller] = {callees}`.  We propagate membership backward from
/// callee to caller until a fixpoint (sets grow monotonically over a finite
/// function universe → terminates, including on cyclic graphs).
fn transitive_callers(
    seed: &BTreeSet<String>,
    call_graph: &BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut levers = seed.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for (caller, callees) in call_graph {
            if levers.contains(caller) {
                continue;
            }
            if callees.iter().any(|c| levers.contains(c)) {
                levers.insert(caller.clone());
                changed = true;
            }
        }
    }
    levers
}

/// Visitor that detects param-keyed writes to a restriction field and records
/// the field name.  The Lem collection mutator surface (spec §13, `03 §13`):
/// - `self.<field>[<param>] = …`     (Map index assignment)
/// - `self.<field>.set(<param>, …)`   (Map set — `balances.set(addr, v)`)
/// - `self.<field>.add(<param>)`      (Set add — `voters.add(addr)`)
///
/// (`insert` is an `Array` positional method, **not** a Map/Set key mutator, so
/// it is intentionally excluded — see spec `03 §13` collection methods.)
struct ParamKeyedWriteScanner<'a> {
    restriction: &'a BTreeSet<String>,
    params: &'a BTreeSet<&'a str>,
    found: &'a mut bool,
}

impl Visitor for ParamKeyedWriteScanner<'_> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Assign { target, .. } = stmt {
            self.check_index_write(target);
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            // Expression-form index assignment: self.field[param] = …
            Expr::Assign_(target, _, _, _) => {
                self.check_index_write(target);
            }
            // Method-call key write: self.field.set(param, …) / .add(param)
            Expr::Call { callee, args, .. } => {
                self.check_collection_write(callee, args);
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

impl ParamKeyedWriteScanner<'_> {
    /// Detect `self.<restriction_field>[<param>] = …`.
    fn check_index_write(&mut self, target: &Expr) {
        if let Expr::Index(base, key, _) = target {
            if let Expr::Member(obj, field, _) = base.as_ref() {
                if is_self(obj) && self.restriction.contains(field) && self.is_param(key) {
                    *self.found = true;
                }
            }
        }
    }

    /// Detect `self.<restriction_field>.set(<param>, …)` / `.add(<param>)`.
    fn check_collection_write(&mut self, callee: &Expr, args: &[CallArg]) {
        let Expr::Member(recv, method, _) = callee else {
            return;
        };
        // Map.set(k, v) and Set.add(t) are the key-mutating collection methods.
        if method != "set" && method != "add" {
            return;
        }
        // Receiver must be `self.<restriction_field>`.
        let Expr::Member(obj, field, _) = recv.as_ref() else {
            return;
        };
        if !is_self(obj) || !self.restriction.contains(field) {
            return;
        }
        // The KEY is the first argument (`set(key, val)` / `add(key)`); a param
        // key ⇒ a per-address blacklist write.
        if let Some(first) = args.first() {
            let e = match first {
                CallArg::Positional(e) | CallArg::Named(_, e) => e,
            };
            if self.is_param(e) {
                *self.found = true;
            }
        }
    }

    /// Returns `true` if `expr` is an identifier that names a function parameter.
    fn is_param(&self, expr: &Expr) -> bool {
        matches!(expr, Expr::Ident(name, _) if self.params.contains(name.as_str()))
    }
}

/// Returns `true` if `expr` is the identifier `self`.
fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
