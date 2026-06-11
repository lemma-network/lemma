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
//! 2. **Restriction functions**: a function that writes a restriction field with
//!    a **parameter-specified address** key — `self.<field>[param] = …` or
//!    `self.<field>.add(param)` / `.insert(param)`, where `param` is one of the
//!    function's parameters (a caller-chosen address ⇒ a per-address blacklist).
//! 3. **Governance check**: each restriction function's `Auth(f)` must resolve to
//!    the `GOVERNANCE` role.  `@onlyOwner` / unguarded ⇒ `UngovernedBlacklist`.
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

use std::collections::BTreeSet;

use crate::analyzer::authset::{auth_set, requires_governance};
use crate::analyzer::dataflow::restriction_fields;
use crate::parser::{CallArg, Expr, Stmt};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_expr, walk_stmt, Visitor};

use crate::analyzer::error::SafetyError;

/// Check a contract for SAFETY-005 blacklist-governance violations.
///
/// Returns one [`SafetyError::UngovernedBlacklist`] per function that can freeze
/// a parameter-specified address (write a restriction field keyed by a param)
/// without GOVERNANCE authority.  Returns an empty `Vec` when safe.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    let restriction = restriction_fields(contract);
    if restriction.is_empty() {
        return violations;
    }

    for func in contract.functions() {
        let Some(body) = func.body else {
            continue;
        };
        // Is this a per-address restriction writer (blacklist setter)?
        if !writes_restriction_for_param(&func, body, &restriction) {
            continue;
        }
        // It must be GOVERNANCE-gated.
        let guards = auth_set(&func);
        if !requires_governance(&guards) {
            violations.push(SafetyError::UngovernedBlacklist {
                func: func.name.to_owned(),
            });
        }
    }

    violations
}

/// Returns `true` if `func` writes one of the `restriction` fields with a key
/// that is one of `func`'s own parameters (a per-address blacklist write).
fn writes_restriction_for_param(
    func: &ContractFunction<'_>,
    body: &[Stmt],
    restriction: &BTreeSet<String>,
) -> bool {
    let params: BTreeSet<&str> = func.params.iter().map(|p| p.name.as_str()).collect();
    let mut scanner = ParamKeyedWriteScanner {
        restriction,
        params: &params,
        found: false,
    };
    scanner.visit_stmts(body);
    scanner.found
}

/// Visitor that detects param-keyed writes to a restriction field:
/// - `self.<field>[<param>] = …`     (Map index assignment)
/// - `self.<field>.add(<param>)`      (Set insert)
/// - `self.<field>.insert(<param>)`   (Map/Set insert)
struct ParamKeyedWriteScanner<'a> {
    restriction: &'a BTreeSet<String>,
    params: &'a BTreeSet<&'a str>,
    found: bool,
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
            // Method-call insert: self.field.add(param) / .insert(param)
            Expr::Call { callee, args, .. } => {
                self.check_collection_insert(callee, args);
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
                    self.found = true;
                }
            }
        }
    }

    /// Detect `self.<restriction_field>.add(<param>)` / `.insert(<param>)`.
    fn check_collection_insert(&mut self, callee: &Expr, args: &[CallArg]) {
        let Expr::Member(recv, method, _) = callee else {
            return;
        };
        if method != "add" && method != "insert" {
            return;
        }
        // Receiver must be `self.<restriction_field>`.
        let Expr::Member(obj, field, _) = recv.as_ref() else {
            return;
        };
        if !is_self(obj) || !self.restriction.contains(field) {
            return;
        }
        // Any argument that is a parameter ⇒ a param-keyed restriction write.
        for arg in args {
            let e = match arg {
                CallArg::Positional(e) | CallArg::Named(_, e) => e,
            };
            if self.is_param(e) {
                self.found = true;
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
