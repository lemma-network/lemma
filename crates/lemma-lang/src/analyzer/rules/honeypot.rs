//! SAFETY-001 — Anti-Honeypot Symmetry.
//!
//! Prevents buyable-but-not-sellable tokens (the classic honeypot).  Lemma's
//! headline anti-scam guarantee.
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
//! when `config.antiHoneypot == true`, the disposal path (`transfer` /
//! `transferFrom`) must be **access-unrestricted** (anyone who holds can sell) and
//! no balance-decreasing public entry may be access-restricted while a
//! balance-mutating entry is public.
//!
//! ## Enforced (decidable over-approximation, option B — §24.1 realization)
//!
//! When `config.antiHoneypot == true`:
//! 1. **Disposal path must exist and be public**: `transfer` (and `transferFrom`
//!    if present) must be declared and access-unrestricted (`EffAuth`/`Auth` has
//!    no `@onlyOwner` / `@onlyRole`).  A missing or owner/role-gated `transfer` ⇒
//!    `Honeypot` (holders cannot freely sell).
//! 2. **No asymmetric balance-mutator guard**: if any `pub` function mutates
//!    `balances` and is access-restricted while another `pub` balance-mutator is
//!    public, the restricted one is an asymmetric disposal lever ⇒ `Honeypot`
//!    (catches `@onlyOwner sell()` alongside a public buy path).
//!
//! ## Cross-rule (not re-implemented here)
//!
//! - **One-way trading gate** blocking sells ⇒ caught by SAFETY-009 independently.
//! - **Owner-only blacklist** blocking a sell ⇒ caught by SAFETY-005.
//! - **Sell fee ≥ 100%** ⇒ caught by SAFETY-002.
//!
//! Under `antiHoneypot`, those rules' violations already reject the contract; this
//! rule adds the disposal-path existence + guard-symmetry check that is its unique
//! contribution (spec §3-001 step 3 "ties to SAFETY-009").
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
use crate::parser::{ConfigValue, Expr, Stmt};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_stmt, Visitor};

use crate::analyzer::error::SafetyError;

/// Check a contract for SAFETY-001 anti-honeypot violations.
///
/// Fires only when `config.antiHoneypot == true`.  Returns
/// [`SafetyError::Honeypot`] for a missing/restricted disposal path or an
/// asymmetric balance-mutator guard.  Returns an empty `Vec` when safe (or when
/// `antiHoneypot` is not enabled).
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    if !anti_honeypot_enabled(contract) {
        return violations;
    }

    let functions = contract.functions();

    // Check 1: a public disposal path (`transfer`) must exist and be unrestricted.
    let transfer = functions.iter().find(|f| f.name == "transfer");
    match transfer {
        None => {
            violations.push(SafetyError::Honeypot {
                reason: "antiHoneypot is set but the token has no `transfer` \
                         function — holders have no way to dispose of the token"
                    .to_owned(),
            });
        }
        Some(f) => {
            if !is_access_unrestricted(&auth_set(f)) {
                violations.push(SafetyError::Honeypot {
                    reason: "`transfer` is access-restricted (@onlyOwner / @onlyRole) \
                             while antiHoneypot is set — holders cannot freely sell"
                        .to_owned(),
                });
            }
        }
    }
    // `transferFrom`, if present, must likewise be unrestricted.
    if let Some(f) = functions.iter().find(|f| f.name == "transferFrom") {
        if !is_access_unrestricted(&auth_set(f)) {
            violations.push(SafetyError::Honeypot {
                reason: "`transferFrom` is access-restricted while antiHoneypot is \
                         set — the delegated disposal path is gated"
                    .to_owned(),
            });
        }
    }

    // Check 2: no asymmetric balance-mutator guard.  If some pub balance-mutator
    // is public (buy possible) and another pub balance-mutator is restricted, the
    // restricted one is an asymmetric disposal lever.
    let balance_mutators: Vec<&ContractFunction<'_>> = functions
        .iter()
        .filter(|f| is_public(f) && mutates_balances(f))
        .collect();
    let any_public = balance_mutators
        .iter()
        .any(|f| is_access_unrestricted(&auth_set(f)));
    if any_public {
        for f in &balance_mutators {
            // `transfer`/`transferFrom` already handled by Check 1 — avoid
            // duplicate violations.
            if f.name == "transfer" || f.name == "transferFrom" {
                continue;
            }
            if !is_access_unrestricted(&auth_set(f)) {
                violations.push(SafetyError::Honeypot {
                    reason: format!(
                        "`{}` mutates balances but is access-restricted while another \
                         balance-mutating entry is public — an asymmetric disposal lever",
                        f.name
                    ),
                });
            }
        }
    }

    violations
}

/// Returns `true` if `config.antiHoneypot == true`.
fn anti_honeypot_enabled(contract: &TypedContract<'_>) -> bool {
    let Some(config) = contract.config() else {
        return false;
    };
    config
        .iter()
        .find(|e| e.key == "antiHoneypot")
        .is_some_and(|e| matches!(e.value, ConfigValue::Bool(true)))
}

/// Returns `true` if `func` is publicly callable (`pub` / external visibility).
fn is_public(func: &ContractFunction<'_>) -> bool {
    use crate::parser::Visibility;
    matches!(func.visibility, Visibility::Pub | Visibility::External)
}

/// Returns `true` if `func` writes the `balances` state field (`self.balances[k]
/// = …` or `self.balances.set(k, …)`).
fn mutates_balances(func: &ContractFunction<'_>) -> bool {
    let Some(body) = func.body else {
        return false;
    };
    let mut scanner = BalanceWriteScanner { found: false };
    scanner.visit_stmts(body);
    scanner.found
}

/// Visitor detecting a write to `self.balances`.
struct BalanceWriteScanner {
    found: bool,
}

impl Visitor for BalanceWriteScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Assign { target, .. } = stmt {
            if is_balances_write_target(target) {
                self.found = true;
            }
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Assign_(target, _, _, _) if is_balances_write_target(target) => {
                self.found = true;
            }
            // self.balances.set(k, v) — collection-method write.
            Expr::Call { callee, .. } => {
                if let Expr::Member(recv, method, _) = callee.as_ref() {
                    if method == "set" {
                        if let Expr::Member(obj, field, _) = recv.as_ref() {
                            if is_self(obj) && field == "balances" {
                                self.found = true;
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        crate::visit::walk_expr(self, expr);
    }
}

/// Returns `true` if `target` is `self.balances` or `self.balances[k]`.
fn is_balances_write_target(target: &Expr) -> bool {
    match target {
        Expr::Member(obj, field, _) => is_self(obj) && field == "balances",
        Expr::Index(base, _, _) => {
            matches!(base.as_ref(), Expr::Member(obj, field, _) if is_self(obj) && field == "balances")
        }
        _ => false,
    }
}

/// Returns `true` if `expr` is the identifier `self`.
fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
