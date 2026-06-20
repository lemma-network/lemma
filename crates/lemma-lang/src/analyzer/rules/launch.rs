//! SAFETY-023 — maxWallet exempt interface + P3-own-3 (a)(c).
//!
//! ## Rule summary
//!
//! - **SAFETY-023** (`check_023_maxwallet_exempt`): A contract with `maxWallet`
//!   enabled must consult the wallet-exempt interface (`isWalletExempt` function
//!   or `walletExempt` state field) on the enforcement path.  WF-014 checks
//!   structural presence; SAFETY-023 checks semantic consultation.
//!
//! - **P3-own-3 (a)** (`check_own3a_missing_required_trait`): A function with
//!   `@onlyOwner` on a plain contract requires a state field named `owner`.
//!
//! ## RETIRED
//!
//! - **SAFETY-024** (all sub-checks): Retired per decision DB-A57.  Substring
//!   field-name detection was bypassable, redundant with SAFETY-009/005/002,
//!   and `MAX_ANTISNIPE_TAX` contradicted the anti-honeypot guarantee.
//!   Number 024 is retired and not reused (same pattern as SAFETY-013).
//!
//! ## Reject-on-doubt policy (spec §5.1)
//!
//! All checks use reject-on-doubt: if the contract cannot be *proven* safe,
//! it is rejected with `Inconclusive`.  Non-canonical shapes trigger
//! `Inconclusive` rather than a false-accept.
//!
//! ## Deferred enforcement
//!
//! - P3-own-3 (b): `@whenNotPaused` requires `Pausable` trait — deferred to Step 8.
//! - P3-own-3 (a) full: `contract.uses contains "Ownable"` — deferred to Step 8.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3-quater` and `living-notes.md`.

use crate::analyzer::authset::{auth_set, requires_owner_only};
use crate::analyzer::error::SafetyError;
use crate::analyzer::util::{is_self, is_transfer_path_entry};
use crate::lexer::token::Span;
use crate::parser::{Expr, Stmt};
use crate::type_checker::typed_contract::TypedContract;
use crate::visit::{walk_expr, walk_stmt, Visitor};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-023 and P3-own-3 (a)(c) violations.
///
/// Applies to Token, TaxToken, and plain contracts as appropriate.
/// Returns an empty `Vec` when the contract is safe.
///
/// SAFETY-024 RETIRED (DB-A57) — all checks deleted.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();
    violations.extend(check_023_maxwallet_exempt(contract));
    violations.extend(check_own3a_missing_required_trait(contract));
    violations
}

// ─── SAFETY-023 ───────────────────────────────────────────────────────────────

/// SAFETY-023: `maxWallet` enforcement path must consult the exempt interface.
///
/// Only fires when `config.maxWallet` is set (Token or TaxToken).
/// WF-014 checks structural presence of `isWalletExempt`/`walletExempt`;
/// SAFETY-023 checks that the enforcement function actually CALLS/READS it.
///
/// Reject-on-doubt: if no enforcement function is found → `Inconclusive`.
///
/// BUG-M2 fix: checks ALL transfer-path entries (not just the first).
/// `transfer` may consult exempt but `transferFrom` may not — both must be checked.
fn check_023_maxwallet_exempt(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    // Only fires when maxWallet is declared in config.
    let Some(config) = contract.config() else {
        return Vec::new();
    };
    if !config.iter().any(|e| e.key == "maxWallet") {
        return Vec::new();
    }

    // Find ALL enforcement functions: non-view functions named "transfer",
    // "transferFrom", or annotated `#[onTransfer]` are the canonical enforcement
    // path for maxWallet (the cap is checked on every transfer).
    // BUG-M2: use .filter() not .find() — every transfer-path entry must consult exempt.
    let enforcers: Vec<_> = contract
        .functions()
        .into_iter()
        .filter(|f| is_transfer_path_entry(f))
        .collect();

    if enforcers.is_empty() {
        // No transfer-path function visible — cannot verify enforcement.
        return vec![SafetyError::Inconclusive {
            rule: "SAFETY-023",
            reason: "maxWallet enforcement path not analyzable — use canonical cap-check pattern \
                     (add `transfer`, `transferFrom`, or `#[onTransfer]` function)"
                .to_owned(),
            span: Span::at(0, 0, 0),
        }];
    }

    let mut violations = Vec::new();
    for enforcer in &enforcers {
        let Some(body) = enforcer.body else {
            continue;
        };

        // Check: does this enforcer call `isWalletExempt` or read `walletExempt`?
        let mut scanner = ExemptConsultationScanner { found: false };
        scanner.visit_stmts(body);

        if !scanner.found {
            violations.push(SafetyError::MaxWalletNoExempt {
                func: enforcer.name.to_owned(),
            });
        }
    }

    violations
}

// ─── P3-own-3 (a) ─────────────────────────────────────────────────────────────

/// P3-own-3 (a): `@onlyOwner` on a plain contract requires state field `owner`.
///
/// For Token/TaxToken standards: skip — the standard implicitly has Ownable.
/// For plain contracts: if `@onlyOwner` used and no `owner` state field → violation.
///
/// Deferred: full `uses Ownable` trait requirement → Step 8.
///
/// TODO(4f-launch/step8): full Ownable/Pausable/AccessControl trait check — deferred, P3-own-1
fn check_own3a_missing_required_trait(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    // Token/TaxToken standards implicitly have Ownable — skip.
    if contract.base_standard().is_some() {
        return Vec::new();
    }

    // Check if any function uses @onlyOwner.
    let only_owner_fns: Vec<&str> = contract
        .functions()
        .into_iter()
        .filter(|f| requires_owner_only(&auth_set(f)))
        .map(|f| f.name)
        .collect();

    if only_owner_fns.is_empty() {
        return Vec::new();
    }

    // Check: does the contract have a state field named `owner`?
    let has_owner_field = contract
        .state_fields()
        .into_iter()
        .any(|f| f.name == "owner");

    if has_owner_field {
        return Vec::new();
    }

    // No `owner` state field — emit one violation per @onlyOwner function.
    only_owner_fns
        .into_iter()
        .map(|func_name| SafetyError::MissingRequiredTrait {
            func: func_name.to_owned(),
            annotation: "onlyOwner".to_owned(),
        })
        .collect()
}

// ─── P3-own-3 (c) helper ──────────────────────────────────────────────────────

/// Detect whether this contract has renounce capability.
///
/// Returns `true` if the contract has a `renounce` function that writes the
/// `owner` state field.
///
/// NOT used for skipping SAFETY-005/009 violations — spec §2.1 requires
/// those rules to remain conservative regardless of renounce:
/// *"static rule remains conservative — owner-settable restriction is a
/// violation regardless of whether the deployer later renounces."*
///
/// Reserved for informational purposes or future Step-6 use when
/// Address.burn recognition is available.
///
/// TODO(4f-launch/step6): wire into auth treatment when Address.burn
/// is available — deferred P3-own-3(c), P3-own-2.
///
/// Deferred: `Address.burn` recognition for the renounce write → Step 6.
/// Currently uses name-based check ("writes to state field named `owner`").
#[allow(dead_code)]
fn is_renounce_aware(contract: &TypedContract<'_>) -> bool {
    contract.functions().into_iter().any(|f| {
        f.name == "renounce" && {
            let Some(body) = f.body else {
                return false;
            };
            let mut scanner = OwnerFieldWriteScanner { found: false };
            scanner.visit_stmts(body);
            scanner.found
        }
    })
}

// ─── Visitors ─────────────────────────────────────────────────────────────────

/// Visitor that detects consultation of the wallet-exempt interface.
///
/// Looks for:
/// - A call to `isWalletExempt` (any receiver)
/// - A read of `self.walletExempt`
struct ExemptConsultationScanner {
    found: bool,
}

impl Visitor for ExemptConsultationScanner {
    fn visit_expr(&mut self, expr: &Expr) {
        if self.found {
            return;
        }
        match expr {
            // `self.walletExempt` read
            Expr::Member(obj, field, _) if is_self(obj) && field == "walletExempt" => {
                self.found = true;
                return;
            }
            // `self.walletExempt[addr]` read
            Expr::Index(base, _, _) => {
                if let Expr::Member(obj, field, _) = base.as_ref() {
                    if is_self(obj) && field == "walletExempt" {
                        self.found = true;
                        return;
                    }
                }
            }
            // `<any>.isWalletExempt(...)` call
            Expr::Call { callee, .. } => {
                if let Expr::Member(_, method, _) = callee.as_ref() {
                    if method == "isWalletExempt" {
                        self.found = true;
                        return;
                    }
                }
                // bare `isWalletExempt(...)` call
                if let Expr::Ident(name, _) = callee.as_ref() {
                    if name == "isWalletExempt" {
                        self.found = true;
                        return;
                    }
                }
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

/// Visitor that detects writes to `self.owner`.
///
/// Used by `is_renounce_aware` to check whether a `renounce` function
/// writes the `owner` state field (permanently locking `@onlyOwner` levers).
struct OwnerFieldWriteScanner {
    found: bool,
}

impl Visitor for OwnerFieldWriteScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if self.found {
            return;
        }
        if let Stmt::Assign { target, .. } = stmt {
            if is_owner_field_write(target) {
                self.found = true;
                return;
            }
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        if self.found {
            return;
        }
        if let Expr::Assign_(target, _, _, _) = expr {
            if is_owner_field_write(target) {
                self.found = true;
                return;
            }
        }
        walk_expr(self, expr);
    }
}

/// Returns `true` if `target` is a write to `self.owner`.
fn is_owner_field_write(target: &Expr) -> bool {
    matches!(target, Expr::Member(obj, field, _) if is_self(obj) && field == "owner")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
