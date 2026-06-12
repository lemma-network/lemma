//! SAFETY-023/024 — Launch/holding-control rules + P3-own-3 (a)(c).
//!
//! ## Rule summary
//!
//! - **SAFETY-023** (`check_023_maxwallet_exempt`): A contract with `maxWallet`
//!   enabled must consult the wallet-exempt interface (`isWalletExempt` function
//!   or `walletExempt` state field) on the enforcement path.  WF-014 checks
//!   structural presence; SAFETY-023 checks semantic consultation.
//!
//! - **SAFETY-024.1** (`check_024_antsnipe_fee_not_block`): Anti-snipe logic
//!   must apply a bounded fee, never block/revert a transfer.
//!
//! - **SAFETY-024.2** (`check_024_has_expiry`): Launch-control logic must
//!   consult the `duration` config key on the enforcement path (self-expiring).
//!
//! - **SAFETY-024.3** (`check_024_no_sniper_gates_disposal`): A sniper-tracking
//!   state field must not gate the sell/transfer path with a revert.
//!
//! - **SAFETY-024.4** (sub-check 4 — enableTrading one-way): Already handled
//!   by SAFETY-009 (`one_way_gate.rs`).  Not duplicated here.
//!
//! - **P3-own-3 (a)** (`check_own3a_missing_required_trait`): A function with
//!   `@onlyOwner` on a plain contract requires a state field named `owner`.
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
//! - SAFETY-024 sub-check 4 (enableTrading one-way): handled by SAFETY-009.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3-quater` and `living-notes.md`.

use std::collections::BTreeSet;

use crate::analyzer::authset::{auth_set, requires_owner_only};
use crate::analyzer::error::SafetyError;
use crate::analyzer::util::is_self;
use crate::lexer::token::Span;
use crate::parser::{Expr, Stmt};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_expr, walk_stmt, Visitor};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-023, SAFETY-024, and P3-own-3 (a)(c) violations.
///
/// Applies to Token, TaxToken, and plain contracts as appropriate.
/// Returns an empty `Vec` when the contract is safe.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();
    violations.extend(check_023_maxwallet_exempt(contract));
    violations.extend(check_024_antsnipe_fee_not_block(contract));
    violations.extend(check_024_has_expiry(contract));
    violations.extend(check_024_no_sniper_gates_disposal(contract));
    // SAFETY-024 sub-check 4 (enableTrading one-way): handled by SAFETY-009.
    // See one_way_gate.rs — not duplicated here.
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
fn check_023_maxwallet_exempt(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    // Only fires when maxWallet is declared in config.
    let Some(config) = contract.config() else {
        return Vec::new();
    };
    if !config.iter().any(|e| e.key == "maxWallet") {
        return Vec::new();
    }

    // Find the enforcement function: a non-view function that reads maxWallet
    // from config or enforces the cap.  Heuristic: functions named "transfer",
    // "transferFrom", or annotated `#[onTransfer]` are the canonical enforcement
    // path for maxWallet (the cap is checked on every transfer).
    let enforcer = contract
        .functions()
        .into_iter()
        .find(|f| is_transfer_path_entry(f.name, f.annotations));

    let Some(enforcer) = enforcer else {
        // No transfer-path function visible — cannot verify enforcement.
        return vec![SafetyError::Inconclusive {
            rule: "SAFETY-023",
            reason: "maxWallet enforcement path not analyzable — use canonical cap-check pattern \
                     (add `transfer`, `transferFrom`, or `#[onTransfer]` function)"
                .to_owned(),
            span: Span::at(0, 0, 0),
        }];
    };

    let Some(body) = enforcer.body else {
        return Vec::new();
    };

    // Check: does the enforcer call `isWalletExempt` or read `walletExempt`?
    let mut scanner = ExemptConsultationScanner { found: false };
    scanner.visit_stmts(body);

    if scanner.found {
        Vec::new()
    } else {
        vec![SafetyError::MaxWalletNoExempt {
            func: enforcer.name.to_owned(),
        }]
    }
}

// ─── SAFETY-024.1 ─────────────────────────────────────────────────────────────

/// SAFETY-024.1: Anti-snipe logic must be a fee, not a block/revert.
///
/// Only fires when `config.fairLaunch` is set (Token or TaxToken).
/// Finds functions that reference `antiSnipeBlocks` and checks whether the
/// snipe-window path reverts/blocks rather than applying a fee.
///
/// Reject-on-doubt: if the snipe-window logic is not canonical → `Inconclusive`.
fn check_024_antsnipe_fee_not_block(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    if !has_fair_launch(contract) {
        return Vec::new();
    }

    // Find functions that reference antiSnipeBlocks (the snipe-window enforcer).
    let snipe_fns: Vec<ContractFunction<'_>> = contract
        .functions()
        .into_iter()
        .filter(|f| {
            f.body.is_some_and(|body| {
                let mut s = FieldReadScanner {
                    field: "antiSnipeBlocks",
                    found: false,
                };
                s.visit_stmts(body);
                s.found
            })
        })
        .collect();

    if snipe_fns.is_empty() {
        // No function references antiSnipeBlocks — cannot verify.
        return vec![SafetyError::Inconclusive {
            rule: "SAFETY-024",
            reason: "fairLaunch declared but no function references `antiSnipeBlocks` — \
                     cannot verify anti-snipe is a fee (add canonical snipe-window logic)"
                .to_owned(),
            span: Span::at(0, 0, 0),
        }];
    }

    let mut violations = Vec::new();
    for func in &snipe_fns {
        let Some(body) = func.body else {
            continue;
        };

        // Check: does the snipe-window path contain a revert (block)?
        // Canonical pattern: `if inSnipeWindow { self.fee += extraFee }` (OK).
        // Dangerous pattern: `if inSnipeWindow { revert }` (block).
        let mut scanner = SnipeWindowRevertScanner { found: false };
        scanner.visit_stmts(body);

        if scanner.found {
            violations.push(SafetyError::AntiSnipeIsBlock {
                func: func.name.to_owned(),
            });
        }
    }

    violations
}

// ─── SAFETY-024.2 ─────────────────────────────────────────────────────────────

/// SAFETY-024.2: Launch-control logic must consult `duration` (self-expiring).
///
/// Only fires when `config.fairLaunch` is set.
/// `duration` is now mandatory in WF-014 (Step 1) — if it passes WF-014,
/// `duration` is declared.  SAFETY-024.2 checks that the enforcement path
/// actually READS `duration` (not just declared in config).
///
/// Reject-on-doubt: if enforcement path doesn't consult duration → `LaunchControlNotExpiring`.
fn check_024_has_expiry(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    if !has_fair_launch(contract) {
        return Vec::new();
    }

    // Find functions that enforce launch-window logic (reference antiSnipeBlocks
    // or cooldownBetweenBuys — the canonical launch-window enforcement functions).
    let launch_fns: Vec<ContractFunction<'_>> = contract
        .functions()
        .into_iter()
        .filter(|f| {
            f.body.is_some_and(|body| {
                let mut s1 = FieldReadScanner {
                    field: "antiSnipeBlocks",
                    found: false,
                };
                s1.visit_stmts(body);
                let mut s2 = FieldReadScanner {
                    field: "cooldownBetweenBuys",
                    found: false,
                };
                s2.visit_stmts(body);
                s1.found || s2.found
            })
        })
        .collect();

    if launch_fns.is_empty() {
        // No launch-window enforcement function found — cannot verify expiry.
        return vec![SafetyError::Inconclusive {
            rule: "SAFETY-024",
            reason: "fairLaunch declared but no function enforces launch-window logic — \
                     cannot verify duration expiry (add canonical launch-window enforcement)"
                .to_owned(),
            span: Span::at(0, 0, 0),
        }];
    }

    let mut violations = Vec::new();
    for func in &launch_fns {
        let Some(body) = func.body else {
            continue;
        };

        // Check: does the enforcement function read `duration`?
        // Canonical pattern: `if block.height < launchBlock + duration { ... }`
        let mut scanner = FieldReadScanner {
            field: "duration",
            found: false,
        };
        scanner.visit_stmts(body);

        if !scanner.found {
            violations.push(SafetyError::LaunchControlNotExpiring {
                func: func.name.to_owned(),
            });
        }
    }

    violations
}

// ─── SAFETY-024.3 ─────────────────────────────────────────────────────────────

/// SAFETY-024.3: Sniper-tracking fields must not gate the sell/transfer path.
///
/// Only fires when `config.fairLaunch` is set.
/// Finds state fields whose names contain "sniper"/"Sniper" and checks whether
/// they are read on the transfer path to BLOCK (revert) a transfer.
///
/// Reuses the restriction-field pattern from SAFETY-005 (dataflow.rs) but
/// scoped to sniper-named fields.
fn check_024_no_sniper_gates_disposal(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    if !has_fair_launch(contract) {
        return Vec::new();
    }

    // Find sniper-tracking state fields (name contains "sniper" case-insensitively).
    let sniper_fields: BTreeSet<String> = contract
        .state_fields()
        .into_iter()
        .filter(|f| f.name.to_lowercase().contains("sniper"))
        .map(|f| f.name.to_owned())
        .collect();

    if sniper_fields.is_empty() {
        return Vec::new();
    }

    // Check: are any sniper fields read on the transfer path to BLOCK a transfer?
    // Pattern: same as restriction_fields analysis but scoped to sniper fields.
    let mut violations = Vec::new();
    for func in contract.functions() {
        if !is_transfer_path_entry(func.name, func.annotations) {
            continue;
        }
        let Some(body) = func.body else {
            continue;
        };

        let mut scanner = SniperFieldDenialScanner {
            sniper_fields: &sniper_fields,
            found_func: None,
        };
        scanner.visit_stmts(body);

        if let Some(field_name) = scanner.found_func {
            violations.push(SafetyError::AntiSnipeIsBlock {
                func: format!(
                    "{} (sniper field `{}` gates transfer)",
                    func.name, field_name
                ),
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

/// Returns `true` if the contract has a `renounce` function that writes the
/// `owner` state field — the owner can permanently lock `@onlyOwner` levers.
///
/// When true: `@onlyOwner` levers are LOCKED (nobody can call them post-renounce),
/// which is SAFER than governance.  SAFETY-005/009 should skip violations for
/// such contracts.
///
/// Deferred: `Address.burn` recognition for the renounce write → Step 6.
/// Currently uses name-based check ("writes to state field named `owner`").
#[must_use]
pub(crate) fn is_renounce_aware(contract: &TypedContract<'_>) -> bool {
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

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `config.fairLaunch` is set on this contract.
fn has_fair_launch(contract: &TypedContract<'_>) -> bool {
    contract
        .config()
        .is_some_and(|cfg| cfg.iter().any(|e| e.key == "fairLaunch"))
}

/// Returns `true` if `name`/`annotations` identify a transfer-path entry.
fn is_transfer_path_entry(name: &str, annotations: &[crate::parser::Annotation]) -> bool {
    name == "transfer"
        || name == "transferFrom"
        || annotations.iter().any(|a| a.name == "onTransfer")
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

/// Visitor that detects reads of a specific config/state field by name.
///
/// Used to check whether a function reads `antiSnipeBlocks`, `cooldownBetweenBuys`,
/// or `duration` from config or state.
struct FieldReadScanner<'a> {
    field: &'a str,
    found: bool,
}

impl Visitor for FieldReadScanner<'_> {
    fn visit_expr(&mut self, expr: &Expr) {
        if self.found {
            return;
        }
        // `self.<field>` read
        if let Expr::Member(obj, name, _) = expr {
            if is_self(obj) && name == self.field {
                self.found = true;
                return;
            }
        }
        // `self.<field>[key]` read
        if let Expr::Index(base, _, _) = expr {
            if let Expr::Member(obj, name, _) = base.as_ref() {
                if is_self(obj) && name == self.field {
                    self.found = true;
                    return;
                }
            }
        }
        // Identifier matching the field name (config reads may appear as bare idents
        // in some Lem patterns — conservative over-approximation).
        if let Expr::Ident(name, _) = expr {
            if name == self.field {
                self.found = true;
                return;
            }
        }
        walk_expr(self, expr);
    }
}

/// Visitor that detects a `revert` statement inside a snipe-window condition.
///
/// Scans for `if (...) { revert }` patterns where the condition references
/// snipe-window logic.  Over-approximation: any revert in the function body
/// is flagged (reject-on-doubt — canonical anti-snipe must be fee-only).
struct SnipeWindowRevertScanner {
    found: bool,
}

impl Visitor for SnipeWindowRevertScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if self.found {
            return;
        }
        // Any revert in the function body is flagged — the canonical anti-snipe
        // pattern must not revert (it applies a fee instead).
        if matches!(stmt, Stmt::Revert { .. }) {
            self.found = true;
            return;
        }
        walk_stmt(self, stmt);
    }
}

/// Visitor that detects sniper-field reads in transfer-denial conditions.
///
/// Looks for `assert(self.<sniper_field>)` or `if (self.<sniper_field>) { revert }`
/// patterns — a sniper field gating a transfer denial.
struct SniperFieldDenialScanner<'a> {
    sniper_fields: &'a BTreeSet<String>,
    /// The first sniper field found in a denial condition, or `None`.
    found_func: Option<String>,
}

impl Visitor for SniperFieldDenialScanner<'_> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if self.found_func.is_some() {
            return;
        }
        match stmt {
            // `assert(<cond>)` — check if cond reads a sniper field.
            Stmt::Assert { cond, .. } => {
                if let Some(field) = self.find_sniper_field_read(cond) {
                    self.found_func = Some(field);
                    return;
                }
            }
            // `if (<cond>) { ... revert ... }` — check if cond reads a sniper field.
            Stmt::If {
                cond, then, else_, ..
            } => {
                let then_reverts = crate::analyzer::util::block_contains_revert(then);
                let else_reverts = else_
                    .as_ref()
                    .is_some_and(|b| crate::analyzer::util::block_contains_revert(b));
                if then_reverts || else_reverts {
                    if let Some(field) = self.find_sniper_field_read(cond) {
                        self.found_func = Some(field);
                        return;
                    }
                }
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }
}

impl SniperFieldDenialScanner<'_> {
    /// Returns the first sniper field name found in `expr`, or `None`.
    ///
    /// Handles direct reads (`self.sniperList`), index reads (`self.sniperList[k]`),
    /// and method calls on sniper fields (`self.sniperList.get(k)` — the callee
    /// is `Member(Member(self, "sniperList"), "get")`).
    fn find_sniper_field_read(&self, expr: &Expr) -> Option<String> {
        match expr {
            // Direct `self.<sniper_field>` read.
            Expr::Member(obj, field, _) if is_self(obj) => {
                if self.sniper_fields.contains(field) {
                    return Some(field.clone());
                }
            }
            // `self.<sniper_field>[key]` read.
            Expr::Index(base, _, _) => {
                if let Expr::Member(obj, field, _) = base.as_ref() {
                    if is_self(obj) && self.sniper_fields.contains(field) {
                        return Some(field.clone());
                    }
                }
            }
            // `self.<sniper_field>.method(...)` call — callee is Member(Member(self, field), method).
            Expr::Call { callee, args, .. } => {
                if let Expr::Member(recv, _, _) = callee.as_ref() {
                    if let Some(field) = self.find_sniper_field_read(recv) {
                        return Some(field);
                    }
                }
                // Also check args for sniper field reads.
                for arg in args {
                    let e = match arg {
                        crate::parser::CallArg::Positional(e)
                        | crate::parser::CallArg::Named(_, e) => e,
                    };
                    if let Some(field) = self.find_sniper_field_read(e) {
                        return Some(field);
                    }
                }
                return None;
            }
            _ => {}
        }
        // Recurse into sub-expressions.
        match expr {
            Expr::Unary(_, inner, _) | Expr::Try_(inner, _) | Expr::Cast { expr: inner, .. } => {
                self.find_sniper_field_read(inner)
            }
            Expr::Binary(_, l, r, _) | Expr::Nullish(l, r, _) => self
                .find_sniper_field_read(l)
                .or_else(|| self.find_sniper_field_read(r)),
            Expr::Member(base, _, _) => self.find_sniper_field_read(base),
            _ => None,
        }
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
