//! SAFETY-010 — Declared Restrictions (force undecidable cases into the open).
//!
//! Prevents *undeclared* transfer restrictions — the catch-all that makes the
//! undecidable residue **visible** instead of silent.
//!
//! ## True property (spec §3-010)
//!
//! "Any condition that can cause a transfer to revert is declared in `config {}`."
//!
//! ## Clause A — external-call declaration (spec §3-010)
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
//! ## Clause B — state-field→config-key mapping (spec §3-010, P3-rule-6)
//!
//! Spec §3-010 also requires state-field-gated transfer reverts to map to a
//! declared restriction key.  Most of this is **already enforced** by sibling
//! rules:
//! - an owner-only blacklist field ⇒ SAFETY-005,
//! - a one-way trading gate ⇒ SAFETY-009,
//! - a fee on the transfer path ⇒ SAFETY-002.
//!
//! The **non-overlapping residual** that clause B adds: if `self.paused` is read
//! on the transfer path inside a revert-condition, the config must declare
//! `pausable: true`.  Similarly `self.frozen` → `freezable: true`.  The mapping
//! is pinned by `@std/access` trait conventions (P3·Step 8):
//!
//! | State field | Required config key |
//! |-------------|---------------------|
//! | `paused`    | `pausable: true`    |
//! | `frozen`    | `freezable: true`   |
//!
//! Detection reuses the same `assert`/`if→revert` scanning pattern as
//! `dataflow::restriction_fields` (DRY — AGENTS §2).
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
use crate::analyzer::error::SafetyError;
use crate::analyzer::util::{block_contains_revert, is_self, is_transfer_path_entry};
use crate::parser::{ConfigValue, Expr, Stmt};
use crate::type_checker::typed_contract::TypedContract;
use crate::visit::{walk_expr, walk_stmt, Visitor};

/// Check a contract for SAFETY-010 undeclared-restriction violations.
///
/// Returns one [`SafetyError::UndeclaredRestriction`] per undeclared restriction
/// source on the transfer path:
/// - **Clause A**: external call without `externalChecker` in config.
/// - **Clause B**: `self.paused`/`self.frozen` read in a revert-condition
///   without the corresponding `pausable`/`freezable` config key.
///
/// Returns an empty `Vec` when safe.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();
    violations.extend(check_external_calls(contract));
    violations.extend(check_state_field_config_mapping(contract));
    violations
}

// ─── Clause A — external-call declaration ─────────────────────────────────────

/// SAFETY-010 clause A: external calls on the transfer path require
/// `externalChecker` declared in `config {}`.
fn check_external_calls(contract: &TypedContract<'_>) -> Vec<SafetyError> {
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

// ─── Clause B — state-field→config-key mapping ───────────────────────────────

/// State fields that, when read on the transfer path inside a revert-condition,
/// require a corresponding config key to be declared (SAFETY-010 clause B).
///
/// The mapping is pinned by `@std/access` trait conventions (P3·Step 8):
///   `paused`  → `pausable`  (Pausable trait)
///   `frozen`  → `freezable` (future freeze trait)
const FIELD_CONFIG_MAPPING: &[(&str, &str)] = &[("paused", "pausable"), ("frozen", "freezable")];

/// SAFETY-010 clause B: state-field-gated transfer reverts must map to declared
/// config keys.
///
/// If `self.paused` is read on the transfer path inside a revert-condition
/// (`assert` or `if`→`revert`), the contract's config must declare
/// `pausable: true` (making the restriction visible to wallets/explorers).
/// Without the declaration, the restriction is undeclared.
///
/// The non-overlapping residual: SAFETY-005 covers blacklist, SAFETY-009 covers
/// one-way gates, SAFETY-002 covers fees.  This clause adds `paused`→`pausable`
/// and `frozen`→`freezable`.
fn check_state_field_config_mapping(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    // Only token contracts have config (plain contracts have no config schema).
    let config = contract.config();

    let mut violations = Vec::new();

    for func in contract.functions() {
        if !is_transfer_path_entry(&func) {
            continue;
        }
        let Some(body) = func.body else {
            continue;
        };

        for &(field, config_key) in FIELD_CONFIG_MAPPING {
            let mut scanner = FieldRevertScanner {
                field,
                found: false,
            };
            scanner.visit_stmts(body);

            if scanner.found {
                // Field is read in a revert-condition — check config has the key.
                let has_config_key = config.is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|e| e.key == config_key && matches!(e.value, ConfigValue::Bool(true)))
                });

                if !has_config_key {
                    violations.push(SafetyError::UndeclaredRestriction {
                        func: format!(
                            "{}: reads `self.{}` in revert-condition but config \
                             does not declare `{}: true`",
                            func.name, field, config_key
                        ),
                    });
                }
            }
        }
    }

    violations
}

/// Visitor that detects `self.<field>` reads inside revert-conditions on the
/// transfer path (`assert` conditions and `if`→`revert` branch conditions).
///
/// Reuses the same scanning pattern as `dataflow::DenialFieldScanner` (AGENTS
/// §2 DRY), narrowed to a single target field name.
struct FieldRevertScanner<'a> {
    /// The state field name to look for (e.g. `"paused"`).
    field: &'a str,
    /// Set to `true` when a matching `self.<field>` read is found in a
    /// revert-condition.
    found: bool,
}

impl Visitor for FieldRevertScanner<'_> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if self.found {
            return; // short-circuit once found
        }
        match stmt {
            // `assert(cond)` reverts when cond is false — any self.<field> read
            // in cond gates a potential revert.
            Stmt::Assert { cond, .. } => {
                if expr_reads_self_field(cond, self.field) {
                    self.found = true;
                    return;
                }
            }
            // `if (cond) { … revert … }` or `else { … revert … }` — if either
            // branch reverts, the condition's self.<field> reads gate a denial.
            Stmt::If {
                cond, then, else_, ..
            } => {
                let then_reverts = block_contains_revert(then);
                let else_reverts = else_.as_ref().is_some_and(|b| block_contains_revert(b));
                if (then_reverts || else_reverts) && expr_reads_self_field(cond, self.field) {
                    self.found = true;
                    return;
                }
            }
            _ => {}
        }
        // Continue canonical recursion into nested control flow.
        walk_stmt(self, stmt);
    }
}

/// Returns `true` if `expr` contains a `self.<field>` read (direct member access
/// or indexed access `self.<field>[key]`).
///
/// Recursively descends into sub-expressions to catch reads inside boolean
/// combinators (`!self.paused`, `self.paused && other`).
fn expr_reads_self_field(expr: &Expr, field: &str) -> bool {
    let mut scanner = SelfFieldReadScanner {
        field,
        found: false,
    };
    scanner.visit_expr(expr);
    scanner.found
}

/// Visitor that detects any `self.<field>` read in an expression tree.
struct SelfFieldReadScanner<'a> {
    field: &'a str,
    found: bool,
}

impl Visitor for SelfFieldReadScanner<'_> {
    fn visit_expr(&mut self, expr: &Expr) {
        if self.found {
            return;
        }
        match expr {
            // `self.field` — direct member access.
            Expr::Member(obj, name, _) if is_self(obj) && name == self.field => {
                self.found = true;
                return;
            }
            // `self.field[key]` — indexed access on the field.
            Expr::Index(base, _, _) => {
                if let Expr::Member(obj, name, _) = base.as_ref() {
                    if is_self(obj) && name == self.field {
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

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
