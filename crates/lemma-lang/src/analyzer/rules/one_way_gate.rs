//! SAFETY-009 — One-Way Gates.
//!
//! Prevents reversible "trading enabled" toggles used to trap holders (enable to
//! attract buys, disable to block sells).
//!
//! ## True property (spec §3-009)
//!
//! "A flag that gates disposal cannot be flipped back to the blocking state by a
//! non-governance actor." Once trading is enabled, only `GOVERNANCE` (or no one)
//! may disable it again.
//!
//! ## Enforced (decidable over-approximation)
//!
//! 1. **Identify gating flags**: boolean `state` fields read on a transfer path
//!    to permit/deny it (the `restriction_fields` analysis from 4f-0, filtered to
//!    `bool` fields).
//! 2. **Infer the blocking polarity**: from the gating condition's shape —
//!    `assert(self.flag)` ⇒ blocking value is `false`; `assert(!self.flag)` ⇒
//!    blocking value is `true`; `if (self.flag) { revert }` ⇒ blocking value is
//!    `true`; `if (!self.flag) { revert }` ⇒ blocking value is `false`.
//! 3. **Find blocking-value writers**: functions that assign `self.flag =
//!    <blocking-literal>`.  A legitimate one-way `enableTrading()` writes only the
//!    *permitting* value and is **not** flagged.
//! 4. **Require governance**: any blocking-value writer not gated by
//!    `@onlyRole("GOVERNANCE")` ⇒ `OneWayGate`.
//!
//! ## Soundness (reject on doubt — spec §5.1)
//!
//! Over-approximation toward rejection in three places:
//! - **Mixed polarity** across gating sites (ambiguous blocking value) ⇒ `Both`
//!   (any non-gov writer of either value ⇒ reject).
//! - **Opaque flag reads** — a gating flag read as an operand of a comparison
//!   (`self.flag == false`), arithmetic, call, or index ⇒ polarity is NOT
//!   trustworthy (`== false` is semantically `!flag`, which structural parity
//!   does not capture) ⇒ `Both`.  Only bare / `!`-wrapped / `&&`/`||` reads keep
//!   exact polarity.
//! - **Non-literal blocking writes** — `self.flag = !self.flag` / `= compute()` /
//!   `= cond` cannot be statically pinned ⇒ treated as a blocking write (a gating
//!   flag must not be settable to an unprovable value by a non-gov actor).
//!
//! These keep the rule free of false-negatives (never accepts an owner-flippable
//! gate).  Reuses `auth_set`/`requires_governance` (4b) + `restriction_fields`
//! (4f-0).  Gates whose condition is an external read slip to SAFETY-010.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-009`, `03-LANGUAGE_SPEC §24.8`.

use std::collections::{BTreeMap, BTreeSet};

use crate::analyzer::authset::{auth_set, requires_governance, requires_owner_only};
use crate::analyzer::dataflow::restriction_fields;
use crate::analyzer::rules::launch::is_renounce_aware;
use crate::parser::{BinaryOp, Expr, Literal, Stmt, UnaryOp};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::type_checker::types::ResolvedType;
use crate::visit::{walk_stmt, Visitor};

use crate::analyzer::error::SafetyError;
use crate::analyzer::util::{block_contains_revert, is_self};

/// Check a contract for SAFETY-009 one-way-gate violations.
///
/// Returns one [`SafetyError::OneWayGate`] per function that can set a
/// transfer-gating boolean flag to its **blocking** value without GOVERNANCE
/// authority.  Returns an empty `Vec` when the contract is safe.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // Step 1: gating flags = restriction fields ∩ boolean state fields.
    let restriction = restriction_fields(contract);
    if restriction.is_empty() {
        return violations;
    }
    let bool_fields: BTreeSet<String> = contract
        .state_fields()
        .into_iter()
        .filter(|f| matches!(f.ty, ResolvedType::Bool))
        .map(|f| f.name.to_owned())
        .collect();
    let gating_flags: BTreeSet<String> = restriction.intersection(&bool_fields).cloned().collect();
    if gating_flags.is_empty() {
        return violations;
    }

    // Step 2: blocking polarity per gating flag (from transfer-path gating use).
    let blocking = blocking_values(contract, &gating_flags);

    // Step 3+4: for each gating flag, find blocking-value writers lacking
    // governance and emit a violation.
    //
    // P3-own-3 (c): if the writer is @onlyOwner AND the contract is renounce-aware
    // (has a `renounce` function that writes `self.owner`), the gate lever is LOCKED
    // post-renounce — nobody can flip it back to blocking.  A permanently-locked
    // gate is SAFER than governance (it cannot be re-asserted at all), so we skip
    // the violation.  Consumer: is_renounce_aware() in rules/launch.rs (4f-launch).
    let renounce_aware = is_renounce_aware(contract);

    for func in contract.functions() {
        let guards = auth_set(&func);
        // Skip: governance-gated writers are always allowed.
        if requires_governance(&guards) {
            continue;
        }
        // Skip: @onlyOwner writer on a renounce-aware contract — lever is LOCKED
        // post-renounce (P3-own-3 c).  Not a governance risk.
        if requires_owner_only(&guards) && renounce_aware {
            continue;
        }
        let Some(body) = func.body else {
            continue;
        };
        for flag in &gating_flags {
            let blocking_set = blocking
                .get(flag)
                .copied()
                .unwrap_or(BlockingValue::Unknown);
            if writes_blocking_value(body, flag, blocking_set) {
                violations.push(SafetyError::OneWayGate {
                    func: func.name.to_owned(),
                });
                break; // one violation per function is enough
            }
        }
    }

    violations
}

// ─── Blocking-polarity inference ──────────────────────────────────────────────

/// The boolean value of a gating flag that **blocks** a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockingValue {
    /// Writing `false` blocks (e.g. `assert(self.flag)` ⇒ flag must be true).
    False,
    /// Writing `true` blocks (e.g. `assert(!self.flag)` ⇒ flag must be false).
    True,
    /// Mixed/ambiguous across gating sites — treat BOTH values as blocking.
    Both,
    /// No clear gating site found — conservatively treat both as blocking.
    Unknown,
}

impl BlockingValue {
    /// Returns `true` if writing the boolean literal `v` is a blocking write.
    fn blocks(self, v: bool) -> bool {
        match self {
            BlockingValue::False => !v,
            BlockingValue::True => v,
            BlockingValue::Both | BlockingValue::Unknown => true,
        }
    }

    /// Merge two observed polarities (lattice meet toward `Both`).
    fn merge(self, other: BlockingValue) -> BlockingValue {
        match (self, other) {
            (BlockingValue::Unknown, x) | (x, BlockingValue::Unknown) => x,
            (a, b) if a == b => a,
            _ => BlockingValue::Both,
        }
    }
}

/// Compute the blocking value for each gating flag by inspecting how the
/// transfer-path functions gate on it.
fn blocking_values(
    contract: &TypedContract<'_>,
    gating_flags: &BTreeSet<String>,
) -> BTreeMap<String, BlockingValue> {
    let mut out: BTreeMap<String, BlockingValue> = BTreeMap::new();
    for func in contract.functions() {
        if !is_transfer_path_fn(&func) {
            continue;
        }
        let Some(body) = func.body else {
            continue;
        };
        let mut scanner = PolarityScanner {
            gating_flags,
            out: &mut out,
        };
        scanner.visit_stmts(body);
    }
    out
}

/// Returns `true` if `func` is a transfer-path entry.
fn is_transfer_path_fn(func: &ContractFunction<'_>) -> bool {
    func.name == "transfer"
        || func.name == "transferFrom"
        || func.annotations.iter().any(|a| a.name == "onTransfer")
}

/// Visitor that infers blocking polarity from gating conditions.
struct PolarityScanner<'a> {
    gating_flags: &'a BTreeSet<String>,
    out: &'a mut BTreeMap<String, BlockingValue>,
}

impl Visitor for PolarityScanner<'_> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            // assert(cond) reverts when cond is FALSE.
            // A flag read positively (`self.flag`) ⇒ must be true ⇒ false blocks.
            // A flag read negated (`!self.flag`) ⇒ must be false ⇒ true blocks.
            Stmt::Assert { cond, .. } => {
                self.record_condition(cond, /* reverts_when_true = */ false);
            }
            // if (cond) { ... revert ... } reverts when cond is TRUE.
            Stmt::If {
                cond, then, else_, ..
            } => {
                if block_contains_revert(then) {
                    self.record_condition(cond, /* reverts_when_true = */ true);
                }
                if else_.as_ref().is_some_and(|b| block_contains_revert(b)) {
                    // else reverts when cond is FALSE.
                    self.record_condition(cond, /* reverts_when_true = */ false);
                }
            }
            _ => {}
        }
        walk_stmt(self, stmt);
    }
}

impl PolarityScanner<'_> {
    /// Record the blocking polarity implied by a gating `cond` that triggers a
    /// revert either when true (`reverts_when_true`) or when false.
    fn record_condition(&mut self, cond: &Expr, reverts_when_true: bool) {
        // Find each gating-flag read in `cond` with its read kind.
        let mut reads: Vec<FlagRead> = Vec::new();
        collect_flag_reads(cond, self.gating_flags, false, &mut reads);
        for read in reads {
            let bv = match read.kind {
                // Clean read: polarity is trustworthy.
                //
                // `cond` takes the revert branch when `cond == reverts_when_true`.
                // For a bare (optionally `!`-negated) flag read, the boolean value
                // of `cond` is `(flag XOR negated)`.  So the revert (BLOCKING)
                // branch is taken when `(flag XOR negated) == reverts_when_true`,
                // i.e. the BLOCKING flag value is `reverts_when_true XOR negated`.
                ReadKind::Clean { negated } => {
                    if reverts_when_true ^ negated {
                        BlockingValue::True
                    } else {
                        BlockingValue::False
                    }
                }
                // Opaque read: the flag appears as an operand of a comparison,
                // arithmetic, call, index, etc.  The polarity CANNOT be trusted
                // (`self.flag == false` is semantically `!self.flag`, but the
                // structural parity does not capture this).  Conservatively treat
                // BOTH boolean values as blocking — reject on doubt (spec §5.1).
                ReadKind::Opaque => BlockingValue::Both,
            };
            let entry = self.out.entry(read.flag).or_insert(BlockingValue::Unknown);
            *entry = entry.merge(bv);
        }
    }
}

/// A gating-flag read found inside a condition, tagged with how trustworthy its
/// polarity is.
struct FlagRead {
    flag: String,
    kind: ReadKind,
}

/// Whether a flag read's polarity can be trusted for blocking-value inference.
enum ReadKind {
    /// The flag is read bare, or under an even/odd chain of `!`, possibly inside
    /// `&&`/`||` boolean combinators.  `negated` is the `!`-parity.  The
    /// inferred polarity is exact.
    Clean { negated: bool },
    /// The flag appears as an operand of a non-boolean operator (comparison
    /// `==`/`!=`/`<`…, arithmetic, a call argument, an index, …).  Polarity is
    /// untrustworthy → caller must treat as `BlockingValue::Both`.
    Opaque,
}

/// Collect a [`FlagRead`] for each gating-flag read in `expr`.
///
/// Distinguishes **clean** reads (bare / `!`-wrapped / inside `&&`/`||`) — whose
/// polarity is exact — from **opaque** reads (the flag is an operand of a
/// comparison, arithmetic, call, or index) — whose polarity cannot be trusted
/// and which therefore force a conservative `Both` (reject-on-doubt) classification.
///
/// `negated` is the running `!`-parity for the clean path.
fn collect_flag_reads(
    expr: &Expr,
    gating_flags: &BTreeSet<String>,
    negated: bool,
    out: &mut Vec<FlagRead>,
) {
    match expr {
        // Bare `self.flag` in a boolean position — clean read.
        Expr::Member(obj, field, _) if is_self(obj) => {
            if gating_flags.contains(field) {
                out.push(FlagRead {
                    flag: field.clone(),
                    kind: ReadKind::Clean { negated },
                });
            }
        }
        // `!expr` — flip parity, stay on the clean path.
        Expr::Unary(UnaryOp::Not, inner, _) => {
            collect_flag_reads(inner, gating_flags, !negated, out);
        }
        // `&&` / `||` — boolean combinators preserve polarity; stay clean.
        Expr::Binary(BinaryOp::And | BinaryOp::Or, l, r, _) => {
            collect_flag_reads(l, gating_flags, negated, out);
            collect_flag_reads(r, gating_flags, negated, out);
        }
        // Any OTHER binary operator (`==`, `!=`, comparisons, arithmetic) — a
        // gating flag read inside is OPAQUE: parity is not trustworthy.
        Expr::Binary(_, l, r, _) => {
            collect_opaque_flag_reads(l, gating_flags, out);
            collect_opaque_flag_reads(r, gating_flags, out);
        }
        Expr::Member(base, _, _) => collect_flag_reads(base, gating_flags, negated, out),
        // Ternary / if-expr / match-expr / call / index / cast in a boolean
        // position obscure polarity — route to the opaque collector so the read
        // is conservatively classified `Both` rather than silently dropped.
        Expr::Ternary { .. }
        | Expr::If_ { .. }
        | Expr::Match_(..)
        | Expr::Call { .. }
        | Expr::Index(..)
        | Expr::Cast { .. }
        | Expr::Nullish(..)
        | Expr::Try_(..) => collect_opaque_flag_reads(expr, gating_flags, out),
        _ => {}
    }
}

/// Collect gating-flag reads anywhere inside `expr` as **opaque** (untrustworthy
/// polarity).  Used for operands of non-boolean operators.
fn collect_opaque_flag_reads(
    expr: &Expr,
    gating_flags: &BTreeSet<String>,
    out: &mut Vec<FlagRead>,
) {
    match expr {
        Expr::Member(obj, field, _) if is_self(obj) => {
            if gating_flags.contains(field) {
                out.push(FlagRead {
                    flag: field.clone(),
                    kind: ReadKind::Opaque,
                });
            }
        }
        Expr::Unary(_, inner, _) | Expr::Try_(inner, _) | Expr::Cast { expr: inner, .. } => {
            collect_opaque_flag_reads(inner, gating_flags, out);
        }
        Expr::Binary(_, l, r, _) | Expr::Nullish(l, r, _) => {
            collect_opaque_flag_reads(l, gating_flags, out);
            collect_opaque_flag_reads(r, gating_flags, out);
        }
        Expr::Member(base, _, _) => collect_opaque_flag_reads(base, gating_flags, out),
        Expr::Index(base, idx, _) => {
            collect_opaque_flag_reads(base, gating_flags, out);
            collect_opaque_flag_reads(idx, gating_flags, out);
        }
        Expr::Call { callee, args, .. } => {
            collect_opaque_flag_reads(callee, gating_flags, out);
            for arg in args {
                let e = match arg {
                    crate::parser::CallArg::Positional(e) | crate::parser::CallArg::Named(_, e) => {
                        e
                    }
                };
                collect_opaque_flag_reads(e, gating_flags, out);
            }
        }
        // Ternary `c ? a : b`: any gating-flag read in any branch is opaque.
        Expr::Ternary {
            cond, then, else_, ..
        } => {
            collect_opaque_flag_reads(cond, gating_flags, out);
            collect_opaque_flag_reads(then, gating_flags, out);
            collect_opaque_flag_reads(else_, gating_flags, out);
        }
        // A gating flag read inside an `if`/`match` expression condition is
        // opaque (the value-position control flow obscures polarity).  Reads in
        // the statement bodies are handled by the statement-level visitor; here
        // we only need the scrutinee/cond expression.
        Expr::If_ { cond, .. } => collect_opaque_flag_reads(cond, gating_flags, out),
        Expr::Match_(scrutinee, _, _) => collect_opaque_flag_reads(scrutinee, gating_flags, out),
        // Leaf / Lambda / literal: no gating-flag read of interest.
        _ => {}
    }
}

// ─── Blocking-value writer detection ──────────────────────────────────────────

/// Returns `true` if `stmts` (a function body) assigns `self.<flag>` a boolean
/// literal whose value is a **blocking** write under `blocking`.
fn writes_blocking_value(stmts: &[Stmt], flag: &str, blocking: BlockingValue) -> bool {
    let mut scanner = BlockingWriteScanner {
        flag,
        blocking,
        found: false,
    };
    scanner.visit_stmts(stmts);
    scanner.found
}

/// Visitor that detects `self.<flag> = <blocking-bool-literal>` writes.
struct BlockingWriteScanner<'a> {
    flag: &'a str,
    blocking: BlockingValue,
    found: bool,
}

impl Visitor for BlockingWriteScanner<'_> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Assign { target, value, .. } = stmt {
            self.check_assign(target, value);
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        if let Expr::Assign_(target, _, value, _) = expr {
            self.check_assign(target, value);
        }
        crate::visit::walk_expr(self, expr);
    }
}

impl BlockingWriteScanner<'_> {
    fn check_assign(&mut self, target: &Expr, value: &Expr) {
        if let Expr::Member(obj, field, _) = target {
            if is_self(obj) && field == self.flag {
                match value {
                    // Literal bool: blocking iff the literal matches the blocking value.
                    Expr::Literal(Literal::Bool(b), _) => {
                        if self.blocking.blocks(*b) {
                            self.found = true;
                        }
                    }
                    // Non-literal write (`= !self.flag`, `= computeFlag()`, `= cond`):
                    // the written value cannot be statically pinned, so it COULD be
                    // the blocking value.  Reject on doubt (spec §5.1 soundness) —
                    // a gating flag should not be settable to an unprovable value by
                    // a non-governance actor.
                    _ => {
                        self.found = true;
                    }
                }
            }
        }
    }
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
