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
//! ## Soundness
//!
//! Over-approximation toward rejection.  If a flag is read with mixed polarity
//! across multiple gating sites (ambiguous blocking value), **both** boolean
//! values are treated as blocking (any non-gov writer of either ⇒ reject) — the
//! conservative choice.  Reuses `auth_set`/`requires_governance` (4b) +
//! `restriction_fields` (4f-0).  Gates whose condition is an external read slip
//! to SAFETY-010.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-009`, `03-LANGUAGE_SPEC §24.8`.

use std::collections::{BTreeMap, BTreeSet};

use crate::analyzer::authset::{auth_set, requires_governance};
use crate::analyzer::dataflow::restriction_fields;
use crate::parser::{Expr, Literal, Stmt, UnaryOp};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::type_checker::types::ResolvedType;
use crate::visit::{walk_stmt, Visitor};

use crate::analyzer::error::SafetyError;

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
    for func in contract.functions() {
        let guards = auth_set(&func);
        if requires_governance(&guards) {
            continue; // governance writers are always allowed
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
        // Find each gating-flag read in `cond` with its negation parity.
        let mut reads: Vec<(String, bool)> = Vec::new(); // (flag, negated)
        collect_flag_reads(cond, self.gating_flags, false, &mut reads);
        for (flag, negated) in reads {
            // The flag's *required* value to AVOID revert:
            //   reverts_when_true  → cond must be false to pass
            //   !reverts_when_true → cond must be true  to pass
            // With negation parity, the flag's blocking value is:
            //   blocking = value that makes `cond` take the revert branch.
            // cond takes revert branch when cond == reverts_when_true.
            // cond (for a bare flag read, possibly negated) == (flag XOR negated).
            // So revert when (flag XOR negated) == reverts_when_true
            //   ⇒ flag == reverts_when_true XOR negated  is the BLOCKING value.
            let blocking_bool = reverts_when_true ^ negated;
            let bv = if blocking_bool {
                BlockingValue::True
            } else {
                BlockingValue::False
            };
            let entry = self.out.entry(flag).or_insert(BlockingValue::Unknown);
            *entry = entry.merge(bv);
        }
    }
}

/// Collect `(flag_name, negated)` for each gating-flag read in `expr`.
///
/// `negated` tracks whether the read sits under an odd number of `!` operators.
/// Only simple boolean-combination conditions are tracked precisely; reads
/// nested under non-boolean operators still register (with their current parity)
/// so the conservative `Both`/`Unknown` merge keeps soundness.
fn collect_flag_reads(
    expr: &Expr,
    gating_flags: &BTreeSet<String>,
    negated: bool,
    out: &mut Vec<(String, bool)>,
) {
    match expr {
        Expr::Member(obj, field, _) if is_self(obj) => {
            if gating_flags.contains(field) {
                out.push((field.clone(), negated));
            }
        }
        Expr::Unary(UnaryOp::Not, inner, _) => {
            collect_flag_reads(inner, gating_flags, !negated, out);
        }
        // && / || / other boolean combinators: propagate current parity.
        Expr::Binary(_, l, r, _) => {
            collect_flag_reads(l, gating_flags, negated, out);
            collect_flag_reads(r, gating_flags, negated, out);
        }
        Expr::Member(base, _, _) => collect_flag_reads(base, gating_flags, negated, out),
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
                if let Expr::Literal(Literal::Bool(b), _) = value {
                    if self.blocking.blocks(*b) {
                        self.found = true;
                    }
                }
            }
        }
    }
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `stmts` contains a top-level `revert`.
fn block_contains_revert(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s| matches!(s, Stmt::Revert { .. }))
}

/// Returns `true` if `expr` is the identifier `self`.
fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
