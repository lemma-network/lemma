//! Shared helpers for the safety analyzer.
//!
//! Small predicates reused across `cfg`, `dataflow`, and the SAFETY-rule modules.
//! Hoisted here to retire the per-module duplication that accumulated across the
//! 4d–4f rule batches (AGENTS §2.4 — shared utilities live in one place).

use crate::parser::{Expr, Stmt};
use crate::type_checker::typed_contract::ContractFunction;

/// Returns `true` if `expr` is the identifier `self`.
///
/// The canonical receiver check used by every state-access analysis
/// (`self.field`, `self.field[k]`, `self.method()`).
#[must_use]
pub(crate) fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

/// Returns `true` if `stmts` contains a top-level `revert` statement.
///
/// "Top-level" = a direct member of the slice (e.g. the direct body of an
/// `if`/`else` branch).  Nested control flow is handled by the caller's own
/// recursion into those sub-blocks.  Used by transfer-denial detection
/// (SAFETY-005/009) to recognise `if (cond) { revert }` gating shapes.
#[must_use]
pub(crate) fn block_contains_revert(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s| matches!(s, Stmt::Revert { .. }))
}

/// Returns `true` if `func` is a transfer-path entry point.
///
/// Transfer-path entries are:
/// - `transfer` — the canonical token transfer function.
/// - `transferFrom` — the delegated transfer function.
/// - Any function annotated `#[onTransfer]` — a transfer hook.
///
/// Used by SAFETY-010, SAFETY-020, SAFETY-023, SAFETY-024, SAFETY-025 and
/// `dataflow` to identify the root of the transfer call graph.
///
/// Canonical form (AGENTS §2.4 — shared utilities live in `lemma-core`/`util`).
#[must_use]
pub(crate) fn is_transfer_path_entry(func: &ContractFunction<'_>) -> bool {
    func.name == "transfer"
        || func.name == "transferFrom"
        || func.annotations.iter().any(|a| a.name == "onTransfer")
}
