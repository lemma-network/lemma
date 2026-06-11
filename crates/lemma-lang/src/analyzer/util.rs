//! Shared helpers for the safety analyzer.
//!
//! Small predicates reused across `cfg`, `dataflow`, and the SAFETY-rule modules.
//! Hoisted here to retire the per-module duplication that accumulated across the
//! 4d–4f rule batches (AGENTS §2.4 — shared utilities live in one place).

use crate::parser::{Expr, Stmt};

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
