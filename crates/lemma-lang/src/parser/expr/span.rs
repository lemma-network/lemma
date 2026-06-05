//! Span utilities for the expression parser.
//!
//! Provides `expr_span` (extract span from any Expr) and `MergeSpan` trait.

use crate::lexer::token::Span;

use super::super::ast::Expr;

// ─── Span helper ──────────────────────────────────────────────────────────────

/// Extract the span from any `Expr` variant.
///
/// The `#[allow(unreachable_patterns)]` is required because `Expr` is
/// `#[non_exhaustive]` — the wildcard arm is needed for forward compatibility
/// even though all current variants are covered above it.
#[allow(unreachable_patterns, dead_code)]
pub(crate) fn expr_span(e: &Expr) -> Span {
    match e {
        Expr::Literal(_, s)
        | Expr::Ident(_, s)
        | Expr::Tuple(_, s)
        | Expr::Array(_, s)
        | Expr::Index(_, _, s)
        | Expr::Member(_, _, s)
        | Expr::Unary(_, _, s)
        | Expr::Binary(_, _, _, s)
        | Expr::Nullish(_, _, s)
        | Expr::Try_(_, s)
        | Expr::Template(_, s)
        | Expr::Assign_(_, _, _, s)
        | Expr::Match_(_, _, s) => *s,
        Expr::Struct_ { span, .. }
        | Expr::Call { span, .. }
        | Expr::Ternary { span, .. }
        | Expr::Lambda { span, .. }
        | Expr::New { span, .. }
        | Expr::If_ { span, .. } => *span,
        // Forward-compatibility fallback for future #[non_exhaustive] variants
        _ => Span::at(0, 0, 0),
    }
}

// ─── Span merge ───────────────────────────────────────────────────────────────

/// Extension trait to merge two spans into one covering both.
// Used by expr.rs internally and by tests; dead_code until stmt.rs/decl.rs land.
#[allow(dead_code)]
pub(crate) trait MergeSpan {
    fn merge_with(self, other: Span) -> Span;
}

impl MergeSpan for Span {
    fn merge_with(self, other: Span) -> Span {
        Span {
            line: self.line,
            col: self.col,
            offset: self.offset,
            len: (other.offset + other.len).saturating_sub(self.offset),
        }
    }
}
