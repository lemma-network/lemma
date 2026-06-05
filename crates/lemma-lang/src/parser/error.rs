//! Parse error type for the Lem language parser.
//!
//! [`ParseError`] carries the source location, a human-readable message, and
//! a list of expected tokens/constructs at the point of failure. It is wrapped
//! by [`crate::error::LangError::Parse`] for propagation through the pipeline.

use crate::lexer::token::Span;

/// A parse error produced by the Lem recursive-descent parser.
///
/// Every error records:
/// - `message` — what went wrong (human-readable)
/// - `span` — exact source location of the offending token
/// - `expected` — what the parser expected at that position (for diagnostics)
///
/// # Examples
///
/// ```ignore
/// use lemma_lang::parser::error::ParseError;
/// use lemma_lang::lexer::token::Span;
///
/// let err = ParseError {
///     message: "expected '{'".to_string(),
///     span: Span::at(1, 10, 9),
///     expected: vec!["'{'".to_string()],
/// };
/// assert!(err.to_string().contains("expected '{'"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("parse error at {span:?}: {message} (expected: {expected:?})")]
pub struct ParseError {
    /// Human-readable description of what went wrong.
    pub message: String,
    /// Source location of the offending token.
    pub span: Span,
    /// What the parser expected at this position (may be empty).
    pub expected: Vec<String>,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
