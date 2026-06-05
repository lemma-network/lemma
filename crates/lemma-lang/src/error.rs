//! Error types for `lemma-lang`.
//!
//! [`LangError`] is the top-level error enum for all Lem language processing
//! stages. Additional variants (Parse, Type, Safety, Codegen) will be added
//! by later build steps. The lexer stage uses the [`LangError::Lex`] variant.
//!
//! ## Usage
//!
//! ```ignore
//! use lemma_lang::error::LangError;
//! use lemma_lang::tokenize;
//!
//! match tokenize("contract Bad { @@ }") {
//!     Ok(tokens) => { /* ... */ }
//!     Err(LangError::Lex { message, span }) => {
//!         eprintln!("lex error at {}:{}: {}", span.line, span.col, message);
//!     }
//! }
//! ```

use thiserror::Error;

use crate::lexer::token::Span;

/// Top-level error type for all Lem language processing stages.
///
/// Each variant corresponds to a compiler stage. The `Lex` variant is
/// populated by the lexer; later stages add `Parse`, `Type`, `Safety`, etc.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LangError {
    /// A lexical error encountered while tokenizing Lem source code.
    ///
    /// The `span` field identifies the exact source location of the error.
    #[error("lex error at {span:?}: {message}")]
    Lex {
        /// Human-readable description of what went wrong.
        message: String,
        /// Source location of the offending character or token.
        span: Span,
    },
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
