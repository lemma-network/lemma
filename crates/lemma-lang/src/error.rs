//! Error types for `lemma-lang`.
//!
//! [`LangError`] is the top-level error enum for all Lem language processing
//! stages. The lexer stage uses [`LangError::Lex`]; the parser stage uses
//! [`LangError::Parse`]. Type, Safety, and Codegen variants will be added
//! by later build steps.
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
//!     _ => {}
//! }
//! ```

use thiserror::Error;

use crate::lexer::token::Span;
use crate::parser::error::ParseError;

/// Top-level error type for all Lem language processing stages.
///
/// Each variant corresponds to a compiler stage. The `Lex` variant is
/// populated by the lexer; `Parse` by the parser; later stages add
/// `Type`, `Safety`, `Codegen`.
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

    /// A parse error encountered while building the AST from the token stream.
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
