//! Error types for `lemma-lang`.
//!
//! [`LangError`] is the top-level error enum for all Lem language processing
//! stages. The lexer stage uses [`LangError::Lex`]; the parser stage uses
//! [`LangError::Parse`]; the type checker uses [`LangError::Type`];
//! the safety analyzer uses [`LangError::Safety`].
//! The `Codegen` variant will be added in Step 6.
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

use crate::analyzer::error::SafetyError;
use crate::lexer::token::Span;
use crate::parser::error::ParseError;
use crate::type_checker::error::TypeError;

/// Top-level error type for all Lem language processing stages.
///
/// Each variant corresponds to a compiler stage:
/// - `Lex`    — lexer (tokenization)
/// - `Parse`  — parser (AST construction)
/// - `Type`   — type checker (type inference + name resolution)
/// - `Safety` — safety analyzer (SAFETY-001…013 token rules)
/// - `Codegen` — planned for Step 6
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

    /// A type error encountered while type-checking the AST.
    // Delegate display entirely to TypeError — avoids "type error: type error at …"
    // double-printing when TypeError's own #[error] already includes "type error at".
    #[error("{0}")]
    Type(#[from] TypeError),

    /// One or more safety violations detected by the safety analyzer.
    ///
    /// Each element is a [`SafetyError`] identifying a specific SAFETY-001…013
    /// violation.  `analyze_safety` collects **all** violations before returning
    /// (never fail-fast), so the developer sees every problem in one compile.
    #[error(
        "safety analysis failed: {} violation(s) — \
         contract cannot be compiled",
        .0.len()
    )]
    Safety(Vec<SafetyError>),
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
