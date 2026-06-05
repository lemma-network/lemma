//! Lem language parser.
//!
//! Converts a token stream (from the lexer) into a full AST.
//!
//! ## Entry point
//!
//! ```ignore
//! use lemma_lang::{tokenize, parse};
//!
//! let tokens = tokenize("contract Foo {}")?;
//! let ast = parse(tokens)?;
//! assert_eq!(ast.items.len(), 1);
//! ```
//!
//! ## Architecture
//!
//! The parser is a recursive-descent parser with one function per EBNF rule.
//! It is fuzz-safe: it never panics on any token stream, returning
//! `Err(LangError::Parse)` on malformed input.
//!
//! Submodules are added incrementally across subtasks 2a–2h:
//! - `ast`   — all AST node definitions (2a)
//! - `error` — `ParseError` type (2a)
//! - `ty`    — type parser (2a)
//! - `expr`  — expression parser (2b)
//! - `stmt`  — statement parser (2c)
//! - `decl`  — declaration parser (2d)
//! - `item`  — struct/enum/interface/trait/library (2e–2f)

pub mod ast;
mod decl;
pub mod error;
mod expr;
mod stmt;
mod ty;

pub use ast::*;
pub use error::ParseError;

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Parse a Lem token stream into an AST.
///
/// # Errors
///
/// Returns `Err(LangError::Parse)` on any parse error. Never panics.
///
/// # Examples
///
/// ```ignore
/// use lemma_lang::{tokenize, parse};
///
/// let tokens = tokenize("contract Foo {}")?;
/// let ast = parse(tokens)?;
/// ```
pub fn parse(tokens: Vec<(Token, Span)>) -> Result<Ast, LangError> {
    let mut parser = Parser::new(tokens);
    parser.parse_program()
}

// ─── Parser struct ────────────────────────────────────────────────────────────

/// The recursive-descent parser for the Lem language.
///
/// Maintains a cursor (`pos`) into the flat token stream. All parsing methods
/// are `pub(crate)` so submodule files can extend `Parser` with `impl Parser`.
pub(crate) struct Parser {
    /// The flat token stream (including `Newline` and `Eof`).
    tokens: Vec<(Token, Span)>,
    /// Current position in the token stream.
    pos: usize,
}

// Cursor helpers are forward-declared here and wired into the sub-parsers
// (expr.rs, stmt.rs, decl.rs, item.rs) in subtasks 2b-2f.
impl Parser {
    /// Create a new parser from a token stream.
    ///
    /// The stream must end with `Token::Eof` (guaranteed by the lexer).
    pub(crate) fn new(tokens: Vec<(Token, Span)>) -> Self {
        Self { tokens, pos: 0 }
    }

    // ── Cursor helpers ────────────────────────────────────────────────────────

    /// Return the current token without advancing.
    ///
    /// Returns `Token::Eof` if past the end of the stream.
    pub(crate) fn peek(&self) -> &Token {
        let idx = self.pos.min(self.tokens.len().saturating_sub(1));
        &self.tokens[idx].0
    }

    /// Return the span of the current token.
    pub(crate) fn peek_span(&self) -> Span {
        let idx = self.pos.min(self.tokens.len().saturating_sub(1));
        self.tokens[idx].1
    }

    /// Look ahead N tokens without advancing.
    ///
    /// Returns `Token::Eof` if the lookahead is past the end.
    pub(crate) fn peek_nth(&self, n: usize) -> &Token {
        let idx = (self.pos + n).min(self.tokens.len().saturating_sub(1));
        &self.tokens[idx].0
    }

    /// Peek at the Nth non-newline token from the current position.
    ///
    /// Used by expression-parser lookahead helpers where newlines are insignificant
    /// (Go/JS rule: inside expression context, newlines do not terminate expressions).
    pub(crate) fn peek_nth_non_newline(&self, n: usize) -> &Token {
        let mut count = 0;
        let mut idx = self.pos;
        while idx < self.tokens.len() {
            if !matches!(self.tokens[idx].0, Token::Newline) {
                if count == n {
                    return &self.tokens[idx].0;
                }
                count += 1;
            }
            idx += 1;
        }
        // Past end — return last token (Eof)
        &self.tokens[self.tokens.len().saturating_sub(1)].0
    }

    /// Advance past the current token and return it with its span.
    pub(crate) fn advance(&mut self) -> (Token, Span) {
        let idx = self.pos.min(self.tokens.len().saturating_sub(1));
        let tok = self.tokens[idx].clone();
        if self.pos < self.tokens.len() {
            self.pos += 1;
        }
        tok
    }

    /// Return `true` if the current token equals `tok` (no advance).
    pub(crate) fn check(&self, tok: &Token) -> bool {
        self.peek() == tok
    }

    /// Advance if the current token equals `tok`. Returns `true` if advanced.
    pub(crate) fn advance_if(&mut self, tok: &Token) -> bool {
        if self.check(tok) {
            self.advance();
            true
        } else {
            false
        }
    }

    /// Advance if the current token equals `tok` and return its span.
    /// Returns `Err` if the token does not match.
    pub(crate) fn expect(&mut self, tok: &Token, ctx: &str) -> Result<Span, LangError> {
        if self.check(tok) {
            Ok(self.advance().1)
        } else {
            Err(self.error(format!("expected {ctx}, got {:?}", self.peek())))
        }
    }

    /// Return `true` if the current token is `Token::Eof`.
    pub(crate) fn at_end(&self) -> bool {
        matches!(self.peek(), Token::Eof)
    }

    // ── Error constructors ────────────────────────────────────────────────────

    /// Build a `LangError::Parse` at the current position.
    pub(crate) fn error(&self, message: impl Into<String>) -> LangError {
        LangError::Parse(ParseError {
            message: message.into(),
            span: self.peek_span(),
            expected: vec![],
        })
    }

    /// Build a `LangError::Parse` with an expected-token list.
    pub(crate) fn error_expected(
        &self,
        expected: Vec<String>,
        message: impl Into<String>,
    ) -> LangError {
        LangError::Parse(ParseError {
            message: message.into(),
            span: self.peek_span(),
            expected,
        })
    }

    // ── Error recovery ────────────────────────────────────────────────────────

    /// Skip tokens until a safe recovery point.
    ///
    /// Stops at the next statement or declaration boundary keyword, or at EOF.
    /// Used after a parse error to continue parsing the rest of the file.
    pub(crate) fn synchronize(&mut self) {
        while !self.at_end() {
            match self.peek() {
                // Declaration boundaries
                Token::Contract
                | Token::Token_
                | Token::Interface
                | Token::Trait
                | Token::Library
                | Token::Struct
                | Token::Enum
                | Token::Fn
                | Token::Let
                | Token::Return
                | Token::If
                | Token::For
                | Token::While
                | Token::Loop
                | Token::State
                | Token::Import
                | Token::Using
                | Token::Const
                | Token::Type
                | Token::Error
                | Token::Immutable
                // Annotation starts (functions/events often begin with @ann or #[ann])
                | Token::At
                | Token::Hash_ => return,
                _ => {
                    self.advance();
                }
            }
        }
    }

    // ── Program entry point ───────────────────────────────────────────────────
    //
    // NOTE: `parse_program` is implemented in `decl.rs` (subtask 2d).
    // The method is declared there as `pub(crate) fn parse_program(...)`.

    /// Skip past any `Token::Newline` tokens at the current position.
    pub(crate) fn skip_newlines(&mut self) {
        while matches!(self.peek(), Token::Newline) {
            self.advance();
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
