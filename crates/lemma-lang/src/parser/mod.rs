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
//! ## Submodule layout
//!
//! - `ast`   — all AST node definitions
//! - `error` — `ParseError` type
//! - `ty`    — type parser (all primitive, composite, and generic types)
//! - `expr`  — expression parser (literals, operators, calls, member access)
//! - `stmt`  — statement parser (let, if, for, match, emit, return, …)
//! - `decl`  — declaration parser (contract, token, function, import, using)
//! - `item`  — struct, enum, event, error, interface, trait, library parsers
//!
//! Integration tests live in `tests/parse_contracts.rs` (P3·Step 2 acceptance proof).

pub mod ast;
mod decl;
pub mod error;
mod expr;
mod item;
mod stmt;
mod ty;

pub use ast::*;
pub use error::ParseError;
// Re-export the canonical span extractor so type_checker and other crate
// modules can use it without reaching into the private `expr` submodule.
pub(crate) use expr::expr_span;

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
    /// Positions where `expect_gt` split a `Token::Shr` (`>>`) into a `Token::Gt`
    /// by mutating the buffer in place (Technical Debt P3-parser-1).
    ///
    /// This is the safety net for that debt: the buffer mutation is only sound
    /// while the parser is strictly forward-moving.  [`Parser::rewind_to`] — the
    /// single sanctioned way to move `pos` backward — `debug_assert!`s that no
    /// rewind crosses any of these positions.  If a future backtracking helper
    /// rewinds past a `>>`-split point, tests will panic immediately rather than
    /// silently misparsing.  See `living-notes.md` "P3-parser-1".
    gt_split_positions: Vec<usize>,
}

// Cursor helpers are forward-declared here and wired into the sub-parsers
// (expr.rs, stmt.rs, decl.rs, item.rs) in subtasks 2b-2f.
impl Parser {
    /// Create a new parser from a token stream.
    ///
    /// The stream must end with `Token::Eof` (guaranteed by the lexer).
    pub(crate) fn new(tokens: Vec<(Token, Span)>) -> Self {
        Self {
            tokens,
            pos: 0,
            gt_split_positions: Vec::new(),
        }
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

    // ── Backtracking safety net (Technical Debt P3-parser-1) ──────────────────

    /// Record that `expect_gt` split a `Token::Shr` into a `Token::Gt` at the
    /// current position by mutating the buffer.
    ///
    /// Called only by [`Parser::expect_gt`].  See [`Parser::rewind_to`] for the
    /// guard that makes this mutation safe.
    pub(crate) fn record_gt_split(&mut self, pos: usize) {
        self.gt_split_positions.push(pos);
    }

    /// Move the cursor backward to `pos` — the ONLY sanctioned way to rewind.
    ///
    /// Any future backtracking / speculative-parse helper MUST route its rewind
    /// through this method (never assign `self.pos` directly — the field is
    /// private to this module).
    ///
    /// # Panics (debug builds)
    ///
    /// `debug_assert!`s that the rewind target does not cross any position where
    /// `expect_gt` split a `>>` token (Technical Debt P3-parser-1).  Crossing such
    /// a position would expose a `Gt` where the source had `Shr`, silently
    /// misparsing.  If this fires, implement the `pending_gt` refactor (so
    /// `expect_gt` no longer mutates the buffer) BEFORE adding the backtracking
    /// that triggered it.  See `living-notes.md` "P3-parser-1".
    //
    // Justified `dead_code`: a deliberate forward-API safety net. The parser is
    // currently strictly forward-moving (no production caller rewinds), so this is
    // exercised only by the P3-parser-1 guard tests today. It exists so the FIRST
    // future backtracking helper is forced through this single guarded door instead
    // of assigning `self.pos` directly. Remove the allow once a production caller lands.
    #[allow(dead_code)]
    pub(crate) fn rewind_to(&mut self, pos: usize) {
        debug_assert!(
            !self.gt_split_positions.iter().any(|&split| split >= pos),
            "P3-parser-1: rewind to {pos} crosses a `>>`-split position \
             ({:?}) — the expect_gt buffer mutation is now unsound. Implement \
             the pending_gt refactor (living-notes P3-parser-1) BEFORE adding \
             this backtracking.",
            self.gt_split_positions,
        );
        self.pos = pos;
    }

    /// Current cursor position — test-only accessor for the P3-parser-1 guard tests.
    #[cfg(test)]
    pub(crate) fn pos_for_test(&self) -> usize {
        self.pos
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

    /// Consume the separator between items in a **block declaration**.
    ///
    /// ## Canonical policy (DB-A35) — applies to ALL block declarations:
    /// `state {}`, `struct {}`, `enum {}`, `event {}`, `error {}`,
    /// `config {}`, `metadata {}` (the latter two are covered transitively:
    /// both delegate to `parse_config_entries` which calls this helper — there
    /// is no separate `metadata` call-site; grep for `parse_config_entries`).
    ///
    /// Pola B: **newline OR comma, trailing separator permitted.**
    /// ```text
    /// field1: u128          ← newline-only
    /// field2: bool,         ← comma (optional trailing)
    /// field3: Address,      ← comma + newline
    /// ```
    ///
    /// Inline lists (params, tuples, arrays, call args) use comma-required
    /// (Pola A) and are NOT affected by this helper.
    pub(crate) fn consume_block_sep(&mut self) {
        self.skip_newlines(); // allow newline before comma
        self.advance_if(&Token::Comma); // optional comma
        self.skip_newlines(); // allow newlines after
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
