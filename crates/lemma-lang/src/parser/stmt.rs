//! Statement parser for the Lem language.
//!
//! Implements all §29 statement forms. Submodules split by concern to stay
//! under the 300-line file limit (AGENTS §3.1):
//!
//! - `stmt.rs` (this file) — dispatcher, block parser, statement-end consumer
//! - `stmt/binding.rs` — `let` and `const` statements
//! - `stmt/control.rs` — `if`, `match`, `for`, `while`, `loop`
//! - `stmt/misc.rs` — `emit`, `assert`, `revert`, `try`, `unchecked`,
//!   `return`, `break`, `continue`, expression stmts

mod binding;
mod control;
mod misc;

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;

use crate::error::LangError;
use crate::lexer::token::Token;

use super::ast::{Expr, Stmt};
use super::expr::expr_span;
use super::Parser;

impl Parser {
    // ── Block parser ──────────────────────────────────────────────────────────

    /// Parse a `{ stmts }` block body.
    ///
    /// Replaces the stub in `expr.rs` (subtask 2c). Called by all control-flow
    /// forms, lambda bodies, and match arms.
    pub(crate) fn parse_block(&mut self) -> Result<Vec<Stmt>, LangError> {
        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();
        let stmts = self.parse_stmt_list()?;
        self.expect(&Token::RBrace, "\"}\"")?;
        Ok(stmts)
    }

    // ── Statement list ────────────────────────────────────────────────────────

    /// Parse a list of statements terminated by `}` or EOF.
    ///
    /// On error, calls `synchronize()` to recover and continues parsing
    /// remaining statements (error-resilient mode).
    pub(crate) fn parse_stmt_list(&mut self) -> Result<Vec<Stmt>, LangError> {
        let mut stmts = Vec::new();
        self.skip_newlines();
        while !self.check(&Token::RBrace) && !self.at_end() {
            match self.parse_stmt() {
                Ok(stmt) => stmts.push(stmt),
                Err(e) => {
                    // Error recovery: synchronize to next statement boundary
                    // and propagate the first error.
                    self.synchronize();
                    return Err(e);
                }
            }
            self.skip_newlines();
        }
        Ok(stmts)
    }

    // ── Statement dispatcher ──────────────────────────────────────────────────

    /// Parse a single statement.
    ///
    /// Dispatches to the appropriate sub-parser based on the leading token.
    /// Newlines are consumed as statement terminators after each form.
    pub(crate) fn parse_stmt(&mut self) -> Result<Stmt, LangError> {
        self.skip_newlines();
        match self.peek().clone() {
            Token::Let => self.parse_let_stmt(),
            Token::Const => self.parse_const_stmt(),
            Token::If => self.parse_if_stmt(),
            Token::Match => self.parse_match_stmt(),
            Token::For => self.parse_for_stmt(),
            Token::While => self.parse_while_stmt(),
            Token::Loop => self.parse_loop_stmt(),
            Token::Return => self.parse_return_stmt(),
            Token::Break => {
                let s = self.peek_span();
                self.advance();
                self.consume_stmt_end();
                Ok(Stmt::Break(s))
            }
            Token::Continue => {
                let s = self.peek_span();
                self.advance();
                self.consume_stmt_end();
                Ok(Stmt::Continue(s))
            }
            Token::Emit => self.parse_emit_stmt(),
            Token::Assert => self.parse_assert_stmt(),
            Token::Revert => self.parse_revert_stmt(),
            Token::Try => self.parse_try_stmt(),
            Token::Unchecked => self.parse_unchecked_stmt(),
            // `_` is lexed as Identifier("_") — canonical placeholder path.
            // The lexer emits Identifier("_") because `_` is is_ident_start;
            // Token::Underscore is never produced for a bare `_`.
            Token::Identifier(ref name) if name == "_" => {
                let s = self.peek_span();
                self.advance();
                self.consume_stmt_end();
                Ok(Stmt::Placeholder(s))
            }
            // Semicolons as empty statements — swallow and recurse
            Token::Semicolon => {
                self.advance();
                self.skip_newlines();
                self.parse_stmt()
            }
            // Anything else: expression or assignment statement
            _ => self.parse_expr_stmt(),
        }
    }

    // ── Statement terminator ──────────────────────────────────────────────────

    /// Consume an optional `;` or `\n` that ends a statement.
    ///
    /// Newlines are the primary statement terminator in Lem (like Go).
    /// Semicolons are also accepted. Before `}` or EOF, no terminator is needed.
    pub(crate) fn consume_stmt_end(&mut self) {
        // Consume optional semicolon
        self.advance_if(&Token::Semicolon);
        // Consume following newlines
        self.skip_newlines();
    }

    // ── Expression / assignment statement ────────────────────────────────────

    /// Parse an expression statement or assignment statement.
    ///
    /// `parse_expr` already handles `Expr::Assign_` at the expression level.
    /// We unwrap it here into `Stmt::Assign` for clarity in the AST.
    pub(crate) fn parse_expr_stmt(&mut self) -> Result<Stmt, LangError> {
        let expr = self.parse_expr()?;
        let span = expr_span(&expr);
        self.consume_stmt_end();
        // Unwrap assignment expressions into Stmt::Assign
        match expr {
            Expr::Assign_(target, op, value, s) => Ok(Stmt::Assign {
                target: *target,
                op,
                value: *value,
                span: s,
            }),
            other => Ok(Stmt::Expr(other, span)),
        }
    }

    // ── Else lookahead ────────────────────────────────────────────────────────

    /// Check if the next non-newline token is `else`.
    ///
    /// In Lem, `else` may appear on the next line after `}`:
    /// ```text
    /// if (cond) {
    ///   ...
    /// }
    /// else {   ← valid
    ///   ...
    /// }
    /// ```
    pub(crate) fn check_else(&self) -> bool {
        let mut i = self.pos;
        while i < self.tokens.len() {
            match &self.tokens[i].0 {
                Token::Newline => i += 1,
                Token::Else => return true,
                _ => return false,
            }
        }
        false
    }

    /// Advance past any newlines and consume the `else` token.
    ///
    /// Caller must have verified `check_else()` returns `true`.
    pub(crate) fn consume_else(&mut self) {
        self.skip_newlines();
        self.advance(); // consume Token::Else
    }
}
