//! Miscellaneous statement parsers: `emit`, `assert`, `revert`, `try`,
//! `unchecked`, and `return`.

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::Stmt;
use super::super::expr::{expr_span, MergeSpan};
use super::super::Parser;

impl Parser {
    // ── Emit statement ────────────────────────────────────────────────────────

    /// Parse `emit EventName { field: value, ... }`.
    ///
    /// Emits a contract event. The event name must be an identifier.
    /// Fields are `name: expr` pairs separated by commas.
    pub(crate) fn parse_emit_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Emit, "emit")?;
        let event = self.expect_identifier("event name")?;
        self.expect(&Token::LBrace, "\"{\" after event name")?;
        let mut fields = Vec::new();
        while !self.check(&Token::RBrace) && !self.at_end() {
            let name = self.expect_identifier("field name")?;
            self.expect(&Token::Colon, "\":\" after field name")?;
            let val = self.parse_expr()?;
            fields.push((name, val));
            if !self.advance_if(&Token::Comma) {
                break;
            }
            self.skip_newlines();
        }
        let end = self.expect(&Token::RBrace, "\"}\" after emit fields")?;
        self.consume_stmt_end();
        Ok(Stmt::Emit {
            event,
            fields,
            span: start.merge_with(end),
        })
    }

    // ── Assert statement ──────────────────────────────────────────────────────

    /// Parse `assert(cond)` or `assert(cond, "message")`.
    ///
    /// The optional second argument is the revert message shown on failure.
    pub(crate) fn parse_assert_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Assert, "assert")?;
        self.expect(&Token::LParen, "\"(\" after assert")?;
        let cond = self.parse_expr()?;
        let msg = if self.advance_if(&Token::Comma) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        let end = self.expect(&Token::RParen, "\")\" after assert arguments")?;
        self.consume_stmt_end();
        Ok(Stmt::Assert {
            cond,
            msg,
            span: start.merge_with(end),
        })
    }

    // ── Revert statement ──────────────────────────────────────────────────────

    /// Parse `revert` or `revert("message")`.
    ///
    /// Reverts the current transaction. The optional message is the revert reason.
    pub(crate) fn parse_revert_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Revert, "revert")?;
        let msg = if self.check(&Token::LParen) {
            self.advance(); // consume `(`
            let m = if !self.check(&Token::RParen) {
                Some(self.parse_expr()?)
            } else {
                None
            };
            self.expect(&Token::RParen, "\")\" after revert message")?;
            m
        } else {
            None
        };
        let end = self.prev_span();
        self.consume_stmt_end();
        Ok(Stmt::Revert {
            msg,
            span: start.merge_with(end),
        })
    }

    // ── Try/catch statement ───────────────────────────────────────────────────

    /// Parse `try { body } catch (e) { catch_body }`.
    ///
    /// The catch variable binds the error value inside the catch block.
    pub(crate) fn parse_try_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Try, "try")?;
        let body = self.parse_block()?;
        self.expect(&Token::Catch, "catch")?;
        self.expect(&Token::LParen, "\"(\" after catch")?;
        let catch_var = self.expect_identifier("error variable name")?;
        self.expect(&Token::RParen, "\")\" after catch variable")?;
        let catch_body = self.parse_block()?;
        let end = self.prev_span();
        Ok(Stmt::Try {
            body,
            catch_var,
            catch_body,
            span: start.merge_with(end),
        })
    }

    // ── Unchecked statement ───────────────────────────────────────────────────

    /// Parse `unchecked { body }`.
    ///
    /// Arithmetic inside an `unchecked` block skips overflow/underflow checks.
    /// The semantic checker validates that this is only used where safe.
    pub(crate) fn parse_unchecked_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Unchecked, "unchecked")?;
        let body = self.parse_block()?;
        let end = self.prev_span();
        Ok(Stmt::Unchecked(body, start.merge_with(end)))
    }

    // ── Return statement ──────────────────────────────────────────────────────

    /// Parse `return expr?`.
    ///
    /// A bare `return` (no expression) is valid when the function returns unit.
    /// The expression is absent when the next token is a newline, `;`, `}`, or EOF.
    pub(crate) fn parse_return_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Return, "return")?;
        // Return with no expression: before newline / `}` / `;` / EOF
        let expr = if self.check(&Token::Newline)
            || self.check(&Token::RBrace)
            || self.check(&Token::Semicolon)
            || self.at_end()
        {
            None
        } else {
            Some(self.parse_expr()?)
        };
        let end = expr.as_ref().map(expr_span).unwrap_or(start);
        self.consume_stmt_end();
        Ok(Stmt::Return(expr, start.merge_with(end)))
    }
}
