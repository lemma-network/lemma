//! Control-flow statement parsers: `if`, `match`, `for`, `while`, `loop`.

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{ForIter, Stmt};
use super::super::expr::MergeSpan;
use super::super::Parser;

impl Parser {
    // ── If statement ──────────────────────────────────────────────────────────

    /// Parse `if (cond) { then } (else { else_ })?`.
    ///
    /// Supports else-if chains: `else if (cond) { ... }` is parsed by
    /// recursing into `parse_if_stmt` for the else branch.
    ///
    /// `else` may appear on the next line after `}` (newlines are skipped
    /// when looking for `else`).
    pub(crate) fn parse_if_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::If, "if")?;
        self.expect(&Token::LParen, "\"(\" after if")?;
        let cond = self.parse_expr()?;
        self.expect(&Token::RParen, "\")\" after if condition")?;
        let then = self.parse_block()?;
        let else_ = if self.check_else() {
            self.consume_else();
            if self.check(&Token::If) {
                // else-if chain: wrap the nested if as a single-element else block
                Some(vec![self.parse_if_stmt()?])
            } else {
                Some(self.parse_block()?)
            }
        } else {
            None
        };
        let end = self.prev_span();
        Ok(Stmt::If {
            cond,
            then,
            else_,
            span: start.merge_with(end),
        })
    }

    // ── Match statement ───────────────────────────────────────────────────────

    /// Parse `match expr { arm* }`.
    ///
    /// Arms are separated by commas or newlines. The trailing comma/newline
    /// after the last arm is optional.
    pub(crate) fn parse_match_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Match, "match")?;
        let expr = self.parse_expr()?;
        self.expect(&Token::LBrace, "\"{\" after match scrutinee")?;
        self.skip_newlines();
        let mut arms = Vec::new();
        while !self.check(&Token::RBrace) && !self.at_end() {
            arms.push(self.parse_match_arm()?);
            self.skip_newlines();
        }
        let end = self.expect(&Token::RBrace, "\"}\" after match arms")?;
        Ok(Stmt::Match {
            expr,
            arms,
            span: start.merge_with(end),
        })
    }

    // ── For statement ─────────────────────────────────────────────────────────

    /// Parse `for pattern of expr { body }` or `for ident in start..end { body }`.
    ///
    /// Two forms:
    /// - `of` form: iterate over a collection (any iterable expression)
    /// - `in` form: range iteration with `..` (exclusive) or `..=` (inclusive)
    pub(crate) fn parse_for_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::For, "for")?;
        let pattern = self.parse_pattern()?;
        let iter = if self.advance_if(&Token::Of) {
            // for x of collection { }
            ForIter::Of(self.parse_expr()?)
        } else if self.advance_if(&Token::In) {
            // for i in start..end { } or for i in start..=end { }
            let range_start = self.parse_expr()?;
            let range_op_span = self.peek_span();
            let inclusive = if self.advance_if(&Token::DotDotEq) {
                true
            } else {
                self.expect(&Token::DotDot, "\"..\" or \"..=\" in for-in range")?;
                false
            };
            let range_end = self.parse_expr()?;
            ForIter::In(range_start, range_op_span, range_end, inclusive)
        } else {
            return Err(self.error_expected(
                vec!["of".into(), "in".into()],
                format!(
                    "expected 'of' or 'in' in for statement, got {:?}",
                    self.peek()
                ),
            ));
        };
        let body = self.parse_block()?;
        let end = self.prev_span();
        Ok(Stmt::For {
            pattern,
            iter,
            body,
            span: start.merge_with(end),
        })
    }

    // ── While statement ───────────────────────────────────────────────────────

    /// Parse `while (cond) { body }`.
    pub(crate) fn parse_while_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::While, "while")?;
        self.expect(&Token::LParen, "\"(\" after while")?;
        let cond = self.parse_expr()?;
        self.expect(&Token::RParen, "\")\" after while condition")?;
        let body = self.parse_block()?;
        let end = self.prev_span();
        Ok(Stmt::While {
            cond,
            body,
            span: start.merge_with(end),
        })
    }

    // ── Loop statement ────────────────────────────────────────────────────────

    /// Parse `loop { body }` — an unconditional infinite loop.
    pub(crate) fn parse_loop_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Loop, "loop")?;
        let body = self.parse_block()?;
        let end = self.prev_span();
        Ok(Stmt::Loop {
            body,
            span: start.merge_with(end),
        })
    }
}
