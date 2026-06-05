//! Binding statement parsers: `let` and `const`.

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{Const, Stmt};
use super::super::expr::{expr_span, MergeSpan};
use super::super::Parser;

impl Parser {
    // ── Let statement ─────────────────────────────────────────────────────────

    /// Parse `let mut? pattern (: type)? = expr`.
    ///
    /// The `mut` keyword marks the binding as mutable. The type annotation is
    /// optional — the type checker infers it when absent.
    pub(crate) fn parse_let_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Let, "let")?;
        let mutable = self.advance_if(&Token::Mut);
        let pattern = self.parse_pattern()?;
        let ty = if self.advance_if(&Token::Colon) {
            Some(self.parse_type()?)
        } else {
            None
        };
        self.expect(&Token::Assign, "\"=\" in let binding")?;
        let expr = self.parse_expr()?;
        let span = start.merge_with(expr_span(&expr));
        self.consume_stmt_end();
        Ok(Stmt::Let {
            mutable,
            pattern,
            ty,
            expr,
            span,
        })
    }

    // ── Const statement ───────────────────────────────────────────────────────

    /// Parse `const NAME: T = expr` inside a function body.
    ///
    /// Unlike top-level `const` declarations (handled by decl.rs), this form
    /// appears as a statement and is wrapped in `Stmt::Const`.
    pub(crate) fn parse_const_stmt(&mut self) -> Result<Stmt, LangError> {
        let start = self.expect(&Token::Const, "const")?;
        let name = self.expect_identifier("constant name")?;
        self.expect(&Token::Colon, "\":\" after constant name")?;
        let ty = self.parse_type()?;
        self.expect(&Token::Assign, "\"=\" in const declaration")?;
        let value = self.parse_expr()?;
        let span = start.merge_with(expr_span(&value));
        self.consume_stmt_end();
        Ok(Stmt::Const(Const {
            name,
            ty,
            value,
            span,
        }))
    }
}
