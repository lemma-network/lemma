//! Constructor-shaped primary expressions: struct literals and `new` expressions.
//!
//! Extracted from `primary.rs` to keep that file under the §3.1 300-line limit.

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

use super::super::ast::{Expr, Param, Type};
use super::super::Parser;
use super::span::MergeSpan;

#[allow(dead_code)] // TODO(2c-2d): wired from stmt/decl parsers
impl Parser {
    /// Parse an identifier that may be:
    /// - A single-param lambda: `x => x * 2`
    /// - A struct literal: `Foo { x: 1, ...base }`
    /// - A plain identifier reference: `foo`
    pub(crate) fn parse_ident_or_struct_or_lambda(
        &mut self,
        name: String,
    ) -> Result<Expr, LangError> {
        let span = self.peek_span();
        self.advance(); // consume the identifier

        // Single-param lambda: ident => body
        if self.check(&Token::FatArrow) {
            self.advance(); // consume `=>`
            let body = self.parse_lambda_body()?;
            let end = self.prev_span();
            return Ok(Expr::Lambda {
                params: vec![Param {
                    name,
                    ty: Type::Named("_".into(), vec![]),
                    default_expr: None,
                    span,
                }],
                body,
                span: span.merge_with(end),
            });
        }

        // Struct literal: Name { field: val, ...base }
        // Only if next token is `{` AND it is NOT a call-opts block.
        // (Call-opts are handled in postfix; struct literals are primary-level.)
        if self.check(&Token::LBrace) && !self.is_call_opts_block() {
            return self.parse_struct_literal(name, span);
        }

        Ok(Expr::Ident(name, span))
    }

    // ── Struct literal ────────────────────────────────────────────────────────

    /// Parse `Name { field: val, field2: val2, ...base }`.
    pub(crate) fn parse_struct_literal(
        &mut self,
        name: String,
        start: Span,
    ) -> Result<Expr, LangError> {
        self.expect(&Token::LBrace, "\"{\"")?;
        let mut fields = Vec::new();
        let mut spread = None;
        while !self.check(&Token::RBrace) && !self.at_end() {
            // Spread: `...base` — lexer emits `...` as [DotDot, Dot]
            // so we check for DotDot followed by Dot (three-dot spread).
            let is_spread = self.check(&Token::DotDot) && self.peek_nth(1) == &Token::Dot;
            if is_spread {
                self.advance(); // consume `..`
                self.advance(); // consume `.`
                let base = self.parse_expr()?;
                spread = Some(Box::new(base));
                self.advance_if(&Token::Comma);
                break; // spread must be last
            }
            let field_name = self.expect_identifier("field name")?;
            self.expect(&Token::Colon, "\":\" after field name")?;
            let val = self.parse_expr()?;
            fields.push((field_name, val));
            if !self.advance_if(&Token::Comma) {
                break;
            }
        }
        let end = self.expect(&Token::RBrace, "\"}\" after struct literal")?;
        Ok(Expr::Struct_ {
            name,
            fields,
            spread,
            span: start.merge_with(end),
        })
    }

    // ── new expression ────────────────────────────────────────────────────────

    /// Parse `new TypeName{opts}?(args)`.
    ///
    /// Syntax: `new Name` optionally followed by `{value:.., gas:.., salt:..}`
    /// call-opts and then `(args)`.
    pub(crate) fn parse_new_expr(&mut self) -> Result<Expr, LangError> {
        let start = self.expect(&Token::New, "new")?;
        let ty_name = self.expect_identifier("type name after new")?;
        // Optional call-opts: {value: ..., gas: ..., salt: ...}
        // Keep in sync with CallOpts fields — if a 4th opt is added, update
        // is_call_opts_block() in ops.rs too.
        let opts = if self.check(&Token::LBrace) && self.is_call_opts_block() {
            Some(self.parse_call_opts()?)
        } else {
            None
        };
        let args = self.parse_call_args()?;
        let end = self.prev_span();
        Ok(Expr::New {
            ty: ty_name,
            opts,
            args,
            span: start.merge_with(end),
        })
    }
}
