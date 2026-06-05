//! Control-flow and complex expression forms.
//!
//! Handles: match expressions, patterns, if expressions, template literals,
//! and lambda expressions. Split from expr.rs to keep files under 300 lines.

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

use super::super::ast::{
    Expr, LambdaBody, Literal, MatchArm, MatchBody, Param, Pattern, TemplateExprSegment, Type,
};
use super::super::Parser;
use super::span::MergeSpan;

// Methods used by expr.rs; dead_code until stmt.rs (2c) and decl.rs (2d) land.
#[allow(dead_code)]
impl Parser {
    // ── Match expression ──────────────────────────────────────────────────────

    /// Parse `match expr { arm* }` as an expression.
    pub(crate) fn parse_match_expr(&mut self) -> Result<Expr, LangError> {
        let start = self.expect(&Token::Match, "match")?;
        let scrutinee = self.parse_expr()?;
        self.expect(&Token::LBrace, "\"{\" after match scrutinee")?;
        self.skip_newlines();
        let mut arms = Vec::new();
        while !self.check(&Token::RBrace) && !self.at_end() {
            arms.push(self.parse_match_arm()?);
            self.skip_newlines();
        }
        let end = self.expect(&Token::RBrace, "\"}\" after match arms")?;
        Ok(Expr::Match_(
            Box::new(scrutinee),
            arms,
            start.merge_with(end),
        ))
    }

    /// Parse a single match arm: `pattern (if guard)? => body`.
    fn parse_match_arm(&mut self) -> Result<MatchArm, LangError> {
        let start = self.peek_span();
        let pattern = self.parse_pattern()?;
        // Optional guard: `if expr`
        let guard = if self.advance_if(&Token::If) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        self.expect(&Token::FatArrow, "\"=>\" in match arm")?;
        let body = if self.check(&Token::LBrace) {
            let stmts = self.parse_block()?;
            MatchBody::Block(stmts)
        } else {
            let expr = self.parse_expr()?;
            MatchBody::Expr(expr)
        };
        // Consume optional trailing comma or newline
        self.advance_if(&Token::Comma);
        self.skip_newlines();
        let end = self.prev_span();
        Ok(MatchArm {
            pattern,
            guard,
            body,
            span: start.merge_with(end),
        })
    }

    // ── Pattern parser ────────────────────────────────────────────────────────

    /// Parse a pattern (used in match arms and let bindings).
    pub(crate) fn parse_pattern(&mut self) -> Result<Pattern, LangError> {
        self.skip_newlines();
        let start = self.peek_span();
        match self.peek().clone() {
            Token::Underscore => {
                self.advance();
                Ok(Pattern::Wildcard(start))
            }
            Token::DotDot => {
                self.advance();
                Ok(Pattern::Rest(start))
            }
            Token::BoolLiteral(b) => {
                self.advance();
                Ok(Pattern::Literal(Literal::Bool(b), start))
            }
            Token::IntLiteral(n) => {
                self.advance();
                Ok(Pattern::Literal(Literal::Int(n), start))
            }
            Token::StringLiteral(s) => {
                self.advance();
                Ok(Pattern::Literal(Literal::Str(s), start))
            }
            Token::LParen => self.parse_tuple_pattern(start),
            Token::Identifier(name) => {
                self.advance();
                // Struct pattern: Name { fields }
                if self.check(&Token::LBrace) {
                    return self.parse_struct_pattern(name, start);
                }
                // Enum variant with inner: Name(patterns)
                if self.check(&Token::LParen) {
                    return self.parse_enum_variant_pattern(name, start);
                }
                // Plain identifier binding
                Ok(Pattern::Ident(name, start))
            }
            tok => Err(self.error_expected(
                vec!["pattern".into()],
                format!("expected pattern, got {tok:?}"),
            )),
        }
    }

    /// Parse `(a, b, c)` tuple pattern.
    fn parse_tuple_pattern(&mut self, start: Span) -> Result<Pattern, LangError> {
        self.expect(&Token::LParen, "\"(\"")?;
        let mut pats = Vec::new();
        while !self.check(&Token::RParen) && !self.at_end() {
            pats.push(self.parse_pattern()?);
            if !self.advance_if(&Token::Comma) {
                break;
            }
        }
        let end = self.expect(&Token::RParen, "\")\" after tuple pattern")?;
        Ok(Pattern::Tuple(pats, start.merge_with(end)))
    }

    /// Parse `Name { field: pat, ... }` struct pattern.
    fn parse_struct_pattern(&mut self, name: String, start: Span) -> Result<Pattern, LangError> {
        self.expect(&Token::LBrace, "\"{\"")?;
        let mut fields = Vec::new();
        while !self.check(&Token::RBrace) && !self.at_end() {
            let field_name = self.expect_identifier("field name")?;
            self.expect(&Token::Colon, "\":\" in struct pattern")?;
            let pat = self.parse_pattern()?;
            fields.push((field_name, pat));
            if !self.advance_if(&Token::Comma) {
                break;
            }
        }
        let end = self.expect(&Token::RBrace, "\"}\" after struct pattern")?;
        Ok(Pattern::Struct_ {
            name,
            fields,
            span: start.merge_with(end),
        })
    }

    /// Parse `Name(pat1, pat2)` enum variant pattern.
    fn parse_enum_variant_pattern(
        &mut self,
        name: String,
        start: Span,
    ) -> Result<Pattern, LangError> {
        self.expect(&Token::LParen, "\"(\"")?;
        let mut inner = Vec::new();
        while !self.check(&Token::RParen) && !self.at_end() {
            inner.push(self.parse_pattern()?);
            if !self.advance_if(&Token::Comma) {
                break;
            }
        }
        let end = self.expect(&Token::RParen, "\")\" after enum variant pattern")?;
        let inner_opt = if inner.is_empty() { None } else { Some(inner) };
        Ok(Pattern::EnumVariant {
            name,
            inner: inner_opt,
            span: start.merge_with(end),
        })
    }

    // ── If expression ─────────────────────────────────────────────────────────

    /// Parse `if (cond) { then } (else { else_ })?` as an expression.
    pub(crate) fn parse_if_expr(&mut self) -> Result<Expr, LangError> {
        let start = self.expect(&Token::If, "if")?;
        self.expect(&Token::LParen, "\"(\" after if")?;
        let cond = self.parse_expr()?;
        self.expect(&Token::RParen, "\")\" after if condition")?;
        let then = self.parse_block()?;
        let else_ = if self.advance_if(&Token::Else) {
            Some(self.parse_block()?)
        } else {
            None
        };
        let end = self.prev_span();
        Ok(Expr::If_ {
            cond: Box::new(cond),
            then,
            else_,
            span: start.merge_with(end),
        })
    }

    // ── Template literal ──────────────────────────────────────────────────────

    /// Parse a template literal `` `text ${expr} text` ``.
    ///
    /// The lexer emits `Token::TemplateLiteral(Vec<TemplateSegment>)` where
    /// `TemplateSegment::Interpolation(String)` holds the raw source of the
    /// interpolated expression. We re-lex and re-parse each interpolation.
    pub(crate) fn parse_template_literal(
        &mut self,
        segs: Vec<crate::lexer::token::TemplateSegment>,
    ) -> Result<Expr, LangError> {
        let span = self.peek_span();
        self.advance(); // consume the TemplateLiteral token
        let mut result = Vec::new();
        for seg in segs {
            match seg {
                crate::lexer::token::TemplateSegment::Literal(s) => {
                    result.push(TemplateExprSegment::Literal(s));
                }
                crate::lexer::token::TemplateSegment::Interpolation(src) => {
                    // Re-lex and re-parse the interpolation source
                    let inner_tokens = crate::lexer::tokenize(&src).map_err(|e| {
                        LangError::Parse(crate::parser::ParseError {
                            message: format!("in template interpolation: {e}"),
                            span,
                            expected: vec![],
                        })
                    })?;
                    let mut inner = Parser::new(inner_tokens);
                    let expr = inner.parse_expr()?;
                    // Ensure no trailing tokens remain — `${1 2}` has a stray `2`
                    // after the expression `1`, which is a syntax error.
                    if !inner.at_end() {
                        return Err(LangError::Parse(crate::parser::ParseError {
                            message: format!(
                                "unexpected tokens after expression in template interpolation: {:?}",
                                inner.peek()
                            ),
                            span,
                            expected: vec![],
                        }));
                    }
                    result.push(TemplateExprSegment::Interpolation(expr));
                }
            }
        }
        Ok(Expr::Template(result, span))
    }

    // ── Lambda ────────────────────────────────────────────────────────────────

    /// Parse a lambda body: either `{ stmts }` or a bare expression.
    pub(crate) fn parse_lambda_body(&mut self) -> Result<LambdaBody, LangError> {
        if self.check(&Token::LBrace) {
            let stmts = self.parse_block()?;
            Ok(LambdaBody::Block(stmts))
        } else {
            let expr = self.parse_expr()?;
            Ok(LambdaBody::Expr(Box::new(expr)))
        }
    }

    /// Convert a list of expressions into lambda params (for `(x, y) => body`).
    ///
    /// Each expression must be a plain `Expr::Ident` — anything else is an error.
    pub(crate) fn parse_lambda_from_exprs(
        &mut self,
        exprs: Vec<Expr>,
        span: Span,
    ) -> Result<Expr, LangError> {
        self.expect(&Token::FatArrow, "\"=>\" in lambda expression")?;
        let mut params = Vec::new();
        for e in exprs {
            match e {
                Expr::Ident(name, s) => params.push(Param {
                    name,
                    ty: Type::Named("_".into(), vec![]),
                    default_expr: None,
                    span: s,
                }),
                _ => return Err(self.error("lambda parameters must be plain identifiers")),
            }
        }
        let body = self.parse_lambda_body()?;
        let end = self.prev_span();
        Ok(Expr::Lambda {
            params,
            body,
            span: span.merge_with(end),
        })
    }
}
