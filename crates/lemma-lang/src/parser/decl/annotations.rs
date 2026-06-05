//! Annotation parser for the Lem language.
//!
//! Handles both `@name(args)` and `#[name(args)]` annotation syntax.
//! Annotation arguments may be positional (`expr`) or named (`key: expr`).

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{Annotation, AnnotationArg};
use super::super::expr::MergeSpan;
use super::super::Parser;

// ── Annotation keyword → canonical name mapping ───────────────────────────────

/// Map a known annotation `Token` to its canonical string name.
///
/// Returns `None` if the token is not a known annotation keyword.
/// This is the single source of truth for the keyword→name mapping,
/// used by both `parse_annotations` (loop guard) and `parse_at_annotation`
/// (name extraction) — DRY, no duplicated match arms.
fn annotation_token_name(tok: &Token) -> Option<&'static str> {
    match tok {
        Token::OnlyOwner => Some("onlyOwner"),
        Token::OnlyRole => Some("onlyRole"),
        Token::WhenNotPaused => Some("whenNotPaused"),
        Token::WhenPaused => Some("whenPaused"),
        Token::NonReentrant => Some("nonReentrant"),
        Token::Cooldown => Some("cooldown"),
        Token::PayableAnn => Some("payable"),
        Token::Deadline => Some("deadline"),
        Token::EstimateGas => Some("estimateGas"),
        Token::OnTransfer => Some("onTransfer"),
        Token::Indexed => Some("indexed"),
        Token::Private => Some("private"),
        Token::AgentCallable => Some("agentCallable"),
        _ => None,
    }
}

impl Parser {
    // ── Annotation list ───────────────────────────────────────────────────────

    /// Collect zero or more annotations appearing before a declaration.
    ///
    /// Each annotation is `@IDENT`, `@IDENT(args)`, `#[IDENT]`, or `#[IDENT(args)]`.
    /// Returns an empty vec if no annotations are present.
    pub(crate) fn parse_annotations(&mut self) -> Result<Vec<Annotation>, LangError> {
        let mut anns = Vec::new();
        loop {
            self.skip_newlines();
            // Known keyword annotation, bare `@`, or `Token::Annotation` string
            let is_at_ann = annotation_token_name(self.peek()).is_some()
                || matches!(self.peek(), Token::At | Token::Annotation(_));
            // `#[...]` style — only if `#` is followed by `[`
            let is_hash_ann = self.check(&Token::Hash_) && self.peek_nth(1) == &Token::LBracket;

            if is_at_ann {
                anns.push(self.parse_at_annotation()?);
            } else if is_hash_ann {
                anns.push(self.parse_hash_annotation()?);
            } else {
                break;
            }
        }
        Ok(anns)
    }

    // ── @-style annotation ────────────────────────────────────────────────────

    /// Parse a single `@name` or `@name(args)` annotation.
    ///
    /// The current token is a known annotation keyword, `@`, or `Token::Annotation`.
    /// Uses `annotation_token_name` to map keyword tokens to their canonical names —
    /// no duplicated match arms here.
    fn parse_at_annotation(&mut self) -> Result<Annotation, LangError> {
        let start = self.peek_span();

        let name = if let Some(canonical) = annotation_token_name(self.peek()) {
            // Known annotation keyword token — advance and use the canonical name.
            self.advance();
            canonical.to_string()
        } else {
            match self.peek().clone() {
                Token::At => {
                    // Bare `@` — next token must be an identifier
                    self.advance();
                    self.expect_identifier("annotation name after @")?
                }
                Token::Annotation(s) => {
                    self.advance();
                    s
                }
                _ => return Err(self.error("expected annotation")),
            }
        };

        // Optional argument list: `(arg1, key: arg2, ...)`
        let args = if self.check(&Token::LParen) {
            self.parse_annotation_args()?
        } else {
            vec![]
        };

        let end = self.prev_span();
        Ok(Annotation {
            name,
            args,
            span: start.merge_with(end),
        })
    }

    // ── #[...]-style annotation ───────────────────────────────────────────────

    /// Parse a single `#[name]` or `#[name(args)]` annotation.
    ///
    /// Caller has verified that `peek()` is `#` and `peek_nth(1)` is `[`.
    fn parse_hash_annotation(&mut self) -> Result<Annotation, LangError> {
        let start = self.peek_span();
        self.expect(&Token::Hash_, "\"#\"")?;
        self.expect(&Token::LBracket, "\"[\"")?;
        let name = self.expect_identifier("annotation name")?;
        let args = if self.check(&Token::LParen) {
            self.parse_annotation_args()?
        } else {
            vec![]
        };
        self.expect(&Token::RBracket, "\"]\"")?;
        let end = self.prev_span();
        Ok(Annotation {
            name,
            args,
            span: start.merge_with(end),
        })
    }

    // ── Annotation argument list ──────────────────────────────────────────────

    /// Parse `(arg1, key: arg2, ...)` annotation arguments.
    ///
    /// Arguments may be positional (`expr`) or named (`IDENT: expr`).
    fn parse_annotation_args(&mut self) -> Result<Vec<AnnotationArg>, LangError> {
        self.expect(&Token::LParen, "\"(\"")?;
        let mut args = Vec::new();
        while !self.check(&Token::RParen) && !self.at_end() {
            // Named arg: `IDENT : expr`
            if matches!(self.peek(), Token::Identifier(_)) && self.peek_nth(1) == &Token::Colon {
                let name = self.expect_identifier("annotation argument name")?;
                self.expect(&Token::Colon, "\":\"")?;
                let val = self.parse_expr()?;
                args.push(AnnotationArg::Named(name, val));
            } else {
                args.push(AnnotationArg::Positional(self.parse_expr()?));
            }
            if !self.advance_if(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen, "\")\"")?;
        Ok(args)
    }
}
