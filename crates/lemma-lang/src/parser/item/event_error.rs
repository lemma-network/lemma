//! Event and error declaration parsers, plus the `is_function_start` helper.

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{Annotation, ErrorDecl, Event, EventField, FieldDecl};
use super::super::expr::MergeSpan;
use super::super::Parser;

impl Parser {
    // ── Event ─────────────────────────────────────────────────────────────────

    /// Parse `event IDENT { (@indexed)? field?: Type, ... | fn method() { ... } }`.
    ///
    /// The `@anonymous` flag is determined from the `annotations` vec collected
    /// by the caller before dispatching here. This avoids re-parsing annotations
    /// and keeps the annotation-collection logic in one place.
    ///
    /// Per spec §15, an event body may contain both regular fields and inline `fn`
    /// declarations ("computed event fields"). The parser distinguishes them via
    /// `is_function_start()` before consuming any tokens.
    pub(crate) fn parse_event_decl(
        &mut self,
        annotations: Vec<Annotation>,
    ) -> Result<Event, LangError> {
        // `@anonymous` is expressed as an annotation on the event declaration.
        let anonymous = annotations.iter().any(|a| a.name == "anonymous");

        let start = self.expect(&Token::Event, "\"event\"")?;
        let name = self.expect_identifier("event name")?;
        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();

        let mut fields = Vec::new();
        let mut methods = Vec::new();

        while !self.check(&Token::RBrace) && !self.at_end() {
            self.skip_newlines();
            if self.check(&Token::RBrace) || self.at_end() {
                break;
            }

            if self.is_function_start() {
                // Computed event field (spec §15): `fn priceImpact() -> decimal(4) { ... }`
                // Collect any leading annotations (e.g. `@view`) then parse the function.
                let anns = self.parse_annotations()?;
                methods.push(self.parse_function(anns)?);
            } else {
                let fs = self.peek_span();

                // `@indexed` annotation on the field — produced by the lexer as Token::Indexed
                let indexed = self.advance_if(&Token::Indexed);

                let field_name = self.expect_identifier("event field name")?;

                // Optional `?` after field name: `name?: Type` means optional field
                let optional = self.advance_if(&Token::QuestionMark);

                self.expect(&Token::Colon, "\":\"")?;
                let ty = self.parse_type()?;

                fields.push(EventField {
                    indexed,
                    name: field_name,
                    optional,
                    ty,
                    span: fs,
                });
            }

            self.skip_newlines();
            self.advance_if(&Token::Comma);
            self.skip_newlines();
        }

        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Event {
            name,
            anonymous,
            fields,
            methods,
            span: start.merge_with(end),
        })
    }

    // ── Error declaration ─────────────────────────────────────────────────────

    /// Parse `error IDENT { field: Type, ... }?`.
    ///
    /// The field block is optional — `error Foo` (no fields) is valid.
    pub(crate) fn parse_error_decl(&mut self) -> Result<ErrorDecl, LangError> {
        let start = self.expect(&Token::Error, "\"error\"")?;
        let name = self.expect_identifier("error name")?;

        let fields = if self.check(&Token::LBrace) {
            self.advance(); // consume `{`
            let mut fields = Vec::new();
            while !self.check(&Token::RBrace) && !self.at_end() {
                self.skip_newlines();
                if self.check(&Token::RBrace) || self.at_end() {
                    break;
                }
                let fs = self.peek_span();
                let field_name = self.expect_identifier("error field name")?;
                self.expect(&Token::Colon, "\":\"")?;
                let ty = self.parse_type()?;
                fields.push(FieldDecl {
                    name: field_name,
                    ty,
                    span: fs,
                });
                if !self.advance_if(&Token::Comma) {
                    break;
                }
                self.skip_newlines();
            }
            self.expect(&Token::RBrace, "\"}\"")?;
            fields
        } else {
            vec![]
        };

        let end = self.prev_span();
        self.skip_newlines();
        Ok(ErrorDecl {
            name,
            fields,
            span: start.merge_with(end),
        })
    }

    // ── Helper: function-start lookahead ──────────────────────────────────────

    /// Returns `true` if the current token sequence looks like the start of a function.
    ///
    /// Used by struct and enum body parsers to distinguish fields from inline methods.
    /// Checks for visibility/mutability keywords, `fn`, and annotation tokens.
    pub(crate) fn is_function_start(&self) -> bool {
        match self.peek() {
            // Visibility / mutability / fn keyword
            Token::Fn
            | Token::Pub
            | Token::View
            | Token::Pure
            | Token::External
            | Token::Payable => true,
            // Known annotation tokens that precede functions
            Token::OnlyOwner
            | Token::OnlyRole
            | Token::WhenNotPaused
            | Token::WhenPaused
            | Token::NonReentrant
            | Token::Cooldown
            | Token::PayableAnn
            | Token::Deadline
            | Token::EstimateGas
            | Token::OnTransfer
            | Token::Private
            | Token::AgentCallable => true,
            // Generic `@name` annotation or `#[name]` annotation
            Token::At | Token::Hash_ | Token::Annotation(_) => true,
            _ => false,
        }
    }
}
