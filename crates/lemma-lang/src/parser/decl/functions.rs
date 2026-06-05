//! Function, generic parameter, and parameter list parsers.
//!
//! `parse_function` is the most complex parser in 2d — it handles:
//! - visibility (`pub`, `external`, default)
//! - mutability (`view`, `pure`, `payable`, default)
//! - generic params `<T, T: Bound>`
//! - parameter list with optional default values
//! - optional return type `-> T`
//! - optional body `{ stmts }` (absent for interface signatures)

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{Annotation, Function, GenericParam, Mutability, Param, Type, Visibility};
use super::super::expr::MergeSpan;
use super::super::Parser;

impl Parser {
    // ── Function declaration ──────────────────────────────────────────────────

    /// Parse a complete function declaration.
    ///
    /// Caller has already collected `annotations` before calling this.
    /// Handles top-level functions, contract methods, and interface signatures.
    pub(crate) fn parse_function(
        &mut self,
        annotations: Vec<Annotation>,
    ) -> Result<Function, LangError> {
        let start = if annotations.is_empty() {
            self.peek_span()
        } else {
            annotations[0].span
        };

        // Visibility: `pub` | `external` | (default = Private)
        let visibility = match self.peek() {
            Token::Pub => {
                self.advance();
                Visibility::Pub
            }
            Token::External => {
                self.advance();
                Visibility::External
            }
            _ => Visibility::Private,
        };

        // Mutability: `view` | `pure` | `payable` | (default)
        let mutability = match self.peek() {
            Token::View => {
                self.advance();
                Mutability::View
            }
            Token::Pure => {
                self.advance();
                Mutability::Pure
            }
            Token::Payable => {
                self.advance();
                Mutability::Payable
            }
            _ => Mutability::Default,
        };

        self.expect(&Token::Fn, "\"fn\"")?;
        let name = self.expect_identifier("function name")?;

        // Optional generic params: `<T, T: Bound>`
        let generic_params = if self.check(&Token::Lt) {
            self.parse_generic_params()?
        } else {
            vec![]
        };

        // Parameter list
        self.expect(&Token::LParen, "\"(\"")?;
        let params = self.parse_param_list()?;
        self.expect(&Token::RParen, "\")\"")?;

        // Optional return type: `-> T`
        let return_type = if self.advance_if(&Token::Arrow) {
            Some(self.parse_type()?)
        } else {
            None
        };

        // Body — optional for interface method signatures
        let body = if self.check(&Token::LBrace) {
            Some(self.parse_block()?)
        } else {
            None
        };

        let end = self.prev_span();
        Ok(Function {
            name,
            annotations,
            visibility,
            mutability,
            generic_params,
            params,
            return_type,
            body,
            span: start.merge_with(end),
        })
    }

    // ── Generic parameters ────────────────────────────────────────────────────

    /// Parse `<T, T: Bound>` generic parameter list.
    ///
    /// Uses `check_gt` / `expect_gt` from `ty.rs` for `>>` disambiguation —
    /// the canonical implementations live there; no local duplicates.
    pub(crate) fn parse_generic_params(&mut self) -> Result<Vec<GenericParam>, LangError> {
        self.expect(&Token::Lt, "\"<\" for generic params")?;
        let mut params = Vec::new();
        while !self.check_gt() && !self.at_end() {
            let start = self.peek_span();
            let name = self.expect_identifier("generic parameter name")?;
            // Optional bound: `: TraitName`
            let bound = if self.advance_if(&Token::Colon) {
                let bound_name = self.expect_identifier("trait bound name")?;
                Some(Type::Named(bound_name, vec![]))
            } else {
                None
            };
            params.push(GenericParam {
                name,
                bound,
                span: start,
            });
            if !self.advance_if(&Token::Comma) {
                break;
            }
        }
        // Delegate to the canonical `>>` disambiguation helper in ty.rs
        self.expect_gt("\">\"")?;
        Ok(params)
    }

    // ── Parameter list ────────────────────────────────────────────────────────

    /// Parse a comma-separated function parameter list.
    ///
    /// Each param: `name: Type` or `name: Type = default_expr`.
    /// Stops before `)`.
    pub(crate) fn parse_param_list(&mut self) -> Result<Vec<Param>, LangError> {
        let mut params = Vec::new();
        while !self.check(&Token::RParen) && !self.at_end() {
            let start = self.peek_span();
            let name = self.expect_identifier("parameter name")?;
            self.expect(&Token::Colon, "\":\"")?;
            let ty = self.parse_type()?;
            // Optional default value: `= expr`
            let default_expr = if self.advance_if(&Token::Assign) {
                Some(self.parse_expr()?)
            } else {
                None
            };
            params.push(Param {
                name,
                ty,
                default_expr,
                span: start,
            });
            if !self.advance_if(&Token::Comma) {
                break;
            }
        }
        Ok(params)
    }
}
