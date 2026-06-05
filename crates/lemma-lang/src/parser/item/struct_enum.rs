//! Struct and enum declaration parsers.

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{Enum, EnumVariant, FieldDecl, Struct, StructMember};
use super::super::expr::MergeSpan;
use super::super::Parser;

impl Parser {
    // ── Struct ────────────────────────────────────────────────────────────────

    /// Parse `struct IDENT<T>? { (field | method)* }`.
    ///
    /// Struct bodies may contain named fields (`name: Type`) and inline methods.
    /// Methods are detected by `is_function_start()` before consuming any tokens.
    pub(crate) fn parse_struct_decl(&mut self) -> Result<Struct, LangError> {
        let start = self.expect(&Token::Struct, "\"struct\"")?;
        let name = self.expect_identifier("struct name")?;

        let generic_params = if self.check(&Token::Lt) {
            self.parse_generic_params()?
        } else {
            vec![]
        };

        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();

        let mut members = Vec::new();
        while !self.check(&Token::RBrace) && !self.at_end() {
            self.skip_newlines();
            if self.check(&Token::RBrace) || self.at_end() {
                break;
            }

            if self.is_function_start() {
                // Inline method: collect annotations then parse function
                let annotations = self.parse_annotations()?;
                let func = self.parse_function(annotations)?;
                members.push(StructMember::Method(func));
            } else {
                // Named field: `IDENT: Type`
                let fs = self.peek_span();
                let fname = self.expect_identifier("field name")?;
                self.expect(&Token::Colon, "\":\"")?;
                let ty = self.parse_type()?;
                members.push(StructMember::Field(FieldDecl {
                    name: fname,
                    ty,
                    span: fs,
                }));
            }

            self.skip_newlines();
            self.advance_if(&Token::Comma);
            self.skip_newlines();
        }

        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Struct {
            name,
            generic_params,
            members,
            span: start.merge_with(end),
        })
    }

    // ── Enum ──────────────────────────────────────────────────────────────────

    /// Parse `enum IDENT<T>? { (variant | method)* }`.
    ///
    /// Per spec §10, methods appear at the enum body level (not per-variant).
    /// Variants may be unit, named-field (`{ f: T }`), or positional (`(T1, T2)`).
    /// Positional fields receive synthetic names `"_0"`, `"_1"`, … to satisfy
    /// the `FieldDecl.name: String` contract.
    pub(crate) fn parse_enum_decl(&mut self) -> Result<Enum, LangError> {
        let start = self.expect(&Token::Enum, "\"enum\"")?;
        let name = self.expect_identifier("enum name")?;

        let generic_params = if self.check(&Token::Lt) {
            self.parse_generic_params()?
        } else {
            vec![]
        };

        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();

        let mut variants = Vec::new();
        let mut methods = Vec::new();

        while !self.check(&Token::RBrace) && !self.at_end() {
            self.skip_newlines();
            if self.check(&Token::RBrace) || self.at_end() {
                break;
            }

            if self.is_function_start() {
                // Enum-body method (spec §10: methods live at enum level, not per-variant)
                let annotations = self.parse_annotations()?;
                let func = self.parse_function(annotations)?;
                methods.push(func);
            } else {
                variants.push(self.parse_enum_variant()?);
            }

            self.skip_newlines();
            self.advance_if(&Token::Comma);
            self.skip_newlines();
        }

        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Enum {
            name,
            generic_params,
            variants,
            methods,
            span: start.merge_with(end),
        })
    }

    /// Parse a single enum variant.
    ///
    /// Variants may be:
    /// - Unit: `Pending`
    /// - Named-field: `Filled { price: u128, timestamp: u64 }`
    /// - Positional: `Pair(u128, Address)` — fields get synthetic names `"_0"`, `"_1"`, …
    /// - With discriminant: `Active = 1`
    pub(crate) fn parse_enum_variant(&mut self) -> Result<EnumVariant, LangError> {
        let start = self.peek_span();
        let name = self.expect_identifier("variant name")?;

        let fields = if self.check(&Token::LBrace) {
            // Named-field variant: `Variant { field: Type, ... }`
            self.advance(); // consume `{`
            let mut fields = Vec::new();
            while !self.check(&Token::RBrace) && !self.at_end() {
                self.skip_newlines();
                if self.check(&Token::RBrace) || self.at_end() {
                    break;
                }
                let fs = self.peek_span();
                let field_name = self.expect_identifier("field name")?;
                self.expect(&Token::Colon, "\":\"")?;
                let ty = self.parse_type()?;
                fields.push(FieldDecl {
                    name: field_name,
                    ty,
                    span: fs,
                });
                self.advance_if(&Token::Comma);
                self.skip_newlines();
            }
            self.expect(&Token::RBrace, "\"}\"")?;
            fields
        } else if self.check(&Token::LParen) {
            // Positional variant: `Variant(T1, T2)` — synthetic names `"_0"`, `"_1"`, …
            self.advance(); // consume `(`
            let mut fields = Vec::new();
            let mut idx: usize = 0;
            while !self.check(&Token::RParen) && !self.at_end() {
                let fs = self.peek_span();
                let ty = self.parse_type()?;
                // Positional fields use synthetic names to satisfy FieldDecl.name: String
                fields.push(FieldDecl {
                    name: format!("_{idx}"),
                    ty,
                    span: fs,
                });
                idx += 1;
                if !self.advance_if(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::RParen, "\")\"")?;
            fields
        } else {
            // Unit variant
            vec![]
        };

        // Optional discriminant: `= expr`
        let discriminant = if self.advance_if(&Token::Assign) {
            Some(self.parse_expr()?)
        } else {
            None
        };

        let end = self.prev_span();
        Ok(EnumVariant {
            name,
            fields,
            discriminant,
            span: start.merge_with(end),
        })
    }
}
