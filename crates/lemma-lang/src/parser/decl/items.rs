//! Top-level item parsers: import, using, const, type alias.

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{Const, Import, ImportNames, Item, TypeAlias, Using};
use super::super::expr::MergeSpan;
use super::super::Parser;

impl Parser {
    // ── Import ────────────────────────────────────────────────────────────────

    /// Parse `import { A, B } from "path"` or `import * as Alias from "path"`.
    pub(crate) fn parse_import_item(&mut self) -> Result<Item, LangError> {
        let start = self.expect(&Token::Import, "\"import\"")?;

        let names = if self.advance_if(&Token::Star) {
            // `import * as Alias from "path"`
            self.expect(&Token::As, "\"as\"")?;
            let alias = self.expect_identifier("import alias")?;
            ImportNames::Star(alias)
        } else {
            // `import { Name1, Name2 } from "path"`
            self.expect(&Token::LBrace, "\"{\"")?;
            let mut names = Vec::new();
            while !self.check(&Token::RBrace) && !self.at_end() {
                names.push(self.expect_identifier("import name")?);
                if !self.advance_if(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::RBrace, "\"}\"")?;
            ImportNames::Named(names)
        };

        self.expect(&Token::From, "\"from\"")?;
        let from = match self.peek().clone() {
            Token::StringLiteral(s) => {
                self.advance();
                s
            }
            _ => return Err(self.error("expected string path in import")),
        };

        let end = self.prev_span();
        self.skip_newlines();
        Ok(Item::Import(Import {
            names,
            from,
            span: start.merge_with(end),
        }))
    }

    // ── Using ─────────────────────────────────────────────────────────────────

    /// Parse `using Library for Type`.
    pub(crate) fn parse_using_item(&mut self) -> Result<Item, LangError> {
        let start = self.expect(&Token::Using, "\"using\"")?;
        let library = self.expect_identifier("library name")?;
        self.expect(&Token::For, "\"for\"")?;
        let for_type = self.parse_type()?;
        let end = self.prev_span();
        self.skip_newlines();
        Ok(Item::Using(Using {
            library,
            for_type,
            span: start.merge_with(end),
        }))
    }

    // ── Const ─────────────────────────────────────────────────────────────────

    /// Parse `const NAME: Type = expr`.
    ///
    /// Used for both top-level consts and contract-member consts.
    pub(crate) fn parse_const_decl(&mut self) -> Result<Const, LangError> {
        let start = self.expect(&Token::Const, "\"const\"")?;
        let name = self.expect_identifier("const name")?;
        self.expect(&Token::Colon, "\":\"")?;
        let ty = self.parse_type()?;
        self.expect(&Token::Assign, "\"=\"")?;
        let value = self.parse_expr()?;
        let end = self.prev_span();
        self.skip_newlines();
        Ok(Const {
            name,
            ty,
            value,
            span: start.merge_with(end),
        })
    }

    // ── Type alias ────────────────────────────────────────────────────────────

    /// Parse `type Alias = Type`.
    pub(crate) fn parse_type_alias_item(&mut self) -> Result<Item, LangError> {
        let start = self.expect(&Token::Type, "\"type\"")?;
        let name = self.expect_identifier("type alias name")?;
        self.expect(&Token::Assign, "\"=\"")?;
        let ty = self.parse_type()?;
        let end = self.prev_span();
        self.skip_newlines();
        Ok(Item::TypeAlias(TypeAlias {
            name,
            ty,
            span: start.merge_with(end),
        }))
    }
}
