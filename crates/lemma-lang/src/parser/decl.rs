//! Core declaration parser for the Lem language.
//!
//! Implements all top-level and contract-member declarations.
//! Replaces the `parse_program()` placeholder from subtask 2a.
//!
//! ## Submodule layout
//!
//! - `decl.rs` (this file) — top-level dispatcher + `parse_program` replacement
//! - `decl/annotations.rs` — `@name(args)` and `#[name(args)]` annotation parser
//! - `decl/functions.rs` — function, generic params, param list
//! - `decl/contracts.rs` — contract, token, contract-member dispatcher
//! - `decl/items.rs` — import, using, const, type alias

mod annotations;
mod contracts;
mod functions;
mod items;

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;

use crate::error::LangError;
use crate::lexer::token::Token;

use super::ast::{Ast, Item};
use super::expr::MergeSpan;
use super::Parser;

impl Parser {
    // ── Program entry point (replaces 2a placeholder) ─────────────────────────

    /// Parse the full program (top-level item list).
    ///
    /// Replaces the skeleton from subtask 2a. Calls `parse_top_level_item`
    /// for each declaration until EOF.
    pub(crate) fn parse_program(&mut self) -> Result<Ast, LangError> {
        let start = self.peek_span();
        let mut items = Vec::new();
        self.skip_newlines();
        while !self.at_end() {
            let item = self.parse_top_level_item()?;
            items.push(item);
            self.skip_newlines();
        }
        let end = self.prev_span();
        Ok(Ast {
            items,
            span: start.merge_with(end),
        })
    }

    // ── Top-level item dispatcher ─────────────────────────────────────────────

    /// Parse a single top-level item.
    ///
    /// Collects any leading annotations first (for annotated top-level fns),
    /// then dispatches on the next keyword.
    pub(crate) fn parse_top_level_item(&mut self) -> Result<Item, LangError> {
        self.skip_newlines();

        // Collect any leading annotations (for annotated top-level fns)
        let annotations = self.parse_annotations()?;
        self.skip_newlines();

        // Annotations are only valid before function declarations.
        // Error early if annotations were collected but the next token is not a function.
        let next_is_fn = matches!(
            self.peek(),
            Token::Fn | Token::Pub | Token::View | Token::Pure | Token::External | Token::Payable
        );
        if !annotations.is_empty() && !next_is_fn {
            return Err(self.error(format!(
                "annotations are not permitted on {:?} declarations; \
                 annotations (@... or #[...]) are only valid before function declarations",
                self.peek()
            )));
        }

        match self.peek().clone() {
            Token::Import => self.parse_import_item(),
            Token::Using => self.parse_using_item(),
            Token::Const => {
                let c = self.parse_const_decl()?;
                Ok(Item::Const(c))
            }
            Token::Type => self.parse_type_alias_item(),
            Token::Contract => self.parse_contract_item(),
            Token::Token_ => self.parse_token_item(),
            Token::Fn
            | Token::Pub
            | Token::View
            | Token::Pure
            | Token::External
            | Token::Payable => {
                let f = self.parse_function(annotations)?;
                Ok(Item::Function(f))
            }
            // User-type declarations at top level (subtask 2e)
            Token::Struct => Ok(Item::Struct(self.parse_struct_decl()?)),
            Token::Enum => Ok(Item::Enum(self.parse_enum_decl()?)),
            Token::Error => Ok(Item::ErrorDecl(self.parse_error_decl()?)),
            // Advanced declarations at top level (subtask 2f)
            Token::Interface => Ok(Item::Interface(self.parse_interface()?)),
            Token::Trait => Ok(Item::Trait(self.parse_trait()?)),
            Token::Library => Ok(Item::Library(self.parse_library()?)),
            tok => Err(self.error_expected(
                vec!["declaration".into()],
                format!("expected top-level declaration, got {tok:?}"),
            )),
        }
    }

    // ── Shared helpers (used by multiple submodules) ───────────────────────────

    /// Parse a comma-separated list of identifiers.
    ///
    /// Used for `implements I1, I2` and `uses T1, T2` clauses.
    pub(crate) fn parse_identifier_list(&mut self) -> Result<Vec<String>, LangError> {
        let mut ids = Vec::new();
        ids.push(self.expect_identifier("identifier")?);
        while self.advance_if(&Token::Comma) {
            // Allow trailing comma before `{`
            if matches!(self.peek(), Token::LBrace) {
                break;
            }
            ids.push(self.expect_identifier("identifier")?);
        }
        Ok(ids)
    }
}
