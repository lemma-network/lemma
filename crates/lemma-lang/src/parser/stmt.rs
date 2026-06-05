//! Statement parser for the Lem language.
//!
//! Implements all §29 statement forms. Full implementation is in subtask 2c.
//! This file provides the `parse_stmt` stub so the module compiles cleanly.

use crate::error::LangError;
use crate::lexer::token::Token;

use super::ast::Stmt;
use super::Parser;

// Statement-parser methods — full implementation in subtask 2c.
#[allow(dead_code)]
impl Parser {
    /// Parse a single statement.
    ///
    /// TODO(2c): full implementation in subtask 2c.
    pub(crate) fn parse_stmt(&mut self) -> Result<Stmt, LangError> {
        Err(self.error("parse_stmt not yet implemented — subtask 2c"))
    }

    /// Parse a list of statements terminated by `}`.
    ///
    /// The stub in expr.rs (`parse_block`) is the active implementation until
    /// subtask 2c replaces it with the full statement parser.
    pub(crate) fn parse_stmt_list(&mut self) -> Result<Vec<Stmt>, LangError> {
        let mut stmts = Vec::new();
        self.skip_newlines();
        while !self.check(&Token::RBrace) && !self.at_end() {
            stmts.push(self.parse_stmt()?);
            self.skip_newlines();
        }
        Ok(stmts)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
