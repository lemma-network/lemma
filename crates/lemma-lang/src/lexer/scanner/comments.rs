//! Comment-scanning methods for the Lem lexer.
//!
//! Handles `///` doc comments, `//` line comments, and `/* */` block comments.
//! Block comments are non-nesting per the Lem spec.

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

use super::{Mark, Scanner};

impl<'src> Scanner<'src> {
    /// Scan a `///` doc comment to end of line.
    pub(super) fn scan_doc_comment(&mut self, mark: Mark) -> (Token, Span) {
        // Consume `///`
        self.advance();
        self.advance();
        self.advance();
        let content_start = self.pos;
        while !self.is_at_end() && self.peek() != Some('\n') {
            self.advance();
        }
        let content = self.src[content_start..self.pos].to_string();
        let span = self.span_from_mark(&mark);
        (Token::DocComment(content), span)
    }

    /// Scan a `//` line comment to end of line.
    pub(super) fn scan_line_comment(&mut self, mark: Mark) -> (Token, Span) {
        // Consume `//`
        self.advance();
        self.advance();
        let content_start = self.pos;
        while !self.is_at_end() && self.peek() != Some('\n') {
            self.advance();
        }
        let content = self.src[content_start..self.pos].to_string();
        let span = self.span_from_mark(&mark);
        (Token::LineComment(content), span)
    }

    /// Scan a `/* ... */` block comment (not nested).
    ///
    /// Per the Lem spec, block comments do NOT nest — the first `*/` closes
    /// the comment regardless of any `/*` inside.
    pub(super) fn scan_block_comment(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        // Consume `/*`
        self.advance();
        self.advance();
        let content_start = self.pos;
        loop {
            if self.is_at_end() {
                // End of input inside block comment — unterminated
                return Err(self.lex_error_at(&mark, "unterminated block comment"));
            }
            if self.peek() == Some('*') && self.peek_next() == Some('/') {
                let content = self.src[content_start..self.pos].to_string();
                self.advance(); // `*`
                self.advance(); // `/`
                let span = self.span_from_mark(&mark);
                return Ok((Token::BlockComment(content), span));
            }
            self.advance();
        }
    }
}
