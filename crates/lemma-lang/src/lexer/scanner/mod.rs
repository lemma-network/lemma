//! Character-by-character scanner for the Lem language lexer.
//!
//! [`Scanner`] is the internal engine that drives tokenization. It is private
//! to the `lexer` module — callers use the public [`super::tokenize`] function.
//!
//! ## Design
//!
//! The scanner maintains a cursor into the source string and emits one token
//! per call to [`Scanner::next_token`]. It is intentionally fuzz-safe: no
//! `unwrap()`, `panic!()`, or `unreachable!()` in production paths.
//!
//! ## Priority order (prevents mis-tokenization)
//!
//! 1. Whitespace (space/tab) — skip
//! 2. Newline — emit `Token::Newline`
//! 3. Comments — `///` before `//` before `/*`
//! 4. String/bytes/template literals
//! 5. Char literals
//! 6. Number literals (hex, binary, decimal)
//! 7. Address literals (`lem1`, `tlem1`, `dlem1`)
//! 8. Annotations (`@name`)
//! 9. Identifiers and keywords
//! 10. Multi-char operators (longest match first)
//! 11. Single-char operators and punctuation
//! 12. Unknown character → error

mod comments;
mod keywords;
mod numbers;
mod operators;
mod strings;

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

// ─── Mark ─────────────────────────────────────────────────────────────────────

/// Cursor position snapshot — replaces the `(start_offset, start_line, start_col)` triple.
///
/// Captured BEFORE scanning a token via `self.mark()`, then passed to
/// `self.span_from_mark()` or `self.lex_error_at()`.
pub(super) struct Mark {
    pub(super) offset: usize,
    pub(super) line: u32,
    pub(super) col: u32,
}

// ─── Scanner ──────────────────────────────────────────────────────────────────

/// Internal character-by-character scanner.
///
/// Holds a reference to the source string and a cursor position. All methods
/// are `&mut self` because scanning advances the cursor.
pub(super) struct Scanner<'src> {
    /// The full source string being scanned.
    src: &'src str,
    /// Current byte offset into `src`.
    pos: usize,
    /// Current 1-indexed line number.
    line: u32,
    /// Current 1-indexed column (byte offset on the current line).
    col: u32,
}

impl<'src> Scanner<'src> {
    /// Create a new scanner positioned at the start of `src`.
    pub(super) fn new(src: &'src str) -> Self {
        Self {
            src,
            pos: 0,
            line: 1,
            col: 1,
        }
    }

    /// Returns `true` when the scanner has consumed all input.
    pub(super) fn is_at_end(&self) -> bool {
        self.pos >= self.src.len()
    }

    /// Current 1-indexed line number at the scanner cursor (for EOF span).
    pub(super) fn line(&self) -> u32 {
        self.line
    }

    /// Current 1-indexed column at the scanner cursor (for EOF span).
    pub(super) fn col(&self) -> u32 {
        self.col
    }

    /// Peek at the current character without advancing.
    pub(super) fn peek(&self) -> Option<char> {
        self.src[self.pos..].chars().next()
    }

    /// Peek at the character after the current one without advancing.
    pub(super) fn peek_next(&self) -> Option<char> {
        let mut chars = self.src[self.pos..].chars();
        chars.next(); // skip current
        chars.next()
    }

    /// Peek two characters ahead without advancing.
    ///
    /// Only used to distinguish `///` (doc comment) from `//` (line comment)
    /// in the comment-scanning dispatch.
    pub(super) fn peek_two_ahead(&self) -> Option<char> {
        let mut chars = self.src[self.pos..].chars();
        chars.next();
        chars.next();
        chars.next()
    }

    /// Advance past the current character and return it.
    ///
    /// Updates `line` and `col` tracking. Returns `None` at end of input.
    pub(super) fn advance(&mut self) -> Option<char> {
        let ch = self.src[self.pos..].chars().next()?;
        self.pos += ch.len_utf8();
        if ch == '\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += ch.len_utf8() as u32;
        }
        Some(ch)
    }

    /// Advance only if the current character matches `expected`.
    pub(super) fn advance_if(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    /// Snapshot the current cursor position.
    pub(super) fn mark(&self) -> Mark {
        Mark {
            offset: self.pos,
            line: self.line,
            col: self.col,
        }
    }

    /// Build a [`Span`] from a previously captured [`Mark`] to the current position.
    pub(super) fn span_from_mark(&self, mark: &Mark) -> Span {
        Span {
            line: mark.line,
            col: mark.col,
            offset: mark.offset,
            len: self.pos - mark.offset,
        }
    }

    /// Build a single-character [`Span`] at the given position.
    pub(super) fn span_single(line: u32, col: u32, offset: usize) -> Span {
        Span {
            line,
            col,
            offset,
            len: 1,
        }
    }

    /// Construct a `LangError::Lex` at the current position.
    pub(super) fn lex_error(&self, message: impl Into<String>, span: Span) -> LangError {
        LangError::Lex {
            message: message.into(),
            span,
        }
    }

    /// Build a lex error at a previously captured [`Mark`] position.
    pub(super) fn lex_error_at(&self, mark: &Mark, message: impl Into<String>) -> LangError {
        LangError::Lex {
            message: message.into(),
            span: self.span_from_mark(mark),
        }
    }

    // ── Scan the next token ───────────────────────────────────────────────────

    /// Scan and return the next `(Token, Span)` pair.
    ///
    /// Returns `None` only when the scanner is at end-of-file (the caller
    /// should emit `Token::Eof` in that case).
    pub(super) fn next_token(&mut self) -> Option<Result<(Token, Span), LangError>> {
        loop {
            if self.is_at_end() {
                return None;
            }

            let mark = self.mark();
            let ch = self.peek()?;

            // 1. Whitespace (space/tab) — skip silently
            if ch == ' ' || ch == '\t' || ch == '\r' {
                self.advance();
                continue;
            }

            // 2. Newline
            if ch == '\n' {
                self.advance();
                let span = self.span_from_mark(&mark);
                return Some(Ok((Token::Newline, span)));
            }

            // 3. Comments — check `///` before `//` before `/*`
            if ch == '/' {
                let next = self.peek_next();
                if next == Some('/') {
                    let two_ahead = self.peek_two_ahead();
                    if two_ahead == Some('/') {
                        // Doc comment `///`
                        return Some(Ok(self.scan_doc_comment(mark)));
                    }
                    // Line comment `//`
                    return Some(Ok(self.scan_line_comment(mark)));
                }
                if next == Some('*') {
                    // Block comment `/*`
                    return Some(self.scan_block_comment(mark));
                }
            }

            // 4. String / bytes / template literals
            if ch == '"' {
                return Some(self.scan_string(mark));
            }
            if ch == 'b' && self.peek_next() == Some('"') {
                return Some(self.scan_bytes_literal(mark));
            }
            if ch == '`' {
                return Some(self.scan_template(mark));
            }

            // 5. Char literals
            if ch == '\'' {
                return Some(self.scan_char(mark));
            }

            // 6. Number literals
            if ch.is_ascii_digit() {
                return Some(self.scan_number(mark));
            }

            // 7. Address literals — check before identifier scanning
            // Prefixes: `lem1`, `tlem1`, `dlem1`
            if self.starts_address_literal() {
                return Some(self.scan_address_literal(mark));
            }

            // 8. Annotations
            if ch == '@' {
                return Some(self.scan_annotation(mark));
            }

            // 9. Identifiers and keywords
            if keywords::is_ident_start(ch) {
                return Some(Ok(self.scan_identifier(mark)));
            }

            // 10 & 11. Operators and punctuation (multi-char first)
            return Some(self.scan_operator(mark));
        }
    }

    // ── Unit suffix peek ──────────────────────────────────────────────────────

    /// If the current position starts a unit suffix (`.ether`, `.gwei`, etc.),
    /// consume it and return the corresponding token + span.
    ///
    /// Called by the `tokenize` function after emitting an integer token.
    pub(super) fn try_scan_unit_suffix(&mut self) -> Option<(Token, Span)> {
        if self.peek() != Some('.') {
            return None;
        }
        // Peek ahead to see if it's a known unit suffix
        let rest = &self.src[self.pos + 1..]; // skip the `.`
        let suffix_len = rest
            .chars()
            .take_while(|c| c.is_alphabetic())
            .map(|c| c.len_utf8())
            .sum::<usize>();
        if suffix_len == 0 {
            return None;
        }
        let suffix = &rest[..suffix_len];
        let unit = match suffix {
            "ether" => Token::UnitEther,
            "gwei" => Token::UnitGwei,
            "minutes" => Token::UnitMinutes,
            "hours" => Token::UnitHours,
            "days" => Token::UnitDays,
            "seconds" => Token::UnitSeconds,
            "months" => Token::UnitMonths,
            "tokens" => Token::UnitTokens,
            _ => return None,
        };
        let mark = self.mark();
        self.advance(); // `.`
        for _ in 0..suffix_len {
            self.advance();
        }
        let span = self.span_from_mark(&mark);
        Some((unit, span))
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
