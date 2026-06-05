//! Operator and punctuation scanning for the Lem lexer.
//!
//! Handles all multi-character and single-character operators using
//! longest-match-first dispatch.

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

use super::{Mark, Scanner};

impl<'src> Scanner<'src> {
    /// Scan an operator or punctuation token (multi-char first, then single).
    pub(super) fn scan_operator(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        let ch = match self.advance() {
            Some(c) => c,
            None => {
                // Should not happen — caller checks is_at_end
                let span = Span::at(mark.line, mark.col, mark.offset);
                return Err(self.lex_error("unexpected end of input", span));
            }
        };

        let token = match ch {
            '-' => {
                if self.advance_if('>') {
                    Token::Arrow
                } else if self.advance_if('=') {
                    Token::MinusAssign
                } else {
                    Token::Minus
                }
            }
            '=' => {
                if self.advance_if('>') {
                    Token::FatArrow
                } else if self.advance_if('=') {
                    Token::Eq
                } else {
                    Token::Assign
                }
            }
            '.' => {
                if self.peek() == Some('.') && self.peek_next() == Some('=') {
                    self.advance(); // second `.`
                    self.advance(); // `=`
                    Token::DotDotEq
                } else if self.advance_if('.') {
                    Token::DotDot
                } else {
                    Token::Dot
                }
            }
            ':' => {
                if self.advance_if(':') {
                    Token::ColonColon
                } else {
                    Token::Colon
                }
            }
            '!' => {
                if self.advance_if('=') {
                    Token::NotEq
                } else {
                    Token::Not
                }
            }
            '<' => {
                if self.advance_if('<') {
                    Token::Shl
                } else if self.advance_if('=') {
                    Token::LtEq
                } else {
                    Token::Lt
                }
            }
            '>' => {
                if self.advance_if('>') {
                    Token::Shr
                } else if self.advance_if('=') {
                    Token::GtEq
                } else {
                    Token::Gt
                }
            }
            '&' => {
                if self.advance_if('&') {
                    Token::And
                } else {
                    Token::BitAnd
                }
            }
            '|' => {
                if self.advance_if('|') {
                    Token::Or
                } else {
                    // Both `Pipe` and `BitOr` are the same character; context
                    // determines meaning. Emit `Pipe` as the canonical form.
                    Token::Pipe
                }
            }
            '+' => {
                if self.advance_if('=') {
                    Token::PlusAssign
                } else {
                    Token::Plus
                }
            }
            '*' => {
                if self.advance_if('*') {
                    Token::StarStar
                } else if self.advance_if('=') {
                    Token::StarAssign
                } else {
                    Token::Star
                }
            }
            '/' => {
                if self.advance_if('=') {
                    Token::SlashAssign
                } else {
                    Token::Slash
                }
            }
            '%' => {
                if self.advance_if('=') {
                    Token::PercentAssign
                } else {
                    Token::Percent
                }
            }
            '^' => Token::BitXor,
            '~' => Token::BitNot,
            '?' => {
                if self.advance_if('?') {
                    Token::NullCoalesce
                } else {
                    Token::QuestionMark
                }
            }
            '_' => Token::Underscore,
            ',' => Token::Comma,
            ';' => Token::Semicolon,
            '(' => Token::LParen,
            ')' => Token::RParen,
            '{' => Token::LBrace,
            '}' => Token::RBrace,
            '[' => Token::LBracket,
            ']' => Token::RBracket,
            '#' => Token::Hash_,
            '$' => Token::Dollar,
            '@' => Token::At,
            unknown => {
                return Err(self.lex_error_at(&mark, format!("unexpected character '{unknown}'")));
            }
        };

        let span = self.span_from_mark(&mark);
        Ok((token, span))
    }
}
