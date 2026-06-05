//! String-scanning methods for the Lem lexer.
//!
//! Handles `"..."` string literals, `b"..."` bytes literals,
//! `` `...${expr}...` `` template strings, `'c'` char literals,
//! and the `\uXXXX` / `\xHH` escape sub-scanners.

use crate::error::LangError;
use crate::lexer::token::{Span, TemplateSegment, Token};

use super::{Mark, Scanner};

impl<'src> Scanner<'src> {
    /// Scan a `"..."` string literal with escape sequences.
    pub(super) fn scan_string(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        self.advance(); // opening `"`
        let mut value = String::new();
        loop {
            let Some(ch) = self.peek() else {
                // End of input inside string — unterminated
                return Err(self.lex_error_at(&mark, "unterminated string literal"));
            };
            match ch {
                '"' => {
                    self.advance();
                    break;
                }
                '\\' => {
                    self.advance(); // consume `\`
                    match self.advance() {
                        Some('n') => value.push('\n'),
                        Some('t') => value.push('\t'),
                        Some('r') => value.push('\r'),
                        Some('\\') => value.push('\\'),
                        Some('"') => value.push('"'),
                        Some('0') => value.push('\0'),
                        Some('u') => {
                            // \uXXXX unicode escape
                            let ch = self.scan_unicode_escape(&mark)?;
                            value.push(ch);
                        }
                        Some(c) => {
                            return Err(self
                                .lex_error_at(&mark, format!("unknown escape sequence '\\{c}'")));
                        }
                        None => {
                            return Err(self.lex_error_at(&mark, "unterminated string literal"));
                        }
                    }
                }
                c => {
                    value.push(c);
                    self.advance();
                }
            }
        }
        let span = self.span_from_mark(&mark);
        Ok((Token::StringLiteral(value), span))
    }

    /// Scan `\uXXXX` unicode escape (4 hex digits).
    fn scan_unicode_escape(&mut self, mark: &Mark) -> Result<char, LangError> {
        let mut hex = String::with_capacity(4);
        for _ in 0..4 {
            match self.advance() {
                Some(c) if c.is_ascii_hexdigit() => hex.push(c),
                Some(c) => {
                    return Err(self.lex_error_at(
                        mark,
                        format!("invalid unicode escape: non-hex char '{c}'"),
                    ));
                }
                None => {
                    return Err(self.lex_error_at(mark, "unterminated unicode escape"));
                }
            }
        }
        let code_point = u32::from_str_radix(&hex, 16)
            .map_err(|_| self.lex_error_at(mark, format!("invalid unicode escape: \\u{hex}")))?;
        char::from_u32(code_point).ok_or_else(|| {
            self.lex_error_at(
                mark,
                format!("invalid unicode code point: U+{code_point:04X}"),
            )
        })
    }

    /// Scan a `b"..."` bytes literal.
    pub(super) fn scan_bytes_literal(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        self.advance(); // `b`
        self.advance(); // `"`
        let mut bytes = Vec::new();
        loop {
            let Some(ch) = self.peek() else {
                // End of input inside bytes literal — unterminated
                return Err(self.lex_error_at(&mark, "unterminated bytes literal"));
            };
            match ch {
                '"' => {
                    self.advance();
                    break;
                }
                '\\' => {
                    self.advance();
                    match self.advance() {
                        Some('n') => bytes.push(b'\n'),
                        Some('t') => bytes.push(b'\t'),
                        Some('r') => bytes.push(b'\r'),
                        Some('\\') => bytes.push(b'\\'),
                        Some('"') => bytes.push(b'"'),
                        Some('0') => bytes.push(0),
                        Some('x') => {
                            // \xHH hex byte escape
                            let b = self.scan_hex_byte_escape(&mark)?;
                            bytes.push(b);
                        }
                        Some(c) => {
                            return Err(self.lex_error_at(
                                &mark,
                                format!("unknown escape sequence '\\{c}' in bytes literal"),
                            ));
                        }
                        None => {
                            return Err(self.lex_error_at(&mark, "unterminated bytes literal"));
                        }
                    }
                }
                c if c.is_ascii() => {
                    bytes.push(c as u8);
                    self.advance();
                }
                c => {
                    return Err(self.lex_error_at(
                        &mark,
                        format!("non-ASCII character '{c}' in bytes literal"),
                    ));
                }
            }
        }
        let span = self.span_from_mark(&mark);
        Ok((Token::BytesLiteral(bytes), span))
    }

    /// Scan `\xHH` hex byte escape (2 hex digits).
    fn scan_hex_byte_escape(&mut self, mark: &Mark) -> Result<u8, LangError> {
        let mut hex = String::with_capacity(2);
        for _ in 0..2 {
            match self.advance() {
                Some(c) if c.is_ascii_hexdigit() => hex.push(c),
                Some(c) => {
                    return Err(self.lex_error_at(
                        mark,
                        format!("invalid hex byte escape: non-hex char '{c}'"),
                    ));
                }
                None => {
                    return Err(self.lex_error_at(mark, "unterminated hex byte escape"));
                }
            }
        }
        u8::from_str_radix(&hex, 16)
            .map_err(|_| self.lex_error_at(mark, format!("invalid hex byte escape: \\x{hex}")))
    }

    /// Scan a template string `` `...${expr}...` ``.
    pub(super) fn scan_template(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        self.advance(); // opening `` ` ``
        let mut segments = Vec::new();
        let mut current_literal = String::new();

        loop {
            let Some(ch) = self.peek() else {
                // End of input inside template string — unterminated
                return Err(self.lex_error_at(&mark, "unterminated template string"));
            };
            match ch {
                '`' => {
                    self.advance();
                    if !current_literal.is_empty() {
                        segments.push(TemplateSegment::Literal(current_literal));
                    }
                    break;
                }
                '$' if self.peek_next() == Some('{') => {
                    // Start of interpolation
                    if !current_literal.is_empty() {
                        segments.push(TemplateSegment::Literal(std::mem::take(
                            &mut current_literal,
                        )));
                    }
                    self.advance(); // `$`
                    self.advance(); // `{`
                    let expr = self.scan_template_interpolation(&mark)?;
                    segments.push(TemplateSegment::Interpolation(expr));
                }
                '\\' => {
                    self.advance();
                    match self.advance() {
                        Some('`') => current_literal.push('`'),
                        Some('$') => current_literal.push('$'),
                        Some('n') => current_literal.push('\n'),
                        Some('t') => current_literal.push('\t'),
                        Some('\\') => current_literal.push('\\'),
                        Some(c) => current_literal.push(c),
                        None => {
                            return Err(self.lex_error_at(&mark, "unterminated template string"));
                        }
                    }
                }
                c => {
                    current_literal.push(c);
                    self.advance();
                }
            }
        }
        let span = self.span_from_mark(&mark);
        Ok((Token::TemplateLiteral(segments), span))
    }

    /// Scan the expression inside `${...}` — stops at the matching `}`.
    ///
    /// Tracks brace depth to handle nested braces in expressions.
    fn scan_template_interpolation(&mut self, mark: &Mark) -> Result<String, LangError> {
        let mut expr = String::new();
        let mut depth: usize = 1;
        loop {
            let Some(ch) = self.peek() else {
                // End of input inside template interpolation — unterminated
                return Err(self.lex_error_at(mark, "unterminated template interpolation"));
            };
            match ch {
                '{' => {
                    depth += 1;
                    expr.push('{');
                    self.advance();
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        self.advance(); // consume closing `}`
                        return Ok(expr);
                    }
                    expr.push('}');
                    self.advance();
                }
                c => {
                    expr.push(c);
                    self.advance();
                }
            }
        }
    }

    /// Scan a `'c'` or `'\n'` char literal.
    pub(super) fn scan_char(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        self.advance(); // opening `'`
        let ch = match self.advance() {
            None => {
                return Err(self.lex_error_at(&mark, "unterminated char literal"));
            }
            Some('\\') => match self.advance() {
                Some('n') => '\n',
                Some('t') => '\t',
                Some('r') => '\r',
                Some('\\') => '\\',
                Some('\'') => '\'',
                Some('0') => '\0',
                Some('u') => self.scan_unicode_escape(&mark)?,
                Some(c) => {
                    return Err(self.lex_error_at(
                        &mark,
                        format!("unknown escape sequence '\\{c}' in char literal"),
                    ));
                }
                None => {
                    return Err(self.lex_error_at(&mark, "unterminated char literal"));
                }
            },
            Some(c) => c,
        };
        // Expect closing `'`
        if !self.advance_if('\'') {
            return Err(self.lex_error_at(&mark, "unterminated char literal: missing closing `'`"));
        }
        let span = self.span_from_mark(&mark);
        Ok((Token::CharLiteral(ch), span))
    }
}
