//! Number-scanning methods for the Lem lexer.
//!
//! Handles decimal integers, typed integer suffixes (e.g. `42u128`),
//! hex literals (`0x...`), binary literals (`0b...`), and float literals.

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

use super::{Mark, Scanner};

impl<'src> Scanner<'src> {
    /// Scan a numeric literal (decimal, hex, binary, float, typed).
    ///
    /// Unit suffixes (`.ether`, `.gwei`, etc.) are handled by the `tokenize`
    /// function which calls `try_scan_unit_suffix` after an integer token.
    pub(super) fn scan_number(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        // Check for hex or binary prefix
        if self.peek() == Some('0') {
            match self.peek_next() {
                Some('x') | Some('X') => {
                    return self.scan_hex(mark);
                }
                Some('b') | Some('B') => {
                    return self.scan_binary(mark);
                }
                _ => {}
            }
        }
        self.scan_decimal(mark)
    }

    /// Scan a `0x...` hex literal.
    fn scan_hex(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        self.advance(); // `0`
        self.advance(); // `x`
        let digits_start = self.pos;
        let mut has_digits = false;
        while let Some(c) = self.peek() {
            if c.is_ascii_hexdigit() || c == '_' {
                has_digits = true;
                self.advance();
            } else {
                break;
            }
        }
        if !has_digits {
            return Err(self.lex_error_at(&mark, "invalid hex literal: no digits after '0x'"));
        }
        // Remove underscores from the raw digits
        let raw = self.src[digits_start..self.pos]
            .chars()
            .filter(|&c| c != '_')
            .collect::<String>();
        // Validate all chars are hex digits (underscores already removed)
        if raw.chars().any(|c| !c.is_ascii_hexdigit()) {
            return Err(self.lex_error_at(&mark, "invalid hex literal: non-hex digit"));
        }
        let span = self.span_from_mark(&mark);
        Ok((Token::HexLiteral(raw), span))
    }

    /// Scan a `0b...` binary literal.
    fn scan_binary(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        self.advance(); // `0`
        self.advance(); // `b`
        let digits_start = self.pos;
        let mut has_digits = false;
        while let Some(c) = self.peek() {
            if c == '0' || c == '1' || c == '_' {
                has_digits = true;
                self.advance();
            } else if c.is_ascii_digit() {
                // Non-binary digit in binary literal
                return Err(self.lex_error_at(
                    &mark,
                    format!("invalid binary literal: digit '{c}' is not 0 or 1"),
                ));
            } else {
                break;
            }
        }
        if !has_digits {
            return Err(self.lex_error_at(&mark, "invalid binary literal: no digits after '0b'"));
        }
        let raw = self.src[digits_start..self.pos]
            .chars()
            .filter(|&c| c != '_')
            .collect::<String>();
        let span = self.span_from_mark(&mark);
        Ok((Token::BinLiteral(raw), span))
    }

    /// Scan a decimal integer or float literal.
    ///
    /// Handles:
    /// - `42` → `IntLiteral(42)`
    /// - `42u128` → `IntLiteralTyped { value: 42, suffix: "u128" }`
    /// - `3.14` → `FloatLiteral("3.14")`
    /// - `1.ether` → `IntLiteral(1)` (unit suffix handled by caller)
    fn scan_decimal(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        // Consume integer part
        let int_start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || c == '_' {
                self.advance();
            } else {
                break;
            }
        }
        let int_raw = self.src[int_start..self.pos]
            .chars()
            .filter(|&c| c != '_')
            .collect::<String>();

        // Check for `.` followed by digit (float) or alpha (unit suffix)
        if self.peek() == Some('.') {
            let next = self.peek_next();
            if let Some(nc) = next {
                if nc.is_ascii_digit() {
                    // Float literal: consume `.` and fractional part
                    self.advance(); // `.`
                    while let Some(c) = self.peek() {
                        if c.is_ascii_digit() || c == '_' {
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let raw = self.src[mark.offset..self.pos].to_string();
                    let span = self.span_from_mark(&mark);
                    return Ok((Token::FloatLiteral(raw), span));
                }
                // `.alpha` — unit suffix; return the integer, caller handles unit
                if nc.is_alphabetic() {
                    let value = parse_u128(&int_raw, &mark)?;
                    let span = self.span_from_mark(&mark);
                    return Ok((Token::IntLiteral(value), span));
                }
            }
        }

        // Check for typed suffix directly after digits (e.g. `42u128`)
        if let Some(c) = self.peek() {
            if c.is_alphabetic() {
                let suffix_start = self.pos;
                while let Some(sc) = self.peek() {
                    if sc.is_alphanumeric() {
                        self.advance();
                    } else {
                        break;
                    }
                }
                let suffix = self.src[suffix_start..self.pos].to_string();
                // Validate suffix is a known integer type
                if is_int_suffix(&suffix) {
                    let value = parse_u128(&int_raw, &mark)?;
                    let span = self.span_from_mark(&mark);
                    return Ok((Token::IntLiteralTyped { value, suffix }, span));
                }
                // Not a known suffix — number immediately followed by unknown alpha
                return Err(self.lex_error_at(&mark, format!("invalid integer suffix '{suffix}'")));
            }
        }

        let value = parse_u128(&int_raw, &mark)?;
        let span = self.span_from_mark(&mark);
        Ok((Token::IntLiteral(value), span))
    }
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Returns `true` if `suffix` is a valid integer type suffix.
fn is_int_suffix(suffix: &str) -> bool {
    matches!(
        suffix,
        "u8" | "u16"
            | "u32"
            | "u64"
            | "u128"
            | "u256"
            | "i8"
            | "i16"
            | "i32"
            | "i64"
            | "i128"
            | "i256"
    )
}

/// Parse a decimal digit string (underscores already removed) into `u128`.
fn parse_u128(digits: &str, mark: &Mark) -> Result<u128, LangError> {
    digits.parse::<u128>().map_err(|_| LangError::Lex {
        message: format!("integer literal '{digits}' overflows u128"),
        span: Span {
            line: mark.line,
            col: mark.col,
            offset: mark.offset,
            len: digits.len(),
        },
    })
}
