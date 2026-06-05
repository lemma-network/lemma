//! Lem language lexer.
//!
//! The lexer converts Lem source code into a flat stream of `(Token, Span)`
//! pairs. All tokens are returned, including comments and newlines — the
//! parser strips what it doesn't need.
//!
//! ## Entry point
//!
//! ```ignore
//! use lemma_lang::tokenize;
//!
//! let tokens = tokenize("contract Foo {}")?;
//! assert_eq!(tokens.last().map(|(t, _)| t), Some(&Token::Eof));
//! ```
//!
//! ## Token stream guarantees
//!
//! - The last token is always `(Token::Eof, <span at end>)`.
//! - On lex error, returns `Err(LangError::Lex { .. })` — never panics.
//! - Unit suffixes (`.ether`, `.gwei`, etc.) are emitted as separate tokens
//!   immediately after the preceding integer literal.

mod scanner;
pub mod token;

use crate::error::LangError;
use scanner::Scanner;
use token::{Span, Token};

/// Tokenize a Lem source string into a flat token stream.
///
/// Returns all tokens including comments (`LineComment`, `BlockComment`,
/// `DocComment`) and `Newline` tokens. The last token is always `Token::Eof`.
///
/// # Errors
///
/// Returns `Err(LangError::Lex { .. })` on the first lexical error encountered.
/// The error carries the source location (`Span`) and a human-readable message.
///
/// # Examples
///
/// ```ignore
/// use lemma_lang::tokenize;
/// use lemma_lang::lexer::token::Token;
///
/// let tokens = tokenize("let x = 42").unwrap();
/// assert!(tokens.iter().any(|(t, _)| matches!(t, Token::Let)));
/// ```
pub fn tokenize(source: &str) -> Result<Vec<(Token, Span)>, LangError> {
    let mut scanner = Scanner::new(source);
    let mut tokens = Vec::new();

    loop {
        match scanner.next_token() {
            None => {
                // End of input — emit Eof with the scanner's actual position.
                let eof_span = Span::at(scanner.line(), scanner.col(), source.len());
                tokens.push((Token::Eof, eof_span));
                break;
            }
            Some(Err(e)) => return Err(e),
            Some(Ok((tok, span))) => {
                // After an integer literal, check for a unit suffix
                let is_int = matches!(tok, Token::IntLiteral(_) | Token::IntLiteralTyped { .. });
                tokens.push((tok, span));
                if is_int {
                    if let Some(unit) = scanner.try_scan_unit_suffix() {
                        tokens.push(unit);
                    }
                }
            }
        }
    }

    Ok(tokens)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
