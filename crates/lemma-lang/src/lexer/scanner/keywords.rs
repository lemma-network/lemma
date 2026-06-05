//! Keyword, annotation, and identifier scanning for the Lem lexer.
//!
//! Handles `@name` annotations, identifiers, and keyword mapping.
//! Also provides address-literal detection (`lem1`, `tlem1`, `dlem1`).

use bech32::primitives::decode::CheckedHrpstring;
use bech32::Bech32m;

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

use super::{Mark, Scanner};

impl<'src> Scanner<'src> {
    /// Check if the current position starts an address literal.
    ///
    /// Accepted prefixes: `lem1`, `tlem1`, `dlem1`.
    pub(super) fn starts_address_literal(&self) -> bool {
        let rest = &self.src[self.pos..];
        rest.starts_with("lem1") || rest.starts_with("tlem1") || rest.starts_with("dlem1")
    }

    /// Scan a Bech32m address literal and validate it.
    pub(super) fn scan_address_literal(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        // Consume all valid bech32 characters (alphanumeric, no uppercase in data)
        // Bech32 charset: 0-9, a-z (lowercase), plus the separator `1`
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' {
                self.advance();
            } else {
                break;
            }
        }
        let raw = &self.src[mark.offset..self.pos];
        // Validate using bech32 crate
        match CheckedHrpstring::new::<Bech32m>(raw) {
            Ok(parsed) => {
                // Bind hrp to a String to avoid temporary-value borrow issues
                let hrp = parsed.hrp().as_str().to_string();
                if matches!(hrp.as_str(), "lem" | "tlem" | "dlem") {
                    let span = self.span_from_mark(&mark);
                    Ok((Token::AddressLiteral(raw.to_string()), span))
                } else {
                    Err(self.lex_error_at(
                        &mark,
                        format!("invalid address literal: unexpected HRP '{hrp}'"),
                    ))
                }
            }
            Err(e) => {
                Err(self.lex_error_at(&mark, format!("invalid address literal '{raw}': {e}")))
            }
        }
    }

    /// Scan an `@name` annotation.
    pub(super) fn scan_annotation(&mut self, mark: Mark) -> Result<(Token, Span), LangError> {
        self.advance(); // consume `@`
        match self.peek() {
            Some(c) if is_ident_start(c) => {
                let name_start = self.pos;
                while let Some(nc) = self.peek() {
                    if is_ident_continue(nc) {
                        self.advance();
                    } else {
                        break;
                    }
                }
                let name = &self.src[name_start..self.pos];
                let token = map_annotation(name);
                let span = self.span_from_mark(&mark);
                Ok((token, span))
            }
            _ => {
                let span = Scanner::span_single(mark.line, mark.col, mark.offset);
                Err(self.lex_error(
                    "invalid annotation: '@' must be followed by an identifier",
                    span,
                ))
            }
        }
    }

    /// Scan an identifier or keyword.
    pub(super) fn scan_identifier(&mut self, mark: Mark) -> (Token, Span) {
        while let Some(c) = self.peek() {
            if is_ident_continue(c) {
                self.advance();
            } else {
                break;
            }
        }
        let word = &self.src[mark.offset..self.pos];
        let token = map_keyword(word);
        let span = self.span_from_mark(&mark);
        (token, span)
    }
}

// ─── Helper functions ─────────────────────────────────────────────────────────

/// Returns `true` if `c` can start an identifier.
pub(super) fn is_ident_start(c: char) -> bool {
    c.is_alphabetic() || c == '_'
}

/// Returns `true` if `c` can continue an identifier.
pub(super) fn is_ident_continue(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Map an annotation name to its specific token variant.
fn map_annotation(name: &str) -> Token {
    match name {
        "onlyOwner" => Token::OnlyOwner,
        "onlyRole" => Token::OnlyRole,
        "whenNotPaused" => Token::WhenNotPaused,
        "whenPaused" => Token::WhenPaused,
        "nonReentrant" => Token::NonReentrant,
        "cooldown" => Token::Cooldown,
        "payable" => Token::PayableAnn,
        "deadline" => Token::Deadline,
        "estimateGas" => Token::EstimateGas,
        "onTransfer" => Token::OnTransfer,
        "indexed" => Token::Indexed,
        "private" => Token::Private,
        "agentCallable" => Token::AgentCallable,
        other => Token::Annotation(other.to_string()),
    }
}

/// Map an identifier string to its keyword token, or `Identifier` if unknown.
fn map_keyword(word: &str) -> Token {
    match word {
        "contract" => Token::Contract,
        "token" => Token::Token_,
        "state" => Token::State,
        "init" => Token::Init,
        "pub" => Token::Pub,
        "view" => Token::View,
        "pure" => Token::Pure,
        "external" => Token::External,
        "payable" => Token::Payable,
        "fn" => Token::Fn,
        "let" => Token::Let,
        "const" => Token::Const,
        "if" => Token::If,
        "else" => Token::Else,
        "match" => Token::Match,
        "for" => Token::For,
        "while" => Token::While,
        "return" => Token::Return,
        "import" => Token::Import,
        "from" => Token::From,
        "as" => Token::As,
        "emit" => Token::Emit,
        "assert" => Token::Assert,
        "revert" => Token::Revert,
        "self" => Token::SelfKw,
        "trait" => Token::Trait,
        "implements" => Token::Implements,
        "uses" => Token::Uses,
        "modifier" => Token::Modifier,
        "unchecked" => Token::Unchecked,
        "type" => Token::Type,
        // Type keywords
        "u8" => Token::U8,
        "u16" => Token::U16,
        "u32" => Token::U32,
        "u64" => Token::U64,
        "u128" => Token::U128,
        "u256" => Token::U256,
        "i8" => Token::I8,
        "i16" => Token::I16,
        "i32" => Token::I32,
        "i64" => Token::I64,
        "i128" => Token::I128,
        "i256" => Token::I256,
        "bool" => Token::Bool,
        "string" => Token::StringTy,
        "char" => Token::CharTy,
        "Address" => Token::AddressTy,
        "Hash" => Token::HashTy,
        "bytes" => Token::Bytes,
        "Array" => Token::ArrayTy,
        "Map" => Token::MapTy,
        "FastMap" => Token::FastMapTy,
        "Set" => Token::SetTy,
        "Option" => Token::OptionTy,
        "Result" => Token::ResultTy,
        "decimal" => Token::Decimal,
        // Bool literals
        "true" => Token::BoolLiteral(true),
        "false" => Token::BoolLiteral(false),
        // Everything else
        other => Token::Identifier(other.to_string()),
    }
}
