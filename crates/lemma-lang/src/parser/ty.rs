//! Type parser for the Lem language.
//!
//! Implements `Parser::parse_type()` covering ALL type forms from §29 of the
//! language spec. One function per EBNF rule (DRY, 1:1 with grammar).
//!
//! ## Grammar (§29 type rule)
//!
//! ```text
//! type = primitive_type
//!      | "bytes" N          (N = 1..=32)
//!      | "Array" "<" type ">"
//!      | "[" type ";" INT "]"
//!      | "Map" "<" type "," type ">"
//!      | "FastMap" "<" type "," type ">"
//!      | "Set" "<" type ">"
//!      | "Option" "<" type ">"
//!      | "Result" "<" type "," type ">"
//!      | "decimal" "(" INT ")"
//!      | "(" type ("," type)* ")"   (tuple)
//!      | "fn" "(" type_list ")" "->" type
//!      | IDENT ("<" type_list ">")?
//! ```

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

use super::ast::Type;
use super::Parser;

// TODO(2d): remove allow when decl.rs wires these type-parser methods.
#[allow(dead_code)]
impl Parser {
    /// Parse a Lem type expression.
    ///
    /// Dispatches to the appropriate sub-parser based on the current token.
    /// Returns `Err` on any unrecognised token — never panics.
    pub(crate) fn parse_type(&mut self) -> Result<Type, LangError> {
        // Skip newlines before a type
        while self.advance_if(&Token::Newline) {}

        match self.peek().clone() {
            // ── Unsigned integers ──────────────────────────────────────────
            Token::U8 => {
                self.advance();
                Ok(Type::U8)
            }
            Token::U16 => {
                self.advance();
                Ok(Type::U16)
            }
            Token::U32 => {
                self.advance();
                Ok(Type::U32)
            }
            Token::U64 => {
                self.advance();
                Ok(Type::U64)
            }
            Token::U128 => {
                self.advance();
                Ok(Type::U128)
            }
            Token::U256 => {
                self.advance();
                Ok(Type::U256)
            }
            // ── Signed integers ────────────────────────────────────────────
            Token::I8 => {
                self.advance();
                Ok(Type::I8)
            }
            Token::I16 => {
                self.advance();
                Ok(Type::I16)
            }
            Token::I32 => {
                self.advance();
                Ok(Type::I32)
            }
            Token::I64 => {
                self.advance();
                Ok(Type::I64)
            }
            Token::I128 => {
                self.advance();
                Ok(Type::I128)
            }
            Token::I256 => {
                self.advance();
                Ok(Type::I256)
            }
            // ── Primitives ─────────────────────────────────────────────────
            Token::Bool => {
                self.advance();
                Ok(Type::Bool)
            }
            Token::StringTy => {
                self.advance();
                Ok(Type::StringTy)
            }
            Token::CharTy => {
                self.advance();
                Ok(Type::CharTy)
            }
            Token::AddressTy => {
                self.advance();
                Ok(Type::AddressTy)
            }
            Token::HashTy => {
                self.advance();
                Ok(Type::HashTy)
            }
            Token::Bytes => {
                self.advance();
                Ok(Type::Bytes)
            }
            // ── Compound types ─────────────────────────────────────────────
            Token::ArrayTy => self.parse_generic_wrapper_1(),
            Token::MapTy => self.parse_map_type(false),
            Token::FastMapTy => self.parse_map_type(true),
            Token::SetTy => self.parse_set_type(),
            Token::OptionTy => self.parse_option_type(),
            Token::ResultTy => self.parse_result_type(),
            Token::Decimal => self.parse_decimal_type(),
            Token::LParen => self.parse_tuple_or_fn_type(),
            Token::LBracket => self.parse_fixed_array_type(),
            Token::Fn => self.parse_fn_type(),
            // ── Named types (Ident or Ident<T1, T2>) ──────────────────────
            Token::Identifier(name) => {
                let name = name.clone();
                self.parse_named_type(name)
            }
            _ => Err(self.error_expected(
                vec!["type".to_string()],
                format!("expected a type, got {:?}", self.peek()),
            )),
        }
    }

    /// Parse `Array<T>` — a generic wrapper with one type argument.
    fn parse_generic_wrapper_1(&mut self) -> Result<Type, LangError> {
        self.advance(); // consume `Array`
        self.expect(&Token::Lt, "\"<\" after Array")?;
        let inner = self.parse_type()?;
        self.expect_gt("\">\"")?;
        Ok(Type::Array(Box::new(inner)))
    }

    /// Parse `Map<K, V>` or `FastMap<K, V>`.
    fn parse_map_type(&mut self, fast: bool) -> Result<Type, LangError> {
        self.advance(); // consume `Map` or `FastMap`
        let label = if fast { "FastMap" } else { "Map" };
        self.expect(&Token::Lt, &format!("\"<\" after {label}"))?;
        let key = self.parse_type()?;
        self.expect(&Token::Comma, &format!("\",\" in {label} type arguments"))?;
        let val = self.parse_type()?;
        self.expect_gt("\">\"")?;
        if fast {
            Ok(Type::FastMap(Box::new(key), Box::new(val)))
        } else {
            Ok(Type::Map(Box::new(key), Box::new(val)))
        }
    }

    /// Parse `Set<T>`.
    fn parse_set_type(&mut self) -> Result<Type, LangError> {
        self.advance(); // consume `Set`
        self.expect(&Token::Lt, "\"<\" after Set")?;
        let inner = self.parse_type()?;
        self.expect_gt("\">\"")?;
        Ok(Type::Set(Box::new(inner)))
    }

    /// Parse `Option<T>`.
    fn parse_option_type(&mut self) -> Result<Type, LangError> {
        self.advance(); // consume `Option`
        self.expect(&Token::Lt, "\"<\" after Option")?;
        let inner = self.parse_type()?;
        self.expect_gt("\">\"")?;
        Ok(Type::Option_(Box::new(inner)))
    }

    /// Parse `Result<T, E>`.
    fn parse_result_type(&mut self) -> Result<Type, LangError> {
        self.advance(); // consume `Result`
        self.expect(&Token::Lt, "\"<\" after Result")?;
        let ok_ty = self.parse_type()?;
        self.expect(&Token::Comma, "\",\" in Result type arguments")?;
        let err_ty = self.parse_type()?;
        self.expect_gt("\">\"")?;
        Ok(Type::Result_(Box::new(ok_ty), Box::new(err_ty)))
    }

    /// Parse `decimal(N)`.
    fn parse_decimal_type(&mut self) -> Result<Type, LangError> {
        self.advance(); // consume `decimal`
        self.expect(&Token::LParen, "\"(\" after decimal")?;
        let n = self.expect_int_literal("decimal precision N")?;
        // Precision must fit in u32
        let precision = u32::try_from(n)
            .map_err(|_| self.error(format!("decimal precision {n} exceeds u32::MAX")))?;
        self.expect(&Token::RParen, "\")\" after decimal precision")?;
        Ok(Type::Decimal(precision))
    }

    /// Parse `(T1, T2, ...)` tuple type or `fn(T1, T2) -> R` function type.
    ///
    /// Disambiguates by checking whether `fn` precedes the `(`.
    fn parse_tuple_or_fn_type(&mut self) -> Result<Type, LangError> {
        self.advance(); // consume `(`
                        // Empty tuple `()`
        if self.advance_if(&Token::RParen) {
            return Ok(Type::Tuple(vec![]));
        }
        let first = self.parse_type()?;
        if self.advance_if(&Token::RParen) {
            // Single-element tuple: `(T)` — treat as the type itself (not a tuple)
            // This matches most language conventions; a trailing comma would make it a tuple.
            return Ok(first);
        }
        // Multiple elements: `(T1, T2, ...)`
        let mut types = vec![first];
        while self.advance_if(&Token::Comma) {
            // Allow trailing comma
            if self.check(&Token::RParen) {
                break;
            }
            types.push(self.parse_type()?);
        }
        self.expect(&Token::RParen, "\")\" after tuple type")?;
        Ok(Type::Tuple(types))
    }

    /// Parse `[T; N]` — a fixed-size array type.
    fn parse_fixed_array_type(&mut self) -> Result<Type, LangError> {
        self.advance(); // consume `[`
        let elem_ty = self.parse_type()?;
        self.expect(&Token::Semicolon, "\";\" in fixed array type [T; N]")?;
        let n_raw = self.expect_int_literal("array size N")?;
        // Array size must fit in u64
        let n = u64::try_from(n_raw)
            .map_err(|_| self.error(format!("array size {n_raw} exceeds u64::MAX")))?;
        self.expect(&Token::RBracket, "\"]\" after fixed array type")?;
        Ok(Type::FixedArray(Box::new(elem_ty), n))
    }

    /// Parse `fn(T1, T2) -> R` — a function type.
    fn parse_fn_type(&mut self) -> Result<Type, LangError> {
        self.advance(); // consume `fn`
        self.expect(&Token::LParen, "\"(\" after fn in function type")?;
        let params = self.parse_type_list(&Token::RParen)?;
        self.expect(&Token::RParen, "\")\" after fn parameter types")?;
        self.expect(&Token::Arrow, "\"->\" in function type")?;
        let ret = self.parse_type()?;
        Ok(Type::Fn(params, Box::new(ret)))
    }

    /// Parse a named type: `Ident` or `Ident<T1, T2>`.
    ///
    /// Also handles `bytesN` (bytes1..bytes32) as a special case.
    fn parse_named_type(&mut self, name: String) -> Result<Type, LangError> {
        self.advance(); // consume the identifier

        // Special case: `bytesN` where N is 1..=32
        if let Some(n) = parse_bytes_n(&name) {
            return Ok(Type::BytesN(n));
        }

        // Check for generic arguments `<T1, T2>`
        if self.check(&Token::Lt) {
            let args = self.parse_generic_type_args()?;
            Ok(Type::Named(name, args))
        } else {
            Ok(Type::Named(name, vec![]))
        }
    }

    /// Parse `<T1, T2, ...>` generic type arguments.
    pub(crate) fn parse_generic_type_args(&mut self) -> Result<Vec<Type>, LangError> {
        self.expect(&Token::Lt, "\"<\" for generic type arguments")?;
        let args = self.parse_type_list_until_gt()?;
        self.expect_gt("\">\"")?;
        Ok(args)
    }

    /// Parse a comma-separated list of types, stopping before `>` or `>>`.
    ///
    /// Returns an empty vec if the next token is `>` or `>>`.
    fn parse_type_list_until_gt(&mut self) -> Result<Vec<Type>, LangError> {
        let mut types = Vec::new();
        while !self.check_gt() && !self.at_end() {
            types.push(self.parse_type()?);
            if !self.advance_if(&Token::Comma) {
                break;
            }
            // Allow trailing comma
            if self.check_gt() {
                break;
            }
        }
        Ok(types)
    }

    /// Parse a comma-separated list of types, stopping before `stop_token`.
    ///
    /// Returns an empty vec if the next token is `stop_token`.
    pub(crate) fn parse_type_list(&mut self, stop_token: &Token) -> Result<Vec<Type>, LangError> {
        let mut types = Vec::new();
        while !self.check(stop_token) && !self.at_end() {
            types.push(self.parse_type()?);
            if !self.advance_if(&Token::Comma) {
                break;
            }
            // Allow trailing comma
            if self.check(stop_token) {
                break;
            }
        }
        Ok(types)
    }

    /// Check if the current token is `>` or the first `>` of `>>`.
    ///
    /// Needed for nested generic disambiguation: `Map<K, Array<V>>` — the
    /// lexer emits `>>` as `Token::Shr`, but the type parser needs two `>`.
    fn check_gt(&self) -> bool {
        matches!(self.peek(), Token::Gt | Token::Shr)
    }

    /// Consume a `>` token, handling the `>>` (`Shr`) case by splitting it into two `>`s
    /// via in-place token buffer mutation.
    ///
    /// This handles the nested generic disambiguation problem:
    /// `Map<K, Array<V>>` — the `>>` is lexed as `Shr` but we need two `>`.
    ///
    /// When `>>` is seen, this method returns the span of the first `>` and
    /// replaces the `>>` token with `>` in the stream WITHOUT advancing.
    /// The outer parser's next `expect_gt` call will then consume that `>`.
    ///
    /// # INVARIANT
    /// This mutates `self.tokens[self.pos]` from `Shr` to `Gt` without advancing.
    /// The parser is strictly forward-moving — it NEVER rewinds `pos` across a position
    /// where this mutation may have occurred. Any future backtracking helper in expr.rs
    /// MUST NOT rewind past a position returned by `expect_gt`. See Technical Debt in
    /// living-notes.md: "P3-parser-1: `expect_gt` buffer mutation → `pending_gt` flag refactor".
    fn expect_gt(&mut self, ctx: &str) -> Result<Span, LangError> {
        match self.peek().clone() {
            Token::Gt => Ok(self.advance().1),
            Token::Shr => {
                // Split `>>` into two `>` tokens:
                // - Return the span of the first `>` (this call "consumes" it logically)
                // - Replace the `>>` with `>` in the stream so the outer parser
                //   can consume the second `>` on its next `expect_gt` call.
                // The span length is adjusted to 1 (the single > we're "consuming").
                let span = self.peek_span();
                // Replace Shr with Gt at the current position (do NOT advance)
                self.tokens[self.pos] = (Token::Gt, Span { len: 1, ..span });
                // Return the span as if we consumed the first `>`
                Ok(Span { len: 1, ..span })
            }
            _ => Err(self.error_expected(
                vec![ctx.to_string()],
                format!("expected {ctx}, got {:?}", self.peek()),
            )),
        }
    }

    /// Consume the current token as an integer literal and return its value.
    ///
    /// Returns `Err` if the current token is not an integer literal.
    pub(crate) fn expect_int_literal(&mut self, ctx: &str) -> Result<u128, LangError> {
        match self.peek().clone() {
            Token::IntLiteral(n) => {
                self.advance();
                Ok(n)
            }
            Token::IntLiteralTyped { value, .. } => {
                self.advance();
                Ok(value)
            }
            _ => Err(self.error_expected(
                vec!["integer literal".to_string()],
                format!("expected integer literal for {ctx}, got {:?}", self.peek()),
            )),
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Try to parse `bytesN` from an identifier name (e.g. `"bytes32"` → `Some(32)`).
///
/// Valid range: bytes1..=bytes32. Called from `parse_named_type`.
pub(crate) fn parse_bytes_n(name: &str) -> Option<u8> {
    let digits = name.strip_prefix("bytes")?;
    if digits.is_empty() {
        return None; // plain `bytes` is handled separately
    }
    let n: u8 = digits.parse().ok()?;
    if (1..=32).contains(&n) {
        Some(n)
    } else {
        None
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
