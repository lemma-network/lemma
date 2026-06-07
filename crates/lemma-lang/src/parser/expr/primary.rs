//! Primary expression parser — leaf forms of the expression grammar.
//! Handles literals, identifiers, paren/tuple, arrays, struct literals,
//! `new` expressions, lambdas, `match`, `if`, and template literals.

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

use super::super::ast::{Expr, Literal, UnitKind};
use super::super::Parser;
use super::span::MergeSpan;

impl Parser {
    // ── Primary dispatch ──────────────────────────────────────────────────────

    /// Parse a primary expression (leaf of the precedence ladder).
    pub(crate) fn parse_primary(&mut self) -> Result<Expr, LangError> {
        self.skip_newlines();
        // Delegate literal tokens to a focused helper to keep this function
        // under 300 lines (AGENTS §3.1 file-size rule).
        if let Some(result) = self.parse_literal_primary() {
            return result;
        }
        match self.peek().clone() {
            // ── Template literal ───────────────────────────────────────────
            Token::TemplateLiteral(segs) => self.parse_template_literal(segs),

            // ── new expression ─────────────────────────────────────────────
            Token::New => self.parse_new_expr(),

            // ── Parenthesized / tuple / lambda ─────────────────────────────
            Token::LParen => self.parse_paren_or_tuple(),

            // ── Array literal ──────────────────────────────────────────────
            Token::LBracket => self.parse_array_literal(),

            // ── Identifier: ident, struct literal, or lambda ───────────────
            Token::Identifier(name) => self.parse_ident_or_struct_or_lambda(name),

            // ── `from` soft/contextual keyword used as an expression ───────
            // `from` is Token::From but may appear as an rvalue in function
            // bodies wherever it was bound as a parameter (e.g. `fn onTransfer
            // (from: Address, …) { emit T { sender: from } }`).  In expression
            // position it behaves as a plain identifier — it cannot be a struct
            // literal or lambda, but member access and call operators on it are
            // handled by the postfix layer that wraps parse_primary.
            // See: DB-A24 (decisions-log), §24 hook function spec.
            Token::From => {
                let span = self.peek_span();
                self.advance();
                Ok(Expr::Ident("from".into(), span))
            }

            // ── self keyword ──────────────────────────────────────────────
            Token::SelfKw => {
                let span = self.peek_span();
                self.advance();
                Ok(Expr::Ident("self".into(), span))
            }

            // ── match expression ───────────────────────────────────────────
            Token::Match => self.parse_match_expr(),

            // ── if expression ──────────────────────────────────────────────
            Token::If => self.parse_if_expr(),

            tok => Err(self.error_expected(
                vec!["expression".into()],
                format!("unexpected token in expression: {tok:?}"),
            )),
        }
    }

    /// Dispatch literal tokens to their `Expr::Literal` forms.
    ///
    /// Returns `Some(result)` if the current token is a literal (consuming it),
    /// or `None` if the current token is not a literal (leaving the cursor unchanged).
    /// Extracted from `parse_primary` to keep that function under 300 lines.
    fn parse_literal_primary(&mut self) -> Option<Result<Expr, LangError>> {
        match self.peek().clone() {
            Token::IntLiteral(n) => {
                let span = self.peek_span();
                self.advance();
                // Check for unit suffix: 1.ether, 1.gwei, etc.
                Some(self.try_parse_unit_suffix(Expr::Literal(Literal::Int(n), span), span))
            }
            Token::IntLiteralTyped { value, suffix } => {
                let span = self.peek_span();
                self.advance();
                let base = Expr::Literal(Literal::IntTyped { value, suffix }, span);
                Some(self.try_parse_unit_suffix(base, span))
            }
            Token::HexLiteral(s) => {
                let span = self.peek_span();
                self.advance();
                Some(Ok(Expr::Literal(Literal::Hex(s), span)))
            }
            Token::BinLiteral(s) => {
                let span = self.peek_span();
                self.advance();
                Some(Ok(Expr::Literal(Literal::Bin(s), span)))
            }
            Token::FloatLiteral(s) => {
                let span = self.peek_span();
                self.advance();
                Some(Ok(Expr::Literal(Literal::Float(s), span)))
            }
            Token::StringLiteral(s) => {
                let span = self.peek_span();
                self.advance();
                Some(Ok(Expr::Literal(Literal::Str(s), span)))
            }
            Token::BytesLiteral(b) => {
                let span = self.peek_span();
                self.advance();
                Some(Ok(Expr::Literal(Literal::Bytes(b), span)))
            }
            Token::CharLiteral(c) => {
                let span = self.peek_span();
                self.advance();
                Some(Ok(Expr::Literal(Literal::Char(c), span)))
            }
            Token::BoolLiteral(b) => {
                let span = self.peek_span();
                self.advance();
                Some(Ok(Expr::Literal(Literal::Bool(b), span)))
            }
            Token::AddressLiteral(s) => {
                let span = self.peek_span();
                self.advance();
                Some(Ok(Expr::Literal(Literal::Address(s), span)))
            }
            // Unit suffix tokens appear after integer literals; standalone = error.
            Token::UnitEther
            | Token::UnitGwei
            | Token::UnitMinutes
            | Token::UnitHours
            | Token::UnitDays
            | Token::UnitTokens => Some(Err(self.error(format!(
                "unexpected unit suffix {:?} without preceding integer literal",
                self.peek()
            )))),
            // Not a literal token — caller handles it
            _ => None,
        }
    }

    /// After parsing an integer literal, check for a unit suffix token.
    ///
    /// The lexer emits unit suffixes as separate tokens: `1.ether` → `[IntLiteral(1), UnitEther]`.
    /// `Token::UnitTokens` requires a parenthesized precision arg — not a simple suffix.
    fn try_parse_unit_suffix(&mut self, base: Expr, base_span: Span) -> Result<Expr, LangError> {
        let kind = match self.peek() {
            Token::UnitEther => UnitKind::Ether,
            Token::UnitGwei => UnitKind::Gwei,
            Token::UnitMinutes => UnitKind::Minutes,
            Token::UnitHours => UnitKind::Hours,
            Token::UnitDays => UnitKind::Days,
            // UnitTokens requires `.tokens(N)` — not a simple suffix; leave for postfix
            _ => return Ok(base),
        };
        let end = self.peek_span();
        self.advance();
        let span = base_span.merge_with(end);
        Ok(Expr::Literal(Literal::Unit(Box::new(base), kind), span))
    }

    // ── Parenthesized / tuple / lambda ────────────────────────────────────────

    /// Parse `(expr)`, `(a, b)` tuple, or `(params) => body` lambda.
    pub(crate) fn parse_paren_or_tuple(&mut self) -> Result<Expr, LangError> {
        let start = self.expect(&Token::LParen, "\"(\"")?;

        // Empty tuple `()`
        if self.check(&Token::RParen) {
            self.advance();
            return Ok(Expr::Tuple(vec![], start));
        }

        let first = self.parse_expr()?;

        if self.advance_if(&Token::Comma) {
            // Tuple or multi-param lambda: (a, b, ...)
            let mut elems = vec![first];
            while !self.check(&Token::RParen) && !self.at_end() {
                elems.push(self.parse_expr()?);
                if !self.advance_if(&Token::Comma) {
                    break;
                }
            }
            self.expect(&Token::RParen, "\")\" after tuple")?;
            // Check for lambda: (x, y) =>
            if self.check(&Token::FatArrow) {
                return self.parse_lambda_from_exprs(elems, start);
            }
            let end = self.prev_span();
            Ok(Expr::Tuple(elems, start.merge_with(end)))
        } else {
            self.expect(&Token::RParen, "\")\" after expression")?;
            // Check for single-param lambda: (x) =>
            if self.check(&Token::FatArrow) {
                return self.parse_lambda_from_exprs(vec![first], start);
            }
            // Plain parenthesized expression — return inner directly
            Ok(first)
        }
    }

    // ── Array literal ─────────────────────────────────────────────────────────

    /// Parse `[a, b, c]` array literal.
    fn parse_array_literal(&mut self) -> Result<Expr, LangError> {
        let start = self.expect(&Token::LBracket, "\"[\"")?;
        let mut elems = Vec::new();
        while !self.check(&Token::RBracket) && !self.at_end() {
            elems.push(self.parse_expr()?);
            if !self.advance_if(&Token::Comma) {
                break;
            }
        }
        let end = self.expect(&Token::RBracket, "\"]\" after array literal")?;
        Ok(Expr::Array(elems, start.merge_with(end)))
    }

    // Identifier / struct literal / lambda / new expression parsers live in
    // constructors.rs (same `impl Parser` block — callable as self.parse_*()).
    // Split there to keep this file under the §3.1 300-line limit.
}
