//! Binary and unary operator parsing — lower half of the precedence ladder.
//!
//! Covers: shift, addition, multiplication, exponentiation, unary, postfix.
//! Split from expr.rs to keep files under 300 lines.

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{BinaryOp, CallArg, CallOpts, Expr, UnaryOp};
use super::super::Parser;
use super::span::{expr_span, MergeSpan};

// TODO(2d): remove allow when decl.rs wires these methods (2c landed).
#[allow(dead_code)]
impl Parser {
    // ── Precedence level: shift (left-associative) ────────────────────────────

    /// `shift → addition (("<<" | ">>") addition)*`
    ///
    /// CRITICAL: In expressions, `>>` is ALWAYS `Token::Shr` (shift-right).
    /// Do NOT call `expect_gt()` here — that is ONLY for the type parser (ty.rs).
    /// See Technical Debt note P3-parser-1 in living-notes.md.
    pub(super) fn parse_shift(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_addition()?;
        loop {
            let op = match self.peek() {
                Token::Shl => BinaryOp::Shl,
                Token::Shr => BinaryOp::Shr,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_addition()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: addition (left-associative) ─────────────────────────

    /// `addition → multiplication (("+" | "-") multiplication)*`
    pub(super) fn parse_addition(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_multiplication()?;
        loop {
            let op = match self.peek() {
                Token::Plus => BinaryOp::Add,
                Token::Minus => BinaryOp::Sub,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_multiplication()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: multiplication (left-associative) ───────────────────

    /// `multiplication → exponent (("*" | "/" | "%") exponent)*`
    pub(super) fn parse_multiplication(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_exponent()?;
        loop {
            let op = match self.peek() {
                Token::Star => BinaryOp::Mul,
                Token::Slash => BinaryOp::Div,
                Token::Percent => BinaryOp::Rem,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_exponent()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: exponentiation (right-associative) ──────────────────

    /// `exponent → unary ("**" unary)*`
    ///
    /// Right-associative: `2**3**2` = `2**(3**2)`.
    pub(super) fn parse_exponent(&mut self) -> Result<Expr, LangError> {
        let lhs = self.parse_unary()?;
        if !self.check(&Token::StarStar) {
            return Ok(lhs);
        }
        self.advance();
        // Right-associative: recurse into exponent (same level)
        let rhs = self.parse_exponent()?;
        let span = expr_span(&lhs).merge_with(expr_span(&rhs));
        Ok(Expr::Binary(
            BinaryOp::Pow,
            Box::new(lhs),
            Box::new(rhs),
            span,
        ))
    }

    // ── Precedence level: unary (prefix) ──────────────────────────────────────

    /// `unary → ("!" | "-" | "~" | "&") unary | postfix`
    pub(super) fn parse_unary(&mut self) -> Result<Expr, LangError> {
        let start = self.peek_span();
        let op = match self.peek() {
            Token::Not => UnaryOp::Not,
            Token::Minus => UnaryOp::Neg,
            Token::BitNot => UnaryOp::BitNot,
            Token::BitAnd => UnaryOp::Ref,
            _ => return self.parse_postfix(),
        };
        self.advance();
        let operand = self.parse_unary()?; // recurse for chained unary
        let span = start.merge_with(expr_span(&operand));
        Ok(Expr::Unary(op, Box::new(operand), span))
    }

    // ── Precedence level: postfix (suffix) ────────────────────────────────────

    /// `postfix → primary (call_suffix | index_suffix | member_suffix | "?")*`
    ///
    /// Newlines between the base expression and a postfix operator are insignificant
    /// (Go/JS rule): `obj\n.field` = `obj.field`, `foo\n(args)` = `foo(args)`.
    /// The statement parser (2c) handles newline-as-statement-terminator separately.
    pub(super) fn parse_postfix(&mut self) -> Result<Expr, LangError> {
        let mut expr = self.parse_primary()?;
        loop {
            // Skip newlines before checking for a postfix operator — inside expression
            // context, newlines are insignificant (see doc comment above).
            self.skip_newlines();
            match self.peek().clone() {
                // Call with call-opts: foo{value: 1.ether}(args)
                Token::LBrace if self.is_call_opts_block() => {
                    let opts = self.parse_call_opts()?;
                    let args = self.parse_call_args()?;
                    let span = expr_span(&expr).merge_with(self.prev_span());
                    expr = Expr::Call {
                        callee: Box::new(expr),
                        opts: Some(opts),
                        args,
                        span,
                    };
                }
                // Plain call: foo(args)
                Token::LParen => {
                    let args = self.parse_call_args()?;
                    let span = expr_span(&expr).merge_with(self.prev_span());
                    expr = Expr::Call {
                        callee: Box::new(expr),
                        opts: None,
                        args,
                        span,
                    };
                }
                // Index: arr[i]
                Token::LBracket => {
                    self.advance();
                    let idx = self.parse_expr()?;
                    self.expect(&Token::RBracket, "\"]\" after index expression")?;
                    let span = expr_span(&expr).merge_with(self.prev_span());
                    expr = Expr::Index(Box::new(expr), Box::new(idx), span);
                }
                // Member access: obj.field
                Token::Dot => {
                    self.advance();
                    let name = self.expect_identifier("field name")?;
                    let span = expr_span(&expr).merge_with(self.prev_span());
                    expr = Expr::Member(Box::new(expr), name, span);
                }
                // Try operator: expr?
                // Disambiguation: `?` is Try only when NOT followed by an expression
                // start (which would indicate ternary `cond ? then : else`).
                Token::QuestionMark if !self.is_expr_start_at(1) => {
                    let q_span = self.peek_span();
                    self.advance();
                    let span = expr_span(&expr).merge_with(q_span);
                    expr = Expr::Try_(Box::new(expr), span);
                }
                _ => break,
            }
        }
        Ok(expr)
    }

    // ── Call-opts helpers ─────────────────────────────────────────────────────

    /// Lookahead: is the `{` at the current position a call-opts block?
    ///
    /// A call-opts block has the form `{ value: ... }`, `{ gas: ... }`, or
    /// `{ salt: ... }`. We peek at the next two non-newline tokens to decide.
    /// Using `peek_nth_non_newline` ensures newlines between tokens don't
    /// confuse the lookahead (consistent with the expression-level newline policy).
    pub(crate) fn is_call_opts_block(&self) -> bool {
        match (self.peek_nth_non_newline(1), self.peek_nth_non_newline(2)) {
            (Token::Identifier(k), Token::Colon) => {
                matches!(k.as_str(), "value" | "gas" | "salt")
            }
            _ => false,
        }
    }

    /// Parse `{value: expr, gas: expr, salt: expr}` call options.
    pub(crate) fn parse_call_opts(&mut self) -> Result<CallOpts, LangError> {
        let start = self.expect(&Token::LBrace, "\"{\"")?;
        let mut value = None;
        let mut gas = None;
        let mut salt = None;
        while !self.check(&Token::RBrace) && !self.at_end() {
            let key = self.expect_identifier("call option key (value, gas, or salt)")?;
            self.expect(&Token::Colon, "\":\" after call option key")?;
            let val = self.parse_expr()?;
            match key.as_str() {
                "value" => value = Some(Box::new(val)),
                "gas" => gas = Some(Box::new(val)),
                "salt" => salt = Some(Box::new(val)),
                _ => {
                    return Err(self.error(format!(
                        "unknown call option '{key}': expected value, gas, or salt"
                    )))
                }
            }
            self.advance_if(&Token::Comma);
        }
        let end = self.expect(&Token::RBrace, "\"}\" after call options")?;
        Ok(CallOpts {
            value,
            gas,
            salt,
            span: start.merge_with(end),
        })
    }

    /// Parse `(arg1, arg2, name: arg3)` call arguments.
    pub(crate) fn parse_call_args(&mut self) -> Result<Vec<CallArg>, LangError> {
        self.expect(&Token::LParen, "\"(\"")?;
        let mut args = Vec::new();
        while !self.check(&Token::RParen) && !self.at_end() {
            let is_named =
                matches!(self.peek(), Token::Identifier(_)) && self.peek_nth(1) == &Token::Colon;
            if is_named {
                let name = self.expect_identifier("argument name")?;
                self.expect(&Token::Colon, "\":\" after named argument")?;
                let val = self.parse_expr()?;
                args.push(CallArg::Named(name, val));
            } else {
                args.push(CallArg::Positional(self.parse_expr()?));
            }
            if !self.advance_if(&Token::Comma) {
                break;
            }
        }
        self.expect(&Token::RParen, "\")\" after arguments")?;
        Ok(args)
    }

    // ── Disambiguation helper ─────────────────────────────────────────────────

    /// Return `true` if the Nth non-newline token from the current position
    /// could start an expression.
    ///
    /// Used to disambiguate `?` as Try (postfix) vs ternary (infix).
    /// Uses `peek_nth_non_newline` so that `expr?\n b : c` correctly identifies
    /// `b` as an expression start (ternary), not a new statement.
    pub(super) fn is_expr_start_at(&self, n: usize) -> bool {
        matches!(
            self.peek_nth_non_newline(n),
            Token::IntLiteral(_)
                | Token::IntLiteralTyped { .. }
                | Token::HexLiteral(_)
                | Token::BinLiteral(_)
                | Token::FloatLiteral(_)
                | Token::StringLiteral(_)
                | Token::BytesLiteral(_)
                | Token::CharLiteral(_)
                | Token::BoolLiteral(_)
                | Token::AddressLiteral(_)
                | Token::TemplateLiteral(_)
                | Token::Identifier(_)
                | Token::SelfKw
                | Token::LParen
                | Token::LBracket
                | Token::New
                | Token::Match
                | Token::If
                | Token::Not
                | Token::Minus
                | Token::BitNot
                | Token::BitAnd
        )
    }
}
