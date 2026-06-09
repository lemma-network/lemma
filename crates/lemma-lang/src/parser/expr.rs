//! Expression parser for the Lem language.
//!
//! Implements the full §29 precedence ladder as one function per EBNF rule.
//! All methods are `pub(crate)` so stmt.rs and decl.rs can call `parse_expr`.
//!
//! ## Precedence (lowest → highest)
//!
//! ```text
//! assignment  (right-assoc)  =  +=  -=  *=  /=  %=
//! ternary     (right-assoc)  ?  :
//! nullish     (left-assoc)   ??
//! logic_or    (left-assoc)   ||
//! logic_and   (left-assoc)   &&
//! bit_or      (left-assoc)   |
//! bit_xor     (left-assoc)   ^
//! bit_and     (left-assoc)   &
//! equality    (left-assoc)   ==  !=
//! comparison  (left-assoc)   <  >  <=  >=
//! shift       (left-assoc)   <<  >>       [ops.rs]
//! addition    (left-assoc)   +  -         [ops.rs]
//! multiply    (left-assoc)   *  /  %      [ops.rs]
//! exponent    (right-assoc)  **           [ops.rs]
//! unary       (prefix)       !  -  ~  &   [ops.rs]
//! postfix     (suffix)       ()  []  .  ? [ops.rs]
//! primary     (leaf)         literals...  [primary.rs]
//! ```
//!
//! ## Submodules
//!
//! - `ops`     — shift, addition, multiply, exponent, unary, postfix, call helpers
//! - `primary` — leaf expression forms (literals, ident, struct, new, lambda, paren/tuple)
//! - `control` — match, patterns, if, template literals, lambda bodies

mod constructors;
mod control;
mod ops;
mod primary;
mod span;

pub(crate) use span::{expr_span, MergeSpan};

use crate::error::LangError;
use crate::lexer::token::{Span, Token};

use super::ast::{AssignOp, BinaryOp, Expr};
use super::Parser;

// ─── Public entry point ───────────────────────────────────────────────────────

impl Parser {
    /// Parse a single expression (entry point for stmt.rs and decl.rs).
    ///
    /// Dispatches to the top of the precedence ladder (`parse_assignment`).
    ///
    /// # Depth guard
    ///
    /// Increments the expression nesting depth counter on entry and decrements
    /// it on exit.  Returns a parse error if the depth exceeds
    /// [`super::MAX_EXPR_DEPTH`], preventing stack overflow on adversarial
    /// inputs like `((((…))))`.  See [`Parser::enter_expr`] for the rationale.
    pub(crate) fn parse_expr(&mut self) -> Result<Expr, LangError> {
        self.skip_newlines();
        // Depth guard: prevents stack overflow on deeply-nested expressions.
        // Every recursive call path that re-enters parse_expr (e.g.
        // parse_paren_or_tuple, parse_call_args, parse_index) goes through
        // this entry point, so a single counter here covers all cycles.
        self.enter_expr()?;
        let result = self.parse_assignment();
        self.leave_expr();
        result
    }

    // ── Precedence level: assignment (right-associative) ─────────────────────

    /// `assignment_expr → ternary (assign_op assignment_expr)?`
    fn parse_assignment(&mut self) -> Result<Expr, LangError> {
        let lhs = self.parse_ternary()?;
        let start = expr_span(&lhs);

        let op = match self.peek() {
            Token::Assign => AssignOp::Assign,
            Token::PlusAssign => AssignOp::Add,
            Token::MinusAssign => AssignOp::Sub,
            Token::StarAssign => AssignOp::Mul,
            Token::SlashAssign => AssignOp::Div,
            Token::PercentAssign => AssignOp::Rem,
            _ => return Ok(lhs),
        };
        self.advance();
        // Right-associative: recurse into same level
        let rhs = self.parse_assignment()?;
        let span = start.merge_with(expr_span(&rhs));
        Ok(Expr::Assign_(Box::new(lhs), op, Box::new(rhs), span))
    }

    // ── Precedence level: ternary (right-associative) ─────────────────────────

    /// `ternary → nullish ("?" expression ":" expression)?`
    fn parse_ternary(&mut self) -> Result<Expr, LangError> {
        let cond = self.parse_nullish()?;
        if !self.check(&Token::QuestionMark) {
            return Ok(cond);
        }
        self.advance(); // consume `?`
        let then = self.parse_expr()?; // full expr for then-branch
        self.expect(&Token::Colon, "\":\" in ternary expression")?;
        let else_ = self.parse_expr()?; // right-assoc: full expr
        let span = expr_span(&cond).merge_with(expr_span(&else_));
        Ok(Expr::Ternary {
            cond: Box::new(cond),
            then: Box::new(then),
            else_: Box::new(else_),
            span,
        })
    }

    // ── Precedence level: nullish coalescing (left-associative) ───────────────

    /// `nullish → logic_or ("??" logic_or)*`
    fn parse_nullish(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_logic_or()?;
        while self.check(&Token::NullCoalesce) {
            self.advance();
            let rhs = self.parse_logic_or()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Nullish(Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: logical OR (left-associative) ───────────────────────

    /// `logic_or → logic_and ("||" logic_and)*`
    fn parse_logic_or(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_logic_and()?;
        while self.check(&Token::Or) {
            self.advance();
            let rhs = self.parse_logic_and()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(BinaryOp::Or, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: logical AND (left-associative) ──────────────────────

    /// `logic_and → bit_or ("&&" bit_or)*`
    fn parse_logic_and(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_bit_or()?;
        while self.check(&Token::And) {
            self.advance();
            let rhs = self.parse_bit_or()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(BinaryOp::And, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: bitwise OR (left-associative) ───────────────────────

    /// `bit_or → bit_xor ("|" bit_xor)*`
    ///
    /// The lexer always emits `Token::Pipe` for `|`. In expression context
    /// (which is always the case when this function is called), `Pipe` is BitOr.
    fn parse_bit_or(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_bit_xor()?;
        while self.check(&Token::Pipe) {
            self.advance();
            let rhs = self.parse_bit_xor()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(BinaryOp::BitOr, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: bitwise XOR (left-associative) ──────────────────────

    /// `bit_xor → bit_and ("^" bit_and)*`
    fn parse_bit_xor(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_bit_and()?;
        while self.check(&Token::BitXor) {
            self.advance();
            let rhs = self.parse_bit_and()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(BinaryOp::BitXor, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: bitwise AND (left-associative) ──────────────────────

    /// `bit_and → equality ("&" equality)*`
    fn parse_bit_and(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_equality()?;
        while self.check(&Token::BitAnd) {
            self.advance();
            let rhs = self.parse_equality()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(BinaryOp::BitAnd, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: equality (left-associative) ─────────────────────────

    /// `equality → comparison (("==" | "!=") comparison)*`
    fn parse_equality(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_comparison()?;
        loop {
            let op = match self.peek() {
                Token::Eq => BinaryOp::Eq,
                Token::NotEq => BinaryOp::NotEq,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_comparison()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Precedence level: comparison (left-associative) ───────────────────────

    /// `comparison → shift (("<" | ">" | "<=" | ">=") shift)*`
    fn parse_comparison(&mut self) -> Result<Expr, LangError> {
        let mut lhs = self.parse_shift()?;
        loop {
            let op = match self.peek() {
                Token::Lt => BinaryOp::Lt,
                Token::Gt => BinaryOp::Gt,
                Token::LtEq => BinaryOp::LtEq,
                Token::GtEq => BinaryOp::GtEq,
                _ => break,
            };
            self.advance();
            let rhs = self.parse_shift()?;
            let span = expr_span(&lhs).merge_with(expr_span(&rhs));
            lhs = Expr::Binary(op, Box::new(lhs), Box::new(rhs), span);
        }
        Ok(lhs)
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    /// Expect and consume an identifier token, returning its name.
    pub(crate) fn expect_identifier(&mut self, ctx: &str) -> Result<String, LangError> {
        match self.peek().clone() {
            Token::Identifier(name) => {
                self.advance();
                Ok(name)
            }
            // `from` is a soft/contextual keyword in Lem: it serves as an
            // import keyword after `import { … }` but is also widely used as a
            // parameter name in hook functions (e.g. `fn onTransfer(from: Address, …)`,
            // as in §24 of the language spec).  Accepting it here keeps identifier
            // positions spec-compliant without making `from` a hard reserved word.
            Token::From => {
                self.advance();
                Ok("from".to_string())
            }
            tok => {
                Err(self.error_expected(vec![ctx.into()], format!("expected {ctx}, got {tok:?}")))
            }
        }
    }

    /// Return the span of the most recently consumed token.
    pub(crate) fn prev_span(&self) -> Span {
        let idx = self
            .pos
            .saturating_sub(1)
            .min(self.tokens.len().saturating_sub(1));
        self.tokens[idx].1
    }
}
// parse_block is implemented in stmt.rs (subtask 2c).

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
