//! Statement AST nodes for the Lem language.
//!
//! Covers all statement forms: let bindings, control flow, loops,
//! emit, assert, revert, try/catch, unchecked, and expression statements.

use crate::lexer::token::Span;

use super::decl::Const;
use super::expr::{AssignOp, Expr, MatchArm, Pattern};

// ─── For iterator ─────────────────────────────────────────────────────────────

/// The iterator form in a `for` statement.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum ForIter {
    /// `for x of collection` — iterate over a collection.
    Of(Expr),
    /// `for x in start..end` or `for x in start..=end` — range iteration.
    ///
    /// Fields: `(start_expr, span_of_range_op, end_expr, inclusive)`
    In(Expr, Span, Expr, bool),
}

// ─── Statements ───────────────────────────────────────────────────────────────

/// A statement in the Lem language.
///
/// All variants carry a `Span` for source location tracking.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// `let mut? pattern (: type)? = expr`
    Let {
        mutable: bool,
        pattern: Pattern,
        ty: Option<super::expr::Type>,
        expr: Expr,
        span: Span,
    },

    /// `const NAME: T = expr` (inside a function body)
    Const(Const),

    /// An assignment statement: `target op= value`
    ///
    /// Note: assignment is parsed as `Expr::Assign_` and re-wrapped here
    /// when it appears as a statement.
    Assign {
        target: Expr,
        op: AssignOp,
        value: Expr,
        span: Span,
    },

    /// `if (cond) { then } else { else_ }`
    If {
        cond: Expr,
        then: Vec<Stmt>,
        else_: Option<Vec<Stmt>>,
        span: Span,
    },

    /// `match expr { arm => body, ... }`
    Match {
        expr: Expr,
        arms: Vec<MatchArm>,
        span: Span,
    },

    /// `for pattern of expr { body }` or `for ident in range { body }`
    For {
        pattern: Pattern,
        iter: ForIter,
        body: Vec<Stmt>,
        span: Span,
    },

    /// `while (cond) { body }`
    While {
        cond: Expr,
        body: Vec<Stmt>,
        span: Span,
    },

    /// `loop { body }`
    Loop { body: Vec<Stmt>, span: Span },

    /// `return expr?`
    Return(Option<Expr>, Span),

    /// `break`
    Break(Span),

    /// `continue`
    Continue(Span),

    /// `emit EventName { field: value, ... }`
    Emit {
        event: String,
        fields: Vec<(String, Expr)>,
        span: Span,
    },

    /// `assert(cond, "message"?)`
    Assert {
        cond: Expr,
        msg: Option<Expr>,
        span: Span,
    },

    /// `revert("message"?)`
    Revert { msg: Option<Expr>, span: Span },

    /// `try { body } catch (e) { catch_body }`
    Try {
        body: Vec<Stmt>,
        catch_var: String,
        catch_body: Vec<Stmt>,
        span: Span,
    },

    /// `unchecked { body }` — arithmetic without overflow checks.
    Unchecked(Vec<Stmt>, Span),

    /// `_` — modifier placeholder.
    ///
    /// Valid only inside modifier bodies. The parser records the position;
    /// the semantic checker (Step 3) validates the context.
    Placeholder(Span),

    /// A bare expression statement: `expr;`
    Expr(Expr, Span),
}
