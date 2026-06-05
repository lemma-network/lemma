//! Expression AST nodes for the Lem language.
//!
//! Covers all expression forms: literals, operators, calls, lambdas,
//! template strings, match expressions, and assignment.

use crate::lexer::token::Span;

use super::decl::{Param, UnitKind};
use super::stmt::Stmt;

// ─── Type ─────────────────────────────────────────────────────────────────────

/// A Lem type expression.
///
/// Covers all type forms from §29 of the language spec.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum Type {
    // ── Unsigned integers ──────────────────────────────────────────────────
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    // ── Signed integers ────────────────────────────────────────────────────
    I8,
    I16,
    I32,
    I64,
    I128,
    I256,
    // ── Primitives ─────────────────────────────────────────────────────────
    /// `bool`
    Bool,
    /// `string`
    StringTy,
    /// `char`
    CharTy,
    /// `Address`
    AddressTy,
    /// `Hash`
    HashTy,
    /// `bytes` (dynamic byte array)
    Bytes,
    /// `bytesN` where N is 1..=32
    BytesN(u8),
    // ── Compound types ─────────────────────────────────────────────────────
    /// `Array<T>`
    Array(Box<Type>),
    /// `[T; N]` — fixed-size array
    FixedArray(Box<Type>, u64),
    /// `Map<K, V>`
    Map(Box<Type>, Box<Type>),
    /// `FastMap<K, V>`
    FastMap(Box<Type>, Box<Type>),
    /// `Set<T>`
    Set(Box<Type>),
    /// `Option<T>`
    Option_(Box<Type>),
    /// `Result<T, E>`
    Result_(Box<Type>, Box<Type>),
    /// `decimal(N)` — fixed-point decimal with N decimal places
    Decimal(u32),
    /// `(T1, T2, ...)` — tuple type
    Tuple(Vec<Type>),
    /// `fn(T1, T2) -> R` — function type
    Fn(Vec<Type>, Box<Type>),
    /// `Ident` or `Ident<T1, T2>` — named type with optional generic args
    Named(String, Vec<Type>),
}

// ─── Literals ─────────────────────────────────────────────────────────────────

/// A literal value in an expression.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum Literal {
    /// Plain integer: `42`
    Int(u128),
    /// Typed integer: `42u128`
    IntTyped { value: u128, suffix: String },
    /// Hex literal: `0xDEAD`
    Hex(String),
    /// Binary literal: `0b1010`
    Bin(String),
    /// Float literal (stored as string for determinism): `3.14`
    Float(String),
    /// String literal: `"hello"`
    Str(String),
    /// Byte string literal: `b"data"`
    Bytes(Vec<u8>),
    /// Character literal: `'a'`
    Char(char),
    /// Boolean literal: `true` / `false`
    Bool(bool),
    /// Address literal: `lem1q...`
    Address(String),
    /// Unit literal: `1.ether`, `6.months`
    Unit(Box<Expr>, UnitKind),
}

// ─── Operators ────────────────────────────────────────────────────────────────

/// Unary operators.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnaryOp {
    /// `!` — logical NOT
    Not,
    /// `-` — arithmetic negation
    Neg,
    /// `~` — bitwise NOT
    BitNot,
    /// `&` — reference (address-of)
    Ref,
}

/// Binary operators (in precedence order, lowest to highest).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryOp {
    // Arithmetic
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Pow,
    // Comparison
    Eq,
    NotEq,
    Lt,
    Gt,
    LtEq,
    GtEq,
    // Logical
    And,
    Or,
    // Bitwise
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
    // Null-coalescing
    Nullish,
}

/// Assignment operators.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssignOp {
    /// `=`
    Assign,
    /// `+=`
    Add,
    /// `-=`
    Sub,
    /// `*=`
    Mul,
    /// `/=`
    Div,
    /// `%=`
    Rem,
}

// ─── Call options ─────────────────────────────────────────────────────────────

/// Call options for cross-contract calls: `{value: x, gas: y, salt: z}`.
#[derive(Debug, Clone, PartialEq)]
pub struct CallOpts {
    /// `value: expr` — LEM value to send.
    pub value: Option<Box<Expr>>,
    /// `gas: expr` — gas limit override.
    pub gas: Option<Box<Expr>>,
    /// `salt: expr` — CREATE2 salt.
    pub salt: Option<Box<Expr>>,
    /// Source location.
    pub span: Span,
}

/// A single argument in a function call.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum CallArg {
    /// `expr` — positional argument.
    Positional(Expr),
    /// `name: expr` — named argument.
    Named(String, Expr),
}

// ─── Lambda ───────────────────────────────────────────────────────────────────

/// The body of a lambda expression.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum LambdaBody {
    /// `=> expr` — expression body.
    Expr(Box<Expr>),
    /// `=> { stmts }` — block body.
    Block(Vec<Stmt>),
}

// ─── Template strings ─────────────────────────────────────────────────────────

/// A segment of a template string expression.
///
/// Note: this is the AST-level representation. The lexer's `TemplateSegment`
/// stores raw source strings; the parser resolves interpolations into `Expr`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum TemplateExprSegment {
    /// Plain text between interpolations.
    Literal(String),
    /// A parsed expression interpolation `${expr}`.
    Interpolation(Expr),
}

// ─── Match arms ───────────────────────────────────────────────────────────────

/// A single arm in a `match` expression.
#[derive(Debug, Clone, PartialEq)]
pub struct MatchArm {
    /// The pattern to match against.
    pub pattern: Pattern,
    /// Optional guard condition: `if expr`.
    pub guard: Option<Expr>,
    /// The arm body.
    pub body: MatchBody,
    /// Source location.
    pub span: Span,
}

/// The body of a match arm.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum MatchBody {
    /// `=> expr`
    Expr(Expr),
    /// `=> { stmts }`
    Block(Vec<Stmt>),
}

// ─── Patterns ─────────────────────────────────────────────────────────────────

/// A pattern used in `let` destructuring and `match` arms.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum Pattern {
    /// `_` — wildcard, matches anything.
    Wildcard(Span),
    /// `name` — binds the matched value to a name.
    Ident(String, Span),
    /// A literal pattern: `42`, `"hello"`, `true`.
    Literal(Literal, Span),
    /// Struct destructure: `Foo { x, y: z }`.
    Struct_ {
        name: String,
        fields: Vec<(String, Pattern)>,
        span: Span,
    },
    /// Tuple destructure: `(a, b, c)`.
    Tuple(Vec<Pattern>, Span),
    /// Enum variant: `Some(x)` or `None`.
    EnumVariant {
        name: String,
        inner: Option<Vec<Pattern>>,
        span: Span,
    },
    /// `..` — rest pattern (ignore remaining fields).
    Rest(Span),
}

// ─── Expressions ─────────────────────────────────────────────────────────────

/// An expression in the Lem language.
///
/// All variants carry a `Span` for source location tracking.
/// Recursive variants use `Box<Expr>` to avoid infinite-size types.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// A literal value: `42`, `"hello"`, `true`.
    Literal(Literal, Span),

    /// An identifier reference: `foo`, `self`.
    Ident(String, Span),

    /// A tuple expression: `(a, b, c)`.
    Tuple(Vec<Expr>, Span),

    /// An array literal: `[1, 2, 3]`.
    Array(Vec<Expr>, Span),

    /// A struct literal: `Foo { x: 1, y: 2, ...base }`.
    Struct_ {
        name: String,
        fields: Vec<(String, Expr)>,
        /// Optional spread: `...base`
        spread: Option<Box<Expr>>,
        span: Span,
    },

    /// A function call: `foo{value: 1}(a, b)`.
    Call {
        callee: Box<Expr>,
        /// Optional call options `{value, gas, salt}`.
        opts: Option<CallOpts>,
        args: Vec<CallArg>,
        span: Span,
    },

    /// An index expression: `arr[i]`.
    Index(Box<Expr>, Box<Expr>, Span),

    /// A member access: `obj.field`.
    Member(Box<Expr>, String, Span),

    /// A unary expression: `!x`, `-y`.
    Unary(UnaryOp, Box<Expr>, Span),

    /// A binary expression: `a + b`, `x == y`.
    Binary(BinaryOp, Box<Expr>, Box<Expr>, Span),

    /// A ternary expression: `cond ? then : else`.
    Ternary {
        cond: Box<Expr>,
        then: Box<Expr>,
        else_: Box<Expr>,
        span: Span,
    },

    /// Null-coalescing: `a ?? b`.
    Nullish(Box<Expr>, Box<Expr>, Span),

    /// Try operator (postfix `?`): `expr?`.
    Try_(Box<Expr>, Span),

    /// A lambda expression: `(x, y) => x + y` or `x => x * 2`.
    Lambda {
        params: Vec<Param>,
        body: LambdaBody,
        span: Span,
    },

    /// A `new` expression: `new Foo{salt: s}(args)`.
    New {
        ty: String,
        opts: Option<CallOpts>,
        args: Vec<CallArg>,
        span: Span,
    },

    /// A `match` expression: `match x { arm, ... }`.
    Match_(Box<Expr>, Vec<MatchArm>, Span),

    /// An `if` expression: `if (cond) { then } else { else_ }`.
    If_ {
        cond: Box<Expr>,
        then: Vec<Stmt>,
        else_: Option<Vec<Stmt>>,
        span: Span,
    },

    /// A template string: `` `hello ${name}` ``.
    Template(Vec<TemplateExprSegment>, Span),

    /// An assignment expression: `x = y`, `x += y`.
    Assign_(Box<Expr>, AssignOp, Box<Expr>, Span),
}
