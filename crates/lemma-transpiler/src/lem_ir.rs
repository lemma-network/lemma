//! Lem Intermediate Representation (IR).
//!
//! These types sit between the Solidity AST (produced by `sol_parser`) and the
//! Lem source text (produced by `codegen`). The mapper transforms Solidity AST
//! nodes into these types; the codegen emits valid Lem source from them.
//!
//! ## Design rationale
//!
//! A separate IR layer (rather than direct AST→text) gives two benefits:
//! 1. The mapper can focus on *semantic* correctness (what Solidity means in Lem)
//!    without worrying about pretty-printing syntax.
//! 2. The codegen can be tested independently against known IR inputs.
//!
//! Both mapper and codegen tests reference these types directly (no string parsing).

use serde::{Deserialize, Serialize};

// ── Types ─────────────────────────────────────────────────────────────────────

/// Lem type system representation.
///
/// Covers all Solidity types that map to a Lem equivalent (§28, DB-A59).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LemType {
    // Unsigned integers
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    // Signed integers
    I8,
    I16,
    I32,
    I64,
    I128,
    // Primitives
    Bool,
    /// UTF-8 string.
    Str,
    /// Dynamic byte array.
    Bytes,
    /// 20-byte Lemma address (Bech32m `lem1...`).
    Address,
    /// Fixed-size byte array — Solidity `bytesN` → `[u8; N]`.
    FixedBytes(usize),
    /// Dynamic array — Solidity `T[]` → `Array<T>`.
    Array(Box<LemType>),
    /// Key-value map — Solidity `mapping(K => V)` → `Map<K, V>`.
    Map(Box<LemType>, Box<LemType>),
    /// Ordered set — used for Lem's `Set<T>` where Solidity uses `EnumerableSet`.
    Set(Box<LemType>),
    /// Named user-defined type (struct, enum, or contract reference).
    Named(String),
    /// Optional value — Solidity `address(0)` sentinel patterns → `Option<T>`.
    Option(Box<LemType>),
    /// 2-tuple — used for multiple return values.
    Tuple(Box<LemType>, Box<LemType>),
}

// ── Visibility ────────────────────────────────────────────────────────────────

/// Lem function visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LemVisibility {
    /// `pub fn` — callable from outside the contract.
    Public,
    /// `fn` (no keyword) — contract-internal only.
    Private,
}

// ── Mutability ────────────────────────────────────────────────────────────────

/// Lem function mutability (state access).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LemMutability {
    /// May read and write state. Default.
    Mutable,
    /// May only read state. Lem: `view` keyword.
    View,
    /// May not access state. Lem: `pure` keyword.
    Pure,
    /// May receive LEM value. Lem: `payable` keyword.
    Payable,
}

// ── Parameters ────────────────────────────────────────────────────────────────

/// A named, typed parameter (function param or struct field).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LemParam {
    pub name: String,
    pub ty: LemType,
}

// ── Operators ─────────────────────────────────────────────────────────────────

/// Binary operators in Lem expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BinOp {
    Add,
    Sub,
    Mul,
    Div,
    Rem,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    And,
    Or,
    BitAnd,
    BitOr,
    BitXor,
    Shl,
    Shr,
}

/// Unary operators in Lem expressions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnaryOp {
    /// Logical `!`
    Not,
    /// Arithmetic `-`
    Neg,
}

// ── Expressions ───────────────────────────────────────────────────────────────

/// Lem expression IR.
///
/// Covers the expression forms needed to represent ERC-20 contract bodies.
/// Complex Solidity expressions with no Lem equivalent are represented as
/// [`LemExpr::Raw`] with a comment inserted by the codegen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LemExpr {
    // Literals
    IntLit(u128),
    BoolLit(bool),
    StringLit(String),
    /// Byte-array literal.
    BytesLit(Vec<u8>),
    /// `Address.zero` / `Address.burn` / named address constant.
    AddressLit(String),

    // References
    /// Simple identifier: variable, function name.
    Ident(String),
    /// `lhs.field` — member access on any expression.
    MemberAccess(Box<LemExpr>, String),
    /// `map[key]` — index access (maps to `map.get(key)` in Lem).
    IndexAccess(Box<LemExpr>, Box<LemExpr>),

    // Calls
    /// Function / method call: `func(arg0, arg1, ...)`.
    Call {
        func: Box<LemExpr>,
        args: Vec<LemExpr>,
    },
    /// Map `.get(key)` call — emitted as `self.map.get(key)`.
    MapGet {
        map: Box<LemExpr>,
        key: Box<LemExpr>,
    },
    /// Map `.set(key, value)` call — emitted as `self.map.set(key, value)`.
    MapSet {
        map: Box<LemExpr>,
        key: Box<LemExpr>,
        value: Box<LemExpr>,
    },

    // Operations
    BinaryOp {
        op: BinOp,
        left: Box<LemExpr>,
        right: Box<LemExpr>,
    },
    UnaryOp {
        op: UnaryOp,
        expr: Box<LemExpr>,
    },

    // Compound
    /// Struct literal: `Foo { field: val, ... }`.
    StructLit {
        name: String,
        fields: Vec<(String, LemExpr)>,
    },
    /// Type cast: `expr as Type` (used for checked numeric casts).
    Cast {
        expr: Box<LemExpr>,
        ty: LemType,
    },
    /// Ternary: `cond ? then : else` — mapped to `if`/`else` in Lem codegen.
    Ternary {
        cond: Box<LemExpr>,
        then_expr: Box<LemExpr>,
        else_expr: Box<LemExpr>,
    },

    /// Raw Lem source fallback — emitted verbatim with a `// transpiled` comment.
    /// Used for expressions that have no clean IR equivalent.
    Raw(String),
}

// ── Statements ────────────────────────────────────────────────────────────────

/// Lem statement IR.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LemStmt {
    /// `let name: Ty = value` or `let name = value`.
    Let {
        name: String,
        ty: Option<LemType>,
        value: LemExpr,
    },
    /// `target = value` assignment.
    Assign { target: LemExpr, value: LemExpr },
    /// `assert(cond, "message")` — mapped from Solidity `require(cond, "msg")`.
    Assert { cond: LemExpr, msg: String },
    /// `emit Event { field: val, ... }`.
    Emit {
        event: String,
        fields: Vec<(String, LemExpr)>,
    },
    /// `return expr` or bare `return`.
    Return(Option<LemExpr>),
    /// `if (cond) { ... } else { ... }`.
    If {
        cond: LemExpr,
        then_body: Vec<LemStmt>,
        else_body: Option<Vec<LemStmt>>,
    },
    /// `while (cond) { ... }`.
    While { cond: LemExpr, body: Vec<LemStmt> },
    /// `for (init; cond; update) { ... }`.
    For {
        init: Option<Box<LemStmt>>,
        cond: Option<LemExpr>,
        update: Option<Box<LemStmt>>,
        body: Vec<LemStmt>,
    },
    /// Standalone expression statement (e.g. a function call).
    Expr(LemExpr),
    /// `break` in a loop.
    Break,
    /// `continue` in a loop.
    Continue,
    /// Raw Lem source fallback.
    Raw(String),
}

// ── Struct ────────────────────────────────────────────────────────────────────

/// A `struct` definition in Lem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LemStruct {
    pub name: String,
    pub fields: Vec<LemParam>,
}

// ── Enum ──────────────────────────────────────────────────────────────────────

/// An `enum` definition in Lem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LemEnum {
    pub name: String,
    pub variants: Vec<String>,
}

// ── Events ────────────────────────────────────────────────────────────────────

/// A single event field (positional → named by the mapper).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LemEventField {
    pub name: String,
    pub ty: LemType,
    /// `@indexed` annotation.
    pub indexed: bool,
}

/// An `event` definition in Lem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LemEvent {
    pub name: String,
    pub fields: Vec<LemEventField>,
}

// ── Functions ─────────────────────────────────────────────────────────────────

/// A function or constructor definition in Lem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LemFunction {
    pub name: String,
    pub params: Vec<LemParam>,
    /// `None` = void return.
    pub returns: Option<LemType>,
    pub visibility: LemVisibility,
    pub mutability: LemMutability,
    /// Decorator names: `["onlyOwner", "whenNotPaused"]` etc.
    pub decorators: Vec<String>,
    pub body: Vec<LemStmt>,
    /// `true` if this was a Solidity `constructor`.
    pub is_constructor: bool,
}

// ── Contract ──────────────────────────────────────────────────────────────────

/// The complete Lem IR for a single contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LemContract {
    /// Contract name.
    pub name: String,
    /// `extends` bases (concrete contract inheritance).
    pub extends: Vec<String>,
    /// `uses` traits/interfaces.
    pub uses: Vec<String>,
    /// `true` if the Solidity source inherits from IERC20 → emit `uses IToken`.
    pub uses_itoken: bool,
    /// Struct definitions declared inside or above the contract.
    pub structs: Vec<LemStruct>,
    /// Enum definitions.
    pub enums: Vec<LemEnum>,
    /// `state { ... }` variables.
    pub state: Vec<LemParam>,
    /// Event definitions.
    pub events: Vec<LemEvent>,
    /// All functions (including constructor).
    pub functions: Vec<LemFunction>,
    /// `true` if the contract emits `uses Ownable` (has `onlyOwner` modifier).
    pub uses_ownable: bool,
    /// `true` if the contract emits `uses Pausable`.
    pub uses_pausable: bool,
    /// `true` if the contract emits `uses AccessControl`.
    pub uses_access_control: bool,
}

#[cfg(test)]
mod tests;
