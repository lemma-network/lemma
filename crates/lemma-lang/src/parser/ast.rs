//! Abstract Syntax Tree (AST) node definitions for the Lem language.
//!
//! All AST types are defined here upfront so that later parser subtasks
//! (2b–2h) can fill in parsing logic without changing the type definitions.
//!
//! ## Structure
//!
//! The AST is split into submodules by concern:
//! - `expr`  — expression nodes (`Expr`, `Literal`, operators, etc.)
//! - `stmt`  — statement nodes (`Stmt`, `Pattern`, `MatchArm`, etc.)
//! - `decl`  — declaration nodes (`Contract`, `Function`, `Struct`, etc.)
//!
//! All submodule types are re-exported at this level for ergonomic use.
//!
//! ## Spans
//!
//! Every AST node carries a [`Span`] for source location tracking. Spans
//! are threaded from the token stream into every node so the type-checker
//! and safety analyzer can produce precise diagnostics.

// Use explicit path to resolve the decl module from decl/mod.rs (Rust 2021 directory split).
// decl.rs also exists (legacy flat file) but is superseded by the directory layout.
#[path = "ast/decl/mod.rs"]
mod decl;
mod expr;
mod stmt;

pub use decl::*;
pub use expr::*;
pub use stmt::*;

use crate::lexer::token::Span;

// ─── Root ─────────────────────────────────────────────────────────────────────

/// The root of a parsed Lem source file.
///
/// Contains all top-level items in source order.
#[derive(Debug, Clone, PartialEq)]
pub struct Ast {
    /// Top-level items in source order.
    pub items: Vec<Item>,
    /// Span covering the entire source file.
    pub span: Span,
}

// ─── Top-level items ──────────────────────────────────────────────────────────

/// A top-level item in a Lem source file.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum Item {
    /// `contract Foo implements I uses T { ... }`
    Contract(Contract),
    /// `token Foo extends Token { ... }`
    Token_(TokenDecl),
    /// `interface Foo { ... }`
    Interface(Interface),
    /// `trait Foo { ... }`
    Trait(Trait),
    /// `library Foo { ... }`
    Library(Library),
    /// `struct Foo<T> { ... }`
    Struct(Struct),
    /// `enum Foo<T> { ... }`
    Enum(Enum),
    /// `fn foo(...) -> T { ... }`
    Function(Function),
    /// `const FOO: T = expr`
    Const(Const),
    /// `type Foo = T`
    TypeAlias(TypeAlias),
    /// `import { A, B } from "path"`
    Import(Import),
    /// `using Library for Type`
    Using(Using),
    /// `error Foo { field: T }`
    ErrorDecl(ErrorDecl),
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
