//! Declaration AST nodes for the Lem language.
//!
//! Covers contracts, tokens, interfaces, traits, libraries, structs, enums,
//! functions, events, errors, imports, type aliases, and config/metadata blocks.
//!
//! ## Submodule layout
//!
//! - `mod.rs` (this file) — core building blocks: `Function`, `Param`,
//!   `Visibility`, `Mutability`, `Annotation`, `AnnotationArg`, `GenericParam`
//! - `types.rs` — type declarations: `Struct`, `Enum`, `Event`, `ErrorDecl`,
//!   `FieldDecl`, `Const`, `TypeAlias`
//! - `members.rs` — container declarations: `Contract`, `ContractMember`,
//!   `TokenDecl`, `StateBlock`, `StateField`, `Immutable`, `Interface`,
//!   `InterfaceMember`, `Trait`, `TraitMember`, `Library`, `ModifierDef`,
//!   `Receive`, `Fallback_`
//! - `config.rs` — config/import declarations: `Config`, `Metadata`,
//!   `ConfigEntry`, `ConfigValue`, `UnitKind`, `Import`, `ImportNames`, `Using`

pub mod config;
pub mod members;
pub mod types;

// Re-export everything so callers can use `decl::*` or `use super::decl::Foo`
pub use config::*;
pub use members::*;
pub use types::*;

use crate::lexer::token::Span;

use super::expr::Expr;
use super::stmt::Stmt;
use super::Type;

// ─── Visibility & Mutability ──────────────────────────────────────────────────

/// Visibility modifier on a function or state field.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visibility {
    /// `pub` — visible to callers outside the contract.
    Pub,
    /// `external` — callable only from outside (not internally).
    External,
    /// No modifier — private by default.
    Private,
}

/// Mutability modifier on a function.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mutability {
    /// `view` — reads state, does not write.
    View,
    /// `pure` — neither reads nor writes state.
    Pure,
    /// `payable` — can receive LEM.
    Payable,
    /// No modifier — default (reads and writes state).
    Default,
}

// ─── Annotations ─────────────────────────────────────────────────────────────

/// An annotation applied to a function or declaration.
///
/// Supports both `@name(args)` and `#[name(args)]` syntax.
#[derive(Debug, Clone, PartialEq)]
pub struct Annotation {
    /// Annotation name (e.g. `"onlyOwner"`, `"agentCallable"`).
    pub name: String,
    /// Arguments passed to the annotation.
    pub args: Vec<AnnotationArg>,
    /// Source location of the annotation.
    pub span: Span,
}

/// A single argument in an annotation's argument list.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum AnnotationArg {
    /// `expr` — positional argument.
    Positional(Expr),
    /// `key: expr` — named argument.
    Named(String, Expr),
}

// ─── Generic parameters ───────────────────────────────────────────────────────

/// A generic type parameter with an optional trait bound.
///
/// Example: `<T: Comparable>` → `GenericParam { name: "T", bound: Some(Named("Comparable", [])) }`
#[derive(Debug, Clone, PartialEq)]
pub struct GenericParam {
    /// Parameter name (e.g. `"T"`).
    pub name: String,
    /// Optional trait bound (e.g. `Comparable`).
    pub bound: Option<Type>,
    /// Source location.
    pub span: Span,
}

// ─── Function parameters ──────────────────────────────────────────────────────

/// A function parameter with optional default value.
#[derive(Debug, Clone, PartialEq)]
pub struct Param {
    /// Parameter name.
    pub name: String,
    /// Parameter type.
    pub ty: Type,
    /// Optional default expression.
    pub default_expr: Option<Expr>,
    /// Source location.
    pub span: Span,
}

// ─── Function ─────────────────────────────────────────────────────────────────

/// A function declaration (top-level or contract member).
///
/// `body` is `None` for interface method signatures (no implementation).
#[derive(Debug, Clone, PartialEq)]
pub struct Function {
    /// Function name.
    pub name: String,
    /// Annotations applied to this function (e.g. `@onlyOwner`).
    pub annotations: Vec<Annotation>,
    /// Visibility modifier.
    pub visibility: Visibility,
    /// Mutability modifier.
    pub mutability: Mutability,
    /// Generic type parameters.
    pub generic_params: Vec<GenericParam>,
    /// Parameter list.
    pub params: Vec<Param>,
    /// Return type (None = unit / void).
    pub return_type: Option<Type>,
    /// Function body (None for interface signatures).
    pub body: Option<Vec<Stmt>>,
    /// Source location.
    pub span: Span,
}

// ─── Modifier / Receive / Fallback ────────────────────────────────────────────

/// A `modifier foo(params) { ... }` definition.
#[derive(Debug, Clone, PartialEq)]
pub struct ModifierDef {
    /// Modifier name.
    pub name: String,
    /// Parameters.
    pub params: Vec<Param>,
    /// Body (may contain `Stmt::Placeholder` for `_`).
    pub body: Vec<Stmt>,
    /// Source location.
    pub span: Span,
}

/// A `receive() { ... }` function.
#[derive(Debug, Clone, PartialEq)]
pub struct Receive {
    /// Whether the receive function is `payable`.
    pub payable: bool,
    /// Function body.
    pub body: Vec<Stmt>,
    /// Source location.
    pub span: Span,
}

/// A `fallback() { ... }` function.
#[derive(Debug, Clone, PartialEq)]
pub struct Fallback_ {
    /// Whether the fallback function is `payable`.
    pub payable: bool,
    /// Function body.
    pub body: Vec<Stmt>,
    /// Source location.
    pub span: Span,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
