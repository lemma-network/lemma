//! Contract, token, interface, trait, and library declaration nodes.
//!
//! Covers the "container" declarations that hold members:
//! `contract`, `token`, `interface`, `trait`, `library`,
//! plus `state`, `immutable`.

use crate::lexer::token::Span;

use super::super::expr::Expr;
use super::super::Type;
use super::config::{Config, Metadata};
use super::types::{Enum, ErrorDecl, Event, Struct};
use super::{Const, Fallback_, Function, ModifierDef, Receive};

// ─── State ────────────────────────────────────────────────────────────────────

/// A `state { ... }` block inside a contract.
#[derive(Debug, Clone, PartialEq)]
pub struct StateBlock {
    /// State fields in declaration order.
    pub fields: Vec<StateField>,
    /// Source location.
    pub span: Span,
}

/// A single field inside a `state { ... }` block.
#[derive(Debug, Clone, PartialEq)]
pub struct StateField {
    /// Whether the field is `pub`.
    pub pub_: bool,
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: Type,
    /// Optional default value expression.
    pub default: Option<Expr>,
    /// Source location.
    pub span: Span,
}

/// An `immutable NAME: T` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Immutable {
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: Type,
    /// Source location.
    pub span: Span,
}

// ─── Contract ─────────────────────────────────────────────────────────────────

/// A `contract` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Contract {
    /// Contract name.
    pub name: String,
    /// Interfaces this contract implements.
    pub implements: Vec<String>,
    /// Traits this contract uses.
    pub uses: Vec<String>,
    /// Contract body members.
    pub members: Vec<ContractMember>,
    /// Source location.
    pub span: Span,
}

/// A member inside a `contract` or `token` body.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum ContractMember {
    /// `state { ... }` block.
    State(StateBlock),
    /// `const NAME: T = expr`
    Const(Const),
    /// `immutable NAME: T`
    Immutable(Immutable),
    /// A function definition.
    Function(Function),
    /// An event definition.
    Event(Event),
    /// A modifier definition.
    Modifier(ModifierDef),
    /// `receive() { ... }`
    Receive(Receive),
    /// `fallback() { ... }`
    Fallback(Fallback_),
    /// An inline struct definition.
    Struct(Struct),
    /// An inline enum definition.
    Enum(Enum),
    /// An inline error declaration.
    ErrorDecl(ErrorDecl),
    /// `config { ... }` block (token standard).
    Config(Config),
    /// `metadata { ... }` block (token standard).
    Metadata(Metadata),
}

// ─── Token declaration ────────────────────────────────────────────────────────

/// A `token Foo extends Bar { ... }` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct TokenDecl {
    /// Token name.
    pub name: String,
    /// Base token standard being extended (e.g. `"Token"`).
    pub extends: String,
    /// Token body members (same set as `ContractMember`).
    pub members: Vec<ContractMember>,
    /// Source location.
    pub span: Span,
}

// ─── Interface / Trait / Library ──────────────────────────────────────────────

/// An `interface Foo { ... }` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Interface {
    /// Interface name.
    pub name: String,
    /// Interface members (function signatures and events).
    pub members: Vec<InterfaceMember>,
    /// Source location.
    pub span: Span,
}

/// A member inside an interface body.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum InterfaceMember {
    /// A function signature (no body).
    Function(Function),
    /// An event definition.
    Event(Event),
}

/// A `trait Foo { ... }` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Trait {
    /// Trait name.
    pub name: String,
    /// Trait members.
    pub members: Vec<TraitMember>,
    /// Source location.
    pub span: Span,
}

/// A member inside a trait body.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum TraitMember {
    /// A `state { ... }` block (trait can declare required state).
    State(StateBlock),
    /// A function (required signature or default implementation).
    Function(Function),
}

/// A `library Foo { ... }` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Library {
    /// Library name.
    pub name: String,
    /// Library functions (stateless).
    pub functions: Vec<Function>,
    /// Source location.
    pub span: Span,
}
