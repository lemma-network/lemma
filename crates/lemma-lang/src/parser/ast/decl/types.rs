//! Type declaration nodes: structs, enums, events, errors, consts, type aliases.

use crate::lexer::token::Span;

use super::super::expr::Expr;
use super::super::Type;
use super::{Function, GenericParam};

// ─── Const / TypeAlias ────────────────────────────────────────────────────────

/// A `const NAME: T = expr` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Const {
    /// Constant name.
    pub name: String,
    /// Constant type.
    pub ty: Type,
    /// Constant value expression.
    pub value: Expr,
    /// Source location.
    pub span: Span,
}

/// A `type Alias = T` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct TypeAlias {
    /// Alias name.
    pub name: String,
    /// The aliased type.
    pub ty: Type,
    /// Source location.
    pub span: Span,
}

// ─── Struct / Enum ────────────────────────────────────────────────────────────

/// A `struct Foo<T> { ... }` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Struct {
    /// Struct name.
    pub name: String,
    /// Generic type parameters.
    pub generic_params: Vec<GenericParam>,
    /// Struct members (fields and methods).
    pub members: Vec<StructMember>,
    /// Source location.
    pub span: Span,
}

/// A member inside a struct body.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum StructMember {
    /// A named field: `name: Type`
    Field(FieldDecl),
    /// An inline method.
    Method(Function),
}

/// A named field declaration (used in structs, events, errors).
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDecl {
    /// Field name.
    pub name: String,
    /// Field type.
    pub ty: Type,
    /// Source location.
    pub span: Span,
}

/// An `enum Foo<T> { ... }` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Enum {
    /// Enum name.
    pub name: String,
    /// Generic type parameters.
    pub generic_params: Vec<GenericParam>,
    /// Enum variants.
    pub variants: Vec<EnumVariant>,
    /// Methods defined at the enum body level (not per-variant).
    ///
    /// Per spec §10, methods appear inside the enum body alongside variants,
    /// not nested inside individual variants.
    pub methods: Vec<Function>,
    /// Source location.
    pub span: Span,
}

/// A single variant inside an enum.
#[derive(Debug, Clone, PartialEq)]
pub struct EnumVariant {
    /// Variant name.
    pub name: String,
    /// Tuple-style fields (e.g. `Variant(u128, Address)`).
    ///
    /// Named-field variants use the declared name; positional variants use
    /// synthetic names `"_0"`, `"_1"`, … (assigned by the parser).
    pub fields: Vec<FieldDecl>,
    /// Optional discriminant value (e.g. `= 42`).
    pub discriminant: Option<Expr>,
    /// Source location.
    pub span: Span,
}

// ─── Event / Error ────────────────────────────────────────────────────────────

/// An `event Foo { ... }` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// Event name.
    pub name: String,
    /// Whether this is an `@anonymous` event.
    pub anonymous: bool,
    /// Event fields.
    pub fields: Vec<EventField>,
    /// Computed event fields (methods) — e.g. `fn priceImpact() -> decimal(4) { ... }`.
    ///
    /// Per spec §15, an event body may contain inline `fn` declarations alongside
    /// regular fields. These are "computed fields" that derive a value from the
    /// event's data at query time.
    pub methods: Vec<Function>,
    /// Source location.
    pub span: Span,
}

/// A single field inside an event declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct EventField {
    /// Whether this field is `@indexed`.
    pub indexed: bool,
    /// Field name.
    pub name: String,
    /// Whether the field is optional (`name?: Type`).
    pub optional: bool,
    /// Field type.
    pub ty: Type,
    /// Source location.
    pub span: Span,
}

/// An `error Foo { ... }` declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct ErrorDecl {
    /// Error name.
    pub name: String,
    /// Error fields.
    pub fields: Vec<FieldDecl>,
    /// Source location.
    pub span: Span,
}
