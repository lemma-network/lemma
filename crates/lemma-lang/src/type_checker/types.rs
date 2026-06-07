//! Semantic (resolved) type representation for the Lem type checker.
//!
//! [`ResolvedType`] is the canonical type used by the type checker and all
//! downstream stages (safety analyzer, codegen).  It is distinct from the
//! syntactic [`crate::parser::ast::Type`] produced by the parser:
//!
//! - All sub-types recursively use `ResolvedType`, not `Type`.
//! - `Named` still carries a plain `String` in 3a; subtask 3b replaces it with
//!   a [`SymbolId`] once name resolution is implemented.
//! - [`ResolvedType::TypeParam`] represents an unresolved generic parameter
//!   (e.g. `T` in `fn first<T>(arr: Array<T>) -> T`).
//! - [`ResolvedType::Unit`] represents the void/unit return type (a function
//!   with no `return_type` in its signature).
//! - [`ResolvedType::Unknown`] is a placeholder during incremental checking;
//!   it must not appear in a fully-checked program.
//!
//! ## Mapping from `Type`
//!
//! Most variants map 1-to-1 from the AST `Type` enum (same name).
//! Where Rust reserved words conflict, both types use the same underscore
//! suffix convention (`Option_`, `Result_`).

// ─── ResolvedType ─────────────────────────────────────────────────────────────

/// The canonical, resolved type used throughout the type checker and downstream.
///
/// See module-level documentation for the difference from [`crate::parser::ast::Type`].
///
/// # Keeping in sync with `parser::ast::Type`
///
/// The leaf variants of `ResolvedType` mirror those of the syntactic `Type` enum.
/// When adding a new `Type` variant, add the corresponding `ResolvedType` variant
/// here **and** update the `Type → ResolvedType` lowering pass in subtask 3b.
/// The lowering is an exhaustive in-crate `match` (no `_` arm) so the compiler
/// enforces this discipline.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolvedType {
    // ── Unsigned integers ──────────────────────────────────────────────────
    /// `u8`
    U8,
    /// `u16`
    U16,
    /// `u32`
    U32,
    /// `u64`
    U64,
    /// `u128`
    U128,
    /// `u256`
    U256,

    // ── Signed integers ────────────────────────────────────────────────────
    /// `i8`
    I8,
    /// `i16`
    I16,
    /// `i32`
    I32,
    /// `i64`
    I64,
    /// `i128`
    I128,
    /// `i256`
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
    /// `decimal(N)` — fixed-point decimal with N decimal places (§3.3).
    /// Deterministic: no floating-point math, pure integer arithmetic.
    Decimal(u32),

    // ── Compound types ─────────────────────────────────────────────────────
    /// `Array<T>`
    Array(Box<ResolvedType>),
    /// `[T; N]` — fixed-size array
    FixedArray(Box<ResolvedType>, u64),
    /// `Map<K, V>`
    Map(Box<ResolvedType>, Box<ResolvedType>),
    /// `FastMap<K, V>`
    FastMap(Box<ResolvedType>, Box<ResolvedType>),
    /// `Set<T>`
    Set(Box<ResolvedType>),
    /// `Option<T>` — trailing underscore avoids Rust `Option` conflict at use sites.
    Option_(Box<ResolvedType>),
    /// `Result<T, E>` — trailing underscore avoids Rust `Result` conflict at use sites.
    Result_(Box<ResolvedType>, Box<ResolvedType>),
    /// `(T1, T2, ...)` — tuple type
    Tuple(Vec<ResolvedType>),
    /// `fn(T1, T2) -> R` — function type
    Fn(Vec<ResolvedType>, Box<ResolvedType>),

    // ── Named / generic ────────────────────────────────────────────────────
    /// A named type (struct, enum, interface, or type alias).
    ///
    /// **3a**: the name is a plain `String`; subtask 3b replaces it with a
    /// [`SymbolId`] once name resolution walks the symbol table.
    Named(String, Vec<ResolvedType>),

    /// A generic type parameter, e.g. `T` in `fn first<T>(arr: Array<T>) -> T`.
    ///
    /// Resolved to a concrete type during generic instantiation (subtask 3f).
    TypeParam(String),

    // ── Special ────────────────────────────────────────────────────────────
    /// The unit type — returned by functions with no declared return type.
    Unit,

    /// A type that has not yet been determined.
    ///
    /// Used as a placeholder during incremental checking.  Must not appear in
    /// a fully type-checked program (the checker reports an error if it does).
    Unknown,
}

impl ResolvedType {
    /// Returns `true` if this type is any unsigned integer.
    #[must_use]
    pub fn is_unsigned_int(&self) -> bool {
        matches!(
            self,
            Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::U128 | Self::U256
        )
    }

    /// Returns `true` if this type is any signed integer.
    #[must_use]
    pub fn is_signed_int(&self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::I128 | Self::I256
        )
    }

    /// Returns `true` if this type is any integer (signed or unsigned).
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.is_unsigned_int() || self.is_signed_int()
    }

    /// Returns `true` if this type is a numeric type (integer or decimal).
    #[must_use]
    pub fn is_numeric(&self) -> bool {
        self.is_integer() || matches!(self, Self::Decimal(_))
    }

    /// Returns `true` if this is a resolved, concrete type (not Unknown or TypeParam).
    #[must_use]
    pub fn is_concrete(&self) -> bool {
        !matches!(self, Self::Unknown | Self::TypeParam(_))
    }
}

// ─── SymbolId ─────────────────────────────────────────────────────────────────

/// A stable, monotonic identifier for a resolved symbol (type or value declaration).
///
/// Assigned by the name resolver (subtask 3b) during a top-down walk of the
/// AST.  Used in [`crate::type_checker::typed_ast::TypedAst::resolutions`] to
/// map identifier source spans to their declaration sites.
///
/// `SymbolId(0)` is reserved as a sentinel "unresolved" value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SymbolId(pub u32);

impl SymbolId {
    /// The sentinel "unresolved" ID.  Not a valid resolved symbol.
    pub const UNRESOLVED: Self = Self(0);

    /// Returns `true` if this ID represents an unresolved symbol.
    #[must_use]
    pub fn is_unresolved(self) -> bool {
        self == Self::UNRESOLVED
    }
}

// ─── SymbolInfo ───────────────────────────────────────────────────────────────

/// Metadata for a resolved symbol — stored in the symbol arena
/// [`crate::type_checker::typed_ast::TypedAst::symbols`].
///
/// Indexed by [`SymbolId`]: `TypedAst::symbol(id)` returns the [`SymbolInfo`]
/// for that ID.  Downstream stages (safety analyzer, codegen) look up symbol
/// metadata here after receiving a [`SymbolId`] from `TypedAst::resolutions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    /// The declared name of this symbol.
    pub name: String,
    /// Source location of the declaration site.
    pub decl_span: crate::lexer::token::Span,
    /// The kind of declaration this symbol represents.
    pub kind: SymbolKind,
}

/// The kind of declaration a [`SymbolInfo`] describes.
///
/// Used by downstream passes to distinguish function symbols from type symbols,
/// mutable locals from immutable params, etc.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolKind {
    // ── Value-namespace kinds ─────────────────────────────────────────────
    /// A top-level or contract-member `fn` declaration.
    Function,
    /// A `const NAME: T = expr` declaration.
    Const,
    /// An `immutable NAME: T` declaration (set once in `init`).
    Immutable,
    /// A field inside a `state { }` block.
    StateField,
    /// A function parameter.
    Param,
    /// A local variable introduced by `let`, `for`, `match`, or `catch`.
    Local,
    /// The synthetic `self` binding inside a method body.
    SelfBinding,

    // ── Type-namespace kinds ──────────────────────────────────────────────
    /// A `contract Foo { }` or `token Foo extends T { }` declaration.
    Contract,
    /// A `struct Foo { }` declaration.
    Struct,
    /// An `enum Foo { }` declaration.
    Enum,
    /// A `type Alias = T` declaration.
    TypeAlias,
    /// An `interface Foo { }` declaration.
    Interface,
    /// A `trait Foo { }` declaration.
    Trait,
    /// A `library Foo { }` declaration.
    Library,
    /// An `error Foo { }` declaration.
    ErrorDecl,
    /// A generic type parameter (e.g. `T` in `fn foo<T>(…)`).
    GenericParam,

    // ── Import ────────────────────────────────────────────────────────────
    /// A name registered by an `import { X } from "path"` statement.
    /// Treated as opaque in 3b; resolved to concrete kinds when the standard
    /// library is available (P3·Step 8).
    Imported,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
