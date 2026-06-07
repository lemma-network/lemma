//! Semantic (resolved) type representation for the Lem type checker.
//!
//! [`ResolvedType`] is the canonical type used by the type checker and all
//! downstream stages (safety analyzer, codegen).  It is distinct from the
//! syntactic [`crate::parser::ast::Type`] produced by the parser:
//!
//! - All sub-types recursively use `ResolvedType`, not `Type`.
//! - `Named` carries a [`SymbolId`] (from name resolution in 3b/3c).
//! - [`ResolvedType::IntLiteral`] is an unconstrained integer literal — it
//!   coerces to any concrete integer type demanded by context (3c/3e), and
//!   defaults to `u256` when no context constrains it (see `decisions-log.md`
//!   DB-A27).
//! - [`ResolvedType::TypeParam`] represents an unresolved generic parameter
//!   (e.g. `T` in `fn first<T>(arr: Array<T>) -> T`).  Instantiated in 3f.
//! - [`ResolvedType::Unit`] represents the void/unit return type (a function
//!   with no `return_type` in its signature).
//! - [`ResolvedType::Unknown`] is a placeholder during incremental checking;
//!   it must not appear in a fully-checked program.
//!
//! ## Mapping from `Type`
//!
//! Most variants map 1-to-1 from the AST `Type` enum (same name).
//! The `Type → ResolvedType` lowering is an exhaustive in-crate `match` (no
//! `_` arm) in [`crate::type_checker::resolver::Resolver::lower_type`] so the
//! compiler enforces that new `Type` variants are handled.
//!
//! ## `IntLiteral` coercion (DB-A27)
//!
//! Un-suffixed integer literals (e.g. `42`, `0xFF`) are assigned the
//! intermediate type `IntLiteral` by the expression typer.  The typer
//! immediately coerces them to a concrete integer type when context provides
//! one (arithmetic expression with a typed operand, explicit type annotation).
//! If no concrete integer context exists the literal defaults to `u256`.
//! See `decisions-log.md` DB-A27.

// ─── ResolvedType ─────────────────────────────────────────────────────────────

/// The canonical, resolved type used throughout the type checker and downstream.
///
/// See module-level documentation for the difference from [`crate::parser::ast::Type`].
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

    /// An unconstrained integer literal (e.g. `42`, `0xFF`, `0b1010`).
    ///
    /// Un-suffixed integer literals are assigned this intermediate type by the
    /// expression typer (3c).  They coerce to any concrete integer demanded
    /// by context, defaulting to `u256` when unconstrained (DB-A27).
    IntLiteral,

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
    /// A named type (struct, enum, interface, type alias, or contract).
    ///
    /// The [`SymbolId`] points to the declaration's entry in the symbol arena.
    /// Generic arguments (if any) are fully lowered to [`ResolvedType`].
    Named(SymbolId, Vec<ResolvedType>),

    /// A generic type parameter, e.g. `T` in `fn first<T>(arr: Array<T>) -> T`.
    ///
    /// Resolved to a concrete type during generic instantiation (subtask 3f).
    TypeParam(String),

    // ── Special ────────────────────────────────────────────────────────────
    /// The unit type — returned by functions with no declared return type.
    Unit,

    /// A type that has not yet been determined.
    ///
    /// Used as a placeholder during incremental checking or for symbol kinds
    /// whose type is resolved in a later subtask.  Must not appear in a fully
    /// type-checked program (the checker reports an error if it does).
    Unknown,
}

impl ResolvedType {
    /// Returns `true` if this type is any unsigned integer (not `IntLiteral`).
    #[must_use]
    pub fn is_unsigned_int(&self) -> bool {
        matches!(
            self,
            Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::U128 | Self::U256
        )
    }

    /// Returns `true` if this type is any signed integer (not `IntLiteral`).
    #[must_use]
    pub fn is_signed_int(&self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::I128 | Self::I256
        )
    }

    /// Returns `true` if this type is a concrete integer (signed or unsigned).
    ///
    /// Does NOT include [`ResolvedType::IntLiteral`] — use [`Self::is_numeric`]
    /// or [`Self::is_int_literal`] to check for the unconstrained literal type.
    #[must_use]
    pub fn is_integer(&self) -> bool {
        self.is_unsigned_int() || self.is_signed_int()
    }

    /// Returns `true` if this type is the unconstrained integer-literal marker.
    ///
    /// Integer literals without an explicit suffix (e.g. `42`) receive this
    /// type and are coerced to a concrete integer type by context (DB-A27).
    #[must_use]
    pub fn is_int_literal(&self) -> bool {
        matches!(self, Self::IntLiteral)
    }

    /// Returns `true` if this type is a numeric type (any integer, any integer
    /// literal, or decimal).
    #[must_use]
    pub fn is_numeric(&self) -> bool {
        self.is_integer() || self.is_int_literal() || matches!(self, Self::Decimal(_))
    }

    /// Returns the bit width of a concrete integer type, or `None` for
    /// non-integer types (including [`ResolvedType::IntLiteral`]).
    ///
    /// Useful for deciding which type is "wider" in an arithmetic expression.
    #[must_use]
    pub fn bit_width(&self) -> Option<u32> {
        match self {
            Self::U8 | Self::I8 => Some(8),
            Self::U16 | Self::I16 => Some(16),
            Self::U32 | Self::I32 => Some(32),
            Self::U64 | Self::I64 => Some(64),
            Self::U128 | Self::I128 => Some(128),
            Self::U256 | Self::I256 => Some(256),
            _ => None,
        }
    }

    /// If `self` is [`ResolvedType::IntLiteral`] and `target` is a concrete
    /// integer type, returns `Some(target.clone())` — the literal coerces to
    /// `target`.  Returns `None` in all other cases.
    #[must_use]
    pub fn coerce_int_literal<'a>(&self, target: &'a ResolvedType) -> Option<&'a ResolvedType> {
        if self.is_int_literal() && target.is_integer() {
            Some(target)
        } else {
            None
        }
    }

    /// Returns `true` if this is a resolved, concrete type.
    ///
    /// Concrete means neither [`ResolvedType::Unknown`] nor
    /// [`ResolvedType::TypeParam`].  [`ResolvedType::IntLiteral`] is
    /// considered concrete (it is a real type, just unconstrained).
    #[must_use]
    pub fn is_concrete(&self) -> bool {
        !matches!(self, Self::Unknown | Self::TypeParam(_))
    }

    /// Returns `true` if this is an `Option<T>` type.
    #[must_use]
    pub fn is_option(&self) -> bool {
        matches!(self, Self::Option_(_))
    }

    /// Returns `true` if this is a `Result<T, E>` type.
    #[must_use]
    pub fn is_result(&self) -> bool {
        matches!(self, Self::Result_(_, _))
    }

    /// If this is `Option<T>`, returns `Some(T)`.
    #[must_use]
    pub fn option_inner(&self) -> Option<&ResolvedType> {
        if let Self::Option_(inner) = self {
            Some(inner)
        } else {
            None
        }
    }

    /// If this is `Array<T>` or `[T; N]`, return the element type.
    #[must_use]
    pub fn array_elem(&self) -> Option<&ResolvedType> {
        match self {
            Self::Array(inner) | Self::FixedArray(inner, _) => Some(inner),
            _ => None,
        }
    }

    /// If this is `Map<K, V>` or `FastMap<K, V>`, return `(key, value)` types.
    #[must_use]
    pub fn map_kv(&self) -> Option<(&ResolvedType, &ResolvedType)> {
        match self {
            Self::Map(k, v) | Self::FastMap(k, v) => Some((k, v)),
            _ => None,
        }
    }

    /// If this is `Tuple(elems)`, return the element types slice.
    #[must_use]
    pub fn tuple_elems(&self) -> Option<&[ResolvedType]> {
        if let Self::Tuple(elems) = self {
            Some(elems)
        } else {
            None
        }
    }

    /// If this is `Named(id, _)`, return the `SymbolId`.
    #[must_use]
    pub fn named_id(&self) -> Option<SymbolId> {
        if let Self::Named(id, _) = self {
            Some(*id)
        } else {
            None
        }
    }

    /// Returns `true` if this type supports integer indexing (Array, FixedArray).
    #[must_use]
    pub fn is_array_type(&self) -> bool {
        matches!(self, Self::Array(_) | Self::FixedArray(_, _))
    }

    /// Returns `true` if this type supports map-style indexing (Map, FastMap).
    #[must_use]
    pub fn is_map_type(&self) -> bool {
        matches!(self, Self::Map(_, _) | Self::FastMap(_, _))
    }

    /// Human-readable name for use in error messages.
    ///
    /// Not a stable serialisation format — for diagnostics only.
    #[must_use]
    pub fn display_name(&self) -> String {
        match self {
            Self::U8 => "u8".into(),
            Self::U16 => "u16".into(),
            Self::U32 => "u32".into(),
            Self::U64 => "u64".into(),
            Self::U128 => "u128".into(),
            Self::U256 => "u256".into(),
            Self::I8 => "i8".into(),
            Self::I16 => "i16".into(),
            Self::I32 => "i32".into(),
            Self::I64 => "i64".into(),
            Self::I128 => "i128".into(),
            Self::I256 => "i256".into(),
            Self::IntLiteral => "{integer}".into(),
            Self::Bool => "bool".into(),
            Self::StringTy => "string".into(),
            Self::CharTy => "char".into(),
            Self::AddressTy => "Address".into(),
            Self::HashTy => "Hash".into(),
            Self::Bytes => "bytes".into(),
            Self::BytesN(n) => format!("bytes{n}"),
            Self::Decimal(n) => format!("decimal({n})"),
            Self::Array(inner) => format!("Array<{}>", inner.display_name()),
            Self::FixedArray(inner, n) => format!("[{}; {n}]", inner.display_name()),
            Self::Map(k, v) => format!("Map<{}, {}>", k.display_name(), v.display_name()),
            Self::FastMap(k, v) => {
                format!("FastMap<{}, {}>", k.display_name(), v.display_name())
            }
            Self::Set(inner) => format!("Set<{}>", inner.display_name()),
            Self::Option_(inner) => format!("Option<{}>", inner.display_name()),
            Self::Result_(ok, err) => {
                format!("Result<{}, {}>", ok.display_name(), err.display_name())
            }
            Self::Tuple(elems) => {
                let inner: Vec<_> = elems.iter().map(Self::display_name).collect();
                format!("({})", inner.join(", "))
            }
            Self::Fn(params, ret) => {
                let ps: Vec<_> = params.iter().map(Self::display_name).collect();
                format!("fn({}) -> {}", ps.join(", "), ret.display_name())
            }
            Self::Named(id, args) => {
                if args.is_empty() {
                    format!("<named:{}>", id.0)
                } else {
                    let gs: Vec<_> = args.iter().map(Self::display_name).collect();
                    format!("<named:{}><{}>", id.0, gs.join(", "))
                }
            }
            Self::TypeParam(name) => name.clone(),
            Self::Unit => "()".into(),
            Self::Unknown => "<unknown>".into(),
        }
    }
}

// ─── SymbolSig ────────────────────────────────────────────────────────────────

/// Structured signature for a symbol — used by the expression typer (3d+)
/// to look up function param types, struct field types, and enum variant
/// shapes without re-walking the AST at inference time.
///
/// Stored in [`crate::type_checker::typed_ast::TypedAst::sigs`] keyed by [`SymbolId`].
/// Populated during the resolver's second pass (3d).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymbolSig {
    /// A function or method declaration.
    Function(FnSig),
    /// A struct declaration.
    Struct(StructSig),
    /// An enum declaration.
    Enum(EnumSig),
}

/// Signature of a function or method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FnSig {
    /// Parameters in declaration order: `(name, resolved_type, has_default)`.
    pub params: Vec<(String, ResolvedType, bool)>,
    /// Return type (`Unit` for functions with no explicit return-type annotation).
    pub ret: ResolvedType,
}

/// Signature of a struct — its field names and types in declaration order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructSig {
    /// Fields in declaration order: `(name, resolved_type, has_default)`.
    ///
    /// The third element (`has_default`) is `true` when the field declaration
    /// includes a default expression (`field: T = expr`).  Fields without a
    /// default are *required* — a struct literal that omits them is a type error
    /// ([`crate::type_checker::error::TypeErrorKind::MissingField`]).
    pub fields: Vec<(String, ResolvedType, bool)>,
    /// Methods: `(name, method_symbol_id)`.
    /// The method's full `FnSig` lives at `sigs[method_symbol_id]`.
    pub methods: Vec<(String, SymbolId)>,
}

/// Signature of an enum — its variant names and field types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnumSig {
    /// Variants in declaration order: `(variant_name, fields)`.
    /// Each field is `(field_name, resolved_type)`.
    /// Positional variants use synthetic names `"_0"`, `"_1"`, … (parser convention).
    pub variants: Vec<(String, Vec<(String, ResolvedType)>)>,
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
///
/// ## `ty` field (DB-A28)
///
/// `ty` carries the [`ResolvedType`] of the declared symbol, populated during
/// the `Type → ResolvedType` lowering pass (3c).  Value-namespace symbols
/// (params, locals, consts, state fields, immutables) get their annotated type
/// lowered here.  Type-namespace symbols (contract, struct, enum, etc.) carry
/// [`ResolvedType::Unknown`] until a later subtask provides the self-referential
/// projection (3g / Step 4).
///
/// ## `mutable` field
///
/// Whether this symbol can be assigned after its initial binding.  `true` only
/// for `let mut` local variables.  All other kinds (params, consts, state
/// fields, immutables) are immutable for assignment purposes.  Populated by the
/// resolver (3e) and consumed by the safety analyzer (Step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    /// The declared name of this symbol.
    pub name: String,
    /// Source location of the declaration site.
    pub decl_span: crate::lexer::token::Span,
    /// The kind of declaration this symbol represents.
    pub kind: SymbolKind,
    /// The resolved type of this symbol (DB-A28).
    ///
    /// `Unknown` for type-namespace symbols and for value-namespace symbols
    /// whose type has not yet been lowered (e.g., function return types
    /// deferred to 3g).
    pub ty: ResolvedType,
    /// Whether this symbol can be assigned after its initial binding.
    ///
    /// `true` only for `let mut` local variables.  All other kinds (params,
    /// consts, state fields, immutables) are immutable for assignment purposes.
    pub mutable: bool,
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
