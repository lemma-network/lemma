//! Type-check error types for the Lem compiler.
//!
//! [`TypeError`] is emitted by the type checker when a Lem program
//! violates the type system.  It is wrapped by
//! [`crate::error::LangError::Type`] for propagation through the pipeline.
//!
//! # Design
//!
//! Mirrors the structure of [`crate::parser::error::ParseError`]:
//! a span-carrying struct with a human-readable `message` plus a
//! structured [`TypeErrorKind`] discriminator.  The discriminator is
//! richer than `ParseError.expected` because type errors carry
//! domain-specific context (what name was duplicated, what types were
//! mismatched, etc.).

use crate::lexer::token::Span;

/// A type-checking error produced by the Lem type checker.
///
/// Every error records:
/// - `kind`    — structured discriminator (for matching and tooling)
/// - `span`    — exact source location of the offending construct
/// - `message` — human-readable description (displayed via [`std::fmt::Display`])
///
/// # Examples
///
/// ```ignore
/// use lemma_lang::type_checker::error::{TypeError, TypeErrorKind};
/// use lemma_lang::lexer::token::Span;
///
/// let err = TypeError {
///     kind: TypeErrorKind::DuplicateDeclaration { name: "Foo".into() },
///     span: Span::at(1, 1, 0),
///     message: "duplicate declaration: 'Foo'".into(),
/// };
/// assert!(err.to_string().contains("duplicate declaration"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("type error at {span:?}: {message}")]
pub struct TypeError {
    /// Structured error kind for matching and diagnostic tooling.
    pub kind: TypeErrorKind,
    /// Source location of the offending construct.
    pub span: Span,
    /// Human-readable description of the error.
    pub message: String,
}

/// Discriminator for [`TypeError`].
///
/// Variants are added as the type checker gains new checking capabilities
/// across subtasks 3a–3g.
///
/// # Adding new variants
///
/// Add the variant here AND a constructor helper in [`TypeError`] (or inline
/// construction in the checker), then expand the test suite in `error/tests.rs`.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeErrorKind {
    /// Two top-level declarations in the same source file share a name.
    ///
    /// Lem does not permit shadowing at the top level — every contract, struct,
    /// enum, function, const, and type alias must have a unique name.
    DuplicateDeclaration {
        /// The duplicated identifier.
        name: String,
    },

    /// An identifier used in a value position does not name any known declaration.
    ///
    /// Examples: `let x = unknown`, `unknown()`.
    /// Note: type-position unknown names → [`TypeErrorKind::UndefinedType`].
    UndefinedName {
        /// The unresolved identifier.
        name: String,
    },

    /// A name used in a type position does not refer to any known type.
    ///
    /// Examples: `let x: Unknown`, `struct Foo { field: NoSuchType }`.
    UndefinedType {
        /// The unresolved type name.
        name: String,
    },

    /// Two types that must agree do not match.
    ///
    /// Examples: `true + 1` (bool vs integer), `cond ? 1u8 : 1u16` (branch types differ).
    TypeMismatch {
        /// The expected type (human-readable, from [`ResolvedType::display_name`]).
        expected: String,
        /// The actual type found.
        found: String,
    },

    /// An operator is applied to a type that does not support it.
    ///
    /// Examples: `!42` (Not on integer), `"a" + "b"` (Add on strings before string
    /// concatenation is introduced).
    InvalidOperand {
        /// The operator name (e.g. `"+"`, `"!"`, `"~"`).
        op: String,
        /// The offending operand type (human-readable).
        ty: String,
    },

    /// An invalid type conversion: `as` used for narrowing instead of `.tryInto()`,
    /// or `as` applied to a non-integer type.
    InvalidConversion {
        /// The source type (human-readable).
        from: String,
        /// The target type (human-readable).
        to: String,
    },

    /// A function call has the wrong number of positional arguments.
    ArityMismatch {
        /// The function name (or `"fn"` for anonymous callees).
        func: String,
        /// The expected maximum number of positional arguments.
        expected: usize,
        /// The number of positional arguments actually provided.
        found: usize,
    },

    /// A struct field access uses a field name that does not exist on the type.
    UnknownField {
        /// The struct type name (human-readable).
        ty: String,
        /// The field name that was not found.
        field: String,
    },

    /// A call target is not callable (not a function type).
    NotCallable {
        /// The type of the callee expression (human-readable).
        ty: String,
    },

    /// An index operation target does not support indexing.
    NotIndexable {
        /// The type of the base expression (human-readable).
        ty: String,
    },

    /// Assignment to a local variable declared without `mut`.
    ///
    /// Example: `let x = 1; x = 2;` — `x` is immutable, use `let mut x`.
    MutationOfImmutable {
        /// The name of the immutable binding being assigned.
        name: String,
    },

    /// A `return` expression type does not match the function's declared return type.
    ///
    /// Example: `fn foo() -> u128 { return true; }` — bool vs u128.
    ReturnTypeMismatch {
        /// The function's declared return type.
        expected: String,
        /// The type of the returned expression.
        found: String,
    },

    /// An `if` or `while` condition expression is not of type `bool`.
    ///
    /// Example: `if 42 { ... }` — integer is not bool.
    ConditionNotBool {
        /// The actual type of the condition expression.
        found: String,
    },

    /// A struct literal omits a required field (one without a default value).
    ///
    /// Example: `Point { x: 1 }` when `Point` has required field `y`.
    MissingField {
        /// The struct type name.
        ty: String,
        /// The field name that was omitted.
        field: String,
    },

    /// A type argument does not satisfy a generic parameter's trait bound.
    ///
    /// Example: `sort<T: Comparable>(arr: Array<T>)` called with `T = bool`
    /// where `bool` does not implement `Comparable`.
    TraitBoundViolation {
        /// The generic parameter name (e.g. `"T"`).
        param: String,
        /// The required trait name (e.g. `"Comparable"`).
        bound: String,
        /// The concrete type that does not satisfy the bound (human-readable).
        found: String,
    },

    /// Wrong number of type arguments for a generic type or function.
    ///
    /// Example: `new Pair<u128>()` when `Pair<A, B>` requires two type args.
    WrongTypeArgCount {
        /// The type or function name.
        name: String,
        /// The expected number of type arguments.
        expected: usize,
        /// The number of type arguments actually provided.
        found: usize,
    },

    /// The `?` (try) operator applied to a non-`Result` expression.
    ///
    /// `?` may only unwrap a `Result<T, E>`.  Applying it to any other type
    /// (e.g. `let x: u128 = 1; x?`) is a type error.
    ///
    /// Example: `let y: u128 = 1; y?` — `u128` is not a `Result`.
    InvalidTry {
        /// The type the `?` operator was applied to (human-readable).
        found: String,
    },
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
