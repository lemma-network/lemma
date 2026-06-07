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
    // 3e: MutationOfImmutable { name: String },
    //     ReturnTypeMismatch { func: String, expected: String, found: String },
    //     ConditionNotBool { found: String }
    // 3f: TraitBoundViolation { param: String, bound: String, found: String },
    //     UnresolvedGeneric(String)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
