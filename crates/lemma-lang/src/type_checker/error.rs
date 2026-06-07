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
    // 3b: UndefinedName(String), UndefinedType(String)
    // 3c: TypeMismatch { expected: String, found: String },
    //     InvalidOperandTypes { op: String, lhs: String, rhs: String }
    // 3d: ArityMismatch { func: String, expected: usize, found: usize },
    //     UnknownField { ty: String, field: String }
    // 3e: MutationOfImmutable { name: String },
    //     ReturnTypeMismatch { func: String, expected: String, found: String },
    //     ConditionNotBool { found: String }
    // 3f: TraitBoundViolation { param: String, bound: String, found: String },
    //     UnresolvedGeneric(String)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
