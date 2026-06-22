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

    // ── Well-Formedness variants (WF-001…015, spec §30) ──────────────────────
    // These are emitted by `type_checker::wellformed::check` (P3·Step 4e-bis).
    // The pass runs after the inferer succeeds and before `Ok(TypedAst)` is
    // returned.  All violations are collected before returning (collect-all,
    // never fail-fast) — consistent with the safety analyzer shape.
    /// WF-001 — A `state` field has no default initializer and is not assigned
    /// on every path through `init`.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-001`.
    UninitializedStateField {
        /// The name of the uninitialized state field.
        field: String,
        /// Source location of the field declaration.
        span: Span,
    },

    /// WF-002 — An `immutable` field is not assigned exactly once inside `init`,
    /// or is assigned outside `init`.
    ///
    /// `found_assignments` is 0 (never set) or >1 (set multiple times on some path).
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-002`.
    ImmutableNotSetOnce {
        /// The name of the immutable field.
        field: String,
        /// The number of assignments found (0 = never set; >1 = set multiple times).
        found_assignments: usize,
        /// Source location of the field declaration.
        span: Span,
    },

    /// WF-003 — The `init` constructor is structurally malformed.
    ///
    /// Covers: duplicate `init`, `pub`/`external`/`@onlyOwner` on `init`,
    /// `init` with a return type, token missing `init`.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-003`.
    MalformedInit {
        /// Human-readable description of the structural violation.
        reason: String,
        /// Source location of the offending `init` (or contract if `init` is absent).
        span: Span,
    },

    /// WF-004 — A function with a non-unit return type has a path that falls
    /// off the end without a `return`, `revert`, or infinite `loop {}`.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-004`.
    MissingReturn {
        /// The name of the function missing a return on some path.
        func: String,
        /// Source location of the function declaration.
        span: Span,
    },

    /// WF-005 — A `match` over an enum/bool/Option/Result does not cover all
    /// variants and has no wildcard `_` arm.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-005`.
    NonExhaustiveMatch {
        /// The variant names that are not covered by any arm.
        missing: Vec<String>,
        /// Source location of the `match` expression.
        span: Span,
    },

    /// WF-006 — A `_` placeholder statement appears outside a `modifier` body.
    ///
    /// `_` is only valid as the splice point inside a modifier; a stray `_` in
    /// a regular function has no codegen target.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-006`.
    PlaceholderOutsideModifier {
        /// Source location of the offending `_` statement.
        span: Span,
    },

    /// WF-007 — A `break` or `continue` statement appears outside any
    /// `for`/`while`/`loop` construct.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-007`.
    ControlFlowOutsideLoop {
        /// `"break"` or `"continue"`.
        kind: String,
        /// Source location of the offending statement.
        span: Span,
    },

    /// WF-008 — A contract declares `implements I` but does not provide every
    /// method required by interface `I`.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-008`.
    IncompleteInterface {
        /// The interface name that is not fully implemented.
        interface: String,
        /// The method names that are missing from the contract.
        missing: Vec<String>,
        /// Source location of the `implements` clause.
        span: Span,
    },

    /// WF-009 — A contract declares `uses T` but does not provide every
    /// required method or state field demanded by trait `T`.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-009`.
    IncompleteTrait {
        /// The trait name whose requirements are not fully satisfied.
        trait_name: String,
        /// The method or state-field names that are missing.
        missing: Vec<String>,
        /// Source location of the `uses` clause.
        span: Span,
    },

    /// WF-010 — A contract declares more than one `receive()` or more than one
    /// `fallback()` function.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-010`.
    DuplicateSpecialFunction {
        /// `"receive"` or `"fallback"`.
        kind: String,
        /// Source location of the duplicate declaration.
        span: Span,
    },

    /// WF-011 — A `struct` or `enum` contains itself by value (directly or via
    /// a cycle of by-value fields), producing an infinite-size type.
    ///
    /// Indirection through `Map`/`Array`/`Option` breaks the cycle and is allowed.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-011`.
    RecursiveType {
        /// The name of the type at the root of the cycle.
        type_name: String,
        /// The sequence of type names forming the cycle (e.g. `["A", "B", "A"]`).
        cycle: Vec<String>,
        /// Source location of the type declaration.
        span: Span,
    },

    /// WF-012 — An `emit` statement's fields do not match the declared event schema.
    ///
    /// Covers: unknown event name, missing field, wrong field type, unknown field key.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-012`.
    EmitMismatch {
        /// The event name referenced by the `emit` statement.
        event: String,
        /// Human-readable description of the mismatch.
        reason: String,
        /// Source location of the `emit` statement.
        span: Span,
    },

    /// WF-013 — A `const` initializer expression is not compile-time evaluable.
    ///
    /// Only literals, other `const`s, and pure arithmetic/bitwise/comparison
    /// over them are allowed.  State reads, runtime calls, and `msg`/`block`
    /// references are rejected.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-013`.
    NonConstExpr {
        /// Source location of the non-evaluable sub-expression.
        span: Span,
    },

    /// WF-014 — A token `config {}` block violates the standard's schema.
    ///
    /// Covers: missing mandatory key, wrong value type, unknown key, partial
    /// nested block, declared feature missing its required interface.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-014`.
    InvalidTokenConfig {
        /// Human-readable description of the config violation.
        reason: String,
        /// Source location of the offending config entry (or the `config` block).
        span: Span,
    },

    /// WF-015 — A `pure` or `view` function performs an effect that violates
    /// its declared effect class.
    ///
    /// `pure` must not read/write state or access `msg`/`block`.
    /// `view` must not write state.
    ///
    /// See `docs/03-LANGUAGE_SPEC.md §30 WF-015`.
    EffectViolation {
        /// The name of the function with the mismatched effect class.
        func: String,
        /// The declared effect class (`"pure"` or `"view"`).
        declared: String,
        /// The effect found (`"state read"`, `"state write"`, `"msg access"`, etc.).
        found: String,
        /// Source location of the offending expression or statement.
        span: Span,
    },

    // ── Agent annotation well-formedness variants (WF-016..018) ──────────────
    // These are emitted by `type_checker::wellformed::check_family_e` (P3·Step 12).
    // The pass runs as Family E within the WF pass, after Family D.
    /// WF-016 — `@agentCallable` carries an invalid argument list: missing
    /// `maxValueOut` named argument, non-integer `maxValueOut`, or uses
    /// positional args instead of named.
    ///
    /// `@agentCallable` must carry `maxValueOut: <integer-expr>` — this WF rule
    /// enforces the arg shape before the safety analyzer runs.
    ///
    /// See `docs/09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-014` for the spec requirement.
    InvalidAgentCallableAnnotation {
        /// The function with the malformed annotation.
        func: String,
        /// Human-readable reason (e.g. "missing maxValueOut argument").
        reason: String,
        /// Source location of the offending annotation.
        span: Span,
    },

    /// WF-017 — `@cosignRequired` is placed on an invalid target: must be on a
    /// `pub` or `external` non-init function (not on private functions).
    ///
    /// See `docs/09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-018` and
    /// `docs/14-AGENT_LAYER §2.3.4` for co-sign semantics.
    InvalidCosignPlacement {
        /// The function with the invalid annotation.
        func: String,
        /// Human-readable reason.
        reason: String,
        /// Source location of the offending annotation.
        span: Span,
    },

    /// WF-018 — `@anomalyGuard` is placed on an invalid target: must be on a
    /// function that returns `bool` (it is a predicate), not on void functions,
    /// events, or init.
    ///
    /// See `docs/09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-019` and
    /// `docs/14-AGENT_LAYER §2.3.5` for anomaly-guard semantics.
    InvalidAnomalyGuardPlacement {
        /// The function with the invalid annotation.
        func: String,
        /// Human-readable reason.
        reason: String,
        /// Source location of the offending annotation.
        span: Span,
    },
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
