//! Type checker for the Lem language.
//!
//! Entry point: [`check`]. Takes a parsed [`Ast`] and produces a [`TypedAst`]
//! (consumed by the downstream safety analyzer and code generator) or a
//! [`crate::error::LangError::Type`] describing the type violation found.
//!
//! ## Pipeline position
//!
//! ```text
//! tokenize(src) → parse(tokens) → check(ast) → (safety analyzer) → (codegen)
//!                                     ↑
//!                                 this module
//! ```
//!
//! ## Submodule layout
//!
//! - `error`     — [`TypeError`] and [`TypeErrorKind`]
//! - `types`     — [`ResolvedType`] (semantic types) and [`SymbolId`]
//! - `typed_ast` — [`TypedAst`] (the span-keyed typed output)
//!
//! ## Implementation status (P3·Step 3a — foundation)
//!
//! 3a ships the architectural foundation:
//! - Error contract: [`TypeError`] + [`crate::error::LangError::Type`]
//! - Output contract: [`TypedAst`] (the side-table typed AST)
//! - Semantic type model: [`ResolvedType`]
//! - Public entry point: [`check`]
//! - First real check: duplicate top-level declaration names
//!
//! Subsequent subtasks fill in the actual type inference and checking:
//! - 3b: name resolution + symbol tables
//! - 3c: expression typing (literals, operators, conversions)
//! - 3d: calls, member access, index, struct/tuple expressions
//! - 3e: statement checking (let inference, return types, conditions)
//! - 3f: generics + trait bounds
//! - 3g: declaration walk → fully-populated TypedAst
//! - 3h: integration + docs closeout

pub mod error;
pub(crate) mod infer;
pub(crate) mod resolver;
pub mod typed_ast;
pub mod types;

use std::collections::BTreeMap;

use crate::error::LangError;
use crate::lexer::token::Span;
use crate::parser::ast::{Ast, Item};

use self::error::{TypeError, TypeErrorKind};
pub use self::typed_ast::TypedAst;
use self::types::SymbolKind;
pub use self::types::{ResolvedType, SymbolId};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Type-check a parsed Lem AST.
///
/// Walks the [`Ast`] to verify type correctness, resolve names, and annotate
/// every expression with its inferred type.  Returns a [`TypedAst`] on success
/// (consumed by the Step 4 safety analyzer) or `Err(LangError::Type(...))`
/// on the first type violation found.
///
/// ## Current coverage (P3·Step 3e)
///
/// - Duplicate top-level declaration names (3a)
/// - Name resolution — every identifier linked to its declaration (3b)
/// - Expression typing — literals, operators, ternary, nullish (3c)
/// - Calls, member access, index, struct/array/tuple literals (3d)
/// - Statement checking — let inference, return types, mutability,
///   conditions, assignment, if/match/try expressions (3e)
///
/// Deferred to later subtasks:
/// - Generics + trait bounds → 3f
/// - Declaration walk → fully-populated TypedAst → 3g
///
/// # Examples
///
/// ```ignore
/// use lemma_lang::{tokenize, parse, check};
///
/// let tokens = tokenize("contract Foo {}")?;
/// let ast = parse(tokens)?;
/// let typed = check(ast)?;
/// assert_eq!(typed.ast.items.len(), 1);
/// ```
pub fn check(ast: Ast) -> Result<TypedAst, LangError> {
    let mut checker = Checker;
    checker.check_program(ast)
}

// ─── Internal checker ─────────────────────────────────────────────────────────

/// The internal type-checking engine.
///
/// A unit struct in 3a (no state yet); subtasks 3b+ add fields for the
/// symbol table, scope stack, generic environment, etc.
///
/// The receiver is `&mut self` throughout (even in 3a where no mutation
/// occurs) so that adding mutable fields in 3b does not change any call sites.
struct Checker;

impl Checker {
    fn check_program(&mut self, ast: Ast) -> Result<TypedAst, LangError> {
        // Pass 1 (3a): reject duplicate top-level declaration names.
        self.check_no_duplicate_top_level_names(&ast.items)?;

        // Pass 2 (3b/3d): name resolution + SymbolSig building.
        let (mut symbols, resolutions, sigs) = resolver::resolve(&ast)?;

        // Build flat global-type namespace for the Inferer's lower_cast_target.
        // Maps each type-namespace symbol's name to its SymbolId.
        // Collected from cloned strings + computed SymbolIds — no live borrows
        // into `symbols` after this block, so the subsequent `&mut symbols`
        // borrow for the Inferer is safe.
        let global_types: BTreeMap<String, SymbolId> = symbols
            .iter()
            .enumerate()
            .filter(|(_, s)| {
                matches!(
                    s.kind,
                    SymbolKind::Struct
                        | SymbolKind::Enum
                        | SymbolKind::Contract
                        | SymbolKind::TypeAlias
                        | SymbolKind::Interface
                        | SymbolKind::Trait
                )
            })
            .map(|(i, s)| (s.name.clone(), SymbolId((i + 1) as u32)))
            .collect();

        // Pass 3 (3c/3e): expression + statement typing — populates expr_types.
        // `symbols` is passed mutably so the Inferer can back-fill unannotated
        // `let` binding types (DB-A27).
        let mut expr_types = BTreeMap::new();
        {
            let mut inferer = infer::Inferer::new(
                &mut symbols,
                &resolutions,
                &sigs,
                &global_types,
                &mut expr_types,
            );
            inferer.walk_ast(&ast)?;
        }

        Ok(TypedAst::new(ast, expr_types, resolutions, symbols, sigs))
    }

    /// Verify that no two top-level items share a declaration name.
    ///
    /// Lem does not permit shadowing at the top level — every `contract`,
    /// `struct`, `enum`, `fn`, `const`, `type`, and `error` must have a
    /// unique name within the same source file.
    ///
    /// [`Item::Import`] and [`Item::Using`] have no name and are skipped.
    fn check_no_duplicate_top_level_names(&self, items: &[Item]) -> Result<(), LangError> {
        // BTreeMap for deterministic error-reporting order (AGENTS §7.1).
        let mut seen: BTreeMap<&str, Span> = BTreeMap::new();
        for item in items {
            let Some((name, span)) = top_level_name(item) else {
                continue;
            };
            if let Some(&first_span) = seen.get(name) {
                return Err(LangError::Type(TypeError {
                    kind: TypeErrorKind::DuplicateDeclaration {
                        name: name.to_owned(),
                    },
                    span,
                    message: format!(
                        "duplicate top-level declaration: '{name}' was first declared at \
                         line {}, col {}",
                        first_span.line, first_span.col,
                    ),
                }));
            }
            seen.insert(name, span);
        }
        Ok(())
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Extract the declaration name and its span from a top-level item.
///
/// Returns `None` for anonymous items ([`Item::Import`], [`Item::Using`]).
fn top_level_name(item: &Item) -> Option<(&str, Span)> {
    match item {
        Item::Contract(c) => Some((&c.name, c.span)),
        Item::Token_(t) => Some((&t.name, t.span)),
        Item::Interface(i) => Some((&i.name, i.span)),
        Item::Trait(t) => Some((&t.name, t.span)),
        Item::Library(l) => Some((&l.name, l.span)),
        Item::Struct(s) => Some((&s.name, s.span)),
        Item::Enum(e) => Some((&e.name, e.span)),
        Item::Function(f) => Some((&f.name, f.span)),
        Item::Const(c) => Some((&c.name, c.span)),
        Item::TypeAlias(a) => Some((&a.name, a.span)),
        Item::ErrorDecl(e) => Some((&e.name, e.span)),
        Item::Import(_) | Item::Using(_) => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
