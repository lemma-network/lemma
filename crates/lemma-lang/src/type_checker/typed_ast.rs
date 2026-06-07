//! The typed AST produced by the Lem type checker.
//!
//! [`TypedAst`] wraps the original untyped [`Ast`] and attaches semantic
//! information as span-keyed side tables.
//!
//! ## Design: span-keyed side tables
//!
//! Rather than duplicating every AST node with a type field (a "typed tree"
//! approach that violates AGENTS §2 DRY by duplicating the entire `Expr`/`Stmt`
//! enum), the checker uses **span-keyed maps**:
//!
//! ```text
//! expr_types:  BTreeMap<Span, ResolvedType>  // span of each Expr → its type
//! resolutions: BTreeMap<Span, SymbolId>      // span of each Ident → its decl
//! ```
//!
//! ## Span-uniqueness invariant
//!
//! The `Span` for each AST node is the **full 4-tuple `(line, col, offset, len)`**
//! derived from the scanner's `span_from_mark`.  Two distinct token positions
//! in the same source file cannot share the same `(offset, len)` because:
//! - A token's `offset` is its byte position in the source string.
//! - Its `len` is the number of bytes it spans.
//! - Non-overlapping tokens at different positions have different `(offset, len)`.
//!
//! As a result, every distinct `Expr` node in a parsed AST has a unique `Span`
//! and can safely serve as a `BTreeMap` key.  The only exception is
//! `Span::at(…)` which produces `len: 0` — this is used only for the EOF
//! token and must **not** be inserted into `expr_types`/`resolutions`.
//!
//! The invariant is verified by `typed_ast/tests.rs::parsed_expression_spans_are_distinct`.
//!
//! `BTreeMap` — not `HashMap` — ensures deterministic iteration order (AGENTS §7.1).
//!
//! ## Downstream contract (Step 4 — Safety Analyzer)
//!
//! `09-SAFETY_ANALYZER_SPEC.md §1` requires `analyze_safety(contract: &TypedContract)`.
//! A fully-populated `TypedAst` **carries all the necessary data**:
//! - `expr_types` covers every `Expr` node span.
//! - `resolutions` maps every identifier span to its `SymbolId`.
//! - The original `Ast` carries `state{}`/`config{}`/annotations.
//!
//! However the **consuming type** the spec names (`TypedContract` — a per-contract
//! projection of these tables) does not yet exist.  Step 3g / Step 4 will add a
//! `TypedContract` view over `TypedAst` once the analyzer's exact per-contract
//! iteration needs are clear.  See `living-notes.md` Technical Debt:
//! "Step 4 needs `TypedContract` projection over `TypedAst`."

use std::collections::BTreeMap;

use crate::lexer::token::Span;
use crate::parser::ast::Ast;

use super::types::{ResolvedType, SymbolId, SymbolInfo};

/// The typed AST returned by [`crate::type_checker::check`].
///
/// Wraps the original `Ast` and attaches type/resolution information
/// as span-keyed side tables (see module-level documentation for rationale).
///
/// Build status per subtask:
/// - **3a**: only `ast` populated; all maps empty.
/// - **3b**: `resolutions` + `symbols` populated (name resolution complete).
/// - **3c–3d**: `expr_types` populated (expression typing complete).
/// - **3g**: fully populated — ready for the Step 4 safety analyzer.
#[derive(Debug, Clone)]
pub struct TypedAst {
    /// The original untyped AST from the parser.
    pub ast: Ast,

    /// Resolved type for each expression span.
    ///
    /// Key: the `Span` carried by the `Expr` node.
    /// Value: the `ResolvedType` the checker inferred or checked for it.
    ///
    /// Populated by expression-typing passes (subtasks 3c–3d).
    pub expr_types: BTreeMap<Span, ResolvedType>,

    /// Resolved symbol for each identifier span.
    ///
    /// Key: the `Span` of an `Expr::Ident` node.
    /// Value: the `SymbolId` of the declaration the identifier refers to.
    ///
    /// Populated by name resolution (subtask 3b).
    pub resolutions: BTreeMap<Span, SymbolId>,

    /// Symbol arena — metadata for every symbol declared in the program.
    ///
    /// Indexed by [`SymbolId`]: `symbol(id)` retrieves the [`SymbolInfo`]
    /// for that ID.  `SymbolId(0)` is the `UNRESOLVED` sentinel and has
    /// no corresponding entry.
    ///
    /// Populated by name resolution (subtask 3b).
    pub symbols: Vec<SymbolInfo>,
}

impl TypedAst {
    /// Construct a [`TypedAst`] from an AST and populated side tables.
    ///
    /// Normally called only by the type checker internals.
    pub fn new(
        ast: Ast,
        expr_types: BTreeMap<Span, ResolvedType>,
        resolutions: BTreeMap<Span, SymbolId>,
        symbols: Vec<SymbolInfo>,
    ) -> Self {
        Self {
            ast,
            expr_types,
            resolutions,
            symbols,
        }
    }

    /// Look up the resolved type for an expression by its source span.
    ///
    /// Returns `None` for expressions not yet annotated (e.g. during
    /// incremental checking) or for non-expression nodes.
    #[must_use]
    pub fn type_of(&self, span: &Span) -> Option<&ResolvedType> {
        self.expr_types.get(span)
    }

    /// Look up the resolved symbol for an identifier by its source span.
    ///
    /// Returns `None` if the identifier has not yet been resolved.
    #[must_use]
    pub fn resolution_of(&self, span: &Span) -> Option<SymbolId> {
        self.resolutions.get(span).copied()
    }

    /// Look up the [`SymbolInfo`] for a [`SymbolId`].
    ///
    /// Returns `None` for [`SymbolId::UNRESOLVED`] or for IDs that do not
    /// correspond to any entry in the symbol arena.
    #[must_use]
    pub fn symbol(&self, id: SymbolId) -> Option<&SymbolInfo> {
        if id.is_unresolved() {
            return None;
        }
        // SymbolId(n) is 1-based; symbols[n-1] is the entry.
        self.symbols.get((id.0 as usize) - 1)
    }

    /// Returns `true` if expression types have been populated (subtask 3c+).
    ///
    /// Returns `false` after 3b (name resolution done, but typing not yet).
    #[must_use]
    pub fn is_fully_typed(&self) -> bool {
        !self.expr_types.is_empty()
    }

    /// Returns `true` if name resolution has been performed (subtask 3b+).
    #[must_use]
    pub fn has_name_resolution(&self) -> bool {
        !self.symbols.is_empty()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
