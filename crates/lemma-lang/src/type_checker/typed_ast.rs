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
use crate::parser::ast::{Ast, Item};

use super::typed_contract::TypedContract;
use super::types::{ResolvedType, SymbolId, SymbolInfo, SymbolSig};

/// The typed AST returned by [`crate::type_checker::check`].
///
/// Wraps the original `Ast` and attaches type/resolution information
/// as span-keyed side tables (see module-level documentation for rationale).
///
/// Build status per subtask:
/// - **3a**: only `ast` populated; all maps empty.
/// - **3b**: `resolutions` + `symbols` populated (name resolution complete).
/// - **3c–3d**: `expr_types` + `sigs` populated (expression typing complete).
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

    /// Structured signatures for functions, structs, and enums.
    ///
    /// Key: [`SymbolId`] of the declaration.
    /// Value: [`SymbolSig`] containing param types, field types, etc.
    ///
    /// Populated by the resolver and inference passes (subtasks 3b/3d+).
    pub sigs: BTreeMap<SymbolId, SymbolSig>,

    /// Maps struct/contract/enum [`SymbolId`] → declared interface + trait names.
    ///
    /// Populated by the resolver from `Contract.implements` + `Contract.uses`.
    /// Structs and enums get an empty vec (they don't implement interfaces in Lem).
    pub struct_traits: BTreeMap<SymbolId, Vec<String>>,

    /// Maps trait [`SymbolId`] → required method names (P3-checker-8).
    ///
    /// Populated by the resolver from `Item::Trait` member functions.  Enables
    /// structural trait-bound checking in [`check_trait_bounds`]: verifying the
    /// concrete type actually has all methods the trait requires, not just that
    /// the type name-declares it implements the trait.
    pub trait_methods: BTreeMap<SymbolId, Vec<String>>,

    /// Maps contract/token [`SymbolId`] → declared function names (P3-checker-8).
    ///
    /// Populated by the resolver from contract/token function members.
    /// Contracts do not get a `SymbolSig::Struct` entry (unlike struct types),
    /// so this table is used by `check_trait_bounds` to verify structural
    /// method presence for contract types that declare `implements Trait`.
    pub contract_methods: BTreeMap<SymbolId, Vec<String>>,

    /// Maps interface [`SymbolId`] → required method names (WF-008/009).
    ///
    /// Populated by the resolver from `Item::Interface` member functions.
    /// Enables WF-008/009 to verify that a contract declaring
    /// `implements InterfaceName` actually provides all methods the interface
    /// requires (structural check, not just name-level).
    ///
    /// `BTreeMap` — not `HashMap` — for deterministic iteration order (AGENTS §7.1).
    pub interface_methods: BTreeMap<SymbolId, Vec<String>>,

    /// Maps event name → ordered `(field_name, resolved_type)` pairs (WF-012).
    ///
    /// Populated by the resolver from `ContractMember::Event` and
    /// `InterfaceMember::Event` declarations.  Enables WF-012 to validate
    /// `emit Foo { field: val }` against the declared event schema.
    ///
    /// Events are registered as `SymbolKind::Struct` (opaque) in the symbol
    /// arena; this table provides the field-level detail needed for emit
    /// validation without duplicating the struct-sig machinery.
    ///
    /// Keyed by event name (`String`) rather than `SymbolId` because emit
    /// statements reference events by name, not by resolved ID.
    ///
    /// `BTreeMap` — not `HashMap` — for deterministic iteration order (AGENTS §7.1).
    pub event_field_sigs: BTreeMap<String, Vec<(String, ResolvedType)>>,
}

impl TypedAst {
    /// Construct a [`TypedAst`] from an AST and populated side tables.
    ///
    /// Normally called only by the type checker internals.
    // Justified: TypedAst holds 9 distinct side-tables each with a separate
    // semantic role (expr types, resolutions, symbol arena, sigs, struct/trait/
    // contract metadata, interface methods, event field sigs).  All are produced
    // by different resolver/inference passes and cannot meaningfully be merged.
    // Called from one site only.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ast: Ast,
        expr_types: BTreeMap<Span, ResolvedType>,
        resolutions: BTreeMap<Span, SymbolId>,
        symbols: Vec<SymbolInfo>,
        sigs: BTreeMap<SymbolId, SymbolSig>,
        struct_traits: BTreeMap<SymbolId, Vec<String>>,
        trait_methods: BTreeMap<SymbolId, Vec<String>>,
        contract_methods: BTreeMap<SymbolId, Vec<String>>,
        interface_methods: BTreeMap<SymbolId, Vec<String>>,
        event_field_sigs: BTreeMap<String, Vec<(String, ResolvedType)>>,
    ) -> Self {
        Self {
            ast,
            expr_types,
            resolutions,
            symbols,
            sigs,
            struct_traits,
            trait_methods,
            contract_methods,
            interface_methods,
            event_field_sigs,
        }
    }

    /// Look up the declared interface + trait names for a struct/contract/enum.
    ///
    /// Returns `None` if the symbol has no entry (e.g. primitives, generics).
    /// Returns `Some(&[])` for structs and enums (which have no traits in Lem).
    #[must_use]
    pub fn traits_of(&self, id: SymbolId) -> Option<&[String]> {
        self.struct_traits.get(&id).map(Vec::as_slice)
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

    /// Look up the structured signature for a symbol by its [`SymbolId`].
    ///
    /// Returns `None` if no signature has been recorded for this symbol
    /// (e.g. imported symbols, or symbols whose sig is deferred to 3g).
    #[must_use]
    pub fn sig(&self, id: SymbolId) -> Option<&SymbolSig> {
        self.sigs.get(&id)
    }

    /// Look up the required method names for an interface by its [`SymbolId`].
    ///
    /// Returns `None` if the symbol has no entry (e.g. not an interface).
    /// Returns `Some(&[])` for interfaces with no function members.
    ///
    /// Consumed by WF-008/009 to verify that a contract declaring
    /// `implements InterfaceName` actually provides all required methods.
    #[must_use]
    pub fn interface_methods(&self, id: SymbolId) -> Option<&[String]> {
        self.interface_methods.get(&id).map(Vec::as_slice)
    }

    /// Look up the declared field signatures for an event by its name.
    ///
    /// Returns `None` if no event with this name was declared.
    /// Returns `Some(&[])` for events with no fields.
    ///
    /// Consumed by WF-012 to validate `emit Foo { field: val }` against the
    /// declared event schema.
    #[must_use]
    pub fn event_field_sigs(&self, event_name: &str) -> Option<&[(String, ResolvedType)]> {
        self.event_field_sigs.get(event_name).map(Vec::as_slice)
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

    /// Iterate over all contracts and tokens in the program, each as a borrowed
    /// [`TypedContract`] view.
    ///
    /// Produced by 3g (P3-checker-1).  Consumed by the Step 4 safety analyzer:
    /// `pub fn analyze_safety(contract: &TypedContract) -> Result<(), Vec<SafetyError>>`
    ///
    /// Skips non-contract items (structs, enums, functions, etc.).
    #[must_use]
    pub fn contracts(&self) -> Vec<TypedContract<'_>> {
        use super::typed_contract::ContractItem;
        self.ast
            .items
            .iter()
            .filter_map(|item| match item {
                Item::Contract(c) => Some(TypedContract::new(self, ContractItem::Contract(c))),
                Item::Token_(t) => Some(TypedContract::new(self, ContractItem::Token(t))),
                _ => None,
            })
            .collect()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
