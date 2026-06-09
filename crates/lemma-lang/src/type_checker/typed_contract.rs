//! Per-contract projection over a [`TypedAst`].
//!
//! [`TypedContract`] is a **borrowed view** — it holds `&TypedAst` plus a
//! reference to one `Item::Contract` or `Item::Token_` from the original AST.
//! Zero-copy: no data is duplicated.
//!
//! ## Downstream contract (09-SAFETY_ANALYZER_SPEC §1)
//!
//! The Step 4 safety analyzer consumes:
//! ```ignore
//! pub fn analyze_safety(contract: &TypedContract) -> Result<(), Vec<SafetyError>>
//! ```
//!
//! `TypedContract` exposes everything §1 requires:
//! - Contract name + `is_token`
//! - `state {}` fields: name, resolved type, `is_immutable`
//! - `config {}` entries for token contracts
//! - All functions (with annotations, param types, return type, body access)
//! - Delegation to the full `TypedAst` for expression-level queries
//!
//! ## What Step 4 builds FROM this (not exposed here)
//! - Call graph / Ext(f) / EffAuth — the analyzer computes these from the AST
//!   + typed data (09-spec §2 "Foundational analyses").
//! - State-effect CFG — Step 5.

use crate::lexer::token::Span;
use crate::parser::ast::Stmt;
use crate::parser::{Annotation, ConfigEntry, ContractMember, Visibility};

use super::typed_ast::TypedAst;
use super::types::{ResolvedType, SymbolId, SymbolInfo, SymbolKind, SymbolSig};

// ─── TypedContract ────────────────────────────────────────────────────────────

/// A per-contract view over a [`TypedAst`].
///
/// Produced by [`TypedAst::contracts`].  Zero-copy — borrows the `TypedAst`
/// and the original AST item.
///
/// Consumed by the Step 4 safety analyzer:
/// `pub fn analyze_safety(contract: &TypedContract) -> Result<(), Vec<SafetyError>>`
///
/// ## What it exposes (09-SAFETY_ANALYZER_SPEC §1)
/// - Contract name + `is_token`
/// - `state {}` fields: name, resolved type, `is_immutable`
/// - `config {}` entries for token contracts
/// - Functions: name, annotations, param types, return type, `is_pub`, body
/// - Access to the full `TypedAst` for expression-level queries
///
/// ## What Step 4 builds FROM this (not exposed here)
/// - Call graph / Ext(f) / EffAuth — analyzer computes these from AST + typed data
/// - State-effect CFG — Step 5
pub struct TypedContract<'a> {
    typed_ast: &'a TypedAst,
    /// Which AST item backs this TypedContract.
    item: ContractItem<'a>,
}

/// Internal: which AST item backs this TypedContract.
pub(super) enum ContractItem<'a> {
    Contract(&'a crate::parser::Contract),
    Token(&'a crate::parser::TokenDecl),
}

impl<'a> TypedContract<'a> {
    /// Construct a new `TypedContract` view.
    ///
    /// Called only by [`TypedAst::contracts`].
    pub(super) fn new(typed_ast: &'a TypedAst, item: ContractItem<'a>) -> Self {
        Self { typed_ast, item }
    }

    /// Contract name.
    #[must_use]
    pub fn name(&self) -> &str {
        match &self.item {
            ContractItem::Contract(c) => &c.name,
            ContractItem::Token(t) => &t.name,
        }
    }

    /// Whether this is a `token` declaration (vs a plain `contract`).
    #[must_use]
    pub fn is_token(&self) -> bool {
        matches!(self.item, ContractItem::Token(_))
    }

    /// Interfaces this contract declares it implements (for plain `contract` declarations).
    ///
    /// Always empty for `token` declarations (use [`is_token`] for those).
    ///
    /// Used by SAFETY-013 and 4f rules to detect `contract Foo implements IToken { ... }`.
    #[must_use]
    pub fn implements(&self) -> &[String] {
        match &self.item {
            ContractItem::Contract(c) => &c.implements,
            ContractItem::Token(_) => &[],
        }
    }

    /// The [`SymbolId`] of this contract in the symbol arena.
    ///
    /// Finds the symbol by matching name + `SymbolKind::Contract`.
    #[must_use]
    pub fn symbol_id(&self) -> Option<SymbolId> {
        let name = self.name();
        self.typed_ast
            .symbols
            .iter()
            .enumerate()
            .find(|(_, s)| s.kind == SymbolKind::Contract && s.name == name)
            .map(|(i, _)| SymbolId((i + 1) as u32))
    }

    /// All `state {}` fields and `immutable` declarations for this contract.
    ///
    /// Returns `(field_name, resolved_type, is_immutable)` tuples in
    /// declaration order.  `is_immutable = true` for `immutable X: T`
    /// declarations; `false` for `state { x: T }` fields.
    #[must_use]
    pub fn state_fields(&self) -> Vec<StateField<'a>> {
        let members = self.members();
        let mut out = Vec::new();
        for member in members {
            match member {
                ContractMember::State(block) => {
                    for field in &block.fields {
                        // Look up the resolved type from the symbol arena.
                        let ty = self
                            .typed_ast
                            .symbols
                            .iter()
                            .find(|s| s.kind == SymbolKind::StateField && s.name == field.name)
                            .map(|s| &s.ty)
                            .unwrap_or(&ResolvedType::Unknown);
                        out.push(StateField {
                            name: &field.name,
                            ty,
                            is_immutable: false,
                        });
                    }
                }
                ContractMember::Immutable(imm) => {
                    let ty = self
                        .typed_ast
                        .symbols
                        .iter()
                        .find(|s| s.kind == SymbolKind::Immutable && s.name == imm.name)
                        .map(|s| &s.ty)
                        .unwrap_or(&ResolvedType::Unknown);
                    out.push(StateField {
                        name: &imm.name,
                        ty,
                        is_immutable: true,
                    });
                }
                _ => {}
            }
        }
        out
    }

    /// Config entries for token contracts (raw `ConfigEntry` access).
    ///
    /// Returns `None` for plain contracts.
    #[must_use]
    pub fn config(&self) -> Option<&[ConfigEntry]> {
        let members = self.members();
        for member in members {
            if let ContractMember::Config(cfg) = member {
                return Some(&cfg.entries);
            }
        }
        None
    }

    /// All functions declared by this contract (including modifiers, receive,
    /// and fallback — but NOT init, which is a regular function named `init`).
    ///
    /// Returns [`ContractFunction`] views in declaration order.
    #[must_use]
    pub fn functions(&self) -> Vec<ContractFunction<'a>> {
        let members = self.members();
        let mut out = Vec::new();
        for member in members {
            if let ContractMember::Function(f) = member {
                let symbol_id = self
                    .typed_ast
                    .symbols
                    .iter()
                    .enumerate()
                    .find(|(_, s)| s.kind == SymbolKind::Function && s.decl_span == f.span)
                    .map(|(i, _)| SymbolId((i + 1) as u32));
                let return_type = symbol_id
                    .and_then(|id| self.typed_ast.sigs.get(&id))
                    .and_then(|sig| {
                        if let SymbolSig::Function(fs) = sig {
                            Some(fs.ret.clone())
                        } else {
                            None
                        }
                    });
                out.push(ContractFunction {
                    name: &f.name,
                    visibility: &f.visibility,
                    annotations: &f.annotations,
                    params: &f.params,
                    return_type,
                    body: f.body.as_deref(),
                    symbol_id,
                });
            }
        }
        out
    }

    /// Look up the resolved type of an expression by span (delegates to TypedAst).
    #[must_use]
    pub fn type_of(&self, span: &Span) -> Option<&ResolvedType> {
        self.typed_ast.type_of(span)
    }

    /// Look up the resolved symbol for an identifier (delegates to TypedAst).
    #[must_use]
    pub fn resolution_of(&self, span: &Span) -> Option<SymbolId> {
        self.typed_ast.resolution_of(span)
    }

    /// Look up a symbol's info (delegates to TypedAst).
    #[must_use]
    pub fn symbol(&self, id: SymbolId) -> Option<&SymbolInfo> {
        self.typed_ast.symbol(id)
    }

    /// Look up a structured signature (delegates to TypedAst).
    #[must_use]
    pub fn sig(&self, id: SymbolId) -> Option<&SymbolSig> {
        self.typed_ast.sig(id)
    }

    /// The underlying TypedAst (for Step 4 analysis needing full access).
    #[must_use]
    pub fn typed_ast(&self) -> &TypedAst {
        self.typed_ast
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Return the contract/token members slice.
    ///
    /// Exposed as `pub(super)` so the `wellformed` sibling module can walk raw
    /// members directly (for WF-001/002 `StateField.default` and `Immutable.span`
    /// access) without duplicating the AST-walk logic in a `contract_members()`
    /// helper. See decisions-log.md DB-A46.
    pub(super) fn members(&self) -> &'a [crate::parser::ContractMember] {
        match &self.item {
            ContractItem::Contract(c) => &c.members,
            ContractItem::Token(t) => &t.members,
        }
    }
}

// ─── StateField ───────────────────────────────────────────────────────────────

/// A state or immutable field as seen by the safety analyzer.
///
/// Produced by [`TypedContract::state_fields`].
pub struct StateField<'a> {
    /// Field name.
    pub name: &'a str,
    /// Resolved type of the field.
    pub ty: &'a ResolvedType,
    /// `true` for `immutable X: T` declarations; `false` for `state { x: T }` fields.
    pub is_immutable: bool,
}

// ─── ContractFunction ─────────────────────────────────────────────────────────

/// A function (or modifier) as seen by the safety analyzer.
///
/// Produced by [`TypedContract::functions`].
pub struct ContractFunction<'a> {
    /// Function name.
    pub name: &'a str,
    /// Visibility of the function (`Pub`, `External`, or `Private`).
    pub visibility: &'a Visibility,
    /// Annotations on this function (e.g. `@onlyOwner`, `@nonReentrant`).
    pub annotations: &'a [Annotation],
    /// Parameters in declaration order.
    pub params: &'a [crate::parser::Param],
    /// Return type.
    ///
    /// - `Some(ResolvedType::Unit)` for functions with no explicit return-type annotation.
    /// - `Some(T)` for functions annotated `-> T`.
    /// - `None` only if the function's symbol could not be resolved in the symbol arena
    ///   (a defensive fallback; should not occur for well-formed programs).
    pub return_type: Option<ResolvedType>,
    /// Function body statements (`None` for interface signatures).
    pub body: Option<&'a [Stmt]>,
    /// The [`SymbolId`] of this function in the symbol arena.
    pub symbol_id: Option<SymbolId>,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
