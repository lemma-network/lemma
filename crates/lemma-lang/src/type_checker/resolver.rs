//! Name resolution for the Lem type checker.
//!
//! The [`Resolver`] walks a parsed [`Ast`] and:
//! - Builds a **symbol arena** (`Vec<SymbolInfo>`) — one entry per declaration.
//! - Fills a **resolution map** (`BTreeMap<Span, SymbolId>`) — every
//!   `Expr::Ident` span that successfully resolves gets an entry.
//! - Emits [`TypeErrorKind::UndefinedName`] / [`TypeErrorKind::UndefinedType`]
//!   for unresolvable references.
//! - Emits [`TypeErrorKind::DuplicateDeclaration`] for same-name members
//!   within a single scope level (contract body, local block).
//!
//! ## Scope rules
//!
//! - **Two namespaces**: *value* (params, locals, consts, state fields, fns)
//!   and *type* (structs, enums, aliases, interfaces, traits, generic params).
//! - **Shadowing**: allowed in nested scopes — an inner `let x` may shadow
//!   an outer binding.  Duplicate bindings at the *same* scope level are
//!   rejected (no overloading; Lem aligns with Move/Vyper/Rust on this).
//! - **Walk order**: global scope (all top-level items + imports) → per item
//!   body: generic params (type scope) → params/state (value scope) → blocks.
//! - **`self`**: a synthetic [`SymbolKind::SelfBinding`] is registered in
//!   the value scope of every contract/trait method body.
//!
//! ## Imports
//!
//! Imported names are registered as [`SymbolKind::Imported`] (opaque) in
//! both namespaces so downstream uses don't false-error.  Actual contents
//! are resolved when the standard library is available (P3·Step 8).
//!
//! ## Deferred
//!
//! - Member-field resolution (`self.field`) — needs the receiver's type (3d).
//! - Generic bound checking (`<T: Comparable>`) — 3f.
//! - Overload selection — removed by design; see `decisions-log.md` DB-A26.

use std::collections::BTreeMap;

use crate::error::LangError;
use crate::lexer::token::Span;
use crate::parser::ast::{
    Ast, ContractMember, Expr, ForIter, Function, GenericParam, Item, LambdaBody, MatchArm,
    MatchBody, Pattern, Stmt, StructMember, TemplateExprSegment, Type,
};

use super::error::{TypeError, TypeErrorKind};
use super::types::{
    EnumSig, FnSig, ResolvedType, StructSig, SymbolId, SymbolInfo, SymbolKind, SymbolSig,
};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Output of the name-resolution pass.
///
/// `(symbols, resolutions, sigs)`:
/// - `symbols`     — the symbol arena (`SymbolId(n)` → `symbols[n-1]`)
/// - `resolutions` — span → SymbolId map for every resolved identifier
/// - `sigs`        — structured signatures for functions, structs, and enums
pub(super) type ResolveOutput = (
    Vec<SymbolInfo>,
    BTreeMap<Span, SymbolId>,
    BTreeMap<SymbolId, SymbolSig>,
);

/// Run name resolution over a parsed AST.
///
/// Returns the **symbol arena**, **resolution map**, and **symbol signatures**
/// on success, or the first [`LangError::Type`] encountered on failure.
pub(super) fn resolve(ast: &Ast) -> Result<ResolveOutput, LangError> {
    let mut r = Resolver::new();
    r.build_global_scope(ast)?;
    for item in &ast.items {
        r.resolve_item(item)?;
    }
    Ok((r.symbols, r.resolutions, r.sigs))
}

// ─── Resolver internals ───────────────────────────────────────────────────────

struct Resolver {
    /// Symbol arena — `SymbolId(n)` → `symbols[n-1]`.
    symbols: Vec<SymbolInfo>,
    /// Span → SymbolId resolution map (the output).
    resolutions: BTreeMap<Span, SymbolId>,
    /// SymbolId → SymbolSig map (the output).
    sigs: BTreeMap<SymbolId, SymbolSig>,
    /// Stack of value-namespace scopes (params, locals, fns, state fields).
    value_scopes: Vec<BTreeMap<String, SymbolId>>,
    /// Stack of type-namespace scopes (structs, enums, generics, etc.).
    type_scopes: Vec<BTreeMap<String, SymbolId>>,
    /// Whether we are currently inside a method body (enabling `self`).
    in_method: bool,
}

impl Resolver {
    fn new() -> Self {
        Self {
            symbols: Vec::new(),
            resolutions: BTreeMap::new(),
            sigs: BTreeMap::new(),
            value_scopes: Vec::new(),
            type_scopes: Vec::new(),
            in_method: false,
        }
    }

    // ── Symbol allocation ─────────────────────────────────────────────────

    /// Allocate a symbol with an explicit resolved type.
    ///
    /// Used for value-namespace symbols (params, locals, consts, state fields)
    /// whose declared type is available at allocation time.  Pass
    /// [`ResolvedType::Unknown`] for type-namespace symbols and for value
    /// symbols whose type is deferred (e.g. function return types in 3g).
    fn alloc_typed(
        &mut self,
        name: impl Into<String>,
        decl_span: Span,
        kind: SymbolKind,
        ty: ResolvedType,
    ) -> SymbolId {
        let id = SymbolId((self.symbols.len() + 1) as u32);
        self.symbols.push(SymbolInfo {
            name: name.into(),
            decl_span,
            kind,
            ty,
        });
        id
    }

    /// Allocate a symbol with [`ResolvedType::Unknown`] (type-namespace symbols
    /// and value symbols deferred to a later subtask).
    fn alloc(&mut self, name: impl Into<String>, decl_span: Span, kind: SymbolKind) -> SymbolId {
        self.alloc_typed(name, decl_span, kind, ResolvedType::Unknown)
    }

    /// Retroactively set the resolved type on an already-allocated symbol.
    ///
    /// Used to set `Function` ty = `Fn(params, ret)` after all param types
    /// are known (i.e. after the type scope is live in `resolve_function_body`).
    fn set_sym_ty(&mut self, id: SymbolId, ty: ResolvedType) {
        if let Some(info) = self.symbols.get_mut((id.0 as usize).saturating_sub(1)) {
            info.ty = ty;
        }
    }

    // ── Type lowering ─────────────────────────────────────────────────────

    /// Lower a syntactic [`Type`] to a [`ResolvedType`] using the current
    /// type-namespace scope stack.
    ///
    /// For primitive and compound types this is a mechanical 1-to-1 mapping.
    /// For [`Type::Named`], the name is looked up in the current type scope:
    /// - Generic params (`SymbolKind::GenericParam`) → `TypeParam(name)`.
    /// - All other named declarations → `Named(SymbolId, lowered_args)`.
    /// - Unknown names (imports and defensive fallback) → `Unknown`.
    ///
    /// The special placeholder `_` (un-annotated lambda params from the parser)
    /// maps to `Unknown` — its type is inferred by the expression typer in 3c.
    ///
    /// This is an exhaustive in-crate `match` (no `_` arm) so the compiler
    /// enforces that new `Type` variants added to the parser are handled here.
    fn lower_type(&self, ty: &Type) -> ResolvedType {
        match ty {
            Type::U8 => ResolvedType::U8,
            Type::U16 => ResolvedType::U16,
            Type::U32 => ResolvedType::U32,
            Type::U64 => ResolvedType::U64,
            Type::U128 => ResolvedType::U128,
            Type::U256 => ResolvedType::U256,
            Type::I8 => ResolvedType::I8,
            Type::I16 => ResolvedType::I16,
            Type::I32 => ResolvedType::I32,
            Type::I64 => ResolvedType::I64,
            Type::I128 => ResolvedType::I128,
            Type::I256 => ResolvedType::I256,
            Type::Bool => ResolvedType::Bool,
            Type::StringTy => ResolvedType::StringTy,
            Type::CharTy => ResolvedType::CharTy,
            Type::AddressTy => ResolvedType::AddressTy,
            Type::HashTy => ResolvedType::HashTy,
            Type::Bytes => ResolvedType::Bytes,
            Type::BytesN(n) => ResolvedType::BytesN(*n),
            Type::Decimal(n) => ResolvedType::Decimal(*n),
            Type::Array(inner) => ResolvedType::Array(Box::new(self.lower_type(inner))),
            Type::FixedArray(inner, n) => {
                ResolvedType::FixedArray(Box::new(self.lower_type(inner)), *n)
            }
            Type::Map(k, v) => {
                ResolvedType::Map(Box::new(self.lower_type(k)), Box::new(self.lower_type(v)))
            }
            Type::FastMap(k, v) => {
                ResolvedType::FastMap(Box::new(self.lower_type(k)), Box::new(self.lower_type(v)))
            }
            Type::Set(inner) => ResolvedType::Set(Box::new(self.lower_type(inner))),
            Type::Option_(inner) => ResolvedType::Option_(Box::new(self.lower_type(inner))),
            Type::Result_(ok, err) => ResolvedType::Result_(
                Box::new(self.lower_type(ok)),
                Box::new(self.lower_type(err)),
            ),
            Type::Tuple(elems) => {
                ResolvedType::Tuple(elems.iter().map(|e| self.lower_type(e)).collect())
            }
            Type::Fn(params, ret) => ResolvedType::Fn(
                params.iter().map(|p| self.lower_type(p)).collect(),
                Box::new(self.lower_type(ret)),
            ),
            Type::Named(name, args) => {
                // `_` is the parser's inferred-type placeholder for untyped
                // lambda params.  It is NOT a user type — inferred in 3c.
                if name == "_" {
                    return ResolvedType::Unknown;
                }
                let lowered_args: Vec<_> = args.iter().map(|a| self.lower_type(a)).collect();
                match self.lookup_type(name) {
                    Some(id) => {
                        // Generic params keep their name for 3f instantiation.
                        let is_generic = self
                            .symbols
                            .get((id.0 as usize).saturating_sub(1))
                            .is_some_and(|info| info.kind == SymbolKind::GenericParam);
                        if is_generic {
                            ResolvedType::TypeParam(name.clone())
                        } else {
                            ResolvedType::Named(id, lowered_args)
                        }
                    }
                    // Import or not-yet-visible name: defensive fallback.
                    // The resolver validates names separately via resolve_type_ref
                    // so UndefinedType errors are caught there regardless.
                    // Reaching here means either:
                    //   (a) import (opaque, resolved at P3·Step 8), or
                    //   (b) out-of-order forward reference — e.g. a top-level
                    //       Const annotation referencing a Struct declared later
                    //       in the same file.  The global-scope build processes
                    //       items sequentially, so the type isn't in scope yet
                    //       when lower_type runs for the Const.
                    // TODO(3g): two-phase type lowering — after all declarations
                    // are resolved, re-lower any Unknown `SymbolInfo.ty` entries
                    // that suffered forward-reference miss.  Tracked in
                    // living-notes Technical Debt as P3-checker-3.
                    None => ResolvedType::Unknown,
                }
            }
        }
    }

    // ── Scope management ──────────────────────────────────────────────────

    fn push_value_scope(&mut self) {
        self.value_scopes.push(BTreeMap::new());
    }

    fn pop_value_scope(&mut self) {
        self.value_scopes.pop();
    }

    fn push_type_scope(&mut self) {
        self.type_scopes.push(BTreeMap::new());
    }

    fn pop_type_scope(&mut self) {
        self.type_scopes.pop();
    }

    /// Define a name in the current (innermost) value scope.
    ///
    /// Returns the *existing* SymbolId if the name is already defined at this
    /// exact scope level (duplicate — caller decides whether to error).
    fn define_value(&mut self, name: &str, id: SymbolId) -> Option<SymbolId> {
        self.value_scopes.last_mut()?.insert(name.to_owned(), id)
    }

    /// Define a name in the current (innermost) type scope.
    fn define_type(&mut self, name: &str, id: SymbolId) -> Option<SymbolId> {
        self.type_scopes.last_mut()?.insert(name.to_owned(), id)
    }

    /// Look up a name in the value scopes (inner→outer).
    fn lookup_value(&self, name: &str) -> Option<SymbolId> {
        for scope in self.value_scopes.iter().rev() {
            if let Some(&id) = scope.get(name) {
                return Some(id);
            }
        }
        None
    }

    /// Look up a name in the type scopes (inner→outer).
    fn lookup_type(&self, name: &str) -> Option<SymbolId> {
        for scope in self.type_scopes.iter().rev() {
            if let Some(&id) = scope.get(name) {
                return Some(id);
            }
        }
        None
    }

    // ── Duplicate-definition guard ────────────────────────────────────────

    /// Define a name in the value scope, returning an error if already defined
    /// at this scope level (no overloading — AGENTS §1 Rule 1 + DB-A26).
    fn define_value_or_err(
        &mut self,
        name: &str,
        id: SymbolId,
        span: Span,
    ) -> Result<(), LangError> {
        if self.define_value(name, id).is_some() {
            return Err(self.dup_err(name, span));
        }
        Ok(())
    }

    fn define_type_or_err(
        &mut self,
        name: &str,
        id: SymbolId,
        span: Span,
    ) -> Result<(), LangError> {
        if self.define_type(name, id).is_some() {
            return Err(self.dup_err(name, span));
        }
        Ok(())
    }

    fn dup_err(&self, name: &str, span: Span) -> LangError {
        LangError::Type(TypeError {
            kind: TypeErrorKind::DuplicateDeclaration {
                name: name.to_owned(),
            },
            span,
            message: format!("duplicate declaration: '{name}'"),
        })
    }

    // ── Error helpers ─────────────────────────────────────────────────────

    fn undef_name_err(&self, name: &str, span: Span) -> LangError {
        LangError::Type(TypeError {
            kind: TypeErrorKind::UndefinedName {
                name: name.to_owned(),
            },
            span,
            message: format!("undefined name: '{name}'"),
        })
    }

    fn undef_type_err(&self, name: &str, span: Span) -> LangError {
        LangError::Type(TypeError {
            kind: TypeErrorKind::UndefinedType {
                name: name.to_owned(),
            },
            span,
            message: format!("undefined type: '{name}'"),
        })
    }

    // ─────────────────────────────────────────────────────────────────────
    // Global scope
    // ─────────────────────────────────────────────────────────────────────

    /// Build the global (file-level) scope from all top-level items.
    ///
    /// Registered first so forward references within the file work
    /// (e.g. a function calling another function defined later).
    fn build_global_scope(&mut self, ast: &Ast) -> Result<(), LangError> {
        self.push_value_scope();
        self.push_type_scope();

        for item in &ast.items {
            match item {
                Item::Contract(c) => {
                    let id = self.alloc(&c.name, c.span, SymbolKind::Contract);
                    self.define_type_or_err(&c.name, id, c.span)?;
                }
                Item::Token_(t) => {
                    let id = self.alloc(&t.name, t.span, SymbolKind::Contract);
                    self.define_type_or_err(&t.name, id, t.span)?;
                }
                Item::Interface(i) => {
                    let id = self.alloc(&i.name, i.span, SymbolKind::Interface);
                    self.define_type_or_err(&i.name, id, i.span)?;
                }
                Item::Trait(t) => {
                    let id = self.alloc(&t.name, t.span, SymbolKind::Trait);
                    self.define_type_or_err(&t.name, id, t.span)?;
                }
                Item::Library(l) => {
                    let id = self.alloc(&l.name, l.span, SymbolKind::Library);
                    self.define_type_or_err(&l.name, id, l.span)?;
                }
                Item::Struct(s) => {
                    let id = self.alloc(&s.name, s.span, SymbolKind::Struct);
                    self.define_type_or_err(&s.name, id, s.span)?;
                }
                Item::Enum(e) => {
                    let id = self.alloc(&e.name, e.span, SymbolKind::Enum);
                    self.define_type_or_err(&e.name, id, e.span)?;
                }
                Item::ErrorDecl(e) => {
                    let id = self.alloc(&e.name, e.span, SymbolKind::ErrorDecl);
                    self.define_type_or_err(&e.name, id, e.span)?;
                }
                Item::Function(f) => {
                    let id = self.alloc(&f.name, f.span, SymbolKind::Function);
                    self.define_value_or_err(&f.name, id, f.span)?;
                }
                Item::Const(c) => {
                    // Lower the const type; primitives always resolve immediately.
                    // User-defined type references in a const annotation that appear
                    // before the type declaration get Unknown (deferred to 3g).
                    let ty = self.lower_type(&c.ty);
                    let id = self.alloc_typed(&c.name, c.span, SymbolKind::Const, ty);
                    self.define_value_or_err(&c.name, id, c.span)?;
                }
                Item::TypeAlias(a) => {
                    let id = self.alloc(&a.name, a.span, SymbolKind::TypeAlias);
                    self.define_type_or_err(&a.name, id, a.span)?;
                }
                Item::Import(import) => {
                    self.register_import(import)?;
                }
                Item::Using(_) => {
                    // `using Library for Type` — no new name bindings in 3b.
                }
            }
        }
        Ok(())
    }

    fn register_import(&mut self, import: &crate::parser::ast::Import) -> Result<(), LangError> {
        let names: Vec<&str> = match &import.names {
            crate::parser::ast::ImportNames::Named(v) => v.iter().map(String::as_str).collect(),
            crate::parser::ast::ImportNames::Star(alias) => vec![alias.as_str()],
        };
        for name in names {
            // Register as opaque Imported symbols in BOTH namespaces so that
            // any use of an imported name doesn't false-error in 3b.
            // Real resolution happens at P3·Step 8 (stdlib).
            let id_val = self.alloc(name, import.span, SymbolKind::Imported);
            // Ignore duplicates here — the same name might be imported by
            // multiple `import` statements; first wins.
            let _ = self.define_value(name, id_val);
            let id_ty = self.alloc(name, import.span, SymbolKind::Imported);
            let _ = self.define_type(name, id_ty);
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Item resolution
    // ─────────────────────────────────────────────────────────────────────

    fn resolve_item(&mut self, item: &Item) -> Result<(), LangError> {
        match item {
            Item::Contract(c) => {
                self.resolve_contract_body(&c.members, c.span)?;
            }
            Item::Token_(t) => {
                self.resolve_contract_body(&t.members, t.span)?;
            }
            Item::Struct(s) => {
                self.push_type_scope();
                for gp in &s.generic_params {
                    self.register_generic_param(gp)?;
                }
                for member in &s.members {
                    if let StructMember::Method(f) = member {
                        self.resolve_function_body(f)?;
                    }
                }
                // Build StructSig — generic params are in scope so lower_type resolves correctly.
                // Struct methods are NOT in any value scope here (they're not in global scope),
                // so methods list is empty for 3d; deferred to 3g.
                let fields: Vec<(String, ResolvedType)> = s
                    .members
                    .iter()
                    .filter_map(|m| {
                        if let StructMember::Field(f) = m {
                            Some((f.name.clone(), self.lower_type(&f.ty)))
                        } else {
                            None
                        }
                    })
                    .collect();
                if let Some(struct_id) = self.lookup_type(&s.name) {
                    self.sigs.insert(
                        struct_id,
                        SymbolSig::Struct(StructSig {
                            fields,
                            methods: Vec::new(), // TODO(3g): populate struct method SymbolIds
                        }),
                    );
                }
                self.pop_type_scope();
            }
            Item::Enum(e) => {
                self.push_type_scope();
                for gp in &e.generic_params {
                    self.register_generic_param(gp)?;
                }
                for method in &e.methods {
                    self.resolve_function_body(method)?;
                }
                // Build EnumSig — generic params are in scope so lower_type resolves correctly.
                let variants: Vec<(String, Vec<(String, ResolvedType)>)> = e
                    .variants
                    .iter()
                    .map(|v| {
                        let fields: Vec<(String, ResolvedType)> = v
                            .fields
                            .iter()
                            .map(|f| (f.name.clone(), self.lower_type(&f.ty)))
                            .collect();
                        (v.name.clone(), fields)
                    })
                    .collect();
                if let Some(enum_id) = self.lookup_type(&e.name) {
                    self.sigs
                        .insert(enum_id, SymbolSig::Enum(EnumSig { variants }));
                }
                self.pop_type_scope();
            }
            Item::Function(f) => {
                self.resolve_function_body(f)?;
            }
            Item::Const(c) => {
                self.resolve_type_ref(&c.ty, c.span)?;
                self.resolve_expr(&c.value)?;
            }
            Item::TypeAlias(a) => {
                self.resolve_type_ref(&a.ty, a.span)?;
            }
            // Interface / Trait / Library: register signatures only in 3b.
            // Full body resolution for these is deferred to 3g.
            Item::Interface(_) | Item::Trait(_) | Item::Library(_) => {}
            Item::Import(_) | Item::Using(_) | Item::ErrorDecl(_) => {}
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Contract body
    // ─────────────────────────────────────────────────────────────────────

    fn resolve_contract_body(
        &mut self,
        members: &[ContractMember],
        contract_span: Span,
    ) -> Result<(), LangError> {
        // Pass 1 — register all member names into the contract scope so
        // forward references within the contract work (fn A calls fn B
        // defined later in the same body).
        self.push_value_scope();
        self.push_type_scope();

        // Register synthetic `self` binding.
        // `self` is lexed as Token::SelfKw (lexer/scanner/keywords.rs:159), so
        // a Lem source field literally named "self" cannot parse — it would not
        // produce Token::Identifier in parse_state_block's expect_identifier.
        // Therefore this binding cannot collide with any user-defined member.
        let self_id = self.alloc("self", contract_span, SymbolKind::SelfBinding);
        self.define_value("self", self_id);

        for member in members {
            self.register_contract_member(member)?;
        }

        // Pass 2 — resolve bodies.
        let prev_in_method = self.in_method;
        self.in_method = true;
        for member in members {
            self.resolve_contract_member(member)?;
        }
        self.in_method = prev_in_method;

        self.pop_type_scope();
        self.pop_value_scope();
        Ok(())
    }

    fn register_contract_member(&mut self, member: &ContractMember) -> Result<(), LangError> {
        match member {
            ContractMember::State(s) => {
                for field in &s.fields {
                    let ty = self.lower_type(&field.ty);
                    let id = self.alloc_typed(&field.name, field.span, SymbolKind::StateField, ty);
                    self.define_value_or_err(&field.name, id, field.span)?;
                }
            }
            ContractMember::Const(c) => {
                let ty = self.lower_type(&c.ty);
                let id = self.alloc_typed(&c.name, c.span, SymbolKind::Const, ty);
                self.define_value_or_err(&c.name, id, c.span)?;
            }
            ContractMember::Immutable(i) => {
                let ty = self.lower_type(&i.ty);
                let id = self.alloc_typed(&i.name, i.span, SymbolKind::Immutable, ty);
                self.define_value_or_err(&i.name, id, i.span)?;
            }
            ContractMember::Function(f) => {
                let id = self.alloc(&f.name, f.span, SymbolKind::Function);
                self.define_value_or_err(&f.name, id, f.span)?;
            }
            ContractMember::Modifier(m) => {
                let id = self.alloc(&m.name, m.span, SymbolKind::Function);
                self.define_value_or_err(&m.name, id, m.span)?;
            }
            ContractMember::Struct(s) => {
                let id = self.alloc(&s.name, s.span, SymbolKind::Struct);
                self.define_type_or_err(&s.name, id, s.span)?;
            }
            ContractMember::Enum(e) => {
                let id = self.alloc(&e.name, e.span, SymbolKind::Enum);
                self.define_type_or_err(&e.name, id, e.span)?;
            }
            ContractMember::Event(e) => {
                let id = self.alloc(&e.name, e.span, SymbolKind::Struct);
                self.define_type_or_err(&e.name, id, e.span)?;
            }
            ContractMember::ErrorDecl(e) => {
                let id = self.alloc(&e.name, e.span, SymbolKind::ErrorDecl);
                self.define_type_or_err(&e.name, id, e.span)?;
            }
            // Config / Metadata / Receive / Fallback — no named bindings.
            ContractMember::Config(_)
            | ContractMember::Metadata(_)
            | ContractMember::Receive(_)
            | ContractMember::Fallback(_) => {}
        }
        Ok(())
    }

    fn resolve_contract_member(&mut self, member: &ContractMember) -> Result<(), LangError> {
        match member {
            ContractMember::State(s) => {
                for field in &s.fields {
                    self.resolve_type_ref(&field.ty, field.span)?;
                    if let Some(default) = &field.default {
                        self.resolve_expr(default)?;
                    }
                }
            }
            ContractMember::Const(c) => {
                self.resolve_type_ref(&c.ty, c.span)?;
                self.resolve_expr(&c.value)?;
            }
            ContractMember::Immutable(i) => {
                self.resolve_type_ref(&i.ty, i.span)?;
            }
            ContractMember::Function(f) => {
                self.resolve_function_body(f)?;
            }
            ContractMember::Modifier(m) => {
                self.push_value_scope();
                for p in &m.params {
                    let ty = self.lower_type(&p.ty);
                    let id = self.alloc_typed(&p.name, p.span, SymbolKind::Param, ty);
                    let _ = self.define_value(&p.name, id);
                    self.resolve_type_ref(&p.ty, p.span)?;
                }
                for stmt in &m.body {
                    self.resolve_stmt(stmt)?;
                }
                self.pop_value_scope();
            }
            ContractMember::Receive(r) => {
                self.push_value_scope();
                for stmt in &r.body {
                    self.resolve_stmt(stmt)?;
                }
                self.pop_value_scope();
            }
            ContractMember::Fallback(f) => {
                self.push_value_scope();
                for stmt in &f.body {
                    self.resolve_stmt(stmt)?;
                }
                self.pop_value_scope();
            }
            ContractMember::Struct(s) => {
                self.push_type_scope();
                for gp in &s.generic_params {
                    self.register_generic_param(gp)?;
                }
                for member in &s.members {
                    if let StructMember::Method(method) = member {
                        self.resolve_function_body(method)?;
                    }
                }
                // Build StructSig for contract-nested struct.
                let fields: Vec<(String, ResolvedType)> = s
                    .members
                    .iter()
                    .filter_map(|m| {
                        if let StructMember::Field(f) = m {
                            Some((f.name.clone(), self.lower_type(&f.ty)))
                        } else {
                            None
                        }
                    })
                    .collect();
                if let Some(struct_id) = self.lookup_type(&s.name) {
                    self.sigs.insert(
                        struct_id,
                        SymbolSig::Struct(StructSig {
                            fields,
                            methods: Vec::new(), // TODO(3g): populate struct method SymbolIds
                        }),
                    );
                }
                self.pop_type_scope();
            }
            ContractMember::Event(_)
            | ContractMember::Enum(_)
            | ContractMember::ErrorDecl(_)
            | ContractMember::Config(_)
            | ContractMember::Metadata(_) => {}
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Function body
    // ─────────────────────────────────────────────────────────────────────

    fn resolve_function_body(&mut self, f: &Function) -> Result<(), LangError> {
        // Generic params introduce type-name bindings (e.g. `T`).
        self.push_type_scope();
        for gp in &f.generic_params {
            self.register_generic_param(gp)?;
        }

        // Compute FnSig — type scopes are live so lower_type resolves correctly.
        // The function's SymbolId is in the OUTER value scope (global or contract body).
        // lookup_value searches inner→outer, so it finds the function in the outer scope.
        let param_sigs: Vec<(String, ResolvedType, bool)> = f
            .params
            .iter()
            .map(|p| {
                (
                    p.name.clone(),
                    self.lower_type(&p.ty),
                    p.default_expr.is_some(),
                )
            })
            .collect();
        let ret_ty = f
            .return_type
            .as_ref()
            .map(|t| self.lower_type(t))
            .unwrap_or(ResolvedType::Unit);
        let fn_ty = ResolvedType::Fn(
            param_sigs.iter().map(|(_, t, _)| t.clone()).collect(),
            Box::new(ret_ty.clone()),
        );
        // Look up this function's SymbolId in the outer value scope and update it.
        if let Some(fn_id) = self.lookup_value(&f.name) {
            self.set_sym_ty(fn_id, fn_ty);
            self.sigs.insert(
                fn_id,
                SymbolSig::Function(FnSig {
                    params: param_sigs,
                    ret: ret_ty,
                }),
            );
        }

        // Params introduce value bindings.
        self.push_value_scope();
        for p in &f.params {
            let ty = self.lower_type(&p.ty);
            let id = self.alloc_typed(&p.name, p.span, SymbolKind::Param, ty);
            // In the same function signature, duplicate param names are errors.
            self.define_value_or_err(&p.name, id, p.span)?;
            self.resolve_type_ref(&p.ty, p.span)?;
            if let Some(default) = &p.default_expr {
                self.resolve_expr(default)?;
            }
        }

        // Return type.
        if let Some(ret) = &f.return_type {
            self.resolve_type_ref(ret, f.span)?;
        }

        // Body (interface signatures have body: None).
        if let Some(body) = &f.body {
            self.push_value_scope();
            for stmt in body {
                self.resolve_stmt(stmt)?;
            }
            self.pop_value_scope();
        }

        self.pop_value_scope();
        self.pop_type_scope();
        Ok(())
    }

    fn register_generic_param(&mut self, gp: &GenericParam) -> Result<(), LangError> {
        let id = self.alloc(&gp.name, gp.span, SymbolKind::GenericParam);
        self.define_type_or_err(&gp.name, id, gp.span)?;
        // Bound is a type reference (e.g. `Comparable`) — resolve it.
        // Full bound *checking* is deferred to 3f.
        if let Some(bound) = &gp.bound {
            self.resolve_type_ref(bound, gp.span)?;
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Type reference resolution
    // ─────────────────────────────────────────────────────────────────────

    /// Resolve a type annotation, using `context_span` for error location.
    ///
    /// `context_span` is the span of the enclosing declaration (param, field,
    /// return type, etc.).  `Type::Named` has no span of its own in the current
    /// AST, so the enclosing context span is used as a proxy — placing the
    /// `UndefinedType` diagnostic at the nearest declaration site.
    ///
    /// TODO(3g): once type-annotation spans are threaded through the AST,
    /// replace `context_span` with the type node's own span for precise
    /// per-annotation location.
    fn resolve_type_ref(&mut self, ty: &Type, context_span: Span) -> Result<(), LangError> {
        match ty {
            // Built-in primitive and composite types need no resolution.
            Type::U8
            | Type::U16
            | Type::U32
            | Type::U64
            | Type::U128
            | Type::U256
            | Type::I8
            | Type::I16
            | Type::I32
            | Type::I64
            | Type::I128
            | Type::I256
            | Type::Bool
            | Type::StringTy
            | Type::CharTy
            | Type::AddressTy
            | Type::HashTy
            | Type::Bytes
            | Type::BytesN(_)
            | Type::Decimal(_) => {}
            // Recursive compound types — propagate the context span.
            Type::Array(inner) | Type::Set(inner) | Type::Option_(inner) => {
                self.resolve_type_ref(inner, context_span)?;
            }
            Type::FixedArray(inner, _) => {
                self.resolve_type_ref(inner, context_span)?;
            }
            Type::Map(k, v) | Type::FastMap(k, v) | Type::Result_(k, v) => {
                self.resolve_type_ref(k, context_span)?;
                self.resolve_type_ref(v, context_span)?;
            }
            Type::Tuple(elems) => {
                for e in elems {
                    self.resolve_type_ref(e, context_span)?;
                }
            }
            Type::Fn(params, ret) => {
                for p in params {
                    self.resolve_type_ref(p, context_span)?;
                }
                self.resolve_type_ref(ret, context_span)?;
            }
            // Named type — the only user-defined name in type position.
            Type::Named(name, args) => {
                // `_` is the parser's inferred-type placeholder for an untyped
                // lambda parameter (parser/expr/control.rs, constructors.rs).
                // It is NOT a user type reference — the type is inferred in 3c,
                // so skip resolution here.
                if name == "_" {
                    return Ok(());
                }
                if self.lookup_type(name).is_none() {
                    return Err(self.undef_type_err(name, context_span));
                }
                for arg in args {
                    self.resolve_type_ref(arg, context_span)?;
                }
            }
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Statement resolution
    // ─────────────────────────────────────────────────────────────────────

    fn resolve_stmt(&mut self, stmt: &Stmt) -> Result<(), LangError> {
        match stmt {
            Stmt::Let {
                pattern,
                ty,
                expr,
                span,
                ..
            } => {
                // RHS resolves in scope *before* the new binding (decision ②).
                self.resolve_expr(expr)?;
                if let Some(t) = ty {
                    self.resolve_type_ref(t, *span)?;
                }
                // Collect pattern bindings and define in current scope.
                let bindings = collect_pattern_bindings(pattern);
                for (name, bspan) in bindings {
                    // For a simple `let x: T = expr` pattern, lower the
                    // annotation to get the local's type.  For destructuring
                    // or unannotated let, use Unknown (inferred in 3c/3e).
                    let sym_ty = if matches!(pattern, Pattern::Ident(_, _)) {
                        ty.as_ref()
                            .map(|t| self.lower_type(t))
                            .unwrap_or(ResolvedType::Unknown)
                    } else {
                        ResolvedType::Unknown
                    };
                    let id = self.alloc_typed(&name, bspan, SymbolKind::Local, sym_ty);
                    // Shadowing is allowed; no duplicate-error for let bindings.
                    // (Dup-error is only for same-scope-level *declarations*, not
                    // let-bindings which naturally shadow in nested scopes.)
                    self.define_value(&name, id);
                }
            }
            Stmt::Const(c) => {
                self.resolve_type_ref(&c.ty, c.span)?;
                self.resolve_expr(&c.value)?;
                let ty = self.lower_type(&c.ty);
                let id = self.alloc_typed(&c.name, c.span, SymbolKind::Const, ty);
                self.define_value_or_err(&c.name, id, c.span)?;
            }
            Stmt::Assign { target, value, .. } => {
                self.resolve_expr(target)?;
                self.resolve_expr(value)?;
            }
            Stmt::Return(expr, _) => {
                if let Some(e) = expr {
                    self.resolve_expr(e)?;
                }
            }
            Stmt::If {
                cond, then, else_, ..
            } => {
                self.resolve_expr(cond)?;
                self.push_value_scope();
                for s in then {
                    self.resolve_stmt(s)?;
                }
                self.pop_value_scope();
                if let Some(else_branch) = else_ {
                    self.push_value_scope();
                    for s in else_branch {
                        self.resolve_stmt(s)?;
                    }
                    self.pop_value_scope();
                }
            }
            Stmt::While { cond, body, .. } => {
                self.resolve_expr(cond)?;
                self.push_value_scope();
                for s in body {
                    self.resolve_stmt(s)?;
                }
                self.pop_value_scope();
            }
            Stmt::Loop { body, .. } => {
                self.push_value_scope();
                for s in body {
                    self.resolve_stmt(s)?;
                }
                self.pop_value_scope();
            }
            Stmt::For {
                pattern,
                iter,
                body,
                ..
            } => {
                // Resolve iterable expressions in the outer scope.
                match iter {
                    ForIter::Of(e) => self.resolve_expr(e)?,
                    ForIter::In(start, _, end, _) => {
                        self.resolve_expr(start)?;
                        self.resolve_expr(end)?;
                    }
                }
                // Loop-variable bindings go into the body scope.
                self.push_value_scope();
                let bindings = collect_pattern_bindings(pattern);
                for (name, span) in bindings {
                    let id = self.alloc(&name, span, SymbolKind::Local);
                    self.define_value(&name, id);
                }
                for s in body {
                    self.resolve_stmt(s)?;
                }
                self.pop_value_scope();
            }
            Stmt::Match { expr, arms, .. } => {
                self.resolve_expr(expr)?;
                for arm in arms {
                    self.resolve_match_arm(arm)?;
                }
            }
            Stmt::Emit { fields, .. } => {
                for (_, e) in fields {
                    self.resolve_expr(e)?;
                }
            }
            Stmt::Assert { cond, msg, .. } => {
                self.resolve_expr(cond)?;
                if let Some(m) = msg {
                    self.resolve_expr(m)?;
                }
            }
            Stmt::Revert { msg, .. } => {
                if let Some(m) = msg {
                    self.resolve_expr(m)?;
                }
            }
            Stmt::Try {
                body,
                catch_var,
                catch_body,
                span,
                ..
            } => {
                self.push_value_scope();
                for s in body {
                    self.resolve_stmt(s)?;
                }
                self.pop_value_scope();
                self.push_value_scope();
                let catch_id = self.alloc(catch_var, *span, SymbolKind::Local);
                self.define_value(catch_var, catch_id);
                for s in catch_body {
                    self.resolve_stmt(s)?;
                }
                self.pop_value_scope();
            }
            Stmt::Unchecked(body, _) => {
                self.push_value_scope();
                for s in body {
                    self.resolve_stmt(s)?;
                }
                self.pop_value_scope();
            }
            // Break, Continue, Placeholder carry no identifiers to resolve.
            Stmt::Break(_) | Stmt::Continue(_) | Stmt::Placeholder(_) => {}
            Stmt::Expr(e, _) => {
                self.resolve_expr(e)?;
            }
        }
        Ok(())
    }

    fn resolve_match_arm(&mut self, arm: &MatchArm) -> Result<(), LangError> {
        self.push_value_scope();
        let bindings = collect_pattern_bindings(&arm.pattern);
        for (name, span) in bindings {
            let id = self.alloc(&name, span, SymbolKind::Local);
            self.define_value(&name, id);
        }
        if let Some(guard) = &arm.guard {
            self.resolve_expr(guard)?;
        }
        match &arm.body {
            MatchBody::Expr(e) => self.resolve_expr(e)?,
            MatchBody::Block(stmts) => {
                for s in stmts {
                    self.resolve_stmt(s)?;
                }
            }
        }
        self.pop_value_scope();
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────────
    // Expression resolution
    // ─────────────────────────────────────────────────────────────────────

    fn resolve_expr(&mut self, expr: &Expr) -> Result<(), LangError> {
        match expr {
            // Identifier — the primary resolution target.
            Expr::Ident(name, span) => match self.lookup_value(name) {
                Some(id) => {
                    self.resolutions.insert(*span, id);
                }
                None => {
                    return Err(self.undef_name_err(name, *span));
                }
            },
            // Literals carry no identifiers.
            Expr::Literal(_, _) => {}
            // Tuple / array — recurse.
            Expr::Tuple(elems, _) => {
                for e in elems {
                    self.resolve_expr(e)?;
                }
            }
            Expr::Array(elems, _) => {
                for e in elems {
                    self.resolve_expr(e)?;
                }
            }
            // Struct literal — type name is a type-namespace lookup.
            Expr::Struct_ {
                name,
                fields,
                spread,
                span,
            } => {
                if self.lookup_type(name).is_none() {
                    return Err(self.undef_type_err(name, *span));
                }
                for (_, val) in fields {
                    self.resolve_expr(val)?;
                }
                if let Some(s) = spread {
                    self.resolve_expr(s)?;
                }
            }
            // Call — resolve callee + args.
            Expr::Call { callee, args, .. } => {
                self.resolve_expr(callee)?;
                for arg in args {
                    match arg {
                        crate::parser::ast::CallArg::Positional(e) => self.resolve_expr(e)?,
                        crate::parser::ast::CallArg::Named(_, e) => self.resolve_expr(e)?,
                    }
                }
            }
            // Index — resolve base + index.
            Expr::Index(base, idx, _) => {
                self.resolve_expr(base)?;
                self.resolve_expr(idx)?;
            }
            // Member access — resolve only the base; field-name resolution
            // needs the base's type (deferred to 3d).
            Expr::Member(base, _, _) => {
                self.resolve_expr(base)?;
            }
            // Unary / Binary / Ternary / Nullish / Try — recurse.
            Expr::Unary(_, e, _) => self.resolve_expr(e)?,
            Expr::Binary(_, lhs, rhs, _) => {
                self.resolve_expr(lhs)?;
                self.resolve_expr(rhs)?;
            }
            Expr::Ternary {
                cond, then, else_, ..
            } => {
                self.resolve_expr(cond)?;
                self.resolve_expr(then)?;
                self.resolve_expr(else_)?;
            }
            Expr::Nullish(lhs, rhs, _) => {
                self.resolve_expr(lhs)?;
                self.resolve_expr(rhs)?;
            }
            Expr::Try_(e, _) => self.resolve_expr(e)?,
            Expr::Assign_(target, _, val, _) => {
                self.resolve_expr(target)?;
                self.resolve_expr(val)?;
            }
            // Lambda — params introduce a new scope.
            Expr::Lambda { params, body, .. } => {
                self.push_value_scope();
                for p in params {
                    // `_` placeholder (unannotated lambda param) lowers to Unknown;
                    // the expression typer resolves it in 3c.
                    let ty = self.lower_type(&p.ty);
                    let id = self.alloc_typed(&p.name, p.span, SymbolKind::Param, ty);
                    let _ = self.define_value(&p.name, id);
                    self.resolve_type_ref(&p.ty, p.span)?;
                }
                match body {
                    LambdaBody::Expr(e) => self.resolve_expr(e)?,
                    LambdaBody::Block(stmts) => {
                        for s in stmts {
                            self.resolve_stmt(s)?;
                        }
                    }
                }
                self.pop_value_scope();
            }
            // `new Foo(args)` — type name in value position.
            Expr::New { ty, args, .. } => {
                // `ty` is a String here (the type name from the AST).
                // We look it up in the type namespace.
                // Note: Expr::New doesn't carry a Span for `ty` separately;
                // the whole expression span is used.
                // TODO(3g): thread precise spans for `ty` in Expr::New.
                if self.lookup_type(ty).is_none() {
                    // Use a zero-span placeholder; type name is in the error msg.
                    let placeholder = Span::at(0, 0, 0);
                    return Err(self.undef_type_err(ty, placeholder));
                }
                for arg in args {
                    match arg {
                        crate::parser::ast::CallArg::Positional(e) => self.resolve_expr(e)?,
                        crate::parser::ast::CallArg::Named(_, e) => self.resolve_expr(e)?,
                    }
                }
            }
            // If expression — new scopes per branch.
            Expr::If_ {
                cond, then, else_, ..
            } => {
                self.resolve_expr(cond)?;
                self.push_value_scope();
                for s in then {
                    self.resolve_stmt(s)?;
                }
                self.pop_value_scope();
                if let Some(else_branch) = else_ {
                    self.push_value_scope();
                    for s in else_branch {
                        self.resolve_stmt(s)?;
                    }
                    self.pop_value_scope();
                }
            }
            // Match expression — arms each get a new scope.
            Expr::Match_(expr, arms, _) => {
                self.resolve_expr(expr)?;
                for arm in arms {
                    self.resolve_match_arm(arm)?;
                }
            }
            // Template literal — resolve interpolation expressions.
            Expr::Template(segments, _) => {
                for seg in segments {
                    if let TemplateExprSegment::Interpolation(e) = seg {
                        self.resolve_expr(e)?;
                    }
                }
            }
            // Cast: `expr as T` — resolve inner expression and validate target type.
            Expr::Cast {
                expr: inner,
                ty,
                span,
            } => {
                self.resolve_expr(inner)?;
                self.resolve_type_ref(ty, *span)?;
            }
        }
        Ok(())
    }
}

// ─── Pattern binding collection ───────────────────────────────────────────────

/// Collect all variable bindings introduced by a pattern.
///
/// Returns `(name, span)` pairs for every [`Pattern::Ident`] encountered;
/// recursive through [`Pattern::Struct_`], [`Pattern::Tuple`], and
/// [`Pattern::EnumVariant`] inner patterns.
///
/// Wildcard (`_`) and rest (`..`) bind nothing.
/// Struct_/EnumVariant `name` strings are **type uses**, not bindings.
pub(super) fn collect_pattern_bindings(pattern: &Pattern) -> Vec<(String, Span)> {
    let mut out = Vec::new();
    collect_recursive(pattern, &mut out);
    out
}

fn collect_recursive(pattern: &Pattern, out: &mut Vec<(String, Span)>) {
    match pattern {
        Pattern::Ident(name, span) => {
            out.push((name.clone(), *span));
        }
        Pattern::Tuple(inner, _) => {
            for p in inner {
                collect_recursive(p, out);
            }
        }
        Pattern::Struct_ { fields, .. } => {
            for (_, p) in fields {
                collect_recursive(p, out);
            }
        }
        Pattern::EnumVariant { inner, .. } => {
            if let Some(patterns) = inner {
                for p in patterns {
                    collect_recursive(p, out);
                }
            }
        }
        // Wildcard, Literal, Rest bind nothing.
        Pattern::Wildcard(_) | Pattern::Literal(_, _) | Pattern::Rest(_) => {}
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
