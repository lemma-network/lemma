//! Expression type inference for the Lem type checker — P3·Step 3c.
//!
//! [`Inferer`] walks a parsed [`Ast`] and infers a [`ResolvedType`] for every
//! expression node, recording the results in [`TypedAst::expr_types`].
//!
//! ## Coverage in 3c
//!
//! Fully typed:
//! - All [`Literal`] forms → exact primitive type (see [DB-A27] for
//!   un-suffixed integer literals → [`ResolvedType::IntLiteral`]).
//! - [`Expr::Ident`] → looks up [`SymbolId`] in `resolutions`, reads `ty`
//!   from the symbol arena (DB-A28).
//! - [`Expr::Unary`] → type rules per operator (§5).
//! - [`Expr::Binary`] → type rules per operator; integer-literal coercion.
//! - [`Expr::Ternary`] → condition must be `bool`, branches must unify.
//! - [`Expr::Nullish`] → lhs `Option<T>` / rhs `T` → `T`.
//!
//! Deferred (return [`ResolvedType::Unknown`], no error):
//! - Calls, member access, index, struct literals, array/tuple literals → 3d.
//! - Lambdas, match expressions, if expressions, template strings,
//!   assignment expressions, try (`?`) → 3e.
//!
//! [DB-A27]: See `decisions-log.md` decision DB-A27.

use std::collections::BTreeMap;

use crate::error::LangError;
use crate::lexer::token::Span;
use crate::parser::ast::{
    Ast, BinaryOp, CallArg, ContractMember, Expr, ForIter, Function, Item, LambdaBody, Literal,
    MatchArm, MatchBody, Stmt, StructMember, TemplateExprSegment, UnaryOp, UnitKind,
};
use crate::parser::expr_span;

use super::error::{TypeError, TypeErrorKind};
use super::types::{ResolvedType, SymbolId, SymbolInfo, SymbolKind, SymbolSig};

// ─── Inferer ──────────────────────────────────────────────────────────────────

/// Expression type inference engine.
///
/// Borrows the resolved symbol arena and resolution map (produced by 3b's
/// name resolver) plus a mutable reference to the `expr_types` side-table it
/// is filling in.
pub(super) struct Inferer<'a> {
    symbols: &'a [SymbolInfo],
    resolutions: &'a BTreeMap<Span, SymbolId>,
    /// Structured signatures for functions, structs, and enums (from 3d resolver pass).
    sigs: &'a BTreeMap<SymbolId, SymbolSig>,
    /// Flat global-type namespace: type-declaration name → SymbolId.
    /// Used by `lower_cast_target` to resolve `Type::Named` in cast targets.
    global_types: &'a BTreeMap<String, SymbolId>,
    expr_types: &'a mut BTreeMap<Span, ResolvedType>,
}

impl<'a> Inferer<'a> {
    pub(super) fn new(
        symbols: &'a [SymbolInfo],
        resolutions: &'a BTreeMap<Span, SymbolId>,
        sigs: &'a BTreeMap<SymbolId, SymbolSig>,
        global_types: &'a BTreeMap<String, SymbolId>,
        expr_types: &'a mut BTreeMap<Span, ResolvedType>,
    ) -> Self {
        Self {
            symbols,
            resolutions,
            sigs,
            global_types,
            expr_types,
        }
    }

    // ── AST walkers ───────────────────────────────────────────────────────

    /// Walk all items in the [`Ast`], inferring types for every expression.
    pub(super) fn walk_ast(&mut self, ast: &Ast) -> Result<(), LangError> {
        for item in &ast.items {
            self.walk_item(item)?;
        }
        Ok(())
    }

    fn walk_item(&mut self, item: &Item) -> Result<(), LangError> {
        match item {
            Item::Function(f) => self.walk_function(f)?,
            Item::Const(c) => {
                self.infer_expr(&c.value)?;
            }
            Item::Contract(c) => {
                for member in &c.members {
                    self.walk_contract_member(member)?;
                }
            }
            Item::Token_(t) => {
                for member in &t.members {
                    self.walk_contract_member(member)?;
                }
            }
            Item::Struct(s) => {
                for member in &s.members {
                    if let StructMember::Method(f) = member {
                        self.walk_function(f)?;
                    }
                }
            }
            Item::Enum(e) => {
                for method in &e.methods {
                    self.walk_function(method)?;
                }
            }
            // Interface / Trait / Library / TypeAlias / ErrorDecl / Import / Using:
            // no expression bodies to type in 3c.
            Item::Interface(_)
            | Item::Trait(_)
            | Item::Library(_)
            | Item::TypeAlias(_)
            | Item::ErrorDecl(_)
            | Item::Import(_)
            | Item::Using(_) => {}
        }
        Ok(())
    }

    fn walk_contract_member(&mut self, member: &ContractMember) -> Result<(), LangError> {
        match member {
            ContractMember::Function(f) => self.walk_function(f)?,
            ContractMember::Modifier(m) => {
                for s in &m.body {
                    self.walk_stmt(s)?;
                }
            }
            ContractMember::Receive(r) => {
                for s in &r.body {
                    self.walk_stmt(s)?;
                }
            }
            ContractMember::Fallback(f) => {
                for s in &f.body {
                    self.walk_stmt(s)?;
                }
            }
            ContractMember::State(s) => {
                for field in &s.fields {
                    if let Some(default) = &field.default {
                        self.infer_expr(default)?;
                    }
                }
            }
            ContractMember::Const(c) => {
                self.infer_expr(&c.value)?;
            }
            ContractMember::Struct(s) => {
                for member in &s.members {
                    if let StructMember::Method(f) = member {
                        self.walk_function(f)?;
                    }
                }
            }
            // Enum, Event, ErrorDecl, Config, Metadata — no expression bodies.
            ContractMember::Enum(_)
            | ContractMember::Event(_)
            | ContractMember::ErrorDecl(_)
            | ContractMember::Config(_)
            | ContractMember::Metadata(_)
            | ContractMember::Immutable(_) => {}
        }
        Ok(())
    }

    fn walk_function(&mut self, f: &Function) -> Result<(), LangError> {
        // Default expressions on parameters.
        for p in &f.params {
            if let Some(default) = &p.default_expr {
                self.infer_expr(default)?;
            }
        }
        if let Some(body) = &f.body {
            for s in body {
                self.walk_stmt(s)?;
            }
        }
        Ok(())
    }

    fn walk_stmt(&mut self, stmt: &Stmt) -> Result<(), LangError> {
        match stmt {
            Stmt::Let { expr, .. } => {
                self.infer_expr(expr)?;
            }
            Stmt::Const(c) => {
                self.infer_expr(&c.value)?;
            }
            Stmt::Assign { target, value, .. } => {
                // 3e: full assignment type check (mutability, type match).
                // 3c: walk sub-expressions to record their types.
                self.infer_expr(target)?;
                self.infer_expr(value)?;
            }
            Stmt::Return(expr, _) => {
                if let Some(e) = expr {
                    self.infer_expr(e)?;
                }
            }
            Stmt::If {
                cond, then, else_, ..
            } => {
                self.infer_expr(cond)?;
                for s in then {
                    self.walk_stmt(s)?;
                }
                if let Some(else_branch) = else_ {
                    for s in else_branch {
                        self.walk_stmt(s)?;
                    }
                }
            }
            Stmt::While { cond, body, .. } => {
                self.infer_expr(cond)?;
                for s in body {
                    self.walk_stmt(s)?;
                }
            }
            Stmt::Loop { body, .. } => {
                for s in body {
                    self.walk_stmt(s)?;
                }
            }
            Stmt::For { iter, body, .. } => {
                match iter {
                    ForIter::Of(e) => {
                        self.infer_expr(e)?;
                    }
                    ForIter::In(start, _, end, _) => {
                        self.infer_expr(start)?;
                        self.infer_expr(end)?;
                    }
                }
                for s in body {
                    self.walk_stmt(s)?;
                }
            }
            Stmt::Match { expr, arms, .. } => {
                self.infer_expr(expr)?;
                for arm in arms {
                    self.walk_match_arm(arm)?;
                }
            }
            Stmt::Emit { fields, .. } => {
                for (_, e) in fields {
                    self.infer_expr(e)?;
                }
            }
            Stmt::Assert { cond, msg, .. } => {
                self.infer_expr(cond)?;
                if let Some(m) = msg {
                    self.infer_expr(m)?;
                }
            }
            Stmt::Revert { msg, .. } => {
                if let Some(m) = msg {
                    self.infer_expr(m)?;
                }
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                for s in body {
                    self.walk_stmt(s)?;
                }
                for s in catch_body {
                    self.walk_stmt(s)?;
                }
            }
            Stmt::Unchecked(body, _) => {
                for s in body {
                    self.walk_stmt(s)?;
                }
            }
            Stmt::Break(_) | Stmt::Continue(_) | Stmt::Placeholder(_) => {}
            Stmt::Expr(e, _) => {
                self.infer_expr(e)?;
            }
        }
        Ok(())
    }

    fn walk_match_arm(&mut self, arm: &MatchArm) -> Result<(), LangError> {
        if let Some(guard) = &arm.guard {
            self.infer_expr(guard)?;
        }
        match &arm.body {
            MatchBody::Expr(e) => {
                self.infer_expr(e)?;
            }
            MatchBody::Block(stmts) => {
                for s in stmts {
                    self.walk_stmt(s)?;
                }
            }
        }
        Ok(())
    }

    // ── Expression inference entry point ──────────────────────────────────

    /// Infer the type of `expr`, record it in `expr_types`, and return it.
    ///
    /// Recursively infers sub-expression types as a side effect, so callers
    /// only need to call this on the outermost expression of interest.
    pub(super) fn infer_expr(&mut self, expr: &Expr) -> Result<ResolvedType, LangError> {
        let ty = self.infer_inner(expr)?;
        let span = expr_span(expr);
        // Only record non-zero-length spans (zero-length = EOF placeholder).
        if span.len > 0 {
            self.expr_types.insert(span, ty.clone());
        }
        Ok(ty)
    }

    fn infer_inner(&mut self, expr: &Expr) -> Result<ResolvedType, LangError> {
        match expr {
            Expr::Literal(lit, _) => Ok(infer_literal(lit)),

            Expr::Ident(_, span) => Ok(self.type_of_ident(*span)),

            Expr::Unary(op, inner, span) => self.infer_unary(op, inner, *span),

            Expr::Binary(op, lhs, rhs, span) => self.infer_binary(op, lhs, rhs, *span),

            Expr::Ternary {
                cond,
                then,
                else_,
                span,
            } => self.infer_ternary(cond, then, else_, *span),

            Expr::Nullish(lhs, rhs, span) => self.infer_nullish(lhs, rhs, *span),

            // ── 3d: implemented ─────────────────────────────────────────────
            // Calls, member access, index, struct literals, array/tuple, cast.
            Expr::Cast {
                expr: inner,
                ty,
                span,
            } => {
                let from_ty = self.infer_expr(inner)?;
                let to_ty = self.lower_cast_target(ty);
                self.infer_cast(&from_ty, &to_ty, *span)
            }
            Expr::Call {
                callee, args, span, ..
            } => {
                // Walk args first to record sub-expression types.
                let mut arg_types: Vec<ResolvedType> = Vec::with_capacity(args.len());
                for arg in args {
                    let ty = match arg {
                        CallArg::Positional(e) | CallArg::Named(_, e) => self.infer_expr(e)?,
                    };
                    arg_types.push(ty);
                }
                let callee_ty = self.infer_expr(callee)?;
                // Special case: if the callee is a Member expression and the member
                // returned a non-Fn type (i.e. a builtin method's return type), treat
                // that type as the call result directly.  This handles `arr.length`,
                // `m.has(k)`, `x.checkedAdd(y)`, etc. where builtin_member_type returns
                // the result type rather than a Fn(...) type.
                if matches!(callee.as_ref(), Expr::Member(_, _, _))
                    && !matches!(callee_ty, ResolvedType::Fn(_, _))
                    && callee_ty != ResolvedType::Unknown
                {
                    return Ok(callee_ty);
                }
                self.infer_call(&callee_ty, args, &arg_types, *span)
            }
            Expr::Member(base, name, span) => {
                let base_ty = self.infer_expr(base)?;
                self.infer_member(&base_ty, name, *span)
            }
            Expr::Index(base, idx, span) => {
                let base_ty = self.infer_expr(base)?;
                let idx_ty = self.infer_expr(idx)?;
                self.infer_index(&base_ty, &idx_ty, *span)
            }
            Expr::Struct_ {
                name,
                fields,
                spread,
                span,
            } => {
                for (_, e) in fields {
                    self.infer_expr(e)?;
                }
                if let Some(s) = spread {
                    self.infer_expr(s)?;
                }
                self.infer_struct_lit(name, fields, *span)
            }
            Expr::Array(elems, span) => self.infer_array_lit(elems, *span),
            Expr::Tuple(elems, _) => {
                let types: Result<Vec<_>, _> = elems.iter().map(|e| self.infer_expr(e)).collect();
                Ok(ResolvedType::Tuple(types?))
            }
            Expr::New {
                ty: type_name,
                args,
                ..
            } => {
                for arg in args {
                    match arg {
                        CallArg::Positional(e) | CallArg::Named(_, e) => {
                            self.infer_expr(e)?;
                        }
                    }
                }
                // Return the Named type for the constructed value.
                if let Some(&type_id) = self.global_types.get(type_name.as_str()) {
                    Ok(ResolvedType::Named(type_id, vec![]))
                } else {
                    Ok(ResolvedType::Unknown) // Unresolved (import, deferred)
                }
            }

            // ── 3e: deferred ────────────────────────────────────────────────
            // Lambdas, match/if expressions, template strings, assignment,
            // try — these need statement-level context (3e) to type fully.
            Expr::Lambda { params, body, .. } => {
                for p in params {
                    if let Some(d) = &p.default_expr {
                        self.infer_expr(d)?;
                    }
                }
                match body {
                    LambdaBody::Expr(e) => {
                        self.infer_expr(e)?;
                    }
                    LambdaBody::Block(stmts) => {
                        for s in stmts {
                            self.walk_stmt(s)?;
                        }
                    }
                }
                Ok(ResolvedType::Unknown) // 3e: fn(…) -> …
            }
            Expr::Match_(scrutinee, arms, _) => {
                self.infer_expr(scrutinee)?;
                for arm in arms {
                    self.walk_match_arm(arm)?;
                }
                Ok(ResolvedType::Unknown) // 3e: unified arm types
            }
            Expr::If_ {
                cond, then, else_, ..
            } => {
                self.infer_expr(cond)?;
                for s in then {
                    self.walk_stmt(s)?;
                }
                if let Some(else_branch) = else_ {
                    for s in else_branch {
                        self.walk_stmt(s)?;
                    }
                }
                Ok(ResolvedType::Unknown) // 3e: unified branch types
            }
            Expr::Template(segments, _) => {
                for seg in segments {
                    if let TemplateExprSegment::Interpolation(e) = seg {
                        self.infer_expr(e)?;
                    }
                }
                Ok(ResolvedType::StringTy) // template string → string always
            }
            Expr::Assign_(target, _, val, _) => {
                self.infer_expr(target)?;
                self.infer_expr(val)?;
                Ok(ResolvedType::Unit) // 3e: assignment statement result
            }
            Expr::Try_(inner, _) => {
                self.infer_expr(inner)?;
                Ok(ResolvedType::Unknown) // 3e: unwraps Result<T,E> → T
            }
        }
    }

    // ── Identifier typing ─────────────────────────────────────────────────

    fn type_of_ident(&self, span: Span) -> ResolvedType {
        match self.resolutions.get(&span).copied() {
            Some(id) if !id.is_unresolved() => {
                // SymbolId(n) → symbols[n-1]
                self.symbols
                    .get((id.0 as usize) - 1)
                    .map(|info| info.ty.clone())
                    .unwrap_or(ResolvedType::Unknown)
            }
            _ => ResolvedType::Unknown,
        }
    }

    // ── Unary inference ───────────────────────────────────────────────────

    fn infer_unary(
        &mut self,
        op: &UnaryOp,
        inner: &Expr,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        let inner_ty = self.infer_expr(inner)?;

        match op {
            UnaryOp::Not => {
                // `!x` — operand must be bool, result is bool.
                if inner_ty != ResolvedType::Bool && inner_ty != ResolvedType::Unknown {
                    return Err(type_err(
                        TypeErrorKind::InvalidOperand {
                            op: "!".into(),
                            ty: inner_ty.display_name(),
                        },
                        span,
                        format!(
                            "operator `!` requires `bool` operand, found `{}`",
                            inner_ty.display_name()
                        ),
                    ));
                }
                Ok(ResolvedType::Bool)
            }
            UnaryOp::Neg => {
                // `-x` — operand must be integer or integer literal; result is same.
                // Un-suffixed literals stay IntLiteral (a negated literal is still
                // an unconstrained integer literal).
                if inner_ty.is_integer() || inner_ty.is_int_literal() {
                    Ok(inner_ty)
                } else if inner_ty == ResolvedType::Unknown {
                    Ok(ResolvedType::Unknown)
                } else {
                    Err(type_err(
                        TypeErrorKind::InvalidOperand {
                            op: "-".into(),
                            ty: inner_ty.display_name(),
                        },
                        span,
                        format!(
                            "operator `-` requires integer operand, found `{}`",
                            inner_ty.display_name()
                        ),
                    ))
                }
            }
            UnaryOp::BitNot => {
                // `~x` — operand must be integer or integer literal.
                if inner_ty.is_integer() || inner_ty.is_int_literal() {
                    Ok(inner_ty)
                } else if inner_ty == ResolvedType::Unknown {
                    Ok(ResolvedType::Unknown)
                } else {
                    Err(type_err(
                        TypeErrorKind::InvalidOperand {
                            op: "~".into(),
                            ty: inner_ty.display_name(),
                        },
                        span,
                        format!(
                            "operator `~` requires integer operand, found `{}`",
                            inner_ty.display_name()
                        ),
                    ))
                }
            }
            // `&expr` — transparent at type level for 3d.
            // A proper reference type may be added in 3f; for now return the inner type.
            UnaryOp::Ref => Ok(inner_ty),
        }
    }

    // ── Binary inference ──────────────────────────────────────────────────

    fn infer_binary(
        &mut self,
        op: &BinaryOp,
        lhs: &Expr,
        rhs: &Expr,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        let lhs_ty = self.infer_expr(lhs)?;
        let rhs_ty = self.infer_expr(rhs)?;

        // NOTE: there is NO blanket Unknown short-circuit here.
        // Each operator branch first validates the *shape* of each operand
        // independently, erroring on a known-bad concrete type regardless of
        // whether the other operand is Unknown.  Only after shape validation
        // passes does a per-branch Unknown bail-out propagate the deferred type.
        //
        // This prevents the hole where `someContractSymbol && true` (with
        // `someContractSymbol.ty == Unknown`) would silently pass as Unknown
        // instead of reporting `&&` requires bool operands.
        match op {
            // ── Arithmetic ────────────────────────────────────────────────
            BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::Div
            | BinaryOp::Rem
            | BinaryOp::Pow => {
                let op_str = binary_op_str(op);
                self.unify_arithmetic(&lhs_ty, &rhs_ty, lhs, rhs, op_str, span)
            }

            // ── Bitwise ───────────────────────────────────────────────────
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                let op_str = binary_op_str(op);
                // Shape check: error if a known concrete type is non-integer.
                self.require_int_or_literal(&lhs_ty, op_str, span)?;
                self.require_int_or_literal(&rhs_ty, op_str, span)?;
                // Propagate Unknown if either deferred.
                if lhs_ty == ResolvedType::Unknown || rhs_ty == ResolvedType::Unknown {
                    return Ok(ResolvedType::Unknown);
                }
                self.unify_int_types(&lhs_ty, &rhs_ty, lhs, rhs, op_str, span)
            }

            // ── Shift ─────────────────────────────────────────────────────
            // `lhs_ty << rhs_ty` — lhs determines result type; rhs can be
            // any integer (shift amount doesn't have to match the shifted type).
            BinaryOp::Shl | BinaryOp::Shr => {
                let op_str = binary_op_str(op);
                self.require_int_or_literal(&lhs_ty, op_str, span)?;
                self.require_int_or_literal(&rhs_ty, op_str, span)?;
                // Propagate Unknown if either deferred.
                if lhs_ty == ResolvedType::Unknown || rhs_ty == ResolvedType::Unknown {
                    return Ok(ResolvedType::Unknown);
                }
                // Result type follows lhs; coerce lhs if it's IntLiteral.
                if lhs_ty.is_int_literal() {
                    // Coerce literal using rhs if rhs is concrete.
                    if rhs_ty.is_integer() {
                        self.expr_types.insert(expr_span(lhs), rhs_ty.clone());
                        Ok(rhs_ty)
                    } else {
                        Ok(ResolvedType::IntLiteral)
                    }
                } else {
                    Ok(lhs_ty)
                }
            }

            // ── Comparison ────────────────────────────────────────────────
            BinaryOp::Eq | BinaryOp::NotEq => {
                // Any two values of the same type; IntLiteral coerces.
                // Unknown operands: skip — cannot prove validity or invalidity.
                let op_str = binary_op_str(op);
                if lhs_ty == ResolvedType::Unknown || rhs_ty == ResolvedType::Unknown {
                    return Ok(ResolvedType::Bool);
                }
                self.unify_eq_types(&lhs_ty, &rhs_ty, lhs, rhs, op_str, span)?;
                Ok(ResolvedType::Bool)
            }
            BinaryOp::Lt | BinaryOp::Gt | BinaryOp::LtEq | BinaryOp::GtEq => {
                let op_str = binary_op_str(op);
                // Shape check: error if known concrete type is non-numeric.
                if !lhs_ty.is_numeric() && lhs_ty != ResolvedType::Unknown {
                    return Err(type_err(
                        TypeErrorKind::InvalidOperand {
                            op: op_str.into(),
                            ty: lhs_ty.display_name(),
                        },
                        span,
                        format!(
                            "operator `{op_str}` requires numeric operands, found `{}`",
                            lhs_ty.display_name()
                        ),
                    ));
                }
                if !rhs_ty.is_numeric() && rhs_ty != ResolvedType::Unknown {
                    return Err(type_err(
                        TypeErrorKind::InvalidOperand {
                            op: op_str.into(),
                            ty: rhs_ty.display_name(),
                        },
                        span,
                        format!(
                            "operator `{op_str}` requires numeric operands, found `{}`",
                            rhs_ty.display_name()
                        ),
                    ));
                }
                if lhs_ty == ResolvedType::Unknown || rhs_ty == ResolvedType::Unknown {
                    return Ok(ResolvedType::Bool);
                }
                // Unify but discard the value type — result is always Bool.
                self.unify_eq_types(&lhs_ty, &rhs_ty, lhs, rhs, op_str, span)?;
                Ok(ResolvedType::Bool)
            }

            // ── Logical ───────────────────────────────────────────────────
            BinaryOp::And | BinaryOp::Or => {
                let op_str = binary_op_str(op);
                // Shape check: error if known concrete type is non-bool.
                if lhs_ty != ResolvedType::Bool && lhs_ty != ResolvedType::Unknown {
                    return Err(type_err(
                        TypeErrorKind::InvalidOperand {
                            op: op_str.into(),
                            ty: lhs_ty.display_name(),
                        },
                        span,
                        format!(
                            "operator `{op_str}` requires `bool` operands, found `{}`",
                            lhs_ty.display_name()
                        ),
                    ));
                }
                if rhs_ty != ResolvedType::Bool && rhs_ty != ResolvedType::Unknown {
                    return Err(type_err(
                        TypeErrorKind::InvalidOperand {
                            op: op_str.into(),
                            ty: rhs_ty.display_name(),
                        },
                        span,
                        format!(
                            "operator `{op_str}` requires `bool` operands, found `{}`",
                            rhs_ty.display_name()
                        ),
                    ));
                }
                if lhs_ty == ResolvedType::Unknown || rhs_ty == ResolvedType::Unknown {
                    return Ok(ResolvedType::Bool);
                }
                Ok(ResolvedType::Bool)
            }

            // ── Null-coalescing as binary op ──────────────────────────────
            // `Expr::Nullish` handles `??` as a dedicated variant; this arm
            // is a defensive fallback for `BinaryOp::Nullish` if the parser
            // ever emits it instead.
            BinaryOp::Nullish => self.infer_nullish_types(&lhs_ty, &rhs_ty, span),
        }
    }

    // ── Ternary / nullish inference ───────────────────────────────────────

    fn infer_ternary(
        &mut self,
        cond: &Expr,
        then: &Expr,
        else_: &Expr,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        let cond_ty = self.infer_expr(cond)?;
        let then_ty = self.infer_expr(then)?;
        let else_ty = self.infer_expr(else_)?;

        // Condition must be bool.
        if cond_ty != ResolvedType::Bool && cond_ty != ResolvedType::Unknown {
            return Err(type_err(
                TypeErrorKind::TypeMismatch {
                    expected: "bool".into(),
                    found: cond_ty.display_name(),
                },
                span,
                format!(
                    "ternary condition must be `bool`, found `{}`",
                    cond_ty.display_name()
                ),
            ));
        }

        // Branch types must unify.
        if then_ty == ResolvedType::Unknown || else_ty == ResolvedType::Unknown {
            return Ok(if then_ty != ResolvedType::Unknown {
                then_ty
            } else {
                else_ty
            });
        }
        // unify_eq_types returns the unified type directly (handles IntLiteral
        // coercion and same-type checks) — use it as the result rather than
        // re-reading from expr_types.
        let result = self.unify_eq_types(&then_ty, &else_ty, then, else_, "?:", span)?;
        Ok(result)
    }

    fn infer_nullish(
        &mut self,
        lhs: &Expr,
        rhs: &Expr,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        let lhs_ty = self.infer_expr(lhs)?;
        let rhs_ty = self.infer_expr(rhs)?;
        self.infer_nullish_types(&lhs_ty, &rhs_ty, span)
    }

    fn infer_nullish_types(
        &self,
        lhs_ty: &ResolvedType,
        rhs_ty: &ResolvedType,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        // `option ?? default` — lhs must be `Option<T>`, rhs must be `T`,
        // result is `T`.
        if *lhs_ty == ResolvedType::Unknown || *rhs_ty == ResolvedType::Unknown {
            return Ok(rhs_ty.clone());
        }
        if let Some(inner) = lhs_ty.option_inner() {
            if inner == rhs_ty || rhs_ty.is_int_literal() {
                return Ok(inner.clone());
            }
            return Err(type_err(
                TypeErrorKind::TypeMismatch {
                    expected: inner.display_name(),
                    found: rhs_ty.display_name(),
                },
                span,
                format!(
                    "`??` default must match `Option` inner type `{}`, found `{}`",
                    inner.display_name(),
                    rhs_ty.display_name()
                ),
            ));
        }
        // lhs is not an Option — type error.
        Err(type_err(
            TypeErrorKind::InvalidOperand {
                op: "??".into(),
                ty: lhs_ty.display_name(),
            },
            span,
            format!(
                "operator `??` requires `Option<T>` on the left, found `{}`",
                lhs_ty.display_name()
            ),
        ))
    }

    // ── Numeric unification helpers ───────────────────────────────────────

    /// Unify two numeric types for arithmetic operators (`+`, `-`, `*`, `/`,
    /// `%`, `**`).
    ///
    /// Rules (§3.1 + DB-A27):
    /// - `T op T` → `T` (same type)
    /// - `IntLiteral op T` or `T op IntLiteral` → `T` (literal coerces)
    /// - `IntLiteral op IntLiteral` → `IntLiteral`
    /// - `decimal(N) op decimal(N)` → `decimal(N)`
    /// - Any other combination → `TypeMismatch`
    fn unify_arithmetic(
        &mut self,
        lhs_ty: &ResolvedType,
        rhs_ty: &ResolvedType,
        lhs: &Expr,
        rhs: &Expr,
        op: &str,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        // Shape check: error if a KNOWN concrete type is non-numeric.
        // Unknown operands (deferred 3d/3e sub-expressions) skip the check —
        // we cannot prove validity but also cannot prove invalidity.
        if !lhs_ty.is_numeric() && *lhs_ty != ResolvedType::Unknown {
            return Err(type_err(
                TypeErrorKind::InvalidOperand {
                    op: op.into(),
                    ty: lhs_ty.display_name(),
                },
                span,
                format!(
                    "operator `{op}` requires numeric operands, found `{}`",
                    lhs_ty.display_name()
                ),
            ));
        }
        if !rhs_ty.is_numeric() && *rhs_ty != ResolvedType::Unknown {
            return Err(type_err(
                TypeErrorKind::InvalidOperand {
                    op: op.into(),
                    ty: rhs_ty.display_name(),
                },
                span,
                format!(
                    "operator `{op}` requires numeric operands, found `{}`",
                    rhs_ty.display_name()
                ),
            ));
        }
        // Propagate Unknown if either side is still deferred.
        if *lhs_ty == ResolvedType::Unknown || *rhs_ty == ResolvedType::Unknown {
            return Ok(ResolvedType::Unknown);
        }
        self.unify_int_types(lhs_ty, rhs_ty, lhs, rhs, op, span)
    }

    /// Unify two integer/integer-literal types, applying coercion.
    fn unify_int_types(
        &mut self,
        lhs_ty: &ResolvedType,
        rhs_ty: &ResolvedType,
        lhs: &Expr,
        rhs: &Expr,
        op: &str,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        // Same type — trivial.
        if lhs_ty == rhs_ty {
            return Ok(lhs_ty.clone());
        }
        // IntLiteral coerces to a concrete integer type.
        if let Some(concrete) = lhs_ty.coerce_int_literal(rhs_ty) {
            self.expr_types.insert(expr_span(lhs), concrete.clone());
            return Ok(concrete.clone());
        }
        if let Some(concrete) = rhs_ty.coerce_int_literal(lhs_ty) {
            self.expr_types.insert(expr_span(rhs), concrete.clone());
            return Ok(concrete.clone());
        }
        // Both IntLiteral.
        if lhs_ty.is_int_literal() && rhs_ty.is_int_literal() {
            return Ok(ResolvedType::IntLiteral);
        }
        // Decimal(N) op Decimal(N) — handled by `same type` branch above.
        // Decimal(N) op Decimal(M) N≠M → mismatch.
        Err(type_err(
            TypeErrorKind::TypeMismatch {
                expected: lhs_ty.display_name(),
                found: rhs_ty.display_name(),
            },
            span,
            format!(
                "operator `{op}` requires matching types; \
                 cannot apply to `{}` and `{}`",
                lhs_ty.display_name(),
                rhs_ty.display_name()
            ),
        ))
    }

    /// Unify two types for equality/comparison — allows IntLiteral coercion
    /// and updates `expr_types` for coerced literals.
    fn unify_eq_types(
        &mut self,
        lhs_ty: &ResolvedType,
        rhs_ty: &ResolvedType,
        lhs: &Expr,
        rhs: &Expr,
        op: &str,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        if lhs_ty == rhs_ty {
            return Ok(lhs_ty.clone());
        }
        if let Some(concrete) = lhs_ty.coerce_int_literal(rhs_ty) {
            self.expr_types.insert(expr_span(lhs), concrete.clone());
            return Ok(concrete.clone());
        }
        if let Some(concrete) = rhs_ty.coerce_int_literal(lhs_ty) {
            self.expr_types.insert(expr_span(rhs), concrete.clone());
            return Ok(concrete.clone());
        }
        if lhs_ty.is_int_literal() && rhs_ty.is_int_literal() {
            return Ok(ResolvedType::IntLiteral);
        }
        Err(type_err(
            TypeErrorKind::TypeMismatch {
                expected: lhs_ty.display_name(),
                found: rhs_ty.display_name(),
            },
            span,
            format!(
                "operator `{op}` requires matching types; \
                 cannot apply to `{}` and `{}`",
                lhs_ty.display_name(),
                rhs_ty.display_name()
            ),
        ))
    }

    fn require_int_or_literal(
        &self,
        ty: &ResolvedType,
        op: &str,
        span: Span,
    ) -> Result<(), LangError> {
        // Unknown operands (deferred 3d/3e sub-expressions) skip the check.
        if *ty == ResolvedType::Unknown || ty.is_integer() || ty.is_int_literal() {
            return Ok(());
        }
        Err(type_err(
            TypeErrorKind::InvalidOperand {
                op: op.into(),
                ty: ty.display_name(),
            },
            span,
            format!(
                "operator `{op}` requires integer operands, found `{}`",
                ty.display_name()
            ),
        ))
    }

    // ── 3d: cast, call, member, index, array, struct helpers ─────────────

    /// Lower a cast target `Type` to `ResolvedType`.
    ///
    /// Uses `global_types` for Named types; handles all primitives directly.
    /// The Inferer does not have the full resolver scope stack, so only
    /// globally-registered type names resolve; others return `Unknown`
    /// (will be refined in 3f when full scope info is available).
    /// Lower a cast target `Type` to `ResolvedType`.
    ///
    /// Uses `global_types` for Named types; handles all primitives directly.
    /// The Inferer does not have the full resolver scope stack, so only
    /// globally-registered type names resolve; others return `Unknown`
    /// (will be refined in 3f when full scope info is available).
    ///
    /// # DRY note
    ///
    /// The primitive and compound arms below duplicate `Resolver::lower_type`.
    /// The two differ only in scope source (`self.lookup_type` vs `global_types`),
    /// making a shared generic helper worthwhile once 3f adds a third caller.
    ///
    /// TODO(3f): extract `lower_type_with<F: Fn(&str, Vec<ResolvedType>) → ResolvedType>`
    /// so all callers share the primitive/compound mapping and inject only the
    /// name-resolution strategy. Tracked in living-notes Technical Debt as
    /// **P3-checker-4**. Catch-all `_ => Unknown` below silently skips new
    /// `Type` variants — the 3f extraction will make this exhaustive.
    fn lower_cast_target(&self, ty: &crate::parser::ast::Type) -> ResolvedType {
        use crate::parser::ast::Type as T;
        match ty {
            T::U8 => ResolvedType::U8,
            T::U16 => ResolvedType::U16,
            T::U32 => ResolvedType::U32,
            T::U64 => ResolvedType::U64,
            T::U128 => ResolvedType::U128,
            T::U256 => ResolvedType::U256,
            T::I8 => ResolvedType::I8,
            T::I16 => ResolvedType::I16,
            T::I32 => ResolvedType::I32,
            T::I64 => ResolvedType::I64,
            T::I128 => ResolvedType::I128,
            T::I256 => ResolvedType::I256,
            T::Bool => ResolvedType::Bool,
            T::StringTy => ResolvedType::StringTy,
            T::CharTy => ResolvedType::CharTy,
            T::AddressTy => ResolvedType::AddressTy,
            T::HashTy => ResolvedType::HashTy,
            T::Bytes => ResolvedType::Bytes,
            T::BytesN(n) => ResolvedType::BytesN(*n),
            T::Decimal(n) => ResolvedType::Decimal(*n),
            T::Named(name, args) => {
                if name == "_" {
                    return ResolvedType::Unknown;
                }
                let lowered_args: Vec<_> = args.iter().map(|a| self.lower_cast_target(a)).collect();
                match self.global_types.get(name.as_str()) {
                    Some(&id) => {
                        // Generic params keep their name for 3f instantiation.
                        let is_generic = self
                            .symbols
                            .get((id.0 as usize).saturating_sub(1))
                            .is_some_and(|s| s.kind == SymbolKind::GenericParam);
                        if is_generic {
                            ResolvedType::TypeParam(name.clone())
                        } else {
                            ResolvedType::Named(id, lowered_args)
                        }
                    }
                    // Not in global type namespace (import or deferred) → Unknown.
                    None => ResolvedType::Unknown,
                }
            }
            // Compound types in cast targets are unusual; return Unknown for 3d.
            // 3f: handle compound cast targets (Array<T> as Array<U>, etc.)
            _ => ResolvedType::Unknown,
        }
    }

    /// Type-check a cast expression `from_ty as to_ty`.
    ///
    /// Only integer widening is supported via `as`.  Narrowing must use
    /// `.tryInto()?`.  Non-integer types cannot use `as` at all.
    fn infer_cast(
        &self,
        from_ty: &ResolvedType,
        to_ty: &ResolvedType,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        // Unknown to_ty (Named cast target not in global_types, or compound) → Unknown.
        if *to_ty == ResolvedType::Unknown {
            return Ok(ResolvedType::Unknown);
        }
        // Unknown from_ty (deferred sub-expr) → return to_ty (assume valid).
        if *from_ty == ResolvedType::Unknown {
            return Ok(to_ty.clone());
        }
        // IntLiteral can cast to any concrete integer type.
        if from_ty.is_int_literal() && to_ty.is_integer() {
            return Ok(to_ty.clone());
        }
        // Integer → Integer: widening only (same signedness class, from_w ≤ to_w).
        if from_ty.is_integer() && to_ty.is_integer() {
            // Both are proven `is_integer()` so `bit_width()` is always `Some`.
            let from_w = from_ty
                .bit_width()
                .expect("integer type has a defined bit width");
            let to_w = to_ty
                .bit_width()
                .expect("integer type has a defined bit width");
            let same_sign = (from_ty.is_unsigned_int() && to_ty.is_unsigned_int())
                || (from_ty.is_signed_int() && to_ty.is_signed_int());
            if same_sign && from_w <= to_w {
                return Ok(to_ty.clone());
            }
            return Err(type_err(
                TypeErrorKind::InvalidConversion {
                    from: from_ty.display_name(),
                    to: to_ty.display_name(),
                },
                span,
                format!(
                    "`as` only widens; use `.tryInto()?` to narrow `{}` to `{}`",
                    from_ty.display_name(),
                    to_ty.display_name()
                ),
            ));
        }
        // Any other conversion via `as` is not supported.
        Err(type_err(
            TypeErrorKind::InvalidConversion {
                from: from_ty.display_name(),
                to: to_ty.display_name(),
            },
            span,
            format!(
                "cannot use `as` to convert `{}` to `{}`; only integer widening is supported",
                from_ty.display_name(),
                to_ty.display_name()
            ),
        ))
    }

    /// Type-check a function call.
    ///
    /// Checks arity (overshoot only for 3d; undershoot ok due to defaults).
    /// Full per-param type checking is deferred to 3e.
    fn infer_call(
        &self,
        callee_ty: &ResolvedType,
        args: &[CallArg],
        _arg_types: &[ResolvedType],
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        match callee_ty {
            ResolvedType::Fn(param_types, ret) => {
                let positional_count = args
                    .iter()
                    .filter(|a| matches!(a, CallArg::Positional(_)))
                    .count();
                // Overshoot check only (undershoot ok — defaults handled in 3e).
                if positional_count > param_types.len() {
                    return Err(type_err(
                        TypeErrorKind::ArityMismatch {
                            func: "fn".into(),
                            expected: param_types.len(),
                            found: positional_count,
                        },
                        span,
                        format!(
                            "too many arguments: expected at most {}, got {}",
                            param_types.len(),
                            positional_count
                        ),
                    ));
                }
                Ok(*ret.clone())
            }
            ResolvedType::Unknown => Ok(ResolvedType::Unknown),
            other => Err(type_err(
                TypeErrorKind::NotCallable {
                    ty: other.display_name(),
                },
                span,
                format!("type `{}` is not callable", other.display_name()),
            )),
        }
    }

    /// Type-check a member access `base.name`.
    ///
    /// Checks built-in members first, then looks up user-defined struct fields
    /// and methods via `SymbolSig`.  Contract member access (`self.field`) is
    /// deferred to 3g (requires contract scope context).
    fn infer_member(
        &self,
        base_ty: &ResolvedType,
        name: &str,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        if *base_ty == ResolvedType::Unknown {
            return Ok(ResolvedType::Unknown);
        }
        // Check built-in members first (they override user-defined).
        if let Some(ty) = builtin_member_type(base_ty, name) {
            return Ok(ty);
        }
        // Named type (struct, enum) → look up in sigs.
        if let Some(struct_id) = base_ty.named_id() {
            match self.sigs.get(&struct_id) {
                Some(SymbolSig::Struct(sig)) => {
                    // Check fields.
                    if let Some((_, ft)) = sig.fields.iter().find(|(n, _)| n == name) {
                        return Ok(ft.clone());
                    }
                    // Check methods (returns the Fn type; Call will extract ret).
                    if let Some((_, method_id)) = sig.methods.iter().find(|(n, _)| n == name) {
                        if let Some(s) = self.symbols.get((method_id.0 as usize).saturating_sub(1))
                        {
                            return Ok(s.ty.clone()); // Fn(params, ret)
                        }
                    }
                    // Field not found on a known struct → error.
                    return Err(type_err(
                        TypeErrorKind::UnknownField {
                            ty: base_ty.display_name(),
                            field: name.to_owned(),
                        },
                        span,
                        format!(
                            "type `{}` has no field or method `{}`",
                            base_ty.display_name(),
                            name
                        ),
                    ));
                }
                Some(SymbolSig::Enum(_)) => {
                    // Enum member access (variant name or method) — deferred to 3e/3f.
                    return Ok(ResolvedType::Unknown);
                }
                Some(SymbolSig::Function(_)) | None => {
                    // Contract or type with no StructSig (P3-checker-3 / deferred to 3g).
                    // Tolerate gracefully — not an error.
                    return Ok(ResolvedType::Unknown);
                }
            }
        }
        // Non-Named type with no matching built-in → Unknown (not an error in 3d;
        // full built-in coverage deferred to 3g).
        Ok(ResolvedType::Unknown)
    }

    /// Type-check an index expression `base[idx]`.
    fn infer_index(
        &self,
        base_ty: &ResolvedType,
        idx_ty: &ResolvedType,
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        if *base_ty == ResolvedType::Unknown {
            return Ok(ResolvedType::Unknown);
        }
        // Array / FixedArray → elem type (integer index).
        if let Some(elem) = base_ty.array_elem() {
            if !idx_ty.is_integer() && !idx_ty.is_int_literal() && *idx_ty != ResolvedType::Unknown
            {
                return Err(type_err(
                    TypeErrorKind::InvalidOperand {
                        op: "[]".into(),
                        ty: idx_ty.display_name(),
                    },
                    span,
                    format!(
                        "array index must be an integer, found `{}`",
                        idx_ty.display_name()
                    ),
                ));
            }
            return Ok(elem.clone());
        }
        // Map / FastMap → value type.
        if let Some((_, val)) = base_ty.map_kv() {
            return Ok(val.clone());
        }
        // Set / other → not indexable.
        Err(type_err(
            TypeErrorKind::NotIndexable {
                ty: base_ty.display_name(),
            },
            span,
            format!(
                "type `{}` does not support indexing",
                base_ty.display_name()
            ),
        ))
    }

    /// Type-check an array literal `[e1, e2, ...]`.
    ///
    /// All elements must have the same type (or be IntLiteral coercible).
    fn infer_array_lit(&mut self, elems: &[Expr], span: Span) -> Result<ResolvedType, LangError> {
        if elems.is_empty() {
            return Ok(ResolvedType::Array(Box::new(ResolvedType::Unknown)));
        }
        let first_ty = self.infer_expr(&elems[0])?;
        let mut unified = first_ty;
        for e in &elems[1..] {
            let ety = self.infer_expr(e)?;
            unified = self.unify_eq_types(&unified, &ety, &elems[0], e, "[]", span)?;
        }
        Ok(ResolvedType::Array(Box::new(unified)))
    }

    /// Type-check a struct literal `Name { field: expr, ... }`.
    ///
    /// Validates that all provided field names exist on the struct.
    /// Full field-type checking is deferred to 3e.
    fn infer_struct_lit(
        &self,
        name: &str,
        fields: &[(String, Expr)],
        span: Span,
    ) -> Result<ResolvedType, LangError> {
        if let Some(&struct_id) = self.global_types.get(name) {
            if let Some(SymbolSig::Struct(sig)) = self.sigs.get(&struct_id) {
                // Check each provided field exists on the struct.
                for (field_name, _) in fields {
                    if !sig.fields.iter().any(|(n, _)| n == field_name) {
                        return Err(type_err(
                            TypeErrorKind::UnknownField {
                                ty: name.to_owned(),
                                field: field_name.clone(),
                            },
                            span,
                            format!("struct `{}` has no field `{}`", name, field_name),
                        ));
                    }
                }
            }
            return Ok(ResolvedType::Named(struct_id, vec![]));
        }
        // Unknown struct (import / deferred) → Unknown.
        Ok(ResolvedType::Unknown)
    }
}

// ─── Built-in member type table ───────────────────────────────────────────────

/// Type for built-in member access (property or method) on known compound types.
///
/// Returns `Some(ResolvedType)` if `name` is a recognized built-in for `base_ty`.
/// Returns `None` if the member should be resolved as a user-defined field/method.
fn builtin_member_type(base_ty: &ResolvedType, name: &str) -> Option<ResolvedType> {
    match base_ty {
        ResolvedType::Array(elem) | ResolvedType::FixedArray(elem, _) => match name {
            "length" => Some(ResolvedType::U256),
            "get" => Some(ResolvedType::Option_(elem.clone())),
            "push" | "pop" => Some(ResolvedType::Unit),
            // Generic methods (map/filter/reduce) deferred to 3f.
            _ => None,
        },
        ResolvedType::Map(_, val) | ResolvedType::FastMap(_, val) => match name {
            "get" => Some(ResolvedType::Option_(val.clone())),
            "getOr" => Some(*val.clone()),
            "set" | "delete" => Some(ResolvedType::Unit),
            "has" => Some(ResolvedType::Bool),
            "size" => Some(ResolvedType::U256),
            _ => None,
        },
        ResolvedType::Set(elem) => match name {
            "add" | "delete" => Some(ResolvedType::Unit),
            "has" => Some(ResolvedType::Bool),
            "size" => Some(ResolvedType::U256),
            "intersection" | "union" | "difference" => Some(ResolvedType::Set(elem.clone())),
            _ => None,
        },
        ResolvedType::Option_(inner) => match name {
            "unwrap" => Some(*inner.clone()),
            "isSome" | "isNone" => Some(ResolvedType::Bool),
            _ => None,
        },
        ty if ty.is_integer() || ty.is_int_literal() => {
            let base_clone = base_ty.clone();
            match name {
                "checkedAdd" | "checkedSub" | "checkedMul" | "checkedDiv" => Some(
                    ResolvedType::Result_(Box::new(base_clone), Box::new(ResolvedType::Unknown)),
                ),
                "wrappingAdd" | "wrappingSub" | "wrappingMul" | "saturatingAdd"
                | "saturatingSub" => Some(base_clone),
                // .tryInto() returns Result<Unknown, _> — target type from annotation (3e).
                "tryInto" => Some(ResolvedType::Result_(
                    Box::new(ResolvedType::Unknown),
                    Box::new(ResolvedType::Unknown),
                )),
                "toI256" => Some(ResolvedType::I256),
                "toU256" => Some(ResolvedType::U256),
                _ => None,
            }
        }
        ResolvedType::Decimal(_) => match name {
            "toRaw" => Some(ResolvedType::U256),
            _ => None,
        },
        ResolvedType::StringTy => match name {
            "length" => Some(ResolvedType::U256),
            _ => None,
        },
        ResolvedType::AddressTy => match name {
            "isZero" => Some(ResolvedType::Bool),
            "toHash" => Some(ResolvedType::HashTy),
            _ => None,
        },
        _ => None,
    }
}

// ─── Literal type inference ────────────────────────────────────────────────────

/// Map a [`Literal`] value to its [`ResolvedType`].
///
/// This is a pure function (no scope needed — literals are self-typing).
fn infer_literal(lit: &Literal) -> ResolvedType {
    match lit {
        // Typed integer suffix → exact type.
        Literal::IntTyped { suffix, .. } => int_suffix_type(suffix),

        // Un-suffixed integer, hex, binary → unconstrained IntLiteral (DB-A27).
        // Coerced to a concrete integer type by context in infer_binary et al.
        Literal::Int(_) | Literal::Hex(_) | Literal::Bin(_) => ResolvedType::IntLiteral,

        // Float literal (stored as string for determinism) → Unknown.
        // Context determines the `decimal(N)` precision (3e, annotation check).
        Literal::Float(_) => ResolvedType::Unknown,

        Literal::Str(_) => ResolvedType::StringTy,
        Literal::Bytes(_) => ResolvedType::Bytes,
        Literal::Char(_) => ResolvedType::CharTy,
        Literal::Bool(_) => ResolvedType::Bool,
        Literal::Address(_) => ResolvedType::AddressTy,

        // Unit literals (`1.ether`, `6.months`) scale to u256 (Drop).
        Literal::Unit(inner, kind) => infer_unit_literal(inner, kind),
    }
}

/// Type for a unit literal (`1.ether`, `6.months`, …).
///
/// All unit literals evaluate to a `u256` Drop value (the underlying chain
/// denomination).  The inner numeric expression's type is noted but the
/// outer unit literal is always `u256`.
fn infer_unit_literal(_inner: &Expr, kind: &UnitKind) -> ResolvedType {
    // All unit kinds scale to u256 (the chain's native Drop denomination).
    // We match exhaustively so the compiler flags new UnitKind variants.
    match kind {
        UnitKind::Ether
        | UnitKind::Gwei
        | UnitKind::Minutes
        | UnitKind::Hours
        | UnitKind::Days
        | UnitKind::Seconds
        | UnitKind::Months => ResolvedType::U256,
    }
}

/// Map an integer suffix string to a concrete [`ResolvedType`].
///
/// Called for typed literals like `42u128` (suffix = `"u128"`).
fn int_suffix_type(suffix: &str) -> ResolvedType {
    match suffix {
        "u8" => ResolvedType::U8,
        "u16" => ResolvedType::U16,
        "u32" => ResolvedType::U32,
        "u64" => ResolvedType::U64,
        "u128" => ResolvedType::U128,
        "u256" => ResolvedType::U256,
        "i8" => ResolvedType::I8,
        "i16" => ResolvedType::I16,
        "i32" => ResolvedType::I32,
        "i64" => ResolvedType::I64,
        "i128" => ResolvedType::I128,
        "i256" => ResolvedType::I256,
        // Unknown suffix — should not reach here if the lexer is correct,
        // but fall back gracefully.
        _ => ResolvedType::IntLiteral,
    }
}

// Span extraction is handled by the canonical `crate::parser::expr_span`
// (re-exported from `parser/mod.rs`).  No local duplicate needed.

// ─── Error construction helper ────────────────────────────────────────────────

fn type_err(kind: TypeErrorKind, span: Span, message: impl Into<String>) -> LangError {
    LangError::Type(TypeError {
        kind,
        span,
        message: message.into(),
    })
}

// ─── Operator name strings ────────────────────────────────────────────────────

fn binary_op_str(op: &BinaryOp) -> &'static str {
    match op {
        BinaryOp::Add => "+",
        BinaryOp::Sub => "-",
        BinaryOp::Mul => "*",
        BinaryOp::Div => "/",
        BinaryOp::Rem => "%",
        BinaryOp::Pow => "**",
        BinaryOp::Eq => "==",
        BinaryOp::NotEq => "!=",
        BinaryOp::Lt => "<",
        BinaryOp::Gt => ">",
        BinaryOp::LtEq => "<=",
        BinaryOp::GtEq => ">=",
        BinaryOp::And => "&&",
        BinaryOp::Or => "||",
        BinaryOp::BitAnd => "&",
        BinaryOp::BitOr => "|",
        BinaryOp::BitXor => "^",
        BinaryOp::Shl => "<<",
        BinaryOp::Shr => ">>",
        BinaryOp::Nullish => "??",
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
