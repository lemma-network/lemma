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

use super::error::{TypeError, TypeErrorKind};
use super::types::{ResolvedType, SymbolId, SymbolInfo};

// ─── Inferer ──────────────────────────────────────────────────────────────────

/// Expression type inference engine.
///
/// Borrows the resolved symbol arena and resolution map (produced by 3b's
/// name resolver) plus a mutable reference to the `expr_types` side-table it
/// is filling in.
pub(super) struct Inferer<'a> {
    symbols: &'a [SymbolInfo],
    resolutions: &'a BTreeMap<Span, SymbolId>,
    expr_types: &'a mut BTreeMap<Span, ResolvedType>,
}

impl<'a> Inferer<'a> {
    pub(super) fn new(
        symbols: &'a [SymbolInfo],
        resolutions: &'a BTreeMap<Span, SymbolId>,
        expr_types: &'a mut BTreeMap<Span, ResolvedType>,
    ) -> Self {
        Self {
            symbols,
            resolutions,
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
        let span = span_of(expr);
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

            // ── 3d: deferred ────────────────────────────────────────────────
            // Calls, member access, index, struct literals, array/tuple —
            // typing requires call-resolution and member-type machinery.
            Expr::Call { callee, args, .. } => {
                // Walk sub-expressions so they get types recorded.
                self.infer_expr(callee)?;
                for arg in args {
                    match arg {
                        CallArg::Positional(e) | CallArg::Named(_, e) => {
                            self.infer_expr(e)?;
                        }
                    }
                }
                Ok(ResolvedType::Unknown) // 3d: call return type
            }
            Expr::Member(base, _, _) => {
                self.infer_expr(base)?;
                Ok(ResolvedType::Unknown) // 3d: member field type
            }
            Expr::Index(base, idx, _) => {
                self.infer_expr(base)?;
                self.infer_expr(idx)?;
                Ok(ResolvedType::Unknown) // 3d: indexed element type
            }
            Expr::Struct_ { fields, spread, .. } => {
                for (_, e) in fields {
                    self.infer_expr(e)?;
                }
                if let Some(s) = spread {
                    self.infer_expr(s)?;
                }
                Ok(ResolvedType::Unknown) // 3d: struct type
            }
            Expr::Array(elems, _) => {
                for e in elems {
                    self.infer_expr(e)?;
                }
                Ok(ResolvedType::Unknown) // 3d: Array<T>
            }
            Expr::Tuple(elems, _) => {
                for e in elems {
                    self.infer_expr(e)?;
                }
                Ok(ResolvedType::Unknown) // 3d: (T1, T2, …)
            }
            Expr::New { args, .. } => {
                for arg in args {
                    match arg {
                        CallArg::Positional(e) | CallArg::Named(_, e) => {
                            self.infer_expr(e)?;
                        }
                    }
                }
                Ok(ResolvedType::Unknown) // 3d: constructor return type
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
            // 3d: `&expr` (reference/address-of) — deferred.
            UnaryOp::Ref => Ok(ResolvedType::Unknown),
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

        // Short-circuit: if either side is Unknown (deferred 3d/3e sub-expr),
        // propagate Unknown rather than generating false type errors.
        if lhs_ty == ResolvedType::Unknown || rhs_ty == ResolvedType::Unknown {
            return Ok(ResolvedType::Unknown);
        }

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
                // Operands must be integers (not decimal).
                self.require_int_or_literal(&lhs_ty, op_str, span)?;
                self.require_int_or_literal(&rhs_ty, op_str, span)?;
                self.unify_int_types(&lhs_ty, &rhs_ty, lhs, rhs, op_str, span)
            }

            // ── Shift ─────────────────────────────────────────────────────
            // `lhs_ty << rhs_ty` — lhs determines result type; rhs can be
            // any integer (shift amount doesn't have to match the shifted type).
            BinaryOp::Shl | BinaryOp::Shr => {
                let op_str = binary_op_str(op);
                self.require_int_or_literal(&lhs_ty, op_str, span)?;
                self.require_int_or_literal(&rhs_ty, op_str, span)?;
                // Result type follows lhs; coerce lhs if it's IntLiteral.
                if lhs_ty.is_int_literal() {
                    // Coerce literal using rhs if rhs is concrete.
                    if rhs_ty.is_integer() {
                        self.expr_types.insert(span_of(lhs), rhs_ty.clone());
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
                let op_str = binary_op_str(op);
                self.unify_eq_types(&lhs_ty, &rhs_ty, lhs, rhs, op_str, span)?;
                Ok(ResolvedType::Bool)
            }
            BinaryOp::Lt | BinaryOp::Gt | BinaryOp::LtEq | BinaryOp::GtEq => {
                let op_str = binary_op_str(op);
                // Both operands must be numeric.
                if !lhs_ty.is_numeric() {
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
                if !rhs_ty.is_numeric() {
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
                // Unify but discard the value type — result is always Bool.
                self.unify_eq_types(&lhs_ty, &rhs_ty, lhs, rhs, op_str, span)?;
                Ok(ResolvedType::Bool)
            }

            // ── Logical ───────────────────────────────────────────────────
            BinaryOp::And | BinaryOp::Or => {
                let op_str = binary_op_str(op);
                if lhs_ty != ResolvedType::Bool {
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
                if rhs_ty != ResolvedType::Bool {
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
        self.unify_eq_types(&then_ty, &else_ty, then, else_, "?:", span)?;
        // After unification, expr_types for the branches may have been updated;
        // read back the (possibly coerced) then type as the result.
        let result = self
            .expr_types
            .get(&span_of(then))
            .cloned()
            .unwrap_or(then_ty);
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
        // Validate that both are numeric.
        if !lhs_ty.is_numeric() {
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
        if !rhs_ty.is_numeric() {
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
            self.expr_types.insert(span_of(lhs), concrete.clone());
            return Ok(concrete.clone());
        }
        if let Some(concrete) = rhs_ty.coerce_int_literal(lhs_ty) {
            self.expr_types.insert(span_of(rhs), concrete.clone());
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
            self.expr_types.insert(span_of(lhs), concrete.clone());
            return Ok(concrete.clone());
        }
        if let Some(concrete) = rhs_ty.coerce_int_literal(lhs_ty) {
            self.expr_types.insert(span_of(rhs), concrete.clone());
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
        if ty.is_integer() || ty.is_int_literal() {
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

// ─── Helper: span extraction ──────────────────────────────────────────────────

/// Extract the source span from an expression.
///
/// Every `Expr` variant carries a `Span` — this function extracts it
/// uniformly without needing the private `parser::expr::span` module.
fn span_of(expr: &Expr) -> Span {
    match expr {
        Expr::Literal(_, s)
        | Expr::Ident(_, s)
        | Expr::Tuple(_, s)
        | Expr::Array(_, s)
        | Expr::Unary(_, _, s)
        | Expr::Binary(_, _, _, s)
        | Expr::Nullish(_, _, s)
        | Expr::Try_(_, s)
        | Expr::Match_(_, _, s)
        | Expr::Template(_, s)
        | Expr::Assign_(_, _, _, s)
        | Expr::Index(_, _, s)
        | Expr::Member(_, _, s) => *s,
        Expr::Struct_ { span, .. }
        | Expr::Call { span, .. }
        | Expr::Ternary { span, .. }
        | Expr::Lambda { span, .. }
        | Expr::New { span, .. }
        | Expr::If_ { span, .. } => *span,
    }
}

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
