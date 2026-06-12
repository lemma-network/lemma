//! Well-formedness pass for the Lem type checker.
//!
//! Entry point: [`check`].  Takes a fully-typed [`TypedAst`] (produced by the
//! inferer after name resolution and expression typing) and verifies the 15
//! structural/semantic well-formedness rules defined in
//! `docs/03-LANGUAGE_SPEC.md §30` (WF-001…015).
//!
//! ## Pipeline position
//!
//! ```text
//! inferer.validate_type_annotations(&ast)?
//!     → TypedAst::new(…)
//!     → wellformed::check(&typed_ast)   ← this pass
//!     → Ok(typed_ast)
//! ```
//!
//! ## Design: collect-all, never fail-fast
//!
//! Mirrors the safety analyzer shape (`analyzer/rules/fee_cap.rs`):
//! - All violations are collected into a `Vec<TypeError>` before returning.
//! - If the vec is non-empty, the caller maps it to
//!   [`crate::error::LangError::WellFormed`] so the developer sees every
//!   problem in one compile.
//! - Individual rule functions return `Vec<TypeError>` and are called in
//!   sequence; their results are appended to a single accumulator.
//!
//! ## Build status
//!
//! **Phase 2 (wf-checker subtask 05)**: Family A rules implemented —
//! WF-001 (state field initialization), WF-002 (immutable set-once in init),
//! WF-003 (init constructor well-formedness).
//!
//! **Phase 3 (wf-checker subtask 07)**: Family B rules implemented —
//! WF-004 (return-path completeness), WF-005 (match exhaustiveness),
//! WF-006 (placeholder only in modifier bodies), WF-007 (break/continue
//! only inside loops).
//!
//! **Phase 4 (wf-checker subtask 09)**: Family C rules implemented —
//! WF-008 (interface implementation completeness), WF-009 (trait `uses`
//! completeness), WF-010 (`receive`/`fallback` uniqueness), WF-011
//! (recursive by-value type detection).
//!
//! **Phase 5 (wf-checker subtask 11)**: Family D rules implemented —
//! WF-012 (emit ↔ event-schema validation — uses Phase 1 event field-sig
//! table), WF-013 (const-expression evaluability — over-approximation
//! grammar), WF-014 (token `config {}` schema validation — per-standard
//! hardcoded schema, bps-integer mandate, conditional requirements),
//! WF-015 (pure/view effect conformance — syntactic gate).

use std::collections::{BTreeMap, BTreeSet};

use crate::analyzer::rules::constants::PROTOCOL_MAX_FEE_BPS;
use crate::parser::ast::{Item, Stmt};
use crate::parser::{
    AssignOp, ConfigValue, ContractMember, Expr, MatchBody, Mutability, Pattern, TraitMember, Type,
};
use crate::type_checker::error::{TypeError, TypeErrorKind};
use crate::type_checker::typed_ast::TypedAst;
use crate::type_checker::typed_contract::TypedContract;
use crate::type_checker::types::{ResolvedType, SymbolId, SymbolKind, SymbolSig};
use crate::visit::{walk_expr, walk_stmt, Visitor};

/// Check a fully-typed AST for well-formedness violations (WF-001…015).
///
/// Runs after the inferer succeeds and before `Ok(TypedAst)` is returned by
/// `check_program`.  Collects **all** violations before returning (never
/// fail-fast) — consistent with the safety analyzer.
///
/// # Returns
///
/// - `Ok(())` — the program is well-formed.
/// - `Err(violations)` — one or more [`TypeError`] values, each carrying a
///   WF-001…015 [`crate::type_checker::error::TypeErrorKind`] variant.
///   The caller maps this to [`crate::error::LangError::WellFormed`].
pub fn check(typed_ast: &TypedAst) -> Result<(), Vec<TypeError>> {
    let mut violations: Vec<TypeError> = Vec::new();

    // Family A: Storage & Initialization (WF-001..003)
    violations.extend(check_family_a(typed_ast));

    // Family B: Control-Flow (WF-004..007)
    violations.extend(check_family_b(typed_ast));

    // Family C: Structural-Completeness (WF-008..011)
    violations.extend(check_family_c(typed_ast));

    // Family D: Schema & Effect (WF-012..015)
    violations.extend(check_family_d(typed_ast));

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ─── Family A: Storage & Initialization (WF-001..003) ────────────────────────

/// Check all Family A rules (WF-001, WF-002, WF-003) for every contract/token.
///
/// Iterates over all contracts in the typed AST and collects violations from
/// each per-contract rule function.  Collect-all: never returns early.
fn check_family_a(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();
    for contract in typed_ast.contracts() {
        violations.extend(check_wf001_state_init(&contract, typed_ast));
        violations.extend(check_wf002_immutable_once(&contract));
        violations.extend(check_wf003_init_wellformed(&contract));
    }
    violations
}

// ─── WF-001: State field initialization ──────────────────────────────────────

/// WF-001 — Every `state` field must be initialized on every deploy path.
///
/// A field is considered initialized if:
/// 1. It has a default initializer in the `state {}` block (`field: T = expr`), OR
/// 2. It is assigned (`self.field = …`) in the `init` function body on ALL paths.
///
/// "All paths" means: the assignment appears at the top level of the init body
/// (not inside a conditional), OR appears in BOTH branches of every `if/else`,
/// OR appears in ALL arms of every `match`.
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-001`.
fn check_wf001_state_init(contract: &TypedContract<'_>, _typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();

    // Collect raw state fields (with default info) from the AST members.
    // We need the AST-level StateField to check `.default`.
    let raw_state_fields = collect_raw_state_fields(contract);

    // Find the init function body (if any).
    let init_body = find_init_body(contract);

    for (field_name, field_span, has_default) in &raw_state_fields {
        if *has_default {
            // Default initializer present — always initialized.
            continue;
        }

        // No default: must be assigned in init on all paths.
        match init_body {
            None => {
                // No init and no default → uninitialized.
                violations.push(TypeError {
                    kind: TypeErrorKind::UninitializedStateField {
                        field: field_name.clone(),
                        span: *field_span,
                    },
                    span: *field_span,
                    message: format!(
                        "WF-001: state field `{field_name}` has no default initializer \
                         and no `init` function assigns it"
                    ),
                });
            }
            Some(body) => {
                // Check that the field is assigned on ALL paths through init.
                if !assigned_on_all_paths(body, field_name) {
                    violations.push(TypeError {
                        kind: TypeErrorKind::UninitializedStateField {
                            field: field_name.clone(),
                            span: *field_span,
                        },
                        span: *field_span,
                        message: format!(
                            "WF-001: state field `{field_name}` is not assigned on all \
                             paths through `init` (missing on at least one branch)"
                        ),
                    });
                }
            }
        }
    }

    violations
}

// ─── WF-002: immutable set exactly once in init ───────────────────────────────

/// WF-002 — Every `immutable` field must be assigned exactly once, only inside
/// `init`, on every path through `init`.
///
/// - Zero assignments → reject (`found_assignments: 0`).
/// - More than one on any path → reject (`found_assignments: N`).
/// - Any assignment outside `init` → reject (already caught by the type-checker's
///   mutability check, but WF-002 adds the init-scope guarantee).
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-002`.
fn check_wf002_immutable_once(contract: &TypedContract<'_>) -> Vec<TypeError> {
    let mut violations = Vec::new();

    // Collect immutable field names and their declaration spans.
    let immutables = collect_immutable_fields(contract);
    if immutables.is_empty() {
        return violations;
    }

    // Find the init function body.
    let init_body = find_init_body(contract);

    for (field_name, field_span) in &immutables {
        match init_body {
            None => {
                // No init → immutable never set.
                violations.push(TypeError {
                    kind: TypeErrorKind::ImmutableNotSetOnce {
                        field: field_name.clone(),
                        found_assignments: 0,
                        span: *field_span,
                    },
                    span: *field_span,
                    message: format!(
                        "WF-002: `immutable` field `{field_name}` is never set \
                         (no `init` function found)"
                    ),
                });
            }
            Some(body) => {
                // Count assignments on all paths.
                // "Exactly once on all paths" means:
                //   - min_assignments_on_any_path == 1 AND max_assignments_on_any_path == 1
                let (min_count, max_count) = immutable_assignment_range(body, field_name);

                if min_count == 0 {
                    // Some path has zero assignments.
                    violations.push(TypeError {
                        kind: TypeErrorKind::ImmutableNotSetOnce {
                            field: field_name.clone(),
                            found_assignments: min_count,
                            span: *field_span,
                        },
                        span: *field_span,
                        message: format!(
                            "WF-002: `immutable` field `{field_name}` is not assigned \
                             on all paths through `init`"
                        ),
                    });
                } else if max_count > 1 {
                    // Some path has more than one assignment.
                    violations.push(TypeError {
                        kind: TypeErrorKind::ImmutableNotSetOnce {
                            field: field_name.clone(),
                            found_assignments: max_count,
                            span: *field_span,
                        },
                        span: *field_span,
                        message: format!(
                            "WF-002: `immutable` field `{field_name}` is assigned \
                             {max_count} times on some path through `init` (must be exactly once)"
                        ),
                    });
                }
                // min == max == 1 → exactly once on all paths → OK.
            }
        }

        // Also check for assignments outside init (in other functions).
        // The type-checker's mutability check already catches this, but we
        // cross-reference here for completeness per the spec.
        for func in contract.functions() {
            if func.name == "init" {
                continue;
            }
            if let Some(body) = func.body {
                let count = count_self_field_assignments(body, field_name);
                if count > 0 {
                    violations.push(TypeError {
                        kind: TypeErrorKind::ImmutableNotSetOnce {
                            field: field_name.clone(),
                            found_assignments: count,
                            span: *field_span,
                        },
                        span: *field_span,
                        message: format!(
                            "WF-002: `immutable` field `{field_name}` is assigned \
                             outside `init` (in function `{}`)",
                            func.name
                        ),
                    });
                }
            }
        }
    }

    violations
}

// ─── WF-003: init constructor well-formedness ─────────────────────────────────

/// WF-003 — The `init` constructor must be structurally well-formed.
///
/// Checks three active clauses (all must pass):
/// 1. At most one `init` per contract.
/// 2. Token contracts MUST have an `init` (required for state initialization
///    at deploy time).
/// 3. `init` carries no access-guard annotations (`@onlyOwner`, `@onlyRole`,
///    `@whenNotPaused`). Only `payable` modifier is permitted.
///
/// Note: WF-003 clauses 3a (visibility), 3b (mutability=view/pure), and 4 (return type)
/// are enforced by the parser — parse_init hardcodes visibility=Private, return_type=None,
/// and mutability=Default|Payable only. No WF check needed for those properties.
/// See decisions-log.md DB-A46.
///
/// Note: Clause 5 (registry.register check) retired per decision DB-A48 —
/// registration is auto-injected by codegen for all token standards.
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-003`.
fn check_wf003_init_wellformed(contract: &TypedContract<'_>) -> Vec<TypeError> {
    let mut violations = Vec::new();

    // Collect all init functions (there should be at most one).
    let init_fns: Vec<_> = contract
        .functions()
        .into_iter()
        .filter(|f| f.name == "init")
        .collect();

    // Clause 1: at most one init.
    if init_fns.len() > 1 {
        // Report on the second (duplicate) init's span.
        // Use the span of the second init function.
        let dup_span = init_fns[1]
            .body
            .and_then(|b| b.first())
            .map(stmt_span)
            .unwrap_or_else(|| contract_span(contract));
        violations.push(TypeError {
            kind: TypeErrorKind::MalformedInit {
                reason: "duplicate `init` function — at most one `init` is allowed per contract"
                    .into(),
                span: dup_span,
            },
            span: dup_span,
            message: "WF-003: contract declares more than one `init` function".into(),
        });
        // Still check the first init for other violations.
    }

    // Clause 2: token requires init.
    if contract.is_token() && init_fns.is_empty() {
        let span = contract_span(contract);
        violations.push(TypeError {
            kind: TypeErrorKind::MalformedInit {
                reason: "token contract must declare an `init` function \
                         (required for state initialization at deploy time)"
                    .into(),
                span,
            },
            span,
            message: format!("WF-003: token `{}` has no `init` function", contract.name()),
        });
        // No init to check further — return early for token.
        return violations;
    }

    // Check the first init (if present) for clause 3.
    let Some(init_fn) = init_fns.first() else {
        // No init — for a non-token contract this is fine (WF-001 handles
        // the case where state fields have no default).
        return violations;
    };

    // Clause 3c: no access-guard annotations.
    // Banned: @onlyOwner, @onlyRole, @whenNotPaused (and similar access guards).
    // Clauses 3a (visibility) and 3b (view/pure mutability) are parser-enforced:
    // parse_init hardcodes visibility=Private and only allows mutability=Default|Payable.
    const BANNED_ANNOTATIONS: &[&str] = &["onlyOwner", "onlyRole", "whenNotPaused"];
    for ann in init_fn.annotations {
        if BANNED_ANNOTATIONS.contains(&ann.name.as_str()) {
            let span = ann.span;
            violations.push(TypeError {
                kind: TypeErrorKind::MalformedInit {
                    reason: format!(
                        "`init` must not carry `@{}` — access guards are not permitted \
                         on the constructor (no owner exists at deploy time)",
                        ann.name
                    ),
                    span,
                },
                span,
                message: format!(
                    "WF-003: `init` carries access-guard annotation `@{}`",
                    ann.name
                ),
            });
        }
    }

    // Clause 5 (registry.register check) retired per decision DB-A48 —
    // registration is auto-injected by codegen for all token standards.

    violations
}

// ─── Family B: Control-Flow (WF-004..007) ────────────────────────────────────

// DRY note: WF-004..007 share `walk_expr_for_stmts` — a helper that descends
// into ALL expression-position constructs that carry statement bodies.
// The cfg.rs skeleton (walk_stmts/walk_expr) is the exact model — it recurses
// into every Expr variant that can contain sub-expressions.  Per AGENTS §2,
// the traversal skeleton is shared; the per-node action differs per rule.
//
// Two blockers fixed here vs the previous shallow version:
//
// BLOCKER-1: The old walker only handled MatchBody::Block arms and silently
// skipped MatchBody::Expr arms — so a `break` inside an expression-arm body
// (e.g. `match (x) { _ => if (flag) { break } else { break } }`) was missed.
//
// BLOCKER-2: The old walker did not recurse into sub-expressions (BinOp,
// Ternary, Call args, etc.) — so a `break` inside a nested expression form
// was missed.  The old `walk_stmt_expr_bodies` also did not handle Stmt::Emit,
// Stmt::Assert, Stmt::Revert, or Stmt::Const — those are now covered.

/// Recursively walk ALL sub-expressions of `expr`, calling `on_stmts` for
/// every statement slice found inside `Expr::If_` / `Expr::Match_` bodies at
/// ANY nesting depth.
///
/// Mirrors `cfg.rs::walk_expr` — recurses into ALL expression forms that can
/// carry statement bodies as operands.  Lambda bodies are intentionally NOT
/// descended into: a `break`/`continue`/`_` inside a lambda is a separate
/// scope and must be validated independently.
///
/// This is the shared descent helper used by WF-004..007 to avoid missing
/// violations hidden inside value-position if/match expressions at any depth.
fn walk_expr_for_stmts<F>(expr: &Expr, on_stmts: &mut F)
where
    F: FnMut(&[Stmt]),
{
    match expr {
        // ── Expression-position constructs that carry statement bodies ────────
        Expr::If_ {
            cond, then, else_, ..
        } => {
            // Recurse into the condition — it may itself contain an if/match.
            walk_expr_for_stmts(cond, on_stmts);
            // Deliver the then/else statement slices to the caller.
            on_stmts(then);
            walk_stmt_expr_bodies_slice(then, on_stmts);
            if let Some(else_body) = else_ {
                on_stmts(else_body);
                walk_stmt_expr_bodies_slice(else_body, on_stmts);
            }
        }
        Expr::Match_(scrutinee, arms, _) => {
            // Recurse into the scrutinee — it may contain an if/match.
            walk_expr_for_stmts(scrutinee, on_stmts);
            for arm in arms {
                // Recurse into the arm guard — it may contain an if/match.
                if let Some(guard) = &arm.guard {
                    walk_expr_for_stmts(guard, on_stmts);
                }
                match &arm.body {
                    MatchBody::Block(stmts) => {
                        // BLOCKER-1 fix: was already handled.
                        on_stmts(stmts);
                        walk_stmt_expr_bodies_slice(stmts, on_stmts);
                    }
                    MatchBody::Expr(e) => {
                        // BLOCKER-1 fix: the old walker skipped MatchBody::Expr entirely.
                        walk_expr_for_stmts(e, on_stmts);
                    }
                }
            }
        }

        // ── BLOCKER-2 fix: recurse into all sub-expressions ──────────────────
        // Every expression form that can carry an Expr::If_/Expr::Match_ as a
        // sub-expression must be recursed into.  Mirrors cfg.rs::walk_expr.
        Expr::Binary(_, left, right, _) => {
            walk_expr_for_stmts(left, on_stmts);
            walk_expr_for_stmts(right, on_stmts);
        }
        Expr::Unary(_, inner, _) => walk_expr_for_stmts(inner, on_stmts),
        Expr::Ternary {
            cond, then, else_, ..
        } => {
            walk_expr_for_stmts(cond, on_stmts);
            walk_expr_for_stmts(then, on_stmts);
            walk_expr_for_stmts(else_, on_stmts);
        }
        Expr::Nullish(left, right, _) => {
            walk_expr_for_stmts(left, on_stmts);
            walk_expr_for_stmts(right, on_stmts);
        }
        Expr::Try_(inner, _) => walk_expr_for_stmts(inner, on_stmts),
        Expr::Cast { expr, .. } => walk_expr_for_stmts(expr, on_stmts),
        Expr::Assign_(target, _, val, _) => {
            walk_expr_for_stmts(target, on_stmts);
            walk_expr_for_stmts(val, on_stmts);
        }
        Expr::Member(base, _, _) => walk_expr_for_stmts(base, on_stmts),
        Expr::Index(base, idx, _) => {
            walk_expr_for_stmts(base, on_stmts);
            walk_expr_for_stmts(idx, on_stmts);
        }
        Expr::Call {
            callee, opts, args, ..
        } => {
            walk_expr_for_stmts(callee, on_stmts);
            if let Some(o) = opts {
                if let Some(v) = &o.value {
                    walk_expr_for_stmts(v, on_stmts);
                }
                if let Some(g) = &o.gas {
                    walk_expr_for_stmts(g, on_stmts);
                }
                if let Some(s) = &o.salt {
                    walk_expr_for_stmts(s, on_stmts);
                }
            }
            for arg in args {
                let e = match arg {
                    crate::parser::CallArg::Positional(e) | crate::parser::CallArg::Named(_, e) => {
                        e
                    }
                };
                walk_expr_for_stmts(e, on_stmts);
            }
        }
        Expr::New { opts, args, .. } => {
            if let Some(o) = opts {
                if let Some(v) = &o.value {
                    walk_expr_for_stmts(v, on_stmts);
                }
                if let Some(g) = &o.gas {
                    walk_expr_for_stmts(g, on_stmts);
                }
                if let Some(s) = &o.salt {
                    walk_expr_for_stmts(s, on_stmts);
                }
            }
            for arg in args {
                let e = match arg {
                    crate::parser::CallArg::Positional(e) | crate::parser::CallArg::Named(_, e) => {
                        e
                    }
                };
                walk_expr_for_stmts(e, on_stmts);
            }
        }
        Expr::Tuple(elems, _) | Expr::Array(elems, _) => {
            for e in elems {
                walk_expr_for_stmts(e, on_stmts);
            }
        }
        Expr::Struct_ { fields, spread, .. } => {
            for (_, e) in fields {
                walk_expr_for_stmts(e, on_stmts);
            }
            if let Some(s) = spread {
                walk_expr_for_stmts(s, on_stmts);
            }
        }
        Expr::Template(segments, _) => {
            for seg in segments {
                if let crate::parser::ast::TemplateExprSegment::Interpolation(e) = seg {
                    walk_expr_for_stmts(e, on_stmts);
                }
            }
        }
        // Lambda bodies are a separate scope — do NOT descend into them.
        // Literal / Ident: leaf nodes with no sub-expressions.
        _ => {}
    }
}

/// Walk a statement slice and call `walk_expr_for_stmts` on every expression
/// that can carry a nested `Expr::If_` / `Expr::Match_` body.
///
/// This is the companion to `walk_expr_for_stmts` — together they ensure that
/// WF-004..007 walkers never miss a violation hidden inside a value-position
/// `if`/`match` expression at any nesting depth.
///
/// Covers ALL statement variants that hold expressions in value position,
/// including `Stmt::Emit`, `Stmt::Assert`, `Stmt::Revert`, and `Stmt::Const`
/// which the previous `walk_stmt_expr_bodies` omitted (BLOCKER-2 fix).
fn walk_stmt_expr_bodies_slice<F>(stmts: &[Stmt], on_stmts: &mut F)
where
    F: FnMut(&[Stmt]),
{
    for stmt in stmts {
        walk_stmt_expr_bodies(stmt, on_stmts);
    }
}

/// Descend into any expression-position constructs within a single `stmt` that
/// carry statement bodies, calling `on_stmts` for each reachable body slice.
///
/// Covers ALL statement variants that hold expressions in value position.
fn walk_stmt_expr_bodies<F>(stmt: &Stmt, on_stmts: &mut F)
where
    F: FnMut(&[Stmt]),
{
    match stmt {
        Stmt::Let { expr, .. } => walk_expr_for_stmts(expr, on_stmts),
        Stmt::Assign { value, .. } => walk_expr_for_stmts(value, on_stmts),
        Stmt::Expr(expr, _) => walk_expr_for_stmts(expr, on_stmts),
        Stmt::Return(Some(expr), _) => walk_expr_for_stmts(expr, on_stmts),
        // BLOCKER-2 fix: these were previously omitted.
        Stmt::Emit { fields, .. } => {
            for (_, e) in fields {
                walk_expr_for_stmts(e, on_stmts);
            }
        }
        Stmt::Assert { cond, msg, .. } => {
            walk_expr_for_stmts(cond, on_stmts);
            if let Some(m) = msg {
                walk_expr_for_stmts(m, on_stmts);
            }
        }
        Stmt::Revert { msg: Some(m), .. } => walk_expr_for_stmts(m, on_stmts),
        Stmt::Const(c) => walk_expr_for_stmts(&c.value, on_stmts),
        // All other statement variants either carry no expression or carry
        // sub-statements that are already handled by the caller's own match.
        _ => {}
    }
}

/// Check all Family B rules (WF-004, WF-005, WF-006, WF-007) for every
/// contract/token in the typed AST.
///
/// Collect-all: never returns early.
fn check_family_b(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();
    for contract in typed_ast.contracts() {
        violations.extend(check_wf004_return_completeness(&contract, typed_ast));
        violations.extend(check_wf005_match_exhaustiveness(&contract, typed_ast));
        violations.extend(check_wf006_placeholder_scope(&contract));
        violations.extend(check_wf007_loop_control_flow(&contract));
    }
    violations
}

// ─── WF-004: Return-path completeness ────────────────────────────────────────

/// WF-004 — Every function with a non-unit return type must have a `return`,
/// `revert`, or infinite `loop {}` (no `break`) on every path through its body.
///
/// Falling off the end of a non-unit function produces an invalid WASM module
/// (stack-type mismatch).
///
/// ## DRY note
///
/// This uses the same structural path-analysis pattern as `assigned_on_all_paths`
/// (WF-001) already in this module — the correct DRY move is to follow the same
/// template rather than calling into `cfg.rs`, which solves a different problem
/// (state-effect tracking, not return-path completeness).
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-004`.
fn check_wf004_return_completeness(
    contract: &TypedContract<'_>,
    typed_ast: &TypedAst,
) -> Vec<TypeError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        // Only check functions with a non-unit return type.
        // `None` return_type means the symbol wasn't resolved — skip defensively.
        let is_non_unit = match &func.return_type {
            Some(ResolvedType::Unit) | None => false,
            Some(_) => true,
        };
        if !is_non_unit {
            continue;
        }

        // Interface signatures have no body — skip.
        let Some(body) = func.body else {
            continue;
        };

        if !path_always_terminates(body) {
            // Use the function's symbol span for the error location.
            let span = func
                .symbol_id
                .and_then(|id| typed_ast.symbol(id))
                .map(|s| s.decl_span)
                .unwrap_or_else(|| crate::lexer::token::Span::at(1, 1, 0));

            violations.push(TypeError {
                kind: TypeErrorKind::MissingReturn {
                    func: func.name.to_owned(),
                    span,
                },
                span,
                message: format!(
                    "WF-004: function `{}` has a non-unit return type but not all \
                     paths end in `return`, `revert`, or an infinite `loop`",
                    func.name
                ),
            });
        }
    }

    violations
}

/// Returns `true` if every path through `stmts` is guaranteed to terminate via
/// `return`, `revert`, or an infinite `loop {}` (a `loop` with no `break`).
///
/// This is a conservative structural analysis — it does not build a full
/// dominator tree.  The approximation is sound for the spec's decidable-exact
/// requirement: it accepts exactly the programs the spec says are well-formed.
///
/// ## Termination rules
///
/// - `Stmt::Return(_)` → terminates ✓
/// - `Stmt::Revert { .. }` → terminates ✓ (always panics)
/// - `Stmt::Loop { body }` with no `Stmt::Break` anywhere in `body` → terminates ✓
/// - `Stmt::If { then, else_: Some(else_body) }` → terminates iff BOTH branches terminate
/// - `Stmt::If { else_: None }` → does NOT terminate (else path falls off)
/// - `Stmt::Match { arms }` → terminates iff ALL arms terminate
/// - All other statements → do not terminate on their own; continue scanning
fn path_always_terminates(stmts: &[Stmt]) -> bool {
    for stmt in stmts {
        match stmt {
            // Unconditional terminators.
            Stmt::Return(_, _) => return true,
            Stmt::Revert { .. } => return true,

            // `loop {}` with no `break` inside is an infinite loop — terminates.
            // `loop {}` with a `break` is NOT a terminator (the break path falls off).
            Stmt::Loop { body, .. } => {
                if !body_contains_break(body) {
                    return true;
                }
                // Loop with break: not a terminator; continue scanning.
            }

            // `if/else`: both branches must terminate.
            // `if` without `else`: the else path falls off — not a terminator.
            Stmt::If {
                then,
                else_: Some(else_body),
                ..
            } => {
                if path_always_terminates(then) && path_always_terminates(else_body) {
                    return true;
                }
                // One or both branches don't terminate — continue scanning.
            }
            Stmt::If { else_: None, .. } => {
                // No else branch — cannot guarantee termination.
            }

            // `match`: all arms must terminate.
            Stmt::Match { arms, .. } => {
                if !arms.is_empty()
                    && arms.iter().all(|arm| match &arm.body {
                        MatchBody::Block(body) => path_always_terminates(body),
                        // Expression arm — cannot contain a return/revert statement.
                        MatchBody::Expr(_) => false,
                    })
                {
                    return true;
                }
                // Not all arms terminate — continue scanning.
            }

            // `try/catch`: both branches must terminate.
            Stmt::Try {
                body, catch_body, ..
            } => {
                if path_always_terminates(body) && path_always_terminates(catch_body) {
                    return true;
                }
            }

            // `unchecked { body }`: transparent scope — check the inner body.
            Stmt::Unchecked(body, _) if path_always_terminates(body) => {
                return true;
            }
            Stmt::Unchecked(_, _) => {}

            // `while`/`for`: may not execute — not a terminator.
            // All other statements: not terminators.
            _ => {}
        }
    }
    false
}

/// Returns `true` if `stmts` contains a `Stmt::Break` at any nesting depth
/// (including inside nested loops — we are checking whether the outer `loop`
/// can be exited, so any `break` at any depth counts).
///
/// Note: this is intentionally conservative — a `break` inside a nested
/// `for`/`while`/`loop` technically exits the inner loop, not the outer one.
/// However, for WF-004 purposes, the presence of ANY `break` in the body
/// means the outer `loop` is not provably infinite, so we conservatively
/// treat it as non-terminating.  This matches the spec's decidable-exact
/// requirement (§30 WF-004).
///
/// Also descends into expression-position `Expr::If_`/`Expr::Match_` bodies
/// via `walk_stmt_expr_bodies` so that a `break` inside a value-position
/// if/match is correctly detected.
fn body_contains_break(stmts: &[Stmt]) -> bool {
    for stmt in stmts {
        match stmt {
            Stmt::Break(_) => return true,
            Stmt::If { then, else_, .. } => {
                if body_contains_break(then) {
                    return true;
                }
                if let Some(b) = else_ {
                    if body_contains_break(b) {
                        return true;
                    }
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let MatchBody::Block(body) = &arm.body {
                        if body_contains_break(body) {
                            return true;
                        }
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                if body_contains_break(body) {
                    return true;
                }
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                if body_contains_break(body) || body_contains_break(catch_body) {
                    return true;
                }
            }
            Stmt::Unchecked(body, _) if body_contains_break(body) => {
                return true;
            }
            Stmt::Unchecked(_, _) => {}
            _ => {}
        }
        // Also check expression-position if/match bodies within this statement.
        let mut found = false;
        walk_stmt_expr_bodies(stmt, &mut |body| {
            if !found && body_contains_break(body) {
                found = true;
            }
        });
        if found {
            return true;
        }
    }
    false
}

// ─── WF-005: match exhaustiveness ────────────────────────────────────────────

/// WF-005 — Every `match` over an enum, bool, Option, or Result must cover all
/// variants, or have a wildcard `_` arm.
///
/// Uses `EnumSig.variants` (already computed by the resolver) to get the
/// canonical variant list.  A missing variant with no `_` arm → reject.
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-005`.
fn check_wf005_match_exhaustiveness(
    contract: &TypedContract<'_>,
    typed_ast: &TypedAst,
) -> Vec<TypeError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        let Some(body) = func.body else {
            continue;
        };
        check_wf005_in_stmts(body, typed_ast, &mut violations);
    }

    // Also check modifier bodies.
    for member in contract.members() {
        if let ContractMember::Modifier(md) = member {
            check_wf005_in_stmts(&md.body, typed_ast, &mut violations);
        }
    }

    violations
}

/// Recursively walk `stmts` and check every `Stmt::Match` and `Expr::Match_`
/// (in expression position) for exhaustiveness.
///
/// Uses `walk_stmt_expr_bodies` to descend into value-position `Expr::If_` and
/// `Expr::Match_` bodies — the cases the original Stmt-only walker missed.
fn check_wf005_in_stmts(stmts: &[Stmt], typed_ast: &TypedAst, out: &mut Vec<TypeError>) {
    for stmt in stmts {
        match stmt {
            Stmt::Match { expr, arms, span } => {
                // Check this match statement.
                check_wf005_match(expr, arms, *span, typed_ast, out);
                // Recurse into arm bodies.
                for arm in arms {
                    if let MatchBody::Block(body) = &arm.body {
                        check_wf005_in_stmts(body, typed_ast, out);
                    }
                }
            }
            Stmt::If { then, else_, .. } => {
                check_wf005_in_stmts(then, typed_ast, out);
                if let Some(b) = else_ {
                    check_wf005_in_stmts(b, typed_ast, out);
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                check_wf005_in_stmts(body, typed_ast, out);
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                check_wf005_in_stmts(body, typed_ast, out);
                check_wf005_in_stmts(catch_body, typed_ast, out);
            }
            Stmt::Unchecked(body, _) => {
                check_wf005_in_stmts(body, typed_ast, out);
            }
            _ => {}
        }
        // Also check expression-position if/match bodies within this statement.
        // For Expr::Match_ specifically, we must check the match itself for
        // exhaustiveness AND recurse into its arm bodies.
        check_wf005_in_stmt_exprs(stmt, typed_ast, out);
    }
}

/// Check expression-position `Expr::If_` and `Expr::Match_` bodies within a
/// single statement for WF-005 exhaustiveness violations.
///
/// For `Expr::Match_`: checks the match expression itself for exhaustiveness,
/// then recurses into each arm body.
/// For `Expr::If_`: recurses into the then/else bodies (no exhaustiveness check
/// on the if itself — that is WF-004's concern).
fn check_wf005_in_stmt_exprs(stmt: &Stmt, typed_ast: &TypedAst, out: &mut Vec<TypeError>) {
    // Extract the expression held by this statement (if any).
    let expr = match stmt {
        Stmt::Let { expr, .. } => expr,
        Stmt::Assign { value, .. } => value,
        Stmt::Expr(expr, _) => expr,
        Stmt::Return(Some(expr), _) => expr,
        // Other statement variants are handled by the caller's match above.
        _ => return,
    };
    check_wf005_in_expr(expr, typed_ast, out);
}

/// Recursively check an expression for WF-005 violations, descending into
/// `Expr::If_` and `Expr::Match_` bodies.
fn check_wf005_in_expr(expr: &Expr, typed_ast: &TypedAst, out: &mut Vec<TypeError>) {
    match expr {
        Expr::Match_(matched_expr, arms, span) => {
            // Check this expression-position match for exhaustiveness.
            check_wf005_match(matched_expr, arms, *span, typed_ast, out);
            // Recurse into arm bodies.
            for arm in arms {
                match &arm.body {
                    MatchBody::Block(body) => check_wf005_in_stmts(body, typed_ast, out),
                    MatchBody::Expr(e) => check_wf005_in_expr(e, typed_ast, out),
                }
            }
        }
        Expr::If_ { then, else_, .. } => {
            check_wf005_in_stmts(then, typed_ast, out);
            if let Some(else_body) = else_ {
                check_wf005_in_stmts(else_body, typed_ast, out);
            }
        }
        // Other expression forms do not carry statement bodies — no descent needed.
        _ => {}
    }
}

/// Check a single `match` statement for exhaustiveness.
///
/// Determines the variant set from the matched expression's resolved type:
/// - `bool` → `["true", "false"]`
/// - `Option<T>` → `["Some", "None"]`
/// - `Result<T, E>` → `["Ok", "Err"]`
/// - Named enum → variants from `EnumSig.variants`
///
/// If a wildcard `_` arm is present, the match is always exhaustive.
fn check_wf005_match(
    expr: &Expr,
    arms: &[crate::parser::MatchArm],
    span: crate::lexer::token::Span,
    typed_ast: &TypedAst,
    out: &mut Vec<TypeError>,
) {
    // If any arm is a wildcard, the match is exhaustive — nothing to check.
    let has_wildcard = arms
        .iter()
        .any(|arm| matches!(arm.pattern, Pattern::Wildcard(_)));
    if has_wildcard {
        return;
    }

    // Determine the expected variant set from the matched expression's type.
    let expr_span = expr_span(expr);
    let Some(resolved_ty) = typed_ast.type_of(&expr_span) else {
        // Type not resolved — skip (defensive; should not occur for well-typed programs).
        return;
    };

    let expected_variants: Vec<String> = match resolved_ty {
        ResolvedType::Bool => vec!["true".into(), "false".into()],
        ResolvedType::Option_(_) => vec!["Some".into(), "None".into()],
        ResolvedType::Result_(_, _) => vec!["Ok".into(), "Err".into()],
        ResolvedType::Named(id, _) => {
            // Look up the EnumSig for this named type.
            match typed_ast.sig(*id) {
                Some(SymbolSig::Enum(enum_sig)) => enum_sig
                    .variants
                    .iter()
                    .map(|(name, _)| name.clone())
                    .collect(),
                _ => {
                    // Not an enum — WF-005 does not apply to non-enum named types.
                    return;
                }
            }
        }
        // All other types (integers, strings, etc.) — WF-005 does not apply.
        _ => return,
    };

    // Collect the variant names covered by the arms.
    // An `EnumVariant { name }` pattern covers that variant.
    // A `Literal(true)` / `Literal(false)` pattern covers the bool variants.
    // An `Ident` pattern that matches a variant name also covers it.
    let covered: std::collections::BTreeSet<String> = arms
        .iter()
        .filter_map(|arm| variant_name_from_pattern(&arm.pattern))
        .collect();

    // Find missing variants.
    let missing: Vec<String> = expected_variants
        .into_iter()
        .filter(|v| !covered.contains(v))
        .collect();

    if !missing.is_empty() {
        out.push(TypeError {
            kind: TypeErrorKind::NonExhaustiveMatch {
                missing: missing.clone(),
                span,
            },
            span,
            message: format!(
                "WF-005: non-exhaustive match — missing variants: {}",
                missing.join(", ")
            ),
        });
    }
}

/// Extract the variant name from a pattern, if it names a specific variant.
///
/// Returns `Some(name)` for:
/// - `Pattern::EnumVariant { name }` — the variant name
/// - `Pattern::Literal(Literal::Bool(true))` → `"true"`
/// - `Pattern::Literal(Literal::Bool(false))` → `"false"`
/// - `Pattern::Ident(name)` — treated as a variant name (e.g. `None`)
///
/// Returns `None` for wildcard, tuple, struct, rest patterns.
fn variant_name_from_pattern(pattern: &Pattern) -> Option<String> {
    match pattern {
        Pattern::EnumVariant { name, .. } => Some(name.clone()),
        Pattern::Ident(name, _) => Some(name.clone()),
        Pattern::Literal(lit, _) => {
            // Bool literals map to "true"/"false" variant names.
            if let crate::parser::Literal::Bool(b) = lit {
                Some(if *b { "true".into() } else { "false".into() })
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract the span from an expression (for type lookup in WF-005).
fn expr_span(expr: &Expr) -> crate::lexer::token::Span {
    match expr {
        Expr::Literal(_, s)
        | Expr::Ident(_, s)
        | Expr::Tuple(_, s)
        | Expr::Array(_, s)
        | Expr::Call { span: s, .. }
        | Expr::Index(_, _, s)
        | Expr::Member(_, _, s)
        | Expr::Unary(_, _, s)
        | Expr::Binary(_, _, _, s)
        | Expr::Assign_(_, _, _, s)
        | Expr::Ternary { span: s, .. }
        | Expr::Cast { span: s, .. }
        | Expr::New { span: s, .. }
        | Expr::Try_(_, s)
        | Expr::Nullish(_, _, s)
        | Expr::If_ { span: s, .. }
        | Expr::Match_(_, _, s)
        | Expr::Lambda { span: s, .. }
        | Expr::Template(_, s) => *s,
        Expr::Struct_ { span: s, .. } => *s,
    }
}

// ─── WF-006: placeholder only in modifier bodies ──────────────────────────────

/// WF-006 — The `_` placeholder statement (`Stmt::Placeholder`) is only valid
/// inside a `modifier` body, exactly once at the top level.
///
/// A stray `_` in a regular function body has no codegen target.
/// Two `_` in the same modifier body is also rejected.
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-006`.
fn check_wf006_placeholder_scope(contract: &TypedContract<'_>) -> Vec<TypeError> {
    let mut violations = Vec::new();

    // Check all non-modifier function bodies — any Placeholder is invalid.
    for func in contract.functions() {
        let Some(body) = func.body else {
            continue;
        };
        check_wf006_in_non_modifier_body(body, &mut violations);
    }

    // Check modifier bodies — exactly one top-level Placeholder required.
    for member in contract.members() {
        if let ContractMember::Modifier(md) = member {
            // Count top-level Placeholder statements.
            let top_level_count = md
                .body
                .iter()
                .filter(|s| matches!(s, Stmt::Placeholder(_)))
                .count();

            if top_level_count == 0 {
                // No `_` in modifier — this is a WF-006 violation (modifier must have `_`).
                // Note: the spec says `_` is only valid IN a modifier; a modifier without
                // `_` is a separate concern (codegen would have no splice point).
                // Per spec §30 WF-006, we only reject `_` OUTSIDE modifiers.
                // A modifier missing `_` is not a WF-006 violation — skip.
            } else if top_level_count > 1 {
                // Two or more `_` in the same modifier — reject.
                // Report on the second occurrence.
                let second_span = md
                    .body
                    .iter()
                    .filter_map(|s| {
                        if let Stmt::Placeholder(sp) = s {
                            Some(*sp)
                        } else {
                            None
                        }
                    })
                    .nth(1)
                    .unwrap_or(md.span);
                violations.push(TypeError {
                    kind: TypeErrorKind::PlaceholderOutsideModifier { span: second_span },
                    span: second_span,
                    message: format!(
                        "WF-006: modifier `{}` contains more than one `_` placeholder \
                         (exactly one is required)",
                        md.name
                    ),
                });
            }

            // Also check nested bodies inside the modifier for stray Placeholders.
            // (A `_` nested inside an `if` inside a modifier is also invalid per spec §30 WF-006
            // which requires `_` at top level only.)
            check_wf006_nested_in_modifier(&md.body, &mut violations);
        }
    }

    violations
}

/// Walk `stmts` (a non-modifier body) and report any `Stmt::Placeholder` found.
///
/// Recurses into all nested scopes — a `_` anywhere in a non-modifier body is invalid.
/// Also descends into expression-position `Expr::If_`/`Expr::Match_` bodies via
/// `walk_stmt_expr_bodies` so that a `_` inside a value-position if/match is caught.
fn check_wf006_in_non_modifier_body(stmts: &[Stmt], out: &mut Vec<TypeError>) {
    for stmt in stmts {
        match stmt {
            Stmt::Placeholder(span) => {
                out.push(TypeError {
                    kind: TypeErrorKind::PlaceholderOutsideModifier { span: *span },
                    span: *span,
                    message: "WF-006: `_` placeholder is only valid inside a modifier body".into(),
                });
            }
            Stmt::If { then, else_, .. } => {
                check_wf006_in_non_modifier_body(then, out);
                if let Some(b) = else_ {
                    check_wf006_in_non_modifier_body(b, out);
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let MatchBody::Block(body) = &arm.body {
                        check_wf006_in_non_modifier_body(body, out);
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                check_wf006_in_non_modifier_body(body, out);
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                check_wf006_in_non_modifier_body(body, out);
                check_wf006_in_non_modifier_body(catch_body, out);
            }
            Stmt::Unchecked(body, _) => {
                check_wf006_in_non_modifier_body(body, out);
            }
            _ => {}
        }
        // Also descend into expression-position if/match bodies within this statement.
        walk_stmt_expr_bodies(stmt, &mut |body| {
            check_wf006_in_non_modifier_body(body, out);
        });
    }
}

/// Walk a modifier body and report any `Stmt::Placeholder` found in NESTED
/// scopes (not at the top level — those are already counted by the caller).
///
/// Per spec §30 WF-006, `_` must appear at the top level of the modifier body,
/// not nested inside an `if`/`match`/loop.
///
/// Also descends into expression-position `Expr::If_`/`Expr::Match_` bodies via
/// `walk_stmt_expr_bodies` so that a `_` inside a value-position if/match is caught.
fn check_wf006_nested_in_modifier(stmts: &[Stmt], out: &mut Vec<TypeError>) {
    for stmt in stmts {
        match stmt {
            // Top-level Placeholder in modifier — valid (already counted by caller).
            Stmt::Placeholder(_) => {}
            Stmt::If { then, else_, .. } => {
                // Inside an if inside a modifier — any Placeholder here is invalid.
                check_wf006_in_non_modifier_body(then, out);
                if let Some(b) = else_ {
                    check_wf006_in_non_modifier_body(b, out);
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let MatchBody::Block(body) = &arm.body {
                        check_wf006_in_non_modifier_body(body, out);
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                check_wf006_in_non_modifier_body(body, out);
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                check_wf006_in_non_modifier_body(body, out);
                check_wf006_in_non_modifier_body(catch_body, out);
            }
            Stmt::Unchecked(body, _) => {
                check_wf006_in_non_modifier_body(body, out);
            }
            _ => {}
        }
        // Also descend into expression-position if/match bodies within this statement.
        // Top-level Placeholder is already handled above; nested ones are invalid.
        walk_stmt_expr_bodies(stmt, &mut |body| {
            check_wf006_in_non_modifier_body(body, out);
        });
    }
}

// ─── WF-007: break/continue only inside loops ─────────────────────────────────

/// WF-007 — `break` and `continue` are only valid inside a `for`/`while`/`loop`
/// body.  A `break`/`continue` outside any loop → reject.
///
/// Uses a `loop_depth` counter: incremented on entering a loop, decremented on
/// exit.  Any `Break`/`Continue` with `loop_depth == 0` is a violation.
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-007`.
fn check_wf007_loop_control_flow(contract: &TypedContract<'_>) -> Vec<TypeError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        let Some(body) = func.body else {
            continue;
        };
        let mut checker = Wf007Checker {
            loop_depth: 0,
            out: Vec::new(),
        };
        checker.visit_stmts(body);
        violations.extend(checker.out);
    }

    // Also check modifier bodies.
    for member in contract.members() {
        if let ContractMember::Modifier(md) = member {
            let mut checker = Wf007Checker {
                loop_depth: 0,
                out: Vec::new(),
            };
            checker.visit_stmts(&md.body);
            violations.extend(checker.out);
        }
    }

    violations
}

// ─── WF-007 Visitor ──────────────────────────────────────────────────────────

/// Walks a function body tracking loop nesting depth.
///
/// `loop_depth` is incremented on entry to each loop statement and decremented
/// on exit.  [`visit_stmt`] intercepts `Break`/`Continue` to check the depth,
/// and manages the depth counter around loop bodies.  The canonical [`walk_stmt`]
/// handles all structural recursion including expression-position `Expr::If_`/
/// `Expr::Match_` bodies — no separate `walk_stmt_expr_bodies` call needed.
struct Wf007Checker {
    loop_depth: usize,
    out: Vec<TypeError>,
}

impl Visitor for Wf007Checker {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        // Check break/continue at current depth before recursion.
        match stmt {
            Stmt::Break(span) if self.loop_depth == 0 => {
                self.out.push(TypeError {
                    kind: TypeErrorKind::ControlFlowOutsideLoop {
                        kind: "break".into(),
                        span: *span,
                    },
                    span: *span,
                    message: "`break` used outside of a loop body".into(),
                });
            }
            Stmt::Continue(span) if self.loop_depth == 0 => {
                self.out.push(TypeError {
                    kind: TypeErrorKind::ControlFlowOutsideLoop {
                        kind: "continue".into(),
                        span: *span,
                    },
                    span: *span,
                    message: "`continue` used outside of a loop body".into(),
                });
            }
            _ => {}
        }
        // Manage depth for loop statements: increment before recursion, decrement after.
        let is_loop = matches!(
            stmt,
            Stmt::While { .. } | Stmt::For { .. } | Stmt::Loop { .. }
        );
        if is_loop {
            self.loop_depth += 1;
        }
        walk_stmt(self, stmt);
        if is_loop {
            self.loop_depth -= 1;
        }
    }
}

// ─── AST-walking helpers ──────────────────────────────────────────────────────

/// Collect raw state fields (name, span, has_default) from the contract's AST members.
///
/// Returns only non-immutable state fields (from `state {}` blocks).
/// Immutable fields are handled by WF-002.
///
/// Map, FastMap, and Set fields are treated as having an implicit default
/// (they are always initialized as empty collections at deploy time) and
/// therefore never trigger WF-001.
fn collect_raw_state_fields(
    contract: &TypedContract<'_>,
) -> Vec<(String, crate::lexer::token::Span, bool)> {
    let mut out = Vec::new();
    for member in contract.members() {
        if let ContractMember::State(block) = member {
            for field in &block.fields {
                // Map/FastMap/Set are implicitly initialized as empty — treat as defaulted.
                let implicitly_defaulted = matches!(
                    &field.ty,
                    Type::Map(_, _) | Type::FastMap(_, _) | Type::Set(_)
                );
                let has_default = field.default.is_some() || implicitly_defaulted;
                out.push((field.name.clone(), field.span, has_default));
            }
        }
    }
    out
}

/// Collect immutable field names and their declaration spans.
fn collect_immutable_fields(
    contract: &TypedContract<'_>,
) -> Vec<(String, crate::lexer::token::Span)> {
    let mut out = Vec::new();
    for member in contract.members() {
        if let ContractMember::Immutable(imm) = member {
            out.push((imm.name.clone(), imm.span));
        }
    }
    out
}

/// Find the body of the `init` function, if one exists.
///
/// Returns `None` if no `init` function is declared, or if the init has no body
/// (interface signature — should not occur for contracts).
fn find_init_body<'a>(contract: &'a TypedContract<'a>) -> Option<&'a [Stmt]> {
    for member in contract.members() {
        if let ContractMember::Function(f) = member {
            if f.name == "init" {
                return f.body.as_deref();
            }
        }
    }
    None
}

/// Get a representative span for the contract (used when we need a span for
/// a contract-level error but don't have a more specific location).
fn contract_span(contract: &TypedContract<'_>) -> crate::lexer::token::Span {
    let name = contract.name();
    let typed_ast = contract.typed_ast();
    for item in &typed_ast.ast.items {
        match item {
            crate::parser::ast::Item::Contract(c) if c.name == name => return c.span,
            crate::parser::ast::Item::Token_(t) if t.name == name => return t.span,
            _ => {}
        }
    }
    // Defensive fallback.
    crate::lexer::token::Span::at(1, 1, 0)
}

/// Extract a span from a statement (for error reporting).
fn stmt_span(stmt: &Stmt) -> crate::lexer::token::Span {
    match stmt {
        Stmt::Let { span, .. }
        | Stmt::Assign { span, .. }
        | Stmt::If { span, .. }
        | Stmt::Match { span, .. }
        | Stmt::For { span, .. }
        | Stmt::While { span, .. }
        | Stmt::Loop { span, .. }
        | Stmt::Emit { span, .. }
        | Stmt::Assert { span, .. }
        | Stmt::Revert { span, .. }
        | Stmt::Try { span, .. } => *span,
        Stmt::Return(_, span)
        | Stmt::Break(span)
        | Stmt::Continue(span)
        | Stmt::Placeholder(span) => *span,
        Stmt::Unchecked(_, span) | Stmt::Expr(_, span) => *span,
        Stmt::Const(c) => c.span,
    }
}

// ─── Path-dominance helpers (WF-001) ─────────────────────────────────────────

/// Returns `true` if `self.field_name = …` is assigned on **all** paths through `stmts`.
///
/// "All paths" means:
/// - A top-level assignment to `self.field_name` is found (dominates everything below), OR
/// - Every `if/else` branch assigns it on all paths (both branches must assign), OR
/// - Every `match` arm assigns it on all paths.
///
/// Assignments inside `while`/`for`/`loop` are NOT counted as dominating
/// (the loop may not execute).
///
/// This is a conservative structural approximation — it does not build a full
/// dominator tree.  Documented per AGENTS §solution-integrity.
fn assigned_on_all_paths(stmts: &[Stmt], field_name: &str) -> bool {
    for stmt in stmts {
        match stmt {
            // Direct top-level assignment to self.field_name — dominates.
            Stmt::Assign {
                target,
                op: AssignOp::Assign,
                ..
            } if is_self_field_target(target, field_name) => {
                return true;
            }
            // Expression-statement assignment (Expr::Assign_ wrapped in Stmt::Expr).
            Stmt::Expr(Expr::Assign_(target, AssignOp::Assign, _, _), _)
                if is_self_field_target(target, field_name) =>
            {
                return true;
            }
            // if/else: both branches must assign on all paths.
            // if without else: cannot guarantee assignment on the else path.
            Stmt::If {
                then,
                else_: Some(else_body),
                ..
            } if assigned_on_all_paths(then, field_name)
                && assigned_on_all_paths(else_body, field_name) =>
            {
                return true;
            }
            Stmt::If { .. } => {}
            // match: all arms must assign on all paths.
            // NOTE: guarded arms (pat if cond => ...) are treated as unconditionally
            // executing when their pattern matches. This is sound only because a match
            // where all arms could be skipped by guards would be non-exhaustive —
            // caught by WF-005. If WF-001 ever runs without WF-005, revisit.
            Stmt::Match { arms, .. } => {
                if !arms.is_empty()
                    && arms.iter().all(|arm| {
                        if let crate::parser::MatchBody::Block(body) = &arm.body {
                            assigned_on_all_paths(body, field_name)
                        } else {
                            // Expr arm — cannot contain an assignment statement.
                            false
                        }
                    })
                {
                    return true;
                }
            }
            // Loops: do not count — loop body may not execute.
            Stmt::While { .. } | Stmt::For { .. } | Stmt::Loop { .. } => {}
            // try/catch: both branches must assign.
            Stmt::Try {
                body, catch_body, ..
            } => {
                if assigned_on_all_paths(body, field_name)
                    && assigned_on_all_paths(catch_body, field_name)
                {
                    return true;
                }
            }
            // unchecked block: treat as a transparent scope.
            Stmt::Unchecked(body, _) if assigned_on_all_paths(body, field_name) => {
                return true;
            }
            Stmt::Unchecked(_, _) => {}
            _ => {}
        }
    }
    false
}

/// Returns `true` if `expr` is `self.field_name` (a member access on `self`).
fn is_self_field_target(expr: &Expr, field_name: &str) -> bool {
    matches!(expr, Expr::Member(obj, f, _) if is_self_expr(obj) && f == field_name)
}

/// Returns `true` if `expr` is the identifier `self`.
fn is_self_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

// ─── Assignment-count helpers (WF-002) ───────────────────────────────────────

/// Returns `(min_count, max_count)` of `self.field_name = …` assignments
/// across all paths through `stmts`.
///
/// - `min_count`: the minimum number of assignments on any path (worst case for
///   "never set" detection).
/// - `max_count`: the maximum number of assignments on any path (worst case for
///   "set multiple times" detection).
///
/// Top-level assignments contribute 1 to both min and max.
/// `if/else` branches: min = min(then_min, else_min), max = max(then_max, else_max).
/// `if` without `else`: min = 0 (else path has 0), max = then_max.
/// Loops: min = 0 (may not execute), max = loop_max (may execute many times,
///   but we cap at 1 for structural analysis — a loop body is not a valid
///   "exactly once" guarantee).
fn immutable_assignment_range(stmts: &[Stmt], field_name: &str) -> (usize, usize) {
    let mut total_min = 0usize;
    let mut total_max = 0usize;

    for stmt in stmts {
        match stmt {
            // Direct top-level assignment.
            Stmt::Assign {
                target,
                op: AssignOp::Assign,
                ..
            } if is_self_field_target(target, field_name) => {
                total_min = total_min.saturating_add(1);
                total_max = total_max.saturating_add(1);
            }
            Stmt::Expr(Expr::Assign_(target, AssignOp::Assign, _, _), _)
                if is_self_field_target(target, field_name) =>
            {
                total_min = total_min.saturating_add(1);
                total_max = total_max.saturating_add(1);
            }
            // if/else: min = min(then, else), max = max(then, else).
            Stmt::If { then, else_, .. } => {
                let (then_min, then_max) = immutable_assignment_range(then, field_name);
                let (else_min, else_max) = else_
                    .as_ref()
                    .map(|b| immutable_assignment_range(b, field_name))
                    .unwrap_or((0, 0));
                total_min = total_min.saturating_add(then_min.min(else_min));
                total_max = total_max.saturating_add(then_max.max(else_max));
            }
            // match: min = min across arms, max = max across arms.
            Stmt::Match { arms, .. } => {
                if arms.is_empty() {
                    continue;
                }
                let mut arm_min = usize::MAX;
                let mut arm_max = 0usize;
                for arm in arms {
                    let (a_min, a_max) = if let crate::parser::MatchBody::Block(body) = &arm.body {
                        immutable_assignment_range(body, field_name)
                    } else {
                        (0, 0)
                    };
                    arm_min = arm_min.min(a_min);
                    arm_max = arm_max.max(a_max);
                }
                let arm_min = if arm_min == usize::MAX { 0 } else { arm_min };
                total_min = total_min.saturating_add(arm_min);
                total_max = total_max.saturating_add(arm_max);
            }
            // Loops: min = 0 (may not execute), max += loop body max.
            // We treat loop body as potentially executing once for max.
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                let (_, loop_max) = immutable_assignment_range(body, field_name);
                // min stays 0 (loop may not execute).
                total_max = total_max.saturating_add(loop_max);
            }
            // try/catch: min = min(body, catch), max = max(body, catch).
            Stmt::Try {
                body, catch_body, ..
            } => {
                let (b_min, b_max) = immutable_assignment_range(body, field_name);
                let (c_min, c_max) = immutable_assignment_range(catch_body, field_name);
                total_min = total_min.saturating_add(b_min.min(c_min));
                total_max = total_max.saturating_add(b_max.max(c_max));
            }
            // unchecked: transparent scope.
            Stmt::Unchecked(body, _) => {
                let (b_min, b_max) = immutable_assignment_range(body, field_name);
                total_min = total_min.saturating_add(b_min);
                total_max = total_max.saturating_add(b_max);
            }
            _ => {}
        }
    }

    (total_min, total_max)
}

/// Count the total number of `self.field_name = …` assignments in `stmts`
/// (flat count, not path-sensitive).  Used for WF-002 outside-init check.
fn count_self_field_assignments(stmts: &[Stmt], field_name: &str) -> usize {
    let mut count = 0usize;
    for stmt in stmts {
        match stmt {
            Stmt::Assign {
                target,
                op: AssignOp::Assign,
                ..
            } if is_self_field_target(target, field_name) => {
                count += 1;
            }
            Stmt::Expr(Expr::Assign_(target, AssignOp::Assign, _, _), _)
                if is_self_field_target(target, field_name) =>
            {
                count += 1;
            }
            Stmt::If { then, else_, .. } => {
                count += count_self_field_assignments(then, field_name);
                if let Some(b) = else_ {
                    count += count_self_field_assignments(b, field_name);
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let crate::parser::MatchBody::Block(body) = &arm.body {
                        count += count_self_field_assignments(body, field_name);
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                count += count_self_field_assignments(body, field_name);
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                count += count_self_field_assignments(body, field_name);
                count += count_self_field_assignments(catch_body, field_name);
            }
            Stmt::Unchecked(body, _) => {
                count += count_self_field_assignments(body, field_name);
            }
            _ => {}
        }
    }
    count
}

// ─── Family C: Structural-Completeness (WF-008..011) ─────────────────────────

/// Check all Family C rules (WF-008, WF-009, WF-010, WF-011).
///
/// WF-008/009 iterate over contracts; WF-010 iterates over contracts;
/// WF-011 iterates over top-level struct/enum declarations.
/// Collect-all: never returns early.
fn check_family_c(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();
    violations.extend(check_wf008_interface_completeness(typed_ast));
    violations.extend(check_wf009_trait_uses_completeness(typed_ast));
    violations.extend(check_wf010_special_fn_uniqueness(typed_ast));
    violations.extend(check_wf011_recursive_type(typed_ast));
    violations
}

// ─── WF-008: Interface implementation completeness ───────────────────────────

/// WF-008 — Every contract declaring `implements I` must provide every method
/// name declared by interface `I` (directly or via a `uses` trait).
///
/// Uses the `interface_methods` table built by the resolver (Phase 1 DRY
/// enabler) — does NOT re-implement interface lookup.
///
/// Name-presence only (per Phase 1 CR note): WF-008 checks that the method
/// name exists in the contract, not that the signature matches.  Signature
/// checking is deferred to a later phase.
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-008`.
fn check_wf008_interface_completeness(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();

    for contract in typed_ast.contracts() {
        let implements = contract.implements();
        if implements.is_empty() {
            continue;
        }

        // Collect the set of method names provided by this contract directly.
        let contract_id = contract.symbol_id();
        let direct_methods: BTreeSet<String> = contract_id
            .and_then(|id| typed_ast.contract_methods.get(&id))
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();

        // Collect method names provided via `uses` traits.
        // Access the raw `uses` list from the AST item.
        let uses_methods: BTreeSet<String> = {
            let mut set = BTreeSet::new();
            let uses_names = contract_uses_names(&contract, typed_ast);
            for trait_name in &uses_names {
                // Look up the trait SymbolId.
                if let Some(trait_id) =
                    find_symbol_id_by_name_and_kind(typed_ast, trait_name, SymbolKind::Trait)
                {
                    if let Some(methods) = typed_ast.trait_methods.get(&trait_id) {
                        set.extend(methods.iter().cloned());
                    }
                }
            }
            set
        };

        // Union of all provided method names.
        let provided: BTreeSet<String> = direct_methods.union(&uses_methods).cloned().collect();

        // Check each declared interface.
        for iface_name in implements {
            // Look up the interface SymbolId.
            let Some(iface_id) =
                find_symbol_id_by_name_and_kind(typed_ast, iface_name, SymbolKind::Interface)
            else {
                // Interface not found in symbol arena — name resolution would
                // have already emitted an error; skip defensively.
                continue;
            };

            let Some(required) = typed_ast.interface_methods(iface_id) else {
                continue;
            };

            let missing: Vec<String> = required
                .iter()
                .filter(|m| !provided.contains(*m))
                .cloned()
                .collect();

            if !missing.is_empty() {
                let span = contract_span(&contract);
                violations.push(TypeError {
                    kind: TypeErrorKind::IncompleteInterface {
                        interface: iface_name.clone(),
                        missing: missing.clone(),
                        span,
                    },
                    span,
                    message: format!(
                        "WF-008: contract `{}` implements `{iface_name}` but is missing \
                         method(s): {}",
                        contract.name(),
                        missing.join(", ")
                    ),
                });
            }
        }
    }

    violations
}

// ─── WF-009: Trait `uses` completeness ───────────────────────────────────────

/// WF-009 — Every contract declaring `uses T` must provide every REQUIRED
/// (body-less) method and required state field declared by trait `T`.
///
/// A trait method with a default body is NOT required — the contract inherits
/// the default.  Only body-less methods and state fields are required.
///
/// Uses the raw `Trait` AST items to distinguish required vs default methods
/// (the `trait_methods` table stores ALL method names, not just required ones).
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-009`.
fn check_wf009_trait_uses_completeness(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();

    for contract in typed_ast.contracts() {
        let uses_names = contract_uses_names(&contract, typed_ast);
        if uses_names.is_empty() {
            continue;
        }

        // Collect method names provided by the contract directly.
        let contract_id = contract.symbol_id();
        let provided_methods: BTreeSet<String> = contract_id
            .and_then(|id| typed_ast.contract_methods.get(&id))
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();

        // Collect state field names provided by the contract.
        let provided_state: BTreeSet<String> = contract
            .state_fields()
            .into_iter()
            .map(|f| f.name.to_owned())
            .collect();

        for trait_name in &uses_names {
            // Find the raw Trait AST item to distinguish required vs default methods.
            let Some(trait_ast) = find_trait_ast(typed_ast, trait_name) else {
                // Trait not found — name resolution already errored; skip.
                continue;
            };

            // Required methods: body-less function members.
            let required_methods: Vec<String> = trait_ast
                .members
                .iter()
                .filter_map(|m| {
                    if let TraitMember::Function(f) = m {
                        // body-less → required; has body → default (not required).
                        if f.body.is_none() {
                            Some(f.name.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                })
                .collect();

            // Required state fields: all state fields declared in the trait.
            let required_state: Vec<String> = trait_ast
                .members
                .iter()
                .flat_map(|m| {
                    if let TraitMember::State(block) = m {
                        block
                            .fields
                            .iter()
                            .map(|f| f.name.clone())
                            .collect::<Vec<_>>()
                    } else {
                        Vec::new()
                    }
                })
                .collect();

            // Compute missing = (required_methods ∪ required_state) - provided.
            let mut missing: Vec<String> = Vec::new();
            for m in &required_methods {
                if !provided_methods.contains(m) {
                    missing.push(m.clone());
                }
            }
            for s in &required_state {
                if !provided_state.contains(s) {
                    missing.push(s.clone());
                }
            }

            if !missing.is_empty() {
                let span = contract_span(&contract);
                violations.push(TypeError {
                    kind: TypeErrorKind::IncompleteTrait {
                        trait_name: trait_name.clone(),
                        missing: missing.clone(),
                        span,
                    },
                    span,
                    message: format!(
                        "WF-009: contract `{}` uses trait `{trait_name}` but is missing \
                         required member(s): {}",
                        contract.name(),
                        missing.join(", ")
                    ),
                });
            }
        }
    }

    violations
}

// ─── WF-010: receive/fallback uniqueness ─────────────────────────────────────

/// WF-010 — At most one `receive()` and at most one `fallback()` per contract.
///
/// Walks `ContractMember::Receive` and `ContractMember::Fallback` occurrences.
/// More than one of either → `DuplicateSpecialFunction`.
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-010`.
fn check_wf010_special_fn_uniqueness(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();

    for contract in typed_ast.contracts() {
        let members = contract.members();

        // Collect spans of all receive() and fallback() declarations.
        let receive_spans: Vec<crate::lexer::token::Span> = members
            .iter()
            .filter_map(|m| {
                if let ContractMember::Receive(r) = m {
                    Some(r.span)
                } else {
                    None
                }
            })
            .collect();

        let fallback_spans: Vec<crate::lexer::token::Span> = members
            .iter()
            .filter_map(|m| {
                if let ContractMember::Fallback(f) = m {
                    Some(f.span)
                } else {
                    None
                }
            })
            .collect();

        // More than one receive() → emit on the second occurrence.
        if receive_spans.len() > 1 {
            let dup_span = receive_spans[1];
            violations.push(TypeError {
                kind: TypeErrorKind::DuplicateSpecialFunction {
                    kind: "receive".into(),
                    span: dup_span,
                },
                span: dup_span,
                message: format!(
                    "WF-010: contract `{}` declares more than one `receive()` function \
                     (at most one is allowed)",
                    contract.name()
                ),
            });
        }

        // More than one fallback() → emit on the second occurrence.
        if fallback_spans.len() > 1 {
            let dup_span = fallback_spans[1];
            violations.push(TypeError {
                kind: TypeErrorKind::DuplicateSpecialFunction {
                    kind: "fallback".into(),
                    span: dup_span,
                },
                span: dup_span,
                message: format!(
                    "WF-010: contract `{}` declares more than one `fallback()` function \
                     (at most one is allowed)",
                    contract.name()
                ),
            });
        }
    }

    violations
}

// ─── WF-011: Recursive (by-value) type detection ─────────────────────────────

/// WF-011 — No `struct` or `enum` may contain itself by value (directly or via
/// a cycle of by-value fields).
///
/// Indirection through `Map`/`FastMap`/`Array`/`Option`/`Set` (heap-allocated
/// collections) breaks the cycle and is allowed.  `FixedArray<T, N>` and
/// `Tuple(…)` are by-value inline and do NOT break cycles.
///
/// ## Algorithm
///
/// 1. Build an adjacency map: for each struct/enum SymbolId, collect the set of
///    user-defined type SymbolIds reachable via by-value fields.
/// 2. DFS cycle detection over this graph using a `visiting` set (grey nodes)
///    and a `visited` set (black nodes).
/// 3. If a cycle is found, emit `RecursiveType` with the cycle path.
///
/// Uses `BTreeMap`/`BTreeSet` for deterministic iteration order (AGENTS §7.1).
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-011`.
fn check_wf011_recursive_type(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();

    // Build adjacency map: struct/enum SymbolId → set of by-value field type SymbolIds.
    // Only user-defined types (Named(id, _)) that are NOT wrapped in an indirection
    // type (Map, FastMap, Array, FixedArray, Option, Set) are by-value.
    let mut adjacency: BTreeMap<SymbolId, BTreeSet<SymbolId>> = BTreeMap::new();

    for (id, sig) in &typed_ast.sigs {
        let by_value_deps = match sig {
            SymbolSig::Struct(s) => {
                // Collect all by-value field type SymbolIds, including those nested
                // inside Tuple and FixedArray fields (handled by by_value_named_ids).
                s.fields
                    .iter()
                    .flat_map(|(_, ty, _)| by_value_named_ids(ty))
                    .collect::<BTreeSet<_>>()
            }
            SymbolSig::Enum(e) => {
                // Collect by-value field type SymbolIds across all variants,
                // including those nested inside Tuple and FixedArray fields.
                e.variants
                    .iter()
                    .flat_map(|(_, fields)| {
                        fields.iter().flat_map(|(_, ty)| by_value_named_ids(ty))
                    })
                    .collect::<BTreeSet<_>>()
            }
            // Functions are not types — skip.
            SymbolSig::Function(_) => continue,
        };
        adjacency.insert(*id, by_value_deps);
    }

    // DFS cycle detection.
    // `visited`: fully explored nodes (no cycle through them).
    // `visiting`: nodes on the current DFS path (grey — cycle if revisited).
    let mut visited: BTreeSet<SymbolId> = BTreeSet::new();
    let mut visiting: Vec<SymbolId> = Vec::new(); // ordered stack for cycle path

    // Iterate in deterministic order (BTreeMap guarantees this).
    let all_ids: Vec<SymbolId> = adjacency.keys().copied().collect();
    for start in all_ids {
        if visited.contains(&start) {
            continue;
        }
        dfs_detect_cycle(
            start,
            &adjacency,
            &mut visiting,
            &mut visited,
            typed_ast,
            &mut violations,
        );
    }

    violations
}

/// DFS helper for WF-011 cycle detection.
///
/// `visiting` is the current DFS path (ordered stack).  If we encounter a node
/// already in `visiting`, we have found a cycle — emit `RecursiveType`.
///
/// After fully exploring a node, it is moved from `visiting` to `visited`.
fn dfs_detect_cycle(
    node: SymbolId,
    adjacency: &BTreeMap<SymbolId, BTreeSet<SymbolId>>,
    visiting: &mut Vec<SymbolId>,
    visited: &mut BTreeSet<SymbolId>,
    typed_ast: &TypedAst,
    violations: &mut Vec<TypeError>,
) {
    // Already fully explored — no cycle through this node.
    if visited.contains(&node) {
        return;
    }

    // Cycle detected: `node` is already on the current DFS path.
    if visiting.contains(&node) {
        // Build the cycle path: from the first occurrence of `node` in `visiting`
        // to the end, then close the cycle by appending `node` again.
        let cycle_start = visiting.iter().position(|&id| id == node).unwrap_or(0);
        let cycle_ids: Vec<SymbolId> = visiting[cycle_start..].to_vec();
        let cycle: Vec<String> = cycle_ids
            .iter()
            .map(|id| symbol_name(typed_ast, *id))
            .chain(std::iter::once(symbol_name(typed_ast, node)))
            .collect();

        let type_name = symbol_name(typed_ast, node);
        let span = typed_ast
            .symbol(node)
            .map(|s| s.decl_span)
            .unwrap_or_else(|| crate::lexer::token::Span::at(1, 1, 0));

        violations.push(TypeError {
            kind: TypeErrorKind::RecursiveType {
                type_name: type_name.clone(),
                cycle,
                span,
            },
            span,
            message: format!(
                "WF-011: type `{type_name}` contains itself by value (recursive type \
                 without indirection)"
            ),
        });
        return;
    }

    // Mark as visiting (grey).
    visiting.push(node);

    // Recurse into by-value dependencies.
    if let Some(deps) = adjacency.get(&node) {
        // Clone to avoid borrow conflict — deps is a small set.
        let deps: Vec<SymbolId> = deps.iter().copied().collect();
        for dep in deps {
            dfs_detect_cycle(dep, adjacency, visiting, visited, typed_ast, violations);
        }
    }

    // Mark as fully visited (black).
    visiting.pop();
    visited.insert(node);
}

/// Return all `SymbolId`s referenced **by value** in `ty` — i.e. every
/// user-defined type (struct/enum) that would be embedded inline in the
/// storage layout, creating a potential infinite-size cycle.
///
/// Returns an empty `Vec` for:
/// - Primitive types (no `SymbolId`).
/// - `Map<K, V>`, `FastMap<K, V>`, `Array<T>`, `Option<T>`, `Set<T>` —
///   heap-allocated / dynamic collections; spec §30.C WF-011 exemption list.
/// - `Fn(…)` — function pointer, not a value type.
///
/// Recurses into compound by-value types:
/// - `Named(id, _)` → `[id]` (user-defined struct/enum, embedded inline).
/// - `Tuple(fields)` → recurse into ALL fields (tuples are by-value inline;
///   `(A, u128)` embeds `A` directly — NOT on the §30.C exemption list).
/// - `FixedArray(inner, _)` → recurse into `inner` (`[T; N]` is by-value
///   inline; `[A; 4]` embeds four copies of `A` — NOT on the §30.C exemption
///   list).
/// - `Result<T, E>` → recurse into both `T` and `E` (`Result` is NOT on the
///   §30.C exemption list; it is a stack-allocated sum type in Lem's storage
///   model, analogous to Rust's `Result` — see DB-A47).
///
/// For `Named(id, args)`: the generic args are NOT checked here — the
/// instantiated type's fields are what matter for cycle detection, and those
/// are already in the adjacency map via the struct/enum sig.
///
/// Uses `BTreeSet` for deterministic iteration order (AGENTS §7.1).
fn by_value_named_ids(ty: &ResolvedType) -> Vec<SymbolId> {
    match ty {
        // User-defined named type — by value (embedded inline in storage layout).
        ResolvedType::Named(id, _) => vec![*id],

        // Tuple is by-value inline — recurse into ALL element types.
        // `(A, u128)` embeds `A` directly; NOT on the §30.C WF-011 exemption list.
        ResolvedType::Tuple(fields) => fields
            .iter()
            .flat_map(by_value_named_ids)
            .collect(),

        // [T; N] is by-value inline — recurse into the element type.
        // `[A; 4]` embeds four copies of `A`; NOT on the §30.C WF-011 exemption list.
        ResolvedType::FixedArray(inner, _) => by_value_named_ids(inner),

        // Result<T, E> is a stack-allocated sum type (NOT on the §30.C exemption list).
        // Cycles through Result are possible: `struct A { r: Result<A, u64> }`.
        // See DB-A47 for the classification decision.
        ResolvedType::Result_(ok, err) => {
            let mut ids = by_value_named_ids(ok);
            ids.extend(by_value_named_ids(err));
            ids
        }

        // Cycle-breaking types (heap-allocated / dynamic — spec §30.C WF-011 exemption list):
        // Map<K,V>, FastMap<K,V>, Array<T>, Option<T>, Set<T> — elements are heap-allocated;
        // a reference to the container does NOT embed the element type inline.
        // Set<T>: dynamic heap-allocated collection — same reasoning as Array<T> (DB-A47).
        ResolvedType::Map(_, _)
        | ResolvedType::FastMap(_, _)
        | ResolvedType::Array(_)
        | ResolvedType::Option_(_)
        | ResolvedType::Set(_)
        // Fn(…): function pointer, not a value type — no storage embedding.
        | ResolvedType::Fn(_, _) => vec![],

        // Primitives and all other types — leaf nodes, no by-value user-defined type.
        _ => vec![],
    }
}

/// Look up the name of a symbol by its SymbolId (for cycle path reporting).
fn symbol_name(typed_ast: &TypedAst, id: SymbolId) -> String {
    typed_ast
        .symbol(id)
        .map(|s| s.name.clone())
        .unwrap_or_else(|| format!("<unknown:{}>", id.0))
}

// ─── Family C helpers ─────────────────────────────────────────────────────────

/// Find a symbol by name and kind in the symbol arena.
///
/// Returns the first matching `SymbolId`, or `None` if not found.
/// Used by WF-008/009 to look up interface/trait SymbolIds by name.
fn find_symbol_id_by_name_and_kind(
    typed_ast: &TypedAst,
    name: &str,
    kind: SymbolKind,
) -> Option<SymbolId> {
    typed_ast
        .symbols
        .iter()
        .enumerate()
        .find(|(_, s)| s.kind == kind && s.name == name)
        .map(|(i, _)| SymbolId((i + 1) as u32))
}

/// Extract the `uses` trait names for a contract from the raw AST.
///
/// Token declarations have no `uses` clause — returns empty vec for tokens.
/// Accesses `typed_ast.ast.items` to find the raw `Contract` item.
fn contract_uses_names(contract: &TypedContract<'_>, typed_ast: &TypedAst) -> Vec<String> {
    let name = contract.name();
    for item in &typed_ast.ast.items {
        if let Item::Contract(c) = item {
            if c.name == name {
                return c.uses.clone();
            }
        }
    }
    Vec::new()
}

/// Find the raw `Trait` AST item by name.
///
/// Returns `None` if no trait with that name is declared in the program.
fn find_trait_ast<'a>(typed_ast: &'a TypedAst, name: &str) -> Option<&'a crate::parser::Trait> {
    for item in &typed_ast.ast.items {
        if let Item::Trait(t) = item {
            if t.name == name {
                return Some(t);
            }
        }
    }
    None
}

// ─── Family D: Schema & Effect (WF-012..015) ─────────────────────────────────

/// Check all Family D rules (WF-012, WF-013, WF-014, WF-015).
///
/// Collect-all: never returns early.
fn check_family_d(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();
    violations.extend(check_wf012_emit_schema(typed_ast));
    violations.extend(check_wf013_const_evaluability(typed_ast));
    violations.extend(check_wf014_token_config(typed_ast));
    violations.extend(check_wf015_effect_conformance(typed_ast));
    violations
}

// ─── WF-012: emit ↔ event-schema validation ──────────────────────────────────

/// WF-012 — Every `emit Foo { field: val }` must match the declared event schema.
///
/// Checks (collect-all per emit statement):
/// 1. The event name is declared (exists in `typed_ast.event_field_sigs`).
/// 2. No duplicate field names in the emitted fields.
/// 3. No unknown fields (emitted key not in schema).
/// 4. No missing fields (schema key not in emitted).
/// 5. Each emitted field's type matches the schema type.
///
/// Uses the Phase 1 `event_field_sigs` table — does NOT re-implement event
/// field lookup (AGENTS §2 DRY).
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-012`.
fn check_wf012_emit_schema(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();

    for contract in typed_ast.contracts() {
        for func in contract.functions() {
            let Some(body) = func.body else {
                continue;
            };
            check_wf012_in_stmts(body, typed_ast, &mut violations);
        }
        // Also check modifier bodies.
        for member in contract.members() {
            if let ContractMember::Modifier(md) = member {
                check_wf012_in_stmts(&md.body, typed_ast, &mut violations);
            }
        }
    }

    violations
}

/// Recursively walk `stmts` and check every `Stmt::Emit` for schema conformance.
///
/// Uses `walk_stmt_expr_bodies` to descend into expression-position if/match
/// bodies so that emit statements nested inside value-position constructs are
/// also checked.
fn check_wf012_in_stmts(stmts: &[Stmt], typed_ast: &TypedAst, out: &mut Vec<TypeError>) {
    for stmt in stmts {
        match stmt {
            Stmt::Emit {
                event,
                fields,
                span,
            } => {
                check_wf012_single_emit(event, fields, *span, typed_ast, out);
            }
            Stmt::If { then, else_, .. } => {
                check_wf012_in_stmts(then, typed_ast, out);
                if let Some(b) = else_ {
                    check_wf012_in_stmts(b, typed_ast, out);
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let MatchBody::Block(body) = &arm.body {
                        check_wf012_in_stmts(body, typed_ast, out);
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                check_wf012_in_stmts(body, typed_ast, out);
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                check_wf012_in_stmts(body, typed_ast, out);
                check_wf012_in_stmts(catch_body, typed_ast, out);
            }
            Stmt::Unchecked(body, _) => {
                check_wf012_in_stmts(body, typed_ast, out);
            }
            _ => {}
        }
        // Descend into expression-position if/match bodies.
        walk_stmt_expr_bodies(stmt, &mut |body| {
            check_wf012_in_stmts(body, typed_ast, out);
        });
    }
}

/// Check a single `emit Event { fields }` statement against the declared schema.
///
/// Collect-all: reports every violation found in this emit statement.
fn check_wf012_single_emit(
    event: &str,
    fields: &[(String, Expr)],
    span: crate::lexer::token::Span,
    typed_ast: &TypedAst,
    out: &mut Vec<TypeError>,
) {
    // Step 1: look up the event schema.
    let Some(schema) = typed_ast.event_field_sigs(event) else {
        out.push(TypeError {
            kind: TypeErrorKind::EmitMismatch {
                event: event.to_owned(),
                reason: format!("unknown event `{event}` — no event with this name is declared"),
                span,
            },
            span,
            message: format!("WF-012: `emit {event}` references an undeclared event"),
        });
        return;
    };

    // Step 2: check for duplicate field names in the emitted fields.
    let mut seen_keys: BTreeSet<&str> = BTreeSet::new();
    for (key, _) in fields {
        if !seen_keys.insert(key.as_str()) {
            out.push(TypeError {
                kind: TypeErrorKind::EmitMismatch {
                    event: event.to_owned(),
                    reason: format!("duplicate field `{key}` in emit statement"),
                    span,
                },
                span,
                message: format!("WF-012: `emit {event}` has duplicate field `{key}`"),
            });
        }
    }

    // Build a map of emitted fields for O(log n) lookup.
    let emitted: BTreeMap<&str, &Expr> = fields.iter().map(|(k, v)| (k.as_str(), v)).collect();

    // Build a map of schema fields for O(log n) lookup.
    let schema_map: BTreeMap<&str, &ResolvedType> =
        schema.iter().map(|(k, ty)| (k.as_str(), ty)).collect();

    // Step 3: check for unknown fields (emitted key not in schema).
    for (key, _) in fields {
        if !schema_map.contains_key(key.as_str()) {
            out.push(TypeError {
                kind: TypeErrorKind::EmitMismatch {
                    event: event.to_owned(),
                    reason: format!(
                        "unknown field `{key}` — event `{event}` does not declare this field"
                    ),
                    span,
                },
                span,
                message: format!("WF-012: `emit {event}` has unknown field `{key}`"),
            });
        }
    }

    // Step 4: check for missing fields (schema key not in emitted).
    for (schema_key, _) in schema {
        if !emitted.contains_key(schema_key.as_str()) {
            out.push(TypeError {
                kind: TypeErrorKind::EmitMismatch {
                    event: event.to_owned(),
                    reason: format!(
                        "missing field `{schema_key}` — event `{event}` requires this field"
                    ),
                    span,
                },
                span,
                message: format!("WF-012: `emit {event}` is missing required field `{schema_key}`"),
            });
        }
    }

    // Step 5: check type match for each field present in both emitted and schema.
    for (key, val_expr) in fields {
        let Some(schema_ty) = schema_map.get(key.as_str()) else {
            // Already reported as unknown above.
            continue;
        };
        let val_span = expr_span(val_expr);
        let Some(emitted_ty) = typed_ast.type_of(&val_span) else {
            // Type not resolved — skip defensively (should not occur for well-typed programs).
            continue;
        };
        if emitted_ty != *schema_ty {
            out.push(TypeError {
                kind: TypeErrorKind::EmitMismatch {
                    event: event.to_owned(),
                    reason: format!(
                        "field `{key}` has wrong type: expected `{}`, found `{}`",
                        schema_ty.display_name(),
                        emitted_ty.display_name(),
                    ),
                    span,
                },
                span,
                message: format!("WF-012: `emit {event}` field `{key}` type mismatch"),
            });
        }
    }
}

// ─── WF-013: Const-expression evaluability ────────────────────────────────────

/// WF-013 — Every `const NAME: T = expr` initializer must be compile-time evaluable.
///
/// ## Over-approximation grammar (conservative = correct)
///
/// Allowed (const-evaluable):
/// - Integer / bool / string / char literals
/// - References to other `const` names (resolved to `SymbolKind::Const`)
/// - Arithmetic / bitwise / comparison binary ops over allowed exprs
/// - Unary ops over allowed exprs
///
/// Rejected (not const-evaluable):
/// - `Expr::Member` where receiver is `self` (state read)
/// - `Expr::Call` (any function call — conservative; only literals and const-refs allowed)
/// - `Expr::Ident("msg")` or `Expr::Ident("block")` (context reads)
/// - `Expr::Ident(name)` that resolves to a non-const symbol
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-013`.
fn check_wf013_const_evaluability(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();

    // Check top-level `const` items.
    for item in &typed_ast.ast.items {
        if let Item::Const(c) = item {
            check_wf013_expr(&c.value, typed_ast, &mut violations);
        }
    }

    // Check `const` members inside contracts/tokens.
    for contract in typed_ast.contracts() {
        for member in contract.members() {
            if let ContractMember::Const(c) = member {
                check_wf013_expr(&c.value, typed_ast, &mut violations);
            }
        }
        // Also check `const` inside function bodies (Stmt::Const).
        for func in contract.functions() {
            let Some(body) = func.body else {
                continue;
            };
            check_wf013_in_stmts(body, typed_ast, &mut violations);
        }
    }

    violations
}

/// Walk statements and check any `Stmt::Const` initializer for evaluability.
fn check_wf013_in_stmts(stmts: &[Stmt], typed_ast: &TypedAst, out: &mut Vec<TypeError>) {
    for stmt in stmts {
        match stmt {
            Stmt::Const(c) => {
                check_wf013_expr(&c.value, typed_ast, out);
            }
            Stmt::If { then, else_, .. } => {
                check_wf013_in_stmts(then, typed_ast, out);
                if let Some(b) = else_ {
                    check_wf013_in_stmts(b, typed_ast, out);
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let MatchBody::Block(body) = &arm.body {
                        check_wf013_in_stmts(body, typed_ast, out);
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                check_wf013_in_stmts(body, typed_ast, out);
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                check_wf013_in_stmts(body, typed_ast, out);
                check_wf013_in_stmts(catch_body, typed_ast, out);
            }
            Stmt::Unchecked(body, _) => {
                check_wf013_in_stmts(body, typed_ast, out);
            }
            _ => {}
        }
    }
}

/// Check whether `expr` is in the const-evaluable grammar.
///
/// Emits `NonConstExpr` for the first non-evaluable sub-expression found.
/// Collect-all: continues checking sibling sub-expressions after a violation.
fn check_wf013_expr(expr: &Expr, typed_ast: &TypedAst, out: &mut Vec<TypeError>) {
    match expr {
        // ── Allowed: literals ─────────────────────────────────────────────────
        Expr::Literal(_, _) => {}

        // ── Allowed: identifier — only if it resolves to a const symbol ───────
        Expr::Ident(name, span) => {
            // Context reads are never const-evaluable.
            if name == "msg" || name == "block" {
                out.push(TypeError {
                    kind: TypeErrorKind::NonConstExpr { span: *span },
                    span: *span,
                    message: format!(
                        "WF-013: `{name}` is a runtime context read — not allowed in `const` initializer"
                    ),
                });
                return;
            }
            // Check if the identifier resolves to a const symbol.
            // If it resolves to anything other than a const, reject.
            if let Some(sym_id) = typed_ast.resolution_of(span) {
                if let Some(sym) = typed_ast.symbol(sym_id) {
                    if sym.kind != SymbolKind::Const {
                        out.push(TypeError {
                            kind: TypeErrorKind::NonConstExpr { span: *span },
                            span: *span,
                            message: format!(
                                "WF-013: `{name}` is not a `const` — only const names are \
                                 allowed in `const` initializers"
                            ),
                        });
                    }
                }
                // If symbol not found in arena, allow defensively (name resolution
                // would have already emitted an error).
            }
            // Unresolved ident: allow defensively.
        }

        // ── Allowed: arithmetic/bitwise/comparison binary ops over allowed exprs
        Expr::Binary(_, left, right, _) => {
            check_wf013_expr(left, typed_ast, out);
            check_wf013_expr(right, typed_ast, out);
        }

        // ── Allowed: unary ops over allowed exprs ─────────────────────────────
        Expr::Unary(_, inner, _) => {
            check_wf013_expr(inner, typed_ast, out);
        }

        // ── Rejected: self.field (state read) ─────────────────────────────────
        Expr::Member(obj, _, span) if is_self_expr(obj) => {
            out.push(TypeError {
                kind: TypeErrorKind::NonConstExpr { span: *span },
                span: *span,
                message:
                    "WF-013: `self.field` is a state read — not allowed in `const` initializer"
                        .into(),
            });
        }

        // ── Rejected: any function call ───────────────────────────────────────
        Expr::Call { span, .. } => {
            out.push(TypeError {
                kind: TypeErrorKind::NonConstExpr { span: *span },
                span: *span,
                message: "WF-013: function calls are not allowed in `const` initializers \
                          (only literals, const names, and arithmetic ops are permitted)"
                    .into(),
            });
        }

        // ── Allowed: struct literals — fields must each be const-evaluable ──
        // `Point { x: 1u128, y: 2u128 }` is a compile-time literal form.
        // Spread (`..other`) is rejected (it reads a runtime value).
        Expr::Struct_ { fields, spread, .. } => {
            for (_, e) in fields {
                check_wf013_expr(e, typed_ast, out);
            }
            if let Some(s) = spread {
                let span = expr_span(s);
                out.push(TypeError {
                    kind: TypeErrorKind::NonConstExpr { span },
                    span,
                    message: "WF-013: struct spread (`..expr`) is not allowed in `const` \
                              initializers — only literal field values are permitted"
                        .into(),
                });
            }
        }

        // ── Allowed: tuple literals — elements must each be const-evaluable ──
        Expr::Tuple(elems, _) => {
            for e in elems {
                check_wf013_expr(e, typed_ast, out);
            }
        }

        // ── Allowed: array literals — elements must each be const-evaluable ──
        Expr::Array(elems, _) => {
            for e in elems {
                check_wf013_expr(e, typed_ast, out);
            }
        }

        // ── Rejected: non-self member access (e.g. `foo.bar`) ────────────────
        // Conservative: any member access that is not a literal chain is rejected.
        Expr::Member(_, _, span) => {
            out.push(TypeError {
                kind: TypeErrorKind::NonConstExpr { span: *span },
                span: *span,
                message: "WF-013: member access is not allowed in `const` initializers".into(),
            });
        }

        // ── Rejected: all other expression forms ──────────────────────────────
        // Ternary, If_, Match_, Lambda, New, Index, Assign_, Try_, Nullish,
        // Cast, Template — none are const-evaluable.
        other => {
            let span = expr_span(other);
            out.push(TypeError {
                kind: TypeErrorKind::NonConstExpr { span },
                span,
                message: "WF-013: expression is not compile-time evaluable — only literals, \
                          const names, and arithmetic/bitwise/comparison ops are allowed"
                    .into(),
            });
        }
    }
}

// ─── WF-014: Token config {} validation ──────────────────────────────────────

/// WF-014 — Every `token ... extends Base { config { ... } }` must conform to
/// the hardcoded schema for its base standard.
///
/// ## Schemas (spec §24 + DB-A40..A43)
///
/// **Token** (base):
/// - Mandatory: `name` (Str), `symbol` (Str), `decimals` (Int), `maxSupply` (Int)
/// - Optional: `maxWallet` (Int, bps), `approvalExpiry` (Unit or Int), `approvalOneTime` (Bool)
/// - Conditional: `maxWallet` present → contract must implement `isWalletExempt` or
///   have state field `walletExempt`
///
/// **TaxToken** (extends Token):
/// - All Token mandatory keys PLUS:
/// - Mandatory: `fees` block `{ burn: Int(bps), holders: Int(bps), others: Int(bps) }`
/// - Optional: `maxFeePercent` (Int, bps, default = PROTOCOL_MAX_FEE_BPS)
/// - Rule: `sum(fees.burn + fees.holders + fees.others) <= maxFeePercent <= PROTOCOL_MAX_FEE_BPS`
/// - Rule: `fees.others > 0` → contract must implement `distributeTaxes`
/// - Conditional (DB-A43): `fairLaunch` block if present →
///   `{ cooldownBetweenBuys: Int, antiSnipeBlocks: Int }` both mandatory
///
/// **NFT**:
/// - Mandatory: `name` (Str), `symbol` (Str), `maxSupply` (Int)
///
/// **MultiToken**:
/// - Mandatory: `name` (Str)
///
/// **Vault**:
/// - Mandatory: `name` (Str), `asset` (Str)
///
/// ## BPS mandate (DB-A40)
///
/// Any config key representing a rate/fee MUST be a non-negative integer
/// (`ConfigValue::Int`).  Imports `PROTOCOL_MAX_FEE_BPS` from
/// `analyzer::rules::constants` — never re-declared (AGENTS §2 DRY).
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-014`.
fn check_wf014_token_config(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();

    for item in &typed_ast.ast.items {
        let Item::Token_(token) = item else {
            continue;
        };

        // Find the config block (if any).
        let config_block = token.members.iter().find_map(|m| {
            if let ContractMember::Config(cfg) = m {
                Some(cfg)
            } else {
                None
            }
        });

        let config_span = config_block.map(|c| c.span).unwrap_or(token.span);

        let entries: &[crate::parser::ConfigEntry] =
            config_block.map(|c| c.entries.as_slice()).unwrap_or(&[]);

        // Collect function names and state field names for conditional checks.
        let func_names: BTreeSet<&str> = token
            .members
            .iter()
            .filter_map(|m| {
                if let ContractMember::Function(f) = m {
                    Some(f.name.as_str())
                } else {
                    None
                }
            })
            .collect();

        let state_field_names: BTreeSet<&str> = token
            .members
            .iter()
            .flat_map(|m| {
                if let ContractMember::State(block) = m {
                    block
                        .fields
                        .iter()
                        .map(|f| f.name.as_str())
                        .collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            })
            .collect();

        match token.extends.as_str() {
            "Token" => {
                check_wf014_token_schema(
                    entries,
                    config_span,
                    &func_names,
                    &state_field_names,
                    &mut violations,
                );
            }
            "TaxToken" => {
                // TaxToken has its own complete schema (Token mandatory keys +
                // TaxToken-specific keys).  We do NOT call check_wf014_token_schema
                // here because that function's unknown-key check would reject
                // TaxToken-specific keys (maxFeePercent, fees, fairLaunch).
                check_wf014_taxtoken_full_schema(
                    entries,
                    config_span,
                    &func_names,
                    &state_field_names,
                    &mut violations,
                );
            }
            "NFT" => {
                check_wf014_nft_schema(entries, config_span, &mut violations);
            }
            "MultiToken" => {
                check_wf014_multitoken_schema(entries, config_span, &mut violations);
            }
            "Vault" => {
                check_wf014_vault_schema(entries, config_span, &mut violations);
            }
            // Unknown base standard — no schema to validate against.
            _ => {}
        }
    }

    violations
}

/// Validate the base Token schema.
///
/// Mandatory: `name` (Str), `symbol` (Str), `decimals` (Int), `maxSupply` (Int)
/// Optional: `antiHoneypot` (Bool, §24.1 anti-scam flag — enables SAFETY-001),
///           `maxWallet` (Int, bps), `approvalExpiry` (Unit or Int), `approvalOneTime` (Bool),
///           `mintable` (Bool), `pausable` (Bool), `freezable` (Bool), `upgradeable` (Bool),
///           `fairLaunch` (Object — §24.8, available to both Token and TaxToken)
/// Unknown keys: rejected.
/// Conditional: `maxWallet` present → `isWalletExempt` fn or `walletExempt` state field.
fn check_wf014_token_schema(
    entries: &[crate::parser::ConfigEntry],
    config_span: crate::lexer::token::Span,
    func_names: &BTreeSet<&str>,
    state_field_names: &BTreeSet<&str>,
    out: &mut Vec<TypeError>,
) {
    const MANDATORY: &[&str] = &["name", "symbol", "decimals", "maxSupply"];
    // Capability flags (mintable/pausable/freezable/upgradeable) are ratchet-off booleans.
    // antiHoneypot: §24.1 anti-scam flag — enables SAFETY-001 symmetric sell-path check.
    // fairLaunch: §24.8 launch-window protections — available to both Token and TaxToken.
    const OPTIONAL: &[&str] = &[
        "antiHoneypot",
        "maxWallet",
        "approvalExpiry",
        "approvalOneTime",
        "mintable",
        "pausable",
        "freezable",
        "upgradeable",
        "fairLaunch",
        // §3-010 (SAFETY-010): declares the address of an external transfer
        // checker, making a transfer-path external call explicit + monitored.
        "externalChecker",
    ];
    const BPS_KEYS: &[&str] = &["maxWallet"];

    let entry_map: BTreeMap<&str, &crate::parser::ConfigEntry> =
        entries.iter().map(|e| (e.key.as_str(), e)).collect();

    // Check mandatory keys.
    for key in MANDATORY {
        match entry_map.get(key) {
            None => {
                out.push(TypeError {
                    kind: TypeErrorKind::InvalidTokenConfig {
                        reason: format!("missing mandatory config key `{key}`"),
                        span: config_span,
                    },
                    span: config_span,
                    message: format!("WF-014: Token config is missing mandatory key `{key}`"),
                });
            }
            Some(entry) => {
                // Type check.
                let expected_type = match *key {
                    "name" | "symbol" => "Str",
                    "decimals" | "maxSupply" => "Int",
                    _ => continue,
                };
                if !config_value_matches_type(&entry.value, expected_type) {
                    out.push(TypeError {
                        kind: TypeErrorKind::InvalidTokenConfig {
                            reason: format!(
                                "config key `{key}` has wrong type: expected {expected_type}"
                            ),
                            span: entry.span,
                        },
                        span: entry.span,
                        message: format!("WF-014: Token config key `{key}` has wrong value type"),
                    });
                }
            }
        }
    }

    // Check optional keys — type-check if present.
    for key in OPTIONAL {
        if let Some(entry) = entry_map.get(key) {
            let ok = match *key {
                "maxWallet" => matches!(entry.value, ConfigValue::Int(_)),
                "approvalExpiry" => {
                    matches!(entry.value, ConfigValue::Unit(_, _) | ConfigValue::Int(_))
                }
                // §24.1 anti-scam flag (Bool) — enables SAFETY-001 symmetric sell-path check.
                "antiHoneypot" | "approvalOneTime" | "mintable" | "pausable" | "freezable"
                | "upgradeable" => {
                    matches!(entry.value, ConfigValue::Bool(_))
                }
                // §24.8 fairLaunch block — validated separately below.
                "fairLaunch" => matches!(entry.value, ConfigValue::Object(_)),
                // §3-010 externalChecker: an address literal (string form).
                "externalChecker" => matches!(entry.value, ConfigValue::Str(_)),
                _ => true,
            };
            if !ok {
                out.push(TypeError {
                    kind: TypeErrorKind::InvalidTokenConfig {
                        reason: format!("config key `{key}` has wrong value type"),
                        span: entry.span,
                    },
                    span: entry.span,
                    message: format!("WF-014: Token config key `{key}` has wrong value type"),
                });
            }
        }
    }

    // BPS mandate: bps keys must be non-negative integers.
    for key in BPS_KEYS {
        if let Some(entry) = entry_map.get(key) {
            if !matches!(entry.value, ConfigValue::Int(_)) {
                out.push(TypeError {
                    kind: TypeErrorKind::InvalidTokenConfig {
                        reason: format!(
                            "config key `{key}` must be an integer (basis points) — \
                             e.g. `{key}: 500` for 5%"
                        ),
                        span: entry.span,
                    },
                    span: entry.span,
                    message: format!(
                        "WF-014: Token config key `{key}` must be an integer (bps mandate)"
                    ),
                });
            }
        }
    }

    // Conditional (§24.8): fairLaunch block if present →
    // { cooldownBetweenBuys: Int, antiSnipeBlocks: Int, duration: Int } all mandatory.
    // Token and TaxToken both support fairLaunch (spec §24.8).
    // `duration` added per DB-A43 — SAFETY-024 requires a self-expiring launch window.
    if let Some(fl_entry) = entry_map.get("fairLaunch") {
        if let ConfigValue::Object(fl_entries) = &fl_entry.value {
            let fl_map: BTreeMap<&str, &crate::parser::ConfigEntry> =
                fl_entries.iter().map(|e| (e.key.as_str(), e)).collect();
            for key in &["cooldownBetweenBuys", "antiSnipeBlocks", "duration"] {
                match fl_map.get(key) {
                    None => {
                        out.push(TypeError {
                            kind: TypeErrorKind::InvalidTokenConfig {
                                reason: format!(
                                    "`fairLaunch` block is missing mandatory key `{key}`"
                                ),
                                span: fl_entry.span,
                            },
                            span: fl_entry.span,
                            message: format!("WF-014: `fairLaunch` block missing `{key}`"),
                        });
                    }
                    Some(fl_key_entry) => {
                        if !matches!(fl_key_entry.value, ConfigValue::Int(_)) {
                            out.push(TypeError {
                                kind: TypeErrorKind::InvalidTokenConfig {
                                    reason: format!("`fairLaunch.{key}` must be an integer"),
                                    span: fl_key_entry.span,
                                },
                                span: fl_key_entry.span,
                                message: format!("WF-014: `fairLaunch.{key}` must be an integer"),
                            });
                        }
                    }
                }
            }
        }
        // Non-object fairLaunch is already caught by the type check above.
    }

    // Unknown keys: reject any key not in MANDATORY ∪ OPTIONAL.
    let known: BTreeSet<&str> = MANDATORY.iter().chain(OPTIONAL.iter()).copied().collect();
    for entry in entries {
        if !known.contains(entry.key.as_str()) {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: format!("unknown config key `{}`", entry.key),
                    span: entry.span,
                },
                span: entry.span,
                message: format!("WF-014: Token config has unknown key `{}`", entry.key),
            });
        }
    }

    // Conditional: maxWallet present → isWalletExempt fn or walletExempt state field.
    if entry_map.contains_key("maxWallet") {
        let has_exempt =
            func_names.contains("isWalletExempt") || state_field_names.contains("walletExempt");
        if !has_exempt {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: "config key `maxWallet` requires the contract to implement \
                             `isWalletExempt` function or declare `walletExempt` state field"
                        .into(),
                    span: config_span,
                },
                span: config_span,
                message: "WF-014: `maxWallet` config requires wallet-exempt interface".into(),
            });
        }
    }
}

/// Validate the complete TaxToken schema (Token mandatory keys + TaxToken additions).
///
/// TaxToken known keys:
/// - Mandatory (from Token): `name` (Str), `symbol` (Str), `decimals` (Int), `maxSupply` (Int)
/// - Mandatory (TaxToken): `fees` block `{ burn: Int(bps), holders: Int(bps), others: Int(bps) }`
/// - Optional (from Token): `antiHoneypot` (Bool, §24.1 anti-scam flag),
///   `maxWallet` (Int, bps), `approvalExpiry`, `approvalOneTime` (Bool),
///   `mintable` (Bool), `pausable` (Bool), `freezable` (Bool), `upgradeable` (Bool)
/// - Optional (TaxToken): `maxFeePercent` (Int, bps), `fairLaunch` block (§24.8)
fn check_wf014_taxtoken_full_schema(
    entries: &[crate::parser::ConfigEntry],
    config_span: crate::lexer::token::Span,
    func_names: &BTreeSet<&str>,
    state_field_names: &BTreeSet<&str>,
    out: &mut Vec<TypeError>,
) {
    // All known TaxToken keys (Token mandatory + Token optional + TaxToken-specific).
    const KNOWN: &[&str] = &[
        // Token mandatory
        "name",
        "symbol",
        "decimals",
        "maxSupply",
        // Token optional — §24.1 anti-scam flag (enables SAFETY-001).
        "antiHoneypot",
        "maxWallet",
        "approvalExpiry",
        "approvalOneTime",
        "mintable",
        "pausable",
        "freezable",
        "upgradeable",
        // TaxToken mandatory
        "fees",
        // TaxToken optional
        "maxFeePercent",
        "fairLaunch",
        // §3-010 (SAFETY-010): external transfer-checker address declaration.
        "externalChecker",
    ];

    let entry_map: BTreeMap<&str, &crate::parser::ConfigEntry> =
        entries.iter().map(|e| (e.key.as_str(), e)).collect();

    // Check Token mandatory keys.
    for key in &["name", "symbol", "decimals", "maxSupply"] {
        match entry_map.get(key) {
            None => {
                out.push(TypeError {
                    kind: TypeErrorKind::InvalidTokenConfig {
                        reason: format!("missing mandatory config key `{key}`"),
                        span: config_span,
                    },
                    span: config_span,
                    message: format!("WF-014: TaxToken config is missing mandatory key `{key}`"),
                });
            }
            Some(entry) => {
                let expected_type = match *key {
                    "name" | "symbol" => "Str",
                    "decimals" | "maxSupply" => "Int",
                    _ => continue,
                };
                if !config_value_matches_type(&entry.value, expected_type) {
                    out.push(TypeError {
                        kind: TypeErrorKind::InvalidTokenConfig {
                            reason: format!(
                                "config key `{key}` has wrong type: expected {expected_type}"
                            ),
                            span: entry.span,
                        },
                        span: entry.span,
                        message: format!(
                            "WF-014: TaxToken config key `{key}` has wrong value type"
                        ),
                    });
                }
            }
        }
    }

    // Check Token optional keys (shared with Token schema).
    // antiHoneypot: §24.1 anti-scam flag — enables SAFETY-001 symmetric sell-path check.
    for key in &[
        "antiHoneypot",
        "maxWallet",
        "approvalExpiry",
        "approvalOneTime",
        "mintable",
        "pausable",
        "freezable",
        "upgradeable",
        "externalChecker",
    ] {
        if let Some(entry) = entry_map.get(key) {
            let ok = match *key {
                "maxWallet" => matches!(entry.value, ConfigValue::Int(_)),
                "approvalExpiry" => {
                    matches!(entry.value, ConfigValue::Unit(_, _) | ConfigValue::Int(_))
                }
                // §24.1 anti-scam flag (Bool) — enables SAFETY-001.
                "antiHoneypot" | "approvalOneTime" | "mintable" | "pausable" | "freezable"
                | "upgradeable" => {
                    matches!(entry.value, ConfigValue::Bool(_))
                }
                // §3-010 externalChecker: an address literal (string form).
                "externalChecker" => matches!(entry.value, ConfigValue::Str(_)),
                _ => true,
            };
            if !ok {
                out.push(TypeError {
                    kind: TypeErrorKind::InvalidTokenConfig {
                        reason: format!("config key `{key}` has wrong value type"),
                        span: entry.span,
                    },
                    span: entry.span,
                    message: format!("WF-014: TaxToken config key `{key}` has wrong value type"),
                });
            }
        }
    }

    // BPS mandate for maxWallet.
    if let Some(entry) = entry_map.get("maxWallet") {
        if !matches!(entry.value, ConfigValue::Int(_)) {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: "config key `maxWallet` must be an integer (basis points)".into(),
                    span: entry.span,
                },
                span: entry.span,
                message: "WF-014: TaxToken config key `maxWallet` must be an integer (bps mandate)"
                    .into(),
            });
        }
    }

    // Conditional: maxWallet present → isWalletExempt fn or walletExempt state field.
    if entry_map.contains_key("maxWallet") {
        let has_exempt =
            func_names.contains("isWalletExempt") || state_field_names.contains("walletExempt");
        if !has_exempt {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: "config key `maxWallet` requires the contract to implement \
                             `isWalletExempt` function or declare `walletExempt` state field"
                        .into(),
                    span: config_span,
                },
                span: config_span,
                message: "WF-014: `maxWallet` config requires wallet-exempt interface".into(),
            });
        }
    }

    // Unknown keys.
    let known: BTreeSet<&str> = KNOWN.iter().copied().collect();
    for entry in entries {
        if !known.contains(entry.key.as_str()) {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: format!("unknown config key `{}`", entry.key),
                    span: entry.span,
                },
                span: entry.span,
                message: format!("WF-014: TaxToken config has unknown key `{}`", entry.key),
            });
        }
    }

    // Delegate TaxToken-specific checks.
    check_wf014_taxtoken_schema(entries, config_span, func_names, out);
}

/// Validate the TaxToken-specific schema additions.
///
/// Mandatory: `fees` block `{ burn: Int(bps), holders: Int(bps), others: Int(bps) }`
/// Optional: `maxFeePercent` (Int, bps)
/// Rule: `sum(fees.*) <= maxFeePercent <= PROTOCOL_MAX_FEE_BPS`
/// Rule: `fees.others > 0` → `distributeTaxes` function must exist
/// Conditional (DB-A43): `fairLaunch` block if present →
///   `{ cooldownBetweenBuys: Int, antiSnipeBlocks: Int }` both mandatory
fn check_wf014_taxtoken_schema(
    entries: &[crate::parser::ConfigEntry],
    config_span: crate::lexer::token::Span,
    func_names: &BTreeSet<&str>,
    out: &mut Vec<TypeError>,
) {
    let entry_map: BTreeMap<&str, &crate::parser::ConfigEntry> =
        entries.iter().map(|e| (e.key.as_str(), e)).collect();

    // Mandatory: fees block.
    let fees_entry = entry_map.get("fees");
    match fees_entry {
        None => {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: "TaxToken config is missing mandatory `fees` block \
                             `{ burn: Int, holders: Int, others: Int }`"
                        .into(),
                    span: config_span,
                },
                span: config_span,
                message: "WF-014: TaxToken config is missing mandatory `fees` block".into(),
            });
        }
        Some(fees_entry) => {
            // fees must be an Object with burn, holders, others (all Int, bps).
            match &fees_entry.value {
                ConfigValue::Object(fee_entries) => {
                    let fee_map: BTreeMap<&str, &crate::parser::ConfigEntry> =
                        fee_entries.iter().map(|e| (e.key.as_str(), e)).collect();

                    let mut burn_val: Option<u128> = None;
                    let mut holders_val: Option<u128> = None;
                    let mut others_val: Option<u128> = None;

                    for key in &["burn", "holders", "others"] {
                        match fee_map.get(key) {
                            None => {
                                out.push(TypeError {
                                    kind: TypeErrorKind::InvalidTokenConfig {
                                        reason: format!(
                                            "TaxToken `fees` block is missing mandatory key `{key}`"
                                        ),
                                        span: fees_entry.span,
                                    },
                                    span: fees_entry.span,
                                    message: format!(
                                        "WF-014: TaxToken `fees` block missing `{key}`"
                                    ),
                                });
                            }
                            Some(fee_entry) => match &fee_entry.value {
                                ConfigValue::Int(n) => match *key {
                                    "burn" => burn_val = Some(*n),
                                    "holders" => holders_val = Some(*n),
                                    "others" => others_val = Some(*n),
                                    _ => {}
                                },
                                _ => {
                                    out.push(TypeError {
                                            kind: TypeErrorKind::InvalidTokenConfig {
                                                reason: format!(
                                                    "TaxToken `fees.{key}` must be an integer \
                                                     (basis points) — e.g. `{key}: 500` for 5%"
                                                ),
                                                span: fee_entry.span,
                                            },
                                            span: fee_entry.span,
                                            message: format!(
                                                "WF-014: TaxToken `fees.{key}` must be an integer (bps mandate)"
                                            ),
                                        });
                                }
                            },
                        }
                    }

                    // Unknown keys inside fees block.
                    for fee_entry in fee_entries {
                        if !matches!(fee_entry.key.as_str(), "burn" | "holders" | "others") {
                            out.push(TypeError {
                                kind: TypeErrorKind::InvalidTokenConfig {
                                    reason: format!(
                                        "unknown key `{}` in TaxToken `fees` block",
                                        fee_entry.key
                                    ),
                                    span: fee_entry.span,
                                },
                                span: fee_entry.span,
                                message: format!(
                                    "WF-014: TaxToken `fees` block has unknown key `{}`",
                                    fee_entry.key
                                ),
                            });
                        }
                    }

                    // Read maxFeePercent (default = PROTOCOL_MAX_FEE_BPS).
                    let max_fee_bps = entry_map
                        .get("maxFeePercent")
                        .and_then(|e| {
                            if let ConfigValue::Int(n) = &e.value {
                                Some(*n as u16)
                            } else {
                                None
                            }
                        })
                        .unwrap_or(PROTOCOL_MAX_FEE_BPS);

                    // Rule: sum(fees.*) <= maxFeePercent <= PROTOCOL_MAX_FEE_BPS.
                    if let (Some(burn), Some(holders), Some(others)) =
                        (burn_val, holders_val, others_val)
                    {
                        let sum = burn.saturating_add(holders).saturating_add(others);
                        if sum > u128::from(max_fee_bps) {
                            out.push(TypeError {
                                kind: TypeErrorKind::InvalidTokenConfig {
                                    reason: format!(
                                        "sum of fees ({sum} bps) exceeds maxFeePercent \
                                         ({max_fee_bps} bps)"
                                    ),
                                    span: fees_entry.span,
                                },
                                span: fees_entry.span,
                                message: "WF-014: TaxToken fee sum exceeds maxFeePercent".into(),
                            });
                        }

                        // Rule: fees.others > 0 → distributeTaxes function must exist.
                        if others > 0 && !func_names.contains("distributeTaxes") {
                            out.push(TypeError {
                                kind: TypeErrorKind::InvalidTokenConfig {
                                    reason: "`fees.others > 0` requires the contract to implement \
                                             a `distributeTaxes` function"
                                        .into(),
                                    span: fees_entry.span,
                                },
                                span: fees_entry.span,
                                message:
                                    "WF-014: `fees.others > 0` requires `distributeTaxes` function"
                                        .into(),
                            });
                        }
                    }
                }
                _ => {
                    out.push(TypeError {
                        kind: TypeErrorKind::InvalidTokenConfig {
                            reason: "TaxToken `fees` must be an object block \
                                     `{ burn: Int, holders: Int, others: Int }`"
                                .into(),
                            span: fees_entry.span,
                        },
                        span: fees_entry.span,
                        message: "WF-014: TaxToken `fees` must be an object block".into(),
                    });
                }
            }
        }
    }

    // Optional: maxFeePercent — must be Int (bps mandate).
    if let Some(entry) = entry_map.get("maxFeePercent") {
        match &entry.value {
            ConfigValue::Int(n) => {
                if *n > u128::from(PROTOCOL_MAX_FEE_BPS) {
                    out.push(TypeError {
                        kind: TypeErrorKind::InvalidTokenConfig {
                            reason: format!(
                                "`maxFeePercent` ({n} bps) exceeds protocol ceiling \
                                 ({PROTOCOL_MAX_FEE_BPS} bps)"
                            ),
                            span: entry.span,
                        },
                        span: entry.span,
                        message: "WF-014: `maxFeePercent` exceeds protocol ceiling".into(),
                    });
                }
            }
            _ => {
                out.push(TypeError {
                    kind: TypeErrorKind::InvalidTokenConfig {
                        reason: "`maxFeePercent` must be an integer (basis points)".into(),
                        span: entry.span,
                    },
                    span: entry.span,
                    message: "WF-014: `maxFeePercent` must be an integer (bps mandate)".into(),
                });
            }
        }
    }

    // Conditional (DB-A43): fairLaunch block if present →
    // { cooldownBetweenBuys: Int, antiSnipeBlocks: Int, duration: Int } all mandatory.
    // `duration` added per DB-A43 — SAFETY-024 requires a self-expiring launch window.
    if let Some(fl_entry) = entry_map.get("fairLaunch") {
        match &fl_entry.value {
            ConfigValue::Object(fl_entries) => {
                let fl_map: BTreeMap<&str, &crate::parser::ConfigEntry> =
                    fl_entries.iter().map(|e| (e.key.as_str(), e)).collect();
                for key in &["cooldownBetweenBuys", "antiSnipeBlocks", "duration"] {
                    match fl_map.get(key) {
                        None => {
                            out.push(TypeError {
                                kind: TypeErrorKind::InvalidTokenConfig {
                                    reason: format!(
                                        "`fairLaunch` block is missing mandatory key `{key}`"
                                    ),
                                    span: fl_entry.span,
                                },
                                span: fl_entry.span,
                                message: format!("WF-014: `fairLaunch` block missing `{key}`"),
                            });
                        }
                        Some(fl_key_entry) => {
                            if !matches!(fl_key_entry.value, ConfigValue::Int(_)) {
                                out.push(TypeError {
                                    kind: TypeErrorKind::InvalidTokenConfig {
                                        reason: format!("`fairLaunch.{key}` must be an integer"),
                                        span: fl_key_entry.span,
                                    },
                                    span: fl_key_entry.span,
                                    message: format!(
                                        "WF-014: `fairLaunch.{key}` must be an integer"
                                    ),
                                });
                            }
                        }
                    }
                }
            }
            _ => {
                out.push(TypeError {
                    kind: TypeErrorKind::InvalidTokenConfig {
                        reason: "`fairLaunch` must be an object block \
                                 `{ cooldownBetweenBuys: Int, antiSnipeBlocks: Int }`"
                            .into(),
                        span: fl_entry.span,
                    },
                    span: fl_entry.span,
                    message: "WF-014: `fairLaunch` must be an object block".into(),
                });
            }
        }
    }
}

/// Validate the NFT schema.
///
/// Mandatory: `name` (Str), `symbol` (Str), `maxSupply` (Int)
/// No `decimals` (NFTs don't have decimals).
fn check_wf014_nft_schema(
    entries: &[crate::parser::ConfigEntry],
    config_span: crate::lexer::token::Span,
    out: &mut Vec<TypeError>,
) {
    const MANDATORY: &[&str] = &["name", "symbol", "maxSupply"];
    const OPTIONAL: &[&str] = &[];

    let entry_map: BTreeMap<&str, &crate::parser::ConfigEntry> =
        entries.iter().map(|e| (e.key.as_str(), e)).collect();

    for key in MANDATORY {
        match entry_map.get(key) {
            None => {
                out.push(TypeError {
                    kind: TypeErrorKind::InvalidTokenConfig {
                        reason: format!("missing mandatory config key `{key}`"),
                        span: config_span,
                    },
                    span: config_span,
                    message: format!("WF-014: NFT config is missing mandatory key `{key}`"),
                });
            }
            Some(entry) => {
                let expected_type = match *key {
                    "name" | "symbol" => "Str",
                    "maxSupply" => "Int",
                    _ => continue,
                };
                if !config_value_matches_type(&entry.value, expected_type) {
                    out.push(TypeError {
                        kind: TypeErrorKind::InvalidTokenConfig {
                            reason: format!(
                                "config key `{key}` has wrong type: expected {expected_type}"
                            ),
                            span: entry.span,
                        },
                        span: entry.span,
                        message: format!("WF-014: NFT config key `{key}` has wrong value type"),
                    });
                }
            }
        }
    }

    // Unknown keys.
    let known: BTreeSet<&str> = MANDATORY.iter().chain(OPTIONAL.iter()).copied().collect();
    for entry in entries {
        if !known.contains(entry.key.as_str()) {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: format!("unknown config key `{}`", entry.key),
                    span: entry.span,
                },
                span: entry.span,
                message: format!("WF-014: NFT config has unknown key `{}`", entry.key),
            });
        }
    }
}

/// Validate the MultiToken schema.
///
/// Mandatory: `name` (Str)
fn check_wf014_multitoken_schema(
    entries: &[crate::parser::ConfigEntry],
    config_span: crate::lexer::token::Span,
    out: &mut Vec<TypeError>,
) {
    const MANDATORY: &[&str] = &["name"];
    const OPTIONAL: &[&str] = &[];

    let entry_map: BTreeMap<&str, &crate::parser::ConfigEntry> =
        entries.iter().map(|e| (e.key.as_str(), e)).collect();

    if !entry_map.contains_key("name") {
        out.push(TypeError {
            kind: TypeErrorKind::InvalidTokenConfig {
                reason: "missing mandatory config key `name`".into(),
                span: config_span,
            },
            span: config_span,
            message: "WF-014: MultiToken config is missing mandatory key `name`".into(),
        });
    } else if let Some(entry) = entry_map.get("name") {
        if !matches!(entry.value, ConfigValue::Str(_)) {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: "config key `name` has wrong type: expected Str".into(),
                    span: entry.span,
                },
                span: entry.span,
                message: "WF-014: MultiToken config key `name` has wrong value type".into(),
            });
        }
    }

    // Unknown keys.
    let known: BTreeSet<&str> = MANDATORY.iter().chain(OPTIONAL.iter()).copied().collect();
    for entry in entries {
        if !known.contains(entry.key.as_str()) {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: format!("unknown config key `{}`", entry.key),
                    span: entry.span,
                },
                span: entry.span,
                message: format!("WF-014: MultiToken config has unknown key `{}`", entry.key),
            });
        }
    }
}

/// Validate the Vault schema.
///
/// Mandatory: `name` (Str), `asset` (Str, address type)
fn check_wf014_vault_schema(
    entries: &[crate::parser::ConfigEntry],
    config_span: crate::lexer::token::Span,
    out: &mut Vec<TypeError>,
) {
    const MANDATORY: &[&str] = &["name", "asset"];
    const OPTIONAL: &[&str] = &[];

    let entry_map: BTreeMap<&str, &crate::parser::ConfigEntry> =
        entries.iter().map(|e| (e.key.as_str(), e)).collect();

    for key in MANDATORY {
        match entry_map.get(key) {
            None => {
                out.push(TypeError {
                    kind: TypeErrorKind::InvalidTokenConfig {
                        reason: format!("missing mandatory config key `{key}`"),
                        span: config_span,
                    },
                    span: config_span,
                    message: format!("WF-014: Vault config is missing mandatory key `{key}`"),
                });
            }
            Some(entry) => {
                // Both name and asset are Str.
                if !matches!(entry.value, ConfigValue::Str(_)) {
                    out.push(TypeError {
                        kind: TypeErrorKind::InvalidTokenConfig {
                            reason: format!("config key `{key}` has wrong type: expected Str"),
                            span: entry.span,
                        },
                        span: entry.span,
                        message: format!("WF-014: Vault config key `{key}` has wrong value type"),
                    });
                }
            }
        }
    }

    // Unknown keys.
    let known: BTreeSet<&str> = MANDATORY.iter().chain(OPTIONAL.iter()).copied().collect();
    for entry in entries {
        if !known.contains(entry.key.as_str()) {
            out.push(TypeError {
                kind: TypeErrorKind::InvalidTokenConfig {
                    reason: format!("unknown config key `{}`", entry.key),
                    span: entry.span,
                },
                span: entry.span,
                message: format!("WF-014: Vault config has unknown key `{}`", entry.key),
            });
        }
    }
}

/// Returns `true` if `value` matches the expected type string.
///
/// Used by WF-014 schema validators for simple type checks.
fn config_value_matches_type(value: &ConfigValue, expected: &str) -> bool {
    match expected {
        "Str" => matches!(value, ConfigValue::Str(_)),
        "Int" => matches!(value, ConfigValue::Int(_)),
        "Bool" => matches!(value, ConfigValue::Bool(_)),
        _ => false,
    }
}

// ─── WF-015: pure/view effect conformance ────────────────────────────────────

/// WF-015 — Functions declared `pure` or `view` must not perform effects that
/// violate their declared effect class.
///
/// ## Syntactic over-approximation (NOT full read/write-set analysis)
///
/// `pure` violation: any `Expr::Member` where receiver is `self` (state read).
/// `view` violation: any `Stmt::Assign { target: Expr::Member(self, field) }` (state write).
///
/// Both violations: walk function body via the canonical [`crate::visit::Visitor`]
/// (`walk_stmt`/`walk_expr`) — the shared traversal in `visit.rs` (AGENTS §2 DRY).
///
/// Mutability is read from the raw `Function.mutability` field in the AST
/// (accessed via `contract.members()` → `ContractMember::Function(f)`).
///
/// See `docs/03-LANGUAGE_SPEC.md §30 WF-015`.
fn check_wf015_effect_conformance(typed_ast: &TypedAst) -> Vec<TypeError> {
    let mut violations = Vec::new();

    for contract in typed_ast.contracts() {
        for member in contract.members() {
            let ContractMember::Function(f) = member else {
                continue;
            };
            let Some(body) = f.body.as_deref() else {
                continue;
            };

            match f.mutability {
                Mutability::Pure => {
                    // pure: no state reads (self.field access) and no msg/block reads.
                    check_wf015_pure_violations(f.name.as_str(), body, &mut violations);
                }
                Mutability::View => {
                    // view: no state writes (self.field = ...).
                    check_wf015_view_violations(f.name.as_str(), body, &mut violations);
                }
                // Default and Payable: no effect restrictions.
                Mutability::Default | Mutability::Payable => {}
            }
        }
    }

    violations
}

/// Check a `pure` function body for state-read violations.
///
/// Violation: any `Expr::Member` where receiver is `self` (state read).
/// Also: `Expr::Ident("msg")` or `Expr::Ident("block")` (context reads).
///
/// Implemented via [`PureChecker`] using the canonical [`crate::visit::Visitor`] traversal.
fn check_wf015_pure_violations(func: &str, stmts: &[Stmt], out: &mut Vec<TypeError>) {
    let mut checker = PureChecker {
        func,
        out: Vec::new(),
    };
    checker.visit_stmts(stmts);
    out.extend(checker.out);
}

// ─── WF-015 pure Visitor ─────────────────────────────────────────────────────

/// Collects `pure` effect violations in a function body.
///
/// Violations: `Expr::Member(self, field)` (state read) and
/// `Expr::Ident("msg" | "block")` (context read).
///
/// The canonical [`walk_stmt`] / [`walk_expr`] traversal covers all nested
/// statement and expression bodies including expression-position `Expr::If_`
/// and `Expr::Match_` arms — no separate `walk_stmt_expr_bodies` call needed.
///
/// Lambda bodies are intentionally NOT descended into (separate scope).
struct PureChecker<'a> {
    func: &'a str,
    out: Vec<TypeError>,
}

impl Visitor for PureChecker<'_> {
    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            // `self.field` — state read.
            Expr::Member(obj, field, span) if is_self_expr(obj) => {
                self.out.push(TypeError {
                    kind: TypeErrorKind::EffectViolation {
                        func: self.func.to_owned(),
                        declared: "pure".into(),
                        found: format!("state read (`self.{field}`)"),
                        span: *span,
                    },
                    span: *span,
                    message: format!(
                        "WF-015: `pure` function `{}` reads state field `self.{field}`",
                        self.func
                    ),
                });
                // Do NOT recurse into obj — it is `self` (a leaf).
                return;
            }
            // `msg` or `block` — context read.
            Expr::Ident(name, span) if name == "msg" || name == "block" => {
                self.out.push(TypeError {
                    kind: TypeErrorKind::EffectViolation {
                        func: self.func.to_owned(),
                        declared: "pure".into(),
                        found: format!("context read (`{name}`)"),
                        span: *span,
                    },
                    span: *span,
                    message: format!(
                        "WF-015: `pure` function `{}` reads runtime context `{name}`",
                        self.func
                    ),
                });
                return; // Ident is a leaf — no sub-expressions.
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

/// Check a `view` function body for state-write violations.
///
/// Implemented via [`ViewChecker`] which uses the canonical [`Visitor`]
/// traversal — no separate `walk_stmt_expr_bodies` call needed.
fn check_wf015_view_violations(func: &str, stmts: &[Stmt], out: &mut Vec<TypeError>) {
    let mut checker = ViewChecker {
        func,
        out: Vec::new(),
    };
    checker.visit_stmts(stmts);
    out.extend(checker.out);
}

// ─── WF-015 view Visitor ─────────────────────────────────────────────────────

/// Collects `view` effect violations in a function body.
///
/// Violations:
/// - `Stmt::Assign { target: self.field }` — direct state write statement.
/// - `Expr::Assign_(self.field, ...)` — expression-form state write (e.g. in
///   loop body or if-expression arm) reached via the canonical [`walk_stmt`].
///
/// The canonical traversal automatically descends into expression-position
/// `Expr::If_` / `Expr::Match_` bodies — no separate `walk_stmt_expr_bodies`
/// call needed.
struct ViewChecker<'a> {
    func: &'a str,
    out: Vec<TypeError>,
}

impl Visitor for ViewChecker<'_> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Assign { target, span, .. } = stmt {
            if is_self_field_target_any(target) {
                self.out.push(TypeError {
                    kind: TypeErrorKind::EffectViolation {
                        func: self.func.to_owned(),
                        declared: "view".into(),
                        found: "state write".into(),
                        span: *span,
                    },
                    span: *span,
                    message: format!(
                        "WF-015: `view` function `{}` writes to contract state",
                        self.func
                    ),
                });
            }
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        // Catch expression-position assignments: `self.field = ...`.
        if let Expr::Assign_(target, _, _, span) = expr {
            if is_self_field_target_any(target) {
                self.out.push(TypeError {
                    kind: TypeErrorKind::EffectViolation {
                        func: self.func.to_owned(),
                        declared: "view".into(),
                        found: "state write".into(),
                        span: *span,
                    },
                    span: *span,
                    message: format!(
                        "WF-015: `view` function `{}` writes to contract state",
                        self.func
                    ),
                });
            }
        }
        walk_expr(self, expr);
    }
}

/// Returns `true` if `expr` is `self.ANYTHING` (any member access on `self`).
///
/// Used by WF-015 view check to detect state writes of the form `self.field = ...`.
fn is_self_field_target_any(expr: &Expr) -> bool {
    matches!(expr, Expr::Member(obj, _, _) if is_self_expr(obj))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
