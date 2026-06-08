//! SAFETY-002 — Fee Cap rule.
//!
//! Verifies that transfer fees declared and implemented in `#[onTransfer]`
//! hooks do not exceed the protocol ceiling of 2500 bps (25.00%).
//!
//! ## Scope (4e)
//!
//! Only `#[onTransfer]`-annotated functions are inspected.  The rule checks:
//!
//! 1. **Config cap**: if `maxFeePercent` in `config {}` exceeds
//!    [`PROTOCOL_MAX_FEE_BPS`] (2500 bps), the config itself is illegal.
//!
//! 2. **Canonical fee form**: walk the hook body for `amount * rate / DENOM`
//!    patterns.  If `rate` is a literal integer, compare it against the
//!    declared `maxFeePercent`.  If `rate` is a non-literal (state field,
//!    variable, expression), the analysis is **inconclusive** — the contract
//!    is rejected (soundness over completeness).
//!
//! 3. **Non-canonical division**: any `/` expression that is NOT in the
//!    `amount * rate / DENOM` form is also inconclusive.
//!
//! ## Scoping decision: state-field rate → Inconclusive
//!
//! Proving that a state-field rate is bounded requires checking every writer
//! of that field enforces `rate <= maxFeePercent`.  This is full writer-body
//! analysis, deferred to 4f/4g.  For 4e: state-field rate → `Inconclusive`.
//! This is **sound** (never lets a violation through) but incomplete (rejects
//! some valid contracts).
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-002`.

use crate::analyzer::error::SafetyError;
use crate::lexer::token::Span;
use crate::parser::{BinaryOp, ConfigValue, Expr, Literal, MatchBody, Stmt};
use crate::type_checker::typed_contract::TypedContract;

use super::constants::{FEE_DENOM, PROTOCOL_MAX_FEE_BPS};

/// Check a contract for SAFETY-002 fee cap violations.
///
/// Returns [`SafetyError::FeeTooHigh`] when a literal fee rate exceeds the
/// declared `maxFeePercent` or the protocol ceiling.  Returns
/// [`SafetyError::Inconclusive`] for non-canonical fee expressions.
/// Returns an empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // Only token contracts with a config block can have fee configuration.
    // Plain contracts have no config → no fee rules apply.
    let Some(config) = contract.config() else {
        return violations;
    };

    // Read the declared maxFeePercent (in basis points).
    let declared_bps = get_config_bps(config, "maxFeePercent").unwrap_or(0);

    // Step 1: config itself is illegal if it exceeds the protocol ceiling.
    if declared_bps > PROTOCOL_MAX_FEE_BPS {
        violations.push(SafetyError::FeeTooHigh {
            declared: declared_bps,
            found: declared_bps,
        });
        // Still continue to check hook bodies — collect all violations.
    }

    // Step 2: inspect every #[onTransfer]-annotated hook.
    for func in contract.functions() {
        if !func.annotations.iter().any(|a| a.name == "onTransfer") {
            continue;
        }
        let Some(body) = func.body else {
            continue;
        };

        // Collect all fee expressions from the hook body.
        let mut fee_exprs: Vec<FeeExpr> = Vec::new();
        collect_fee_expressions(body, &mut fee_exprs);

        for fee_expr in fee_exprs {
            match fee_expr {
                FeeExpr::Canonical {
                    rate_expr,
                    div_span,
                } => {
                    match rate_expr {
                        Expr::Literal(Literal::Int(n), _)
                        | Expr::Literal(Literal::IntTyped { value: n, .. }, _) => {
                            // Literal rate — compare against declared cap.
                            // Safe cast: rates above u16::MAX are always > 2500.
                            let rate_bps = if *n > u128::from(u16::MAX) {
                                u16::MAX
                            } else {
                                *n as u16
                            };
                            if rate_bps > declared_bps {
                                violations.push(SafetyError::FeeTooHigh {
                                    declared: declared_bps,
                                    found: rate_bps,
                                });
                            }
                        }
                        other => {
                            // Non-literal rate — inconclusive (sound rejection).
                            let span = expr_span(other).unwrap_or(div_span);
                            violations.push(SafetyError::Inconclusive {
                                rule: "SAFETY-002",
                                reason: "fee rate is non-canonical — use `amount * LITERAL_RATE / 10_000`"
                                    .to_owned(),
                                span,
                            });
                        }
                    }
                }
                FeeExpr::NonCanonical { span } => {
                    violations.push(SafetyError::Inconclusive {
                        rule: "SAFETY-002",
                        reason: "fee expression is not in canonical form `amount * rate / 10_000`"
                            .to_owned(),
                        span,
                    });
                }
            }
        }
    }

    violations
}

// ─── Fee expression classification ───────────────────────────────────────────

/// A fee expression found in a hook body.
enum FeeExpr<'a> {
    /// `amount * rate / DENOM` — canonical form.
    /// `rate_expr` is the second operand of the `*`.
    Canonical { rate_expr: &'a Expr, div_span: Span },
    /// Any `/` expression that is NOT in the canonical form.
    NonCanonical { span: Span },
}

/// Walk all expressions in `stmts` recursively and collect fee expressions.
///
/// A fee expression is any `Expr::Binary(BinaryOp::Div, ..)` found anywhere
/// in the hook body.  Only hooks that contain at least one division are
/// inspected — a hook with no division has no fee expression and passes.
fn collect_fee_expressions<'a>(stmts: &'a [Stmt], out: &mut Vec<FeeExpr<'a>>) {
    for stmt in stmts {
        match stmt {
            Stmt::Assign { value, .. } => collect_fee_in_expr(value, out),
            Stmt::Let { expr, .. } => collect_fee_in_expr(expr, out),
            Stmt::Return(Some(expr), _) => collect_fee_in_expr(expr, out),
            Stmt::Expr(expr, _) => collect_fee_in_expr(expr, out),
            Stmt::If {
                cond, then, else_, ..
            } => {
                collect_fee_in_expr(cond, out);
                collect_fee_expressions(then, out);
                if let Some(b) = else_ {
                    collect_fee_expressions(b, out);
                }
            }
            Stmt::While { cond, body, .. } => {
                collect_fee_in_expr(cond, out);
                collect_fee_expressions(body, out);
            }
            Stmt::For { body, .. } => collect_fee_expressions(body, out),
            Stmt::Loop { body, .. } => collect_fee_expressions(body, out),
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    match &arm.body {
                        MatchBody::Block(stmts) => collect_fee_expressions(stmts, out),
                        MatchBody::Expr(e) => collect_fee_in_expr(e, out),
                    }
                }
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                collect_fee_expressions(body, out);
                collect_fee_expressions(catch_body, out);
            }
            Stmt::Unchecked(body, _) => collect_fee_expressions(body, out),
            Stmt::Assert { cond, .. } => collect_fee_in_expr(cond, out),
            Stmt::Emit { fields, .. } => {
                for (_, e) in fields {
                    collect_fee_in_expr(e, out);
                }
            }
            _ => {}
        }
    }
}

/// Walk an expression tree and collect fee expressions.
///
/// For each `Expr::Binary(BinaryOp::Div, numerator, denom, span)`:
/// - If `numerator` is `Expr::Binary(BinaryOp::Mul, _, rhs, _)` AND `denom`
///   is the literal `FEE_DENOM` (10_000) → canonical form; `rhs` is the rate.
/// - Otherwise → non-canonical division.
///
/// Recurses into all sub-expressions to catch nested fee computations.
fn collect_fee_in_expr<'a>(expr: &'a Expr, out: &mut Vec<FeeExpr<'a>>) {
    match expr {
        Expr::Binary(BinaryOp::Div, numerator, denom, span) => {
            // Check if this is the canonical form: `x * y / FEE_DENOM`.
            let denom_is_fee_denom = matches!(
                denom.as_ref(),
                Expr::Literal(Literal::Int(n), _) if *n == FEE_DENOM
            );
            if denom_is_fee_denom {
                if let Expr::Binary(BinaryOp::Mul, _lhs, rhs, _) = numerator.as_ref() {
                    // Canonical: `amount * rate / FEE_DENOM`.
                    // Treat the second operand of Mul as the rate.
                    out.push(FeeExpr::Canonical {
                        rate_expr: rhs.as_ref(),
                        div_span: *span,
                    });
                } else {
                    // Denominator is FEE_DENOM but numerator is not `x * y` → non-canonical.
                    out.push(FeeExpr::NonCanonical { span: *span });
                }
            } else {
                // Denominator is not FEE_DENOM → non-canonical division.
                out.push(FeeExpr::NonCanonical { span: *span });
            }
            // Also recurse into sub-expressions of the division operands
            // to catch nested fee computations (e.g. `(a * b / c) * d / e`).
            collect_fee_in_expr(numerator, out);
            // Note: we do NOT recurse into denom here — the denominator is
            // typically a literal and recursing would double-count.
        }
        // Recurse into all other binary expressions.
        Expr::Binary(_, lhs, rhs, _) => {
            collect_fee_in_expr(lhs, out);
            collect_fee_in_expr(rhs, out);
        }
        Expr::Unary(_, inner, _) => collect_fee_in_expr(inner, out),
        Expr::Call { callee, args, .. } => {
            collect_fee_in_expr(callee, out);
            for arg in args {
                match arg {
                    crate::parser::CallArg::Positional(e) => collect_fee_in_expr(e, out),
                    crate::parser::CallArg::Named(_, e) => collect_fee_in_expr(e, out),
                }
            }
        }
        Expr::Member(base, _, _) => collect_fee_in_expr(base, out),
        Expr::Index(base, idx, _) => {
            collect_fee_in_expr(base, out);
            collect_fee_in_expr(idx, out);
        }
        Expr::Cast { expr, .. } => collect_fee_in_expr(expr, out),
        Expr::Ternary {
            cond, then, else_, ..
        } => {
            collect_fee_in_expr(cond, out);
            collect_fee_in_expr(then, out);
            collect_fee_in_expr(else_, out);
        }
        Expr::Assign_(target, _, value, _) => {
            collect_fee_in_expr(target, out);
            collect_fee_in_expr(value, out);
        }
        Expr::If_ {
            cond, then, else_, ..
        } => {
            collect_fee_in_expr(cond, out);
            collect_fee_expressions(then, out);
            if let Some(b) = else_ {
                collect_fee_expressions(b, out);
            }
        }
        Expr::Match_(e, arms, _) => {
            collect_fee_in_expr(e, out);
            for arm in arms {
                match &arm.body {
                    MatchBody::Block(stmts) => collect_fee_expressions(stmts, out),
                    MatchBody::Expr(e2) => collect_fee_in_expr(e2, out),
                }
            }
        }
        // Literals, Ident, Tuple, Array, Struct_, New, Template, Try_, Nullish:
        // no division sub-expressions to recurse into at this level.
        _ => {}
    }
}

// ─── Config helpers ───────────────────────────────────────────────────────────

/// Read a config entry as basis points.
///
/// - `ConfigValue::Int(n)` → `n as u16` (already in bps)
/// - `ConfigValue::Percent(n)` → `n * 100` as u16 (e.g. `Percent(25)` = 2500 bps)
///
/// Returns `None` if the key is absent or has an incompatible type.
fn get_config_bps(entries: &[crate::parser::ConfigEntry], key: &str) -> Option<u16> {
    entries
        .iter()
        .find(|e| e.key == key)
        .and_then(|e| match &e.value {
            ConfigValue::Int(n) => {
                if *n > u128::from(u16::MAX) {
                    Some(u16::MAX)
                } else {
                    Some(*n as u16)
                }
            }
            ConfigValue::Percent(n) => {
                // Percent(25) = "25%" = 2500 bps.  Scale: n * 100.
                let bps = n.saturating_mul(100);
                if bps > u128::from(u16::MAX) {
                    Some(u16::MAX)
                } else {
                    Some(bps as u16)
                }
            }
            _ => None,
        })
}

/// Extract the source span from an expression (best-effort).
fn expr_span(expr: &Expr) -> Option<Span> {
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
        | Expr::Nullish(_, _, s)
        | Expr::Try_(_, s)
        | Expr::Template(_, s)
        | Expr::Match_(_, _, s)
        | Expr::Assign_(_, _, _, s) => Some(*s),
        Expr::Ternary { span: s, .. }
        | Expr::Cast { span: s, .. }
        | Expr::Lambda { span: s, .. }
        | Expr::New { span: s, .. }
        | Expr::If_ { span: s, .. }
        | Expr::Struct_ { span: s, .. } => Some(*s),
        // Expr is #[non_exhaustive]; future variants may not carry a span.
        #[allow(unreachable_patterns)]
        _ => None,
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
