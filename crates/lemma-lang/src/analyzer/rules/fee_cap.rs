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
//! ## Scoping decisions (4e)
//!
//! **State-field rate → Inconclusive.** Proving that a state-field rate is
//! bounded requires checking every writer of that field enforces
//! `rate <= maxFeePercent`.  Full writer-body analysis deferred to 4f/4g.
//! For 4e: state-field rate → `Inconclusive` (sound, rejects on doubt).
//!
//! **Multiplication-only fee not caught.** A fee expressed as `self.fee =
//! amount * feeRate` (no `/DENOM`) produces no `FeeExpr` and passes.  The
//! spec requires canonical `amount * rate / DENOM` form; a hook with no
//! division expression is assumed fee-free.  Extend in 4f/4g to detect
//! multiply-only fee paths.
//!
//! **Rate is assumed to be the second `Mul` operand** (`amount * rate`).
//! `rate * amount / DENOM` (operands swapped) treats `amount` as the rate
//! and emits `Inconclusive` rather than checking the literal.  This is safe
//! (sound — never lets a violation through) but rejects valid contracts
//! with flipped operand order.  Document your fee hook as `amount * RATE /
//! 10_000` to avoid this false positive.
//!
//! ## FeeExpr design (P3·Step 4e.5)
//!
//! The original implementation stored `rate_expr: &'a Expr` in `FeeExpr<'a>`,
//! tieing the collection result to the AST lifetime.  The port to
//! [`crate::visit::Visitor`] uses an owned `FeeExpr` enum instead — rate
//! classification happens at collection time, storing only the literal value
//! or the span needed for error reporting.  This removes the lifetime and
//! makes the consuming `check()` code simpler.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-002`.

use crate::analyzer::error::SafetyError;
use crate::lexer::token::Span;
use crate::parser::{expr_span, BinaryOp, ConfigValue, Expr, Literal};
use crate::type_checker::typed_contract::TypedContract;
use crate::visit::{walk_expr, Visitor};

use super::constants::{FEE_DENOM, PROTOCOL_MAX_FEE_BPS};

// ─── Public entry point ───────────────────────────────────────────────────────

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

        let mut collector = FeeCollector { out: Vec::new() };
        collector.visit_stmts(body);

        for fee_expr in collector.out {
            match fee_expr {
                FeeExpr::CanonicalLiteral { rate } => {
                    let rate_bps = clamp_bps(rate);
                    if rate_bps > declared_bps {
                        violations.push(SafetyError::FeeTooHigh {
                            declared: declared_bps,
                            found: rate_bps,
                        });
                    }
                }
                FeeExpr::CanonicalNonLiteral { rate_span } => {
                    let span = rate_span;
                    violations.push(SafetyError::Inconclusive {
                        rule: "SAFETY-002",
                        reason: "fee rate is non-canonical — use `amount * LITERAL_RATE / 10_000`"
                            .to_owned(),
                        span,
                    });
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

/// A fee expression found in a hook body, fully classified at collection time.
///
/// Using an owned enum (no lifetime) allows [`FeeCollector`] to implement
/// [`crate::visit::Visitor`] cleanly — rate classification happens in
/// `visit_expr` before any sub-expression recursion.
enum FeeExpr {
    /// `amount * LITERAL_RATE / DENOM` — canonical form with a literal rate.
    CanonicalLiteral {
        /// The fee rate in its raw form (interpret as basis points).
        rate: u128,
    },
    /// `amount * <non-literal> / DENOM` — canonical form, non-literal rate
    /// (inconclusive).
    CanonicalNonLiteral {
        /// Source span of the rate expression (from the canonical `crate::parser::expr_span`).
        /// Always valid — the canonical function returns `Span::at(0,0,0)` only for
        /// future `#[non_exhaustive]` variants that have no span (unreachable in practice).
        rate_span: Span,
    },
    /// Any `/` expression that is NOT in the canonical `x * y / DENOM` form.
    NonCanonical {
        /// Source location of the `/` operator.
        span: Span,
    },
}

// ─── Visitor impl ─────────────────────────────────────────────────────────────

/// Collects fee expressions from a hook body.
struct FeeCollector {
    out: Vec<FeeExpr>,
}

impl Visitor for FeeCollector {
    fn visit_expr(&mut self, expr: &Expr) {
        if let Expr::Binary(BinaryOp::Div, numerator, denom, span) = expr {
            // Classify the division expression based on denom and numerator shape.
            match (denom.as_ref(), numerator.as_ref()) {
                (Expr::Literal(Literal::Int(d), _), Expr::Binary(BinaryOp::Mul, _, rhs, _))
                    if *d == FEE_DENOM =>
                {
                    // Canonical form: `amount * rate / FEE_DENOM`.
                    // The second Mul operand is treated as the rate.
                    match rhs.as_ref() {
                        Expr::Literal(Literal::Int(n), _)
                        | Expr::Literal(Literal::IntTyped { value: n, .. }, _) => {
                            self.out.push(FeeExpr::CanonicalLiteral { rate: *n });
                        }
                        other => {
                            self.out.push(FeeExpr::CanonicalNonLiteral {
                                rate_span: expr_span(other),
                            });
                        }
                    }
                }
                _ => {
                    // Denom is not FEE_DENOM, or numerator is not `x * y`.
                    self.out.push(FeeExpr::NonCanonical { span: *span });
                }
            }
            // Fall through to walk_expr — recurses into both operands.
        }
        walk_expr(self, expr);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Clamp a `u128` value to `u16::MAX`, then cast to `u16`.
///
/// Used for basis-point values that may exceed `u16::MAX` (all such values are
/// already > `PROTOCOL_MAX_FEE_BPS` and will be rejected by the rule).
fn clamp_bps(n: u128) -> u16 {
    if n > u128::from(u16::MAX) {
        u16::MAX
    } else {
        n as u16
    }
}

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
            ConfigValue::Int(n) => Some(clamp_bps(*n)),
            // Percent(25) = "25%" = 2500 bps.  Scale: n * 100.
            ConfigValue::Percent(n) => Some(clamp_bps(n.saturating_mul(100))),
            _ => None,
        })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
