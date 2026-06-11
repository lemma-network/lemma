//! SAFETY-002 — Fee Cap rule (DB-A41 model).
//!
//! Verifies that the declared fee ceiling does not exceed the protocol hard
//! cap of 2500 bps (25.00%).
//!
//! ## DB-A41 fee model (replaces the old `amount * rate / DENOM` hook scan)
//!
//! Under DB-A41, fees are **not** computed in `#[onTransfer]` hooks.  Instead:
//!
//! - **Plain `Token`**: fee-free.  `maxFeePercent` in `config {}` is an
//!   immutable declared ceiling (informational).  The rule verifies: if
//!   `maxFeePercent` is present, it must not exceed `PROTOCOL_MAX_FEE_BPS`.
//!   No hook scanning is needed — plain tokens have no fee arithmetic.
//!
//! - **`TaxToken`**: the protocol accumulates `taxPool` automatically; the
//!   developer declares `fees { burn, holders, others }` in `state {}`.
//!   The rule checks:
//!   1. `maxFeePercent` config ≤ `PROTOCOL_MAX_FEE_BPS` (same as Token).
//!   2. The initial `fees` config block sum (`burn + holders + others`) ≤
//!      `maxFeePercent` AND ≤ `PROTOCOL_MAX_FEE_BPS`.  (WF-014 also checks
//!      this; SAFETY-002 is defense-in-depth.)
//!   3. Any function that writes `self.fees.burn` / `self.fees.holders` /
//!      `self.fees.others` with a non-literal value → `Inconclusive`
//!      (soundness over completeness).
//!   4. Any function that writes all three components with literals in the
//!      same function body → check the sum against the cap.
//!
//! ## What changed from the old model
//!
//! The old `FeeCollector` visitor that walked `#[onTransfer]` hooks for
//! `amount * rate / DENOM` patterns is **removed** — that model is superseded
//! by DB-A41.  The `FeeTooHigh` error variant is retained (same name, updated
//! semantics).
//!
//! ## Relationship to SAFETY-022
//!
//! SAFETY-022 (fee-change asymmetric timelock) is the runtime companion: it
//! checks that fee *increases* go through a timelock.  SAFETY-002 is the
//! compile-time ceiling check: it checks that the declared/set fee never
//! exceeds the protocol cap, regardless of timing.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-002`.

use crate::analyzer::error::SafetyError;
use crate::lexer::token::Span;
use crate::parser::{ConfigValue, Expr, Literal, Stmt};
use crate::type_checker::typed_contract::TypedContract;
use crate::visit::{walk_expr, walk_stmt, Visitor};

use super::constants::PROTOCOL_MAX_FEE_BPS;

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-002 fee cap violations (DB-A41 model).
///
/// - **Plain `Token`**: verifies `maxFeePercent` config ≤ `PROTOCOL_MAX_FEE_BPS`.
/// - **`TaxToken`**: verifies `maxFeePercent` config ceiling AND the initial
///   `fees` config block sum AND any literal fees-setter totals.
/// - **Plain `contract`**: no config block → no fee rules apply.
///
/// Returns an empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // Only token contracts with a config block can have fee configuration.
    let Some(config) = contract.config() else {
        return violations;
    };

    // Read the declared maxFeePercent ceiling (in basis points).
    // Absent → treat as PROTOCOL_MAX_FEE_BPS (no tighter declared ceiling).
    let declared_bps = get_config_bps(config, "maxFeePercent").unwrap_or(PROTOCOL_MAX_FEE_BPS);

    // Step 1: config ceiling itself must not exceed the protocol hard cap.
    // (WF-014 also catches this, but defense-in-depth is correct here.)
    if declared_bps > PROTOCOL_MAX_FEE_BPS {
        violations.push(SafetyError::FeeTooHigh {
            declared: declared_bps,
            found: declared_bps,
        });
        // Continue — collect all violations in one pass.
    }

    // Step 2: TaxToken only — check the initial fees config block sum AND
    // any fees-setter functions.
    // Plain Token is fee-free (DB-A41: no hook fee arithmetic).
    // Plain contract (None base_standard): no fee rules apply.
    if contract.base_standard() == Some("TaxToken") {
        check_tax_token_fees(contract, config, declared_bps, &mut violations);
    }

    violations
}

// ─── TaxToken fees check ──────────────────────────────────────────────────────

/// Check TaxToken-specific fee constraints:
/// 1. Initial `fees` config block sum ≤ cap.
/// 2. Any fees-setter function with literal component writes → check sum.
/// 3. Any fees-setter function with non-literal component writes → Inconclusive.
fn check_tax_token_fees(
    contract: &TypedContract<'_>,
    config: &[crate::parser::ConfigEntry],
    cap_bps: u16,
    violations: &mut Vec<SafetyError>,
) {
    // Step 2a: check the initial fees config block sum.
    if let Some(fees_sum) = get_fees_config_sum(config) {
        if fees_sum > cap_bps {
            violations.push(SafetyError::FeeTooHigh {
                declared: cap_bps,
                found: fees_sum,
            });
        }
    }

    // Step 2b: inspect fees-setter functions.
    for func in contract.functions() {
        let Some(body) = func.body else {
            continue;
        };

        let mut collector = FeesComponentCollector::default();
        collector.visit_stmts(body);

        // Non-literal component write → Inconclusive.
        if let Some(span) = collector.non_literal_span {
            violations.push(SafetyError::Inconclusive {
                rule: "SAFETY-002",
                reason: "fees component setter uses a non-literal value — \
                         use literal bps values so the fee cap can be verified statically"
                    .to_owned(),
                span,
            });
            continue; // One Inconclusive per function is sufficient.
        }

        // All three components written with literals → check sum.
        if let (Some(burn), Some(holders), Some(others)) = (
            collector.burn_literal,
            collector.holders_literal,
            collector.others_literal,
        ) {
            let total = burn.saturating_add(holders).saturating_add(others);
            let total_bps = clamp_bps(total);
            if total_bps > cap_bps {
                violations.push(SafetyError::FeeTooHigh {
                    declared: cap_bps,
                    found: total_bps,
                });
            }
        }
    }
}

// ─── Fees component collector ─────────────────────────────────────────────────

/// Collects literal values written to `self.fees.burn`, `self.fees.holders`,
/// `self.fees.others` in a single function body.
///
/// If any component is written with a non-literal value, `non_literal_span`
/// is set (analysis is inconclusive for this function).
#[derive(Default)]
struct FeesComponentCollector {
    /// Literal value written to `self.fees.burn`, if any.
    burn_literal: Option<u128>,
    /// Literal value written to `self.fees.holders`, if any.
    holders_literal: Option<u128>,
    /// Literal value written to `self.fees.others`, if any.
    others_literal: Option<u128>,
    /// Span of the first non-literal component write, if any.
    non_literal_span: Option<Span>,
}

impl Visitor for FeesComponentCollector {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Assign {
            target,
            value,
            span,
            ..
        } = stmt
        {
            self.check_fees_component_write(target, value, *span);
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        if let Expr::Assign_(target, _, value, span) = expr {
            self.check_fees_component_write(target, value, *span);
        }
        walk_expr(self, expr);
    }
}

impl FeesComponentCollector {
    /// Detect `self.fees.<component> = <value>` writes.
    ///
    /// Shape: `Member(Member(self, "fees"), component)`.
    fn check_fees_component_write(&mut self, target: &Expr, value: &Expr, span: Span) {
        // Target must be `self.fees.<component>`.
        let Expr::Member(inner, component, _) = target else {
            return;
        };
        let Expr::Member(obj, field, _) = inner.as_ref() else {
            return;
        };
        if !is_self_expr(obj) || field != "fees" {
            return;
        }
        // Only the three canonical fee components are relevant.
        let component_name = component.as_str();
        if !matches!(component_name, "burn" | "holders" | "others") {
            return;
        }

        // Classify the value.
        let literal_val = extract_literal_int(value);
        if let Some(n) = literal_val {
            match component_name {
                "burn" => self.burn_literal = Some(n),
                "holders" => self.holders_literal = Some(n),
                "others" => self.others_literal = Some(n),
                _ => {}
            }
        } else if self.non_literal_span.is_none() {
            self.non_literal_span = Some(span);
        }
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Returns `true` if `expr` is the identifier `self`.
fn is_self_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

/// Extract a literal integer from an expression, if it is one.
fn extract_literal_int(expr: &Expr) -> Option<u128> {
    match expr {
        Expr::Literal(Literal::Int(n), _) => Some(*n),
        Expr::Literal(Literal::IntTyped { value: n, .. }, _) => Some(*n),
        _ => None,
    }
}

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

/// Read the `fees` config block and return the sum of `burn + holders + others`.
///
/// Returns `None` if the `fees` key is absent or not an object block.
fn get_fees_config_sum(entries: &[crate::parser::ConfigEntry]) -> Option<u16> {
    let fees_entry = entries.iter().find(|e| e.key == "fees")?;
    let ConfigValue::Object(fee_fields) = &fees_entry.value else {
        return None;
    };
    let burn = fee_fields
        .iter()
        .find(|e| e.key == "burn")
        .and_then(|e| match &e.value {
            ConfigValue::Int(n) => Some(*n),
            _ => None,
        })
        .unwrap_or(0);
    let holders = fee_fields
        .iter()
        .find(|e| e.key == "holders")
        .and_then(|e| match &e.value {
            ConfigValue::Int(n) => Some(*n),
            _ => None,
        })
        .unwrap_or(0);
    let others = fee_fields
        .iter()
        .find(|e| e.key == "others")
        .and_then(|e| match &e.value {
            ConfigValue::Int(n) => Some(*n),
            _ => None,
        })
        .unwrap_or(0);
    let total = burn.saturating_add(holders).saturating_add(others);
    Some(clamp_bps(total))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
