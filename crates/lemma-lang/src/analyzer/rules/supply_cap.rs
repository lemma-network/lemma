//! SAFETY-003 — Supply Cap rule.
//!
//! Enforces that token supply constraints declared in `config {}` are upheld
//! by the contract's implementation:
//!
//! 1. **`mintable: false`**: no function may contain a `totalSupply`-increasing
//!    write (`+=` or `= expr + totalSupply`).
//!
//! 2. **`maxSupply` declared**: every function that increases `totalSupply`
//!    must be preceded (in the linear statement sequence) by an `assert` that
//!    contains a `<=` or `<` comparison — a conservative cap guard.
//!
//! ## Applies to
//!
//! Token contracts (`is_token()`) AND contracts with `mintable` or `maxSupply`
//! in their `config {}` block.
//!
//! ## Scoping decision: conservative cap-assert detection
//!
//! The "preceding assert" check uses a recursive linear scan.  Any
//! `Stmt::Assert` with a `<=` or `<` comparison that provably precedes the
//! increasing write (at the same or an enclosing scope) is treated as a cap
//! guard.  This may accept contracts where the assert is unrelated to the
//! supply cap (over-acceptance).  Full operand inspection and a proper
//! dominator tree are 4g work.  Documented per AGENTS §solution-integrity.
//!
//! See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-003`.

use crate::analyzer::error::SafetyError;
use crate::lexer::token::Span;
use crate::parser::{AssignOp, BinaryOp, ConfigValue, Expr, MatchBody, Stmt};
use crate::type_checker::typed_contract::TypedContract;

/// Check a contract for SAFETY-003 supply cap violations.
///
/// Returns [`SafetyError::SupplyCapViolation`] for each violation found.
/// Returns an empty `Vec` if the contract is clean.
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // Rule applies only to contracts with a config block.
    let Some(config) = contract.config() else {
        return violations;
    };

    // Read mintable (default: true if absent).
    let mintable = get_config_bool(config, "mintable").unwrap_or(true);

    // Read maxSupply (default: uncapped if absent).
    let max_supply = get_config_int(config, "maxSupply");

    // If neither mintable:false nor maxSupply is declared, nothing to check.
    if mintable && max_supply.is_none() {
        return violations;
    }

    // Inspect every function for totalSupply-increasing writes.
    for func in contract.functions() {
        let Some(body) = func.body else {
            continue;
        };

        let writes = collect_increasing_supply_writes(body);

        if !mintable {
            // mintable: false — any increasing write is a violation.
            // One violation per function is sufficient to communicate the issue.
            if !writes.is_empty() {
                violations.push(SafetyError::SupplyCapViolation {
                    reason: format!(
                        "token declares mintable: false but totalSupply can be increased in `{}`",
                        func.name
                    ),
                });
            }
        }

        if let Some(_max_val) = max_supply {
            // maxSupply declared — each increasing write must be preceded by a cap assert.
            if !writes.is_empty() && !has_cap_assert_before_write(body) {
                violations.push(SafetyError::SupplyCapViolation {
                    reason: format!(
                        "totalSupply increase in `{}` is not dominated by a supply cap check",
                        func.name
                    ),
                });
            }
        }
    }

    violations
}

// ─── Increasing write detection ───────────────────────────────────────────────

/// Walk `stmts` recursively and collect the spans of all `totalSupply`-increasing writes.
fn collect_increasing_supply_writes(stmts: &[Stmt]) -> Vec<Span> {
    let mut out = Vec::new();
    walk_for_increasing_supply_writes(stmts, &mut out);
    out
}

/// Returns `true` if `stmts` contains at least one `totalSupply`-increasing write.
fn has_any_increasing_write(stmts: &[Stmt]) -> bool {
    !collect_increasing_supply_writes(stmts).is_empty()
}

fn walk_for_increasing_supply_writes(stmts: &[Stmt], out: &mut Vec<Span>) {
    for stmt in stmts {
        match stmt {
            Stmt::Assign {
                target,
                op,
                value,
                span,
            } => {
                if is_increasing_supply_write(target, op, value) {
                    out.push(*span);
                }
            }
            Stmt::Expr(Expr::Assign_(target, op, value, span), _) => {
                if is_increasing_supply_write(target, op, value) {
                    out.push(*span);
                }
            }
            // Recurse into control flow to find writes in nested blocks.
            Stmt::If { then, else_, .. } => {
                walk_for_increasing_supply_writes(then, out);
                if let Some(b) = else_ {
                    walk_for_increasing_supply_writes(b, out);
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                walk_for_increasing_supply_writes(body, out);
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let MatchBody::Block(stmts) = &arm.body {
                        walk_for_increasing_supply_writes(stmts, out);
                    }
                }
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                walk_for_increasing_supply_writes(body, out);
                walk_for_increasing_supply_writes(catch_body, out);
            }
            Stmt::Unchecked(body, _) => walk_for_increasing_supply_writes(body, out),
            _ => {}
        }
    }
}

/// Returns `true` if `(target, op, value)` is a `totalSupply`-increasing write.
///
/// - `self.totalSupply += amount` → `AssignOp::Add` → always increasing.
/// - `self.totalSupply = self.totalSupply + delta` → `AssignOp::Assign` with
///   `BinaryOp::Add` containing `self.totalSupply` as an operand.
fn is_increasing_supply_write(target: &Expr, op: &AssignOp, value: &Expr) -> bool {
    if !is_self_field(target, "totalSupply") {
        return false;
    }
    match op {
        AssignOp::Add => true, // += always increases
        AssignOp::Assign => expr_contains_add_with_total_supply(value),
        _ => false, // -=, *=, /=, %= are decreases or other operations
    }
}

/// Returns `true` if `expr` is `self.field` where `field == name`.
fn is_self_field(expr: &Expr, field: &str) -> bool {
    matches!(expr, Expr::Member(obj, f, _) if is_self(obj) && f == field)
}

/// Returns `true` if `expr` is the identifier `self`.
fn is_self(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

/// Returns `true` if `expr` contains `BinaryOp::Add` with `self.totalSupply`
/// as one of the operands (i.e., `self.totalSupply + delta` or `delta + self.totalSupply`).
fn expr_contains_add_with_total_supply(expr: &Expr) -> bool {
    match expr {
        Expr::Binary(BinaryOp::Add, lhs, rhs, _) => {
            is_self_field(lhs, "totalSupply")
                || is_self_field(rhs, "totalSupply")
                || expr_contains_add_with_total_supply(lhs)
                || expr_contains_add_with_total_supply(rhs)
        }
        Expr::Binary(_, lhs, rhs, _) => {
            expr_contains_add_with_total_supply(lhs) || expr_contains_add_with_total_supply(rhs)
        }
        _ => false,
    }
}

// ─── Cap assert detection ─────────────────────────────────────────────────────

/// Returns `true` if every `totalSupply`-increasing write in `stmts` is
/// **preceded** by a cap-guarding `assert` (any `<=` / `<` comparison).
///
/// ## Traversal rules
///
/// - **Direct writes**: guarded iff a cap assert appeared earlier in the same
///   statement list (linear scan, `saw_cap_assert` flag).
/// - **Nested blocks** (`if`/`while`/`for`/`loop`/`match`/`try`/`unchecked`):
///   if a nested block contains any increasing write it must be guarded by
///   either an enclosing assert (`saw_cap_assert`) **or** by an assert that
///   precedes the write *within* that nested block (recursive call).  A nested
///   write with no covering assert at any level → returns `false` (unsound to
///   accept).
///
/// No increasing write found anywhere → returns `true` (trivially guarded).
///
/// ## Known over-acceptance
///
/// Any assert with a `<=` / `<` comparison is treated as a cap guard,
/// regardless of whether its operands mention `totalSupply`.  Full operand
/// inspection is deferred to the 4g dominator-tree pass.
fn has_cap_assert_before_write(stmts: &[Stmt]) -> bool {
    let mut saw_cap_assert = false;
    for stmt in stmts {
        match stmt {
            Stmt::Assert { cond, .. } => {
                if expr_is_comparison(cond) {
                    saw_cap_assert = true;
                }
            }
            // Direct writes at this statement level.
            Stmt::Assign {
                target, op, value, ..
            } => {
                if is_increasing_supply_write(target, op, value) {
                    return saw_cap_assert;
                }
            }
            Stmt::Expr(Expr::Assign_(target, op, value, _), _) => {
                if is_increasing_supply_write(target, op, value) {
                    return saw_cap_assert;
                }
            }
            // Nested blocks: if writes exist inside, they must be covered by
            // either the enclosing assert or an internal assert.
            Stmt::If { then, else_, .. } => {
                let then_w = has_any_increasing_write(then);
                let else_w = else_.as_ref().is_some_and(|b| has_any_increasing_write(b));
                if (then_w || else_w) && !saw_cap_assert {
                    if then_w && !has_cap_assert_before_write(then) {
                        return false;
                    }
                    if else_w {
                        if let Some(b) = else_ {
                            if !has_cap_assert_before_write(b) {
                                return false;
                            }
                        }
                    }
                }
            }
            Stmt::While { body, .. } | Stmt::For { body, .. } | Stmt::Loop { body, .. } => {
                if has_any_increasing_write(body)
                    && !saw_cap_assert
                    && !has_cap_assert_before_write(body)
                {
                    return false;
                }
            }
            Stmt::Match { arms, .. } => {
                for arm in arms {
                    if let MatchBody::Block(body) = &arm.body {
                        if has_any_increasing_write(body)
                            && !saw_cap_assert
                            && !has_cap_assert_before_write(body)
                        {
                            return false;
                        }
                    }
                }
            }
            Stmt::Try {
                body, catch_body, ..
            } => {
                for b in [body.as_slice(), catch_body.as_slice()] {
                    if has_any_increasing_write(b)
                        && !saw_cap_assert
                        && !has_cap_assert_before_write(b)
                    {
                        return false;
                    }
                }
            }
            Stmt::Unchecked(body, _)
                if has_any_increasing_write(body)
                    && !saw_cap_assert
                    && !has_cap_assert_before_write(body) =>
            {
                return false;
            }
            _ => {}
        }
    }
    // No increasing write found at any depth → trivially guarded.
    true
}

/// Returns `true` if `expr` contains a `<=` or `<` comparison.
///
/// Conservative: any comparison is treated as a potential cap guard.
fn expr_is_comparison(expr: &Expr) -> bool {
    match expr {
        Expr::Binary(BinaryOp::LtEq | BinaryOp::Lt, _, _, _) => true,
        Expr::Binary(BinaryOp::And | BinaryOp::Or, lhs, rhs, _) => {
            expr_is_comparison(lhs) || expr_is_comparison(rhs)
        }
        Expr::Unary(_, inner, _) => expr_is_comparison(inner),
        _ => false,
    }
}

// ─── Config helpers ───────────────────────────────────────────────────────────

fn get_config_bool(entries: &[crate::parser::ConfigEntry], key: &str) -> Option<bool> {
    entries.iter().find(|e| e.key == key).and_then(|e| {
        if let ConfigValue::Bool(b) = e.value {
            Some(b)
        } else {
            None
        }
    })
}

fn get_config_int(entries: &[crate::parser::ConfigEntry], key: &str) -> Option<u128> {
    entries
        .iter()
        .find(|e| e.key == key)
        .and_then(|e| match &e.value {
            ConfigValue::Int(n) => Some(*n),
            // Percent(25) = "25%" = 2500 bps.  Scale: n * 100.
            ConfigValue::Percent(n) => Some(n.saturating_mul(100)),
            _ => None,
        })
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
