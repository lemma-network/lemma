//! Tests for SAFETY-012 — Integer Safety rule.
//!
//! ## Inconclusive coverage (spec §5.2)
//!
//! SAFETY-012 is **decidable-exact** — `Stmt::Unchecked` is a syntactic marker
//! that is either present or absent. There is no `Inconclusive` path; all
//! contracts either pass (no unchecked arithmetic on state fields) or fail
//! (exact `UncheckedArithmetic` variant). No `Inconclusive→reject` case needed.
//!
//! ## Cross-rule interaction tests (P3·Step 4g)
//!
//! Cross-rule tests call `analyze_safety` directly to verify that multiple
//! rules fire simultaneously on a single contract.

use crate::analyzer::error::SafetyError;
use crate::{analyze_safety, parse, tokenize};

use super::check as integer_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── Positive tests (safe contracts → empty Vec) ──────────────────────────────

#[test]
fn integer_no_unchecked_block_passes() {
    // No unchecked block at all — no violation possible.
    let ast = typed_ast(
        r#"contract C {
state { balance: u128 = 0 }
pub fn deposit(amount: u128) {
self.balance = self.balance + amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "arithmetic outside unchecked must pass SAFETY-012; got {violations:?}"
    );
}

#[test]
fn integer_unchecked_local_only_passes() {
    // unchecked block with arithmetic that only touches a local variable — safe.
    let ast = typed_ast(
        r#"contract C {
state { balance: u128 = 0 }
pub fn compute(a: u128, b: u128) -> u128 {
let mut result: u128 = 0
unchecked {
result = a + b
}
return result
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "unchecked arithmetic on local var must pass SAFETY-012; got {violations:?}"
    );
}

// ─── Negative tests (violations → exact SafetyError variant) ─────────────────

#[test]
fn integer_unchecked_add_to_state_field_rejected() {
    // unchecked { self.balance = self.balance + amount } — must be rejected.
    let ast = typed_ast(
        r#"contract C {
state { balance: u128 = 0 }
pub fn badDeposit(amount: u128) {
unchecked {
self.balance = self.balance + amount
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "unchecked + to state field must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UncheckedArithmetic { op, .. } if op == "+"),
        "expected UncheckedArithmetic(+); got {:?}",
        violations[0]
    );
}

// ─── Cross-rule interaction tests (P3·Step 4g) ────────────────────────────────

#[test]
fn cross_rule_safety_012_and_002_combined() {
    // Contract with unchecked arithmetic on balance (SAFETY-012) AND a
    // maxFeePercent that exceeds the protocol ceiling of 2500 bps (SAFETY-002)
    // → both violations must appear in the combined Vec<SafetyError>.
    //
    // maxFeePercent: 3000 (30%) exceeds the protocol hard cap of 2500 bps (25%).
    let tokens = tokenize(
        r#"token T extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 maxFeePercent: 3000 }
state { balance: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
unchecked {
self.balance = self.balance - amount
}
}
}"#,
    )
    .expect("tokenize");
    let ast = parse(tokens).expect("parse");
    let typed = crate::type_checker::check_skip_wf(ast).expect("type check");
    let contracts = typed.contracts();
    let result = analyze_safety(&contracts[0]);
    let violations = result.unwrap_err();
    assert!(
        violations
            .iter()
            .any(|e| matches!(e, SafetyError::UncheckedArithmetic { .. })),
        "SAFETY-012 UncheckedArithmetic must be present; got {violations:?}"
    );
    assert!(
        violations
            .iter()
            .any(|e| matches!(e, SafetyError::FeeTooHigh { .. })),
        "SAFETY-002 FeeTooHigh must be present; got {violations:?}"
    );
}

#[test]
fn integer_unchecked_sub_to_state_field_rejected() {
    // unchecked { self.total_supply = self.total_supply - amount } — must be rejected.
    let ast = typed_ast(
        r#"contract C {
state { total_supply: u128 = 0 }
pub fn badBurn(amount: u128) {
unchecked {
self.total_supply = self.total_supply - amount
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "unchecked - to state field must produce one violation; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UncheckedArithmetic { op, .. } if op == "-"),
        "violation must be UncheckedArithmetic with op '-'; got {:?}",
        violations[0]
    );
}

// ─── Boundary tests ───────────────────────────────────────────────────────────

#[test]
fn integer_unchecked_local_var_not_state_write_passes() {
    // unchecked block that only computes a local variable (not self.*) — safe.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn localOnly(a: u128, b: u128) {
let mut tmp: u128 = 0
unchecked {
tmp = a * b
}
self.x = tmp
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "unchecked arithmetic on local var only must pass SAFETY-012; got {violations:?}"
    );
}

#[test]
fn integer_empty_unchecked_block_passes() {
    // Empty unchecked block — no violation.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
pub fn noop() {
unchecked {
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "empty unchecked block must pass SAFETY-012; got {violations:?}"
    );
}

// ─── Gap-closure tests (P3·Step 4e.5): match/try inside unchecked ────────────
//
// These tests prove the SAFETY-012 rule (not just the traversal infrastructure)
// emits UncheckedArithmetic for patterns that were false-negatives before the
// Visitor refactor.  The recording-visitor tests in visit/tests.rs prove
// traversal completeness; these tests prove the rule acts on what is traversed.

/// SAFETY-012 detects unchecked arithmetic nested inside a match arm.
///
/// Before P3·Step 4e.5, `find_unchecked_arithmetic` missed `Stmt::Match`
/// inside unchecked blocks — `self.x = self.x + val` in a match arm was a
/// false negative.
#[test]
fn integer_unchecked_match_arm_add_to_state_rejected() {
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
init() { self.x = 0 }
pub fn badMint(val: u128) {
unchecked {
match (val) {
0 => {}
_ => { self.x = self.x + val }
}
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "arithmetic in match arm inside unchecked must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UncheckedArithmetic { op, .. } if op == "+"),
        "expected UncheckedArithmetic(+); got {:?}",
        violations[0]
    );
}

/// SAFETY-012 detects unchecked arithmetic nested inside a try body.
///
/// Before P3·Step 4e.5, `find_unchecked_arithmetic` missed `Stmt::Try`
/// inside unchecked blocks — `self.x = self.x + val` in the try body was a
/// false negative.
#[test]
fn integer_unchecked_try_body_add_to_state_rejected() {
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
init() { self.x = 0 }
pub fn badMint(val: u128) {
unchecked {
try {
self.x = self.x + val
} catch (err) {
self.x = 0
}
}
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = integer_check(&contracts[0]);
    assert_eq!(
        violations.len(),
        1,
        "arithmetic in try body inside unchecked must be rejected; got {violations:?}"
    );
    assert!(
        matches!(&violations[0], SafetyError::UncheckedArithmetic { op, .. } if op == "+"),
        "expected UncheckedArithmetic(+); got {:?}",
        violations[0]
    );
}
