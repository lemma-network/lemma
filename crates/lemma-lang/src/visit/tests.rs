//! Recording-visitor tests for [`crate::visit`].
//!
//! Proves that [`walk_stmt`] / [`walk_expr`] reach every reachable node,
//! including the gap-closures for SAFETY-012 (unchecked inside match/try).

use crate::parser::{Expr, Stmt};
use crate::visit::{walk_expr, walk_stmt, Visitor};
use crate::{check, parse, tokenize};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Recording visitor ────────────────────────────────────────────────────────

/// Counts visits by node kind.  Used to verify traversal completeness.
#[derive(Default)]
struct CountingVisitor {
    // Stmt kinds
    assign_stmt_count: usize,
    if_stmt_count: usize,
    match_stmt_count: usize,
    while_count: usize,
    for_count: usize,
    loop_count: usize,
    break_count: usize,
    continue_count: usize,
    assert_count: usize,
    revert_count: usize,
    try_count: usize,
    unchecked_count: usize,

    // Expr kinds
    if_expr_count: usize,
    match_expr_count: usize,
    assign_expr_count: usize,
}

impl Visitor for CountingVisitor {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Assign { .. } => self.assign_stmt_count += 1,
            Stmt::If { .. } => self.if_stmt_count += 1,
            Stmt::Match { .. } => self.match_stmt_count += 1,
            Stmt::While { .. } => self.while_count += 1,
            Stmt::For { .. } => self.for_count += 1,
            Stmt::Loop { .. } => self.loop_count += 1,
            Stmt::Break(..) => self.break_count += 1,
            Stmt::Continue(..) => self.continue_count += 1,
            Stmt::Assert { .. } => self.assert_count += 1,
            Stmt::Revert { .. } => self.revert_count += 1,
            Stmt::Try { .. } => self.try_count += 1,
            Stmt::Unchecked(..) => self.unchecked_count += 1,
            _ => {}
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            Expr::Assign_(..) => self.assign_expr_count += 1,
            Expr::If_ { .. } => self.if_expr_count += 1,
            Expr::Match_(..) => self.match_expr_count += 1,
            _ => {}
        }
        walk_expr(self, expr);
    }
}

fn count_fn_body(contract_src: &str, fn_name: &str) -> CountingVisitor {
    let ast = typed_ast(contract_src);
    let contracts = ast.contracts();
    let func = contracts[0]
        .functions()
        .into_iter()
        .find(|f| f.name == fn_name)
        .unwrap_or_else(|| panic!("function '{fn_name}' not found"));
    let mut v = CountingVisitor::default();
    if let Some(body) = func.body {
        v.visit_stmts(body);
    }
    v
}

// ─── Tests: structural coverage ───────────────────────────────────────────────

/// Visitor descends into nested control-flow statements.
/// Note: `if`/`match` require parenthesised scrutinee in Lem.
#[test]
fn visitor_reaches_nested_control_flow_stmts() {
    let v = count_fn_body(
        r#"contract C {
state { x: u128 = 0 }
init() { self.x = 0 }
pub fn exercise(val: u128) {
if (val > 0) {
while (self.x < val) {
self.x = self.x + 1
}
}
match (val) {
0 => {}
_ => { self.x = 1 }
}
loop {
if (self.x > 100) { break }
continue
}
for i in 0..10 {
self.x = self.x + i
}
unchecked {
self.x = self.x + val
}
try { assert (self.x > 0) } catch (err) { revert }
}
}"#,
        "exercise",
    );

    assert!(v.if_stmt_count >= 2, "if stmts: {}", v.if_stmt_count);
    assert!(v.while_count >= 1, "while: {}", v.while_count);
    assert!(v.match_stmt_count >= 1, "match: {}", v.match_stmt_count);
    assert!(v.loop_count >= 1, "loop: {}", v.loop_count);
    assert!(v.break_count >= 1, "break: {}", v.break_count);
    assert!(v.continue_count >= 1, "continue: {}", v.continue_count);
    assert!(v.for_count >= 1, "for: {}", v.for_count);
    assert!(v.unchecked_count >= 1, "unchecked: {}", v.unchecked_count);
    assert!(v.try_count >= 1, "try: {}", v.try_count);
    assert!(v.assert_count >= 1, "assert: {}", v.assert_count);
    assert!(v.revert_count >= 1, "revert: {}", v.revert_count);
    assert!(v.assign_stmt_count >= 3, "assigns: {}", v.assign_stmt_count);
}

/// Visitor descends into Expr::If_ statement bodies (value-position if).
///
/// `let x = if (cond) { stmt; expr } else { expr }` — the `Assign` inside
/// the Expr::If_ body must be visited as a statement.
#[test]
fn visitor_descends_into_expr_if_stmt_bodies() {
    let v = count_fn_body(
        r#"contract C {
state { x: u128 = 0 }
init() { self.x = 0 }
pub fn foo(flag: bool) {
let y = if (flag) { self.x = 99
self.x } else { self.x }
}
}"#,
        "foo",
    );

    assert!(
        v.if_expr_count >= 1,
        "Expr::If_ visited: {}",
        v.if_expr_count
    );
    // `self.x = 99` inside the Expr::If_ body must be visited as a Stmt::Assign
    assert!(
        v.assign_stmt_count >= 1,
        "assign inside If_ body visited: {}",
        v.assign_stmt_count
    );
}

/// Visitor descends into Expr::Match_ statement bodies (value-position match).
///
/// `let result = match (val) { arm => { stmt; expr } }` — assigns inside
/// match arm block bodies must be visited.
#[test]
fn visitor_descends_into_expr_match_stmt_bodies() {
    let v = count_fn_body(
        r#"contract C {
state { x: u128 = 0 }
init() { self.x = 0 }
pub fn foo(val: u128) -> u128 {
let result = match (val) {
0 => { self.x = 10
0 }
_ => { self.x = 20
val }
}
return result
}
}"#,
        "foo",
    );

    assert!(
        v.match_expr_count >= 1,
        "Expr::Match_ visited: {}",
        v.match_expr_count
    );
    assert!(
        v.assign_stmt_count >= 2,
        "assigns inside Match_ arms visited: {}",
        v.assign_stmt_count
    );
}

/// Gap-closure: visitor reaches Assign inside `unchecked { match (...) { } }`.
///
/// This was the false-negative in `integer.rs::find_unchecked_arithmetic`
/// before P3·Step 4e.5 — `Stmt::Match` inside an unchecked block was missed.
/// The canonical visitor handles it automatically.
#[test]
fn visitor_reaches_assign_inside_unchecked_match_gap_closure() {
    let v = count_fn_body(
        r#"contract C {
state { x: u128 = 0 }
init() { self.x = 0 }
pub fn foo(val: u128) {
unchecked {
match (val) {
0 => { self.x = 0 }
_ => { self.x = self.x + val }
}
}
}
}"#,
        "foo",
    );

    assert_eq!(v.unchecked_count, 1, "unchecked block visited");
    assert_eq!(
        v.match_stmt_count, 1,
        "match inside unchecked visited (was missing before)"
    );
    assert_eq!(
        v.assign_stmt_count, 2,
        "both assigns inside unchecked match arms visited"
    );
}

/// Gap-closure: visitor reaches Assign inside `unchecked { try { ... } }`.
///
/// `Stmt::Try` inside an unchecked block was also missed by the old walker.
#[test]
fn visitor_reaches_assign_inside_unchecked_try_gap_closure() {
    let v = count_fn_body(
        r#"contract C {
state { x: u128 = 0 }
init() { self.x = 0 }
pub fn foo(val: u128) {
unchecked {
try {
self.x = self.x + val
} catch (err) {
self.x = 0
}
}
}
}"#,
        "foo",
    );

    assert_eq!(v.unchecked_count, 1, "unchecked block visited");
    assert_eq!(
        v.try_count, 1,
        "try inside unchecked visited (was missing before)"
    );
    assert_eq!(
        v.assign_stmt_count, 2,
        "assigns inside unchecked try body and catch visited"
    );
}

/// Visitor visits both range-bound expressions in `for i in start..end`.
#[test]
fn visitor_visits_for_in_range_stmts() {
    let v = count_fn_body(
        r#"contract C {
state { x: u128 = 0 }
init() { self.x = 0 }
pub fn foo() {
for i in 0..10 {
self.x = self.x + i
}
}
}"#,
        "foo",
    );

    assert_eq!(v.for_count, 1, "for loop visited");
    assert_eq!(v.assign_stmt_count, 1, "assign inside for body visited");
}

/// Visitor visits both try body and catch body statements.
#[test]
fn visitor_visits_try_body_and_catch_body() {
    let v = count_fn_body(
        r#"contract C {
state { a: u128 = 0 }
state { b: u128 = 0 }
init() { self.a = 0 self.b = 0 }
pub fn foo() {
try {
self.a = 1
} catch (err) {
self.b = 2
}
}
}"#,
        "foo",
    );

    assert_eq!(v.try_count, 1, "try visited");
    assert_eq!(
        v.assign_stmt_count, 2,
        "both try-body and catch-body assigns visited"
    );
}
