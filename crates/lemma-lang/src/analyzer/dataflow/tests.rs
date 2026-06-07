use crate::{check, parse, tokenize};

use super::{state_write_reachability, taint_propagate, TaintedVar};
use crate::analyzer::cfg::build_call_graph;

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── taint_propagate ─────────────────────────────────────────────────────────

#[test]
fn taint_does_not_propagate_through_pure_fn() {
    // A function with no parameters and no external calls must have an empty
    // taint set — there are no untrusted inputs.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub view fn pureCalc() -> u128 {
return 42
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    let taint = taint_propagate(&contracts[0], &cg);

    let calc_taint = taint.get("pureCalc").cloned().unwrap_or_default();
    assert!(
        calc_taint.is_empty(),
        "pureCalc has no params or ext calls — taint set must be empty; got {calc_taint:?}"
    );
}

#[test]
fn taint_params_always_tainted() {
    // Every function parameter is a taint seed (caller-controlled).
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn process(a: u128, b: Address) {}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    let taint = taint_propagate(&contracts[0], &cg);

    let proc_taint = taint.get("process").expect("process must be in taint map");
    assert!(
        proc_taint.contains(&TaintedVar::param("a")),
        "param `a` must be tainted; got {proc_taint:?}"
    );
    assert!(
        proc_taint.contains(&TaintedVar::param("b")),
        "param `b` must be tainted; got {proc_taint:?}"
    );
}

#[test]
fn taint_propagates_from_external_call_arg() {
    // `let result = target.getBalance()` — result is tainted (ExternalCallReturn).
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn fetch(target: Address, amount: u128) {
let result = target.getBalance()
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    let taint = taint_propagate(&contracts[0], &cg);

    let fetch_taint = taint.get("fetch").expect("fetch must be in taint map");
    assert!(
        fetch_taint.contains(&TaintedVar::ext_return("result")),
        "result from ext call must be ExternalCallReturn-tainted; got {fetch_taint:?}"
    );
    // Params are also tainted.
    assert!(fetch_taint.contains(&TaintedVar::param("target")));
    assert!(fetch_taint.contains(&TaintedVar::param("amount")));
}

#[test]
fn taint_propagation_terminates_on_cyclic_call_graph() {
    // Mutual recursion: a() calls b(), b() calls a() — must terminate without
    // hanging (the fixpoint converges because taint sets only grow, never shrink,
    // and are bounded by the finite parameter universe).
    let ast = typed_ast(
        r#"contract C {
state { n: u128 }
pub fn a(x: u128) {
let _ = self.b(x)
}
pub fn b(y: u128) {
let _ = self.a(y)
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    // Must not hang.
    let taint = taint_propagate(&contracts[0], &cg);

    assert!(taint.contains_key("a"), "a must appear in taint map");
    assert!(taint.contains_key("b"), "b must appear in taint map");
    assert!(
        taint["a"].contains(&TaintedVar::param("x")),
        "a.x must be tainted; got {:?}",
        taint["a"]
    );
    assert!(
        taint["b"].contains(&TaintedVar::param("y")),
        "b.y must be tainted; got {:?}",
        taint["b"]
    );
}

#[test]
fn taint_propagates_from_ext_call_inside_if_branch() {
    // `let r = target.getBalance()` nested inside an `if` branch — the
    // `collect_ext_bindings` recursion into nested control flow must reach it.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn f(c: bool, target: Address) {
if (c) {
let r = target.getBalance()
}
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    let taint = taint_propagate(&contracts[0], &cg);

    assert!(
        taint["f"].contains(&TaintedVar::ext_return("r")),
        "ext binding inside if-branch must be ExternalCallReturn-tainted; got {:?}",
        taint["f"]
    );
}

// ─── state_write_reachability ─────────────────────────────────────────────────

#[test]
fn state_write_reachable_from_transfer_fn() {
    // transfer() writes to self.balances[to] — it must appear as a writer.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    let reach = state_write_reachability(&contracts[0], &cg);

    let writers = reach
        .get("balances")
        .expect("balances must have at least one writer");
    assert!(
        writers.contains("transfer"),
        "transfer must be in balances writers; got {writers:?}"
    );
}

#[test]
fn state_write_unreachable_from_view_fn() {
    // getBalance() only reads self.bal — it must NOT appear as a writer.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 }
pub view fn getBalance() -> u128 {
return self.bal
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    let reach = state_write_reachability(&contracts[0], &cg);

    let writers = reach.get("bal").cloned().unwrap_or_default();
    assert!(
        !writers.contains("getBalance"),
        "getBalance is read-only — must not be a bal writer; got {writers:?}"
    );
}

#[test]
fn state_write_reachability_is_transitive() {
    // outer() calls inner(); inner() writes self.bal.
    // Expected: both outer AND inner appear as writers of bal.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 }
pub fn outer() {
let _ = self.inner()
}
pub fn inner() {
self.bal = 0
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    let reach = state_write_reachability(&contracts[0], &cg);

    let writers = reach.get("bal").expect("bal must have at least one writer");
    assert!(
        writers.contains("inner"),
        "inner directly writes bal — must be in writers; got {writers:?}"
    );
    assert!(
        writers.contains("outer"),
        "outer calls inner (which writes bal) — must be transitively in writers; got {writers:?}"
    );
}

#[test]
fn state_write_reachability_multiple_fields_tracked_independently() {
    // Two state fields written by different functions.
    let ast = typed_ast(
        r#"contract C {
state {
supply: u128
paused: bool
}
pub fn mint(amount: u128) {
self.supply = self.supply + amount
}
@onlyOwner pub fn pause() {
self.paused = true
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    let reach = state_write_reachability(&contracts[0], &cg);

    let supply_w = reach.get("supply").expect("supply must have writers");
    let paused_w = reach.get("paused").expect("paused must have writers");
    assert!(supply_w.contains("mint"), "mint must write supply");
    assert!(!supply_w.contains("pause"), "pause must NOT write supply");
    assert!(paused_w.contains("pause"), "pause must write paused");
    assert!(!paused_w.contains("mint"), "mint must NOT write paused");
}
