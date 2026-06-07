use crate::{check, parse, tokenize};

use super::{build_call_graph, cfg_nodes, ext_calls, CfgNode};

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── build_call_graph ─────────────────────────────────────────────────────────

#[test]
fn call_graph_records_self_method_call_as_internal_edge() {
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn outer() {
let _ = self.inner()
}
pub view fn inner() -> u128 {
return self.x
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    let outer_callees = &cg["outer"];
    assert!(
        outer_callees.contains("inner"),
        "outer → inner edge must be recorded; got {outer_callees:?}"
    );
}

#[test]
fn call_graph_does_not_record_external_call_as_edge() {
    // A call to a non-self object must not appear in the internal call graph.
    let ast = typed_ast(
        r#"contract C {
state { other: Address }
pub fn bridge(target: Address, amount: u128) {
let _ = target.transfer(amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let cg = build_call_graph(&contracts[0]);
    // "transfer" is an external call — must not be in the call graph edges.
    let bridge_callees = cg.get("bridge").cloned().unwrap_or_default();
    assert!(
        !bridge_callees.contains("transfer"),
        "external method call must not be a call-graph edge; got {bridge_callees:?}"
    );
}

#[test]
fn call_graph_handles_recursion_without_infinite_loop() {
    let ast = typed_ast(
        r#"contract C {
state { n: u128 }
pub fn count(x: u128) {
let _ = self.count(x)
}
}"#,
    );
    let contracts = ast.contracts();
    // Must not hang.
    let cg = build_call_graph(&contracts[0]);
    assert!(cg.contains_key("count"));
    assert!(
        cg["count"].contains("count"),
        "self-recursive edge must be recorded"
    );
}

// ─── ext_calls ────────────────────────────────────────────────────────────────

#[test]
fn ext_calls_empty_for_self_only_fn() {
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 }
pub view fn getBalance() -> u128 {
return self.bal
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let ext = ext_calls(&fns[0]);
    assert!(
        ext.is_empty(),
        "pure self-read fn must have no external calls; got {ext:?}"
    );
}

#[test]
fn ext_calls_detected_for_cross_contract_method_call() {
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn pay(target: Address, amount: u128) {
let _ = target.transfer(amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    // "pay" is the only function (or find it by name)
    let pay_fn = fns.iter().find(|f| f.name == "pay").expect("pay fn");
    let ext = ext_calls(pay_fn);
    assert!(
        !ext.is_empty(),
        "cross-contract method call must appear in ext_calls; got {ext:?}"
    );
    assert!(
        ext.iter().any(|e| e.callee_desc.contains("transfer")),
        "callee_desc must mention 'transfer'; got {ext:?}"
    );
}

// ─── cfg_nodes ────────────────────────────────────────────────────────────────

#[test]
fn cfg_nodes_state_write_detected_for_self_field_assign() {
    let ast = typed_ast(
        r#"contract C {
state { count: u128 }
pub fn increment() {
self.count = self.count + 1
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let nodes = cfg_nodes(&fns[0]);
    assert!(
        nodes
            .iter()
            .any(|n| matches!(n, CfgNode::StateWrite { key, .. } if key == "count")),
        "state write to `count` must appear in cfg_nodes; got {nodes:?}"
    );
}

#[test]
fn cfg_nodes_external_call_detected_before_state_write() {
    // Pattern that SAFETY-004 should catch: external call then state write.
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 }
pub fn badWithdraw(target: Address, amount: u128) {
let _ = target.transfer(amount)
self.bal = self.bal - amount
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let withdraw = fns.iter().find(|f| f.name == "badWithdraw").expect("fn");
    let nodes = cfg_nodes(withdraw);

    let ext_pos = nodes
        .iter()
        .position(|n| matches!(n, CfgNode::ExternalCall { .. }));
    let write_pos = nodes
        .iter()
        .position(|n| matches!(n, CfgNode::StateWrite { .. }));

    assert!(ext_pos.is_some(), "ExternalCall node must appear");
    assert!(write_pos.is_some(), "StateWrite node must appear");
    assert!(
        ext_pos.unwrap() < write_pos.unwrap(),
        "ExternalCall must precede StateWrite in CFG (reentrancy pattern)"
    );
}

#[test]
fn cfg_nodes_state_write_before_external_call_not_flagged_as_reentrancy_pattern() {
    // Good pattern: state write BEFORE external call (CEI order — no violation).
    let ast = typed_ast(
        r#"contract C {
state { bal: u128 }
pub fn goodWithdraw(target: Address, amount: u128) {
self.bal = self.bal - amount
let _ = target.transfer(amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let withdraw = fns.iter().find(|f| f.name == "goodWithdraw").expect("fn");
    let nodes = cfg_nodes(withdraw);

    let ext_pos = nodes
        .iter()
        .position(|n| matches!(n, CfgNode::ExternalCall { .. }));
    let write_pos = nodes
        .iter()
        .position(|n| matches!(n, CfgNode::StateWrite { .. }));

    assert!(ext_pos.is_some() && write_pos.is_some());
    assert!(
        write_pos.unwrap() < ext_pos.unwrap(),
        "In CEI pattern, StateWrite must precede ExternalCall"
    );
}
