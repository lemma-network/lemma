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
state { x: u128 = 0 }
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
init(other: Address) {
self.other = other
}
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
state { n: u128 = 0 }
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
state { bal: u128 = 0 }
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
state { x: u128 = 0 }
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
state { count: u128 = 0 }
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
state { bal: u128 = 0 }
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
state { bal: u128 = 0 }
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

// ─── Collection-method state writes (P3-cfg-1 fix) ──────────────────────────────

#[test]
fn cfg_nodes_collection_set_recorded_as_state_write() {
    // self.balances.set(k, v) is a write to OWN storage — must be StateWrite,
    // NOT an external call. (P3-cfg-1: state_write_key was blind to this.)
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
init() {}
pub fn credit(to: Address, amount: u128) {
self.balances.set(to, amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let credit = fns.iter().find(|f| f.name == "credit").expect("fn");
    let nodes = cfg_nodes(credit);
    assert!(
        nodes
            .iter()
            .any(|n| matches!(n, CfgNode::StateWrite { key, .. } if key == "balances")),
        "self.balances.set(...) must be a StateWrite to `balances`; got {nodes:?}"
    );
    assert!(
        !nodes
            .iter()
            .any(|n| matches!(n, CfgNode::ExternalCall { .. })),
        "a collection mutator on own state must NOT be an ExternalCall; got {nodes:?}"
    );
}

#[test]
fn cfg_nodes_set_add_recorded_as_state_write() {
    // self.voters.add(t) (Set mutator) — StateWrite to `voters`.
    let ast = typed_ast(
        r#"contract C {
state { voters: Set<Address> }
init() {}
pub fn enroll(who: Address) {
self.voters.add(who)
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let enroll = fns.iter().find(|f| f.name == "enroll").expect("fn");
    let nodes = cfg_nodes(enroll);
    assert!(
        nodes
            .iter()
            .any(|n| matches!(n, CfgNode::StateWrite { key, .. } if key == "voters")),
        "self.voters.add(...) must be a StateWrite to `voters`; got {nodes:?}"
    );
}

#[test]
fn cfg_nodes_array_sort_recorded_as_state_write() {
    // self.queue.sort() — in-place Array reordering, conservatively a StateWrite
    // (spec §11 ambiguous on in-place vs returns-new; reject-on-doubt for
    // SAFETY-004 soundness).
    let ast = typed_ast(
        r#"contract C {
state { queue: Array<u128> }
init() { self.queue = [] }
pub fn order() {
self.queue.sort()
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let order = fns.iter().find(|f| f.name == "order").expect("fn");
    let nodes = cfg_nodes(order);
    assert!(
        nodes
            .iter()
            .any(|n| matches!(n, CfgNode::StateWrite { key, .. } if key == "queue")),
        "self.queue.sort() must be a StateWrite to `queue`; got {nodes:?}"
    );
}

#[test]
fn cfg_nodes_array_query_method_not_state_write() {
    // self.queue.contains(x) (a read/query) must NOT be a StateWrite.
    let ast = typed_ast(
        r#"contract C {
state { queue: Array<u128> }
init() { self.queue = [] }
pub fn look(x: u128) {
let _ = self.queue.contains(x)
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let look = fns.iter().find(|f| f.name == "look").expect("fn");
    let nodes = cfg_nodes(look);
    assert!(
        !nodes
            .iter()
            .any(|n| matches!(n, CfgNode::StateWrite { key, .. } if key == "queue")),
        "self.queue.contains(...) is a read — must NOT be a StateWrite; got {nodes:?}"
    );
}

#[test]
fn cfg_nodes_address_field_method_is_external_not_write() {
    // self.checker.canTransfer(...) — `checker` is an Address field; calling a
    // method on it leaves the contract. NOT a collection mutator → ExternalCall,
    // NOT a StateWrite. (Confirms the P3-cfg-1 fix doesn't over-classify.)
    let ast = typed_ast(
        r#"contract C {
state { checker: Address }
init(c: Address) { self.checker = c }
pub fn gate(to: Address, amount: u128) {
let ok = self.checker.canTransfer(to, amount)
}
}"#,
    );
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let gate = fns.iter().find(|f| f.name == "gate").expect("fn");
    let nodes = cfg_nodes(gate);
    assert!(
        nodes
            .iter()
            .any(|n| matches!(n, CfgNode::ExternalCall { .. })),
        "method call on an Address field must be an ExternalCall; got {nodes:?}"
    );
    assert!(
        !nodes
            .iter()
            .any(|n| matches!(n, CfgNode::StateWrite { key, .. } if key == "checker")),
        "a non-mutator method on an Address field must NOT be a StateWrite; got {nodes:?}"
    );
}
