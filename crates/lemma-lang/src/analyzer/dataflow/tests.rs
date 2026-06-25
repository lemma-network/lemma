use crate::{parse, tokenize};

use super::{restriction_fields, state_write_reachability};
use crate::analyzer::cfg::build_call_graph;

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

// ─── state_write_reachability ─────────────────────────────────────────────────

#[test]
fn state_write_reachable_from_transfer_fn() {
    // transfer() writes to self.balances[to] — it must appear as a writer.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
init() {}
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
state { bal: u128 = 0 }
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
state { bal: u128 = 0 }
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
supply: u128 = 0
paused: bool = false
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

// ─── restriction_fields ───────────────────────────────────────────────────────

#[test]
fn restriction_field_detected_via_assert_in_transfer() {
    // transfer() asserts !self.frozen[from] — `frozen` is a restriction field.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
state { frozen: Map<Address, bool> }
init() {}
pub fn transfer(to: Address, amount: u128) {
assert (!self.frozen[to])
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let fields = restriction_fields(&contracts[0]);
    assert!(
        fields.contains("frozen"),
        "`frozen` read in assert on transfer path must be a restriction field; got {fields:?}"
    );
}

#[test]
fn restriction_field_detected_via_if_revert_in_transfer() {
    // transfer() reverts when self.blacklisted[to] — `blacklisted` is a restriction field.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
state { blacklisted: Map<Address, bool> }
init() {}
pub fn transfer(to: Address, amount: u128) {
if (self.blacklisted[to]) {
revert "blocked"
}
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let fields = restriction_fields(&contracts[0]);
    assert!(
        fields.contains("blacklisted"),
        "`blacklisted` read in if-revert on transfer path must be a restriction field; got {fields:?}"
    );
}

#[test]
fn restriction_field_detected_in_on_transfer_hook() {
    // #[onTransfer] hook gating on self.paused — `paused` is a restriction field.
    let ast = typed_ast(
        r#"contract C {
state { paused: bool = false }
init() {}
@onTransfer
pub fn onTransfer(from: Address, to: Address, amount: u128) {
assert (!self.paused)
}
}"#,
    );
    let contracts = ast.contracts();
    let fields = restriction_fields(&contracts[0]);
    assert!(
        fields.contains("paused"),
        "`paused` read in onTransfer assert must be a restriction field; got {fields:?}"
    );
}

#[test]
fn non_gating_field_read_is_not_a_restriction_field() {
    // transfer() reads self.balances but only to compute, never to deny.
    // `balances` must NOT be flagged as a restriction field.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
init() {}
pub fn transfer(to: Address, amount: u128) {
self.balances[to] = self.balances[to] + amount
}
}"#,
    );
    let contracts = ast.contracts();
    let fields = restriction_fields(&contracts[0]);
    assert!(
        !fields.contains("balances"),
        "`balances` is read to compute, not to deny — must NOT be a restriction field; got {fields:?}"
    );
}

#[test]
fn restriction_field_not_detected_outside_transfer_path() {
    // A non-transfer function (`adminCheck`) asserting on self.frozen does NOT
    // make `frozen` a restriction field — only transfer-path reads count.
    let ast = typed_ast(
        r#"contract C {
state { frozen: Map<Address, bool> }
init() {}
pub fn adminCheck(who: Address) {
assert (!self.frozen[who])
}
}"#,
    );
    let contracts = ast.contracts();
    let fields = restriction_fields(&contracts[0]);
    assert!(
        !fields.contains("frozen"),
        "`frozen` read outside transfer path must NOT be a restriction field; got {fields:?}"
    );
}

#[test]
fn restriction_field_detected_via_else_branch_revert() {
    // Denial expressed as `if (self.allowed[to]) { ... } else { revert }` —
    // the else branch reverts, so `allowed` (read in the cond) is a restriction field.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
state { allowed: Map<Address, bool> }
init() {}
pub fn transfer(to: Address, amount: u128) {
if (self.allowed[to]) {
self.balances[to] = amount
} else {
revert "not allowed"
}
}
}"#,
    );
    let contracts = ast.contracts();
    let fields = restriction_fields(&contracts[0]);
    assert!(
        fields.contains("allowed"),
        "`allowed` gating an else-branch revert must be a restriction field; got {fields:?}"
    );
}

#[test]
fn restriction_field_detected_via_call_form_read() {
    // Call-form gating read: `assert(!self.frozen.contains(to))` — the
    // `self.frozen` member base inside the call must mark `frozen`.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
state { frozen: Set<Address> }
init() {}
pub fn transfer(to: Address, amount: u128) {
assert (!self.frozen.contains(to))
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let fields = restriction_fields(&contracts[0]);
    assert!(
        fields.contains("frozen"),
        "`frozen` read via .contains() in an assert must be a restriction field; got {fields:?}"
    );
}

#[test]
fn restriction_field_nested_if_flags_inner_guard_only() {
    // `if (a) { if (self.blacklisted[to]) { revert } }` — the INNER guard
    // (blacklisted) directly wraps the revert and must be flagged; the outer
    // guard (`a`, a param, not a field) reads no field, so nothing spurious.
    let ast = typed_ast(
        r#"contract C {
state { balances: Map<Address, u128> }
state { blacklisted: Map<Address, bool> }
state { checkEnabled: bool = true }
init() {}
pub fn transfer(to: Address, amount: u128) {
if (self.checkEnabled) {
if (self.blacklisted[to]) {
revert "blocked"
}
}
self.balances[to] = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let fields = restriction_fields(&contracts[0]);
    assert!(
        fields.contains("blacklisted"),
        "inner guard `blacklisted` directly wrapping revert must be flagged; got {fields:?}"
    );
    // `checkEnabled` is the outer guard — it does NOT directly gate the revert,
    // so it must NOT be flagged (correct attribution of the denial).
    assert!(
        !fields.contains("checkEnabled"),
        "outer guard `checkEnabled` does not directly gate the revert — must NOT be flagged; got {fields:?}"
    );
}
