use std::collections::BTreeSet;

use crate::{check, parse, tokenize};

use super::{
    all_auth_sets, auth_set, compute_eff_auth, is_unguarded, requires_governance,
    requires_owner_only, Guard,
};
use crate::analyzer::cfg::build_call_graph;

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── auth_set ─────────────────────────────────────────────────────────────────

#[test]
fn auth_set_empty_for_unguarded_pub_fn() {
    let ast = typed_ast("contract C { pub fn foo() {} }");
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let guards = auth_set(&fns[0]);
    assert!(guards.is_empty(), "unguarded fn must have empty auth set");
}

#[test]
fn auth_set_has_only_owner_for_onlyowner_fn() {
    let ast = typed_ast("contract C { @onlyOwner pub fn admin() {} }");
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let guards = auth_set(&fns[0]);
    assert!(
        guards.contains(&Guard::OnlyOwner),
        "expected OnlyOwner guard, got {guards:?}"
    );
    assert!(!requires_governance(&guards));
    assert!(requires_owner_only(&guards));
}

#[test]
fn auth_set_has_governance_role_for_role_annotated_fn() {
    let ast = typed_ast(r#"contract C { @onlyRole("GOVERNANCE") pub fn gov() {} }"#);
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let guards = auth_set(&fns[0]);
    assert!(
        guards.contains(&Guard::OnlyRole("GOVERNANCE".to_owned())),
        "expected OnlyRole(GOVERNANCE) guard, got {guards:?}"
    );
    assert!(requires_governance(&guards));
    assert!(!requires_owner_only(&guards));
}

#[test]
fn auth_set_has_when_not_paused_guard() {
    let ast = typed_ast("contract C { @whenNotPaused pub fn guarded() {} }");
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let guards = auth_set(&fns[0]);
    assert!(guards.contains(&Guard::WhenNotPaused));
    assert!(
        is_unguarded(&guards),
        "whenNotPaused alone is not an access-restriction guard"
    );
}

#[test]
fn auth_set_has_non_reentrant_guard() {
    let ast = typed_ast("contract C { @nonReentrant pub fn withdraw() {} }");
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let guards = auth_set(&fns[0]);
    assert!(guards.contains(&Guard::NonReentrant));
}

#[test]
fn auth_set_collects_multiple_guards() {
    let ast =
        typed_ast(r#"contract C { @onlyOwner @whenNotPaused @nonReentrant pub fn admin() {} }"#);
    let contracts = ast.contracts();
    let fns = contracts[0].functions();
    let guards = auth_set(&fns[0]);
    assert!(guards.contains(&Guard::OnlyOwner));
    assert!(guards.contains(&Guard::WhenNotPaused));
    assert!(guards.contains(&Guard::NonReentrant));
    assert_eq!(guards.len(), 3);
}

// ─── compute_eff_auth ─────────────────────────────────────────────────────────

#[test]
fn eff_auth_propagates_entry_guards_to_callees() {
    // @onlyOwner pub fn entry calls helper(); helper has no own guards.
    // EffAuth(helper from entry) = {OnlyOwner}.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
@onlyOwner pub fn entry() {
let _ = self.getX()
}
pub view fn getX() -> u128 {
return self.x
}
}"#,
    );
    let contracts = ast.contracts();
    let contract = &contracts[0];
    let cg = build_call_graph(contract);
    let fn_guards = all_auth_sets(contract);

    let eff = compute_eff_auth("entry", &fn_guards, &cg);
    // entry itself should have OnlyOwner
    assert!(eff["entry"].contains(&Guard::OnlyOwner));
    // getX reached from entry should inherit OnlyOwner
    assert!(
        eff.get("getX")
            .is_some_and(|g| g.contains(&Guard::OnlyOwner)),
        "EffAuth for getX from @onlyOwner entry must include OnlyOwner; got {eff:?}"
    );
}

#[test]
fn eff_auth_handles_entry_with_no_callees() {
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
@onlyOwner pub fn setX(v: u128) { self.x = v }
}"#,
    );
    let contracts = ast.contracts();
    let contract = &contracts[0];
    let cg = build_call_graph(contract);
    let fn_guards = all_auth_sets(contract);

    let eff = compute_eff_auth("setX", &fn_guards, &cg);
    assert!(eff["setX"].contains(&Guard::OnlyOwner));
    // No other entries since setX has no callees.
    assert_eq!(eff.len(), 1);
}

#[test]
fn eff_auth_handles_direct_recursion_without_hang() {
    // A directly recursive function must not cause infinite loop.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 }
pub fn recurse(n: u128) {
let _ = self.recurse(n)
}
}"#,
    );
    let contracts = ast.contracts();
    let contract = &contracts[0];
    let cg = build_call_graph(contract);
    let fn_guards = all_auth_sets(contract);

    // Must terminate without hanging.
    let eff = compute_eff_auth("recurse", &fn_guards, &cg);
    assert!(eff.contains_key("recurse"));
}

// ─── Guard predicates ─────────────────────────────────────────────────────────

#[test]
fn requires_governance_false_for_only_owner() {
    let mut guards = BTreeSet::new();
    guards.insert(Guard::OnlyOwner);
    assert!(!requires_governance(&guards));
}

#[test]
fn requires_governance_true_only_for_governance_role() {
    let mut guards = BTreeSet::new();
    guards.insert(Guard::OnlyRole("GOVERNANCE".to_owned()));
    assert!(requires_governance(&guards));
    guards.clear();
    guards.insert(Guard::OnlyRole("OPERATOR".to_owned()));
    assert!(
        !requires_governance(&guards),
        "OPERATOR role is not GOVERNANCE"
    );
}

#[test]
fn is_unguarded_true_for_empty_set() {
    let guards: BTreeSet<Guard> = BTreeSet::new();
    assert!(is_unguarded(&guards));
}

#[test]
fn is_unguarded_false_for_onlyowner() {
    let mut guards = BTreeSet::new();
    guards.insert(Guard::OnlyOwner);
    assert!(!is_unguarded(&guards));
}
