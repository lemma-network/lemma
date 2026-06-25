use std::collections::BTreeSet;

use crate::{parse, tokenize};

use super::{auth_set, is_access_unrestricted, requires_governance, requires_owner_only, Guard};

fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
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
        is_access_unrestricted(&guards),
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
fn is_access_unrestricted_true_for_empty_set() {
    let guards: BTreeSet<Guard> = BTreeSet::new();
    assert!(is_access_unrestricted(&guards));
}

#[test]
fn is_access_unrestricted_false_for_onlyowner() {
    let mut guards = BTreeSet::new();
    guards.insert(Guard::OnlyOwner);
    assert!(!is_access_unrestricted(&guards));
}
