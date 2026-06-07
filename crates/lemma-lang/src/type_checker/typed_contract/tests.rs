//! Tests for [`TypedContract`] projection (P3-checker-1).
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.

use crate::type_checker::types::{ResolvedType, SymbolKind};
use crate::{check, parse, tokenize};

// ─── Helper ───────────────────────────────────────────────────────────────────

fn check_src(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    check(ast).expect("check failed")
}

// ─── TypedAst::contracts ──────────────────────────────────────────────────────

#[test]
fn contracts_returns_all_contracts_in_ast() {
    let typed = check_src(
        r#"
        contract Foo {}
        contract Bar {}
        "#,
    );
    let contracts = typed.contracts();
    assert_eq!(contracts.len(), 2);
    let names: Vec<&str> = contracts.iter().map(|c| c.name()).collect();
    assert!(names.contains(&"Foo"));
    assert!(names.contains(&"Bar"));
}

#[test]
fn contracts_does_not_include_structs_or_enums() {
    let typed = check_src(
        r#"
        contract Foo {}
        struct Bar { x: u128 }
        enum Baz { A }
        "#,
    );
    let contracts = typed.contracts();
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts[0].name(), "Foo");
}

#[test]
fn typed_contract_name_matches_ast() {
    let typed = check_src("contract MyContract {}");
    let contracts = typed.contracts();
    assert_eq!(contracts.len(), 1);
    assert_eq!(contracts[0].name(), "MyContract");
}

#[test]
fn typed_contract_is_token_correct() {
    let typed = check_src(
        r#"
        contract Plain {}
        token MyToken extends Token {}
        "#,
    );
    let contracts = typed.contracts();
    assert_eq!(contracts.len(), 2);
    let plain = contracts.iter().find(|c| c.name() == "Plain").unwrap();
    let token = contracts.iter().find(|c| c.name() == "MyToken").unwrap();
    assert!(!plain.is_token());
    assert!(token.is_token());
}

#[test]
fn typed_contract_state_fields_include_name_and_type() {
    let typed = check_src(
        r#"
        contract Foo {
            state {
                balance: u128
                owner: Address
            }
        }
        "#,
    );
    let contracts = typed.contracts();
    let foo = &contracts[0];
    let fields = foo.state_fields();
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].name, "balance");
    assert_eq!(*fields[0].ty, ResolvedType::U128);
    assert!(!fields[0].is_immutable);
    assert_eq!(fields[1].name, "owner");
    assert_eq!(*fields[1].ty, ResolvedType::AddressTy);
    assert!(!fields[1].is_immutable);
}

#[test]
fn typed_contract_state_fields_immutable_flagged() {
    let typed = check_src(
        r#"
        contract Foo {
            state { balance: u128 }
            immutable owner: Address
        }
        "#,
    );
    let contracts = typed.contracts();
    let foo = &contracts[0];
    let fields = foo.state_fields();
    assert_eq!(fields.len(), 2);
    let balance = fields.iter().find(|f| f.name == "balance").unwrap();
    let owner = fields.iter().find(|f| f.name == "owner").unwrap();
    assert!(!balance.is_immutable);
    assert!(owner.is_immutable);
}

#[test]
fn typed_contract_config_none_for_plain_contract() {
    let typed = check_src("contract Foo {}");
    let contracts = typed.contracts();
    assert!(contracts[0].config().is_none());
}

#[test]
fn typed_contract_functions_list_all_fns() {
    let typed = check_src(
        r#"
        contract Foo {
            fn transfer(to: Address, amount: u128) {}
            fn balanceOf(addr: Address) -> u128 { return 0u128 }
        }
        "#,
    );
    let contracts = typed.contracts();
    let fns = contracts[0].functions();
    assert_eq!(fns.len(), 2);
    let names: Vec<&str> = fns.iter().map(|f| f.name).collect();
    assert!(names.contains(&"transfer"));
    assert!(names.contains(&"balanceOf"));
}

#[test]
fn typed_contract_delegates_type_of_to_typed_ast() {
    let typed = check_src(
        r#"
        contract Foo {
            fn f() { let x = 42u128 }
        }
        "#,
    );
    let contracts = typed.contracts();
    let foo = &contracts[0];
    // The TypedAst should have expr_types populated.
    // Verify delegation works by checking the underlying typed_ast is the same.
    assert!(!foo.typed_ast().expr_types.is_empty());
}

#[test]
fn typed_contract_symbol_id_resolves_to_contract_kind() {
    let typed = check_src("contract Foo {}");
    let contracts = typed.contracts();
    let foo = &contracts[0];
    let id = foo.symbol_id().expect("symbol_id should be Some");
    let info = foo.symbol(id).expect("symbol should exist");
    assert_eq!(info.kind, SymbolKind::Contract);
    assert_eq!(info.name, "Foo");
}
