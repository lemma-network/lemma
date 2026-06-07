//! Tests for the type checker entry point [`super::check`].
//!
//! Covers: successful check (→ TypedAst), duplicate-name rejection,
//! items without names (import/using are skipped), and fuzz safety.

use crate::error::LangError;
use crate::lexer::tokenize;
use crate::parser::parse;
use crate::type_checker::{check, TypeErrorKind};

// ── Helper ─────────────────────────────────────────────────────────────────────

fn check_src(src: &str) -> Result<crate::type_checker::TypedAst, LangError> {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    check(ast)
}

// ── Successful checks ──────────────────────────────────────────────────────────

#[test]
fn check_empty_program_succeeds() {
    let result = check_src("");
    assert!(
        result.is_ok(),
        "empty program should type-check: {result:?}"
    );
}

#[test]
fn check_single_contract_succeeds() {
    let result = check_src("contract Foo {}");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().ast.items.len(), 1);
}

#[test]
fn check_two_different_contracts_succeeds() {
    let result = check_src("contract Foo {}\ncontract Bar {}");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().ast.items.len(), 2);
}

#[test]
fn check_contract_and_struct_with_different_names_succeeds() {
    let result = check_src(
        r#"contract Vault {}
struct Position { amount: u128 }"#,
    );
    assert!(result.is_ok());
}

#[test]
fn check_function_const_type_alias_all_different_names_succeeds() {
    let result = check_src(
        r#"fn compute(x: u128) -> u128 { return x }
const MAX_FEE: u128 = 2500
type TokenId = u256"#,
    );
    assert!(result.is_ok());
}

#[test]
fn check_import_and_using_are_not_named_and_do_not_conflict() {
    // import + using have no name — should never trigger duplicate check
    let result = check_src(
        r#"import { Token } from "@std/token"
using SafeMath for u128
contract Vault {}"#,
    );
    assert!(result.is_ok());
}

#[test]
fn check_returns_typed_ast_with_original_ast_preserved() {
    let src = "contract C {}";
    let result = check_src(src).expect("should succeed");
    assert_eq!(result.ast.items.len(), 1);
}

// ── Duplicate-name errors ──────────────────────────────────────────────────────

#[test]
fn check_duplicate_contracts_returns_type_error() {
    let result = check_src("contract Foo {}\ncontract Foo {}");
    match result {
        Err(LangError::Type(e)) => {
            assert!(
                matches!(&e.kind, TypeErrorKind::DuplicateDeclaration { name } if name == "Foo"),
                "expected DuplicateDeclaration for Foo, got: {:?}",
                e.kind
            );
        }
        other => panic!("expected LangError::Type, got: {other:?}"),
    }
}

#[test]
fn check_duplicate_structs_returns_type_error() {
    let result = check_src(
        r#"struct Point { x: u128 }
struct Point { x: u256 }"#,
    );
    assert!(matches!(
        result,
        Err(LangError::Type(ref e))
            if matches!(&e.kind, TypeErrorKind::DuplicateDeclaration { name } if name == "Point")
    ));
}

#[test]
fn check_duplicate_error_message_contains_name() {
    let result = check_src("contract Dupe {}\ncontract Dupe {}");
    match result {
        Err(LangError::Type(e)) => {
            assert!(
                e.message.contains("Dupe"),
                "error message should mention 'Dupe', got: {}",
                e.message
            );
        }
        other => panic!("expected LangError::Type, got: {other:?}"),
    }
}

#[test]
fn check_duplicate_error_message_contains_first_location() {
    let result = check_src("contract Same {}\ncontract Same {}");
    match result {
        Err(LangError::Type(e)) => {
            // Message should tell the user where the first declaration was
            assert!(
                e.message.contains("line") || e.message.contains("col"),
                "error should mention first declaration location: {}",
                e.message
            );
        }
        other => panic!("expected LangError::Type, got: {other:?}"),
    }
}

#[test]
fn check_first_duplicate_wins_rest_not_checked() {
    // Only the FIRST duplicate pair is reported (fail-fast in 3a)
    let result = check_src("contract A {}\ncontract A {}\ncontract B {}\ncontract B {}");
    match result {
        Err(LangError::Type(e)) => {
            // Should be "A" (first dup encountered), not "B"
            assert!(matches!(&e.kind, TypeErrorKind::DuplicateDeclaration { name } if name == "A"));
        }
        other => panic!("expected LangError::Type, got: {other:?}"),
    }
}

#[test]
fn check_contract_and_struct_same_name_returns_error() {
    // Top-level namespace is shared: a contract and a struct can't share a name
    let result = check_src("contract Shared {}\nstruct Shared { x: u128 }");
    assert!(matches!(result, Err(LangError::Type(_))));
}

// ── Duplicate detection: all named Item kinds ─────────────────────────────────

/// Parameterised helper — parse two declarations with the same name and
/// expect a DuplicateDeclaration error.
fn assert_dup_error(src: &str, expected_name: &str) {
    let result = check_src(src);
    match result {
        Err(LangError::Type(e)) => {
            assert!(
                matches!(&e.kind, TypeErrorKind::DuplicateDeclaration { name } if name == expected_name),
                "expected DuplicateDeclaration({expected_name}), got: {:?}",
                e.kind
            );
        }
        other => panic!("expected LangError::Type for {expected_name}, got: {other:?}"),
    }
}

#[test]
fn duplicate_token_returns_error() {
    assert_dup_error(
        "token T extends Token { config { name: \"A\" } }\ntoken T extends Token { config { name: \"B\" } }",
        "T",
    );
}

#[test]
fn duplicate_interface_returns_error() {
    assert_dup_error("interface IFoo {}\ninterface IFoo {}", "IFoo");
}

#[test]
fn duplicate_trait_returns_error() {
    assert_dup_error("trait MyTrait {}\ntrait MyTrait {}", "MyTrait");
}

#[test]
fn duplicate_library_returns_error() {
    assert_dup_error("library MathLib {}\nlibrary MathLib {}", "MathLib");
}

#[test]
fn duplicate_enum_returns_error() {
    assert_dup_error(
        "enum Status { Active, Inactive }\nenum Status { Pending }",
        "Status",
    );
}

#[test]
fn duplicate_function_returns_error() {
    assert_dup_error(
        "fn transfer(to: Address, amount: u128) {}\nfn transfer(to: Address) {}",
        "transfer",
    );
}

#[test]
fn duplicate_const_returns_error() {
    assert_dup_error(
        "const MAX_FEE: u128 = 2500\nconst MAX_FEE: u128 = 5000",
        "MAX_FEE",
    );
}

#[test]
fn duplicate_type_alias_returns_error() {
    assert_dup_error("type TokenId = u256\ntype TokenId = u128", "TokenId");
}

#[test]
fn duplicate_error_decl_returns_error() {
    assert_dup_error(
        "error InsufficientBalance { amount: u128 }\nerror InsufficientBalance { balance: u128 }",
        "InsufficientBalance",
    );
}

// ── Typed AST properties ───────────────────────────────────────────────────────

#[test]
fn check_result_has_empty_type_tables_in_3a() {
    // 3a is the skeleton pass — type maps not yet populated
    let typed = check_src("contract C {}").expect("should succeed");
    assert!(
        typed.expr_types.is_empty(),
        "3a: expr_types should be empty"
    );
    assert!(
        typed.resolutions.is_empty(),
        "3a: resolutions should be empty"
    );
    assert!(!typed.is_fully_typed(), "3a: not fully typed yet");
}

// ── Fuzz safety ────────────────────────────────────────────────────────────────

#[test]
fn check_valid_samples_all_succeed() {
    let samples = [
        "",
        "contract C {}",
        "token T extends Token { config { name: \"A\" } }",
        "fn f(x: u128) -> u128 { return x }",
        "struct S { x: u128 }",
    ];
    for src in &samples {
        let result = check_src(src);
        assert!(result.is_ok(), "should succeed for {src:?}: {result:?}");
    }
}
