//! Tests for the core declaration parser (subtask 2d).
//!
//! Covers: annotations, functions, contracts, token declarations,
//! import/using/const/type-alias, and the full `parse_program` pipeline.

use crate::lexer::tokenize;
use crate::parser::ast::{
    AnnotationArg, ContractMember, Expr, Item, Literal, Mutability, Visibility,
};
use crate::parser::{parse, Parser};

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// Parse a single top-level item from source.
fn parse_item(src: &str) -> Item {
    let tokens = tokenize(src).expect("tokenize failed");
    let mut p = Parser::new(tokens);
    p.parse_top_level_item()
        .expect("parse_top_level_item failed")
}

/// Parse a full program from source.
fn parse_program(src: &str) -> crate::parser::ast::Ast {
    let tokens = tokenize(src).expect("tokenize failed");
    parse(tokens).expect("parse failed")
}

/// Parse a single top-level item and expect an error.
fn parse_item_err(src: &str) -> crate::error::LangError {
    let tokens = tokenize(src).expect("tokenize failed");
    let mut p = Parser::new(tokens);
    p.parse_top_level_item()
        .expect_err("expected parse error but got Ok")
}

/// Parse a single top-level item, returning `Result` (used for error-path assertions).
fn parse_item_from_str(src: &str) -> Result<Item, crate::error::LangError> {
    let tokens = tokenize(src)?;
    let mut p = Parser::new(tokens);
    p.parse_top_level_item()
}

// ─── Annotation tests ─────────────────────────────────────────────────────────

#[test]
fn parse_decl_annotation_no_args() {
    // `@onlyOwner` before a function
    let item = parse_item("@onlyOwner\npub fn transfer(to: Address, amount: u128) {}");
    let Item::Function(f) = item else {
        panic!("expected Function, got {item:?}");
    };
    assert_eq!(f.annotations.len(), 1);
    assert_eq!(f.annotations[0].name, "onlyOwner");
    assert!(f.annotations[0].args.is_empty());
}

#[test]
fn parse_decl_annotation_positional_arg() {
    // `@onlyRole("ADMIN")`
    let item = parse_item("@onlyRole(\"ADMIN\")\npub fn adminAction() {}");
    let Item::Function(f) = item else {
        panic!("expected Function, got {item:?}");
    };
    assert_eq!(f.annotations.len(), 1);
    assert_eq!(f.annotations[0].name, "onlyRole");
    assert_eq!(f.annotations[0].args.len(), 1);
    assert!(matches!(
        &f.annotations[0].args[0],
        AnnotationArg::Positional(Expr::Literal(Literal::Str(_), _))
    ));
}

#[test]
fn parse_decl_annotation_named_arg() {
    // `@agentCallable(maxValueOut: cap)`
    let item = parse_item("@agentCallable(maxValueOut: cap)\npub fn agentFn() {}");
    let Item::Function(f) = item else {
        panic!("expected Function, got {item:?}");
    };
    assert_eq!(f.annotations.len(), 1);
    assert_eq!(f.annotations[0].name, "agentCallable");
    assert_eq!(f.annotations[0].args.len(), 1);
    let AnnotationArg::Named(key, _) = &f.annotations[0].args[0] else {
        panic!("expected Named arg");
    };
    assert_eq!(key, "maxValueOut");
}

#[test]
fn parse_decl_annotation_hash_style() {
    // `#[onTransfer]`
    let item = parse_item("#[onTransfer]\npub fn onTransferHook() {}");
    let Item::Function(f) = item else {
        panic!("expected Function, got {item:?}");
    };
    assert_eq!(f.annotations.len(), 1);
    assert_eq!(f.annotations[0].name, "onTransfer");
    assert!(f.annotations[0].args.is_empty());
}

#[test]
fn parse_decl_annotation_hash_with_args() {
    // `#[onTransfer(filter: addr)]`
    let item = parse_item("#[onTransfer(filter: addr)]\npub fn hook() {}");
    let Item::Function(f) = item else {
        panic!("expected Function, got {item:?}");
    };
    assert_eq!(f.annotations.len(), 1);
    assert_eq!(f.annotations[0].name, "onTransfer");
    assert_eq!(f.annotations[0].args.len(), 1);
    let AnnotationArg::Named(key, _) = &f.annotations[0].args[0] else {
        panic!("expected Named arg");
    };
    assert_eq!(key, "filter");
}

#[test]
fn parse_decl_multiple_annotations() {
    // `@onlyOwner @nonReentrant` on same fn
    let item = parse_item("@onlyOwner\n@nonReentrant\npub fn secure() {}");
    let Item::Function(f) = item else {
        panic!("expected Function, got {item:?}");
    };
    assert_eq!(f.annotations.len(), 2);
    assert_eq!(f.annotations[0].name, "onlyOwner");
    assert_eq!(f.annotations[1].name, "nonReentrant");
}

// ─── Function tests ───────────────────────────────────────────────────────────

#[test]
fn parse_decl_function_simple() {
    let item = parse_item("fn foo() {}");
    let Item::Function(f) = item else {
        panic!("expected Function");
    };
    assert_eq!(f.name, "foo");
    assert_eq!(f.visibility, Visibility::Private);
    assert_eq!(f.mutability, Mutability::Default);
    assert!(f.params.is_empty());
    assert!(f.return_type.is_none());
    assert!(f.body.is_some());
}

#[test]
fn parse_decl_function_pub() {
    let item = parse_item("pub fn bar() {}");
    let Item::Function(f) = item else {
        panic!("expected Function");
    };
    assert_eq!(f.visibility, Visibility::Pub);
}

#[test]
fn parse_decl_function_view() {
    let item = parse_item("pub view fn getBalance() -> u128 {}");
    let Item::Function(f) = item else {
        panic!("expected Function");
    };
    assert_eq!(f.mutability, Mutability::View);
    assert!(f.return_type.is_some());
}

#[test]
fn parse_decl_function_with_return_type() {
    let item = parse_item("fn compute() -> u256 {}");
    let Item::Function(f) = item else {
        panic!("expected Function");
    };
    assert!(f.return_type.is_some());
}

#[test]
fn parse_decl_function_with_params() {
    let item = parse_item("fn transfer(to: Address, amount: u128) {}");
    let Item::Function(f) = item else {
        panic!("expected Function");
    };
    assert_eq!(f.params.len(), 2);
    assert_eq!(f.params[0].name, "to");
    assert_eq!(f.params[1].name, "amount");
}

#[test]
fn parse_decl_function_with_default_param() {
    // `fn f(x: u128 = 0)`
    let item = parse_item("fn f(x: u128 = 0) {}");
    let Item::Function(f) = item else {
        panic!("expected Function");
    };
    assert_eq!(f.params.len(), 1);
    assert!(f.params[0].default_expr.is_some());
}

#[test]
fn parse_decl_function_with_generic_params() {
    // `fn swap<T>(a: T, b: T) -> T`
    let item = parse_item("fn swap<T>(a: T, b: T) -> T {}");
    let Item::Function(f) = item else {
        panic!("expected Function");
    };
    assert_eq!(f.generic_params.len(), 1);
    assert_eq!(f.generic_params[0].name, "T");
    assert!(f.generic_params[0].bound.is_none());
}

#[test]
fn parse_decl_function_with_generic_bound() {
    // `fn max<T: Comparable>(a: T, b: T) -> T`
    let item = parse_item("fn max<T: Comparable>(a: T, b: T) -> T {}");
    let Item::Function(f) = item else {
        panic!("expected Function");
    };
    assert_eq!(f.generic_params.len(), 1);
    assert_eq!(f.generic_params[0].name, "T");
    assert!(f.generic_params[0].bound.is_some());
}

// ─── Contract tests ───────────────────────────────────────────────────────────

#[test]
fn parse_decl_contract_empty() {
    let item = parse_item("contract Empty {}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.name, "Empty");
    assert!(c.implements.is_empty());
    assert!(c.uses.is_empty());
    assert!(c.members.is_empty());
}

#[test]
fn parse_decl_contract_with_implements() {
    let item = parse_item("contract Foo implements IToken {}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.implements, vec!["IToken"]);
}

#[test]
fn parse_decl_contract_with_uses() {
    let item = parse_item("contract Foo uses SafeMath {}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.uses, vec!["SafeMath"]);
}

#[test]
fn parse_decl_contract_with_state_block() {
    // Converted to comma style (DB-A35: Pola B — newline-or-comma).
    let item = parse_item(
        "contract Foo {\n  state {\n    balance: u128,\n    pub owner: Address,\n  }\n}",
    );
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.members.len(), 1);
    let ContractMember::State(sb) = &c.members[0] else {
        panic!("expected State member");
    };
    assert_eq!(sb.fields.len(), 2);
    assert_eq!(sb.fields[0].name, "balance");
    assert!(!sb.fields[0].pub_);
    assert_eq!(sb.fields[1].name, "owner");
    assert!(sb.fields[1].pub_);
}

#[test]
fn parse_decl_state_block_comma_separator() {
    // Pola B: inline comma-separated state fields — `state { a: u128, b: bool }`.
    // Was a parse error before DB-A35; must now produce 2 fields.
    let item = parse_item("contract C { state { x: u128, y: bool } }");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    let ContractMember::State(sb) = &c.members[0] else {
        panic!("expected State");
    };
    assert_eq!(sb.fields.len(), 2);
    assert_eq!(sb.fields[0].name, "x");
    assert_eq!(sb.fields[1].name, "y");
}

#[test]
fn parse_decl_state_block_trailing_comma() {
    // Trailing comma before `}` is permitted (Pola B).
    let item = parse_item("contract C {\n  state {\n    a: u128,\n    b: bool,\n  }\n}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    let ContractMember::State(sb) = &c.members[0] else {
        panic!("expected State");
    };
    assert_eq!(
        sb.fields.len(),
        2,
        "trailing comma must not produce a phantom field"
    );
}

#[test]
fn parse_decl_state_block_mixed_comma_and_newline() {
    // Mixed: comma on some fields, newline-only on others — all valid.
    let item =
        parse_item("contract C {\n  state {\n    a: u128,\n    b: bool\n    c: Address,\n  }\n}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    let ContractMember::State(sb) = &c.members[0] else {
        panic!("expected State");
    };
    assert_eq!(sb.fields.len(), 3);
    assert_eq!(sb.fields[0].name, "a");
    assert_eq!(sb.fields[1].name, "b");
    assert_eq!(sb.fields[2].name, "c");
}

#[test]
fn parse_decl_contract_with_immutable() {
    let item = parse_item("contract Foo {\n  immutable owner: Address\n}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.members.len(), 1);
    assert!(matches!(c.members[0], ContractMember::Immutable(_)));
}

#[test]
fn parse_decl_contract_with_init() {
    let item = parse_item("contract Foo {\n  init(owner: Address) {}\n}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.members.len(), 1);
    let ContractMember::Function(f) = &c.members[0] else {
        panic!("expected Function member");
    };
    assert_eq!(f.name, "init");
    assert_eq!(f.params.len(), 1);
}

#[test]
fn parse_decl_contract_with_modifier() {
    // modifier body contains `_` (Stmt::Placeholder)
    let item = parse_item("contract Foo {\n  modifier onlyOwner() {\n    _\n  }\n}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.members.len(), 1);
    let ContractMember::Modifier(m) = &c.members[0] else {
        panic!("expected Modifier member");
    };
    assert_eq!(m.name, "onlyOwner");
    // Body should contain Stmt::Placeholder
    assert_eq!(m.body.len(), 1);
    assert!(matches!(
        m.body[0],
        crate::parser::ast::Stmt::Placeholder(_)
    ));
}

#[test]
fn parse_decl_contract_with_receive_fallback() {
    let item = parse_item("contract Foo {\n  receive() payable {}\n  fallback() {}\n}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.members.len(), 2);
    let ContractMember::Receive(r) = &c.members[0] else {
        panic!("expected Receive member");
    };
    assert!(r.payable);
    assert!(matches!(c.members[1], ContractMember::Fallback(_)));
}

#[test]
fn parse_decl_contract_full() {
    // state + const + immutable + fn + modifier
    let src = r#"
contract Vault {
  state {
    balance: u128
  }
  const MAX: u128 = 1000
  immutable owner: Address
  @onlyOwner
  pub fn withdraw(amount: u128) {}
  modifier onlyOwner() {
    _
  }
}
"#;
    let item = parse_item(src);
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.name, "Vault");
    assert_eq!(c.members.len(), 5);
}

// ─── Token declaration tests ──────────────────────────────────────────────────

#[test]
fn parse_decl_token_extends() {
    // `token MyToken extends Token { ... }`
    let item = parse_item("token MyToken extends Token {}");
    let Item::Token_(t) = item else {
        panic!("expected Token_");
    };
    assert_eq!(t.name, "MyToken");
    assert_eq!(t.extends, "Token");
    assert!(t.members.is_empty());
}

// ─── Top-level item tests ─────────────────────────────────────────────────────

#[test]
fn parse_decl_import_named() {
    let item = parse_item("import { Transfer, Approval } from \"./events\"");
    let Item::Import(imp) = item else {
        panic!("expected Import");
    };
    assert_eq!(imp.from, "./events");
    let crate::parser::ast::ImportNames::Named(names) = &imp.names else {
        panic!("expected Named imports");
    };
    assert_eq!(names, &["Transfer", "Approval"]);
}

#[test]
fn parse_decl_import_star() {
    let item = parse_item("import * as Events from \"./events\"");
    let Item::Import(imp) = item else {
        panic!("expected Import");
    };
    let crate::parser::ast::ImportNames::Star(alias) = &imp.names else {
        panic!("expected Star import");
    };
    assert_eq!(alias, "Events");
    assert_eq!(imp.from, "./events");
}

#[test]
fn parse_decl_using() {
    let item = parse_item("using SafeMath for u128");
    let Item::Using(u) = item else {
        panic!("expected Using");
    };
    assert_eq!(u.library, "SafeMath");
}

#[test]
fn parse_decl_const_item() {
    let item = parse_item("const MAX_SUPPLY: u128 = 1000000");
    let Item::Const(c) = item else {
        panic!("expected Const");
    };
    assert_eq!(c.name, "MAX_SUPPLY");
}

#[test]
fn parse_decl_type_alias() {
    let item = parse_item("type TokenId = u256");
    let Item::TypeAlias(ta) = item else {
        panic!("expected TypeAlias");
    };
    assert_eq!(ta.name, "TokenId");
}

// ─── Program (full pipeline) tests ───────────────────────────────────────────

#[test]
fn parse_decl_program_with_import_and_contract() {
    let src = r#"
import { IToken } from "./interfaces"
contract MyToken implements IToken {
  state {
    supply: u128
  }
}
"#;
    let ast = parse_program(src);
    assert_eq!(ast.items.len(), 2);
    assert!(matches!(ast.items[0], Item::Import(_)));
    assert!(matches!(ast.items[1], Item::Contract(_)));
}

#[test]
fn parse_decl_program_multiple_items() {
    let src = r#"
const VERSION: u128 = 1
type TokenId = u256
using SafeMath for u128
contract Foo {}
"#;
    let ast = parse_program(src);
    assert_eq!(ast.items.len(), 4);
    assert!(matches!(ast.items[0], Item::Const(_)));
    assert!(matches!(ast.items[1], Item::TypeAlias(_)));
    assert!(matches!(ast.items[2], Item::Using(_)));
    assert!(matches!(ast.items[3], Item::Contract(_)));
}

// ─── Error path tests ─────────────────────────────────────────────────────────

#[test]
fn parse_decl_unknown_top_level_token_returns_error() {
    // A bare integer is not a valid top-level declaration.
    let err = parse_item_err("42");
    assert!(matches!(err, crate::error::LangError::Parse(_)));
}

// ─── MF-1: Annotation on non-function → error ────────────────────────────────

#[test]
fn parse_decl_annotation_on_contract_returns_error() {
    // @onlyOwner before a contract declaration must be an error.
    let result = parse_item_from_str("@onlyOwner\ncontract Foo {}");
    assert!(
        result.is_err(),
        "annotations on contract declarations should error"
    );
}

#[test]
fn parse_decl_annotation_on_const_returns_error() {
    // @onlyOwner before a const declaration must be an error.
    let result = parse_item_from_str("@onlyOwner\nconst MAX: u128 = 100");
    assert!(
        result.is_err(),
        "annotations on const declarations should error"
    );
}

// ─── SF-5: Missing visibility / mutability / token tests ─────────────────────

#[test]
fn parse_decl_function_external_visibility() {
    let item = parse_item_from_str("external fn onlyExternal() {}").expect("should parse");
    match item {
        Item::Function(f) => assert!(
            matches!(f.visibility, Visibility::External),
            "expected External visibility"
        ),
        _ => panic!("expected Function"),
    }
}

#[test]
fn parse_decl_function_pure_mutability() {
    let item =
        parse_item_from_str("pure fn add(a: u128, b: u128) -> u128 {}").expect("should parse");
    match item {
        Item::Function(f) => assert!(
            matches!(f.mutability, Mutability::Pure),
            "expected Pure mutability"
        ),
        _ => panic!("expected Function"),
    }
}

#[test]
fn parse_decl_token_with_state_and_function() {
    let src = r#"token MyToken extends Token {
    state {
        owner: Address
    }
    pub fn getOwner() -> Address {}
}"#;
    let item = parse_item_from_str(src).expect("should parse");
    match item {
        Item::Token_(t) => {
            assert_eq!(t.name, "MyToken");
            assert_eq!(t.extends, "Token");
            assert_eq!(t.members.len(), 2);
        }
        _ => panic!("expected Token_"),
    }
}

// ─── Fuzz safety tests ────────────────────────────────────────────────────────

#[test]
fn parse_decl_malformed_never_panics() {
    // A collection of malformed inputs — must return Err, never panic.
    let malformed = [
        "contract",
        "contract {",
        "fn",
        "fn foo",
        "fn foo(",
        "@",
        "#[",
        "import from",
        "using for",
        "const x",
        "token extends",
        "contract Foo implements {",
    ];
    for src in &malformed {
        let result = tokenize(src).and_then(|tokens| {
            let mut p = Parser::new(tokens);
            p.parse_top_level_item()
        });
        // Must be Err — never panic
        assert!(
            result.is_err(),
            "expected Err for malformed input {src:?}, got Ok"
        );
    }
}

// ─── Init constructor parser tests ───────────────────────────────────────────

#[test]
fn parse_decl_init_plain_has_default_mutability() {
    // `init(params) { body }` — plain init, mutability must be Default.
    let item = parse_item("contract Foo {\n  init(owner: Address) {}\n}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    let ContractMember::Function(f) = &c.members[0] else {
        panic!("expected Function member");
    };
    assert_eq!(f.name, "init");
    assert_eq!(f.visibility, Visibility::Private);
    assert_eq!(f.mutability, Mutability::Default);
    assert!(f.return_type.is_none());
}

#[test]
fn parse_decl_payable_init_has_payable_mutability() {
    // `payable init(params) { body }` — the ONE permitted modifier on init (§9, WF-003).
    // Parser must set mutability=Payable and visibility=Private.
    let item = parse_item("contract Foo {\n  payable init(seed: u128 = 0) {}\n}");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    let ContractMember::Function(f) = &c.members[0] else {
        panic!("expected Function member");
    };
    assert_eq!(f.name, "init");
    assert_eq!(f.visibility, Visibility::Private);
    assert_eq!(f.mutability, Mutability::Payable);
    assert!(f.return_type.is_none());
    assert_eq!(f.params.len(), 1);
    assert_eq!(f.params[0].name, "seed");
}

#[test]
fn parse_decl_payable_init_in_token_decl() {
    // `payable init` inside a `token` declaration — same grammar, same rules.
    let item = parse_item("token MyToken extends Token {\n  payable init(seed: u128 = 0) {}\n}");
    let Item::Token_(t) = item else {
        panic!("expected Token_");
    };
    let ContractMember::Function(f) = &t.members[0] else {
        panic!("expected Function member");
    };
    assert_eq!(f.name, "init");
    assert_eq!(f.mutability, Mutability::Payable);
}

// Note: `pub init` and `external init` are parse-time errors (visibility is
// parser-enforced as Private for init). These cannot be tested as WF errors
// because they never reach the type checker. The parse error is produced by
// the contract-member dispatcher routing `pub` → parse_function (not parse_init),
// which then fails to find `fn` after `pub`. This is the correct behavior —
// `pub init` is not valid Lem syntax.}
