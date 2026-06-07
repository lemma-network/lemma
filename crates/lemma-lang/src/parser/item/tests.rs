//! Tests for the user-type declaration parsers (subtasks 2e and 2f).
//!
//! Covers: struct, enum, event, error — both as top-level items and as
//! contract members. Also covers interface, trait, library, generic bounds,
//! using-for, and contract composition (subtask 2f).
//! Verifies fuzz-safety (no panics on malformed input).

use crate::error::LangError;
use crate::lexer::tokenize;
use crate::parser::ast::{ContractMember, InterfaceMember, Item, StructMember, TraitMember, Type};
use crate::parser::Parser;

// ─── Test helpers ─────────────────────────────────────────────────────────────

/// Parse a single top-level item from source, returning `Result`.
fn parse_item_from_str(src: &str) -> Result<Item, LangError> {
    let tokens = tokenize(src)?;
    let mut p = Parser::new(tokens);
    p.parse_top_level_item()
}

/// Parse a single top-level item, panicking on error.
fn parse_item(src: &str) -> Item {
    parse_item_from_str(src).expect("parse_top_level_item failed")
}

/// Parse a single contract member from source, returning `Result`.
///
/// Wraps the source in a minimal contract body so `parse_contract_member`
/// can be exercised through the full `parse_top_level_item` pipeline.
fn parse_contract_member_from_str(member_src: &str) -> Result<ContractMember, LangError> {
    let src = format!("contract _Test {{\n{member_src}\n}}");
    let tokens = tokenize(&src)?;
    let mut p = Parser::new(tokens);
    let item = p.parse_top_level_item()?;
    let Item::Contract(c) = item else {
        return Err(LangError::Parse(crate::parser::ParseError {
            message: "expected Contract wrapper".into(),
            span: crate::lexer::token::Span::at(0, 0, 0),
            expected: vec![],
        }));
    };
    c.members.into_iter().next().ok_or_else(|| {
        LangError::Parse(crate::parser::ParseError {
            message: "contract had no members".into(),
            span: crate::lexer::token::Span::at(0, 0, 0),
            expected: vec![],
        })
    })
}

// ─── Struct tests ─────────────────────────────────────────────────────────────

#[test]
fn parse_item_struct_fields_only() {
    let item = parse_item("struct Point { x: u128\n y: u128 }");
    let Item::Struct(s) = item else {
        panic!("expected Struct, got {item:?}");
    };
    assert_eq!(s.name, "Point");
    assert_eq!(s.members.len(), 2);
    let StructMember::Field(f0) = &s.members[0] else {
        panic!("expected Field");
    };
    assert_eq!(f0.name, "x");
    let StructMember::Field(f1) = &s.members[1] else {
        panic!("expected Field");
    };
    assert_eq!(f1.name, "y");
}

#[test]
fn parse_item_struct_with_methods() {
    let src = "struct Counter {\n  count: u128\n  pub fn increment() {}\n}";
    let item = parse_item(src);
    let Item::Struct(s) = item else {
        panic!("expected Struct");
    };
    assert_eq!(s.name, "Counter");
    assert_eq!(s.members.len(), 2);
    assert!(matches!(s.members[0], StructMember::Field(_)));
    assert!(matches!(s.members[1], StructMember::Method(_)));
}

#[test]
fn parse_item_struct_with_generic_params() {
    let item = parse_item("struct Pair<A, B> { first: A\n second: B }");
    let Item::Struct(s) = item else {
        panic!("expected Struct");
    };
    assert_eq!(s.generic_params.len(), 2);
    assert_eq!(s.generic_params[0].name, "A");
    assert_eq!(s.generic_params[1].name, "B");
}

#[test]
fn parse_item_struct_empty_body() {
    let item = parse_item("struct Empty {}");
    let Item::Struct(s) = item else {
        panic!("expected Struct");
    };
    assert_eq!(s.name, "Empty");
    assert!(s.members.is_empty());
}

// ─── Enum tests ───────────────────────────────────────────────────────────────

#[test]
fn parse_item_enum_unit_variants() {
    let item = parse_item("enum Status {\n  Pending\n  Active\n  Closed\n}");
    let Item::Enum(e) = item else {
        panic!("expected Enum, got {item:?}");
    };
    assert_eq!(e.name, "Status");
    assert_eq!(e.variants.len(), 3);
    assert_eq!(e.variants[0].name, "Pending");
    assert_eq!(e.variants[1].name, "Active");
    assert_eq!(e.variants[2].name, "Closed");
    assert!(e.methods.is_empty());
}

#[test]
fn parse_item_enum_data_variants_named() {
    let src = "enum Order {\n  Filled { price: u128, timestamp: u64 }\n}";
    let item = parse_item(src);
    let Item::Enum(e) = item else {
        panic!("expected Enum");
    };
    assert_eq!(e.variants.len(), 1);
    let v = &e.variants[0];
    assert_eq!(v.name, "Filled");
    assert_eq!(v.fields.len(), 2);
    assert_eq!(v.fields[0].name, "price");
    assert_eq!(v.fields[1].name, "timestamp");
}

#[test]
fn parse_item_enum_data_variants_positional() {
    // Positional fields get synthetic names `_0`, `_1`, …
    let src = "enum Pair {\n  Values(u128, Address)\n}";
    let item = parse_item(src);
    let Item::Enum(e) = item else {
        panic!("expected Enum");
    };
    assert_eq!(e.variants.len(), 1);
    let v = &e.variants[0];
    assert_eq!(v.name, "Values");
    assert_eq!(v.fields.len(), 2);
    assert_eq!(v.fields[0].name, "_0");
    assert_eq!(v.fields[1].name, "_1");
}

#[test]
fn parse_item_enum_with_discriminants() {
    let src = "enum Code {\n  Ok = 0\n  Err = 1\n}";
    let item = parse_item(src);
    let Item::Enum(e) = item else {
        panic!("expected Enum");
    };
    assert_eq!(e.variants.len(), 2);
    assert!(e.variants[0].discriminant.is_some());
    assert!(e.variants[1].discriminant.is_some());
}

#[test]
fn parse_item_enum_with_methods() {
    // Methods at enum body level (spec §10)
    let src = "enum Status {\n  Active\n  Inactive\n  pub view fn isActive() -> bool {}\n}";
    let item = parse_item(src);
    let Item::Enum(e) = item else {
        panic!("expected Enum");
    };
    assert_eq!(e.variants.len(), 2);
    assert_eq!(e.methods.len(), 1);
    assert_eq!(e.methods[0].name, "isActive");
}

#[test]
fn parse_item_enum_with_generic_params() {
    // Note: `Option` is a type keyword in Lem — use a non-keyword name.
    let item = parse_item("enum Maybe<T> {\n  Some(T)\n  None\n}");
    let Item::Enum(e) = item else {
        panic!("expected Enum");
    };
    assert_eq!(e.generic_params.len(), 1);
    assert_eq!(e.generic_params[0].name, "T");
    assert_eq!(e.variants.len(), 2);
}

// ─── Event tests ──────────────────────────────────────────────────────────────

#[test]
fn parse_item_event_basic() {
    // Note: `from` is a keyword in Lem — use non-keyword field names.
    let member = parse_contract_member_from_str(
        "event Transfer {\n  sender: Address\n  recipient: Address\n  amount: u128\n}",
    )
    .expect("parse failed");
    let ContractMember::Event(ev) = member else {
        panic!("expected Event, got {member:?}");
    };
    assert_eq!(ev.name, "Transfer");
    assert!(!ev.anonymous);
    assert_eq!(ev.fields.len(), 3);
    assert_eq!(ev.fields[0].name, "sender");
    assert!(!ev.fields[0].indexed);
    assert!(!ev.fields[0].optional);
}

#[test]
fn parse_item_event_indexed_field() {
    // `@indexed` is Token::Indexed in the lexer; `from` is a keyword — use `sender`.
    let member = parse_contract_member_from_str(
        "event Transfer {\n  @indexed sender: Address\n  amount: u128\n}",
    )
    .expect("parse failed");
    let ContractMember::Event(ev) = member else {
        panic!("expected Event");
    };
    assert!(ev.fields[0].indexed, "first field should be indexed");
    assert!(!ev.fields[1].indexed, "second field should not be indexed");
}

#[test]
fn parse_item_event_optional_field() {
    let member =
        parse_contract_member_from_str("event Log {\n  data?: string\n}").expect("parse failed");
    let ContractMember::Event(ev) = member else {
        panic!("expected Event");
    };
    assert!(ev.fields[0].optional, "field should be optional");
}

#[test]
fn parse_item_event_anonymous() {
    // `@anonymous` annotation before `event` keyword
    let member =
        parse_contract_member_from_str("@anonymous\nevent Heartbeat {\n  timestamp: u64\n}")
            .expect("parse failed");
    let ContractMember::Event(ev) = member else {
        panic!("expected Event");
    };
    assert!(ev.anonymous, "event should be anonymous");
    assert_eq!(ev.name, "Heartbeat");
}

// ─── Error declaration tests ──────────────────────────────────────────────────

#[test]
fn parse_item_error_no_fields() {
    let item = parse_item("error Unauthorized");
    let Item::ErrorDecl(e) = item else {
        panic!("expected ErrorDecl, got {item:?}");
    };
    assert_eq!(e.name, "Unauthorized");
    assert!(e.fields.is_empty());
}

#[test]
fn parse_item_error_with_fields() {
    let item = parse_item("error InsufficientBalance { have: u128, need: u128 }");
    let Item::ErrorDecl(e) = item else {
        panic!("expected ErrorDecl");
    };
    assert_eq!(e.name, "InsufficientBalance");
    assert_eq!(e.fields.len(), 2);
    assert_eq!(e.fields[0].name, "have");
    assert_eq!(e.fields[1].name, "need");
}

// ─── Contract member wiring tests ─────────────────────────────────────────────

#[test]
fn parse_decl_contract_with_struct() {
    let member =
        parse_contract_member_from_str("struct Point { x: u128\n y: u128 }").expect("parse failed");
    assert!(matches!(member, ContractMember::Struct(_)));
    let ContractMember::Struct(s) = member else {
        unreachable!()
    };
    assert_eq!(s.name, "Point");
    assert_eq!(s.members.len(), 2);
}

#[test]
fn parse_decl_contract_with_enum() {
    let member = parse_contract_member_from_str("enum Status {\n  Active\n  Inactive\n}")
        .expect("parse failed");
    assert!(matches!(member, ContractMember::Enum(_)));
    let ContractMember::Enum(e) = member else {
        unreachable!()
    };
    assert_eq!(e.name, "Status");
    assert_eq!(e.variants.len(), 2);
}

#[test]
fn parse_decl_contract_with_event() {
    let member = parse_contract_member_from_str("event Mint {\n  to: Address\n  amount: u128\n}")
        .expect("parse failed");
    assert!(matches!(member, ContractMember::Event(_)));
    let ContractMember::Event(ev) = member else {
        unreachable!()
    };
    assert_eq!(ev.name, "Mint");
    assert_eq!(ev.fields.len(), 2);
}

#[test]
fn parse_decl_contract_with_error() {
    let member =
        parse_contract_member_from_str("error Overflow { value: u256 }").expect("parse failed");
    assert!(matches!(member, ContractMember::ErrorDecl(_)));
    let ContractMember::ErrorDecl(e) = member else {
        unreachable!()
    };
    assert_eq!(e.name, "Overflow");
    assert_eq!(e.fields.len(), 1);
}

// ─── Event computed-field (method) tests ─────────────────────────────────────

#[test]
fn parse_item_event_with_computed_method() {
    // Spec §15: computed event fields — `fn` inside event body.
    let member = parse_contract_member_from_str(
        "@anonymous event Swap {
            @indexed pair: Address
            amountIn: u128
            fn priceImpact() -> u128 { return self.amountOut }
        }",
    )
    .expect("should parse event with computed method");
    let ContractMember::Event(ev) = member else {
        panic!("expected Event, got {member:?}");
    };
    assert!(ev.anonymous, "event should be anonymous");
    assert_eq!(ev.fields.len(), 2, "should have 2 regular fields");
    assert_eq!(ev.fields[0].name, "pair");
    assert!(ev.fields[0].indexed, "pair should be @indexed");
    assert_eq!(ev.fields[1].name, "amountIn");
    assert_eq!(ev.methods.len(), 1, "should have 1 computed method");
    assert_eq!(ev.methods[0].name, "priceImpact");
}

#[test]
fn parse_item_event_methods_only() {
    // Edge case: event with only a computed method and no regular fields.
    let member = parse_contract_member_from_str(
        "event Computed {
            fn value() -> u128 { return 42 }
        }",
    )
    .expect("should parse event with only a method");
    let ContractMember::Event(ev) = member else {
        panic!("expected Event");
    };
    assert!(ev.fields.is_empty(), "no regular fields");
    assert_eq!(ev.methods.len(), 1);
    assert_eq!(ev.methods[0].name, "value");
}

#[test]
fn parse_item_event_mixed_fields_and_methods() {
    // Event with fields before AND after a method (order should be preserved).
    let member = parse_contract_member_from_str(
        "event Mixed {
            @indexed sender: Address
            fn computedA() -> u128 { return 1 }
            amount: u128
        }",
    )
    .expect("should parse mixed event");
    let ContractMember::Event(ev) = member else {
        panic!("expected Event");
    };
    assert_eq!(ev.fields.len(), 2, "two regular fields");
    assert_eq!(ev.methods.len(), 1, "one computed method");
    assert_eq!(ev.methods[0].name, "computedA");
}

// ─── Fuzz safety tests ────────────────────────────────────────────────────────

#[test]
fn parse_item_malformed_never_panics() {
    // Malformed inputs must return Err, never panic.
    let malformed = [
        "struct",
        "struct {",
        "struct Foo",
        "struct Foo {",
        "enum",
        "enum {",
        "enum Foo",
        "enum Foo {",
        "error",
        "error {",
    ];
    for src in &malformed {
        let result = tokenize(src).and_then(|tokens| {
            let mut p = Parser::new(tokens);
            p.parse_top_level_item()
        });
        assert!(
            result.is_err(),
            "expected Err for malformed input {src:?}, got Ok"
        );
    }
}

#[test]
fn parse_item_malformed_event_enum_never_panics() {
    // Malformed event/enum edge cases — must not panic (may return Ok or Err).
    let malformed = [
        "event E { @indexed }", // @indexed with no field name
        "enum E { V(,) }",      // positional with trailing comma only
        "enum E { A = }",       // discriminant with no expr
        "event E { name?: }",   // optional field with no type
        "enum E {}",            // empty enum (valid — should parse ok)
        "struct S { fn }",      // fn keyword with no name
    ];
    for src in malformed {
        // Must not panic — Ok or Err are both acceptable outcomes.
        let _ = tokenize(src).and_then(|tokens| {
            let mut p = Parser::new(tokens);
            p.parse_top_level_item()
        });
    }
}

// ── Interface tests (subtask 2f) ──────────────────────────────────────────────

#[test]
fn parse_item_interface_function_signatures() {
    // Interface with body-less function signatures (body = None).
    let item = parse_item_from_str(
        "interface IToken {
            fn totalSupply() -> u128
            fn balanceOf(addr: Address) -> u128
            fn transfer(to: Address, amount: u128) -> bool
        }",
    )
    .expect("should parse");
    let Item::Interface(iface) = item else {
        panic!("expected Interface, got {item:?}");
    };
    assert_eq!(iface.name, "IToken");
    assert_eq!(iface.members.len(), 3);
    // Each member is a function with body = None (signature-only)
    for m in &iface.members {
        let InterfaceMember::Function(f) = m else {
            panic!("expected Function member, got {m:?}");
        };
        assert!(f.body.is_none(), "interface fn should have no body");
    }
}

#[test]
fn parse_item_interface_with_event() {
    let item = parse_item_from_str(
        "interface IToken {
            fn transfer(to: Address, amount: u128) -> bool
            event Transfer { sender: Address\n recipient: Address\n amount: u128 }
        }",
    )
    .expect("should parse");
    let Item::Interface(iface) = item else {
        panic!("expected Interface, got {item:?}");
    };
    assert_eq!(iface.members.len(), 2);
    assert!(
        matches!(iface.members[0], InterfaceMember::Function(_)),
        "first member should be Function"
    );
    assert!(
        matches!(iface.members[1], InterfaceMember::Event(_)),
        "second member should be Event"
    );
}

#[test]
fn parse_item_interface_with_annotations() {
    let item = parse_item_from_str(
        "interface IVault {
            @payable fn deposit(amount: u128)
            view fn balanceOf(addr: Address) -> u128
        }",
    )
    .expect("should parse");
    let Item::Interface(iface) = item else {
        panic!("expected Interface, got {item:?}");
    };
    assert_eq!(iface.members.len(), 2);
    let InterfaceMember::Function(f) = &iface.members[0] else {
        panic!("expected Function");
    };
    assert_eq!(f.annotations.len(), 1);
    assert_eq!(f.annotations[0].name, "payable");
}

#[test]
fn parse_item_interface_empty_body() {
    let item = parse_item_from_str("interface IEmpty {}").expect("should parse");
    let Item::Interface(iface) = item else {
        panic!("expected Interface");
    };
    assert_eq!(iface.name, "IEmpty");
    assert!(iface.members.is_empty());
}

// ── Trait tests (subtask 2f) ──────────────────────────────────────────────────

#[test]
fn parse_item_trait_required_functions() {
    // Functions without body = required (abstract)
    let item = parse_item_from_str(
        "trait Ownable {
            state { owner: Address }
            fn onlyOwner()
            pub fn transferOwnership(newOwner: Address)
        }",
    )
    .expect("should parse");
    let Item::Trait(t) = item else {
        panic!("expected Trait, got {item:?}");
    };
    assert_eq!(t.name, "Ownable");
    assert_eq!(t.members.len(), 3);
    // First member is State
    assert!(
        matches!(t.members[0], TraitMember::State(_)),
        "first member should be State"
    );
    // Remaining are Functions (required, body=None)
    for m in &t.members[1..] {
        let TraitMember::Function(f) = m else {
            panic!("expected Function member");
        };
        assert!(f.body.is_none(), "required trait fn has no body");
    }
}

#[test]
fn parse_item_trait_default_implementations() {
    // Functions WITH body = default implementation
    let item = parse_item_from_str(
        "trait Vault {
            fn asset() -> Address
            view fn totalAssets() -> u128 { return 0 }
        }",
    )
    .expect("should parse");
    let Item::Trait(t) = item else {
        panic!("expected Trait, got {item:?}");
    };
    assert_eq!(t.members.len(), 2);
    let TraitMember::Function(f0) = &t.members[0] else {
        panic!("expected Function");
    };
    assert!(f0.body.is_none(), "required fn has no body");
    let TraitMember::Function(f1) = &t.members[1] else {
        panic!("expected Function");
    };
    assert!(f1.body.is_some(), "default impl fn has a body");
}

#[test]
fn parse_item_trait_empty_body() {
    let item = parse_item_from_str("trait Empty {}").expect("should parse");
    let Item::Trait(t) = item else {
        panic!("expected Trait");
    };
    assert_eq!(t.name, "Empty");
    assert!(t.members.is_empty());
}

// ── Library tests (subtask 2f) ────────────────────────────────────────────────

#[test]
fn parse_item_library_with_functions() {
    let item = parse_item_from_str(
        "library SafeMath {
            fn add(a: u128, b: u128) -> u128 { return a + b }
            fn sub(a: u128, b: u128) -> u128 { return a - b }
            fn mul(a: u128, b: u128) -> u128 { return a * b }
        }",
    )
    .expect("should parse");
    let Item::Library(lib) = item else {
        panic!("expected Library, got {item:?}");
    };
    assert_eq!(lib.name, "SafeMath");
    assert_eq!(lib.functions.len(), 3);
    assert_eq!(lib.functions[0].name, "add");
    assert_eq!(lib.functions[1].name, "sub");
    assert_eq!(lib.functions[2].name, "mul");
}

#[test]
fn parse_item_library_empty_body() {
    let item = parse_item_from_str("library Empty {}").expect("should parse");
    let Item::Library(lib) = item else {
        panic!("expected Library");
    };
    assert_eq!(lib.name, "Empty");
    assert!(lib.functions.is_empty());
}

#[test]
fn parse_item_library_rejects_state() {
    // Libraries cannot have state — must return Err
    let result = parse_item_from_str("library Bad { state { x: u128 } }");
    assert!(result.is_err(), "library with state should error");
}

// ── Generic bounds tests (subtask 2f) ─────────────────────────────────────────

#[test]
fn parse_decl_generic_bound_simple() {
    // `<T: Comparable>` — single bound on struct
    let item = parse_item_from_str("struct Sorted<T: Comparable> { items: Array<T> }")
        .expect("should parse");
    let Item::Struct(s) = item else {
        panic!("expected Struct, got {item:?}");
    };
    assert_eq!(s.generic_params.len(), 1);
    assert_eq!(s.generic_params[0].name, "T");
    assert!(
        s.generic_params[0].bound.is_some(),
        "T should have Comparable bound"
    );
    // Bound is represented as Type::Named("Comparable", [])
    assert_eq!(
        s.generic_params[0].bound,
        Some(Type::Named("Comparable".into(), vec![]))
    );
}

#[test]
fn parse_decl_generic_bound_multiple() {
    // `<K: Hashable, V: Default>` — multiple bounds
    let item = parse_item_from_str("struct Cache<K: Hashable, V: Default> { entries: Map<K, V> }")
        .expect("should parse");
    let Item::Struct(s) = item else {
        panic!("expected Struct, got {item:?}");
    };
    assert_eq!(s.generic_params.len(), 2);
    assert_eq!(s.generic_params[0].name, "K");
    assert!(
        s.generic_params[0].bound.is_some(),
        "K should have Hashable bound"
    );
    assert_eq!(s.generic_params[1].name, "V");
    assert!(
        s.generic_params[1].bound.is_some(),
        "V should have Default bound"
    );
}

#[test]
fn parse_decl_generic_no_bound() {
    // `<T>` — no bound
    let item = parse_item_from_str("struct Box<T> { value: T }").expect("should parse");
    let Item::Struct(s) = item else {
        panic!("expected Struct");
    };
    assert_eq!(s.generic_params.len(), 1);
    assert_eq!(s.generic_params[0].name, "T");
    assert!(s.generic_params[0].bound.is_none(), "T has no bound");
}

#[test]
fn parse_decl_function_generic_bound() {
    // `fn max<T: Comparable>(a: T, b: T) -> T { ... }`
    let item = parse_item_from_str("fn max<T: Comparable>(a: T, b: T) -> T { return a }")
        .expect("should parse");
    let Item::Function(f) = item else {
        panic!("expected Function, got {item:?}");
    };
    assert_eq!(f.generic_params.len(), 1);
    assert_eq!(f.generic_params[0].name, "T");
    assert!(f.generic_params[0].bound.is_some());
    assert_eq!(
        f.generic_params[0].bound,
        Some(Type::Named("Comparable".into(), vec![]))
    );
}

// ── using-for tests (subtask 2f) ──────────────────────────────────────────────

#[test]
fn parse_item_using_for_top_level() {
    let item = parse_item_from_str("using SafeMath for u128").expect("should parse");
    let Item::Using(u) = item else {
        panic!("expected Using, got {item:?}");
    };
    assert_eq!(u.library, "SafeMath");
    assert_eq!(u.for_type, Type::U128);
}

// ── Contract composition tests (subtask 2f) ───────────────────────────────────

#[test]
fn parse_decl_contract_implements_and_uses() {
    let item = parse_item_from_str(
        "contract DEX implements IDEX, ISwap uses Ownable, ReentrancyGuard {
            state { fee: u128 }
        }",
    )
    .expect("should parse");
    let Item::Contract(c) = item else {
        panic!("expected Contract, got {item:?}");
    };
    assert_eq!(c.implements, vec!["IDEX", "ISwap"]);
    assert_eq!(c.uses, vec!["Ownable", "ReentrancyGuard"]);
}

#[test]
fn parse_decl_contract_implements_only() {
    let item = parse_item_from_str("contract Token implements IToken { state { supply: u128 } }")
        .expect("should parse");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert_eq!(c.implements, vec!["IToken"]);
    assert!(c.uses.is_empty());
}

#[test]
fn parse_decl_contract_uses_only() {
    let item = parse_item_from_str("contract Safe uses Ownable { state { owner: Address } }")
        .expect("should parse");
    let Item::Contract(c) = item else {
        panic!("expected Contract");
    };
    assert!(c.implements.is_empty());
    assert_eq!(c.uses, vec!["Ownable"]);
}

// ── Fuzz safety — interface/trait/library (subtask 2f) ────────────────────────

#[test]
fn parse_item_interface_trait_library_malformed_never_panic() {
    // Malformed inputs must return Err, never panic.
    let malformed = [
        "interface I {",
        "interface I { fn",
        "interface I { @onlyOwner }",
        "trait T { state",
        "library L { state { x: u128 } }",
        "interface",
        "trait",
        "library",
        "interface I",
        "trait T",
        "library L",
    ];
    for src in malformed {
        // Must not panic — Ok or Err are both acceptable outcomes.
        let _ = tokenize(src).and_then(|tokens| {
            let mut p = Parser::new(tokens);
            p.parse_top_level_item()
        });
    }
}

// ── Token config / metadata (subtask 2g) ──────────────────────────────────────

#[cfg(test)]
mod token_config {
    use crate::lexer::tokenize;
    use crate::parser::ast::{Config, ConfigValue, ContractMember, Item, Metadata, UnitKind};
    use crate::parser::Parser;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn parse_token(src: &str) -> Result<Item, crate::error::LangError> {
        let tokens = tokenize(src)?;
        let mut p = Parser::new(tokens);
        p.parse_top_level_item()
    }

    fn token_members(src: &str) -> Vec<ContractMember> {
        match parse_token(src).expect("parse failed") {
            Item::Token_(decl) => decl.members,
            other => panic!("expected Token_ item, got: {other:?}"),
        }
    }

    fn single_config(src: &str) -> Config {
        let members = token_members(src);
        assert_eq!(members.len(), 1, "expected exactly one member");
        match members.into_iter().next().unwrap() {
            ContractMember::Config(c) => c,
            other => panic!("expected Config member, got: {other:?}"),
        }
    }

    fn single_metadata(src: &str) -> Metadata {
        let members = token_members(src);
        assert_eq!(members.len(), 1, "expected exactly one member");
        match members.into_iter().next().unwrap() {
            ContractMember::Metadata(m) => m,
            other => panic!("expected Metadata member, got: {other:?}"),
        }
    }

    // ── ConfigValue::Str ──────────────────────────────────────────────────────

    #[test]
    fn parse_config_str_value() {
        let cfg = single_config(
            r#"token T extends Token {
config {
name: "Example Token"
symbol: "EXT"
}
}"#,
        );
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].key, "name");
        assert_eq!(
            cfg.entries[0].value,
            ConfigValue::Str("Example Token".into())
        );
        assert_eq!(cfg.entries[1].key, "symbol");
        assert_eq!(cfg.entries[1].value, ConfigValue::Str("EXT".into()));
    }

    // ── ConfigValue::Int ──────────────────────────────────────────────────────

    #[test]
    fn parse_config_int_value() {
        let cfg = single_config(
            "token T extends Token {\nconfig {\ndecimals: 18\nmaxSupply: 1000000000\n}\n}",
        );
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].key, "decimals");
        assert_eq!(cfg.entries[0].value, ConfigValue::Int(18));
        assert_eq!(cfg.entries[1].key, "maxSupply");
        assert_eq!(cfg.entries[1].value, ConfigValue::Int(1_000_000_000));
    }

    // ── ConfigValue::Bool ─────────────────────────────────────────────────────

    #[test]
    fn parse_config_bool_value() {
        let cfg = single_config(
            "token T extends Token {\nconfig {\nantiHoneypot: true\nmintable: false\n}\n}",
        );
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].value, ConfigValue::Bool(true));
        assert_eq!(cfg.entries[1].value, ConfigValue::Bool(false));
    }

    // ── ConfigValue::Percent ──────────────────────────────────────────────────

    #[test]
    fn parse_config_percent_value() {
        let cfg = single_config(
            "token T extends Token {\nconfig {\nteamShare: 15%\ninvestorShare: 10%\n}\n}",
        );
        assert_eq!(cfg.entries.len(), 2);
        assert_eq!(cfg.entries[0].key, "teamShare");
        assert_eq!(cfg.entries[0].value, ConfigValue::Percent(15));
        assert_eq!(cfg.entries[1].value, ConfigValue::Percent(10));
    }

    // ── ConfigValue::Unit — hours / seconds / months ──────────────────────────

    #[test]
    fn parse_config_unit_hours() {
        let cfg =
            single_config("token T extends Token {\nconfig {\napprovalExpiry: 24.hours\n}\n}");
        assert_eq!(cfg.entries[0].key, "approvalExpiry");
        assert_eq!(cfg.entries[0].value, ConfigValue::Unit(24, UnitKind::Hours));
    }

    #[test]
    fn parse_config_unit_seconds() {
        let cfg = single_config(
            "token T extends Token {\nconfig {\ncooldownBetweenBuys: 30.seconds\n}\n}",
        );
        assert_eq!(
            cfg.entries[0].value,
            ConfigValue::Unit(30, UnitKind::Seconds)
        );
    }

    #[test]
    fn parse_config_unit_months() {
        let cfg = single_config("token T extends Token {\nconfig {\ncliff: 6.months\n}\n}");
        assert_eq!(cfg.entries[0].value, ConfigValue::Unit(6, UnitKind::Months));
    }

    // ── ConfigValue::Object (nested block) ────────────────────────────────────

    #[test]
    fn parse_config_nested_object() {
        let cfg = single_config(
            r#"token T extends Token {
config {
fairLaunch: {
enabled: true
maxBuyPerWallet: 10000
cooldownBetweenBuys: 30.seconds
antiSnipeBlocks: 3
}
}
}"#,
        );
        assert_eq!(cfg.entries.len(), 1);
        assert_eq!(cfg.entries[0].key, "fairLaunch");
        match &cfg.entries[0].value {
            ConfigValue::Object(inner) => {
                assert_eq!(inner.len(), 4);
                assert_eq!(inner[0].key, "enabled");
                assert_eq!(inner[0].value, ConfigValue::Bool(true));
                assert_eq!(inner[1].key, "maxBuyPerWallet");
                assert_eq!(inner[1].value, ConfigValue::Int(10000));
                assert_eq!(inner[2].key, "cooldownBetweenBuys");
                assert_eq!(inner[2].value, ConfigValue::Unit(30, UnitKind::Seconds));
                assert_eq!(inner[3].key, "antiSnipeBlocks");
                assert_eq!(inner[3].value, ConfigValue::Int(3));
            }
            other => panic!("expected Object, got: {other:?}"),
        }
    }

    #[test]
    fn parse_config_deeply_nested_object() {
        // vesting: { team: { amount: 15%, cliff: 6.months, linear: 24.months } }
        let cfg = single_config(
            r#"token T extends Token {
config {
vesting: {
team: { amount: 15%, cliff: 6.months, linear: 24.months }
}
}
}"#,
        );
        assert_eq!(cfg.entries[0].key, "vesting");
        let vesting = match &cfg.entries[0].value {
            ConfigValue::Object(v) => v,
            other => panic!("expected Object, got: {other:?}"),
        };
        assert_eq!(vesting.len(), 1);
        assert_eq!(vesting[0].key, "team");
        let team = match &vesting[0].value {
            ConfigValue::Object(t) => t,
            other => panic!("expected Object, got: {other:?}"),
        };
        assert_eq!(team.len(), 3);
        assert_eq!(team[0].value, ConfigValue::Percent(15));
        assert_eq!(team[1].value, ConfigValue::Unit(6, UnitKind::Months));
        assert_eq!(team[2].value, ConfigValue::Unit(24, UnitKind::Months));
    }

    // ── Metadata block ────────────────────────────────────────────────────────

    #[test]
    fn parse_metadata_block() {
        let meta = single_metadata(
            r#"token T extends Token {
metadata {
image: "ipfs://Qm..."
website: "https://example.com"
}
}"#,
        );
        assert_eq!(meta.entries.len(), 2);
        assert_eq!(meta.entries[0].key, "image");
        assert_eq!(
            meta.entries[0].value,
            ConfigValue::Str("ipfs://Qm...".into())
        );
        assert_eq!(meta.entries[1].key, "website");
        assert_eq!(
            meta.entries[1].value,
            ConfigValue::Str("https://example.com".into())
        );
    }

    #[test]
    fn parse_metadata_nested_socials() {
        let meta = single_metadata(
            r#"token T extends Token {
metadata {
socials: { twitter: "@example", telegram: "t.me/example" }
}
}"#,
        );
        assert_eq!(meta.entries[0].key, "socials");
        match &meta.entries[0].value {
            ConfigValue::Object(inner) => {
                assert_eq!(inner.len(), 2);
                assert_eq!(inner[0].key, "twitter");
                assert_eq!(inner[0].value, ConfigValue::Str("@example".into()));
                assert_eq!(inner[1].key, "telegram");
                assert_eq!(inner[1].value, ConfigValue::Str("t.me/example".into()));
            }
            other => panic!("expected Object, got: {other:?}"),
        }
    }

    // ── Full §24 example: config + metadata in one token ─────────────────────

    #[test]
    fn parse_full_token_standard_example() {
        // Abridged §24 example — all config value forms + metadata in one token.
        let src = r#"token MyToken extends Token {
config {
name: "Example Token"
symbol: "EXT"
decimals: 18
antiHoneypot: true
approvalExpiry: 24.hours
fairLaunch: {
enabled: true
maxBuyPerWallet: 10000
cooldownBetweenBuys: 30.seconds
}
vesting: {
team: { amount: 15%, cliff: 6.months, linear: 24.months }
}
}
metadata {
image: "ipfs://Qm..."
website: "https://example.com"
}
}"#;
        let members = token_members(src);
        assert_eq!(members.len(), 2, "expected Config + Metadata members");
        assert!(matches!(members[0], ContractMember::Config(_)));
        assert!(matches!(members[1], ContractMember::Metadata(_)));

        let cfg = match &members[0] {
            ContractMember::Config(c) => c,
            _ => unreachable!(),
        };
        // Spot-check config entries
        assert_eq!(cfg.entries[0].key, "name");
        assert_eq!(cfg.entries[2].key, "decimals");
        assert_eq!(cfg.entries[2].value, ConfigValue::Int(18));
        assert_eq!(cfg.entries[4].value, ConfigValue::Unit(24, UnitKind::Hours));
    }

    // ── ConfigValue::Ident ────────────────────────────────────────────────────

    #[test]
    fn parse_config_ident_value() {
        let cfg = single_config("token T extends Token {\nconfig {\nmodel: BondingCurve\n}\n}");
        assert_eq!(cfg.entries[0].key, "model");
        assert_eq!(
            cfg.entries[0].value,
            ConfigValue::Ident("BondingCurve".into())
        );
    }

    // ── Edge cases: zero int / empty string / empty nested object ─────────────

    #[test]
    fn parse_config_zero_int_value() {
        let cfg = single_config("token T extends Token {\nconfig {\ndecimals: 0\n}\n}");
        assert_eq!(cfg.entries[0].value, ConfigValue::Int(0));
    }

    #[test]
    fn parse_config_empty_string_value() {
        let cfg = single_config("token T extends Token {\nconfig {\nname: \"\"\n}\n}");
        assert_eq!(cfg.entries[0].value, ConfigValue::Str(String::new()));
    }

    #[test]
    fn parse_config_empty_nested_object() {
        let cfg = single_config("token T extends Token {\nconfig {\nextensions: {}\n}\n}");
        assert_eq!(cfg.entries[0].key, "extensions");
        match &cfg.entries[0].value {
            ConfigValue::Object(inner) => assert!(inner.is_empty()),
            other => panic!("expected empty Object, got: {other:?}"),
        }
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    #[test]
    fn parse_config_rejects_missing_brace() {
        let result = parse_token("token T extends Token {\nconfig\n}");
        assert!(
            result.is_err(),
            "expected parse error for config without brace"
        );
    }

    #[test]
    fn parse_config_rejects_missing_colon() {
        let result = parse_token("token T extends Token {\nconfig {\nname \"oops\"\n}\n}");
        assert!(
            result.is_err(),
            "expected parse error for missing colon in config entry"
        );
    }

    // ── Fuzz safety ───────────────────────────────────────────────────────────

    #[test]
    fn parse_token_config_metadata_malformed_never_panic() {
        let malformed = [
            "token T extends Token { config",
            "token T extends Token { config {",
            "token T extends Token { config { name: }",
            "token T extends Token { metadata",
            "token T extends Token { metadata {",
            "token T extends Token { config { nested: { }",
        ];
        for src in malformed {
            let _ = tokenize(src).and_then(|tokens| {
                let mut p = Parser::new(tokens);
                p.parse_top_level_item()
            });
        }
    }
}
