//! Tests for the user-type declaration parsers (subtask 2e).
//!
//! Covers: struct, enum, event, error — both as top-level items and as
//! contract members. Also verifies fuzz-safety (no panics on malformed input).

use crate::error::LangError;
use crate::lexer::tokenize;
use crate::parser::ast::{ContractMember, Item, StructMember};
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
