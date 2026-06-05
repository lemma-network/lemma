//! Tests for `lemma_lang::parser::ty`.
//!
//! Covers ALL type forms from §29 of the language spec.
//! Uses the lexer to produce token streams, then calls `Parser::parse_type()`.

use crate::lexer::token::{Span, Token};
use crate::lexer::tokenize;
use crate::parser::ast::Type;
use crate::parser::Parser;

// ── Test helper ───────────────────────────────────────────────────────────────

/// Tokenize a type string and parse it with `Parser::parse_type()`.
fn parse_type(src: &str) -> Result<Type, crate::error::LangError> {
    let tokens = tokenize(src)?;
    let mut parser = Parser::new(tokens);
    parser.parse_type()
}

// ── Primitive types ───────────────────────────────────────────────────────────

#[test]
fn parse_type_u8() {
    assert_eq!(parse_type("u8").unwrap(), Type::U8);
}
#[test]
fn parse_type_u16() {
    assert_eq!(parse_type("u16").unwrap(), Type::U16);
}
#[test]
fn parse_type_u32() {
    assert_eq!(parse_type("u32").unwrap(), Type::U32);
}
#[test]
fn parse_type_u64() {
    assert_eq!(parse_type("u64").unwrap(), Type::U64);
}
#[test]
fn parse_type_u128() {
    assert_eq!(parse_type("u128").unwrap(), Type::U128);
}
#[test]
fn parse_type_u256() {
    assert_eq!(parse_type("u256").unwrap(), Type::U256);
}

#[test]
fn parse_type_i8() {
    assert_eq!(parse_type("i8").unwrap(), Type::I8);
}
#[test]
fn parse_type_i16() {
    assert_eq!(parse_type("i16").unwrap(), Type::I16);
}
#[test]
fn parse_type_i32() {
    assert_eq!(parse_type("i32").unwrap(), Type::I32);
}
#[test]
fn parse_type_i64() {
    assert_eq!(parse_type("i64").unwrap(), Type::I64);
}
#[test]
fn parse_type_i128() {
    assert_eq!(parse_type("i128").unwrap(), Type::I128);
}
#[test]
fn parse_type_i256() {
    assert_eq!(parse_type("i256").unwrap(), Type::I256);
}

#[test]
fn parse_type_bool() {
    assert_eq!(parse_type("bool").unwrap(), Type::Bool);
}
#[test]
fn parse_type_string() {
    assert_eq!(parse_type("string").unwrap(), Type::StringTy);
}
#[test]
fn parse_type_char() {
    assert_eq!(parse_type("char").unwrap(), Type::CharTy);
}
#[test]
fn parse_type_address() {
    assert_eq!(parse_type("Address").unwrap(), Type::AddressTy);
}
#[test]
fn parse_type_hash() {
    assert_eq!(parse_type("Hash").unwrap(), Type::HashTy);
}
#[test]
fn parse_type_bytes() {
    assert_eq!(parse_type("bytes").unwrap(), Type::Bytes);
}

// ── bytesN ────────────────────────────────────────────────────────────────────

#[test]
fn parse_type_bytes1() {
    assert_eq!(parse_type("bytes1").unwrap(), Type::BytesN(1));
}
#[test]
fn parse_type_bytes16() {
    assert_eq!(parse_type("bytes16").unwrap(), Type::BytesN(16));
}
#[test]
fn parse_type_bytes32() {
    assert_eq!(parse_type("bytes32").unwrap(), Type::BytesN(32));
}

// ── Array<T> ──────────────────────────────────────────────────────────────────

#[test]
fn parse_type_array_u128() {
    let ty = parse_type("Array<u128>").unwrap();
    assert_eq!(ty, Type::Array(Box::new(Type::U128)));
}

#[test]
fn parse_type_array_address() {
    let ty = parse_type("Array<Address>").unwrap();
    assert_eq!(ty, Type::Array(Box::new(Type::AddressTy)));
}

// ── [T; N] ────────────────────────────────────────────────────────────────────

#[test]
fn parse_type_fixed_array_u8_32() {
    let ty = parse_type("[u8; 32]").unwrap();
    assert_eq!(ty, Type::FixedArray(Box::new(Type::U8), 32));
}

#[test]
fn parse_type_fixed_array_bool_10() {
    let ty = parse_type("[bool; 10]").unwrap();
    assert_eq!(ty, Type::FixedArray(Box::new(Type::Bool), 10));
}

// ── Map<K, V> ─────────────────────────────────────────────────────────────────

#[test]
fn parse_type_map_address_u256() {
    let ty = parse_type("Map<Address, u256>").unwrap();
    assert_eq!(
        ty,
        Type::Map(Box::new(Type::AddressTy), Box::new(Type::U256))
    );
}

#[test]
fn parse_type_map_string_bool() {
    let ty = parse_type("Map<string, bool>").unwrap();
    assert_eq!(
        ty,
        Type::Map(Box::new(Type::StringTy), Box::new(Type::Bool))
    );
}

// ── FastMap<K, V> ─────────────────────────────────────────────────────────────

#[test]
fn parse_type_fast_map_address_u128() {
    let ty = parse_type("FastMap<Address, u128>").unwrap();
    assert_eq!(
        ty,
        Type::FastMap(Box::new(Type::AddressTy), Box::new(Type::U128))
    );
}

// ── Set<T> ────────────────────────────────────────────────────────────────────

#[test]
fn parse_type_set_address() {
    let ty = parse_type("Set<Address>").unwrap();
    assert_eq!(ty, Type::Set(Box::new(Type::AddressTy)));
}

// ── Option<T> ────────────────────────────────────────────────────────────────

#[test]
fn parse_type_option_u64() {
    let ty = parse_type("Option<u64>").unwrap();
    assert_eq!(ty, Type::Option_(Box::new(Type::U64)));
}

#[test]
fn parse_type_option_string() {
    let ty = parse_type("Option<string>").unwrap();
    assert_eq!(ty, Type::Option_(Box::new(Type::StringTy)));
}

// ── Result<T, E> ─────────────────────────────────────────────────────────────

#[test]
fn parse_type_result_u256_string() {
    let ty = parse_type("Result<u256, string>").unwrap();
    assert_eq!(
        ty,
        Type::Result_(Box::new(Type::U256), Box::new(Type::StringTy))
    );
}

#[test]
fn parse_type_result_bool_u64() {
    let ty = parse_type("Result<bool, u64>").unwrap();
    assert_eq!(ty, Type::Result_(Box::new(Type::Bool), Box::new(Type::U64)));
}

// ── decimal(N) ────────────────────────────────────────────────────────────────

#[test]
fn parse_type_decimal_18() {
    let ty = parse_type("decimal(18)").unwrap();
    assert_eq!(ty, Type::Decimal(18));
}

#[test]
fn parse_type_decimal_6() {
    let ty = parse_type("decimal(6)").unwrap();
    assert_eq!(ty, Type::Decimal(6));
}

// ── Tuple (T1, T2, T3) ───────────────────────────────────────────────────────

#[test]
fn parse_type_tuple_two_elements() {
    let ty = parse_type("(u64, bool)").unwrap();
    assert_eq!(ty, Type::Tuple(vec![Type::U64, Type::Bool]));
}

#[test]
fn parse_type_tuple_three_elements() {
    let ty = parse_type("(u64, Address, string)").unwrap();
    assert_eq!(
        ty,
        Type::Tuple(vec![Type::U64, Type::AddressTy, Type::StringTy])
    );
}

#[test]
fn parse_type_empty_tuple() {
    let ty = parse_type("()").unwrap();
    assert_eq!(ty, Type::Tuple(vec![]));
}

#[test]
fn parse_type_single_paren_is_not_tuple() {
    // `(u64)` is just `u64` — single-element parens are transparent
    let ty = parse_type("(u64)").unwrap();
    assert_eq!(ty, Type::U64);
}

// ── fn(T1, T2) -> R ──────────────────────────────────────────────────────────

#[test]
fn parse_type_fn_no_params() {
    let ty = parse_type("fn() -> bool").unwrap();
    assert_eq!(ty, Type::Fn(vec![], Box::new(Type::Bool)));
}

#[test]
fn parse_type_fn_one_param() {
    let ty = parse_type("fn(u64) -> bool").unwrap();
    assert_eq!(ty, Type::Fn(vec![Type::U64], Box::new(Type::Bool)));
}

#[test]
fn parse_type_fn_two_params() {
    let ty = parse_type("fn(Address, u256) -> bool").unwrap();
    assert_eq!(
        ty,
        Type::Fn(vec![Type::AddressTy, Type::U256], Box::new(Type::Bool))
    );
}

// ── Named types ───────────────────────────────────────────────────────────────

#[test]
fn parse_type_named_no_generics() {
    let ty = parse_type("MyToken").unwrap();
    assert_eq!(ty, Type::Named("MyToken".to_string(), vec![]));
}

#[test]
fn parse_type_named_one_generic() {
    let ty = parse_type("Pair<u64>").unwrap();
    assert_eq!(ty, Type::Named("Pair".to_string(), vec![Type::U64]));
}

#[test]
fn parse_type_named_two_generics() {
    let ty = parse_type("Pair<u64, Address>").unwrap();
    assert_eq!(
        ty,
        Type::Named("Pair".to_string(), vec![Type::U64, Type::AddressTy])
    );
}

// ── Nested types ──────────────────────────────────────────────────────────────

#[test]
fn parse_type_map_address_array_u128() {
    // Map<Address, Array<u128>>
    let ty = parse_type("Map<Address, Array<u128>>").unwrap();
    assert_eq!(
        ty,
        Type::Map(
            Box::new(Type::AddressTy),
            Box::new(Type::Array(Box::new(Type::U128))),
        )
    );
}

#[test]
fn parse_type_option_map() {
    // Option<Map<Address, u256>>
    let ty = parse_type("Option<Map<Address, u256>>").unwrap();
    assert_eq!(
        ty,
        Type::Option_(Box::new(Type::Map(
            Box::new(Type::AddressTy),
            Box::new(Type::U256),
        )))
    );
}

#[test]
fn parse_type_result_with_named_error() {
    // Result<u256, MyError>
    let ty = parse_type("Result<u256, MyError>").unwrap();
    assert_eq!(
        ty,
        Type::Result_(
            Box::new(Type::U256),
            Box::new(Type::Named("MyError".to_string(), vec![])),
        )
    );
}

// ── 3-level nesting (triple `>` / `>>` + `>` disambiguation) ─────────────────

#[test]
fn parse_type_three_level_nested_map_handles_triple_gt() {
    // Map<u8, Map<u16, Map<u32, u64>>> lexes the closing as Shr, Gt
    // expect_gt must correctly unwind all 3 closing >
    let ty = parse_type("Map<u8, Map<u16, Map<u32, u64>>>").expect("should parse");
    if let Type::Map(k, v) = ty {
        assert!(matches!(*k, Type::U8));
        if let Type::Map(k2, v2) = *v {
            assert!(matches!(*k2, Type::U16));
            if let Type::Map(k3, v3) = *v2 {
                assert!(matches!(*k3, Type::U32));
                assert!(matches!(*v3, Type::U64));
            } else {
                panic!("expected 3rd Map");
            }
        } else {
            panic!("expected 2nd Map");
        }
    } else {
        panic!("expected outer Map");
    }
}

#[test]
fn parse_type_array_of_array_of_array_handles_triple_gt() {
    // Array<Array<Array<u8>>> — triple >
    let ty = parse_type("Array<Array<Array<u8>>>").expect("should parse");
    if let Type::Array(inner) = ty {
        if let Type::Array(inner2) = *inner {
            assert!(matches!(*inner2, Type::Array(_)));
        } else {
            panic!("expected Array<Array>");
        }
    } else {
        panic!("expected Array");
    }
}

#[test]
fn parse_type_result_with_nested_map_value() {
    // Result<Map<Address, u128>, string>
    let ty = parse_type("Result<Map<Address, u128>, string>").expect("should parse");
    assert!(matches!(ty, Type::Result_(_, _)));
}

#[test]
fn parse_type_option_of_option_of_u64() {
    // Option<Option<u64>> — double >
    let ty = parse_type("Option<Option<u64>>").expect("should parse");
    if let Type::Option_(inner) = ty {
        assert!(matches!(*inner, Type::Option_(_)));
    } else {
        panic!("expected Option<Option<u64>>");
    }
}

#[test]
fn parse_type_map_with_option_value_nested() {
    // Map<Address, Option<Map<string, u64>>>
    let ty = parse_type("Map<Address, Option<Map<string, u64>>>").expect("should parse");
    if let Type::Map(k, v) = ty {
        assert!(matches!(*k, Type::AddressTy));
        if let Type::Option_(inner) = *v {
            assert!(matches!(*inner, Type::Map(_, _)));
        } else {
            panic!("expected Option<Map<...>>");
        }
    } else {
        panic!("expected outer Map");
    }
}

// ── Error cases ───────────────────────────────────────────────────────────────

#[test]
fn parse_type_unknown_token_returns_error() {
    // `42` is not a valid type
    let tokens = tokenize("42").unwrap();
    let mut parser = Parser::new(tokens);
    let result = parser.parse_type();
    assert!(
        result.is_err(),
        "expected parse error for integer literal as type"
    );
}

#[test]
fn parse_type_missing_closing_angle_returns_error() {
    // `Array<u64` — missing `>`
    let tokens = tokenize("Array<u64").unwrap();
    let mut parser = Parser::new(tokens);
    let result = parser.parse_type();
    assert!(result.is_err(), "expected parse error for unclosed generic");
}

#[test]
fn parse_type_map_missing_comma_returns_error() {
    // `Map<Address u256>` — missing `,`
    let tokens = tokenize("Map<Address u256>").unwrap();
    let mut parser = Parser::new(tokens);
    let result = parser.parse_type();
    assert!(
        result.is_err(),
        "expected parse error for missing comma in Map"
    );
}

#[test]
fn parse_type_decimal_missing_paren_returns_error() {
    // `decimal 18` — missing `(`
    let tokens = tokenize("decimal 18").unwrap();
    let mut parser = Parser::new(tokens);
    let result = parser.parse_type();
    assert!(
        result.is_err(),
        "expected parse error for decimal without parens"
    );
}

#[test]
fn parse_type_fn_missing_arrow_returns_error() {
    // `fn(u64) bool` — missing `->`
    let tokens = tokenize("fn(u64) bool").unwrap();
    let mut parser = Parser::new(tokens);
    let result = parser.parse_type();
    assert!(
        result.is_err(),
        "expected parse error for fn type without ->"
    );
}

// ── Parser does not panic on any type input ───────────────────────────────────

#[test]
fn parse_type_does_not_panic_on_empty_stream() {
    // Empty token stream (just Eof)
    let span = Span::at(1, 1, 0);
    let tokens = vec![(Token::Eof, span)];
    let mut parser = Parser::new(tokens);
    let result = parser.parse_type();
    assert!(result.is_err());
}

#[test]
fn parse_type_does_not_panic_on_truncated_map() {
    // `Map<` — truncated
    let tokens = tokenize("Map<").unwrap();
    let mut parser = Parser::new(tokens);
    let _ = parser.parse_type(); // must not panic
}

#[test]
fn parse_type_does_not_panic_on_truncated_fn() {
    // `fn(` — truncated
    let tokens = tokenize("fn(").unwrap();
    let mut parser = Parser::new(tokens);
    let _ = parser.parse_type(); // must not panic
}
