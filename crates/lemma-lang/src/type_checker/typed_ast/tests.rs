//! Tests for [`TypedAst`].

use std::collections::BTreeMap;

use crate::lexer::token::Span;
use crate::parser::ast::Ast;
use crate::type_checker::types::{ResolvedType, SymbolId, SymbolSig};

use super::TypedAst;

fn empty_ast() -> Ast {
    Ast {
        items: vec![],
        span: Span::at(0, 0, 0),
    }
}

fn make_typed(ast: Ast) -> TypedAst {
    TypedAst::new(
        ast,
        BTreeMap::new(),
        BTreeMap::new(),
        vec![],
        BTreeMap::<SymbolId, SymbolSig>::new(),
    )
}

fn test_span(offset: usize) -> Span {
    Span {
        line: 1,
        col: 1,
        offset,
        len: 1,
    }
}

// ── TypedAst construction ──────────────────────────────────────────────────────

#[test]
fn typed_ast_constructs_with_empty_tables() {
    let ast = empty_ast();
    let typed = TypedAst::new(
        ast,
        BTreeMap::new(),
        BTreeMap::new(),
        vec![],
        BTreeMap::<SymbolId, SymbolSig>::new(),
    );
    assert!(typed.expr_types.is_empty());
    assert!(typed.resolutions.is_empty());
}

#[test]
fn typed_ast_is_fully_typed_false_when_empty() {
    let typed = make_typed(empty_ast());
    assert!(!typed.is_fully_typed());
}

#[test]
fn typed_ast_is_fully_typed_true_when_populated() {
    let mut expr_types = BTreeMap::new();
    expr_types.insert(test_span(0), ResolvedType::U128);
    let typed = TypedAst::new(
        empty_ast(),
        expr_types,
        BTreeMap::new(),
        vec![],
        BTreeMap::<SymbolId, SymbolSig>::new(),
    );
    assert!(typed.is_fully_typed());
}

// ── type_of ────────────────────────────────────────────────────────────────────

#[test]
fn type_of_returns_inserted_type() {
    let span = test_span(5);
    let mut expr_types = BTreeMap::new();
    expr_types.insert(span, ResolvedType::Bool);
    let typed = TypedAst::new(
        empty_ast(),
        expr_types,
        BTreeMap::new(),
        vec![],
        BTreeMap::<SymbolId, SymbolSig>::new(),
    );
    assert_eq!(typed.type_of(&span), Some(&ResolvedType::Bool));
}

#[test]
fn type_of_returns_none_for_unknown_span() {
    let typed = make_typed(empty_ast());
    assert!(typed.type_of(&test_span(99)).is_none());
}

#[test]
fn type_of_distinguishes_spans_by_offset() {
    let span_a = test_span(0);
    let span_b = test_span(10);
    let mut expr_types = BTreeMap::new();
    expr_types.insert(span_a, ResolvedType::U128);
    expr_types.insert(span_b, ResolvedType::Bool);
    let typed = TypedAst::new(
        empty_ast(),
        expr_types,
        BTreeMap::new(),
        vec![],
        BTreeMap::<SymbolId, SymbolSig>::new(),
    );
    assert_eq!(typed.type_of(&span_a), Some(&ResolvedType::U128));
    assert_eq!(typed.type_of(&span_b), Some(&ResolvedType::Bool));
}

// ── resolution_of ──────────────────────────────────────────────────────────────

#[test]
fn resolution_of_returns_inserted_symbol() {
    let span = test_span(3);
    let mut resolutions = BTreeMap::new();
    resolutions.insert(span, SymbolId(1));
    let typed = TypedAst::new(
        empty_ast(),
        BTreeMap::new(),
        resolutions,
        vec![],
        BTreeMap::<SymbolId, SymbolSig>::new(),
    );
    assert_eq!(typed.resolution_of(&span), Some(SymbolId(1)));
}

#[test]
fn resolution_of_returns_none_for_unknown_span() {
    let typed = make_typed(empty_ast());
    assert!(typed.resolution_of(&test_span(0)).is_none());
}

// ── ast field passthrough ──────────────────────────────────────────────────────

#[test]
fn typed_ast_ast_field_is_original_ast() {
    let ast = empty_ast();
    let typed = make_typed(ast.clone());
    assert_eq!(typed.ast.items.len(), 0);
}

#[test]
fn typed_ast_clones_without_panic() {
    let typed = make_typed(empty_ast());
    let _ = typed.clone();
}

// ── Span-uniqueness invariant ──────────────────────────────────────────────────

/// Verify the load-bearing span-uniqueness invariant: two distinct expressions
/// in a parsed program have distinct `Span` values and thus different
/// `BTreeMap` keys.  This guards the `expr_types`/`resolutions` side-table
/// design against silent key collisions.
///
/// Also verifies that real expression spans carry non-zero `len` (they are not
/// constructed via `Span::at(…)` which produces `len: 0`).
#[test]
fn parsed_expression_spans_are_distinct() {
    use crate::lexer::tokenize;
    use crate::parser::ast::{Expr, Item, Stmt};
    use crate::parser::parse;

    // A function with two literal expressions in its body.
    // `42` and `100` must have distinct spans (different source positions).
    let src = "fn f() -> u128 { let a = 42\nlet b = 100\nreturn a }";
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");

    let func = match &ast.items[0] {
        Item::Function(f) => f,
        other => panic!("expected Function, got: {other:?}"),
    };
    let body = func.body.as_ref().expect("body");

    // Collect the spans of all literal expressions in the body.
    let mut literal_spans: Vec<Span> = Vec::new();
    for stmt in body {
        if let Stmt::Let {
            expr: Expr::Literal(_, span),
            ..
        } = stmt
        {
            literal_spans.push(*span);
            assert!(
                span.len > 0,
                "literal span must have non-zero len: {span:?}"
            );
        }
    }
    assert_eq!(literal_spans.len(), 2, "expected two literal expressions");
    assert_ne!(
        literal_spans[0], literal_spans[1],
        "two distinct literals must have distinct spans"
    );

    // Verify they are usable as unique BTreeMap keys.
    let mut map: BTreeMap<Span, &str> = BTreeMap::new();
    map.insert(literal_spans[0], "forty_two");
    map.insert(literal_spans[1], "one_hundred");
    assert_eq!(map.len(), 2, "spans should produce distinct BTreeMap keys");
}

#[test]
fn span_at_zero_len_is_not_a_valid_expr_key() {
    // Spans constructed via Span::at(…) have len: 0 — they are only used for
    // the EOF token and must never be inserted into expr_types.
    // Demonstrate the behaviour: two Span::at with same position ARE equal.
    let s1 = Span::at(1, 1, 0);
    let s2 = Span::at(1, 1, 0);
    assert_eq!(
        s1, s2,
        "identical Span::at spans are equal — collision risk"
    );
    assert_eq!(s1.len, 0, "Span::at produces zero-length span");
    // The checker must therefore never insert EOF-span entries.
}
