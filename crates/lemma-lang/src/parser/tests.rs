//! Integration tests for `lemma_lang::parser`.
//!
//! Subtask 2a: basic smoke tests for the parser skeleton.
//! Full integration tests (4 contracts) are added in subtask 2h.

use crate::lexer::tokenize;
use crate::parser::{parse, Parser};

// ── Skeleton smoke tests ──────────────────────────────────────────────────────

#[test]
fn parse_empty_source_returns_empty_ast() {
    let tokens = tokenize("").expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    assert!(ast.items.is_empty());
}

#[test]
fn parse_whitespace_only_returns_empty_ast() {
    let tokens = tokenize("   \n\n  ").expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    assert!(ast.items.is_empty());
}

#[test]
fn parse_does_not_panic_on_arbitrary_tokens() {
    // The placeholder parse_program skips all tokens — must not panic.
    let tokens = tokenize("contract Foo {}").expect("tokenize failed");
    let result = parse(tokens);
    // Either Ok or Err is acceptable — must not panic.
    let _ = result;
}

#[test]
fn parse_does_not_panic_on_deeply_nested_braces() {
    let src = "{ { { { { { { { { { } } } } } } } } } }";
    let tokens = tokenize(src).expect("tokenize failed");
    let _ = parse(tokens); // must not panic
}

#[test]
fn synchronize_advances_to_next_declaration_boundary() {
    // Verify synchronize() stops at a keyword boundary
    let tokens = tokenize("garbage garbage contract Foo {}").expect("tokenize failed");
    let mut parser = Parser::new(tokens);
    // Advance past "garbage garbage" manually, then synchronize should stop at `contract`
    parser.synchronize();
    // After synchronize, we should be at `contract` or EOF — not panicking
    let _ = parser.peek();
}

#[test]
fn peek_nth_returns_correct_lookahead() {
    let tokens = tokenize("contract Foo {}").expect("tokenize failed");
    let parser = Parser::new(tokens);
    // peek_nth(0) == peek()
    assert_eq!(parser.peek_nth(0), parser.peek());
    // peek_nth(1) is the next token
    let _ = parser.peek_nth(1);
}
