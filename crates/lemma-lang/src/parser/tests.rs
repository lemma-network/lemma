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
fn parse_contract_foo_produces_one_item() {
    // parse_program is now real (subtask 2d) — must parse a contract correctly.
    let tokens = tokenize("contract Foo {}").expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    assert_eq!(ast.items.len(), 1);
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

// ── P3-parser-1 backtracking safety net ───────────────────────────────────────

#[test]
fn nested_generic_splits_shr_and_parses() {
    // `Map<u8, Array<u8>>` ends in `>>` (Token::Shr) which expect_gt must split.
    // Proves the split mechanism still works and the type parses correctly.
    let tokens = tokenize("Map<u8, Array<u8>>").expect("tokenize failed");
    let mut parser = Parser::new(tokens);
    let ty = parser.parse_type().expect("nested generic should parse");
    // The outer type must be a Map (sanity that the `>>` was consumed as two `>`).
    assert!(
        format!("{ty:?}").contains("Map"),
        "expected a Map type, got {ty:?}"
    );
}

#[test]
fn rewind_to_forward_safe_position_succeeds() {
    // Rewinding to a position at/after any `>>`-split is sound and must not panic.
    let tokens = tokenize("Map<u8, Array<u8>>").expect("tokenize failed");
    let mut parser = Parser::new(tokens);
    let _ = parser.parse_type().expect("parse");
    let end = parser.pos_for_test();
    // Rewind to the current (end) position — crosses nothing. Safe.
    parser.rewind_to(end);
}

#[test]
#[should_panic(expected = "P3-parser-1")]
fn rewind_across_shr_split_panics() {
    // Rewinding to position 0 after a `>>` split crossed an earlier position
    // must trip the debug_assert guard (this is the unsound case the net catches).
    let tokens = tokenize("Map<u8, Array<u8>>").expect("tokenize failed");
    let mut parser = Parser::new(tokens);
    let _ = parser.parse_type().expect("parse");
    // Rewinding to 0 crosses the recorded split position → guard must fire.
    parser.rewind_to(0);
}
