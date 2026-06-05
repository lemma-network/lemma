//! Tests for the statement parser stub (subtask 2c will expand these).

use crate::lexer::tokenize;
use crate::parser::Parser;

#[test]
fn parse_stmt_returns_error_not_implemented() {
    let tokens = tokenize("let x = 1").expect("tokenize failed");
    let mut p = Parser::new(tokens);
    // The stub always returns Err — this is expected until subtask 2c
    let result = p.parse_stmt();
    assert!(result.is_err(), "parse_stmt stub should return Err");
}
