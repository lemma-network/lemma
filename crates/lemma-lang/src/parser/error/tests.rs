//! Tests for `lemma_lang::parser::error`.
//!
//! Covers construction, Display output, Clone round-trips, and PartialEq.
//! 100% public API coverage per AGENTS.md §11.1.

use super::*;
use crate::lexer::token::Span;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn test_span() -> Span {
    Span {
        line: 5,
        col: 12,
        offset: 100,
        len: 3,
    }
}

fn simple_error() -> ParseError {
    ParseError {
        message: "expected '{'".to_string(),
        span: test_span(),
        expected: vec!["'{'".to_string()],
    }
}

// ── Construction ─────────────────────────────────────────────────────────────

#[test]
fn parse_error_constructs_with_all_fields() {
    let err = simple_error();
    assert_eq!(err.message, "expected '{'");
    assert_eq!(err.span, test_span());
    assert_eq!(err.expected, vec!["'{'".to_string()]);
}

#[test]
fn parse_error_constructs_with_empty_expected() {
    let err = ParseError {
        message: "unexpected token".to_string(),
        span: test_span(),
        expected: vec![],
    };
    assert!(err.expected.is_empty());
}

#[test]
fn parse_error_constructs_with_multiple_expected() {
    let err = ParseError {
        message: "unexpected token".to_string(),
        span: test_span(),
        expected: vec![
            "'fn'".to_string(),
            "'contract'".to_string(),
            "'let'".to_string(),
        ],
    };
    assert_eq!(err.expected.len(), 3);
}

// ── Display ──────────────────────────────────────────────────────────────────

#[test]
fn parse_error_display_contains_message() {
    let err = simple_error();
    let s = err.to_string();
    assert!(s.contains("expected '{'"), "got: {s}");
}

#[test]
fn parse_error_display_contains_parse_error_prefix() {
    let err = simple_error();
    let s = err.to_string();
    assert!(s.starts_with("parse error at"), "got: {s}");
}

#[test]
fn parse_error_display_contains_expected_list() {
    let err = simple_error();
    let s = err.to_string();
    // The expected list is shown in Debug format
    assert!(s.contains("expected:"), "got: {s}");
}

#[test]
fn parse_error_display_with_empty_expected() {
    let err = ParseError {
        message: "bad token".to_string(),
        span: Span::at(1, 1, 0),
        expected: vec![],
    };
    let s = err.to_string();
    assert!(s.contains("bad token"), "got: {s}");
    assert!(s.starts_with("parse error at"), "got: {s}");
}

// ── Clone + PartialEq ────────────────────────────────────────────────────────

#[test]
fn parse_error_clones_equal_to_original() {
    let err = simple_error();
    assert_eq!(err.clone(), err);
}

#[test]
fn parse_error_same_fields_are_equal() {
    let a = simple_error();
    let b = simple_error();
    assert_eq!(a, b);
}

#[test]
fn parse_error_different_messages_are_not_equal() {
    let a = ParseError {
        message: "error A".to_string(),
        span: test_span(),
        expected: vec![],
    };
    let b = ParseError {
        message: "error B".to_string(),
        span: test_span(),
        expected: vec![],
    };
    assert_ne!(a, b);
}

#[test]
fn parse_error_different_spans_are_not_equal() {
    let a = ParseError {
        message: "same".to_string(),
        span: Span {
            line: 1,
            col: 1,
            offset: 0,
            len: 1,
        },
        expected: vec![],
    };
    let b = ParseError {
        message: "same".to_string(),
        span: Span {
            line: 2,
            col: 5,
            offset: 10,
            len: 3,
        },
        expected: vec![],
    };
    assert_ne!(a, b);
}

#[test]
fn parse_error_different_expected_are_not_equal() {
    let a = ParseError {
        message: "same".to_string(),
        span: test_span(),
        expected: vec!["'fn'".to_string()],
    };
    let b = ParseError {
        message: "same".to_string(),
        span: test_span(),
        expected: vec!["'contract'".to_string()],
    };
    assert_ne!(a, b);
}

// ── std::error::Error trait ──────────────────────────────────────────────────

#[test]
fn parse_error_implements_std_error() {
    // Verify it satisfies the std::error::Error bound (thiserror derives it)
    let err: &dyn std::error::Error = &simple_error();
    assert!(err.to_string().contains("parse error at"));
}
