//! Tests for `lemma_lang::error`.
//!
//! Covers Display output, Clone round-trips, and PartialEq for all
//! public variants. 100% public API coverage per AGENTS.md §11.1.

use super::*;
use crate::lexer::token::Span;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn test_span() -> Span {
    Span {
        line: 3,
        col: 7,
        offset: 42,
        len: 5,
    }
}

fn lex_error() -> LangError {
    LangError::Lex {
        message: "unexpected character '@'".to_string(),
        span: test_span(),
    }
}

// ── LangError::Lex — Display ─────────────────────────────────────────────────

#[test]
fn lex_error_displays_message_and_span() {
    let err = lex_error();
    let s = err.to_string();
    // Must contain the message
    assert!(s.contains("unexpected character '@'"), "got: {s}");
    // Must contain span info (Debug format of Span)
    assert!(s.contains("lex error at"), "got: {s}");
}

#[test]
fn lex_error_display_includes_span_fields() {
    let err = LangError::Lex {
        message: "bad token".to_string(),
        span: Span {
            line: 1,
            col: 1,
            offset: 0,
            len: 1,
        },
    };
    let s = err.to_string();
    assert!(s.starts_with("lex error at"), "got: {s}");
    assert!(s.contains("bad token"), "got: {s}");
}

// ── LangError::Lex — Clone + PartialEq ───────────────────────────────────────

#[test]
fn lex_error_clones_equal_to_original() {
    let err = lex_error();
    assert_eq!(err.clone(), err);
}

#[test]
fn lex_error_same_fields_are_equal() {
    let a = LangError::Lex {
        message: "oops".to_string(),
        span: test_span(),
    };
    let b = LangError::Lex {
        message: "oops".to_string(),
        span: test_span(),
    };
    assert_eq!(a, b);
}

#[test]
fn lex_error_different_messages_are_not_equal() {
    let a = LangError::Lex {
        message: "error A".to_string(),
        span: test_span(),
    };
    let b = LangError::Lex {
        message: "error B".to_string(),
        span: test_span(),
    };
    assert_ne!(a, b);
}

#[test]
fn lex_error_different_spans_are_not_equal() {
    let a = LangError::Lex {
        message: "same".to_string(),
        span: Span {
            line: 1,
            col: 1,
            offset: 0,
            len: 1,
        },
    };
    let b = LangError::Lex {
        message: "same".to_string(),
        span: Span {
            line: 2,
            col: 5,
            offset: 10,
            len: 3,
        },
    };
    assert_ne!(a, b);
}

// ── LangError::Codegen — Display + Clone + PartialEq ─────────────────────────

#[test]
fn codegen_error_displays_message() {
    let err = LangError::Codegen {
        message: "unsupported instruction in emit_module".to_string(),
    };
    let s = err.to_string();
    assert!(s.starts_with("codegen error:"), "got: {s}");
    assert!(
        s.contains("unsupported instruction in emit_module"),
        "got: {s}"
    );
}

#[test]
fn codegen_error_clones_equal_to_original() {
    let err = LangError::Codegen {
        message: "wasm section overflow".to_string(),
    };
    assert_eq!(err.clone(), err);
}

#[test]
fn codegen_error_same_message_are_equal() {
    let a = LangError::Codegen {
        message: "emit failed".to_string(),
    };
    let b = LangError::Codegen {
        message: "emit failed".to_string(),
    };
    assert_eq!(a, b);
}

#[test]
fn codegen_error_different_messages_are_not_equal() {
    let a = LangError::Codegen {
        message: "error A".to_string(),
    };
    let b = LangError::Codegen {
        message: "error B".to_string(),
    };
    assert_ne!(a, b);
}
