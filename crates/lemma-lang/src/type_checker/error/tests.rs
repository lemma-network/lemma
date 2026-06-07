//! Tests for [`TypeError`] and [`TypeErrorKind`].

use crate::lexer::token::Span;

use super::{TypeError, TypeErrorKind};

fn test_span() -> Span {
    Span::at(1, 1, 0)
}

// ── TypeError construction ─────────────────────────────────────────────────────

#[test]
fn type_error_constructs_with_all_fields() {
    let err = TypeError {
        kind: TypeErrorKind::DuplicateDeclaration { name: "Foo".into() },
        span: test_span(),
        message: "duplicate declaration: 'Foo'".into(),
    };
    assert_eq!(err.span.line, 1);
    assert_eq!(err.message, "duplicate declaration: 'Foo'");
}

#[test]
fn type_error_display_contains_message() {
    let err = TypeError {
        kind: TypeErrorKind::DuplicateDeclaration { name: "Bar".into() },
        span: test_span(),
        message: "duplicate: Bar".into(),
    };
    let s = err.to_string();
    assert!(s.contains("duplicate: Bar"), "display was: {s}");
}

#[test]
fn type_error_display_contains_span() {
    let err = TypeError {
        kind: TypeErrorKind::DuplicateDeclaration { name: "X".into() },
        span: Span::at(5, 3, 42),
        message: "dup".into(),
    };
    let s = err.to_string();
    assert!(s.contains("type error at"), "display was: {s}");
}

#[test]
fn type_error_clones_equal_to_original() {
    let err = TypeError {
        kind: TypeErrorKind::DuplicateDeclaration { name: "C".into() },
        span: test_span(),
        message: "msg".into(),
    };
    assert_eq!(err.clone(), err);
}

#[test]
fn type_error_same_fields_are_equal() {
    let a = TypeError {
        kind: TypeErrorKind::DuplicateDeclaration { name: "A".into() },
        span: test_span(),
        message: "m".into(),
    };
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn type_error_different_messages_are_not_equal() {
    let base = TypeError {
        kind: TypeErrorKind::DuplicateDeclaration { name: "A".into() },
        span: test_span(),
        message: "first".into(),
    };
    let other = TypeError {
        message: "second".into(),
        ..base.clone()
    };
    assert_ne!(base, other);
}

#[test]
fn type_error_different_spans_are_not_equal() {
    let a = TypeError {
        kind: TypeErrorKind::DuplicateDeclaration { name: "A".into() },
        span: Span::at(1, 1, 0),
        message: "m".into(),
    };
    let b = TypeError {
        span: Span::at(2, 1, 10),
        ..a.clone()
    };
    assert_ne!(a, b);
}

#[test]
fn type_error_implements_std_error() {
    let err = TypeError {
        kind: TypeErrorKind::DuplicateDeclaration { name: "Z".into() },
        span: test_span(),
        message: "err".into(),
    };
    // Ensure it satisfies std::error::Error (used for ? propagation)
    let _: &dyn std::error::Error = &err;
}

// ── TypeErrorKind ──────────────────────────────────────────────────────────────

#[test]
fn duplicate_declaration_kind_stores_name() {
    let kind = TypeErrorKind::DuplicateDeclaration {
        name: "MyContract".into(),
    };
    match kind {
        TypeErrorKind::DuplicateDeclaration { name } => assert_eq!(name, "MyContract"),
    }
}

#[test]
fn duplicate_declaration_kind_clones_equal() {
    let kind = TypeErrorKind::DuplicateDeclaration { name: "T".into() };
    assert_eq!(kind.clone(), kind);
}

#[test]
fn duplicate_declaration_same_names_are_equal() {
    let a = TypeErrorKind::DuplicateDeclaration { name: "X".into() };
    let b = TypeErrorKind::DuplicateDeclaration { name: "X".into() };
    assert_eq!(a, b);
}

#[test]
fn duplicate_declaration_different_names_are_not_equal() {
    let a = TypeErrorKind::DuplicateDeclaration { name: "X".into() };
    let b = TypeErrorKind::DuplicateDeclaration { name: "Y".into() };
    assert_ne!(a, b);
}
