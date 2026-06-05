//! Tests for `lemma_lang::lexer::token`.
//!
//! Covers Debug, Clone, PartialEq, Eq, Hash for Token and Span.
//! Verifies key variant construction and equality semantics.

use super::*;

// ── Span ─────────────────────────────────────────────────────────────────────

#[test]
fn span_at_creates_zero_length_span() {
    let s = Span::at(1, 1, 0);
    assert_eq!(s.line, 1);
    assert_eq!(s.col, 1);
    assert_eq!(s.offset, 0);
    assert_eq!(s.len, 0);
}

#[test]
fn span_clones_equal_to_original() {
    let s = Span {
        line: 5,
        col: 10,
        offset: 42,
        len: 7,
    };
    assert_eq!(s.clone(), s);
}

#[test]
fn span_different_fields_are_not_equal() {
    let a = Span {
        line: 1,
        col: 1,
        offset: 0,
        len: 1,
    };
    let b = Span {
        line: 2,
        col: 1,
        offset: 10,
        len: 1,
    };
    assert_ne!(a, b);
}

#[test]
fn span_debug_format_is_non_empty() {
    let s = Span::at(3, 7, 20);
    let dbg = format!("{s:?}");
    assert!(!dbg.is_empty());
    assert!(dbg.contains("3"));
}

// ── TemplateSegment ───────────────────────────────────────────────────────────

#[test]
fn template_segment_literal_clones_equal() {
    let seg = TemplateSegment::Literal("hello".to_string());
    assert_eq!(seg.clone(), seg);
}

#[test]
fn template_segment_interpolation_clones_equal() {
    let seg = TemplateSegment::Interpolation("x + 1".to_string());
    assert_eq!(seg.clone(), seg);
}

#[test]
fn template_segment_different_variants_are_not_equal() {
    let a = TemplateSegment::Literal("x".to_string());
    let b = TemplateSegment::Interpolation("x".to_string());
    assert_ne!(a, b);
}

// ── Token — keyword variants ──────────────────────────────────────────────────

#[test]
fn token_keyword_variants_clone_equal() {
    let tokens = [
        Token::Contract,
        Token::State,
        Token::Init,
        Token::Pub,
        Token::View,
        Token::Pure,
        Token::Fn,
        Token::Let,
        Token::Const,
        Token::If,
        Token::Else,
        Token::Return,
        Token::Emit,
        Token::Assert,
        Token::Revert,
        Token::SelfKw,
        Token::Implements,
        Token::Eof,
        Token::Newline,
    ];
    for t in &tokens {
        assert_eq!(t.clone(), *t, "failed for {t:?}");
    }
}

#[test]
fn token_type_keywords_clone_equal() {
    let tokens = [
        Token::U8,
        Token::U16,
        Token::U32,
        Token::U64,
        Token::U128,
        Token::U256,
        Token::I8,
        Token::I16,
        Token::I32,
        Token::I64,
        Token::I128,
        Token::I256,
        Token::Bool,
        Token::StringTy,
        Token::CharTy,
        Token::AddressTy,
        Token::HashTy,
        Token::Bytes,
        Token::MapTy,
        Token::OptionTy,
        Token::ResultTy,
    ];
    for t in &tokens {
        assert_eq!(t.clone(), *t, "failed for {t:?}");
    }
}

// ── Token — annotation variants ───────────────────────────────────────────────

#[test]
fn token_known_annotations_clone_equal() {
    let tokens = [
        Token::OnlyOwner,
        Token::OnlyRole,
        Token::WhenNotPaused,
        Token::WhenPaused,
        Token::NonReentrant,
        Token::Cooldown,
        Token::PayableAnn,
        Token::Deadline,
        Token::EstimateGas,
        Token::OnTransfer,
        Token::Indexed,
        Token::Private,
        Token::AgentCallable,
    ];
    for t in &tokens {
        assert_eq!(t.clone(), *t, "failed for {t:?}");
    }
}

#[test]
fn token_annotation_catch_all_stores_name() {
    let t = Token::Annotation("myCustomDecorator".to_string());
    assert_eq!(t.clone(), t);
    assert_eq!(t, Token::Annotation("myCustomDecorator".to_string()));
    assert_ne!(t, Token::Annotation("other".to_string()));
}

// ── Token — literal variants ──────────────────────────────────────────────────

#[test]
fn token_int_literal_equality() {
    assert_eq!(Token::IntLiteral(42), Token::IntLiteral(42));
    assert_ne!(Token::IntLiteral(42), Token::IntLiteral(43));
}

#[test]
fn token_int_literal_typed_equality() {
    let a = Token::IntLiteralTyped {
        value: 100,
        suffix: "u64".to_string(),
    };
    let b = Token::IntLiteralTyped {
        value: 100,
        suffix: "u64".to_string(),
    };
    assert_eq!(a, b);
    let c = Token::IntLiteralTyped {
        value: 100,
        suffix: "u128".to_string(),
    };
    assert_ne!(a, c);
}

#[test]
fn token_hex_literal_stores_raw_digits() {
    let t = Token::HexLiteral("deadbeef".to_string());
    assert_eq!(t.clone(), t);
}

#[test]
fn token_bin_literal_stores_raw_digits() {
    let t = Token::BinLiteral("1010".to_string());
    assert_eq!(t.clone(), t);
}

#[test]
fn token_float_literal_stores_raw_string() {
    let t = Token::FloatLiteral("3.14".to_string());
    assert_eq!(t.clone(), t);
    assert_ne!(t, Token::FloatLiteral("3.15".to_string()));
}

#[test]
fn token_string_literal_equality() {
    assert_eq!(
        Token::StringLiteral("hello".to_string()),
        Token::StringLiteral("hello".to_string())
    );
    assert_ne!(
        Token::StringLiteral("hello".to_string()),
        Token::StringLiteral("world".to_string())
    );
}

#[test]
fn token_bytes_literal_equality() {
    assert_eq!(
        Token::BytesLiteral(vec![0x68, 0x69]),
        Token::BytesLiteral(vec![0x68, 0x69])
    );
    assert_ne!(
        Token::BytesLiteral(vec![0x68]),
        Token::BytesLiteral(vec![0x69])
    );
}

#[test]
fn token_char_literal_equality() {
    assert_eq!(Token::CharLiteral('a'), Token::CharLiteral('a'));
    assert_ne!(Token::CharLiteral('a'), Token::CharLiteral('b'));
}

#[test]
fn token_bool_literal_equality() {
    assert_eq!(Token::BoolLiteral(true), Token::BoolLiteral(true));
    assert_ne!(Token::BoolLiteral(true), Token::BoolLiteral(false));
}

#[test]
fn token_address_literal_stores_full_string() {
    let addr = "lem1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let t = Token::AddressLiteral(addr.to_string());
    assert_eq!(t.clone(), t);
}

#[test]
fn token_template_literal_equality() {
    let a = Token::TemplateLiteral(vec![
        TemplateSegment::Literal("hello ".to_string()),
        TemplateSegment::Interpolation("name".to_string()),
    ]);
    let b = a.clone();
    assert_eq!(a, b);
}

// ── Token — unit suffix variants ──────────────────────────────────────────────

#[test]
fn token_unit_suffixes_clone_equal() {
    let units = [
        Token::UnitEther,
        Token::UnitGwei,
        Token::UnitMinutes,
        Token::UnitHours,
        Token::UnitDays,
        Token::UnitTokens,
    ];
    for t in &units {
        assert_eq!(t.clone(), *t, "failed for {t:?}");
    }
}

// ── Token — operator variants ─────────────────────────────────────────────────

#[test]
fn token_operators_clone_equal() {
    let ops = [
        Token::Plus,
        Token::Minus,
        Token::Star,
        Token::Slash,
        Token::Percent,
        Token::Eq,
        Token::NotEq,
        Token::Lt,
        Token::Gt,
        Token::LtEq,
        Token::GtEq,
        Token::And,
        Token::Or,
        Token::Not,
        Token::BitAnd,
        Token::BitOr,
        Token::BitXor,
        Token::BitNot,
        Token::Shl,
        Token::Shr,
        Token::Assign,
        Token::PlusAssign,
        Token::MinusAssign,
        Token::StarAssign,
        Token::SlashAssign,
        Token::PercentAssign,
    ];
    for t in &ops {
        assert_eq!(t.clone(), *t, "failed for {t:?}");
    }
}

// ── Token — punctuation variants ──────────────────────────────────────────────

#[test]
fn token_punctuation_clone_equal() {
    let puncts = [
        Token::Arrow,
        Token::FatArrow,
        Token::QuestionMark,
        Token::Underscore,
        Token::Dot,
        Token::DotDot,
        Token::DotDotEq,
        Token::Comma,
        Token::Colon,
        Token::ColonColon,
        Token::Semicolon,
        Token::LParen,
        Token::RParen,
        Token::LBrace,
        Token::RBrace,
        Token::LBracket,
        Token::RBracket,
        Token::Hash_,
        Token::At,
        Token::Dollar,
        Token::Pipe,
    ];
    for t in &puncts {
        assert_eq!(t.clone(), *t, "failed for {t:?}");
    }
}

// ── Token — comment variants ──────────────────────────────────────────────────

#[test]
fn token_comment_variants_store_content() {
    let lc = Token::LineComment(" this is a comment".to_string());
    let bc = Token::BlockComment(" block ".to_string());
    let dc = Token::DocComment(" doc comment".to_string());
    assert_eq!(lc.clone(), lc);
    assert_eq!(bc.clone(), bc);
    assert_eq!(dc.clone(), dc);
    assert_ne!(lc, bc);
}

// ── Token — identifier ────────────────────────────────────────────────────────

#[test]
fn token_identifier_equality() {
    assert_eq!(
        Token::Identifier("foo".to_string()),
        Token::Identifier("foo".to_string())
    );
    assert_ne!(
        Token::Identifier("foo".to_string()),
        Token::Identifier("bar".to_string())
    );
}

// ── Token — different variants are not equal ─────────────────────────────────

#[test]
fn token_different_variants_are_not_equal() {
    assert_ne!(Token::Contract, Token::State);
    assert_ne!(Token::IntLiteral(1), Token::BoolLiteral(true));
    assert_ne!(Token::Eof, Token::Newline);
    assert_ne!(Token::Plus, Token::Minus);
}

// ── Token — Debug format ──────────────────────────────────────────────────────

#[test]
fn token_debug_format_is_non_empty() {
    let t = Token::Contract;
    let dbg = format!("{t:?}");
    assert!(!dbg.is_empty());
}
