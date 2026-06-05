//! Unit tests for `lemma_lang::lexer::scanner`.
//!
//! Tests scanner internals: character advancement, span tracking,
//! individual scan methods, and edge cases.

use super::*;
use crate::lexer::token::Token;

/// Build a Mark at position 0, line 1, col 1 — the initial scanner state.
/// Used by tests that call scan_number directly on a freshly-created scanner.
fn mark_start() -> Mark {
    Mark {
        offset: 0,
        line: 1,
        col: 1,
    }
}

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn scanner(src: &str) -> Scanner<'_> {
    Scanner::new(src)
}

// ── Basic scanner state ───────────────────────────────────────────────────────

#[test]
fn scanner_new_starts_at_beginning() {
    let s = scanner("hello");
    assert!(!s.is_at_end());
}

#[test]
fn scanner_empty_source_is_at_end() {
    let s = scanner("");
    assert!(s.is_at_end());
}

#[test]
fn scanner_advances_through_all_chars() {
    let mut s = scanner("abc");
    assert_eq!(s.peek(), Some('a'));
    s.advance();
    assert_eq!(s.peek(), Some('b'));
    s.advance();
    assert_eq!(s.peek(), Some('c'));
    s.advance();
    assert!(s.is_at_end());
}

#[test]
fn scanner_peek_does_not_advance() {
    let mut s = scanner("xy");
    assert_eq!(s.peek(), Some('x'));
    assert_eq!(s.peek(), Some('x')); // still 'x'
    s.advance();
    assert_eq!(s.peek(), Some('y'));
}

#[test]
fn scanner_peek_next_returns_second_char() {
    let s = scanner("ab");
    assert_eq!(s.peek_next(), Some('b'));
}

#[test]
fn scanner_peek_next_returns_none_at_end() {
    let s = scanner("a");
    assert_eq!(s.peek_next(), None);
}

// ── Line/col tracking ─────────────────────────────────────────────────────────

#[test]
fn scanner_tracks_line_on_newline() {
    let mut s = scanner("a\nb");
    s.advance(); // 'a'
    assert_eq!(s.line, 1);
    s.advance(); // '\n'
    assert_eq!(s.line, 2);
    assert_eq!(s.col, 1);
}

#[test]
fn scanner_tracks_col_within_line() {
    let mut s = scanner("abc");
    assert_eq!(s.col, 1);
    s.advance(); // 'a'
    assert_eq!(s.col, 2);
    s.advance(); // 'b'
    assert_eq!(s.col, 3);
}

#[test]
fn scanner_resets_col_after_newline() {
    let mut s = scanner("ab\ncd");
    s.advance(); // 'a'
    s.advance(); // 'b'
    s.advance(); // '\n'
    assert_eq!(s.col, 1);
    s.advance(); // 'c'
    assert_eq!(s.col, 2);
}

// ── Hex literal scanning ──────────────────────────────────────────────────────

#[test]
fn scan_hex_produces_hex_literal_without_prefix() {
    let mut s = scanner("0xDEAD");
    let result = s.scan_number(mark_start());
    assert!(result.is_ok(), "expected Ok, got {result:?}");
    let (tok, _) = result.unwrap();
    assert_eq!(tok, Token::HexLiteral("DEAD".to_string()));
}

#[test]
fn scan_hex_strips_underscores() {
    let mut s = scanner("0xFF_FF");
    let (tok, _) = s.scan_number(mark_start()).unwrap();
    assert_eq!(tok, Token::HexLiteral("FFFF".to_string()));
}

#[test]
fn scan_hex_no_digits_returns_error() {
    let mut s = scanner("0x");
    let result = s.scan_number(mark_start());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("no digits after '0x'"),
        "got: {err}"
    );
}

#[test]
fn scan_hex_invalid_chars_returns_error() {
    let mut s = scanner("0xinvalid");
    let result = s.scan_number(mark_start());
    assert!(result.is_err());
}

// ── Binary literal scanning ───────────────────────────────────────────────────

#[test]
fn scan_binary_produces_bin_literal() {
    let mut s = scanner("0b1010");
    let (tok, _) = s.scan_number(mark_start()).unwrap();
    assert_eq!(tok, Token::BinLiteral("1010".to_string()));
}

#[test]
fn scan_binary_strips_underscores() {
    let mut s = scanner("0b1010_1010");
    let (tok, _) = s.scan_number(mark_start()).unwrap();
    assert_eq!(tok, Token::BinLiteral("10101010".to_string()));
}

#[test]
fn scan_binary_no_digits_returns_error() {
    let mut s = scanner("0b");
    let result = s.scan_number(mark_start());
    assert!(result.is_err());
}

#[test]
fn scan_binary_non_binary_digit_returns_error() {
    let mut s = scanner("0b102");
    let result = s.scan_number(mark_start());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("not 0 or 1"), "got: {err}");
}

// ── Decimal integer scanning ──────────────────────────────────────────────────

#[test]
fn scan_decimal_produces_int_literal() {
    let mut s = scanner("42");
    let (tok, _) = s.scan_number(mark_start()).unwrap();
    assert_eq!(tok, Token::IntLiteral(42));
}

#[test]
fn scan_decimal_with_underscores() {
    let mut s = scanner("1_000_000");
    let (tok, _) = s.scan_number(mark_start()).unwrap();
    assert_eq!(tok, Token::IntLiteral(1_000_000));
}

#[test]
fn scan_decimal_typed_suffix_u128() {
    let mut s = scanner("100u128");
    let (tok, _) = s.scan_number(mark_start()).unwrap();
    assert_eq!(
        tok,
        Token::IntLiteralTyped {
            value: 100,
            suffix: "u128".to_string()
        }
    );
}

#[test]
fn scan_decimal_typed_suffix_i64() {
    let mut s = scanner("99i64");
    let (tok, _) = s.scan_number(mark_start()).unwrap();
    assert_eq!(
        tok,
        Token::IntLiteralTyped {
            value: 99,
            suffix: "i64".to_string()
        }
    );
}

#[test]
fn scan_float_produces_float_literal() {
    let mut s = scanner("3.14");
    let (tok, _) = s.scan_number(mark_start()).unwrap();
    assert_eq!(tok, Token::FloatLiteral("3.14".to_string()));
}

#[test]
fn scan_int_before_unit_suffix_returns_int_literal() {
    // `1.ether` — the `.ether` is a unit suffix, not a float
    let mut s = scanner("1.ether");
    let (tok, _) = s.scan_number(mark_start()).unwrap();
    assert_eq!(tok, Token::IntLiteral(1));
    // Scanner should be positioned at `.ether`
    assert_eq!(s.peek(), Some('.'));
}

// ── Unit suffix scanning ──────────────────────────────────────────────────────

#[test]
fn try_scan_unit_suffix_ether_returns_unit_token() {
    let mut s = scanner(".ether");
    let result = s.try_scan_unit_suffix();
    assert!(result.is_some());
    let (tok, _) = result.unwrap();
    assert_eq!(tok, Token::UnitEther);
}

#[test]
fn try_scan_unit_suffix_gwei_returns_unit_token() {
    let mut s = scanner(".gwei");
    let (tok, _) = s.try_scan_unit_suffix().unwrap();
    assert_eq!(tok, Token::UnitGwei);
}

#[test]
fn try_scan_unit_suffix_minutes_returns_unit_token() {
    let mut s = scanner(".minutes");
    let (tok, _) = s.try_scan_unit_suffix().unwrap();
    assert_eq!(tok, Token::UnitMinutes);
}

#[test]
fn try_scan_unit_suffix_hours_returns_unit_token() {
    let mut s = scanner(".hours");
    let (tok, _) = s.try_scan_unit_suffix().unwrap();
    assert_eq!(tok, Token::UnitHours);
}

#[test]
fn try_scan_unit_suffix_days_returns_unit_token() {
    let mut s = scanner(".days");
    let (tok, _) = s.try_scan_unit_suffix().unwrap();
    assert_eq!(tok, Token::UnitDays);
}

#[test]
fn try_scan_unit_suffix_tokens_returns_unit_token() {
    let mut s = scanner(".tokens");
    let (tok, _) = s.try_scan_unit_suffix().unwrap();
    assert_eq!(tok, Token::UnitTokens);
}

#[test]
fn try_scan_unit_suffix_unknown_returns_none() {
    let mut s = scanner(".foo");
    assert!(s.try_scan_unit_suffix().is_none());
}

#[test]
fn try_scan_unit_suffix_no_dot_returns_none() {
    let mut s = scanner("ether");
    assert!(s.try_scan_unit_suffix().is_none());
}

// ── Annotation scanning ───────────────────────────────────────────────────────

#[test]
fn scan_annotation_only_owner_returns_correct_token() {
    let mut s = scanner("@onlyOwner");
    let result = s.next_token();
    assert!(result.is_some());
    let (tok, _) = result.unwrap().unwrap();
    assert_eq!(tok, Token::OnlyOwner);
}

#[test]
fn scan_annotation_unknown_returns_catch_all() {
    let mut s = scanner("@myCustomDecorator");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::Annotation("myCustomDecorator".to_string()));
}

#[test]
fn scan_annotation_at_alone_returns_error() {
    let mut s = scanner("@ ");
    let result = s.next_token().unwrap();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string()
            .contains("'@' must be followed by an identifier"),
        "got: {err}"
    );
}

// ── Keyword mapping ───────────────────────────────────────────────────────────

#[test]
fn scan_identifier_contract_returns_contract_token() {
    let mut s = scanner("contract");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::Contract);
}

#[test]
fn scan_identifier_true_returns_bool_literal() {
    let mut s = scanner("true");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::BoolLiteral(true));
}

#[test]
fn scan_identifier_false_returns_bool_literal() {
    let mut s = scanner("false");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::BoolLiteral(false));
}

#[test]
fn scan_identifier_unknown_returns_identifier_token() {
    let mut s = scanner("myVar");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::Identifier("myVar".to_string()));
}

// ── Operator scanning ─────────────────────────────────────────────────────────

#[test]
fn scan_arrow_returns_arrow_token() {
    let mut s = scanner("->");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::Arrow);
}

#[test]
fn scan_fat_arrow_returns_fat_arrow_token() {
    let mut s = scanner("=>");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::FatArrow);
}

#[test]
fn scan_dot_dot_eq_returns_dot_dot_eq_token() {
    let mut s = scanner("..=");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::DotDotEq);
}

#[test]
fn scan_dot_dot_returns_dot_dot_token() {
    let mut s = scanner("..");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::DotDot);
}

#[test]
fn scan_colon_colon_returns_colon_colon_token() {
    let mut s = scanner("::");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::ColonColon);
}

#[test]
fn scan_eq_eq_returns_eq_token() {
    let mut s = scanner("==");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::Eq);
}

#[test]
fn scan_not_eq_returns_not_eq_token() {
    let mut s = scanner("!=");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::NotEq);
}

#[test]
fn scan_and_and_returns_and_token() {
    let mut s = scanner("&&");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::And);
}

#[test]
fn scan_or_or_returns_or_token() {
    let mut s = scanner("||");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::Or);
}

#[test]
fn scan_shl_returns_shl_token() {
    let mut s = scanner("<<");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::Shl);
}

#[test]
fn scan_shr_returns_shr_token() {
    let mut s = scanner(">>");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::Shr);
}

#[test]
fn scan_plus_assign_returns_plus_assign_token() {
    let mut s = scanner("+=");
    let (tok, _) = s.next_token().unwrap().unwrap();
    assert_eq!(tok, Token::PlusAssign);
}

// ── Unknown character ─────────────────────────────────────────────────────────

#[test]
fn scan_unknown_char_returns_lex_error() {
    let mut s = scanner("§");
    let result = s.next_token().unwrap();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("unexpected character"),
        "got: {err}"
    );
}
