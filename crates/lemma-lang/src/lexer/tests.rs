//! Integration tests for `lemma_lang::lexer`.
//!
//! Tests the public `tokenize()` function against full Lem contract sources
//! and individual language constructs. Covers all literal forms, comment
//! forms, annotations, operators, unit suffixes, and error cases.

use super::token::{Span, TemplateSegment, Token};
use super::tokenize;

// ── Shared fixtures ───────────────────────────────────────────────────────────

/// Minimal token contract — the canonical integration test source.
const MINIMAL_TOKEN_CONTRACT: &str = r#"
contract MyToken implements IToken {
    state {
        totalSupply: u128
        balances: Map<Address, u128>
        owner: Address
    }

    init(initialSupply: u128) {
        self.totalSupply = initialSupply
        self.balances[msg.sender] = initialSupply
        self.owner = msg.sender
    }

    @onlyOwner
    pub fn mint(to: Address, amount: u128) {
        self.totalSupply = self.totalSupply + amount
        self.balances[to] = self.balances[to] + amount
        emit Transfer { from: Address::zero(), to, amount }
    }

    pub fn transfer(to: Address, amount: u128) -> bool {
        assert(self.balances[msg.sender] >= amount, "Insufficient balance")
        self.balances[msg.sender] = self.balances[msg.sender] - amount
        self.balances[to] = self.balances[to] + amount
        emit Transfer { from: msg.sender, to, amount }
        return true
    }

    view fn balanceOf(addr: Address) -> u128 {
        return self.balances[addr]
    }
}
"#;

/// Extract just the token kinds from a token stream (discards spans).
fn kinds(tokens: &[(Token, Span)]) -> Vec<&Token> {
    tokens.iter().map(|(t, _)| t).collect()
}

/// Find the first non-Newline token in the stream.
fn first_non_newline(tokens: &[(Token, Span)]) -> Option<&Token> {
    tokens
        .iter()
        .find(|(t, _)| !matches!(t, Token::Newline))
        .map(|(t, _)| t)
}

// ── Test 1: Minimal token contract ───────────────────────────────────────────

#[test]
fn tokenize_minimal_token_contract_succeeds() {
    let tokens = tokenize(MINIMAL_TOKEN_CONTRACT).expect("should lex without error");

    // Must end with Eof
    assert_eq!(
        tokens.last().map(|(t, _)| t),
        Some(&Token::Eof),
        "last token must be Eof"
    );

    let ks = kinds(&tokens);

    // First non-newline token is Contract
    let first_kw = first_non_newline(&tokens).expect("must have tokens");
    assert!(
        matches!(first_kw, Token::Contract),
        "expected Contract, got {first_kw:?}"
    );

    // Spot-check: Contract → Identifier("MyToken") → Implements → Identifier("IToken") → LBrace
    let contract_pos = ks
        .iter()
        .position(|t| matches!(t, Token::Contract))
        .expect("Contract token must be present");
    // Skip newlines between tokens
    let non_nl: Vec<_> = ks.iter().filter(|t| !matches!(t, Token::Newline)).collect();
    let contract_idx = non_nl
        .iter()
        .position(|t| matches!(t, Token::Contract))
        .unwrap();
    assert!(
        matches!(non_nl[contract_idx + 1], Token::Identifier(s) if s == "MyToken"),
        "expected Identifier(MyToken) after Contract"
    );
    assert!(
        matches!(non_nl[contract_idx + 2], Token::Implements),
        "expected Implements"
    );
    assert!(
        matches!(non_nl[contract_idx + 3], Token::Identifier(s) if s == "IToken"),
        "expected Identifier(IToken)"
    );
    assert!(
        matches!(non_nl[contract_idx + 4], Token::LBrace),
        "expected LBrace"
    );

    // OnlyOwner annotation present
    assert!(
        ks.iter().any(|t| matches!(t, Token::OnlyOwner)),
        "OnlyOwner annotation must be present"
    );

    // U128 type keyword present
    assert!(
        ks.iter().any(|t| matches!(t, Token::U128)),
        "U128 type keyword must be present"
    );

    // State keyword present
    assert!(ks.iter().any(|t| matches!(t, Token::State)));

    // Pub keyword present
    assert!(ks.iter().any(|t| matches!(t, Token::Pub)));

    // Fn keyword present
    assert!(ks.iter().any(|t| matches!(t, Token::Fn)));

    // View keyword present
    assert!(ks.iter().any(|t| matches!(t, Token::View)));

    // Emit keyword present
    assert!(ks.iter().any(|t| matches!(t, Token::Emit)));

    // Return keyword present
    assert!(ks.iter().any(|t| matches!(t, Token::Return)));

    // Arrow (->) present
    assert!(ks.iter().any(|t| matches!(t, Token::Arrow)));

    // ColonColon (::) present (Address::zero())
    assert!(ks.iter().any(|t| matches!(t, Token::ColonColon)));

    // BoolLiteral(true) present
    assert!(ks.iter().any(|t| matches!(t, Token::BoolLiteral(true))));

    // MapTy present
    assert!(ks.iter().any(|t| matches!(t, Token::MapTy)));

    // AddressTy present
    assert!(ks.iter().any(|t| matches!(t, Token::AddressTy)));

    // No panic — stream is non-empty
    assert!(!tokens.is_empty());

    // Contract position is valid (not out of bounds)
    assert!(contract_pos < tokens.len());
}

// ── Test 2: Hex literal ───────────────────────────────────────────────────────

#[test]
fn tokenize_hex_literal_produces_hex_token() {
    let tokens = tokenize("0xDEADBEEF").unwrap();
    let ks = kinds(&tokens);
    assert!(
        ks.iter()
            .any(|t| matches!(t, Token::HexLiteral(s) if s == "DEADBEEF")),
        "expected HexLiteral(DEADBEEF), got {ks:?}"
    );
}

#[test]
fn tokenize_hex_literal_lowercase_produces_hex_token() {
    let tokens = tokenize("0xdeadbeef").unwrap();
    let ks = kinds(&tokens);
    assert!(ks
        .iter()
        .any(|t| matches!(t, Token::HexLiteral(s) if s == "deadbeef")));
}

#[test]
fn tokenize_hex_literal_with_underscores_strips_them() {
    let tokens = tokenize("0xFF_FF").unwrap();
    let ks = kinds(&tokens);
    assert!(ks
        .iter()
        .any(|t| matches!(t, Token::HexLiteral(s) if s == "FFFF")));
}

// ── Test 3: Invalid hex → lex error ──────────────────────────────────────────

#[test]
fn tokenize_invalid_hex_returns_lex_error() {
    let result = tokenize("0xinvalid");
    assert!(result.is_err(), "expected Err, got {result:?}");
    let err = result.unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("lex error"), "got: {msg}");
}

#[test]
fn tokenize_hex_no_digits_returns_lex_error() {
    let result = tokenize("0x");
    assert!(result.is_err());
}

// ── Test 4: Address literal ───────────────────────────────────────────────────

/// Generate a valid bech32m address string for the given HRP and 20-byte payload.
///
/// Used to produce test vectors at runtime so we don't hardcode checksums that
/// depend on the bech32 crate version.
fn make_bech32m_address(hrp_str: &str) -> String {
    use bech32::{Bech32m, Hrp};
    let hrp = Hrp::parse(hrp_str).expect("valid HRP");
    let data = [0u8; 20];
    bech32::encode::<Bech32m>(hrp, &data).expect("encode succeeds")
}

#[test]
fn tokenize_address_literal_produces_address_token() {
    // Generate a valid bech32m address with `lem` HRP at test time
    let addr = make_bech32m_address("lem");
    let tokens = tokenize(&addr).unwrap_or_else(|e| panic!("failed to lex '{addr}': {e}"));
    let ks = kinds(&tokens);
    assert!(
        ks.iter()
            .any(|t| matches!(t, Token::AddressLiteral(s) if s == &addr)),
        "expected AddressLiteral({addr}), got {ks:?}"
    );
}

#[test]
fn tokenize_testnet_address_literal_produces_address_token() {
    // Generate a valid bech32m address with `tlem` HRP at test time
    let addr = make_bech32m_address("tlem");
    let tokens = tokenize(&addr).unwrap_or_else(|e| panic!("failed to lex '{addr}': {e}"));
    let ks = kinds(&tokens);
    assert!(
        ks.iter()
            .any(|t| matches!(t, Token::AddressLiteral(s) if s == &addr)),
        "expected AddressLiteral({addr}), got {ks:?}"
    );
}

#[test]
fn tokenize_devnet_address_literal_produces_address_token() {
    // Generate a valid bech32m address with `dlem` HRP at test time
    let addr = make_bech32m_address("dlem");
    let tokens = tokenize(&addr).unwrap_or_else(|e| panic!("failed to lex '{addr}': {e}"));
    let ks = kinds(&tokens);
    assert!(
        ks.iter()
            .any(|t| matches!(t, Token::AddressLiteral(s) if s == &addr)),
        "expected AddressLiteral({addr}), got {ks:?}"
    );
}

#[test]
fn tokenize_invalid_address_literal_returns_lex_error() {
    // A string that starts with lem1 but has an invalid bech32m checksum
    let result = tokenize("lem1invalidchecksum");
    assert!(result.is_err(), "expected Err for invalid address");
    let err = result.unwrap_err();
    assert!(err.to_string().contains("lex error"), "got: {err}");
}

// ── Test 5: Unit suffix ───────────────────────────────────────────────────────

#[test]
fn tokenize_unit_ether_produces_int_then_unit_token() {
    let tokens = tokenize("1.ether").unwrap();
    let ks = kinds(&tokens);
    // Should have IntLiteral(1) followed by UnitEther
    let int_pos = ks
        .iter()
        .position(|t| matches!(t, Token::IntLiteral(1)))
        .expect("IntLiteral(1) must be present");
    assert!(
        matches!(ks[int_pos + 1], Token::UnitEther),
        "UnitEther must follow IntLiteral(1), got {:?}",
        ks[int_pos + 1]
    );
}

#[test]
fn tokenize_unit_gwei_produces_int_then_unit_token() {
    let tokens = tokenize("100.gwei").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::IntLiteral(100))));
    assert!(ks.iter().any(|t| matches!(t, Token::UnitGwei)));
}

#[test]
fn tokenize_unit_minutes_produces_int_then_unit_token() {
    let tokens = tokenize("30.minutes").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::UnitMinutes)));
}

#[test]
fn tokenize_unit_hours_produces_int_then_unit_token() {
    let tokens = tokenize("24.hours").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::UnitHours)));
}

#[test]
fn tokenize_unit_days_produces_int_then_unit_token() {
    let tokens = tokenize("7.days").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::UnitDays)));
}

#[test]
fn tokenize_unit_tokens_produces_unit_tokens_token() {
    let tokens = tokenize("1000.tokens").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::UnitTokens)));
}

// ── Test 6: Template string ───────────────────────────────────────────────────

#[test]
fn tokenize_template_string_produces_template_literal() {
    let tokens = tokenize(r#"`hello ${name}!`"#).unwrap();
    let ks = kinds(&tokens);
    let tmpl = ks
        .iter()
        .find(|t| matches!(t, Token::TemplateLiteral(_)))
        .expect("TemplateLiteral must be present");
    if let Token::TemplateLiteral(segs) = tmpl {
        assert_eq!(segs.len(), 3);
        assert_eq!(segs[0], TemplateSegment::Literal("hello ".to_string()));
        assert_eq!(segs[1], TemplateSegment::Interpolation("name".to_string()));
        assert_eq!(segs[2], TemplateSegment::Literal("!".to_string()));
    }
}

#[test]
fn tokenize_template_string_no_interpolation() {
    let tokens = tokenize(r#"`plain text`"#).unwrap();
    let ks = kinds(&tokens);
    let tmpl = ks
        .iter()
        .find(|t| matches!(t, Token::TemplateLiteral(_)))
        .expect("TemplateLiteral must be present");
    if let Token::TemplateLiteral(segs) = tmpl {
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0], TemplateSegment::Literal("plain text".to_string()));
    }
}

#[test]
fn tokenize_template_string_multiple_interpolations() {
    let tokens = tokenize(r#"`${a} + ${b} = ${c}`"#).unwrap();
    let ks = kinds(&tokens);
    let tmpl = ks
        .iter()
        .find(|t| matches!(t, Token::TemplateLiteral(_)))
        .expect("TemplateLiteral must be present");
    if let Token::TemplateLiteral(segs) = tmpl {
        // Segments: Interp(a), Literal(" + "), Interp(b), Literal(" = "), Interp(c)
        assert_eq!(segs.len(), 5);
    }
}

// ── Test 7: Doc comment ───────────────────────────────────────────────────────

#[test]
fn tokenize_doc_comment_produces_doc_comment_token() {
    let tokens = tokenize("/// This is a doc comment").unwrap();
    let ks = kinds(&tokens);
    assert!(
        ks.iter()
            .any(|t| matches!(t, Token::DocComment(s) if s.contains("This is a doc comment"))),
        "DocComment must be present, got {ks:?}"
    );
}

#[test]
fn tokenize_line_comment_produces_line_comment_token() {
    let tokens = tokenize("// regular comment").unwrap();
    let ks = kinds(&tokens);
    assert!(ks
        .iter()
        .any(|t| matches!(t, Token::LineComment(s) if s.contains("regular comment"))));
}

#[test]
fn tokenize_block_comment_produces_block_comment_token() {
    let tokens = tokenize("/* block */").unwrap();
    let ks = kinds(&tokens);
    assert!(ks
        .iter()
        .any(|t| matches!(t, Token::BlockComment(s) if s.contains("block"))));
}

#[test]
fn tokenize_doc_comment_before_line_comment_distinguishes_correctly() {
    // `///` must be recognized as DocComment, not LineComment
    let tokens = tokenize("/// doc\n// line").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::DocComment(_))));
    assert!(ks.iter().any(|t| matches!(t, Token::LineComment(_))));
}

// ── Test 8: All annotation variants ──────────────────────────────────────────

#[test]
fn tokenize_known_annotations_produce_correct_tokens() {
    let cases = [
        ("@onlyOwner", Token::OnlyOwner),
        ("@onlyRole", Token::OnlyRole),
        ("@whenNotPaused", Token::WhenNotPaused),
        ("@whenPaused", Token::WhenPaused),
        ("@nonReentrant", Token::NonReentrant),
        ("@cooldown", Token::Cooldown),
        ("@payable", Token::PayableAnn),
        ("@deadline", Token::Deadline),
        ("@estimateGas", Token::EstimateGas),
        ("@onTransfer", Token::OnTransfer),
        ("@indexed", Token::Indexed),
        ("@private", Token::Private),
        ("@agentCallable", Token::AgentCallable),
    ];
    for (src, expected) in &cases {
        let tokens = tokenize(src).unwrap_or_else(|e| panic!("failed to lex '{src}': {e}"));
        let ks = kinds(&tokens);
        assert!(
            ks.contains(&expected),
            "expected {expected:?} for '{src}', got {ks:?}"
        );
    }
}

// ── Test 9: Unknown annotation ────────────────────────────────────────────────

#[test]
fn tokenize_unknown_annotation_produces_annotation_catch_all() {
    let tokens = tokenize("@myCustomDecorator").unwrap();
    let ks = kinds(&tokens);
    assert!(
        ks.iter()
            .any(|t| matches!(t, Token::Annotation(s) if s == "myCustomDecorator")),
        "expected Annotation(myCustomDecorator), got {ks:?}"
    );
}

#[test]
fn tokenize_at_alone_returns_lex_error() {
    let result = tokenize("@ ");
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("lex error"), "got: {err}");
}

// ── Test 10: Span tracking ────────────────────────────────────────────────────

#[test]
fn tokenize_tracks_line_and_col_correctly() {
    let src = "contract\nFoo";
    let tokens = tokenize(src).unwrap();

    // `contract` is on line 1, col 1
    let (_, contract_span) = tokens
        .iter()
        .find(|(t, _)| matches!(t, Token::Contract))
        .expect("Contract must be present");
    assert_eq!(contract_span.line, 1, "contract must be on line 1");
    assert_eq!(contract_span.col, 1, "contract must start at col 1");
    assert_eq!(contract_span.offset, 0);
    assert_eq!(contract_span.len, "contract".len());

    // `Foo` is on line 2, col 1
    let (_, foo_span) = tokens
        .iter()
        .find(|(t, _)| matches!(t, Token::Identifier(s) if s == "Foo"))
        .expect("Identifier(Foo) must be present");
    assert_eq!(foo_span.line, 2, "Foo must be on line 2");
    assert_eq!(foo_span.col, 1, "Foo must start at col 1");
}

#[test]
fn tokenize_span_offset_is_byte_offset() {
    let src = "let x";
    let tokens = tokenize(src).unwrap();
    let (_, let_span) = tokens
        .iter()
        .find(|(t, _)| matches!(t, Token::Let))
        .unwrap();
    assert_eq!(let_span.offset, 0);
    assert_eq!(let_span.len, 3); // "let" is 3 bytes

    let (_, x_span) = tokens
        .iter()
        .find(|(t, _)| matches!(t, Token::Identifier(s) if s == "x"))
        .unwrap();
    assert_eq!(x_span.offset, 4); // "let " = 4 bytes
    assert_eq!(x_span.len, 1);
}

// ── Additional literal tests ──────────────────────────────────────────────────

#[test]
fn tokenize_binary_literal_produces_bin_token() {
    let tokens = tokenize("0b1010").unwrap();
    let ks = kinds(&tokens);
    assert!(ks
        .iter()
        .any(|t| matches!(t, Token::BinLiteral(s) if s == "1010")));
}

#[test]
fn tokenize_float_literal_produces_float_token() {
    let tokens = tokenize("3.14").unwrap();
    let ks = kinds(&tokens);
    assert!(ks
        .iter()
        .any(|t| matches!(t, Token::FloatLiteral(s) if s == "3.14")));
}

#[test]
fn tokenize_string_literal_with_escapes() {
    let tokens = tokenize(r#""hello\nworld""#).unwrap();
    let ks = kinds(&tokens);
    assert!(ks
        .iter()
        .any(|t| matches!(t, Token::StringLiteral(s) if s == "hello\nworld")));
}

#[test]
fn tokenize_bytes_literal_produces_bytes_token() {
    let tokens = tokenize(r#"b"hi""#).unwrap();
    let ks = kinds(&tokens);
    assert!(ks
        .iter()
        .any(|t| matches!(t, Token::BytesLiteral(b) if b == b"hi")));
}

#[test]
fn tokenize_char_literal_produces_char_token() {
    let tokens = tokenize("'a'").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::CharLiteral('a'))));
}

#[test]
fn tokenize_char_literal_escape_newline() {
    let tokens = tokenize(r"'\n'").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::CharLiteral('\n'))));
}

#[test]
fn tokenize_bool_true_produces_bool_literal() {
    let tokens = tokenize("true").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::BoolLiteral(true))));
}

#[test]
fn tokenize_bool_false_produces_bool_literal() {
    let tokens = tokenize("false").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t, Token::BoolLiteral(false))));
}

#[test]
fn tokenize_typed_int_literal_u128() {
    let tokens = tokenize("42u128").unwrap();
    let ks = kinds(&tokens);
    assert!(ks.iter().any(|t| matches!(t,
        Token::IntLiteralTyped { value: 42, suffix } if suffix == "u128"
    )));
}

// ── Operator and punctuation tests ───────────────────────────────────────────

#[test]
fn tokenize_all_compound_operators() {
    let cases = [
        ("->", Token::Arrow),
        ("=>", Token::FatArrow),
        ("..=", Token::DotDotEq),
        ("..", Token::DotDot),
        ("::", Token::ColonColon),
        ("==", Token::Eq),
        ("!=", Token::NotEq),
        ("<=", Token::LtEq),
        (">=", Token::GtEq),
        ("&&", Token::And),
        ("||", Token::Or),
        ("<<", Token::Shl),
        (">>", Token::Shr),
        ("+=", Token::PlusAssign),
        ("-=", Token::MinusAssign),
        ("*=", Token::StarAssign),
        ("/=", Token::SlashAssign),
        ("%=", Token::PercentAssign),
    ];
    for (src, expected) in &cases {
        let tokens = tokenize(src).unwrap_or_else(|e| panic!("failed to lex '{src}': {e}"));
        let ks = kinds(&tokens);
        assert!(
            ks.contains(&expected),
            "expected {expected:?} for '{src}', got {ks:?}"
        );
    }
}

// ── Eof span ──────────────────────────────────────────────────────────────────

#[test]
fn tokenize_eof_span_offset_equals_source_length() {
    let src = "let x";
    let tokens = tokenize(src).unwrap();
    let (_, eof_span) = tokens.last().unwrap();
    assert_eq!(eof_span.offset, src.len());
}

// ── Edge-case tests (Fix 3) ───────────────────────────────────────────────────

#[test]
fn tokenize_block_comment_does_not_nest() {
    // `/* outer /* inner */ rest */` should close at the FIRST `*/`
    // leaving ` rest */` to be tokenized as further tokens
    let src = "/* outer /* inner */ x";
    let tokens = tokenize(src).expect("should lex");
    // First non-Newline token after the comment is Identifier("x")
    let kinds: Vec<_> = tokens.iter().map(|(t, _)| t).collect();
    assert!(
        kinds.iter().any(|t| matches!(t, Token::BlockComment(_))),
        "should have block comment"
    );
    assert!(
        kinds
            .iter()
            .any(|t| matches!(t, Token::Identifier(s) if s == "x")),
        "x should be tokenized"
    );
}

#[test]
fn tokenize_three_dots_produces_dot_dot_then_dot() {
    // Lem has `..` (range) and `..=` (inclusive range) but no `...`.
    // Scanner emits `[DotDot, Dot]` — this locks in the defined behavior.
    let tokens = tokenize("...").expect("should lex");
    let kinds: Vec<_> = tokens
        .iter()
        .filter(|(t, _)| !matches!(t, Token::Eof))
        .map(|(t, _)| t)
        .collect();
    assert_eq!(kinds.len(), 2);
    assert!(matches!(kinds[0], Token::DotDot));
    assert!(matches!(kinds[1], Token::Dot));
}

#[test]
fn tokenize_float_with_unit_suffix_not_treated_as_unit() {
    // `1.5.ether` → [FloatLiteral("1.5"), Dot, Identifier("ether")]
    // Unit suffix is only emitted after INTEGER literals, not float.
    let tokens = tokenize("1.5.ether").expect("should lex");
    let kinds: Vec<_> = tokens
        .iter()
        .filter(|(t, _)| !matches!(t, Token::Eof))
        .map(|(t, _)| t)
        .collect();
    assert!(
        matches!(kinds[0], Token::FloatLiteral(_)),
        "should be float"
    );
    assert!(matches!(kinds[1], Token::Dot), "should be dot");
    assert!(
        matches!(kinds[2], Token::Identifier(_)),
        "ether is identifier after float"
    );
}

#[test]
fn tokenize_four_slashes_produces_doc_comment() {
    // `////` — the `///` prefix is matched, leaving `/` as doc comment content
    let tokens = tokenize("////").expect("should lex");
    let kinds: Vec<_> = tokens
        .iter()
        .filter(|(t, _)| !matches!(t, Token::Eof | Token::Newline))
        .map(|(t, _)| t)
        .collect();
    assert_eq!(kinds.len(), 1);
    assert!(
        matches!(kinds[0], Token::DocComment(_)),
        "four slashes = doc comment"
    );
    if let Token::DocComment(content) = kinds[0] {
        assert!(content.contains('/'), "content should have the extra slash");
    }
}

#[test]
fn tokenize_unterminated_block_comment_returns_lex_error() {
    let result = tokenize("/* not closed");
    assert!(result.is_err(), "unterminated block comment should error");
}

#[test]
fn tokenize_eof_span_has_correct_line_and_col_for_multiline_source() {
    // "a\nb" → EOF should be at line:2, col:2 (after the 'b')
    let tokens = tokenize("a\nb").expect("should lex");
    let (tok, span) = tokens.last().expect("at least Eof");
    assert!(matches!(tok, Token::Eof));
    assert_eq!(span.line, 2, "EOF line should be 2");
    assert_eq!(span.col, 2, "EOF col should be 2 (after 'b')");
    assert_eq!(span.offset, 3, "EOF offset should be source.len()");
}
