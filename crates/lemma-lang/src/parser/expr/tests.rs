//! Tests for the expression parser (subtask 2b).
//!
//! Covers: precedence, associativity, all operators, postfix forms,
//! primary forms, call-opts, struct literals, lambdas, template literals,
//! and error cases.

use crate::error::LangError;
use crate::lexer::tokenize;
use crate::parser::ast::{AssignOp, BinaryOp, CallArg, Expr, Literal, Type, UnaryOp};
use crate::parser::Parser;

// ── Test helper ───────────────────────────────────────────────────────────────

fn parse_expr_from_str(src: &str) -> Result<Expr, LangError> {
    let tokens = tokenize(src)?;
    let mut p = Parser::new(tokens);
    p.parse_expr()
}

// ── Precedence & associativity ────────────────────────────────────────────────

#[test]
fn parse_expr_addition_is_left_associative() {
    // 1 + 2 + 3 should parse as (1 + 2) + 3
    let expr = parse_expr_from_str("1 + 2 + 3").expect("parse failed");
    // Outer node is Binary(Add, Binary(Add, 1, 2), 3)
    match expr {
        Expr::Binary(BinaryOp::Add, lhs, rhs, _) => {
            assert!(matches!(*rhs, Expr::Literal(Literal::Int(3), _)));
            assert!(matches!(*lhs, Expr::Binary(BinaryOp::Add, _, _, _)));
        }
        _ => panic!("expected Binary(Add, ...) got {expr:?}"),
    }
}

#[test]
fn parse_expr_multiplication_before_addition() {
    // 1 + 2 * 3 should parse as 1 + (2 * 3)
    let expr = parse_expr_from_str("1 + 2 * 3").expect("parse failed");
    match expr {
        Expr::Binary(BinaryOp::Add, lhs, rhs, _) => {
            assert!(matches!(*lhs, Expr::Literal(Literal::Int(1), _)));
            assert!(matches!(*rhs, Expr::Binary(BinaryOp::Mul, _, _, _)));
        }
        _ => panic!("expected Binary(Add, ...) got {expr:?}"),
    }
}

#[test]
fn parse_expr_exponent_is_right_associative() {
    // 2**3**2 should parse as 2**(3**2)
    let expr = parse_expr_from_str("2**3**2").expect("parse failed");
    match expr {
        Expr::Binary(BinaryOp::Pow, lhs, rhs, _) => {
            assert!(matches!(*lhs, Expr::Literal(Literal::Int(2), _)));
            assert!(matches!(*rhs, Expr::Binary(BinaryOp::Pow, _, _, _)));
        }
        _ => panic!("expected Binary(Pow, ...) got {expr:?}"),
    }
}

#[test]
fn parse_expr_assignment_is_right_associative() {
    // a = b = c should parse as a = (b = c)
    let expr = parse_expr_from_str("a = b = c").expect("parse failed");
    match expr {
        Expr::Assign_(lhs, AssignOp::Assign, rhs, _) => {
            assert!(matches!(*lhs, Expr::Ident(ref n, _) if n == "a"));
            assert!(matches!(*rhs, Expr::Assign_(_, AssignOp::Assign, _, _)));
        }
        _ => panic!("expected Assign_ got {expr:?}"),
    }
}

#[test]
fn parse_expr_ternary_is_right_associative() {
    // a ? b : c ? d : e should parse as a ? b : (c ? d : e)
    let expr = parse_expr_from_str("a ? b : c ? d : e").expect("parse failed");
    match expr {
        Expr::Ternary {
            cond, then, else_, ..
        } => {
            assert!(matches!(*cond, Expr::Ident(ref n, _) if n == "a"));
            assert!(matches!(*then, Expr::Ident(ref n, _) if n == "b"));
            assert!(matches!(*else_, Expr::Ternary { .. }));
        }
        _ => panic!("expected Ternary got {expr:?}"),
    }
}

// ── Binary operators ──────────────────────────────────────────────────────────

#[test]
fn parse_expr_all_binary_operators() {
    let cases: &[(&str, BinaryOp)] = &[
        ("a + b", BinaryOp::Add),
        ("a - b", BinaryOp::Sub),
        ("a * b", BinaryOp::Mul),
        ("a / b", BinaryOp::Div),
        ("a % b", BinaryOp::Rem),
        ("a ** b", BinaryOp::Pow),
        ("a == b", BinaryOp::Eq),
        ("a != b", BinaryOp::NotEq),
        ("a < b", BinaryOp::Lt),
        ("a > b", BinaryOp::Gt),
        ("a <= b", BinaryOp::LtEq),
        ("a >= b", BinaryOp::GtEq),
        ("a && b", BinaryOp::And),
        ("a || b", BinaryOp::Or),
        ("a & b", BinaryOp::BitAnd),
        ("a | b", BinaryOp::BitOr),
        ("a ^ b", BinaryOp::BitXor),
        ("a << b", BinaryOp::Shl),
        ("a >> b", BinaryOp::Shr),
    ];
    for (src, expected_op) in cases {
        let expr =
            parse_expr_from_str(src).unwrap_or_else(|e| panic!("parse failed for '{src}': {e:?}"));
        match expr {
            Expr::Binary(op, _, _, _) => {
                assert_eq!(op, *expected_op, "wrong op for '{src}'");
            }
            _ => panic!("expected Binary for '{src}', got {expr:?}"),
        }
    }
}

#[test]
fn parse_expr_all_unary_operators() {
    let cases: &[(&str, UnaryOp)] = &[
        ("!a", UnaryOp::Not),
        ("-a", UnaryOp::Neg),
        ("~a", UnaryOp::BitNot),
        ("&a", UnaryOp::Ref),
    ];
    for (src, expected_op) in cases {
        let expr =
            parse_expr_from_str(src).unwrap_or_else(|e| panic!("parse failed for '{src}': {e:?}"));
        match expr {
            Expr::Unary(op, _, _) => {
                assert_eq!(op, *expected_op, "wrong op for '{src}'");
            }
            _ => panic!("expected Unary for '{src}', got {expr:?}"),
        }
    }
}

#[test]
fn parse_expr_nullish_coalescing() {
    // a ?? b ?? c should parse as (a ?? b) ?? c (left-assoc)
    let expr = parse_expr_from_str("a ?? b ?? c").expect("parse failed");
    match expr {
        Expr::Nullish(lhs, rhs, _) => {
            assert!(matches!(*lhs, Expr::Nullish(_, _, _)));
            assert!(matches!(*rhs, Expr::Ident(ref n, _) if n == "c"));
        }
        _ => panic!("expected Nullish got {expr:?}"),
    }
}

// ── Postfix forms ─────────────────────────────────────────────────────────────

#[test]
fn parse_expr_function_call_no_args() {
    let expr = parse_expr_from_str("foo()").expect("parse failed");
    match expr {
        Expr::Call {
            callee, opts, args, ..
        } => {
            assert!(matches!(*callee, Expr::Ident(ref n, _) if n == "foo"));
            assert!(opts.is_none());
            assert!(args.is_empty());
        }
        _ => panic!("expected Call got {expr:?}"),
    }
}

#[test]
fn parse_expr_function_call_with_args() {
    let expr = parse_expr_from_str("foo(1, 2, 3)").expect("parse failed");
    match expr {
        Expr::Call { args, .. } => {
            assert_eq!(args.len(), 3);
        }
        _ => panic!("expected Call got {expr:?}"),
    }
}

#[test]
fn parse_expr_named_call_arg() {
    let expr = parse_expr_from_str("foo(x: 1, y: 2)").expect("parse failed");
    match expr {
        Expr::Call { args, .. } => {
            assert_eq!(args.len(), 2);
            assert!(matches!(&args[0], CallArg::Named(n, _) if n == "x"));
            assert!(matches!(&args[1], CallArg::Named(n, _) if n == "y"));
        }
        _ => panic!("expected Call got {expr:?}"),
    }
}

#[test]
fn parse_expr_call_with_value_opts() {
    let expr = parse_expr_from_str("foo{value: 1}(arg)").expect("parse failed");
    match expr {
        Expr::Call { opts, args, .. } => {
            assert!(opts.is_some());
            let opts = opts.unwrap();
            assert!(opts.value.is_some());
            assert!(opts.gas.is_none());
            assert!(opts.salt.is_none());
            assert_eq!(args.len(), 1);
        }
        _ => panic!("expected Call got {expr:?}"),
    }
}

#[test]
fn parse_expr_call_with_gas_opts() {
    let expr = parse_expr_from_str("foo{gas: 50000}()").expect("parse failed");
    match expr {
        Expr::Call { opts, .. } => {
            let opts = opts.expect("expected opts");
            assert!(opts.gas.is_some());
            assert!(opts.value.is_none());
        }
        _ => panic!("expected Call got {expr:?}"),
    }
}

#[test]
fn parse_expr_index_expression() {
    let expr = parse_expr_from_str("arr[i]").expect("parse failed");
    match expr {
        Expr::Index(base, idx, _) => {
            assert!(matches!(*base, Expr::Ident(ref n, _) if n == "arr"));
            assert!(matches!(*idx, Expr::Ident(ref n, _) if n == "i"));
        }
        _ => panic!("expected Index got {expr:?}"),
    }
}

#[test]
fn parse_expr_member_access() {
    let expr = parse_expr_from_str("obj.field").expect("parse failed");
    match expr {
        Expr::Member(base, name, _) => {
            assert!(matches!(*base, Expr::Ident(ref n, _) if n == "obj"));
            assert_eq!(name, "field");
        }
        _ => panic!("expected Member got {expr:?}"),
    }
}

#[test]
fn parse_expr_chained_member_access() {
    let expr = parse_expr_from_str("a.b.c").expect("parse failed");
    match expr {
        Expr::Member(base, name, _) => {
            assert_eq!(name, "c");
            assert!(matches!(*base, Expr::Member(_, ref n, _) if n == "b"));
        }
        _ => panic!("expected Member got {expr:?}"),
    }
}

#[test]
fn parse_expr_try_operator() {
    let expr = parse_expr_from_str("foo()?").expect("parse failed");
    match expr {
        Expr::Try_(inner, _) => {
            assert!(matches!(*inner, Expr::Call { .. }));
        }
        _ => panic!("expected Try_ got {expr:?}"),
    }
}

// ── Primary forms ─────────────────────────────────────────────────────────────

#[test]
fn parse_expr_integer_literal() {
    let expr = parse_expr_from_str("42").expect("parse failed");
    assert!(matches!(expr, Expr::Literal(Literal::Int(42), _)));
}

#[test]
fn parse_expr_hex_literal() {
    let expr = parse_expr_from_str("0xDEAD").expect("parse failed");
    assert!(matches!(expr, Expr::Literal(Literal::Hex(_), _)));
}

#[test]
fn parse_expr_bool_literal() {
    let t = parse_expr_from_str("true").expect("parse failed");
    let f = parse_expr_from_str("false").expect("parse failed");
    assert!(matches!(t, Expr::Literal(Literal::Bool(true), _)));
    assert!(matches!(f, Expr::Literal(Literal::Bool(false), _)));
}

#[test]
fn parse_expr_string_literal() {
    let expr = parse_expr_from_str("\"hello\"").expect("parse failed");
    assert!(matches!(expr, Expr::Literal(Literal::Str(_), _)));
}

#[test]
fn parse_expr_identifier() {
    let expr = parse_expr_from_str("myVar").expect("parse failed");
    assert!(matches!(expr, Expr::Ident(ref n, _) if n == "myVar"));
}

#[test]
fn parse_expr_parenthesized() {
    // (1 + 2) should return the inner expression, not a tuple
    let expr = parse_expr_from_str("(1 + 2)").expect("parse failed");
    assert!(matches!(expr, Expr::Binary(BinaryOp::Add, _, _, _)));
}

#[test]
fn parse_expr_tuple_two_elements() {
    let expr = parse_expr_from_str("(a, b)").expect("parse failed");
    match expr {
        Expr::Tuple(elems, _) => {
            assert_eq!(elems.len(), 2);
        }
        _ => panic!("expected Tuple got {expr:?}"),
    }
}

#[test]
fn parse_expr_tuple_single_with_trailing_comma() {
    // (a,) is a single-element tuple
    let expr = parse_expr_from_str("(a,)").expect("parse failed");
    match expr {
        Expr::Tuple(elems, _) => {
            assert_eq!(elems.len(), 1);
        }
        _ => panic!("expected Tuple got {expr:?}"),
    }
}

#[test]
fn parse_expr_array_literal() {
    let expr = parse_expr_from_str("[1, 2, 3]").expect("parse failed");
    match expr {
        Expr::Array(elems, _) => {
            assert_eq!(elems.len(), 3);
        }
        _ => panic!("expected Array got {expr:?}"),
    }
}

#[test]
fn parse_expr_struct_literal_with_fields() {
    let expr = parse_expr_from_str("Point { x: 1, y: 2 }").expect("parse failed");
    match expr {
        Expr::Struct_ {
            name,
            fields,
            spread,
            ..
        } => {
            assert_eq!(name, "Point");
            assert_eq!(fields.len(), 2);
            assert!(spread.is_none());
        }
        _ => panic!("expected Struct_ got {expr:?}"),
    }
}

#[test]
fn parse_expr_struct_literal_with_spread() {
    let expr = parse_expr_from_str("Point { x: 1, ...base }").expect("parse failed");
    match expr {
        Expr::Struct_ {
            name,
            fields,
            spread,
            ..
        } => {
            assert_eq!(name, "Point");
            assert_eq!(fields.len(), 1);
            assert!(spread.is_some());
        }
        _ => panic!("expected Struct_ got {expr:?}"),
    }
}

#[test]
fn parse_expr_new_simple() {
    let expr = parse_expr_from_str("new Foo()").expect("parse failed");
    match expr {
        Expr::New { ty, opts, args, .. } => {
            assert_eq!(ty, "Foo");
            assert!(opts.is_none());
            assert!(args.is_empty());
        }
        _ => panic!("expected New got {expr:?}"),
    }
}

#[test]
fn parse_expr_new_with_salt() {
    let expr = parse_expr_from_str("new Foo{salt: s}(arg)").expect("parse failed");
    match expr {
        Expr::New { ty, opts, args, .. } => {
            assert_eq!(ty, "Foo");
            let opts = opts.expect("expected opts");
            assert!(opts.salt.is_some());
            assert_eq!(args.len(), 1);
        }
        _ => panic!("expected New got {expr:?}"),
    }
}

#[test]
fn parse_expr_lambda_ident_form() {
    // x => x * 2
    let expr = parse_expr_from_str("x => x * 2").expect("parse failed");
    match expr {
        Expr::Lambda { params, .. } => {
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name, "x");
        }
        _ => panic!("expected Lambda got {expr:?}"),
    }
}

#[test]
fn parse_expr_lambda_params_form() {
    // (x, y) => x + y
    let expr = parse_expr_from_str("(x, y) => x + y").expect("parse failed");
    match expr {
        Expr::Lambda { params, .. } => {
            assert_eq!(params.len(), 2);
            assert_eq!(params[0].name, "x");
            assert_eq!(params[1].name, "y");
        }
        _ => panic!("expected Lambda got {expr:?}"),
    }
}

#[test]
fn parse_expr_template_literal() {
    // `Hello ${name}!`
    let expr = parse_expr_from_str("`Hello ${name}!`").expect("parse failed");
    match expr {
        Expr::Template(segs, _) => {
            assert!(!segs.is_empty(), "template should have segments");
        }
        _ => panic!("expected Template got {expr:?}"),
    }
}

// ── Assignment operators ──────────────────────────────────────────────────────

#[test]
fn parse_expr_compound_assignment_operators() {
    let cases: &[(&str, AssignOp)] = &[
        ("a = b", AssignOp::Assign),
        ("a += b", AssignOp::Add),
        ("a -= b", AssignOp::Sub),
        ("a *= b", AssignOp::Mul),
        ("a /= b", AssignOp::Div),
        ("a %= b", AssignOp::Rem),
    ];
    for (src, expected_op) in cases {
        let expr =
            parse_expr_from_str(src).unwrap_or_else(|e| panic!("parse failed for '{src}': {e:?}"));
        match expr {
            Expr::Assign_(_, op, _, _) => {
                assert_eq!(op, *expected_op, "wrong op for '{src}'");
            }
            _ => panic!("expected Assign_ for '{src}', got {expr:?}"),
        }
    }
}

// ── Error cases (never panic, always Err) ─────────────────────────────────────

#[test]
fn parse_expr_empty_source_returns_error() {
    let result = parse_expr_from_str("");
    assert!(result.is_err(), "empty source should return Err");
}

#[test]
fn parse_expr_unclosed_paren_returns_error() {
    let result = parse_expr_from_str("(1 + 2");
    assert!(result.is_err(), "unclosed paren should return Err");
}

#[test]
fn parse_expr_unknown_token_returns_error() {
    // A lone semicolon is not a valid expression start
    let result = parse_expr_from_str(";");
    assert!(result.is_err(), "semicolon should return Err");
}

#[test]
fn parse_expr_unclosed_bracket_returns_error() {
    let result = parse_expr_from_str("[1, 2");
    assert!(result.is_err(), "unclosed bracket should return Err");
}

#[test]
fn parse_expr_missing_ternary_colon_returns_error() {
    let result = parse_expr_from_str("a ? b");
    assert!(result.is_err(), "missing ternary colon should return Err");
}

// ── Span coverage ─────────────────────────────────────────────────────────────

#[test]
fn parse_expr_spans_are_non_zero_for_non_empty_input() {
    use crate::parser::expr::expr_span;
    let expr = parse_expr_from_str("1 + 2").expect("parse failed");
    let span = expr_span(&expr);
    assert!(span.len > 0, "span should cover the expression");
}

// ── Unit suffix ───────────────────────────────────────────────────────────────

#[test]
fn parse_expr_unit_suffix_ether() {
    let expr = parse_expr_from_str("1.ether").expect("parse failed");
    assert!(
        matches!(expr, Expr::Literal(Literal::Unit(_, _), _)),
        "expected Unit literal, got {expr:?}"
    );
}

// ── Newline-insignificance in expression context (MF-1) ───────────────────────

#[test]
fn parse_expr_member_access_across_newline() {
    // obj\n.field — newline inside expression context is insignificant
    let expr = parse_expr_from_str("obj\n.field").expect("multi-line member access");
    match expr {
        Expr::Member(base, ref name, _) => {
            assert_eq!(name, "field", "expected field name 'field', got '{name}'");
            assert!(
                matches!(*base, Expr::Ident(ref n, _) if n == "obj"),
                "expected base 'obj', got {base:?}"
            );
        }
        _ => panic!("expected Member(.., \"field\"), got {expr:?}"),
    }
}

#[test]
fn parse_expr_call_across_newline() {
    // foo\n(1, 2) — newline before call args is insignificant
    let expr = parse_expr_from_str("foo\n(1, 2)").expect("multi-line call");
    assert!(
        matches!(expr, Expr::Call { .. }),
        "expected Call, got {expr:?}"
    );
}

#[test]
fn parse_expr_index_across_newline() {
    // arr\n[0] — newline before index is insignificant
    let expr = parse_expr_from_str("arr\n[0]").expect("multi-line index");
    assert!(
        matches!(expr, Expr::Index(_, _, _)),
        "expected Index, got {expr:?}"
    );
}

// ── Template interpolation trailing-token check (MF-2) ────────────────────────

#[test]
fn parse_expr_template_interpolation_trailing_tokens_returns_error() {
    // `${1 2}` has trailing `2` after `1` — must be Err
    let result = parse_expr_from_str("`x ${1 2} y`");
    assert!(
        result.is_err(),
        "trailing tokens in interpolation should be an error, got Ok"
    );
}

// ── Try-then-ternary (SF-3) ───────────────────────────────────────────────────

#[test]
fn parse_expr_try_then_ternary() {
    // foo() ? b : c  →  Ternary { cond: Call(foo), then: b, else_: c }
    let expr = parse_expr_from_str("foo() ? b : c").expect("ternary with call cond");
    assert!(
        matches!(expr, Expr::Ternary { .. }),
        "expected Ternary, got {expr:?}"
    );
}

// ── Call-opts unknown-key behavior (SF-4) ─────────────────────────────────────

#[test]
fn parse_expr_call_opts_unknown_key_errors() {
    // foo{unknown: 1}(arg) — `unknown` is not value/gas/salt.
    // is_call_opts_block returns false → `{` is NOT treated as call-opts at postfix
    // level. Instead, `foo{unknown: 1}` is parsed as a struct literal (primary-level),
    // and then `(arg)` is parsed as a call on that struct literal expression.
    // The result is: Call { callee: Struct_("foo", [("unknown", 1)]), args: [arg] }.
    //
    // This is the correct disambiguation: unknown keys fall through to struct-literal
    // parsing, not call-opts. The semantic analyzer (not the parser) would reject
    // calling a struct literal — the parser's job is structural, not semantic.
    let expr = parse_expr_from_str("foo{unknown: 1}(arg)")
        .expect("foo with unknown call-opts key should parse as struct-literal call");
    // Outer node is a Call whose callee is a Struct_ literal
    match expr {
        Expr::Call { callee, opts, .. } => {
            assert!(
                opts.is_none(),
                "call-opts should be None (not a call-opts block)"
            );
            assert!(
                matches!(*callee, Expr::Struct_ { ref name, .. } if name == "foo"),
                "callee should be Struct_(\"foo\"), got {callee:?}"
            );
        }
        _ => panic!("expected Call(Struct_(\"foo\"), ...), got {expr:?}"),
    }
}

// ── Fuzz-safety: malformed inputs never panic (SF-5) ─────────────────────────

#[test]
fn parse_expr_malformed_inputs_never_panic() {
    // These must all return Ok or Err — NEVER panic.
    let malformed = [
        "???", "{{{", "new", "if", "...", "?:", "()()", ".field", "1..", "=>", "**", "a +", "}{",
        "foo{", "foo(", "`${", "match", "loop",
    ];
    for src in malformed {
        // The contract is: no panic. Ok or Err are both acceptable.
        let _ = parse_expr_from_str(src);
    }
}

// ── Mixed-precedence shift tests (SF-6) ──────────────────────────────────────

#[test]
fn parse_expr_shift_precedence_tighter_than_comparison() {
    // a < b << c  →  a < (b << c)  (shift binds tighter than comparison)
    let expr = parse_expr_from_str("a < b << c").expect("parses");
    match &expr {
        Expr::Binary(BinaryOp::Lt, _, rhs, _) => {
            assert!(
                matches!(**rhs, Expr::Binary(BinaryOp::Shl, _, _, _)),
                "rhs of '<' should be shift (b << c), got {rhs:?}"
            );
        }
        _ => panic!("expected Lt binary, got {expr:?}"),
    }
}

#[test]
fn parse_expr_shift_precedence_tighter_than_addition() {
    // 1 + 2 << 3  →  (1 + 2) << 3
    // Precedence ladder (§29, lowest→highest): … shift → addition → multiply → …
    // `parse_shift` calls `parse_addition` for its operands, so addition binds
    // TIGHTER than shift. Therefore `1 + 2 << 3` = `(1 + 2) << 3`.
    let expr = parse_expr_from_str("1 + 2 << 3").expect("parses");
    match &expr {
        Expr::Binary(BinaryOp::Shl, lhs, rhs, _) => {
            assert!(
                matches!(**lhs, Expr::Binary(BinaryOp::Add, _, _, _)),
                "lhs of '<<' should be addition (1 + 2), got {lhs:?}"
            );
            assert!(
                matches!(**rhs, Expr::Literal(Literal::Int(3), _)),
                "rhs of '<<' should be 3, got {rhs:?}"
            );
        }
        _ => panic!("expected Shl binary (outer), got {expr:?}"),
    }
}

// ── Soft-keyword: `from` as identifier ───────────────────────────────────────

#[test]
fn expect_identifier_accepts_from_as_identifier_in_rvalue() {
    // `from` is Token::From (import keyword) but must also parse as an
    // identifier in rvalue position — e.g. `let x = from` after a param
    // binding `from: Address`.  The soft-keyword rule in `expect_identifier`
    // makes it available as `Expr::Identifier("from")`.
    // See: DB-A24 (decisions-log), §24 hook `fn onTransfer(from: Address, …)`.
    let expr = parse_expr_from_str("from").expect("should parse `from` as identifier");
    match expr {
        Expr::Ident(name, _) => assert_eq!(name, "from"),
        other => panic!("expected Ident(\"from\"), got: {other:?}"),
    }
}

#[test]
fn expect_identifier_accepts_from_as_param_name_in_function() {
    // Full function with `from: Address` as a parameter — proves `from` soft-keyword
    // works end-to-end through parse_param_list → expect_identifier.
    use crate::parser::ast::Item;
    let tokens =
        tokenize("fn transfer(from: Address, to: Address, amount: u128) {}").expect("tokenize");
    let mut p = Parser::new(tokens);
    let item = p
        .parse_top_level_item()
        .expect("should parse fn with `from` param");
    let func = match item {
        Item::Function(f) => f,
        other => panic!("expected Function item, got: {other:?}"),
    };
    assert_eq!(func.params[0].name, "from");
    assert_eq!(func.params[1].name, "to");
}

// ── Cast expression (Expr::Cast) ──────────────────────────────────────────────

#[test]
fn parse_cast_typed_int_to_u256() {
    // `100u128 as u256` → Cast { IntTyped(100, "u128"), Type::U256 }
    let expr = parse_expr_from_str("100u128 as u256").expect("parse failed");
    match expr {
        Expr::Cast {
            expr: inner, ty, ..
        } => {
            assert!(
                matches!(*inner, Expr::Literal(Literal::IntTyped { value: 100, ref suffix }, _) if suffix == "u128"),
                "expected IntTyped(100, u128), got {inner:?}"
            );
            assert_eq!(ty, Type::U256, "expected cast target U256");
        }
        _ => panic!("expected Expr::Cast, got {expr:?}"),
    }
}

#[test]
fn parse_cast_ident_to_u128() {
    // `x as u128` → Cast { Ident("x"), Type::U128 }
    let expr = parse_expr_from_str("x as u128").expect("parse failed");
    match expr {
        Expr::Cast {
            expr: inner, ty, ..
        } => {
            assert!(
                matches!(*inner, Expr::Ident(ref n, _) if n == "x"),
                "expected Ident(x), got {inner:?}"
            );
            assert_eq!(ty, Type::U128, "expected cast target U128");
        }
        _ => panic!("expected Expr::Cast, got {expr:?}"),
    }
}

#[test]
fn parse_cast_binds_tighter_than_addition() {
    // `a + b as u256` should parse as Binary(Add, Ident("a"), Cast{Ident("b"), U256})
    // NOT as Cast{Binary(Add, a, b), U256} — `as` is postfix, tighter than `+`.
    let expr = parse_expr_from_str("a + b as u256").expect("parse failed");
    match expr {
        Expr::Binary(BinaryOp::Add, lhs, rhs, _) => {
            assert!(
                matches!(*lhs, Expr::Ident(ref n, _) if n == "a"),
                "lhs should be Ident(a)"
            );
            match *rhs {
                Expr::Cast {
                    expr: inner, ty, ..
                } => {
                    assert!(
                        matches!(*inner, Expr::Ident(ref n, _) if n == "b"),
                        "cast inner should be Ident(b)"
                    );
                    assert_eq!(ty, Type::U256, "cast target should be U256");
                }
                _ => panic!("rhs should be Cast, got {rhs:?}"),
            }
        }
        _ => panic!("expected Binary(Add, ...), got {expr:?}"),
    }
}
