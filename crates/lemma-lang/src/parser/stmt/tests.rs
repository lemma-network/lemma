//! Tests for the full statement parser (subtask 2c).
//!
//! All tests follow AGENTS §11.3 naming: `{action}_{expected_outcome}`.
//! Shared fixtures are defined once at the top (AGENTS §2.6 DRY in tests).

use crate::lexer::tokenize;
use crate::parser::ast::{ForIter, Literal, Pattern, Stmt};
use crate::parser::Parser;

// ─── Shared fixtures ──────────────────────────────────────────────────────────

/// Parse a block body `{ stmts }` from source.
fn parse_block(src: &str) -> Vec<Stmt> {
    let tokens = tokenize(src).expect("tokenize failed");
    let mut p = Parser::new(tokens);
    p.parse_block().expect("parse_block failed")
}

/// Parse a single statement from source (no surrounding braces).
fn parse_stmt(src: &str) -> Stmt {
    let tokens = tokenize(src).expect("tokenize failed");
    let mut p = Parser::new(tokens);
    p.parse_stmt().expect("parse_stmt failed")
}

// ─── Let binding ──────────────────────────────────────────────────────────────

#[test]
fn parse_stmt_let_simple() {
    let stmt = parse_stmt("let x = 42");
    assert!(
        matches!(stmt, Stmt::Let { mutable: false, .. }),
        "expected immutable let, got {stmt:?}"
    );
}

#[test]
fn parse_stmt_let_mutable() {
    let stmt = parse_stmt("let mut x = 42");
    assert!(
        matches!(stmt, Stmt::Let { mutable: true, .. }),
        "expected mutable let, got {stmt:?}"
    );
}

#[test]
fn parse_stmt_let_with_type_annotation() {
    let stmt = parse_stmt("let x: u256 = 0");
    match stmt {
        Stmt::Let { ty: Some(_), .. } => {}
        other => panic!("expected let with type annotation, got {other:?}"),
    }
}

#[test]
fn parse_stmt_let_tuple_destructure() {
    let stmt = parse_stmt("let (a, b) = pair");
    match stmt {
        Stmt::Let {
            pattern: Pattern::Tuple(pats, _),
            ..
        } => {
            assert_eq!(pats.len(), 2, "expected 2 tuple elements");
        }
        other => panic!("expected tuple destructure, got {other:?}"),
    }
}

#[test]
fn parse_stmt_let_struct_destructure() {
    let stmt = parse_stmt("let Point { x: px, y: py } = point");
    match stmt {
        Stmt::Let {
            pattern: Pattern::Struct_ { name, fields, .. },
            ..
        } => {
            assert_eq!(name, "Point");
            assert_eq!(fields.len(), 2);
        }
        other => panic!("expected struct destructure, got {other:?}"),
    }
}

#[test]
fn parse_stmt_let_wildcard_pattern() {
    let stmt = parse_stmt("let _ = unused");
    assert!(
        matches!(
            stmt,
            Stmt::Let {
                pattern: Pattern::Wildcard(_),
                ..
            }
        ),
        "expected wildcard pattern"
    );
}

#[test]
fn parse_pattern_wildcard_from_underscore_ident() {
    // `_` is lexed as Identifier("_") → Pattern::Wildcard (not Token::Underscore).
    // This test confirms the canonical path is the live one.
    let stmt = parse_stmt("let _ = 42");
    match stmt {
        Stmt::Let { pattern, .. } => {
            assert!(
                matches!(pattern, Pattern::Wildcard(_)),
                "expected Pattern::Wildcard from Identifier(\"_\"), got {pattern:?}"
            );
        }
        other => panic!("expected Let, got {other:?}"),
    }
}

// ─── Const statement ──────────────────────────────────────────────────────────

#[test]
fn parse_stmt_const_simple() {
    let stmt = parse_stmt("const MAX: u256 = 1000");
    assert!(
        matches!(stmt, Stmt::Const(_)),
        "expected Stmt::Const, got {stmt:?}"
    );
}

// ─── If statement ─────────────────────────────────────────────────────────────

#[test]
fn parse_stmt_if_simple() {
    let stmt = parse_stmt("if (x > 0) { let y = 1 }");
    assert!(
        matches!(stmt, Stmt::If { else_: None, .. }),
        "expected if without else, got {stmt:?}"
    );
}

#[test]
fn parse_stmt_if_else() {
    let stmt = parse_stmt("if (x > 0) { let y = 1 } else { let y = 0 }");
    match stmt {
        Stmt::If {
            else_: Some(else_stmts),
            ..
        } => {
            assert!(!else_stmts.is_empty(), "else block should have statements");
        }
        other => panic!("expected if-else, got {other:?}"),
    }
}

#[test]
fn parse_stmt_if_else_if_chain() {
    let stmt = parse_stmt("if (a) { let x = 1 } else if (b) { let x = 2 } else { let x = 3 }");
    match stmt {
        Stmt::If {
            else_: Some(else_stmts),
            ..
        } => {
            // The else branch contains a single nested if statement
            assert_eq!(else_stmts.len(), 1);
            assert!(
                matches!(else_stmts[0], Stmt::If { .. }),
                "else-if chain should nest as Stmt::If"
            );
        }
        other => panic!("expected else-if chain, got {other:?}"),
    }
}

// ─── Match statement ──────────────────────────────────────────────────────────

#[test]
fn parse_stmt_match_simple() {
    // Use (x) to avoid struct-literal ambiguity: `match x {` would parse
    // `x { ... }` as a struct literal expression.
    let stmts = parse_block("{ match (x) { a => 1\nb => 2 } }");
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], Stmt::Match { .. }));
}

#[test]
fn parse_stmt_match_with_guard() {
    let stmts = parse_block("{ match (x) { n if n > 0 => 1\n_ => 0 } }");
    assert_eq!(stmts.len(), 1);
    match &stmts[0] {
        Stmt::Match { arms, .. } => {
            assert_eq!(arms.len(), 2);
            assert!(arms[0].guard.is_some(), "first arm should have guard");
        }
        other => panic!("expected match, got {other:?}"),
    }
}

#[test]
fn parse_stmt_match_with_block_body() {
    use crate::parser::ast::MatchBody;
    let stmts = parse_block("{ match (x) { a => { let y = 1 } } }");
    match &stmts[0] {
        Stmt::Match { arms, .. } => {
            assert!(
                matches!(arms[0].body, MatchBody::Block(_)),
                "arm body should be a block"
            );
        }
        other => panic!("expected match, got {other:?}"),
    }
}

// ─── For statement ────────────────────────────────────────────────────────────

#[test]
fn parse_stmt_for_of() {
    // Use items.iter() to avoid struct-literal ambiguity: `for x of items {`
    // would parse `items { ... }` as a struct literal expression.
    let stmt = parse_stmt("for x of items.iter() { let y = x }");
    match stmt {
        Stmt::For {
            iter: ForIter::Of(_),
            ..
        } => {}
        other => panic!("expected for-of, got {other:?}"),
    }
}

#[test]
fn parse_stmt_for_in_exclusive() {
    let stmt = parse_stmt("for i in 0..10 { let x = i }");
    match stmt {
        Stmt::For {
            iter: ForIter::In(_, _, _, inclusive),
            ..
        } => {
            assert!(!inclusive, "expected exclusive range");
        }
        other => panic!("expected for-in exclusive, got {other:?}"),
    }
}

#[test]
fn parse_stmt_for_in_inclusive() {
    let stmt = parse_stmt("for i in 0..=9 { let x = i }");
    match stmt {
        Stmt::For {
            iter: ForIter::In(_, _, _, inclusive),
            ..
        } => {
            assert!(inclusive, "expected inclusive range");
        }
        other => panic!("expected for-in inclusive, got {other:?}"),
    }
}

#[test]
fn parse_stmt_for_with_pattern_binding() {
    // Use pairs.iter() to avoid struct-literal ambiguity
    let stmt = parse_stmt("for (k, v) of pairs.iter() { let x = k }");
    match stmt {
        Stmt::For {
            pattern: Pattern::Tuple(pats, _),
            iter: ForIter::Of(_),
            ..
        } => {
            assert_eq!(pats.len(), 2);
        }
        other => panic!("expected for-of with tuple pattern, got {other:?}"),
    }
}

// ─── While statement ──────────────────────────────────────────────────────────

#[test]
fn parse_stmt_while_simple() {
    let stmt = parse_stmt("while (x > 0) { let x = x - 1 }");
    assert!(
        matches!(stmt, Stmt::While { .. }),
        "expected while, got {stmt:?}"
    );
}

// ─── Loop statement ───────────────────────────────────────────────────────────

#[test]
fn parse_stmt_loop_simple() {
    let stmt = parse_stmt("loop { break }");
    assert!(
        matches!(stmt, Stmt::Loop { .. }),
        "expected loop, got {stmt:?}"
    );
}

// ─── Jump statements ──────────────────────────────────────────────────────────

#[test]
fn parse_stmt_return_with_value() {
    let stmt = parse_stmt("return 42");
    assert!(
        matches!(stmt, Stmt::Return(Some(_), _)),
        "expected return with value, got {stmt:?}"
    );
}

#[test]
fn parse_stmt_return_without_value() {
    let stmt = parse_stmt("return");
    assert!(
        matches!(stmt, Stmt::Return(None, _)),
        "expected return without value, got {stmt:?}"
    );
}

#[test]
fn parse_stmt_break() {
    let stmt = parse_stmt("break");
    assert!(
        matches!(stmt, Stmt::Break(_)),
        "expected break, got {stmt:?}"
    );
}

#[test]
fn parse_stmt_continue() {
    let stmt = parse_stmt("continue");
    assert!(
        matches!(stmt, Stmt::Continue(_)),
        "expected continue, got {stmt:?}"
    );
}

// ─── Emit statement ───────────────────────────────────────────────────────────

#[test]
fn parse_stmt_emit_simple() {
    // Avoid keyword field names: `from` is Token::From, `to` is not a keyword.
    // Use non-keyword identifiers for field names.
    let stmt = parse_stmt("emit Transfer { sender: alice, recipient: bob }");
    match stmt {
        Stmt::Emit { event, fields, .. } => {
            assert_eq!(event, "Transfer");
            assert_eq!(fields.len(), 2);
        }
        other => panic!("expected emit, got {other:?}"),
    }
}

#[test]
fn parse_stmt_emit_multiple_fields() {
    let stmt = parse_stmt("emit Approval { owner: a, spender: b, amount: c }");
    match stmt {
        Stmt::Emit { fields, .. } => {
            assert_eq!(fields.len(), 3, "expected 3 fields");
        }
        other => panic!("expected emit, got {other:?}"),
    }
}

#[test]
fn parse_stmt_emit_no_fields() {
    let stmt = parse_stmt("emit Paused {}");
    match stmt {
        Stmt::Emit { event, fields, .. } => {
            assert_eq!(event, "Paused");
            assert!(fields.is_empty());
        }
        other => panic!("expected emit, got {other:?}"),
    }
}

// ─── Assert statement ─────────────────────────────────────────────────────────

#[test]
fn parse_stmt_assert_without_message() {
    let stmt = parse_stmt("assert(x > 0)");
    match stmt {
        Stmt::Assert { msg: None, .. } => {}
        other => panic!("expected assert without message, got {other:?}"),
    }
}

#[test]
fn parse_stmt_assert_with_message() {
    let stmt = parse_stmt("assert(x > 0, \"must be positive\")");
    match stmt {
        Stmt::Assert { msg: Some(_), .. } => {}
        other => panic!("expected assert with message, got {other:?}"),
    }
}

// ─── Revert statement ─────────────────────────────────────────────────────────

#[test]
fn parse_stmt_revert_without_message() {
    let stmt = parse_stmt("revert");
    match stmt {
        Stmt::Revert { msg: None, .. } => {}
        other => panic!("expected revert without message, got {other:?}"),
    }
}

#[test]
fn parse_stmt_revert_with_message() {
    let stmt = parse_stmt("revert(\"not allowed\")");
    match stmt {
        Stmt::Revert { msg: Some(_), .. } => {}
        other => panic!("expected revert with message, got {other:?}"),
    }
}

// ─── Try/catch statement ──────────────────────────────────────────────────────

#[test]
fn parse_stmt_try_catch() {
    let stmt = parse_stmt("try { let x = 1 } catch (e) { revert }");
    match stmt {
        Stmt::Try {
            catch_var,
            body,
            catch_body,
            ..
        } => {
            assert_eq!(catch_var, "e");
            assert!(!body.is_empty(), "try body should have statements");
            assert!(!catch_body.is_empty(), "catch body should have statements");
        }
        other => panic!("expected try-catch, got {other:?}"),
    }
}

// ─── Unchecked statement ──────────────────────────────────────────────────────

#[test]
fn parse_stmt_unchecked_block() {
    let stmt = parse_stmt("unchecked { let x = a + b }");
    match stmt {
        Stmt::Unchecked(body, _) => {
            assert!(!body.is_empty(), "unchecked body should have statements");
        }
        other => panic!("expected unchecked, got {other:?}"),
    }
}

// ─── Placeholder ──────────────────────────────────────────────────────────────

#[test]
fn parse_stmt_placeholder_accepted_anywhere() {
    let stmt = parse_stmt("_");
    assert!(
        matches!(stmt, Stmt::Placeholder(_)),
        "expected placeholder, got {stmt:?}"
    );
}

// ─── Expression statement ─────────────────────────────────────────────────────

#[test]
fn parse_stmt_expression_statement() {
    let stmt = parse_stmt("foo()");
    assert!(
        matches!(stmt, Stmt::Expr(_, _)),
        "expected expression statement, got {stmt:?}"
    );
}

#[test]
fn parse_stmt_assignment_becomes_stmt_assign() {
    let stmt = parse_stmt("x = 42");
    assert!(
        matches!(stmt, Stmt::Assign { .. }),
        "expected Stmt::Assign, got {stmt:?}"
    );
}

#[test]
fn parse_stmt_compound_assignment() {
    let stmt = parse_stmt("x += 1");
    assert!(
        matches!(stmt, Stmt::Assign { .. }),
        "expected Stmt::Assign for +=, got {stmt:?}"
    );
}

// ─── Block tests ──────────────────────────────────────────────────────────────

#[test]
fn parse_block_empty() {
    let stmts = parse_block("{}");
    assert!(stmts.is_empty(), "empty block should have no statements");
}

#[test]
fn parse_block_multiple_statements() {
    let stmts = parse_block("{ let x = 1\nlet y = 2\nlet z = 3 }");
    assert_eq!(stmts.len(), 3, "expected 3 statements");
}

#[test]
fn parse_block_nested_blocks() {
    let stmts = parse_block("{ if (true) { let x = 1 } }");
    assert_eq!(stmts.len(), 1);
    assert!(matches!(stmts[0], Stmt::If { .. }));
}

#[test]
fn parse_block_with_semicolons() {
    let stmts = parse_block("{ let x = 1; let y = 2; }");
    assert_eq!(stmts.len(), 2, "semicolons should separate statements");
}

// ─── Pattern tests ────────────────────────────────────────────────────────────

#[test]
fn parse_stmt_let_literal_pattern_int() {
    // Literal patterns in let are unusual but syntactically valid
    let stmt = parse_stmt("let 42 = value");
    assert!(
        matches!(
            stmt,
            Stmt::Let {
                pattern: Pattern::Literal(Literal::Int(42), _),
                ..
            }
        ),
        "expected literal int pattern"
    );
}

#[test]
fn parse_stmt_let_bool_pattern() {
    let stmt = parse_stmt("let true = flag");
    assert!(
        matches!(
            stmt,
            Stmt::Let {
                pattern: Pattern::Literal(Literal::Bool(true), _),
                ..
            }
        ),
        "expected bool literal pattern"
    );
}

// ─── Struct shorthand patterns ────────────────────────────────────────────────

#[test]
fn parse_stmt_match_struct_pattern_shorthand() {
    // Shorthand struct pattern: `Filled { price, timestamp }` — no colons.
    // Spec §6: field name IS the binding name.
    let stmts = parse_block("{ match (order) { Filled { price, timestamp } => log(price) } }");
    assert_eq!(stmts.len(), 1);
    match &stmts[0] {
        Stmt::Match { arms, .. } => {
            assert_eq!(arms.len(), 1);
            match &arms[0].pattern {
                Pattern::Struct_ { name, fields, .. } => {
                    assert_eq!(name, "Filled");
                    assert_eq!(fields.len(), 2);
                    // Shorthand: field name == binding name
                    assert_eq!(fields[0].0, "price");
                    assert!(matches!(&fields[0].1, Pattern::Ident(n, _) if n == "price"));
                    assert_eq!(fields[1].0, "timestamp");
                    assert!(matches!(&fields[1].1, Pattern::Ident(n, _) if n == "timestamp"));
                }
                p => panic!("expected Struct_ pattern, got {p:?}"),
            }
        }
        s => panic!("expected Match, got {s:?}"),
    }
}

#[test]
fn parse_stmt_let_struct_shorthand_destructure() {
    // Shorthand destructure: `let {x, y} = point` — no colons, no type name.
    let stmt = parse_stmt("let {x, y} = point");
    match stmt {
        Stmt::Let { pattern, .. } => match pattern {
            Pattern::Struct_ { fields, .. } => {
                assert_eq!(fields.len(), 2, "expected 2 shorthand fields");
                assert_eq!(fields[0].0, "x");
                assert_eq!(fields[1].0, "y");
                // Shorthand: each pattern is Ident with the same name as the field
                assert!(
                    matches!(&fields[0].1, Pattern::Ident(n, _) if n == "x"),
                    "field 'x' should bind to Ident(\"x\")"
                );
                assert!(
                    matches!(&fields[1].1, Pattern::Ident(n, _) if n == "y"),
                    "field 'y' should bind to Ident(\"y\")"
                );
            }
            other => panic!("expected Struct_ pattern, got {other:?}"),
        },
        other => panic!("expected Let, got {other:?}"),
    }
}

#[test]
fn parse_stmt_let_struct_mixed_long_and_shorthand() {
    // Mixed: `let Point { x: px, y }` — long form for x, shorthand for y.
    let stmt = parse_stmt("let Point { x: px, y } = point");
    match stmt {
        Stmt::Let { pattern, .. } => match pattern {
            Pattern::Struct_ { name, fields, .. } => {
                assert_eq!(name, "Point");
                assert_eq!(fields.len(), 2);
                // Long form: field "x" → Ident("px")
                assert_eq!(fields[0].0, "x");
                assert!(
                    matches!(&fields[0].1, Pattern::Ident(n, _) if n == "px"),
                    "long-form field should bind to Ident(\"px\")"
                );
                // Shorthand: field "y" → Ident("y")
                assert_eq!(fields[1].0, "y");
                assert!(
                    matches!(&fields[1].1, Pattern::Ident(n, _) if n == "y"),
                    "shorthand field should bind to Ident(\"y\")"
                );
            }
            other => panic!("expected Struct_ pattern, got {other:?}"),
        },
        other => panic!("expected Let, got {other:?}"),
    }
}

// ─── Fuzz-safety: malformed inputs must never panic ───────────────────────────

#[test]
fn parse_stmt_malformed_never_panics() {
    // None of these should panic — they should return Err
    let malformed_inputs = [
        "let",
        "let =",
        "if",
        "if (",
        "if (x",
        "for",
        "for x",
        "while",
        "while (",
        "emit",
        "assert",
        "assert(",
        "try",
        "try {",
        "return return return",
        "{ { {",
        "} } }",
        "let x = let y = let z =",
        "match",
        "match x {",
    ];
    for input in &malformed_inputs {
        let tokens = tokenize(input);
        match tokens {
            Err(_) => {} // lex error is fine
            Ok(toks) => {
                let mut p = Parser::new(toks);
                // Must not panic — result can be Ok or Err
                let _ = p.parse_stmt();
            }
        }
    }
}

// ─── Edge-case tests ──────────────────────────────────────────────────────────

#[test]
fn parse_block_bare_return_does_not_swallow_next_stmt() {
    // A bare `return` (no value) must not consume the following statement.
    let stmts = parse_block("{\n    return\n    let x = 1\n}");
    assert_eq!(stmts.len(), 2, "return + let should be 2 statements");
    assert!(
        matches!(stmts[0], Stmt::Return(None, _)),
        "first stmt should be bare return, got {:?}",
        stmts[0]
    );
    assert!(
        matches!(stmts[1], Stmt::Let { .. }),
        "second stmt should be let, got {:?}",
        stmts[1]
    );
}

#[test]
fn parse_stmt_if_else_on_next_line() {
    // `else` on the next line after `}` must still be parsed as the else branch.
    let stmt = parse_stmt("if (x) {\n    a\n}\nelse {\n    b\n}");
    match stmt {
        Stmt::If { else_, .. } => {
            assert!(
                else_.is_some(),
                "else block should parse across newline boundary"
            );
        }
        other => panic!("expected If, got {other:?}"),
    }
}

#[test]
fn parse_stmt_match_nested_with_guard() {
    // Match arm with a guard expression: `n if n > 1000 => big()`.
    // Scrutinee wrapped in parens to avoid struct-literal ambiguity.
    let stmt = parse_stmt("match (amount) { n if n > 1000 => big() }");
    match stmt {
        Stmt::Match { arms, .. } => {
            assert_eq!(arms.len(), 1);
            assert!(arms[0].guard.is_some(), "guard should be parsed");
        }
        other => panic!("expected Match, got {other:?}"),
    }
}

// ─── Span correctness ─────────────────────────────────────────────────────────

#[test]
fn parse_stmt_let_span_starts_at_let_keyword() {
    let tokens = tokenize("let x = 1").expect("tokenize failed");
    let mut p = Parser::new(tokens);
    let stmt = p.parse_stmt().expect("parse failed");
    match stmt {
        Stmt::Let { span, .. } => {
            // Span should start at offset 0 (the `let` keyword)
            assert_eq!(span.offset, 0, "let span should start at offset 0");
        }
        other => panic!("expected let, got {other:?}"),
    }
}

#[test]
fn parse_stmt_break_span_is_single_token() {
    let tokens = tokenize("break").expect("tokenize failed");
    let mut p = Parser::new(tokens);
    let stmt = p.parse_stmt().expect("parse failed");
    match stmt {
        Stmt::Break(span) => {
            assert_eq!(span.offset, 0);
        }
        other => panic!("expected break, got {other:?}"),
    }
}
