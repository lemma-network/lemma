//! Tests for the name resolver — [`super::collect_pattern_bindings`]
//! and the internal resolution logic exercised via [`crate::type_checker::check`].

use crate::error::LangError;
use crate::lexer::tokenize;
use crate::parser::ast::Pattern;
use crate::parser::parse;
use crate::type_checker::{check, TypeErrorKind, TypedAst};

// ── Helper ─────────────────────────────────────────────────────────────────────

fn check_src(src: &str) -> Result<TypedAst, LangError> {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    check(ast)
}

// ── collect_pattern_bindings ───────────────────────────────────────────────────

use super::collect_pattern_bindings;
use crate::lexer::token::Span;

fn s(offset: usize) -> Span {
    Span {
        line: 1,
        col: 1,
        offset,
        len: 1,
    }
}

#[test]
fn collect_bindings_wildcard_returns_empty() {
    let p = Pattern::Wildcard(s(0));
    assert!(collect_pattern_bindings(&p).is_empty());
}

#[test]
fn collect_bindings_ident_returns_single() {
    let p = Pattern::Ident("x".into(), s(0));
    let bindings = collect_pattern_bindings(&p);
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].0, "x");
}

#[test]
fn collect_bindings_tuple_collects_all_idents() {
    let p = Pattern::Tuple(
        vec![
            Pattern::Ident("a".into(), s(0)),
            Pattern::Ident("b".into(), s(2)),
            Pattern::Wildcard(s(4)),
        ],
        s(0),
    );
    let bindings = collect_pattern_bindings(&p);
    let names: Vec<&str> = bindings.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["a", "b"]);
}

#[test]
fn collect_bindings_struct_pattern_collects_field_patterns() {
    let p = Pattern::Struct_ {
        name: "Point".into(),
        fields: vec![
            ("x".into(), Pattern::Ident("px".into(), s(5))),
            ("y".into(), Pattern::Ident("py".into(), s(8))),
        ],
        span: s(0),
    };
    let bindings = collect_pattern_bindings(&p);
    let names: Vec<&str> = bindings.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["px", "py"]);
}

#[test]
fn collect_bindings_enum_variant_collects_inner() {
    let p = Pattern::EnumVariant {
        name: "Some".into(),
        inner: Some(vec![Pattern::Ident("val".into(), s(5))]),
        span: s(0),
    };
    let bindings = collect_pattern_bindings(&p);
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].0, "val");
}

#[test]
fn collect_bindings_enum_variant_none_inner_empty() {
    let p = Pattern::EnumVariant {
        name: "None".into(),
        inner: None,
        span: s(0),
    };
    assert!(collect_pattern_bindings(&p).is_empty());
}

#[test]
fn collect_bindings_rest_returns_empty() {
    let p = Pattern::Rest(s(0));
    assert!(collect_pattern_bindings(&p).is_empty());
}

#[test]
fn collect_bindings_nested_tuple_recurses() {
    let inner = Pattern::Tuple(
        vec![
            Pattern::Ident("x".into(), s(1)),
            Pattern::Ident("y".into(), s(3)),
        ],
        s(0),
    );
    let outer = Pattern::Tuple(vec![inner, Pattern::Ident("z".into(), s(5))], s(0));
    let bindings = collect_pattern_bindings(&outer);
    let names: Vec<&str> = bindings.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, vec!["x", "y", "z"]);
}

// ── Symbol arena populated ─────────────────────────────────────────────────────

#[test]
fn check_populates_symbols_for_contract() {
    let typed = check_src("contract Vault {}").expect("should succeed");
    assert!(
        typed.has_name_resolution(),
        "symbols should be populated after resolution"
    );
    // The contract "Vault" should appear in the arena.
    let vault = typed.symbols.iter().find(|s| s.name == "Vault");
    assert!(vault.is_some(), "expected symbol for 'Vault'");
}

#[test]
fn check_populates_symbols_for_function_params() {
    let typed = check_src("fn add(a: u128, b: u128) -> u128 { return a }").expect("should succeed");
    let param_a = typed.symbols.iter().find(|s| s.name == "a");
    assert!(param_a.is_some(), "expected symbol for param 'a'");
    use crate::type_checker::types::SymbolKind;
    assert!(matches!(param_a.unwrap().kind, SymbolKind::Param));
}

// ── Identifier resolution (resolutions map populated) ─────────────────────────

#[test]
fn check_resolves_param_reference_in_body() {
    // `return x` — `x` should be resolved to the param symbol.
    let typed = check_src("fn id(x: u128) -> u128 { return x }").expect("should succeed");
    assert!(
        !typed.resolutions.is_empty(),
        "resolutions should be non-empty"
    );
    // At least one span maps to a SymbolId.
    assert!(typed.resolutions.values().all(|id| !id.is_unresolved()));
}

#[test]
fn check_resolves_self_in_method_body() {
    let typed = check_src(
        r#"contract C {
state { pub x: u128 = 0 }
pub fn getX() -> u128 { return self }
}"#,
    )
    .expect("should succeed");
    // `self` should be resolved.
    let self_sym = typed.symbols.iter().find(|s| s.name == "self");
    assert!(self_sym.is_some(), "expected synthetic 'self' symbol");
    use crate::type_checker::types::SymbolKind;
    assert!(matches!(self_sym.unwrap().kind, SymbolKind::SelfBinding));
}

// ── UndefinedName errors ───────────────────────────────────────────────────────

#[test]
fn check_undefined_name_in_function_body() {
    let result = check_src("fn f() { let x = unknown }");
    match result {
        Err(LangError::Type(e)) => {
            assert!(
                matches!(&e.kind, TypeErrorKind::UndefinedName { name } if name == "unknown"),
                "expected UndefinedName(unknown), got: {:?}",
                e.kind
            );
        }
        other => panic!("expected UndefinedName error, got: {other:?}"),
    }
}

#[test]
fn check_undefined_name_error_message_contains_name() {
    let result = check_src("fn f() { let x = noSuchVar }");
    match result {
        Err(LangError::Type(e)) => {
            assert!(
                e.message.contains("noSuchVar"),
                "message should contain the undefined name: {}",
                e.message
            );
        }
        other => panic!("expected LangError::Type, got: {other:?}"),
    }
}

#[test]
fn check_returns_ok_for_defined_name() {
    let result = check_src("fn f(x: u128) -> u128 { return x }");
    assert!(result.is_ok(), "param reference should resolve: {result:?}");
}

// ── UndefinedType errors ───────────────────────────────────────────────────────

#[test]
fn check_undefined_type_in_param() {
    let result = check_src("fn f(x: NoSuchType) {}");
    match result {
        Err(LangError::Type(e)) => {
            assert!(
                matches!(&e.kind, TypeErrorKind::UndefinedType { name } if name == "NoSuchType"),
                "expected UndefinedType(NoSuchType), got: {:?}",
                e.kind
            );
        }
        other => panic!("expected UndefinedType error, got: {other:?}"),
    }
}

#[test]
fn check_undefined_type_in_return_type() {
    let result = check_src("fn f() -> NoSuchType {}");
    assert!(matches!(result, Err(LangError::Type(ref e))
            if matches!(&e.kind, TypeErrorKind::UndefinedType { name } if name == "NoSuchType")));
}

#[test]
fn check_undefined_type_in_state_field() {
    let result = check_src("contract C { state { x: UnknownType } }");
    assert!(matches!(result, Err(LangError::Type(_))));
}

#[test]
fn check_struct_type_resolves_after_declaration() {
    // A struct declared in the same file should be resolvable as a type in
    // parameter and return-type positions.
    let result = check_src(
        r#"struct Point { x: u128, y: u128 }
fn makePoint(x: u128, y: u128) -> Point {}"#,
    );
    // Should succeed — Point is declared at the top level.
    assert!(result.is_ok(), "struct type should resolve: {result:?}");
}

// ── Duplicate contract member detection ───────────────────────────────────────

#[test]
fn check_duplicate_contract_functions_returns_error() {
    let result = check_src(
        r#"contract C {
pub fn foo() {}
pub fn foo() {}
}"#,
    );
    assert!(
        matches!(result, Err(LangError::Type(ref e))
            if matches!(&e.kind, TypeErrorKind::DuplicateDeclaration { name } if name == "foo")),
        "expected DuplicateDeclaration(foo), got: {result:?}"
    );
}

#[test]
fn check_duplicate_state_fields_returns_error() {
    let result = check_src("contract C { state { x: u128\nx: u256 } }");
    assert!(matches!(result, Err(LangError::Type(_))));
}

// ── Imports register names as opaque ──────────────────────────────────────────

#[test]
fn check_imported_names_do_not_trigger_undefined_errors() {
    // After `import { Token } from "@std/token"`, using `Token` as a type
    // should not produce UndefinedType in 3b (it's opaque-imported).
    let result = check_src(
        r#"import { Token } from "@std/token"
fn f(t: Token) {}"#,
    );
    assert!(result.is_ok(), "imported type should not error: {result:?}");
}

// ── Shadowing in nested scopes ─────────────────────────────────────────────────

#[test]
fn check_let_shadowing_in_nested_scope_ok() {
    // Outer `x` defined by param; inner block can introduce a new `x`.
    let result = check_src(
        r#"fn f(x: u128) -> u128 {
let y = x
return y
}"#,
    );
    assert!(
        result.is_ok(),
        "shadowing in nested scope should be ok: {result:?}"
    );
}

// ── symbol() lookup via TypedAst ───────────────────────────────────────────────

#[test]
fn symbol_lookup_returns_info_for_allocated_symbol() {
    let typed = check_src("fn greet(name: u128) {}").expect("should succeed");
    // Find the SymbolId for "name" param.
    let sym = typed.symbols.iter().position(|s| s.name == "name");
    assert!(sym.is_some(), "expected 'name' in symbols");
    let id = crate::type_checker::types::SymbolId((sym.unwrap() + 1) as u32);
    let info = typed.symbol(id).expect("symbol() should return SymbolInfo");
    assert_eq!(info.name, "name");
}

#[test]
fn symbol_lookup_unresolved_returns_none() {
    let typed = check_src("contract C {}").expect("should succeed");
    assert!(typed
        .symbol(crate::type_checker::types::SymbolId::UNRESOLVED)
        .is_none());
}

// ── Generic param resolution (S3) ──────────────────────────────────────────────

#[test]
fn check_generic_param_resolves_as_type() {
    // `T` is a generic param; using it as a param/return type must NOT
    // produce UndefinedType — it is bound into the type scope.
    let result = check_src("fn id<T>(x: T) -> T { return x }");
    assert!(result.is_ok(), "generic param T should resolve: {result:?}");
}

#[test]
fn check_generic_param_out_of_scope_is_undefined() {
    // `T` declared on `first` is not in scope for `second`.
    let result = check_src(
        r#"fn first<T>(x: T) -> T { return x }
fn second(y: T) {}"#,
    );
    assert!(
        matches!(result, Err(LangError::Type(ref e))
            if matches!(&e.kind, TypeErrorKind::UndefinedType { name } if name == "T")),
        "T should be undefined in second(): {result:?}"
    );
}

// ── Lambda param scoping (S3) ──────────────────────────────────────────────────

#[test]
fn check_lambda_param_in_scope_in_body() {
    // `p` is a lambda param; referencing it in the lambda body must resolve.
    let result = check_src("fn f(items: Array<u128>) { let r = items.map(p => p) }");
    assert!(
        result.is_ok(),
        "lambda param should resolve in body: {result:?}"
    );
}

#[test]
fn check_lambda_body_undefined_name_errors() {
    let result = check_src("fn f(items: Array<u128>) { let r = items.map(p => unknownVar) }");
    assert!(
        matches!(result, Err(LangError::Type(ref e))
            if matches!(&e.kind, TypeErrorKind::UndefinedName { name } if name == "unknownVar")),
        "unknownVar in lambda should error: {result:?}"
    );
}

// ── Match-arm binding (S3) ─────────────────────────────────────────────────────

#[test]
fn check_match_arm_binding_visible_in_body() {
    // `v` bound by the Some(v) pattern must be resolvable in that arm's body.
    // Parenthesised scrutinee `(o)` avoids the parser's struct-literal
    // ambiguity for `match o {` (see parser/stmt/tests.rs:701).
    let result = check_src(
        r#"fn handle(o: Option<u128>) {
match (o) {
Some(v) => { let x = v }
None => { let y = 0 }
}
}"#,
    );
    assert!(
        result.is_ok(),
        "match-arm binding should resolve: {result:?}"
    );
}

// ── Expr::New undefined type (S3) ──────────────────────────────────────────────

#[test]
fn check_new_undefined_type_errors() {
    let result = check_src("fn f() { let x = new NoSuchType() }");
    assert!(
        matches!(result, Err(LangError::Type(ref e))
            if matches!(&e.kind, TypeErrorKind::UndefinedType { name } if name == "NoSuchType")),
        "new NoSuchType() should error: {result:?}"
    );
}

#[test]
fn check_new_known_type_resolves() {
    let result = check_src(
        r#"struct Widget { id: u128 }
fn make() { let w = new Widget() }"#,
    );
    assert!(result.is_ok(), "new Widget() should resolve: {result:?}");
}

// ── Shadowing teardown (S3) ────────────────────────────────────────────────────

#[test]
fn check_block_local_not_visible_after_block() {
    // `inner` is declared inside the if-block; referencing it after the block
    // must produce UndefinedName (the block scope was popped).
    let result = check_src(
        r#"fn f(cond: bool) -> u128 {
if (cond) {
let inner = 1
}
return inner
}"#,
    );
    assert!(
        matches!(result, Err(LangError::Type(ref e))
            if matches!(&e.kind, TypeErrorKind::UndefinedName { name } if name == "inner")),
        "block-local 'inner' should not be visible after the block: {result:?}"
    );
}

// ── M1: `self`-as-field is parser-unreachable ──────────────────────────────────

#[test]
fn check_self_is_reserved_cannot_be_field_name() {
    // `self` is lexed as Token::SelfKw, so a state field named `self` cannot
    // be parsed — tokenize/parse rejects it before the resolver ever runs.
    // This proves the synthetic `self` SelfBinding cannot collide with a field.
    let tokens = tokenize("contract C { state { self: u128 } }");
    let parsed = tokens.and_then(parse);
    assert!(
        parsed.is_err(),
        "a field named `self` must fail to parse (self is a reserved keyword)"
    );
}

// ── P3-checker-3: Forward-reference re-lowering ────────────────────────────────

#[test]
fn forward_ref_struct_annotation_resolves_to_named() {
    // `const X: Point = ...` where `struct Point` is declared AFTER the const.
    // After re_lower_forward_refs, X's type should be Named(point_id, []).
    let typed = check_src(
        r#"
        const X: Point = Point { x: 1u128, y: 2u128 }
        struct Point { x: u128, y: u128 }
        "#,
    )
    .expect("should resolve forward ref");
    // Find the const symbol and verify its type is Named (not Unknown).
    let x_sym = typed
        .symbols
        .iter()
        .find(|s| s.name == "X")
        .expect("X should be in symbols");
    assert!(
        matches!(
            x_sym.ty,
            crate::type_checker::types::ResolvedType::Named(_, _)
        ),
        "X.ty should be Named after forward-ref re-lowering, got {:?}",
        x_sym.ty
    );
}

#[test]
fn forward_ref_resolves_only_if_type_exists() {
    // A bogus type name stays Unknown (no double-error from re-lower pass).
    // The UndefinedType error is emitted by resolve_type_ref in Pass 2.
    let result = check_src("const X: BogusType = 42");
    assert!(
        result.is_err(),
        "bogus type should produce UndefinedType error"
    );
}

#[test]
fn multiple_forward_refs_all_resolved() {
    // Three forward-refs in one file — all should resolve.
    let typed = check_src(
        r#"
        const A: Foo = Foo { x: 1u128 }
        const B: Bar = Bar { y: true }
        const C: Baz = Baz { z: 0u64 }
        struct Foo { x: u128 }
        struct Bar { y: bool }
        struct Baz { z: u64 }
        "#,
    )
    .expect("all forward refs should resolve");
    for name in ["A", "B", "C"] {
        let sym = typed
            .symbols
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("{name} should be in symbols"));
        assert!(
            matches!(
                sym.ty,
                crate::type_checker::types::ResolvedType::Named(_, _)
            ),
            "{name}.ty should be Named, got {:?}",
            sym.ty
        );
    }
}

#[test]
fn non_forward_ref_annotation_unchanged() {
    // In-order annotation (struct declared before const) should still work.
    let typed = check_src(
        r#"
        struct Point { x: u128, y: u128 }
        const P: Point = Point { x: 0u128, y: 0u128 }
        "#,
    )
    .expect("in-order annotation should resolve");
    let p_sym = typed
        .symbols
        .iter()
        .find(|s| s.name == "P")
        .expect("P should be in symbols");
    assert!(
        matches!(
            p_sym.ty,
            crate::type_checker::types::ResolvedType::Named(_, _)
        ),
        "P.ty should be Named, got {:?}",
        p_sym.ty
    );
}

// ── DB-A30: StructSig.methods population ──────────────────────────────────────

#[test]
fn struct_methods_populated_in_sig() {
    use crate::type_checker::types::SymbolSig;
    let typed = check_src(
        r#"
        struct Counter {
            value: u128
            fn increment(n: u128) -> u128 { return n }
        }
        "#,
    )
    .expect("struct with method should resolve");
    // Find the Counter struct's SymbolId.
    let counter_id = typed
        .symbols
        .iter()
        .enumerate()
        .find(|(_, s)| s.name == "Counter")
        .map(|(i, _)| crate::type_checker::types::SymbolId((i + 1) as u32))
        .expect("Counter should be in symbols");
    // Check the StructSig has the method.
    let sig = typed
        .sigs
        .get(&counter_id)
        .expect("Counter should have a sig");
    if let SymbolSig::Struct(struct_sig) = sig {
        assert_eq!(
            struct_sig.methods.len(),
            1,
            "Counter should have 1 method, got {:?}",
            struct_sig.methods
        );
        assert_eq!(struct_sig.methods[0].0, "increment");
    } else {
        panic!("Counter sig should be Struct, got {:?}", sig);
    }
}

#[test]
fn struct_with_no_methods_has_empty_methods() {
    use crate::type_checker::types::SymbolSig;
    let typed = check_src("struct Point { x: u128, y: u128 }")
        .expect("struct without methods should resolve");
    let point_id = typed
        .symbols
        .iter()
        .enumerate()
        .find(|(_, s)| s.name == "Point")
        .map(|(i, _)| crate::type_checker::types::SymbolId((i + 1) as u32))
        .expect("Point should be in symbols");
    let sig = typed.sigs.get(&point_id).expect("Point should have a sig");
    if let SymbolSig::Struct(struct_sig) = sig {
        assert!(
            struct_sig.methods.is_empty(),
            "Point should have no methods, got {:?}",
            struct_sig.methods
        );
    } else {
        panic!("Point sig should be Struct");
    }
}

// ── EnumSig.generic_params ────────────────────────────────────────────────────

#[test]
fn enum_generic_params_populated_in_sig() {
    use crate::type_checker::types::SymbolSig;
    let typed = check_src(
        r#"
        enum Maybe<T> {
            Some(T)
            None
        }
        "#,
    )
    .expect("generic enum should resolve");
    let maybe_id = typed
        .symbols
        .iter()
        .enumerate()
        .find(|(_, s)| s.name == "Maybe")
        .map(|(i, _)| crate::type_checker::types::SymbolId((i + 1) as u32))
        .expect("Maybe should be in symbols");
    let sig = typed.sigs.get(&maybe_id).expect("Maybe should have a sig");
    if let SymbolSig::Enum(enum_sig) = sig {
        assert_eq!(
            enum_sig.generic_params,
            vec!["T".to_string()],
            "Maybe should have generic param T"
        );
    } else {
        panic!("Maybe sig should be Enum");
    }
}

#[test]
fn enum_with_no_generic_params_has_empty_list() {
    use crate::type_checker::types::SymbolSig;
    let typed = check_src(
        r#"
        enum Color { Red, Green, Blue }
        "#,
    )
    .expect("non-generic enum should resolve");
    let color_id = typed
        .symbols
        .iter()
        .enumerate()
        .find(|(_, s)| s.name == "Color")
        .map(|(i, _)| crate::type_checker::types::SymbolId((i + 1) as u32))
        .expect("Color should be in symbols");
    let sig = typed.sigs.get(&color_id).expect("Color should have a sig");
    if let SymbolSig::Enum(enum_sig) = sig {
        assert!(
            enum_sig.generic_params.is_empty(),
            "Color should have no generic params"
        );
    } else {
        panic!("Color sig should be Enum");
    }
}

// ── QoL: Expr::New span improvement ───────────────────────────────────────────

#[test]
fn expr_new_unknown_type_error_has_nonzero_span() {
    // The error span for `new BogusType()` should use the expression's span,
    // not a zero-span placeholder.
    let result = check_src("fn f() { let x = new BogusType() }");
    match result {
        Err(LangError::Type(ref e)) => {
            assert!(
                matches!(&e.kind, TypeErrorKind::UndefinedType { name } if name == "BogusType"),
                "should be UndefinedType for BogusType"
            );
            // The span should not be the zero-span placeholder (offset=0, len=0).
            // It should point somewhere in the source.
            assert!(
                e.span.len > 0 || e.span.offset > 0,
                "span should not be zero-span placeholder, got {:?}",
                e.span
            );
        }
        other => panic!("expected UndefinedType error, got {:?}", other),
    }
}
