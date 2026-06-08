//! Tests for `lemma_lang::parser::ast`.
//!
//! Verifies that all major AST node types can be constructed, cloned,
//! and pattern-matched. No parser calls — pure construction tests.
//! 100% public API coverage per AGENTS.md §11.1.

use super::*;
use crate::lexer::token::Span;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn span() -> Span {
    Span {
        line: 1,
        col: 1,
        offset: 0,
        len: 5,
    }
}

fn ident_expr(name: &str) -> Expr {
    Expr::Ident(name.to_string(), span())
}

fn int_expr(n: u128) -> Expr {
    Expr::Literal(Literal::Int(n), span())
}

fn bool_type() -> Type {
    Type::Bool
}

fn simple_param(name: &str) -> Param {
    Param {
        name: name.to_string(),
        ty: Type::U64,
        default_expr: None,
        span: span(),
    }
}

fn simple_function(name: &str) -> Function {
    Function {
        name: name.to_string(),
        annotations: vec![],
        visibility: Visibility::Private,
        mutability: Mutability::Default,
        generic_params: vec![],
        params: vec![],
        return_type: None,
        body: Some(vec![]),
        span: span(),
    }
}

// ── Ast root ──────────────────────────────────────────────────────────────────

#[test]
fn ast_constructs_empty() {
    let ast = Ast {
        items: vec![],
        span: span(),
    };
    assert!(ast.items.is_empty());
}

#[test]
fn ast_clones_equal_to_original() {
    let ast = Ast {
        items: vec![],
        span: span(),
    };
    assert_eq!(ast.clone(), ast);
}

// ── Item variants ─────────────────────────────────────────────────────────────

#[test]
fn item_contract_variant_constructs() {
    let contract = Contract {
        name: "Foo".to_string(),
        implements: vec![],
        uses: vec![],
        members: vec![],
        span: span(),
    };
    let item = Item::Contract(contract);
    assert!(matches!(item, Item::Contract(_)));
}

#[test]
fn item_function_variant_constructs() {
    let item = Item::Function(simple_function("transfer"));
    assert!(matches!(item, Item::Function(_)));
}

#[test]
fn item_import_variant_constructs() {
    let import = Import {
        names: ImportNames::Named(vec!["Token".to_string()]),
        from: "@std/token".to_string(),
        span: span(),
    };
    let item = Item::Import(import);
    assert!(matches!(item, Item::Import(_)));
}

// ── Type variants ─────────────────────────────────────────────────────────────

#[test]
fn type_primitives_construct() {
    let types = [
        Type::U8,
        Type::U16,
        Type::U32,
        Type::U64,
        Type::U128,
        Type::U256,
        Type::I8,
        Type::I16,
        Type::I32,
        Type::I64,
        Type::I128,
        Type::I256,
        Type::Bool,
        Type::StringTy,
        Type::CharTy,
        Type::AddressTy,
        Type::HashTy,
        Type::Bytes,
    ];
    for ty in &types {
        assert_eq!(ty.clone(), ty.clone());
    }
}

#[test]
fn type_bytes_n_constructs() {
    let ty = Type::BytesN(32);
    assert_eq!(ty, Type::BytesN(32));
    assert_ne!(ty, Type::BytesN(16));
}

#[test]
fn type_array_constructs() {
    let ty = Type::Array(Box::new(Type::U128));
    assert!(matches!(ty, Type::Array(_)));
}

#[test]
fn type_fixed_array_constructs() {
    let ty = Type::FixedArray(Box::new(Type::U8), 32);
    assert!(matches!(ty, Type::FixedArray(_, 32)));
}

#[test]
fn type_map_constructs() {
    let ty = Type::Map(Box::new(Type::AddressTy), Box::new(Type::U128));
    assert!(matches!(ty, Type::Map(_, _)));
}

#[test]
fn type_fast_map_constructs() {
    let ty = Type::FastMap(Box::new(Type::AddressTy), Box::new(Type::U128));
    assert!(matches!(ty, Type::FastMap(_, _)));
}

#[test]
fn type_set_constructs() {
    let ty = Type::Set(Box::new(Type::AddressTy));
    assert!(matches!(ty, Type::Set(_)));
}

#[test]
fn type_option_constructs() {
    let ty = Type::Option_(Box::new(Type::U64));
    assert!(matches!(ty, Type::Option_(_)));
}

#[test]
fn type_result_constructs() {
    let ty = Type::Result_(Box::new(Type::U64), Box::new(Type::StringTy));
    assert!(matches!(ty, Type::Result_(_, _)));
}

#[test]
fn type_decimal_constructs() {
    let ty = Type::Decimal(18);
    assert_eq!(ty, Type::Decimal(18));
}

#[test]
fn type_tuple_constructs() {
    let ty = Type::Tuple(vec![Type::U64, Type::Bool, Type::StringTy]);
    assert!(matches!(ty, Type::Tuple(_)));
    if let Type::Tuple(inner) = &ty {
        assert_eq!(inner.len(), 3);
    }
}

#[test]
fn type_fn_constructs() {
    let ty = Type::Fn(vec![Type::U64, Type::AddressTy], Box::new(Type::Bool));
    assert!(matches!(ty, Type::Fn(_, _)));
}

#[test]
fn type_named_constructs() {
    let ty = Type::Named("MyToken".to_string(), vec![]);
    assert!(matches!(ty, Type::Named(_, _)));
}

#[test]
fn type_named_with_generics_constructs() {
    let ty = Type::Named("Pair".to_string(), vec![Type::U64, Type::AddressTy]);
    if let Type::Named(name, args) = &ty {
        assert_eq!(name, "Pair");
        assert_eq!(args.len(), 2);
    } else {
        panic!("expected Named type");
    }
}

#[test]
fn type_nested_map_constructs() {
    // Map<Address, Array<u128>>
    let ty = Type::Map(
        Box::new(Type::AddressTy),
        Box::new(Type::Array(Box::new(Type::U128))),
    );
    assert!(matches!(ty, Type::Map(_, _)));
}

// ── Expr variants ─────────────────────────────────────────────────────────────

#[test]
fn expr_literal_int_constructs() {
    let e = Expr::Literal(Literal::Int(42), span());
    assert!(matches!(e, Expr::Literal(Literal::Int(42), _)));
}

#[test]
fn expr_literal_bool_constructs() {
    let e = Expr::Literal(Literal::Bool(true), span());
    assert!(matches!(e, Expr::Literal(Literal::Bool(true), _)));
}

#[test]
fn expr_literal_str_constructs() {
    let e = Expr::Literal(Literal::Str("hello".to_string()), span());
    assert!(matches!(e, Expr::Literal(Literal::Str(_), _)));
}

#[test]
fn expr_ident_constructs() {
    let e = ident_expr("balance");
    assert!(matches!(e, Expr::Ident(_, _)));
}

#[test]
fn expr_tuple_constructs() {
    let e = Expr::Tuple(vec![int_expr(1), int_expr(2)], span());
    assert!(matches!(e, Expr::Tuple(_, _)));
}

#[test]
fn expr_array_constructs() {
    let e = Expr::Array(vec![int_expr(1), int_expr(2), int_expr(3)], span());
    assert!(matches!(e, Expr::Array(_, _)));
}

#[test]
fn expr_struct_literal_constructs() {
    let e = Expr::Struct_ {
        name: "Position".to_string(),
        fields: vec![
            ("x".to_string(), int_expr(0)),
            ("y".to_string(), int_expr(0)),
        ],
        spread: None,
        span: span(),
    };
    assert!(matches!(e, Expr::Struct_ { .. }));
}

#[test]
fn expr_struct_with_spread_constructs() {
    let e = Expr::Struct_ {
        name: "Position".to_string(),
        fields: vec![("x".to_string(), int_expr(1))],
        spread: Some(Box::new(ident_expr("base"))),
        span: span(),
    };
    if let Expr::Struct_ { spread, .. } = &e {
        assert!(spread.is_some());
    } else {
        panic!("expected Struct_");
    }
}

#[test]
fn expr_call_constructs() {
    let e = Expr::Call {
        callee: Box::new(ident_expr("transfer")),
        opts: None,
        args: vec![
            CallArg::Positional(ident_expr("to")),
            CallArg::Positional(int_expr(100)),
        ],
        span: span(),
    };
    assert!(matches!(e, Expr::Call { .. }));
}

#[test]
fn expr_call_with_opts_constructs() {
    let opts = CallOpts {
        value: Some(Box::new(int_expr(1000))),
        gas: None,
        salt: None,
        span: span(),
    };
    let e = Expr::Call {
        callee: Box::new(ident_expr("deposit")),
        opts: Some(opts),
        args: vec![],
        span: span(),
    };
    if let Expr::Call { opts, .. } = &e {
        assert!(opts.is_some());
    } else {
        panic!("expected Call");
    }
}

#[test]
fn expr_index_constructs() {
    let e = Expr::Index(Box::new(ident_expr("arr")), Box::new(int_expr(0)), span());
    assert!(matches!(e, Expr::Index(_, _, _)));
}

#[test]
fn expr_member_constructs() {
    let e = Expr::Member(Box::new(ident_expr("self")), "balance".to_string(), span());
    assert!(matches!(e, Expr::Member(_, _, _)));
}

#[test]
fn expr_unary_constructs() {
    let e = Expr::Unary(UnaryOp::Not, Box::new(ident_expr("flag")), span());
    assert!(matches!(e, Expr::Unary(UnaryOp::Not, _, _)));
}

#[test]
fn expr_binary_constructs() {
    let e = Expr::Binary(
        BinaryOp::Add,
        Box::new(int_expr(1)),
        Box::new(int_expr(2)),
        span(),
    );
    assert!(matches!(e, Expr::Binary(BinaryOp::Add, _, _, _)));
}

#[test]
fn expr_ternary_constructs() {
    let e = Expr::Ternary {
        cond: Box::new(ident_expr("ok")),
        then: Box::new(int_expr(1)),
        else_: Box::new(int_expr(0)),
        span: span(),
    };
    assert!(matches!(e, Expr::Ternary { .. }));
}

#[test]
fn expr_nullish_constructs() {
    let e = Expr::Nullish(Box::new(ident_expr("opt")), Box::new(int_expr(0)), span());
    assert!(matches!(e, Expr::Nullish(_, _, _)));
}

#[test]
fn expr_try_constructs() {
    let e = Expr::Try_(Box::new(ident_expr("result")), span());
    assert!(matches!(e, Expr::Try_(_, _)));
}

#[test]
fn expr_lambda_expr_body_constructs() {
    let e = Expr::Lambda {
        params: vec![simple_param("x")],
        body: LambdaBody::Expr(Box::new(ident_expr("x"))),
        span: span(),
    };
    assert!(matches!(e, Expr::Lambda { .. }));
}

#[test]
fn expr_lambda_block_body_constructs() {
    let e = Expr::Lambda {
        params: vec![simple_param("x")],
        body: LambdaBody::Block(vec![]),
        span: span(),
    };
    if let Expr::Lambda { body, .. } = &e {
        assert!(matches!(body, LambdaBody::Block(_)));
    } else {
        panic!("expected Lambda");
    }
}

#[test]
fn expr_new_constructs() {
    let e = Expr::New {
        ty: "MyContract".to_string(),
        opts: None,
        args: vec![],
        span: span(),
    };
    assert!(matches!(e, Expr::New { .. }));
}

#[test]
fn expr_match_constructs() {
    let arm = MatchArm {
        pattern: Pattern::Wildcard(span()),
        guard: None,
        body: MatchBody::Expr(int_expr(0)),
        span: span(),
    };
    let e = Expr::Match_(Box::new(ident_expr("x")), vec![arm], span());
    assert!(matches!(e, Expr::Match_(_, _, _)));
}

#[test]
fn expr_if_constructs() {
    let e = Expr::If_ {
        cond: Box::new(ident_expr("ok")),
        then: vec![],
        else_: None,
        span: span(),
    };
    assert!(matches!(e, Expr::If_ { .. }));
}

#[test]
fn expr_template_constructs() {
    let e = Expr::Template(
        vec![
            TemplateExprSegment::Literal("hello ".to_string()),
            TemplateExprSegment::Interpolation(ident_expr("name")),
        ],
        span(),
    );
    assert!(matches!(e, Expr::Template(_, _)));
}

#[test]
fn expr_assign_constructs() {
    let e = Expr::Assign_(
        Box::new(ident_expr("x")),
        AssignOp::Add,
        Box::new(int_expr(1)),
        span(),
    );
    assert!(matches!(e, Expr::Assign_(_, AssignOp::Add, _, _)));
}

// ── Stmt variants ─────────────────────────────────────────────────────────────

#[test]
fn stmt_let_constructs() {
    let s = Stmt::Let {
        mutable: false,
        pattern: Pattern::Ident("x".to_string(), span()),
        ty: Some(Type::U64),
        expr: int_expr(42),
        span: span(),
    };
    assert!(matches!(s, Stmt::Let { .. }));
}

#[test]
fn stmt_if_constructs() {
    let s = Stmt::If {
        cond: ident_expr("ok"),
        then: vec![],
        else_: None,
        span: span(),
    };
    assert!(matches!(s, Stmt::If { .. }));
}

#[test]
fn stmt_return_constructs() {
    let s = Stmt::Return(Some(int_expr(0)), span());
    assert!(matches!(s, Stmt::Return(Some(_), _)));
}

#[test]
fn stmt_return_unit_constructs() {
    let s = Stmt::Return(None, span());
    assert!(matches!(s, Stmt::Return(None, _)));
}

#[test]
fn stmt_emit_constructs() {
    let s = Stmt::Emit {
        event: "Transfer".to_string(),
        fields: vec![("from".to_string(), ident_expr("sender"))],
        span: span(),
    };
    assert!(matches!(s, Stmt::Emit { .. }));
}

#[test]
fn stmt_placeholder_constructs() {
    let s = Stmt::Placeholder(span());
    assert!(matches!(s, Stmt::Placeholder(_)));
}

#[test]
fn stmt_break_continue_construct() {
    assert!(matches!(Stmt::Break(span()), Stmt::Break(_)));
    assert!(matches!(Stmt::Continue(span()), Stmt::Continue(_)));
}

#[test]
fn stmt_while_constructs() {
    let s = Stmt::While {
        cond: ident_expr("running"),
        body: vec![],
        span: span(),
    };
    assert!(matches!(s, Stmt::While { .. }));
}

#[test]
fn stmt_loop_constructs() {
    let s = Stmt::Loop {
        body: vec![],
        span: span(),
    };
    assert!(matches!(s, Stmt::Loop { .. }));
}

#[test]
fn stmt_try_constructs() {
    let s = Stmt::Try {
        body: vec![],
        catch_var: "e".to_string(),
        catch_body: vec![],
        span: span(),
    };
    assert!(matches!(s, Stmt::Try { .. }));
}

#[test]
fn stmt_unchecked_constructs() {
    let s = Stmt::Unchecked(vec![], span());
    assert!(matches!(s, Stmt::Unchecked(_, _)));
}

#[test]
fn stmt_assert_constructs() {
    let s = Stmt::Assert {
        cond: ident_expr("ok"),
        msg: Some(Expr::Literal(Literal::Str("failed".to_string()), span())),
        span: span(),
    };
    assert!(matches!(s, Stmt::Assert { .. }));
}

#[test]
fn stmt_revert_constructs() {
    let s = Stmt::Revert {
        msg: None,
        span: span(),
    };
    assert!(matches!(s, Stmt::Revert { .. }));
}

// ── Pattern variants ──────────────────────────────────────────────────────────

#[test]
fn pattern_wildcard_constructs() {
    let p = Pattern::Wildcard(span());
    assert!(matches!(p, Pattern::Wildcard(_)));
}

#[test]
fn pattern_ident_constructs() {
    let p = Pattern::Ident("x".to_string(), span());
    assert!(matches!(p, Pattern::Ident(_, _)));
}

#[test]
fn pattern_literal_constructs() {
    let p = Pattern::Literal(Literal::Int(42), span());
    assert!(matches!(p, Pattern::Literal(_, _)));
}

#[test]
fn pattern_struct_constructs() {
    let p = Pattern::Struct_ {
        name: "Point".to_string(),
        fields: vec![("x".to_string(), Pattern::Ident("x".to_string(), span()))],
        span: span(),
    };
    assert!(matches!(p, Pattern::Struct_ { .. }));
}

#[test]
fn pattern_tuple_constructs() {
    let p = Pattern::Tuple(
        vec![
            Pattern::Ident("a".to_string(), span()),
            Pattern::Wildcard(span()),
        ],
        span(),
    );
    assert!(matches!(p, Pattern::Tuple(_, _)));
}

#[test]
fn pattern_enum_variant_constructs() {
    let p = Pattern::EnumVariant {
        name: "Some".to_string(),
        inner: Some(vec![Pattern::Ident("x".to_string(), span())]),
        span: span(),
    };
    assert!(matches!(p, Pattern::EnumVariant { .. }));
}

#[test]
fn pattern_rest_constructs() {
    let p = Pattern::Rest(span());
    assert!(matches!(p, Pattern::Rest(_)));
}

// ── Contract ──────────────────────────────────────────────────────────────────

#[test]
fn contract_constructs_with_all_fields() {
    let contract = Contract {
        name: "MyToken".to_string(),
        implements: vec!["IToken".to_string()],
        uses: vec!["Ownable".to_string()],
        members: vec![ContractMember::State(StateBlock {
            fields: vec![StateField {
                pub_: true,
                name: "totalSupply".to_string(),
                ty: Type::U256,
                default: Some(int_expr(0)),
                span: span(),
            }],
            span: span(),
        })],
        span: span(),
    };
    assert_eq!(contract.name, "MyToken");
    assert_eq!(contract.implements.len(), 1);
    assert_eq!(contract.uses.len(), 1);
    assert_eq!(contract.members.len(), 1);
}

// ── Function ──────────────────────────────────────────────────────────────────

#[test]
fn function_constructs_with_all_fields() {
    let f = Function {
        name: "transfer".to_string(),
        annotations: vec![Annotation {
            name: "onlyOwner".to_string(),
            args: vec![],
            span: span(),
        }],
        visibility: Visibility::Pub,
        mutability: Mutability::Payable,
        generic_params: vec![GenericParam {
            name: "T".to_string(),
            bound: Some(Type::Named("Comparable".to_string(), vec![])),
            span: span(),
        }],
        params: vec![
            Param {
                name: "to".to_string(),
                ty: Type::AddressTy,
                default_expr: None,
                span: span(),
            },
            Param {
                name: "amount".to_string(),
                ty: Type::U256,
                default_expr: None,
                span: span(),
            },
        ],
        return_type: Some(Type::Bool),
        body: Some(vec![Stmt::Return(
            Some(Expr::Literal(Literal::Bool(true), span())),
            span(),
        )]),
        span: span(),
    };
    assert_eq!(f.name, "transfer");
    assert_eq!(f.annotations.len(), 1);
    assert!(matches!(f.visibility, Visibility::Pub));
    assert!(matches!(f.mutability, Mutability::Payable));
    assert_eq!(f.generic_params.len(), 1);
    assert_eq!(f.params.len(), 2);
    assert!(f.return_type.is_some());
    assert!(f.body.is_some());
}

// ── Annotation ────────────────────────────────────────────────────────────────

#[test]
fn annotation_positional_arg_constructs() {
    let ann = Annotation {
        name: "cooldown".to_string(),
        args: vec![AnnotationArg::Positional(int_expr(3600))],
        span: span(),
    };
    assert_eq!(ann.args.len(), 1);
    assert!(matches!(ann.args[0], AnnotationArg::Positional(_)));
}

#[test]
fn annotation_named_arg_constructs() {
    let ann = Annotation {
        name: "agentCallable".to_string(),
        args: vec![AnnotationArg::Named(
            "maxValueOut".to_string(),
            int_expr(1000),
        )],
        span: span(),
    };
    assert!(matches!(ann.args[0], AnnotationArg::Named(_, _)));
}

// ── Struct / Enum ─────────────────────────────────────────────────────────────

#[test]
fn struct_constructs() {
    let s = Struct {
        name: "Position".to_string(),
        generic_params: vec![],
        members: vec![
            StructMember::Field(FieldDecl {
                name: "x".to_string(),
                ty: Type::I64,
                span: span(),
            }),
            StructMember::Field(FieldDecl {
                name: "y".to_string(),
                ty: Type::I64,
                span: span(),
            }),
        ],
        span: span(),
    };
    assert_eq!(s.members.len(), 2);
}

#[test]
fn enum_constructs() {
    let e = Enum {
        name: "OrderStatus".to_string(),
        generic_params: vec![],
        variants: vec![
            EnumVariant {
                name: "Open".to_string(),
                fields: vec![],
                discriminant: None,
                span: span(),
            },
            EnumVariant {
                name: "Filled".to_string(),
                fields: vec![],
                discriminant: None,
                span: span(),
            },
            EnumVariant {
                name: "Cancelled".to_string(),
                fields: vec![],
                discriminant: None,
                span: span(),
            },
        ],
        methods: vec![],
        span: span(),
    };
    assert_eq!(e.variants.len(), 3);
}

// ── Event / Error ─────────────────────────────────────────────────────────────

#[test]
fn event_constructs() {
    let ev = Event {
        name: "Transfer".to_string(),
        anonymous: false,
        fields: vec![
            EventField {
                indexed: true,
                name: "from".to_string(),
                optional: false,
                ty: Type::AddressTy,
                span: span(),
            },
            EventField {
                indexed: true,
                name: "to".to_string(),
                optional: false,
                ty: Type::AddressTy,
                span: span(),
            },
            EventField {
                indexed: false,
                name: "amount".to_string(),
                optional: false,
                ty: Type::U256,
                span: span(),
            },
        ],
        methods: vec![],
        span: span(),
    };
    assert_eq!(ev.fields.len(), 3);
    assert!(ev.fields[0].indexed);
    assert!(!ev.anonymous);
}

#[test]
fn error_decl_constructs() {
    let err = ErrorDecl {
        name: "InsufficientBalance".to_string(),
        fields: vec![
            FieldDecl {
                name: "required".to_string(),
                ty: Type::U256,
                span: span(),
            },
            FieldDecl {
                name: "available".to_string(),
                ty: Type::U256,
                span: span(),
            },
        ],
        span: span(),
    };
    assert_eq!(err.fields.len(), 2);
}

// ── Config / Metadata ─────────────────────────────────────────────────────────

#[test]
fn config_constructs() {
    let cfg = Config {
        entries: vec![
            ConfigEntry {
                key: "name".to_string(),
                value: ConfigValue::Str("MyToken".to_string()),
                span: span(),
            },
            ConfigEntry {
                key: "supply".to_string(),
                value: ConfigValue::Int(1_000_000),
                span: span(),
            },
            ConfigEntry {
                key: "transferable".to_string(),
                value: ConfigValue::Bool(true),
                span: span(),
            },
            ConfigEntry {
                key: "fee".to_string(),
                value: ConfigValue::Percent(15),
                span: span(),
            },
            ConfigEntry {
                key: "lockup".to_string(),
                value: ConfigValue::Unit(6, UnitKind::Days),
                span: span(),
            },
        ],
        span: span(),
    };
    assert_eq!(cfg.entries.len(), 5);
}

#[test]
fn config_value_object_constructs() {
    let nested = ConfigValue::Object(vec![ConfigEntry {
        key: "twitter".to_string(),
        value: ConfigValue::Str("@example".to_string()),
        span: span(),
    }]);
    assert!(matches!(nested, ConfigValue::Object(_)));
}

// ── Import / Using ────────────────────────────────────────────────────────────

#[test]
fn import_named_constructs() {
    let imp = Import {
        names: ImportNames::Named(vec!["Token".to_string(), "IToken".to_string()]),
        from: "@std/token".to_string(),
        span: span(),
    };
    if let ImportNames::Named(names) = &imp.names {
        assert_eq!(names.len(), 2);
    } else {
        panic!("expected Named");
    }
}

#[test]
fn import_star_constructs() {
    let imp = Import {
        names: ImportNames::Star("std".to_string()),
        from: "@std".to_string(),
        span: span(),
    };
    assert!(matches!(imp.names, ImportNames::Star(_)));
}

#[test]
fn using_constructs() {
    let u = Using {
        library: "SafeMath".to_string(),
        for_type: Type::U256,
        span: span(),
    };
    assert_eq!(u.library, "SafeMath");
    assert_eq!(u.for_type, Type::U256);
}

// ── TokenDecl ─────────────────────────────────────────────────────────────────

#[test]
fn token_decl_constructs() {
    let td = TokenDecl {
        name: "MyToken".to_string(),
        extends: "Token".to_string(),
        members: vec![],
        span: span(),
    };
    assert_eq!(td.extends, "Token");
}

// ── Interface / Trait / Library ───────────────────────────────────────────────

#[test]
fn interface_constructs() {
    let iface = Interface {
        name: "IToken".to_string(),
        members: vec![InterfaceMember::Function(simple_function("transfer"))],
        span: span(),
    };
    assert_eq!(iface.members.len(), 1);
}

#[test]
fn trait_constructs() {
    let t = Trait {
        name: "Ownable".to_string(),
        members: vec![TraitMember::Function(simple_function("onlyOwner"))],
        span: span(),
    };
    assert_eq!(t.members.len(), 1);
}

#[test]
fn library_constructs() {
    let lib = Library {
        name: "SafeMath".to_string(),
        functions: vec![simple_function("add"), simple_function("sub")],
        span: span(),
    };
    assert_eq!(lib.functions.len(), 2);
}

// ── UnitKind ──────────────────────────────────────────────────────────────────

#[test]
fn unit_kind_all_variants_construct() {
    let kinds = [
        UnitKind::Ether,
        UnitKind::Gwei,
        UnitKind::Minutes,
        UnitKind::Hours,
        UnitKind::Days,
        UnitKind::Seconds,
    ];
    for k in &kinds {
        assert_eq!(k.clone(), k.clone());
    }
}

// ── Literal variants ──────────────────────────────────────────────────────────

#[test]
fn literal_all_variants_construct() {
    let _ = Literal::Int(42);
    let _ = Literal::IntTyped {
        value: 42,
        suffix: "u128".to_string(),
    };
    let _ = Literal::Hex("DEADBEEF".to_string());
    let _ = Literal::Bin("1010".to_string());
    let _ = Literal::Float("3.14".to_string());
    let _ = Literal::Str("hello".to_string());
    let _ = Literal::Bytes(vec![0xDE, 0xAD]);
    let _ = Literal::Char('a');
    let _ = Literal::Bool(false);
    let _ = Literal::Address("lem1q...".to_string());
    let _ = Literal::Unit(Box::new(int_expr(1)), UnitKind::Ether);
}

// ── Clone round-trips ─────────────────────────────────────────────────────────

#[test]
fn all_major_types_clone_equal() {
    let ast = Ast {
        items: vec![Item::Contract(Contract {
            name: "Test".to_string(),
            implements: vec![],
            uses: vec![],
            members: vec![],
            span: span(),
        })],
        span: span(),
    };
    assert_eq!(ast.clone(), ast);
}

// ── Visibility / Mutability ───────────────────────────────────────────────────

#[test]
fn visibility_variants_construct() {
    assert!(matches!(Visibility::Pub, Visibility::Pub));
    assert!(matches!(Visibility::External, Visibility::External));
    assert!(matches!(Visibility::Private, Visibility::Private));
}

#[test]
fn mutability_variants_construct() {
    assert!(matches!(Mutability::View, Mutability::View));
    assert!(matches!(Mutability::Pure, Mutability::Pure));
    assert!(matches!(Mutability::Payable, Mutability::Payable));
    assert!(matches!(Mutability::Default, Mutability::Default));
}

// ── ForIter ───────────────────────────────────────────────────────────────────

#[test]
fn for_iter_of_constructs() {
    let fi = ForIter::Of(ident_expr("items"));
    assert!(matches!(fi, ForIter::Of(_)));
}

#[test]
fn for_iter_in_constructs() {
    let fi = ForIter::In(int_expr(0), span(), int_expr(10), false);
    assert!(matches!(fi, ForIter::In(_, _, _, false)));
}

#[test]
fn for_iter_in_inclusive_constructs() {
    let fi = ForIter::In(int_expr(0), span(), int_expr(10), true);
    assert!(matches!(fi, ForIter::In(_, _, _, true)));
}

// ── MatchArm with guard ───────────────────────────────────────────────────────

#[test]
fn match_arm_with_guard_constructs() {
    let arm = MatchArm {
        pattern: Pattern::Ident("x".to_string(), span()),
        guard: Some(Expr::Binary(
            BinaryOp::Gt,
            Box::new(ident_expr("x")),
            Box::new(int_expr(0)),
            span(),
        )),
        body: MatchBody::Expr(ident_expr("x")),
        span: span(),
    };
    assert!(arm.guard.is_some());
}

// ── TypeAlias ─────────────────────────────────────────────────────────────────

#[test]
fn type_alias_constructs() {
    let ta = TypeAlias {
        name: "Balance".to_string(),
        ty: Type::U256,
        span: span(),
    };
    assert_eq!(ta.name, "Balance");
    assert_eq!(ta.ty, Type::U256);
}

// ── Const ─────────────────────────────────────────────────────────────────────

#[test]
fn const_constructs() {
    let c = Const {
        name: "MAX_SUPPLY".to_string(),
        ty: Type::U256,
        value: int_expr(1_000_000),
        span: span(),
    };
    assert_eq!(c.name, "MAX_SUPPLY");
}

// ── bool_type helper used in tests ────────────────────────────────────────────

#[test]
fn bool_type_helper_returns_bool() {
    assert_eq!(bool_type(), Type::Bool);
}
