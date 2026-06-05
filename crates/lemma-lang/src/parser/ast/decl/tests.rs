//! Tests for `lemma_lang::parser::ast::decl` submodules.
#![allow(clippy::useless_vec)] // Test construction uses vec! for readability
//!
//! Verifies that all declaration node types can be constructed, cloned,
//! and pattern-matched. Covers the split across `mod.rs`, `types.rs`,
//! `members.rs`, and `config.rs`.

use super::*;
use crate::lexer::token::Span;
use crate::parser::ast::expr::{Expr, Literal};
use crate::parser::ast::Type;

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn span() -> Span {
    Span {
        line: 1,
        col: 1,
        offset: 0,
        len: 5,
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

// ── mod.rs types ──────────────────────────────────────────────────────────────

#[test]
fn visibility_all_variants_construct() {
    assert!(matches!(Visibility::Pub, Visibility::Pub));
    assert!(matches!(Visibility::External, Visibility::External));
    assert!(matches!(Visibility::Private, Visibility::Private));
}

#[test]
fn mutability_all_variants_construct() {
    assert!(matches!(Mutability::View, Mutability::View));
    assert!(matches!(Mutability::Pure, Mutability::Pure));
    assert!(matches!(Mutability::Payable, Mutability::Payable));
    assert!(matches!(Mutability::Default, Mutability::Default));
}

#[test]
fn annotation_arg_positional_constructs() {
    let arg = AnnotationArg::Positional(Expr::Literal(Literal::Int(42), span()));
    assert!(matches!(arg, AnnotationArg::Positional(_)));
}

#[test]
fn annotation_arg_named_constructs() {
    let arg = AnnotationArg::Named(
        "maxValue".to_string(),
        Expr::Literal(Literal::Int(1000), span()),
    );
    assert!(matches!(arg, AnnotationArg::Named(_, _)));
}

#[test]
fn generic_param_constructs() {
    let gp = GenericParam {
        name: "T".to_string(),
        bound: None,
        span: span(),
    };
    assert_eq!(gp.name, "T");
    assert!(gp.bound.is_none());
}

#[test]
fn param_constructs() {
    let p = Param {
        name: "amount".to_string(),
        ty: Type::U256,
        default_expr: None,
        span: span(),
    };
    assert_eq!(p.name, "amount");
}

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
        generic_params: vec![],
        params: vec![Param {
            name: "to".to_string(),
            ty: Type::AddressTy,
            default_expr: None,
            span: span(),
        }],
        return_type: Some(Type::Bool),
        body: Some(vec![]),
        span: span(),
    };
    assert_eq!(f.name, "transfer");
    assert_eq!(f.annotations.len(), 1);
    assert!(matches!(f.visibility, Visibility::Pub));
}

// ── types.rs types ────────────────────────────────────────────────────────────

#[test]
fn const_constructs() {
    let c = Const {
        name: "MAX_SUPPLY".to_string(),
        ty: Type::U256,
        value: Expr::Literal(Literal::Int(1_000_000), span()),
        span: span(),
    };
    assert_eq!(c.name, "MAX_SUPPLY");
}

#[test]
fn type_alias_constructs() {
    let ta = TypeAlias {
        name: "Balance".to_string(),
        ty: Type::U256,
        span: span(),
    };
    assert_eq!(ta.name, "Balance");
}

#[test]
fn struct_member_field_constructs() {
    let m = StructMember::Field(FieldDecl {
        name: "x".to_string(),
        ty: Type::I64,
        span: span(),
    });
    assert!(matches!(m, StructMember::Field(_)));
}

#[test]
fn struct_member_method_constructs() {
    let m = StructMember::Method(simple_function("get_x"));
    assert!(matches!(m, StructMember::Method(_)));
}

#[test]
fn enum_variant_constructs() {
    let v = EnumVariant {
        name: "Open".to_string(),
        fields: vec![],
        discriminant: None,
        methods: vec![],
        span: span(),
    };
    assert_eq!(v.name, "Open");
}

#[test]
fn event_field_indexed_constructs() {
    let ef = EventField {
        indexed: true,
        name: "from".to_string(),
        optional: false,
        ty: Type::AddressTy,
        span: span(),
    };
    assert!(ef.indexed);
}

#[test]
fn error_decl_constructs() {
    let err = ErrorDecl {
        name: "InsufficientBalance".to_string(),
        fields: vec![FieldDecl {
            name: "required".to_string(),
            ty: Type::U256,
            span: span(),
        }],
        span: span(),
    };
    assert_eq!(err.fields.len(), 1);
}

// ── members.rs types ──────────────────────────────────────────────────────────

#[test]
fn state_block_constructs() {
    let sb = StateBlock {
        fields: vec![StateField {
            pub_: true,
            name: "totalSupply".to_string(),
            ty: Type::U256,
            default: None,
            span: span(),
        }],
        span: span(),
    };
    assert_eq!(sb.fields.len(), 1);
    assert!(sb.fields[0].pub_);
}

#[test]
fn immutable_constructs() {
    let im = Immutable {
        name: "owner".to_string(),
        ty: Type::AddressTy,
        span: span(),
    };
    assert_eq!(im.name, "owner");
}

#[test]
fn modifier_def_constructs() {
    let md = ModifierDef {
        name: "onlyOwner".to_string(),
        params: vec![],
        body: vec![],
        span: span(),
    };
    assert_eq!(md.name, "onlyOwner");
}

#[test]
fn receive_constructs() {
    let r = Receive {
        payable: true,
        body: vec![],
        span: span(),
    };
    assert!(r.payable);
}

#[test]
fn fallback_constructs() {
    let f = Fallback_ {
        payable: false,
        body: vec![],
        span: span(),
    };
    assert!(!f.payable);
}

#[test]
fn contract_member_all_variants_construct() {
    let members: Vec<ContractMember> = vec![
        ContractMember::State(StateBlock {
            fields: vec![],
            span: span(),
        }),
        ContractMember::Const(Const {
            name: "C".to_string(),
            ty: Type::U64,
            value: Expr::Literal(Literal::Int(0), span()),
            span: span(),
        }),
        ContractMember::Immutable(Immutable {
            name: "owner".to_string(),
            ty: Type::AddressTy,
            span: span(),
        }),
        ContractMember::Function(simple_function("foo")),
        ContractMember::Event(Event {
            name: "Ev".to_string(),
            anonymous: false,
            fields: vec![],
            span: span(),
        }),
        ContractMember::Modifier(ModifierDef {
            name: "mod".to_string(),
            params: vec![],
            body: vec![],
            span: span(),
        }),
        ContractMember::Receive(Receive {
            payable: true,
            body: vec![],
            span: span(),
        }),
        ContractMember::Fallback(Fallback_ {
            payable: false,
            body: vec![],
            span: span(),
        }),
        ContractMember::Struct(Struct {
            name: "S".to_string(),
            generic_params: vec![],
            members: vec![],
            span: span(),
        }),
        ContractMember::Enum(Enum {
            name: "E".to_string(),
            generic_params: vec![],
            variants: vec![],
            span: span(),
        }),
        ContractMember::ErrorDecl(ErrorDecl {
            name: "Err".to_string(),
            fields: vec![],
            span: span(),
        }),
        ContractMember::Config(Config {
            entries: vec![],
            span: span(),
        }),
        ContractMember::Metadata(Metadata {
            entries: vec![],
            span: span(),
        }),
    ];
    assert_eq!(members.len(), 13);
}

#[test]
fn interface_member_variants_construct() {
    let members = vec![
        InterfaceMember::Function(simple_function("transfer")),
        InterfaceMember::Event(Event {
            name: "Transfer".to_string(),
            anonymous: false,
            fields: vec![],
            span: span(),
        }),
    ];
    assert_eq!(members.len(), 2);
}

#[test]
fn trait_member_variants_construct() {
    let members = vec![
        TraitMember::State(StateBlock {
            fields: vec![],
            span: span(),
        }),
        TraitMember::Function(simple_function("hook")),
    ];
    assert_eq!(members.len(), 2);
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

// ── config.rs types ───────────────────────────────────────────────────────────

#[test]
fn import_names_named_constructs() {
    let names = ImportNames::Named(vec!["Token".to_string(), "IToken".to_string()]);
    if let ImportNames::Named(v) = &names {
        assert_eq!(v.len(), 2);
    } else {
        panic!("expected Named");
    }
}

#[test]
fn import_names_star_constructs() {
    let names = ImportNames::Star("std".to_string());
    assert!(matches!(names, ImportNames::Star(_)));
}

#[test]
fn config_value_all_variants_construct() {
    let values = vec![
        ConfigValue::Str("hello".to_string()),
        ConfigValue::Int(42),
        ConfigValue::Bool(true),
        ConfigValue::Percent(15),
        ConfigValue::Unit(6, UnitKind::Months),
        ConfigValue::Object(vec![]),
        ConfigValue::Ident("TokenType".to_string()),
    ];
    assert_eq!(values.len(), 7);
}

#[test]
fn unit_kind_all_variants_construct() {
    let kinds = [
        UnitKind::Ether,
        UnitKind::Gwei,
        UnitKind::Minutes,
        UnitKind::Hours,
        UnitKind::Days,
        UnitKind::Seconds,
        UnitKind::Months,
    ];
    for k in &kinds {
        assert_eq!(k.clone(), k.clone());
    }
}

#[test]
fn config_entry_constructs() {
    let entry = ConfigEntry {
        key: "name".to_string(),
        value: ConfigValue::Str("MyToken".to_string()),
        span: span(),
    };
    assert_eq!(entry.key, "name");
}

#[test]
fn using_constructs() {
    let u = Using {
        library: "SafeMath".to_string(),
        for_type: Type::U256,
        span: span(),
    };
    assert_eq!(u.library, "SafeMath");
}
