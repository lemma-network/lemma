//! Tests for [`ResolvedType`], [`SymbolId`], [`SymbolInfo`], and [`SymbolKind`].

use crate::lexer::token::Span;

use super::{ResolvedType, SymbolId, SymbolInfo, SymbolKind};

fn unknown() -> ResolvedType {
    ResolvedType::Unknown
}

// ── ResolvedType construction ──────────────────────────────────────────────────

#[test]
fn resolved_type_primitive_variants_construct() {
    let _: Vec<ResolvedType> = vec![
        ResolvedType::U8,
        ResolvedType::U16,
        ResolvedType::U32,
        ResolvedType::U64,
        ResolvedType::U128,
        ResolvedType::U256,
        ResolvedType::I8,
        ResolvedType::I16,
        ResolvedType::I32,
        ResolvedType::I64,
        ResolvedType::I128,
        ResolvedType::I256,
        ResolvedType::IntLiteral,
        ResolvedType::Bool,
        ResolvedType::StringTy,
        ResolvedType::CharTy,
        ResolvedType::AddressTy,
        ResolvedType::HashTy,
        ResolvedType::Bytes,
        ResolvedType::BytesN(32),
        ResolvedType::Decimal(18),
        ResolvedType::Unit,
        ResolvedType::Unknown,
    ];
}

#[test]
fn resolved_type_compound_variants_construct() {
    let elem = Box::new(ResolvedType::U128);
    let _ = ResolvedType::Array(elem.clone());
    let _ = ResolvedType::FixedArray(elem.clone(), 10);
    let _ = ResolvedType::Map(elem.clone(), Box::new(ResolvedType::Bool));
    let _ = ResolvedType::FastMap(elem.clone(), Box::new(ResolvedType::StringTy));
    let _ = ResolvedType::Set(elem.clone());
    let _ = ResolvedType::Option_(elem.clone());
    let _ = ResolvedType::Result_(elem.clone(), Box::new(ResolvedType::StringTy));
    let _ = ResolvedType::Tuple(vec![ResolvedType::U128, ResolvedType::Bool]);
    let _ = ResolvedType::Fn(vec![ResolvedType::U128], elem);
}

#[test]
fn resolved_type_named_and_param_variants_construct() {
    // Named now carries a SymbolId (resolved in 3b/3c) instead of a String.
    let _ = ResolvedType::Named(SymbolId(1), vec![]);
    let _ = ResolvedType::Named(SymbolId(2), vec![ResolvedType::U128, ResolvedType::Bool]);
    let _ = ResolvedType::TypeParam("T".into());
}

#[test]
fn resolved_type_int_literal_constructs_and_predicates() {
    let lit = ResolvedType::IntLiteral;
    assert!(lit.is_int_literal());
    assert!(lit.is_numeric());
    assert!(!lit.is_integer());
    assert!(!lit.is_unsigned_int());
    assert!(!lit.is_signed_int());
    assert!(lit.is_concrete()); // IntLiteral IS concrete (not Unknown/TypeParam)
}

#[test]
fn resolved_type_bit_width_integers() {
    assert_eq!(ResolvedType::U8.bit_width(), Some(8));
    assert_eq!(ResolvedType::U128.bit_width(), Some(128));
    assert_eq!(ResolvedType::U256.bit_width(), Some(256));
    assert_eq!(ResolvedType::I8.bit_width(), Some(8));
    assert_eq!(ResolvedType::I256.bit_width(), Some(256));
    assert_eq!(ResolvedType::IntLiteral.bit_width(), None);
    assert_eq!(ResolvedType::Bool.bit_width(), None);
}

#[test]
fn resolved_type_coerce_int_literal_to_concrete() {
    let lit = ResolvedType::IntLiteral;
    assert_eq!(
        lit.coerce_int_literal(&ResolvedType::U8),
        Some(&ResolvedType::U8)
    );
    assert_eq!(
        lit.coerce_int_literal(&ResolvedType::I128),
        Some(&ResolvedType::I128)
    );
    // Non-integer target → None.
    assert_eq!(lit.coerce_int_literal(&ResolvedType::Bool), None);
    // Non-literal self → None.
    assert_eq!(
        ResolvedType::U8.coerce_int_literal(&ResolvedType::U16),
        None
    );
}

#[test]
fn resolved_type_display_name_round_trips() {
    assert_eq!(ResolvedType::U128.display_name(), "u128");
    assert_eq!(ResolvedType::Bool.display_name(), "bool");
    assert_eq!(ResolvedType::IntLiteral.display_name(), "{integer}");
    assert_eq!(ResolvedType::StringTy.display_name(), "string");
    assert_eq!(ResolvedType::BytesN(4).display_name(), "bytes4");
    assert_eq!(ResolvedType::Decimal(18).display_name(), "decimal(18)");
    assert_eq!(ResolvedType::Unit.display_name(), "()");
    assert_eq!(ResolvedType::Unknown.display_name(), "<unknown>");
}

#[test]
fn resolved_type_clones_equal() {
    let ty = ResolvedType::Map(
        Box::new(ResolvedType::AddressTy),
        Box::new(ResolvedType::U128),
    );
    assert_eq!(ty.clone(), ty);
}

#[test]
fn resolved_type_different_variants_not_equal() {
    assert_ne!(ResolvedType::U8, ResolvedType::U16);
    assert_ne!(ResolvedType::Bool, ResolvedType::StringTy);
    assert_ne!(ResolvedType::Unit, ResolvedType::Unknown);
}

// ── ResolvedType predicates ────────────────────────────────────────────────────

#[test]
fn is_unsigned_int_true_for_all_unsigned() {
    for ty in [
        ResolvedType::U8,
        ResolvedType::U16,
        ResolvedType::U32,
        ResolvedType::U64,
        ResolvedType::U128,
        ResolvedType::U256,
    ] {
        assert!(ty.is_unsigned_int(), "{ty:?} should be unsigned int");
    }
}

#[test]
fn is_unsigned_int_false_for_signed_and_other() {
    assert!(!ResolvedType::I128.is_unsigned_int());
    assert!(!ResolvedType::Bool.is_unsigned_int());
    assert!(!ResolvedType::AddressTy.is_unsigned_int());
}

#[test]
fn is_signed_int_true_for_all_signed() {
    for ty in [
        ResolvedType::I8,
        ResolvedType::I16,
        ResolvedType::I32,
        ResolvedType::I64,
        ResolvedType::I128,
        ResolvedType::I256,
    ] {
        assert!(ty.is_signed_int(), "{ty:?} should be signed int");
    }
}

#[test]
fn is_integer_true_for_signed_and_unsigned() {
    assert!(ResolvedType::U128.is_integer());
    assert!(ResolvedType::I64.is_integer());
    assert!(!ResolvedType::Bool.is_integer());
}

#[test]
fn is_numeric_true_for_integers_and_decimal() {
    assert!(ResolvedType::U256.is_numeric());
    assert!(ResolvedType::I32.is_numeric());
    assert!(ResolvedType::Decimal(18).is_numeric());
    assert!(!ResolvedType::Bool.is_numeric());
    assert!(!ResolvedType::StringTy.is_numeric());
}

#[test]
fn is_concrete_false_for_unknown_and_type_param() {
    assert!(!ResolvedType::Unknown.is_concrete());
    assert!(!ResolvedType::TypeParam("T".into()).is_concrete());
    assert!(ResolvedType::U128.is_concrete());
    assert!(ResolvedType::Bool.is_concrete());
}

// ── SymbolId ───────────────────────────────────────────────────────────────────

#[test]
fn symbol_id_zero_is_unresolved_sentinel() {
    assert_eq!(SymbolId::UNRESOLVED, SymbolId(0));
    assert!(SymbolId(0).is_unresolved());
    assert!(!SymbolId(1).is_unresolved());
}

#[test]
fn symbol_id_ordering_is_numeric() {
    assert!(SymbolId(1) < SymbolId(2));
    assert!(SymbolId(10) > SymbolId(9));
}

#[test]
fn symbol_id_copy_semantics() {
    let a = SymbolId(42);
    let b = a; // Copy
    assert_eq!(a, b);
}

#[test]
fn symbol_id_same_values_are_equal() {
    assert_eq!(SymbolId(7), SymbolId(7));
}

#[test]
fn symbol_id_different_values_not_equal() {
    assert_ne!(SymbolId(1), SymbolId(2));
}

// ── SymbolInfo ─────────────────────────────────────────────────────────────────

fn test_span() -> Span {
    Span::at(1, 1, 0)
}

#[test]
fn symbol_info_constructs_with_all_fields() {
    let info = SymbolInfo {
        name: "transfer".into(),
        decl_span: test_span(),
        kind: SymbolKind::Function,
        ty: unknown(),
        mutable: false,
        pending_ann: None,
    };
    assert_eq!(info.name, "transfer");
    assert!(matches!(info.kind, SymbolKind::Function));
}

#[test]
fn symbol_info_carries_resolved_type() {
    let info = SymbolInfo {
        name: "amount".into(),
        decl_span: test_span(),
        kind: SymbolKind::Param,
        ty: ResolvedType::U128,
        mutable: false,
        pending_ann: None,
    };
    assert_eq!(info.ty, ResolvedType::U128);
}

#[test]
fn symbol_info_clones_equal() {
    let info = SymbolInfo {
        name: "owner".into(),
        decl_span: test_span(),
        kind: SymbolKind::StateField,
        ty: unknown(),
        mutable: false,
        pending_ann: None,
    };
    assert_eq!(info.clone(), info);
}

#[test]
fn symbol_info_different_names_not_equal() {
    let a = SymbolInfo {
        name: "a".into(),
        decl_span: test_span(),
        kind: SymbolKind::Local,
        ty: unknown(),
        mutable: false,
        pending_ann: None,
    };
    let b = SymbolInfo {
        name: "b".into(),
        decl_span: test_span(),
        kind: SymbolKind::Local,
        ty: unknown(),
        mutable: false,
        pending_ann: None,
    };
    assert_ne!(a, b);
}

// ── SymbolKind ─────────────────────────────────────────────────────────────────

#[test]
fn symbol_kind_all_variants_construct() {
    let _: Vec<SymbolKind> = vec![
        SymbolKind::Function,
        SymbolKind::Const,
        SymbolKind::Immutable,
        SymbolKind::StateField,
        SymbolKind::Param,
        SymbolKind::Local,
        SymbolKind::SelfBinding,
        SymbolKind::Contract,
        SymbolKind::Struct,
        SymbolKind::Enum,
        SymbolKind::TypeAlias,
        SymbolKind::Interface,
        SymbolKind::Trait,
        SymbolKind::Library,
        SymbolKind::ErrorDecl,
        SymbolKind::GenericParam,
        SymbolKind::Imported,
    ];
}

#[test]
fn symbol_kind_clones_equal() {
    let k = SymbolKind::Param;
    assert_eq!(k.clone(), k);
}

#[test]
fn symbol_kind_different_variants_not_equal() {
    assert_ne!(SymbolKind::Function, SymbolKind::Local);
    assert_ne!(SymbolKind::Struct, SymbolKind::Enum);
}
