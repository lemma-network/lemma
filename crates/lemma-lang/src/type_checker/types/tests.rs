//! Tests for [`ResolvedType`] and [`SymbolId`].

use super::{ResolvedType, SymbolId};

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
    let _ = ResolvedType::Named("MyStruct".into(), vec![]);
    let _ = ResolvedType::Named("Pair".into(), vec![ResolvedType::U128, ResolvedType::Bool]);
    let _ = ResolvedType::TypeParam("T".into());
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
