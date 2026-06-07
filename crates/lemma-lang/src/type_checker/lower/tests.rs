//! Tests for `lower_type_with` (P3-checker-4).

use crate::parser::ast::Type;
use crate::type_checker::lower::lower_type_with;
use crate::type_checker::types::ResolvedType;

/// A no-op resolve_named that always returns Unknown (for primitive tests).
fn resolve_unknown(_name: &str, _args: Vec<ResolvedType>) -> ResolvedType {
    ResolvedType::Unknown
}

#[test]
fn lower_type_with_handles_all_primitives() {
    // Verify every primitive type lowers correctly via the extracted function.
    let cases: &[(Type, ResolvedType)] = &[
        (Type::U8, ResolvedType::U8),
        (Type::U16, ResolvedType::U16),
        (Type::U32, ResolvedType::U32),
        (Type::U64, ResolvedType::U64),
        (Type::U128, ResolvedType::U128),
        (Type::U256, ResolvedType::U256),
        (Type::I8, ResolvedType::I8),
        (Type::I16, ResolvedType::I16),
        (Type::I32, ResolvedType::I32),
        (Type::I64, ResolvedType::I64),
        (Type::I128, ResolvedType::I128),
        (Type::I256, ResolvedType::I256),
        (Type::Bool, ResolvedType::Bool),
        (Type::StringTy, ResolvedType::StringTy),
        (Type::CharTy, ResolvedType::CharTy),
        (Type::AddressTy, ResolvedType::AddressTy),
        (Type::HashTy, ResolvedType::HashTy),
        (Type::Bytes, ResolvedType::Bytes),
        (Type::BytesN(8), ResolvedType::BytesN(8)),
        (Type::Decimal(4), ResolvedType::Decimal(4)),
    ];
    for (ty, expected) in cases {
        let result = lower_type_with(
            ty,
            &|t| lower_type_with(t, &|_| ResolvedType::Unknown, &resolve_unknown),
            &resolve_unknown,
        );
        assert_eq!(result, *expected, "failed for {ty:?}");
    }
}

#[test]
fn lower_type_with_array_recurses() {
    let ty = Type::Array(Box::new(Type::U128));
    let result = lower_type_with(
        &ty,
        &|t| lower_type_with(t, &|_| ResolvedType::Unknown, &resolve_unknown),
        &resolve_unknown,
    );
    assert_eq!(result, ResolvedType::Array(Box::new(ResolvedType::U128)));
}

#[test]
fn lower_type_with_option_recurses() {
    let ty = Type::Option_(Box::new(Type::Bool));
    let result = lower_type_with(
        &ty,
        &|t| lower_type_with(t, &|_| ResolvedType::Unknown, &resolve_unknown),
        &resolve_unknown,
    );
    assert_eq!(result, ResolvedType::Option_(Box::new(ResolvedType::Bool)));
}

#[test]
fn lower_type_with_named_underscore_returns_unknown() {
    let ty = Type::Named("_".into(), vec![]);
    let result = lower_type_with(&ty, &|_| ResolvedType::Unknown, &resolve_unknown);
    assert_eq!(result, ResolvedType::Unknown);
}
