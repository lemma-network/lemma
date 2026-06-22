//! Tests for the `lem_ir` module — IR type construction, cloning, and serde.

use super::*;

#[test]
fn lem_type_map_holds_nested_types() {
    let ty = LemType::Map(Box::new(LemType::Address), Box::new(LemType::U128));
    assert!(matches!(ty, LemType::Map(_, _)));
}

#[test]
fn lem_type_fixed_bytes_stores_size() {
    let ty = LemType::FixedBytes(32);
    assert_eq!(ty, LemType::FixedBytes(32));
}

#[test]
fn lem_expr_binary_op_round_trips() {
    let expr = LemExpr::BinaryOp {
        op: BinOp::Add,
        left: Box::new(LemExpr::Ident("a".to_owned())),
        right: Box::new(LemExpr::IntLit(1)),
    };
    // Verify Clone derives work correctly (needed by mapper/codegen)
    let cloned = expr.clone();
    assert_eq!(expr, cloned);
}

#[test]
fn lem_stmt_assert_stores_message() {
    let stmt = LemStmt::Assert {
        cond: LemExpr::BoolLit(true),
        msg: "must be true".to_owned(),
    };
    match stmt {
        LemStmt::Assert { msg, .. } => assert_eq!(msg, "must be true"),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn lem_contract_default_has_empty_vecs() {
    let c = LemContract {
        name: "MyToken".to_owned(),
        extends: vec![],
        uses: vec![],
        uses_itoken: false,
        structs: vec![],
        enums: vec![],
        state: vec![],
        events: vec![],
        functions: vec![],
        uses_ownable: false,
        uses_pausable: false,
        uses_access_control: false,
    };
    assert!(c.functions.is_empty());
    assert_eq!(c.name, "MyToken");
}

#[test]
fn lem_function_kind_constructor() {
    let f = LemFunction {
        name: "init".to_owned(),
        params: vec![],
        returns: None,
        visibility: LemVisibility::Public,
        mutability: LemMutability::Mutable,
        decorators: vec![],
        body: vec![],
        kind: LemFunctionKind::Constructor,
    };
    assert_eq!(f.kind, LemFunctionKind::Constructor);
    assert_eq!(f.name, "init");
}

#[test]
fn lem_function_kind_method() {
    let f = LemFunction {
        name: "transfer".to_owned(),
        params: vec![],
        returns: Some(LemType::Bool),
        visibility: LemVisibility::Public,
        mutability: LemMutability::Mutable,
        decorators: vec![],
        body: vec![],
        kind: LemFunctionKind::Method,
    };
    assert_eq!(f.kind, LemFunctionKind::Method);
}

#[test]
fn lem_expr_tuple_holds_elements() {
    let t = LemExpr::Tuple(vec![LemExpr::BoolLit(true), LemExpr::IntLit(42)]);
    match t {
        LemExpr::Tuple(elems) => assert_eq!(elems.len(), 2),
        _ => panic!("wrong variant"),
    }
}

#[test]
fn lem_event_field_indexed() {
    let f = LemEventField {
        name: "from".to_owned(),
        ty: LemType::Address,
        indexed: true,
    };
    assert!(f.indexed);
    assert_eq!(f.ty, LemType::Address);
}

#[test]
fn lem_type_serde_round_trip() {
    let ty = LemType::Map(Box::new(LemType::Address), Box::new(LemType::U128));
    let json = serde_json::to_string(&ty).expect("serialize");
    let back: LemType = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ty, back);
}
