//! Tests for the `codegen` module — Lem IR → Lem source text emission.
//!
//! All tests build IR directly (no Solidity parsing) to exercise the codegen
//! in isolation. This keeps tests fast and independent of the mapper.
//!
//! Round-trip tests (at the bottom) feed `emit_lem()` output into
//! `lemma_lang::tokenize` + `lemma_lang::parse` to verify the emitted source
//! is valid per the grammar (MF-3 fix — the critical parseability guarantee).

use super::*;
use crate::lem_ir::{
    BinOp, LemContract, LemEnum, LemEvent, LemEventField, LemExpr, LemFunction, LemFunctionKind,
    LemMutability, LemParam, LemStmt, LemStruct, LemType, LemVisibility, UnaryOp,
};

// ── Shared fixtures ───────────────────────────────────────────────────────────

/// Build a minimal [`LemContract`] with only a name and state.
fn make_minimal_contract() -> LemContract {
    LemContract {
        name: "SimpleToken".to_owned(),
        extends: Vec::new(),
        uses: Vec::new(),
        uses_itoken: false,
        structs: Vec::new(),
        enums: Vec::new(),
        state: vec![LemParam {
            name: "totalSupply".to_owned(),
            ty: LemType::U128,
        }],
        events: Vec::new(),
        functions: Vec::new(),
        uses_ownable: false,
        uses_pausable: false,
        uses_access_control: false,
    }
}

/// Build a [`LemContract`] with `uses_itoken = true`.
fn make_itoken_contract() -> LemContract {
    LemContract {
        name: "MyToken".to_owned(),
        extends: Vec::new(),
        uses: Vec::new(),
        uses_itoken: true,
        structs: Vec::new(),
        enums: Vec::new(),
        state: vec![LemParam {
            name: "balances".to_owned(),
            ty: LemType::Map(Box::new(LemType::Address), Box::new(LemType::U128)),
        }],
        events: Vec::new(),
        functions: Vec::new(),
        uses_ownable: false,
        uses_pausable: false,
        uses_access_control: false,
    }
}

/// Build a simple transfer function.
fn make_transfer_function() -> LemFunction {
    LemFunction {
        name: "transfer".to_owned(),
        params: vec![
            LemParam {
                name: "to".to_owned(),
                ty: LemType::Address,
            },
            LemParam {
                name: "amount".to_owned(),
                ty: LemType::U128,
            },
        ],
        returns: Some(LemType::Bool),
        visibility: LemVisibility::Public,
        mutability: LemMutability::Mutable,
        decorators: Vec::new(),
        body: vec![LemStmt::Return(Some(LemExpr::BoolLit(true)))],
        kind: LemFunctionKind::Method,
    }
}

// ── Type emitter tests ────────────────────────────────────────────────────────

#[test]
fn emit_type_u128_produces_u128_keyword() {
    assert_eq!(emit_type(&LemType::U128), "u128");
}

#[test]
fn emit_type_u8_produces_u8_keyword() {
    assert_eq!(emit_type(&LemType::U8), "u8");
}

#[test]
fn emit_type_u256_produces_u256_keyword() {
    assert_eq!(emit_type(&LemType::U256), "u256");
}

#[test]
fn emit_type_i128_produces_i128_keyword() {
    assert_eq!(emit_type(&LemType::I128), "i128");
}

#[test]
fn emit_type_bool_produces_bool_keyword() {
    assert_eq!(emit_type(&LemType::Bool), "bool");
}

#[test]
fn emit_type_address_produces_address_keyword() {
    assert_eq!(emit_type(&LemType::Address), "Address");
}

#[test]
fn emit_type_str_produces_string_keyword() {
    assert_eq!(emit_type(&LemType::Str), "String");
}

#[test]
fn emit_type_bytes_produces_bytes_keyword() {
    assert_eq!(emit_type(&LemType::Bytes), "bytes");
}

#[test]
fn emit_type_fixed_bytes_produces_array_syntax() {
    assert_eq!(emit_type(&LemType::FixedBytes(32)), "[u8; 32]");
}

#[test]
fn emit_type_map_produces_map_generic_syntax() {
    let ty = LemType::Map(Box::new(LemType::Address), Box::new(LemType::U128));
    assert_eq!(emit_type(&ty), "Map<Address, u128>");
}

#[test]
fn emit_type_array_produces_array_generic_syntax() {
    let ty = LemType::Array(Box::new(LemType::U64));
    assert_eq!(emit_type(&ty), "Array<u64>");
}

#[test]
fn emit_type_set_produces_set_generic_syntax() {
    let ty = LemType::Set(Box::new(LemType::Address));
    assert_eq!(emit_type(&ty), "Set<Address>");
}

#[test]
fn emit_type_named_passes_through_name() {
    let ty = LemType::Named("MyStruct".to_owned());
    assert_eq!(emit_type(&ty), "MyStruct");
}

#[test]
fn emit_type_option_produces_option_generic_syntax() {
    let ty = LemType::Option(Box::new(LemType::Address));
    assert_eq!(emit_type(&ty), "Option<Address>");
}

#[test]
fn emit_type_tuple_produces_parenthesized_pair() {
    let ty = LemType::Tuple(Box::new(LemType::U128), Box::new(LemType::Bool));
    assert_eq!(emit_type(&ty), "(u128, bool)");
}

#[test]
fn emit_type_nested_map_produces_nested_generic_syntax() {
    // Map<Address, Map<Address, u128>>
    let inner = LemType::Map(Box::new(LemType::Address), Box::new(LemType::U128));
    let outer = LemType::Map(Box::new(LemType::Address), Box::new(inner));
    assert_eq!(emit_type(&outer), "Map<Address, Map<Address, u128>>");
}

// ── Expression emitter tests ──────────────────────────────────────────────────

#[test]
fn emit_expr_int_lit_produces_decimal_string() {
    assert_eq!(emit_expr(&LemExpr::IntLit(42)), "42");
}

#[test]
fn emit_expr_int_lit_zero_produces_zero() {
    assert_eq!(emit_expr(&LemExpr::IntLit(0)), "0");
}

#[test]
fn emit_expr_bool_lit_true_produces_true() {
    assert_eq!(emit_expr(&LemExpr::BoolLit(true)), "true");
}

#[test]
fn emit_expr_bool_lit_false_produces_false() {
    assert_eq!(emit_expr(&LemExpr::BoolLit(false)), "false");
}

#[test]
fn emit_expr_string_lit_wraps_in_quotes() {
    assert_eq!(
        emit_expr(&LemExpr::StringLit("hello".to_owned())),
        "\"hello\""
    );
}

#[test]
fn emit_expr_bytes_lit_produces_hex_prefix() {
    assert_eq!(emit_expr(&LemExpr::BytesLit(vec![0xde, 0xad])), "0xdead");
}

#[test]
fn emit_expr_address_lit_passes_through() {
    assert_eq!(
        emit_expr(&LemExpr::AddressLit("Address.zero".to_owned())),
        "Address.zero"
    );
}

#[test]
fn emit_expr_ident_passes_through_name() {
    assert_eq!(emit_expr(&LemExpr::Ident("myVar".to_owned())), "myVar");
}

#[test]
fn emit_expr_member_access_produces_dot_notation() {
    let expr = LemExpr::MemberAccess(
        Box::new(LemExpr::Ident("msg".to_owned())),
        "sender".to_owned(),
    );
    assert_eq!(emit_expr(&expr), "msg.sender");
}

#[test]
fn emit_expr_index_access_produces_bracket_notation() {
    let expr = LemExpr::IndexAccess(
        Box::new(LemExpr::Ident("arr".to_owned())),
        Box::new(LemExpr::IntLit(0)),
    );
    assert_eq!(emit_expr(&expr), "arr[0]");
}

#[test]
fn emit_expr_call_produces_call_syntax() {
    let expr = LemExpr::Call {
        func: Box::new(LemExpr::Ident("foo".to_owned())),
        args: vec![LemExpr::IntLit(1), LemExpr::BoolLit(true)],
    };
    assert_eq!(emit_expr(&expr), "foo(1, true)");
}

#[test]
fn emit_expr_call_no_args_produces_empty_parens() {
    let expr = LemExpr::Call {
        func: Box::new(LemExpr::Ident("totalSupply".to_owned())),
        args: vec![],
    };
    assert_eq!(emit_expr(&expr), "totalSupply()");
}

#[test]
fn emit_expr_map_get_produces_get_call() {
    let expr = LemExpr::MapGet {
        map: Box::new(LemExpr::MemberAccess(
            Box::new(LemExpr::Ident("self".to_owned())),
            "balances".to_owned(),
        )),
        key: Box::new(LemExpr::MemberAccess(
            Box::new(LemExpr::Ident("msg".to_owned())),
            "sender".to_owned(),
        )),
    };
    assert_eq!(emit_expr(&expr), "self.balances.get(msg.sender)");
}

#[test]
fn emit_expr_map_set_produces_set_call() {
    let expr = LemExpr::MapSet {
        map: Box::new(LemExpr::MemberAccess(
            Box::new(LemExpr::Ident("self".to_owned())),
            "balances".to_owned(),
        )),
        key: Box::new(LemExpr::Ident("to".to_owned())),
        value: Box::new(LemExpr::IntLit(100)),
    };
    assert_eq!(emit_expr(&expr), "self.balances.set(to, 100)");
}

#[test]
fn emit_expr_binary_op_add_produces_parenthesized_expression() {
    let expr = LemExpr::BinaryOp {
        op: BinOp::Add,
        left: Box::new(LemExpr::Ident("a".to_owned())),
        right: Box::new(LemExpr::IntLit(1)),
    };
    assert_eq!(emit_expr(&expr), "(a + 1)");
}

#[test]
fn emit_expr_binary_op_eq_produces_double_equals() {
    let expr = LemExpr::BinaryOp {
        op: BinOp::Eq,
        left: Box::new(LemExpr::Ident("x".to_owned())),
        right: Box::new(LemExpr::IntLit(0)),
    };
    assert_eq!(emit_expr(&expr), "(x == 0)");
}

#[test]
fn emit_expr_binary_op_ge_produces_greater_equal() {
    let expr = LemExpr::BinaryOp {
        op: BinOp::Ge,
        left: Box::new(LemExpr::Ident("balance".to_owned())),
        right: Box::new(LemExpr::Ident("amount".to_owned())),
    };
    assert_eq!(emit_expr(&expr), "(balance >= amount)");
}

#[test]
fn emit_expr_unary_not_produces_bang_prefix() {
    let expr = LemExpr::UnaryOp {
        op: UnaryOp::Not,
        expr: Box::new(LemExpr::Ident("paused".to_owned())),
    };
    assert_eq!(emit_expr(&expr), "!paused");
}

#[test]
fn emit_expr_unary_neg_produces_minus_prefix() {
    let expr = LemExpr::UnaryOp {
        op: UnaryOp::Neg,
        expr: Box::new(LemExpr::Ident("x".to_owned())),
    };
    assert_eq!(emit_expr(&expr), "-x");
}

#[test]
fn emit_expr_struct_lit_produces_brace_syntax() {
    let expr = LemExpr::StructLit {
        name: "Allowance".to_owned(),
        fields: vec![
            ("amount".to_owned(), LemExpr::IntLit(0)),
            ("expiry".to_owned(), LemExpr::IntLit(0)),
        ],
    };
    assert_eq!(emit_expr(&expr), "Allowance { amount: 0, expiry: 0 }");
}

#[test]
fn emit_expr_cast_produces_as_syntax() {
    let expr = LemExpr::Cast {
        expr: Box::new(LemExpr::Ident("x".to_owned())),
        ty: LemType::U128,
    };
    assert_eq!(emit_expr(&expr), "x as u128");
}

#[test]
fn emit_expr_ternary_produces_comment_not_if_else() {
    // Lem has no ternary operator — ternary in expr position emits a Raw comment.
    let expr = LemExpr::Ternary {
        cond: Box::new(LemExpr::BoolLit(true)),
        then_expr: Box::new(LemExpr::IntLit(1)),
        else_expr: Box::new(LemExpr::IntLit(0)),
    };
    let out = emit_expr(&expr);
    assert!(
        out.contains("ternary") && out.contains("refactor"),
        "ternary in expr position should emit a Raw comment, got: {out}"
    );
}

#[test]
fn emit_expr_tuple_produces_parenthesized_list() {
    let expr = LemExpr::Tuple(vec![LemExpr::IntLit(1), LemExpr::BoolLit(false)]);
    assert_eq!(emit_expr(&expr), "(1, false)");
}

#[test]
fn emit_expr_raw_passes_through_verbatim() {
    let expr = LemExpr::Raw("/* unsupported */".to_owned());
    assert_eq!(emit_expr(&expr), "/* unsupported */");
}

// ── Statement emitter tests ───────────────────────────────────────────────────

/// Helper: emit a single statement and return the resulting string.
fn emit_one_stmt(stmt: &LemStmt) -> String {
    let mut out = CodegenWriter::new();
    emit_stmt(stmt, &mut out);
    out.finish()
}

#[test]
fn emit_stmt_let_with_type_produces_typed_binding() {
    let stmt = LemStmt::Let {
        name: "x".to_owned(),
        ty: Some(LemType::U128),
        value: LemExpr::IntLit(0),
    };
    assert_eq!(emit_one_stmt(&stmt).trim(), "let x: u128 = 0");
}

#[test]
fn emit_stmt_let_without_type_produces_inferred_binding() {
    let stmt = LemStmt::Let {
        name: "y".to_owned(),
        ty: None,
        value: LemExpr::BoolLit(true),
    };
    assert_eq!(emit_one_stmt(&stmt).trim(), "let y = true");
}

#[test]
fn emit_stmt_assign_produces_assignment_line() {
    let stmt = LemStmt::Assign {
        target: LemExpr::Ident("count".to_owned()),
        value: LemExpr::IntLit(5),
    };
    assert_eq!(emit_one_stmt(&stmt).trim(), "count = 5");
}

#[test]
fn emit_stmt_assert_produces_assert_call() {
    let stmt = LemStmt::Assert {
        cond: LemExpr::BinaryOp {
            op: BinOp::Ge,
            left: Box::new(LemExpr::Ident("balance".to_owned())),
            right: Box::new(LemExpr::Ident("amount".to_owned())),
        },
        msg: "Insufficient balance".to_owned(),
    };
    assert_eq!(
        emit_one_stmt(&stmt).trim(),
        "assert((balance >= amount), \"Insufficient balance\")"
    );
}

#[test]
fn emit_stmt_return_with_expr_produces_return_line() {
    let stmt = LemStmt::Return(Some(LemExpr::BoolLit(true)));
    assert_eq!(emit_one_stmt(&stmt).trim(), "return true");
}

#[test]
fn emit_stmt_return_none_produces_bare_return() {
    let stmt = LemStmt::Return(None);
    assert_eq!(emit_one_stmt(&stmt).trim(), "return");
}

#[test]
fn emit_stmt_emit_produces_emit_line() {
    let stmt = LemStmt::Emit {
        event: "Transfer".to_owned(),
        fields: vec![
            (
                "from".to_owned(),
                LemExpr::MemberAccess(
                    Box::new(LemExpr::Ident("msg".to_owned())),
                    "sender".to_owned(),
                ),
            ),
            ("to".to_owned(), LemExpr::Ident("to".to_owned())),
            ("amount".to_owned(), LemExpr::Ident("amount".to_owned())),
        ],
    };
    assert_eq!(
        emit_one_stmt(&stmt).trim(),
        "emit Transfer { from: msg.sender, to: to, amount: amount }"
    );
}

#[test]
fn emit_stmt_if_without_else_produces_if_block() {
    let stmt = LemStmt::If {
        cond: LemExpr::BoolLit(true),
        then_body: vec![LemStmt::Return(None)],
        else_body: None,
    };
    let out = emit_one_stmt(&stmt);
    assert!(out.contains("if (true) {"));
    assert!(out.contains("return"));
    assert!(out.contains("}"));
    assert!(!out.contains("else"));
}

#[test]
fn emit_stmt_if_else_produces_if_else_block() {
    let stmt = LemStmt::If {
        cond: LemExpr::Ident("flag".to_owned()),
        then_body: vec![LemStmt::Return(Some(LemExpr::BoolLit(true)))],
        else_body: Some(vec![LemStmt::Return(Some(LemExpr::BoolLit(false)))]),
    };
    let out = emit_one_stmt(&stmt);
    assert!(out.contains("if (flag) {"));
    assert!(out.contains("} else {"));
    assert!(out.contains("return true"));
    assert!(out.contains("return false"));
}

#[test]
fn emit_stmt_while_produces_while_block() {
    let stmt = LemStmt::While {
        cond: LemExpr::BoolLit(true),
        body: vec![LemStmt::Break],
    };
    let out = emit_one_stmt(&stmt);
    assert!(out.contains("while (true) {"));
    assert!(out.contains("break"));
}

#[test]
fn emit_stmt_break_produces_break_keyword() {
    assert_eq!(emit_one_stmt(&LemStmt::Break).trim(), "break");
}

#[test]
fn emit_stmt_continue_produces_continue_keyword() {
    assert_eq!(emit_one_stmt(&LemStmt::Continue).trim(), "continue");
}

#[test]
fn emit_stmt_expr_produces_expression_line() {
    let stmt = LemStmt::Expr(LemExpr::Call {
        func: Box::new(LemExpr::Ident("doSomething".to_owned())),
        args: vec![],
    });
    assert_eq!(emit_one_stmt(&stmt).trim(), "doSomething()");
}

#[test]
fn emit_stmt_raw_passes_through_verbatim() {
    let stmt = LemStmt::Raw("// W001: inline assembly — skipped".to_owned());
    assert_eq!(
        emit_one_stmt(&stmt).trim(),
        "// W001: inline assembly — skipped"
    );
}

// ── Event emitter tests ───────────────────────────────────────────────────────

/// Helper: emit a single event and return the resulting string.
fn emit_one_event(event: &LemEvent) -> String {
    let mut out = CodegenWriter::new();
    emit_event(&mut out, event);
    out.finish()
}

#[test]
fn emit_event_with_indexed_fields_produces_at_indexed_annotations() {
    let event = LemEvent {
        name: "Transfer".to_owned(),
        fields: vec![
            LemEventField {
                name: "from".to_owned(),
                ty: LemType::Address,
                indexed: true,
            },
            LemEventField {
                name: "to".to_owned(),
                ty: LemType::Address,
                indexed: true,
            },
            LemEventField {
                name: "amount".to_owned(),
                ty: LemType::U128,
                indexed: false,
            },
        ],
    };
    let out = emit_one_event(&event);
    assert!(out.contains("event Transfer {"));
    assert!(out.contains("@indexed from: Address"));
    assert!(out.contains("@indexed to: Address"));
    assert!(out.contains("amount: u128"));
    // Non-indexed field must NOT have @indexed.
    assert!(!out.contains("@indexed amount"));
}

#[test]
fn emit_event_no_indexed_fields_produces_plain_event() {
    let event = LemEvent {
        name: "Log".to_owned(),
        fields: vec![LemEventField {
            name: "msg".to_owned(),
            ty: LemType::Str,
            indexed: false,
        }],
    };
    let out = emit_one_event(&event);
    assert!(out.contains("event Log {"));
    assert!(out.contains("msg: String"));
    assert!(!out.contains("@indexed"));
}

// ── Function emitter tests ────────────────────────────────────────────────────

/// Helper: emit a single function and return the resulting string.
fn emit_one_function(func: &LemFunction) -> String {
    let mut out = CodegenWriter::new();
    emit_function(&mut out, func);
    out.finish()
}

#[test]
fn emit_function_public_produces_pub_keyword() {
    let func = make_transfer_function();
    let out = emit_one_function(&func);
    assert!(out.contains("pub fn transfer("));
}

#[test]
fn emit_function_private_omits_pub_keyword() {
    let mut func = make_transfer_function();
    func.visibility = LemVisibility::Private;
    let out = emit_one_function(&func);
    assert!(out.contains("fn transfer("));
    assert!(!out.contains("pub fn"));
}

#[test]
fn emit_function_view_produces_view_keyword() {
    let mut func = make_transfer_function();
    func.mutability = LemMutability::View;
    let out = emit_one_function(&func);
    assert!(out.contains("pub view fn transfer("));
}

#[test]
fn emit_function_with_return_type_produces_arrow_syntax() {
    let func = make_transfer_function();
    let out = emit_one_function(&func);
    assert!(out.contains("-> bool"));
}

#[test]
fn emit_function_constructor_uses_init_name() {
    let func = LemFunction {
        name: "constructor".to_owned(),
        params: vec![LemParam {
            name: "supply".to_owned(),
            ty: LemType::U128,
        }],
        returns: None,
        visibility: LemVisibility::Public,
        mutability: LemMutability::Mutable,
        decorators: Vec::new(),
        body: Vec::new(),
        kind: LemFunctionKind::Constructor,
    };
    let out = emit_one_function(&func);
    // Constructor emits `init(params) {` — keyword form, no `pub fn` prefix.
    assert!(out.contains("init("), "constructor should emit 'init(': {out}");
    assert!(!out.contains("fn init("), "constructor should NOT use 'fn init': {out}");
    assert!(!out.contains("fn constructor("));
}

#[test]
fn emit_function_with_decorators_produces_at_prefix_lines() {
    let mut func = make_transfer_function();
    func.decorators = vec!["onlyOwner".to_owned(), "whenNotPaused".to_owned()];
    let out = emit_one_function(&func);
    assert!(out.contains("@onlyOwner"));
    assert!(out.contains("@whenNotPaused"));
    // Decorators must appear before the fn line.
    let decorator_pos = out.find("@onlyOwner").expect("decorator not found");
    let fn_pos = out.find("pub fn").expect("fn not found");
    assert!(
        decorator_pos < fn_pos,
        "decorator must precede fn signature"
    );
}

#[test]
fn emit_function_body_statements_are_indented() {
    let func = make_transfer_function();
    let out = emit_one_function(&func);
    // The `return true` line should be indented (4 spaces inside the fn body).
    assert!(out.contains("    return true"));
}

// ── Contract emitter tests ────────────────────────────────────────────────────

#[test]
fn emit_contract_has_contract_keyword_and_name() {
    let contract = make_minimal_contract();
    let out = emit_lem(&contract);
    assert!(out.contains("contract SimpleToken {"));
}

#[test]
fn emit_contract_has_state_block() {
    let contract = make_minimal_contract();
    let out = emit_lem(&contract);
    assert!(out.contains("state {"));
    assert!(out.contains("totalSupply: u128,"));
}

#[test]
fn emit_contract_uses_itoken_adds_itoken_to_implements_clause() {
    // MF-2: IToken is an interface → `implements IToken`, not `uses IToken`
    let contract = make_itoken_contract();
    let out = emit_lem(&contract);
    assert!(out.contains("implements IToken"), "IToken should be in implements: {out}");
    assert!(!out.contains("uses IToken"), "IToken should NOT be in uses: {out}");
}

#[test]
fn emit_contract_uses_ownable_adds_ownable_to_uses_clause() {
    let mut contract = make_minimal_contract();
    contract.uses_ownable = true;
    let out = emit_lem(&contract);
    assert!(out.contains("uses Ownable"));
}

#[test]
fn emit_contract_uses_pausable_adds_pausable_to_uses_clause() {
    let mut contract = make_minimal_contract();
    contract.uses_pausable = true;
    let out = emit_lem(&contract);
    assert!(out.contains("uses Pausable"));
}

#[test]
fn emit_contract_uses_access_control_adds_access_control_to_uses_clause() {
    let mut contract = make_minimal_contract();
    contract.uses_access_control = true;
    let out = emit_lem(&contract);
    assert!(out.contains("uses AccessControl"));
}

#[test]
fn emit_contract_multiple_traits_all_appear_in_uses_clause() {
    let mut contract = make_minimal_contract();
    contract.uses_itoken = true;
    contract.uses_ownable = true;
    contract.uses_pausable = true;
    let out = emit_lem(&contract);
    assert!(out.contains("IToken"));
    assert!(out.contains("Ownable"));
    assert!(out.contains("Pausable"));
}

#[test]
fn emit_contract_extends_produces_comment_not_header_extends() {
    // MF-1: concrete bases emit as comment, NOT `extends` in the header (invalid Lem grammar)
    let mut contract = make_minimal_contract();
    contract.extends = vec!["BaseToken".to_owned()];
    let out = emit_lem(&contract);
    assert!(
        !out.contains("extends BaseToken"),
        "header should NOT contain 'extends BaseToken': {out}"
    );
    assert!(
        out.contains("// Concrete inheritance from Solidity: BaseToken"),
        "should emit concrete base as comment: {out}"
    );
}

#[test]
fn emit_contract_no_traits_omits_uses_clause() {
    let contract = make_minimal_contract();
    let out = emit_lem(&contract);
    assert!(!out.contains("uses "));
}

#[test]
fn emit_contract_includes_preamble_comment() {
    let contract = make_minimal_contract();
    let out = emit_lem(&contract);
    assert!(out.contains("// Transpiled from Solidity by lemma-transpiler"));
}

#[test]
fn emit_contract_with_function_includes_function_body() {
    let mut contract = make_minimal_contract();
    contract.functions = vec![make_transfer_function()];
    let out = emit_lem(&contract);
    assert!(out.contains("pub fn transfer("));
    assert!(out.contains("return true"));
}

#[test]
fn emit_contract_with_struct_includes_struct_definition() {
    let mut contract = make_minimal_contract();
    contract.structs = vec![LemStruct {
        name: "Allowance".to_owned(),
        fields: vec![
            LemParam {
                name: "amount".to_owned(),
                ty: LemType::U128,
            },
            LemParam {
                name: "expiry".to_owned(),
                ty: LemType::U64,
            },
        ],
    }];
    let out = emit_lem(&contract);
    assert!(out.contains("struct Allowance {"));
    assert!(out.contains("amount: u128,"));
    assert!(out.contains("expiry: u64,"));
}

#[test]
fn emit_contract_with_enum_includes_enum_definition() {
    let mut contract = make_minimal_contract();
    contract.enums = vec![LemEnum {
        name: "Status".to_owned(),
        variants: vec!["Active".to_owned(), "Paused".to_owned()],
    }];
    let out = emit_lem(&contract);
    assert!(out.contains("enum Status {"));
    assert!(out.contains("Active,"));
    assert!(out.contains("Paused,"));
}

#[test]
fn emit_contract_with_event_includes_event_definition() {
    let mut contract = make_minimal_contract();
    contract.events = vec![LemEvent {
        name: "Transfer".to_owned(),
        fields: vec![
            LemEventField {
                name: "from".to_owned(),
                ty: LemType::Address,
                indexed: true,
            },
            LemEventField {
                name: "amount".to_owned(),
                ty: LemType::U128,
                indexed: false,
            },
        ],
    }];
    let out = emit_lem(&contract);
    assert!(out.contains("event Transfer {"));
    assert!(out.contains("@indexed from: Address"));
}

#[test]
fn emit_contract_empty_state_omits_state_block() {
    let mut contract = make_minimal_contract();
    contract.state = Vec::new();
    let out = emit_lem(&contract);
    assert!(!out.contains("state {"));
}

// ── For-loop lowering test ────────────────────────────────────────────────────

#[test]
fn emit_stmt_for_loop_lowers_to_while_loop() {
    let stmt = LemStmt::For {
        init: Some(Box::new(LemStmt::Let {
            name: "i".to_owned(),
            ty: Some(LemType::U64),
            value: LemExpr::IntLit(0),
        })),
        cond: Some(LemExpr::BinaryOp {
            op: BinOp::Lt,
            left: Box::new(LemExpr::Ident("i".to_owned())),
            right: Box::new(LemExpr::IntLit(10)),
        }),
        update: Some(Box::new(LemStmt::Assign {
            target: LemExpr::Ident("i".to_owned()),
            value: LemExpr::BinaryOp {
                op: BinOp::Add,
                left: Box::new(LemExpr::Ident("i".to_owned())),
                right: Box::new(LemExpr::IntLit(1)),
            },
        })),
        body: vec![LemStmt::Continue],
    };
    let out = emit_one_stmt(&stmt);
    // Init emitted before the while.
    assert!(out.contains("let i: u64 = 0"));
    // Condition in while header.
    assert!(out.contains("while ((i < 10)) {"));
    // Update at end of body.
    assert!(out.contains("i = (i + 1)"));
    // Body statement.
    assert!(out.contains("continue"));
}

// ── Integration: full ERC-20-like contract ────────────────────────────────────

#[test]
fn emit_lem_full_erc20_like_contract_is_well_formed() {
    let contract = LemContract {
        name: "MyToken".to_owned(),
        extends: Vec::new(),
        uses: Vec::new(),
        uses_itoken: true,
        uses_ownable: true,
        uses_pausable: false,
        uses_access_control: false,
        structs: Vec::new(),
        enums: Vec::new(),
        state: vec![
            LemParam {
                name: "balances".to_owned(),
                ty: LemType::Map(Box::new(LemType::Address), Box::new(LemType::U128)),
            },
            LemParam {
                name: "totalSupply".to_owned(),
                ty: LemType::U128,
            },
        ],
        events: vec![LemEvent {
            name: "Transfer".to_owned(),
            fields: vec![
                LemEventField {
                    name: "from".to_owned(),
                    ty: LemType::Address,
                    indexed: true,
                },
                LemEventField {
                    name: "to".to_owned(),
                    ty: LemType::Address,
                    indexed: true,
                },
                LemEventField {
                    name: "amount".to_owned(),
                    ty: LemType::U128,
                    indexed: false,
                },
            ],
        }],
        functions: vec![
            LemFunction {
                name: "transfer".to_owned(),
                params: vec![
                    LemParam {
                        name: "to".to_owned(),
                        ty: LemType::Address,
                    },
                    LemParam {
                        name: "amount".to_owned(),
                        ty: LemType::U128,
                    },
                ],
                returns: Some(LemType::Bool),
                visibility: LemVisibility::Public,
                mutability: LemMutability::Mutable,
                decorators: Vec::new(),
                body: vec![
                    LemStmt::Assert {
                        cond: LemExpr::BinaryOp {
                            op: BinOp::Ge,
                            left: Box::new(LemExpr::MapGet {
                                map: Box::new(LemExpr::MemberAccess(
                                    Box::new(LemExpr::Ident("self".to_owned())),
                                    "balances".to_owned(),
                                )),
                                key: Box::new(LemExpr::MemberAccess(
                                    Box::new(LemExpr::Ident("msg".to_owned())),
                                    "sender".to_owned(),
                                )),
                            }),
                            right: Box::new(LemExpr::Ident("amount".to_owned())),
                        },
                        msg: "Insufficient balance".to_owned(),
                    },
                    LemStmt::Return(Some(LemExpr::BoolLit(true))),
                ],
                kind: LemFunctionKind::Method,
            },
            LemFunction {
                name: "mint".to_owned(),
                params: vec![
                    LemParam {
                        name: "to".to_owned(),
                        ty: LemType::Address,
                    },
                    LemParam {
                        name: "amount".to_owned(),
                        ty: LemType::U128,
                    },
                ],
                returns: None,
                visibility: LemVisibility::Public,
                mutability: LemMutability::Mutable,
                decorators: vec!["onlyOwner".to_owned()],
                body: Vec::new(),
                kind: LemFunctionKind::Method,
            },
        ],
    };

    let out = emit_lem(&contract);

    // Contract header.
    // MF-2: IToken → implements; Ownable → uses; order: implements before uses
    assert!(out.contains("contract MyToken implements IToken uses Ownable {"));
    // State block.
    assert!(out.contains("state {"));
    assert!(out.contains("balances: Map<Address, u128>,"));
    assert!(out.contains("totalSupply: u128,"));
    // Event.
    assert!(out.contains("event Transfer {"));
    assert!(out.contains("@indexed from: Address"));
    // Transfer function.
    assert!(out.contains("pub fn transfer(to: Address, amount: u128) -> bool {"));
    assert!(
        out.contains("assert((self.balances.get(msg.sender) >= amount), \"Insufficient balance\")")
    );
    assert!(out.contains("return true"));
    // Mint function with decorator.
    assert!(out.contains("@onlyOwner"));
    assert!(out.contains("pub fn mint(to: Address, amount: u128) {"));
    // Closing brace.
    assert!(out.ends_with("}\n"));
}

// ── Round-trip tests (MF-3 fix) ───────────────────────────────────────────────
// These tests feed emit_lem() output into lemma_lang::tokenize + lemma_lang::parse
// to verify the emitted Lem source is actually valid per the grammar.
//
// The Lem parser does not skip comment tokens (LineComment/BlockComment/DocComment).
// These are emitted by the tokenizer for the benefit of LSP/doc tools but must be
// filtered before calling parse(). `parse_lem_src` handles this correctly.

/// Parse Lem source through the full tokenize→filter-trivia→parse pipeline.
///
/// The lemma-lang parser does not skip comment tokens, so we filter
/// `LineComment`, `BlockComment`, and `DocComment` tokens before parsing.
fn parse_lem_src(src: &str) {
    use lemma_lang::lexer::token::Token;
    let tokens = lemma_lang::tokenize(src)
        .unwrap_or_else(|e| panic!("tokenize failed:\n{src}\n{e:?}"));
    // Filter comment trivia — the parser processes logic tokens only.
    let non_trivia: Vec<_> = tokens
        .into_iter()
        .filter(|(t, _)| {
            !matches!(
                t,
                Token::LineComment(_) | Token::BlockComment(_) | Token::DocComment(_)
            )
        })
        .collect();
    lemma_lang::parse(non_trivia)
        .unwrap_or_else(|e| panic!("parse failed:\n{src}\n{e:?}"));
}

#[test]
fn round_trip_minimal_contract_parses() {
    let contract = make_minimal_contract();
    let src = emit_lem(&contract);
    parse_lem_src(&src);
}

#[test]
fn round_trip_itoken_contract_uses_implements_not_uses() {
    // MF-2 regression: `uses_itoken` must emit `implements IToken`, not `uses IToken`
    let contract = LemContract {
        name: "MyToken".to_owned(),
        extends: vec![],
        uses: vec![],
        uses_itoken: true,
        uses_ownable: false,
        uses_pausable: false,
        uses_access_control: false,
        structs: vec![],
        enums: vec![],
        state: vec![LemParam { name: "supply".to_owned(), ty: LemType::U128 }],
        events: vec![],
        functions: vec![],
    };
    let src = emit_lem(&contract);
    assert!(
        src.contains("implements IToken"),
        "should contain 'implements IToken', got:\n{src}"
    );
    assert!(
        !src.contains("uses IToken"),
        "should NOT contain 'uses IToken' (interfaces go in implements), got:\n{src}"
    );
    parse_lem_src(&src);
}

#[test]
fn round_trip_ownable_trait_goes_in_uses_not_implements() {
    let contract = LemContract {
        name: "OwnedToken".to_owned(),
        extends: vec![],
        uses: vec![],
        uses_itoken: false,
        uses_ownable: true,
        uses_pausable: false,
        uses_access_control: false,
        structs: vec![],
        enums: vec![],
        state: vec![LemParam { name: "owner".to_owned(), ty: LemType::Address }],
        events: vec![],
        functions: vec![],
    };
    let src = emit_lem(&contract);
    assert!(src.contains("uses Ownable"), "Ownable is a trait, should go in uses: {src}");
    assert!(!src.contains("implements Ownable"), "Ownable should not be in implements: {src}");
    parse_lem_src(&src);
}

#[test]
fn round_trip_concrete_base_emits_comment_not_extends() {
    // MF-1 regression: concrete bases must emit as comments, not `extends` (invalid grammar)
    let contract = LemContract {
        name: "ChildToken".to_owned(),
        extends: vec!["ERC20Base".to_owned()],
        uses: vec![],
        uses_itoken: false,
        uses_ownable: false,
        uses_pausable: false,
        uses_access_control: false,
        structs: vec![],
        enums: vec![],
        state: vec![],
        events: vec![],
        functions: vec![],
    };
    let src = emit_lem(&contract);
    assert!(
        !src.contains("extends ERC20Base"),
        "should NOT contain 'extends' in contract header, got:\n{src}"
    );
    assert!(
        !src.contains("uses IToken"),
        "should NOT contain 'uses IToken' (interfaces go in implements), got:\n{src}"
    );
    // Must parse without error
    parse_lem_src(&src);
}

#[test]
fn round_trip_function_with_view_parses() {
    let contract = LemContract {
        name: "ViewToken".to_owned(),
        extends: vec![],
        uses: vec![],
        uses_itoken: false,
        uses_ownable: false,
        uses_pausable: false,
        uses_access_control: false,
        structs: vec![],
        enums: vec![],
        state: vec![LemParam { name: "supply".to_owned(), ty: LemType::U128 }],
        events: vec![],
        functions: vec![LemFunction {
            name: "totalSupply".to_owned(),
            params: vec![],
            returns: Some(LemType::U128),
            visibility: LemVisibility::Public,
            mutability: LemMutability::View,
            decorators: vec![],
            body: vec![LemStmt::Return(Some(LemExpr::MemberAccess(
                Box::new(LemExpr::Ident("self".to_owned())),
                "supply".to_owned(),
            )))],
            kind: LemFunctionKind::Method,
        }],
    };
    let src = emit_lem(&contract);
    parse_lem_src(&src);
}

#[test]
fn round_trip_assert_stmt_parses() {
    let contract = LemContract {
        name: "AssertToken".to_owned(),
        extends: vec![],
        uses: vec![],
        uses_itoken: false,
        uses_ownable: false,
        uses_pausable: false,
        uses_access_control: false,
        structs: vec![],
        enums: vec![],
        state: vec![],
        events: vec![],
        functions: vec![LemFunction {
            name: "check".to_owned(),
            params: vec![LemParam { name: "x".to_owned(), ty: LemType::U128 }],
            returns: None,
            visibility: LemVisibility::Public,
            mutability: LemMutability::Mutable,
            decorators: vec![],
            body: vec![LemStmt::Assert {
                cond: LemExpr::BinaryOp {
                    op: BinOp::Gt,
                    left: Box::new(LemExpr::Ident("x".to_owned())),
                    right: Box::new(LemExpr::IntLit(0)),
                },
                msg: "must be positive".to_owned(),
            }],
            kind: LemFunctionKind::Method,
        }],
    };
    let src = emit_lem(&contract);
    parse_lem_src(&src);
}

#[test]
fn round_trip_string_with_quotes_escapes_correctly() {
    // m-1 regression: strings with embedded quotes must be escaped
    let src = emit_expr(&LemExpr::StringLit("say \"hello\"".to_owned()));
    assert_eq!(src, r#""say \"hello\"""#, "quotes must be escaped: {src}");
}

#[test]
fn round_trip_constructor_emits_fn_init() {
    let contract = LemContract {
        name: "InitToken".to_owned(),
        extends: vec![],
        uses: vec![],
        uses_itoken: false,
        uses_ownable: false,
        uses_pausable: false,
        uses_access_control: false,
        structs: vec![],
        enums: vec![],
        state: vec![LemParam { name: "supply".to_owned(), ty: LemType::U128 }],
        events: vec![],
        functions: vec![LemFunction {
            name: "init".to_owned(),
            params: vec![LemParam { name: "initialSupply".to_owned(), ty: LemType::U128 }],
            returns: None,
            visibility: LemVisibility::Public,
            mutability: LemMutability::Mutable,
            decorators: vec![],
            body: vec![LemStmt::Assign {
                target: LemExpr::MemberAccess(
                    Box::new(LemExpr::Ident("self".to_owned())),
                    "supply".to_owned(),
                ),
                value: LemExpr::Ident("initialSupply".to_owned()),
            }],
            kind: LemFunctionKind::Constructor,
        }],
    };
    let src = emit_lem(&contract);
    // Lem constructor syntax: `init(params) { }` — keyword form, not `pub fn init`.
    assert!(src.contains("init(initialSupply"), "constructor should emit as 'init(': {src}");
    assert!(!src.contains("fn init("), "constructor should NOT use 'fn init': {src}");
    parse_lem_src(&src);
}
