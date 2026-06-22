//! Tests for the `mapper` module — Solidity AST → Lem IR mapping.
//!
//! All tests parse real Solidity snippets via `solang_parser::parse` to exercise
//! the full mapper path against the actual solang-parser API surface.

use solang_parser::pt;

use super::*;
use crate::warnings::WarningCollector;

// ── Shared fixtures ───────────────────────────────────────────────────────────

/// Parse a Solidity source string and extract the last concrete `contract`
/// definition (not interface or library).
///
/// When tests define helper interfaces/bases before the main contract, this
/// ensures we always get the primary contract under test. Falls back to the
/// last `ContractDefinition` of any kind if no concrete contract is found.
///
/// Panics if parsing fails or no contract is found — tests are expected to
/// provide valid Solidity.
fn parse_contract(src: &str) -> pt::ContractDefinition {
    let (unit, _) = solang_parser::parse(src, 0).expect("parse failed");
    let all: Vec<pt::ContractDefinition> = unit
        .0
        .into_iter()
        .filter_map(|p| {
            if let pt::SourceUnitPart::ContractDefinition(def) = p {
                Some(*def)
            } else {
                None
            }
        })
        .collect();

    // Prefer the last concrete `contract` (not interface/library/abstract).
    all.iter()
        .rev()
        .find(|def| matches!(def.ty, pt::ContractTy::Contract(_)))
        .or_else(|| all.last())
        .cloned()
        .expect("no contract found")
}

/// Parse a Solidity source string and extract the first `FunctionDefinition`
/// from the first contract.
fn parse_first_function(src: &str) -> pt::FunctionDefinition {
    let contract = parse_contract(src);
    contract
        .parts
        .into_iter()
        .find_map(|p| {
            if let pt::ContractPart::FunctionDefinition(f) = p {
                Some(*f)
            } else {
                None
            }
        })
        .expect("no function found")
}

/// Parse a Solidity source string and extract the first `EventDefinition`
/// from the first contract.
fn parse_first_event(src: &str) -> pt::EventDefinition {
    let contract = parse_contract(src);
    contract
        .parts
        .into_iter()
        .find_map(|p| {
            if let pt::ContractPart::EventDefinition(e) = p {
                Some(*e)
            } else {
                None
            }
        })
        .expect("no event found")
}

/// Parse a Solidity source string and extract the first `EnumDefinition`
/// from the first contract.
fn parse_first_enum(src: &str) -> pt::EnumDefinition {
    let contract = parse_contract(src);
    contract
        .parts
        .into_iter()
        .find_map(|p| {
            if let pt::ContractPart::EnumDefinition(e) = p {
                Some(*e)
            } else {
                None
            }
        })
        .expect("no enum found")
}

/// Parse a Solidity source string and extract the first `StructDefinition`
/// from the first contract.
fn parse_first_struct(src: &str) -> pt::StructDefinition {
    let contract = parse_contract(src);
    contract
        .parts
        .into_iter()
        .find_map(|p| {
            if let pt::ContractPart::StructDefinition(s) = p {
                Some(*s)
            } else {
                None
            }
        })
        .expect("no struct found")
}

/// Parse a Solidity source string and extract the first `VariableDefinition`
/// from the first contract.
fn parse_first_state_var(src: &str) -> pt::VariableDefinition {
    let contract = parse_contract(src);
    contract
        .parts
        .into_iter()
        .find_map(|p| {
            if let pt::ContractPart::VariableDefinition(v) = p {
                Some(*v)
            } else {
                None
            }
        })
        .expect("no variable definition found")
}

// ── Type mapping tests ────────────────────────────────────────────────────────

#[test]
fn map_sol_type_uint256_returns_u256() {
    let ty = map_sol_type(&pt::Type::Uint(256));
    assert_eq!(ty, LemType::U256);
}

#[test]
fn map_sol_type_uint8_returns_u8() {
    let ty = map_sol_type(&pt::Type::Uint(8));
    assert_eq!(ty, LemType::U8);
}

#[test]
fn map_sol_type_uint128_returns_u128() {
    let ty = map_sol_type(&pt::Type::Uint(128));
    assert_eq!(ty, LemType::U128);
}

#[test]
fn map_sol_type_address_returns_address() {
    let ty = map_sol_type(&pt::Type::Address);
    assert_eq!(ty, LemType::Address);
}

#[test]
fn map_sol_type_address_payable_returns_address() {
    let ty = map_sol_type(&pt::Type::AddressPayable);
    assert_eq!(ty, LemType::Address);
}

#[test]
fn map_sol_type_bool_returns_bool() {
    let ty = map_sol_type(&pt::Type::Bool);
    assert_eq!(ty, LemType::Bool);
}

#[test]
fn map_sol_type_string_returns_str() {
    let ty = map_sol_type(&pt::Type::String);
    assert_eq!(ty, LemType::Str);
}

#[test]
fn map_sol_type_dynamic_bytes_returns_bytes() {
    let ty = map_sol_type(&pt::Type::DynamicBytes);
    assert_eq!(ty, LemType::Bytes);
}

#[test]
fn map_sol_type_bytes32_returns_fixed_bytes() {
    let ty = map_sol_type(&pt::Type::Bytes(32));
    assert_eq!(ty, LemType::FixedBytes(32));
}

#[test]
fn map_sol_type_bytes1_returns_fixed_bytes_1() {
    let ty = map_sol_type(&pt::Type::Bytes(1));
    assert_eq!(ty, LemType::FixedBytes(1));
}

#[test]
fn map_sol_type_int256_returns_i128() {
    // int256 → I128 for MVP (no I256 in LemType yet).
    let ty = map_sol_type(&pt::Type::Int(256));
    assert_eq!(ty, LemType::I128);
}

#[test]
fn map_sol_type_int8_returns_i8() {
    let ty = map_sol_type(&pt::Type::Int(8));
    assert_eq!(ty, LemType::I8);
}

#[test]
fn map_sol_type_mapping_k_v() {
    // mapping(address => uint256) → Map(Address, U256)
    let loc = pt::Loc::File(0, 0, 0);
    let key = Box::new(pt::Expression::Type(loc, pt::Type::Address));
    let value = Box::new(pt::Expression::Type(loc, pt::Type::Uint(256)));
    let mapping = pt::Type::Mapping {
        loc,
        key,
        key_name: None,
        value,
        value_name: None,
    };
    let ty = map_sol_type(&mapping);
    assert_eq!(
        ty,
        LemType::Map(Box::new(LemType::Address), Box::new(LemType::U256))
    );
}

// ── State variable mapping tests ──────────────────────────────────────────────

#[test]
fn map_state_var_strips_underscore_prefix() {
    let var = parse_first_state_var(
        "pragma solidity ^0.8.0; contract C { uint256 private _totalSupply; }",
    );
    let param = map_state_var(&var).expect("should map");
    assert_eq!(param.name, "totalSupply");
    assert_eq!(param.ty, LemType::U256);
}

#[test]
fn map_state_var_no_underscore_unchanged() {
    let var = parse_first_state_var("pragma solidity ^0.8.0; contract C { address public owner; }");
    let param = map_state_var(&var).expect("should map");
    assert_eq!(param.name, "owner");
    assert_eq!(param.ty, LemType::Address);
}

#[test]
fn map_state_var_mapping_type() {
    let var = parse_first_state_var(
        "pragma solidity ^0.8.0; contract C { mapping(address => uint256) private _balances; }",
    );
    let param = map_state_var(&var).expect("should map");
    assert_eq!(param.name, "balances");
    assert_eq!(
        param.ty,
        LemType::Map(Box::new(LemType::Address), Box::new(LemType::U256))
    );
}

// ── Function signature mapping tests ─────────────────────────────────────────

#[test]
fn map_function_sig_constructor_has_init_name_and_constructor_kind() {
    let func = parse_first_function(
        "pragma solidity ^0.8.0; contract C { constructor(address owner_) public {} }",
    );
    let mut seen = BTreeMap::new();
    let mut warnings = WarningCollector::new();
    let lem_fn = map_function_sig(&func, &mut seen, &mut warnings).expect("should map");
    assert_eq!(lem_fn.name, "init");
    assert_eq!(lem_fn.kind, LemFunctionKind::Constructor);
    assert!(warnings.finish().is_empty());
}

#[test]
fn map_function_sig_view_function_has_view_mutability() {
    let func = parse_first_function(
        "pragma solidity ^0.8.0; contract C { function totalSupply() public view returns (uint256) {} }",
    );
    let mut seen = BTreeMap::new();
    let mut warnings = WarningCollector::new();
    let lem_fn = map_function_sig(&func, &mut seen, &mut warnings).expect("should map");
    assert_eq!(lem_fn.name, "totalSupply");
    assert_eq!(lem_fn.mutability, LemMutability::View);
    assert_eq!(lem_fn.visibility, LemVisibility::Public);
    assert_eq!(lem_fn.returns, Some(LemType::U256));
}

#[test]
fn map_function_sig_pure_function_has_pure_mutability() {
    let func = parse_first_function(
        "pragma solidity ^0.8.0; contract C { function decimals() public pure returns (uint8) {} }",
    );
    let mut seen = BTreeMap::new();
    let mut warnings = WarningCollector::new();
    let lem_fn = map_function_sig(&func, &mut seen, &mut warnings).expect("should map");
    assert_eq!(lem_fn.mutability, LemMutability::Pure);
    assert_eq!(lem_fn.returns, Some(LemType::U8));
}

#[test]
fn map_function_sig_private_function_has_private_visibility() {
    let func = parse_first_function(
        "pragma solidity ^0.8.0; contract C { function _update(address from, address to, uint256 amount) internal {} }",
    );
    let mut seen = BTreeMap::new();
    let mut warnings = WarningCollector::new();
    let lem_fn = map_function_sig(&func, &mut seen, &mut warnings).expect("should map");
    // internal → Private in Lem
    assert_eq!(lem_fn.visibility, LemVisibility::Private);
    // Leading _ stripped from name
    assert_eq!(lem_fn.name, "update");
}

#[test]
fn map_function_sig_overloaded_gets_renamed_and_emits_w002() {
    let src = r#"
        pragma solidity ^0.8.0;
        contract C {
            function transfer(address to, uint256 amount) public returns (bool) {}
            function transfer(address to, uint256 amount, bytes memory data) public returns (bool) {}
        }
    "#;
    let contract = parse_contract(src);
    let mut seen = BTreeMap::new();
    let mut warnings = WarningCollector::new();

    let functions: Vec<LemFunction> = contract
        .parts
        .iter()
        .filter_map(|p| {
            if let pt::ContractPart::FunctionDefinition(f) = p {
                map_function_sig(f, &mut seen, &mut warnings)
            } else {
                None
            }
        })
        .collect();

    assert_eq!(functions[0].name, "transfer");
    assert_eq!(functions[1].name, "transfer_2");

    let emitted = warnings.finish();
    assert_eq!(emitted.len(), 1);
    assert_eq!(
        emitted[0].code,
        crate::warnings::WarningCode::FunctionOverloading
    );
    assert!(emitted[0].message.contains("transfer_2"));
}

#[test]
fn map_function_sig_modifier_returns_none() {
    let src = r#"
        pragma solidity ^0.8.0;
        contract C {
            modifier onlyOwner() { _; }
        }
    "#;
    let contract = parse_contract(src);
    let mut seen = BTreeMap::new();
    let mut warnings = WarningCollector::new();

    let mapped: Vec<Option<LemFunction>> = contract
        .parts
        .iter()
        .filter_map(|p| {
            if let pt::ContractPart::FunctionDefinition(f) = p {
                Some(map_function_sig(f, &mut seen, &mut warnings))
            } else {
                None
            }
        })
        .collect();

    // All modifier definitions should return None.
    assert!(mapped.iter().all(|f| f.is_none()));
}

#[test]
fn map_function_sig_bool_return_type() {
    let func = parse_first_function(
        "pragma solidity ^0.8.0; contract C { function approve(address spender, uint256 amount) public returns (bool) {} }",
    );
    let mut seen = BTreeMap::new();
    let mut warnings = WarningCollector::new();
    let lem_fn = map_function_sig(&func, &mut seen, &mut warnings).expect("should map");
    assert_eq!(lem_fn.returns, Some(LemType::Bool));
    assert_eq!(lem_fn.params.len(), 2);
    assert_eq!(lem_fn.params[0].name, "spender");
    assert_eq!(lem_fn.params[0].ty, LemType::Address);
    assert_eq!(lem_fn.params[1].name, "amount");
    assert_eq!(lem_fn.params[1].ty, LemType::U256);
}

#[test]
fn map_function_sig_no_return_is_none() {
    let func = parse_first_function(
        "pragma solidity ^0.8.0; contract C { function _mint(address to, uint256 amount) internal {} }",
    );
    let mut seen = BTreeMap::new();
    let mut warnings = WarningCollector::new();
    let lem_fn = map_function_sig(&func, &mut seen, &mut warnings).expect("should map");
    assert_eq!(lem_fn.returns, None);
}

// ── Event mapping tests ───────────────────────────────────────────────────────

#[test]
fn map_event_named_params_preserved() {
    let event = parse_first_event(
        "pragma solidity ^0.8.0; contract C { event Transfer(address indexed from, address indexed to, uint256 value); }",
    );
    let lem_event = map_event(&event);
    assert_eq!(lem_event.name, "Transfer");
    assert_eq!(lem_event.fields.len(), 3);
    assert_eq!(lem_event.fields[0].name, "from");
    assert!(lem_event.fields[0].indexed);
    assert_eq!(lem_event.fields[0].ty, LemType::Address);
    assert_eq!(lem_event.fields[1].name, "to");
    assert!(lem_event.fields[1].indexed);
    assert_eq!(lem_event.fields[2].name, "amount"); // value → amount
    assert!(!lem_event.fields[2].indexed);
}

#[test]
fn map_event_value_param_renamed_to_amount() {
    let event = parse_first_event(
        "pragma solidity ^0.8.0; contract C { event Approval(address indexed owner, address indexed spender, uint256 value); }",
    );
    let lem_event = map_event(&event);
    // `value` → `amount` per IToken convention (spec §13).
    assert_eq!(lem_event.fields[2].name, "amount");
}

#[test]
fn map_event_positional_params_get_names() {
    // Anonymous event parameters get positional fallback names.
    let event =
        parse_first_event("pragma solidity ^0.8.0; contract C { event Foo(address, uint256); }");
    let lem_event = map_event(&event);
    assert_eq!(lem_event.fields[0].name, "param0");
    assert_eq!(lem_event.fields[1].name, "param1");
}

// ── Enum mapping tests ────────────────────────────────────────────────────────

#[test]
fn map_enum_variants_preserved() {
    let en = parse_first_enum(
        "pragma solidity ^0.8.0; contract C { enum Status { Active, Inactive, Paused } }",
    );
    let lem_enum = map_enum(&en);
    assert_eq!(lem_enum.name, "Status");
    assert_eq!(lem_enum.variants, vec!["Active", "Inactive", "Paused"]);
}

#[test]
fn map_enum_single_variant() {
    let en = parse_first_enum("pragma solidity ^0.8.0; contract C { enum Phase { Launch } }");
    let lem_enum = map_enum(&en);
    assert_eq!(lem_enum.name, "Phase");
    assert_eq!(lem_enum.variants, vec!["Launch"]);
}

// ── Struct mapping tests ──────────────────────────────────────────────────────

#[test]
fn map_struct_fields_preserved() {
    let s = parse_first_struct(
        r#"pragma solidity ^0.8.0;
        contract C {
            struct VestingSchedule {
                uint256 start;
                uint256 duration;
                uint256 amount;
            }
        }"#,
    );
    let lem_struct = map_struct(&s);
    assert_eq!(lem_struct.name, "VestingSchedule");
    assert_eq!(lem_struct.fields.len(), 3);
    assert_eq!(lem_struct.fields[0].name, "start");
    assert_eq!(lem_struct.fields[0].ty, LemType::U256);
    assert_eq!(lem_struct.fields[2].name, "amount");
}

// ── Contract-level mapping tests ──────────────────────────────────────────────

#[test]
fn map_contract_ierc20_base_sets_uses_itoken() {
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        interface IERC20 {}
        contract MyToken is IERC20 {}"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert!(lem.uses_itoken, "IERC20 base should set uses_itoken");
}

#[test]
fn map_contract_ownable_base_sets_uses_ownable() {
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        contract Ownable {}
        contract MyToken is Ownable {}"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert!(lem.uses_ownable, "Ownable base should set uses_ownable");
}

#[test]
fn map_contract_pausable_base_sets_uses_pausable() {
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        contract Pausable {}
        contract MyToken is Pausable {}"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert!(lem.uses_pausable, "Pausable base should set uses_pausable");
}

#[test]
fn map_contract_access_control_base_sets_flag() {
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        contract AccessControl {}
        contract MyToken is AccessControl {}"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert!(
        lem.uses_access_control,
        "AccessControl base should set uses_access_control"
    );
}

#[test]
fn map_contract_unknown_interface_goes_to_uses() {
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        interface ICustom {}
        contract MyToken is ICustom {}"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert!(lem.uses.contains(&"ICustom".to_owned()));
}

#[test]
fn map_contract_concrete_base_goes_to_extends() {
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        contract ERC20Base {}
        contract MyToken is ERC20Base {}"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert!(lem.extends.contains(&"ERC20Base".to_owned()));
}

#[test]
fn map_contract_state_vars_collected() {
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        contract C {
            mapping(address => uint256) private _balances;
            uint256 private _totalSupply;
            address private _owner;
        }"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert_eq!(lem.state.len(), 3);
    assert_eq!(lem.state[0].name, "balances");
    assert_eq!(lem.state[1].name, "totalSupply");
    assert_eq!(lem.state[2].name, "owner");
}

#[test]
fn map_contract_events_collected() {
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        contract C {
            event Transfer(address indexed from, address indexed to, uint256 value);
            event Approval(address indexed owner, address indexed spender, uint256 value);
        }"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert_eq!(lem.events.len(), 2);
    assert_eq!(lem.events[0].name, "Transfer");
    assert_eq!(lem.events[1].name, "Approval");
}

#[test]
fn map_contract_functions_collected_with_populated_bodies() {
    // Batch 3: function bodies are now populated (not empty).
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        contract C {
            function totalSupply() public view returns (uint256) { return 0; }
            function balanceOf(address account) public view returns (uint256) { return 0; }
        }"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert_eq!(lem.functions.len(), 2);
    // Bodies are populated in Batch 3.
    assert!(!lem.functions[0].body.is_empty(), "totalSupply body should be populated");
    assert!(!lem.functions[1].body.is_empty(), "balanceOf body should be populated");
    // Both return 0 → Return(IntLit(0))
    assert_eq!(lem.functions[0].body, vec![LemStmt::Return(Some(LemExpr::IntLit(0)))]);
    assert_eq!(lem.functions[1].body, vec![LemStmt::Return(Some(LemExpr::IntLit(0)))]);
}

#[test]
fn map_contract_only_owner_modifier_sets_uses_ownable() {
    // Even without an Ownable base, using onlyOwner modifier sets the flag.
    let contract = parse_contract(
        r#"pragma solidity ^0.8.0;
        contract Ownable { modifier onlyOwner() { _; } }
        contract C is Ownable {
            function pause() public onlyOwner {}
        }"#,
    );
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);
    assert!(lem.uses_ownable);
}

#[test]
fn map_contract_full_erc20_shape() {
    // Smoke test: a minimal ERC-20 contract maps to the expected IR shape.
    let src = r#"
        pragma solidity ^0.8.0;
        interface IERC20 {}
        contract MyToken is IERC20 {
            mapping(address => uint256) private _balances;
            uint256 private _totalSupply;
            string private _name;

            event Transfer(address indexed from, address indexed to, uint256 value);
            event Approval(address indexed owner, address indexed spender, uint256 value);

            constructor(string memory name_) {
                _name = name_;
            }

            function totalSupply() public view returns (uint256) {
                return _totalSupply;
            }

            function balanceOf(address account) public view returns (uint256) {
                return _balances[account];
            }

            function transfer(address to, uint256 amount) public returns (bool) {
                return true;
            }
        }
    "#;
    let contract = parse_contract(src);
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);

    assert_eq!(lem.name, "MyToken");
    assert!(lem.uses_itoken);
    assert_eq!(lem.state.len(), 3);
    assert_eq!(lem.events.len(), 2);
    // constructor + 3 functions
    assert_eq!(lem.functions.len(), 4);
    assert_eq!(lem.functions[0].kind, LemFunctionKind::Constructor);
    assert_eq!(lem.functions[0].name, "init");
    assert!(warnings.finish().is_empty());
}

// ── Batch 3: Expression mapping tests ────────────────────────────────────────

/// Parse a Solidity function body and return its statements.
///
/// Wraps the function in a minimal contract so solang-parser can parse it.
fn parse_function_body(fn_src: &str) -> Vec<pt::Statement> {
    let contract_src = format!("pragma solidity ^0.8.0; contract T {{ {} }}", fn_src);
    let contract = parse_contract(&contract_src);
    let func_def = contract
        .parts
        .into_iter()
        .find_map(|p| {
            if let pt::ContractPart::FunctionDefinition(f) = p {
                Some(*f)
            } else {
                None
            }
        })
        .expect("no function found");
    match func_def.body {
        Some(pt::Statement::Block { statements, .. }) => statements,
        _ => vec![],
    }
}

#[test]
fn map_expr_number_literal_produces_int_lit() {
    let loc = pt::Loc::File(0, 0, 0);
    let expr = pt::Expression::NumberLiteral(loc, "42".to_owned(), "".to_owned(), None);
    let mut warnings = WarningCollector::new();
    let result = map_expr(&expr, &mut warnings);
    assert_eq!(result, LemExpr::IntLit(42));
    assert!(warnings.finish().is_empty());
}

#[test]
fn map_expr_bool_literal_true_produces_bool_lit() {
    let loc = pt::Loc::File(0, 0, 0);
    let expr = pt::Expression::BoolLiteral(loc, true);
    let mut warnings = WarningCollector::new();
    let result = map_expr(&expr, &mut warnings);
    assert_eq!(result, LemExpr::BoolLit(true));
}

#[test]
fn map_expr_bool_literal_false_produces_bool_lit() {
    let loc = pt::Loc::File(0, 0, 0);
    let expr = pt::Expression::BoolLiteral(loc, false);
    let mut warnings = WarningCollector::new();
    let result = map_expr(&expr, &mut warnings);
    assert_eq!(result, LemExpr::BoolLit(false));
}

#[test]
fn map_expr_string_literal_produces_string_lit() {
    let loc = pt::Loc::File(0, 0, 0);
    let expr = pt::Expression::StringLiteral(vec![pt::StringLiteral {
        loc,
        unicode: false,
        string: "hello".to_owned(),
    }]);
    let mut warnings = WarningCollector::new();
    let result = map_expr(&expr, &mut warnings);
    assert_eq!(result, LemExpr::StringLit("hello".to_owned()));
}

#[test]
fn map_expr_variable_ident_produces_ident() {
    let loc = pt::Loc::File(0, 0, 0);
    let expr = pt::Expression::Variable(pt::Identifier {
        loc,
        name: "myVar".to_owned(),
    });
    let mut warnings = WarningCollector::new();
    let result = map_expr(&expr, &mut warnings);
    assert_eq!(result, LemExpr::Ident("myVar".to_owned()));
}

#[test]
fn map_expr_member_access_msg_sender() {
    // `msg.sender` → MemberAccess(Ident("msg"), "sender")
    let stmts = parse_function_body(
        r#"function f() public view returns (address) { return msg.sender; }"#,
    );
    let mut warnings = WarningCollector::new();
    // The return statement contains the member access expression.
    let stmt = map_stmt(&stmts[0], &mut warnings);
    assert!(
        matches!(
            stmt,
            LemStmt::Return(Some(LemExpr::MemberAccess(ref inner, ref field)))
            if matches!(inner.as_ref(), LemExpr::Ident(n) if n == "msg")
            && field == "sender"
        ),
        "expected Return(MemberAccess(Ident(msg), sender)), got: {stmt:?}"
    );
}

#[test]
fn map_expr_add_binary_op_produces_binary_op() {
    let loc = pt::Loc::File(0, 0, 0);
    let left = Box::new(pt::Expression::NumberLiteral(
        loc,
        "1".to_owned(),
        "".to_owned(),
        None,
    ));
    let right = Box::new(pt::Expression::NumberLiteral(
        loc,
        "2".to_owned(),
        "".to_owned(),
        None,
    ));
    let expr = pt::Expression::Add(loc, left, right);
    let mut warnings = WarningCollector::new();
    let result = map_expr(&expr, &mut warnings);
    assert_eq!(
        result,
        LemExpr::BinaryOp {
            op: BinOp::Add,
            left: Box::new(LemExpr::IntLit(1)),
            right: Box::new(LemExpr::IntLit(2)),
        }
    );
}

#[test]
fn map_expr_comparison_less_produces_lt_op() {
    let loc = pt::Loc::File(0, 0, 0);
    let left = Box::new(pt::Expression::Variable(pt::Identifier {
        loc,
        name: "a".to_owned(),
    }));
    let right = Box::new(pt::Expression::NumberLiteral(
        loc,
        "10".to_owned(),
        "".to_owned(),
        None,
    ));
    let expr = pt::Expression::Less(loc, left, right);
    let mut warnings = WarningCollector::new();
    let result = map_expr(&expr, &mut warnings);
    assert_eq!(
        result,
        LemExpr::BinaryOp {
            op: BinOp::Lt,
            left: Box::new(LemExpr::Ident("a".to_owned())),
            right: Box::new(LemExpr::IntLit(10)),
        }
    );
}

#[test]
fn map_expr_logical_not_produces_unary_not() {
    let loc = pt::Loc::File(0, 0, 0);
    let inner = Box::new(pt::Expression::BoolLiteral(loc, true));
    let expr = pt::Expression::Not(loc, inner);
    let mut warnings = WarningCollector::new();
    let result = map_expr(&expr, &mut warnings);
    assert_eq!(
        result,
        LemExpr::UnaryOp {
            op: UnaryOp::Not,
            expr: Box::new(LemExpr::BoolLit(true)),
        }
    );
}

#[test]
fn map_expr_address_zero_cast_produces_address_lit() {
    // `address(0)` → AddressLit("Address.zero")
    let stmts = parse_function_body(
        r#"function f() public pure returns (address) { return address(0); }"#,
    );
    let mut warnings = WarningCollector::new();
    let stmt = map_stmt(&stmts[0], &mut warnings);
    assert!(
        matches!(stmt, LemStmt::Return(Some(LemExpr::AddressLit(ref s))) if s == "Address.zero"),
        "expected Return(AddressLit(Address.zero)), got: {stmt:?}"
    );
}

// ── Batch 3: Statement mapping tests ─────────────────────────────────────────

#[test]
fn map_stmt_return_expr_produces_return() {
    let stmts = parse_function_body(
        r#"function f() public pure returns (uint256) { return 42; }"#,
    );
    let mut warnings = WarningCollector::new();
    let stmt = map_stmt(&stmts[0], &mut warnings);
    assert_eq!(stmt, LemStmt::Return(Some(LemExpr::IntLit(42))));
}

#[test]
fn map_stmt_require_becomes_assert() {
    // `require(condition, "msg")` → `LemStmt::Assert { cond, msg }`
    let stmts = parse_function_body(
        r#"function f(uint256 x) public pure { require(x > 0, "must be positive"); }"#,
    );
    let mut warnings = WarningCollector::new();
    let stmt = map_stmt(&stmts[0], &mut warnings);
    match stmt {
        LemStmt::Assert { cond, msg } => {
            assert_eq!(msg, "must be positive");
            // cond should be x > 0
            assert!(
                matches!(cond, LemExpr::BinaryOp { op: BinOp::Gt, .. }),
                "expected Gt binary op, got: {cond:?}"
            );
        }
        other => panic!("expected Assert, got: {other:?}"),
    }
}

#[test]
fn map_stmt_if_else_produces_if_stmt() {
    let stmts = parse_function_body(
        r#"function f(bool b) public pure returns (uint256) {
            if (b) { return 1; } else { return 2; }
        }"#,
    );
    let mut warnings = WarningCollector::new();
    let stmt = map_stmt(&stmts[0], &mut warnings);
    match stmt {
        LemStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            assert_eq!(cond, LemExpr::Ident("b".to_owned()));
            assert_eq!(then_body, vec![LemStmt::Return(Some(LemExpr::IntLit(1)))]);
            assert_eq!(
                else_body,
                Some(vec![LemStmt::Return(Some(LemExpr::IntLit(2)))])
            );
        }
        other => panic!("expected If, got: {other:?}"),
    }
}

#[test]
fn map_stmt_assembly_emits_w001_and_raw() {
    // Inline assembly → W001 warning + Raw fallback.
    let stmts = parse_function_body(
        r#"function f() public pure returns (uint256 result) {
            assembly { result := 42 }
        }"#,
    );
    let mut warnings = WarningCollector::new();
    let stmt = map_stmt(&stmts[0], &mut warnings);
    // Must produce a Raw fallback.
    assert!(
        matches!(stmt, LemStmt::Raw(ref s) if s.contains("W001")),
        "expected Raw with W001, got: {stmt:?}"
    );
    // Must emit exactly one W001 warning.
    let emitted = warnings.finish();
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].code, crate::warnings::WarningCode::InlineAssembly);
}

#[test]
fn map_stmt_unchecked_block_emits_w003() {
    // `unchecked { x = x + 1; }` → W003 warning + normal mapping.
    let stmts = parse_function_body(
        r#"function f(uint256 x) public pure returns (uint256) {
            unchecked { return x + 1; }
        }"#,
    );
    let mut warnings = WarningCollector::new();
    let _stmt = map_stmt(&stmts[0], &mut warnings);
    let emitted = warnings.finish();
    assert_eq!(emitted.len(), 1);
    assert_eq!(emitted[0].code, crate::warnings::WarningCode::UncheckedBlock);
}

#[test]
fn map_function_body_is_populated_after_batch3() {
    // After Batch 3, function bodies must be non-empty for functions with bodies.
    let func = parse_first_function(
        r#"pragma solidity ^0.8.0;
        contract C {
            function totalSupply() public view returns (uint256) {
                return 100;
            }
        }"#,
    );
    let mut seen = BTreeMap::new();
    let mut warnings = WarningCollector::new();
    let lem_fn = map_function_sig(&func, &mut seen, &mut warnings).expect("should map");
    // Body must be populated — Batch 3 fills it.
    assert!(
        !lem_fn.body.is_empty(),
        "function body should be populated after Batch 3"
    );
    assert_eq!(lem_fn.body, vec![LemStmt::Return(Some(LemExpr::IntLit(100)))]);
}

#[test]
fn map_contract_function_bodies_not_empty() {
    // End-to-end: parse ERC-20 snippet with bodies — all non-abstract functions
    // must have non-empty bodies after Batch 3.
    let src = r#"
        pragma solidity ^0.8.0;
        interface IERC20 {}
        contract MyToken is IERC20 {
            mapping(address => uint256) private _balances;
            uint256 private _totalSupply;

            event Transfer(address indexed from, address indexed to, uint256 value);

            constructor(uint256 initialSupply) {
                _totalSupply = initialSupply;
            }

            function totalSupply() public view returns (uint256) {
                return _totalSupply;
            }

            function transfer(address to, uint256 amount) public returns (bool) {
                require(amount > 0, "zero amount");
                _balances[to] = _balances[to] + amount;
                emit Transfer(msg.sender, to, amount);
                return true;
            }
        }
    "#;
    let contract = parse_contract(src);
    let mut warnings = WarningCollector::new();
    let lem = map_contract(&contract, &mut warnings);

    // All 3 functions (constructor + 2 methods) must have non-empty bodies.
    assert_eq!(lem.functions.len(), 3);
    for func in &lem.functions {
        assert!(
            !func.body.is_empty(),
            "function '{}' body should not be empty",
            func.name
        );
    }

    // Constructor body: `_totalSupply = initialSupply` → Assign
    let constructor = &lem.functions[0];
    assert_eq!(constructor.name, "init");
    assert!(
        matches!(constructor.body[0], LemStmt::Assign { .. }),
        "constructor body[0] should be Assign, got: {:?}",
        constructor.body[0]
    );

    // totalSupply body: `return _totalSupply` → Return(Ident)
    let total_supply = &lem.functions[1];
    assert_eq!(total_supply.name, "totalSupply");
    assert!(
        matches!(total_supply.body[0], LemStmt::Return(Some(LemExpr::Ident(_)))),
        "totalSupply body[0] should be Return(Ident), got: {:?}",
        total_supply.body[0]
    );

    // transfer body: require → Assert, assign → Assign, emit → Emit, return → Return
    let transfer = &lem.functions[2];
    assert_eq!(transfer.name, "transfer");
    assert!(
        matches!(transfer.body[0], LemStmt::Assert { .. }),
        "transfer body[0] should be Assert (from require), got: {:?}",
        transfer.body[0]
    );
    assert!(
        matches!(transfer.body[1], LemStmt::Assign { .. }),
        "transfer body[1] should be Assign, got: {:?}",
        transfer.body[1]
    );
    assert!(
        matches!(transfer.body[2], LemStmt::Emit { .. }),
        "transfer body[2] should be Emit, got: {:?}",
        transfer.body[2]
    );
    assert!(
        matches!(transfer.body[3], LemStmt::Return(Some(LemExpr::BoolLit(true)))),
        "transfer body[3] should be Return(true), got: {:?}",
        transfer.body[3]
    );
}
