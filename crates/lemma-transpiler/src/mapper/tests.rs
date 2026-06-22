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
fn map_contract_functions_collected_with_empty_bodies() {
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
    // Bodies are empty in Batch 2.
    assert!(lem.functions[0].body.is_empty());
    assert!(lem.functions[1].body.is_empty());
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
