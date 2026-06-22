//! Tests for the `sol_parser` module (solang-parser wrapper).

use super::{extract_primary_contract_name, parse_solidity};

#[test]
fn parse_valid_contract_succeeds() {
    let src = r#"
        pragma solidity ^0.8.0;
        contract Foo { uint256 x; }
    "#;
    let unit = parse_solidity(src).expect("valid solidity should parse");
    assert!(!unit.0.is_empty());
}

#[test]
fn parse_invalid_source_returns_error() {
    let src = "NOT SOLIDITY { {{";
    assert!(parse_solidity(src).is_err());
}

#[test]
fn extract_name_finds_contract() {
    let src = r#"
        pragma solidity ^0.8.0;
        interface IERC20 { }
        contract MyToken { }
    "#;
    let unit = parse_solidity(src).unwrap();
    // Should pick the contract, not the interface
    let name = extract_primary_contract_name(&unit);
    assert_eq!(name.as_deref(), Some("MyToken"));
}

#[test]
fn extract_name_returns_none_for_interface_only() {
    let src = r#"
        pragma solidity ^0.8.0;
        interface IToken { function balanceOf(address a) external view returns (uint256); }
    "#;
    let unit = parse_solidity(src).unwrap();
    let name = extract_primary_contract_name(&unit);
    assert!(name.is_none(), "interface-only should return None");
}

#[test]
fn extract_name_returns_first_contract() {
    let src = r#"
        pragma solidity ^0.8.0;
        contract Alpha { }
        contract Beta { }
    "#;
    let unit = parse_solidity(src).unwrap();
    let name = extract_primary_contract_name(&unit);
    assert_eq!(name.as_deref(), Some("Alpha"));
}

#[test]
fn extract_name_skips_abstract_contract() {
    // Real ERC-20 pattern: abstract base first, concrete token last.
    // extract_primary_contract_name must skip the abstract and return the concrete.
    let src = r#"
        pragma solidity ^0.8.0;
        abstract contract ERC20Base {
            mapping(address => uint256) internal _balances;
        }
        contract MyToken is ERC20Base { }
    "#;
    let unit = parse_solidity(src).expect("should parse");
    let name = extract_primary_contract_name(&unit);
    // Must NOT return "ERC20Base" (that's abstract, ContractTy::Abstract)
    assert_eq!(
        name.as_deref(),
        Some("MyToken"),
        "should skip abstract and return concrete contract"
    );
}
