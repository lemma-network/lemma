//! Tests for the top-level `transpile()` public API.

use super::{transpile, TranspileError};

const SIMPLE_ERC20: &str = r#"
pragma solidity ^0.8.0;

contract SimpleToken {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }
}
"#;

#[test]
fn transpile_returns_contract_name() {
    let result = transpile(SIMPLE_ERC20).expect("should succeed");
    assert_eq!(result.contract_name, "SimpleToken");
}

#[test]
fn transpile_lem_source_is_non_empty() {
    let result = transpile(SIMPLE_ERC20).expect("should succeed");
    assert!(!result.lem_source.is_empty());
}

#[test]
fn transpile_no_warnings_for_simple_contract() {
    let result = transpile(SIMPLE_ERC20).expect("should succeed");
    // Simple ERC-20 has no assembly or overloaded fns — zero warnings expected.
    assert!(result.warnings.is_empty());
}

#[test]
fn transpile_invalid_solidity_returns_parse_error() {
    let bad_source = "this is not solidity { {{ broken";
    let err = transpile(bad_source).expect_err("should fail to parse");
    assert!(matches!(err, TranspileError::ParseError { .. }));
}

#[test]
fn transpile_empty_source_returns_no_contract_found() {
    // Empty source or pragma-only → no contract definition
    let pragma_only = "pragma solidity ^0.8.0;";
    let err = transpile(pragma_only).expect_err("should fail: no contract");
    assert!(matches!(err, TranspileError::NoContractFound));
}
