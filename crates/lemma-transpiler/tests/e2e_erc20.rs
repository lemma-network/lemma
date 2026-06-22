//! End-to-end integration tests: Solidity ERC-20 → Lem transpilation + parse.
//!
//! Each test calls `lemma_transpiler::transpile()` with real Solidity source and
//! verifies the output round-trips through `lemma_lang::tokenize + filter + parse`.
//!
//! The `parse_lem` helper filters comment trivia before parsing — the Lem parser
//! processes logic tokens only (LineComment/BlockComment/DocComment are emitted by
//! the tokenizer for LSP/doc tools but must be stripped before `parse()`).

use lemma_transpiler::{TranspileResult, WarningCode};

// ── Parse helper ─────────────────────────────────────────────────────────────

/// Tokenize, filter comment trivia, and parse Lem source.
///
/// Panics with a descriptive message if tokenization or parsing fails,
/// making test failures easy to diagnose.
fn parse_lem(src: &str) {
    use lemma_lang::lexer::token::Token;
    let tokens =
        lemma_lang::tokenize(src).unwrap_or_else(|e| panic!("tokenize failed:\n{src}\n{e:?}"));
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
    lemma_lang::parse(non_trivia).unwrap_or_else(|e| panic!("parse failed:\n{src}\n{e:?}"));
}

// ── Shared Solidity fixtures ──────────────────────────────────────────────────

/// Minimal ERC-20 with state + two view functions.
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

/// ERC-20 with `require` (→ assert) and `emit Transfer`.
const ERC20_WITH_TRANSFER: &str = r#"
pragma solidity ^0.8.0;

contract TransferToken {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 value);

    function transfer(address to, uint256 amount) public returns (bool) {
        require(_balances[msg.sender] >= amount, "Insufficient balance");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
"#;

/// ERC-20 with `mapping(address => uint256)` state.
const ERC20_WITH_MAPPING: &str = r#"
pragma solidity ^0.8.0;

contract MappingToken {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }
}
"#;

/// ERC-20 implementing IERC20 interface.
const ERC20_IMPLEMENTS_IERC20: &str = r#"
pragma solidity ^0.8.0;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract IfaceToken is IERC20 {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

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

/// ERC-20 with `onlyOwner` modifier.
const ERC20_WITH_ONLYOWNER: &str = r#"
pragma solidity ^0.8.0;

contract OwnableToken {
    address private _owner;
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    modifier onlyOwner() {
        require(msg.sender == _owner, "Not owner");
        _;
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _balances[to] += amount;
        _totalSupply += amount;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }
}
"#;

/// ERC-20 with inline assembly block (→ W001 warning).
const ERC20_WITH_ASSEMBLY: &str = r#"
pragma solidity ^0.8.0;

contract AssemblyToken {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function getCodeSize(address addr) public view returns (uint256 size) {
        assembly {
            size := extcodesize(addr)
        }
    }
}
"#;

/// ERC-20 with overloaded `transfer` function (→ W002 warning + rename).
const ERC20_WITH_OVERLOAD: &str = r#"
pragma solidity ^0.8.0;

contract OverloadToken {
    mapping(address => uint256) private _balances;
    uint256 private _totalSupply;

    function transfer(address to, uint256 amount) public returns (bool) {
        return true;
    }

    function transfer(address to, uint256 amount, bytes memory data) public returns (bool) {
        return true;
    }
}
"#;

/// Full OpenZeppelin-style ERC-20 with all standard functions, events, and constructor.
const FULL_OZ_ERC20: &str = r#"
pragma solidity ^0.8.0;

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract FullERC20 is IERC20 {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _totalSupply;
    string private _name;
    string private _symbol;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(_balances[msg.sender] >= amount, "Insufficient balance");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        _allowances[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(_allowances[from][msg.sender] >= amount, "Insufficient allowance");
        _allowances[from][msg.sender] -= amount;
        require(_balances[from] >= amount, "Insufficient balance");
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
"#;

// ── E2E tests ─────────────────────────────────────────────────────────────────

/// 1. Minimal ERC-20 with state + view functions transpiles and parses.
#[test]
fn e2e_simple_erc20_transpiles_and_parses() {
    let result = lemma_transpiler::transpile(SIMPLE_ERC20).expect("should transpile");
    assert_eq!(result.contract_name, "SimpleToken");
    // No warnings expected for a simple contract.
    assert!(
        result.warnings.is_empty(),
        "expected no warnings, got: {:?}",
        result.warnings
    );
    parse_lem(&result.lem_source);
}

/// 2. ERC-20 with `require` (→ assert) and `emit Transfer` transpiles correctly.
#[test]
fn e2e_erc20_with_transfer_fn_transpiles() {
    let result = lemma_transpiler::transpile(ERC20_WITH_TRANSFER).expect("should transpile");
    assert_eq!(result.contract_name, "TransferToken");
    // `require(cond, msg)` → `assert(cond, msg)` in Lem.
    assert!(
        result.lem_source.contains("assert("),
        "expected 'assert(' in output, got:\n{}",
        result.lem_source
    );
    // `emit Transfer(...)` → `emit Transfer { ... }` in Lem.
    assert!(
        result.lem_source.contains("emit Transfer"),
        "expected 'emit Transfer' in output, got:\n{}",
        result.lem_source
    );
    parse_lem(&result.lem_source);
}

/// 3. `mapping(address => uint256)` state → `Map<Address, u128>` in Lem output.
#[test]
fn e2e_erc20_with_mapping_state_transpiles() {
    let result = lemma_transpiler::transpile(ERC20_WITH_MAPPING).expect("should transpile");
    assert_eq!(result.contract_name, "MappingToken");
    // Solidity `mapping(address => uint256)` → Lem `Map<Address, u128>`.
    assert!(
        result.lem_source.contains("Map<Address,"),
        "expected 'Map<Address,' in output, got:\n{}",
        result.lem_source
    );
    parse_lem(&result.lem_source);
}

/// 4. `contract C is IERC20` → `implements IToken` in Lem output.
#[test]
fn e2e_erc20_implements_ierc20_outputs_implements() {
    let result = lemma_transpiler::transpile(ERC20_IMPLEMENTS_IERC20).expect("should transpile");
    assert_eq!(result.contract_name, "IfaceToken");
    // IERC20 interface → IToken in Lem (Lemma naming convention, AGENTS §10).
    assert!(
        result.lem_source.contains("implements IToken"),
        "expected 'implements IToken' in output, got:\n{}",
        result.lem_source
    );
    // Must NOT use `uses IToken` — interfaces go in `implements`, traits in `uses`.
    assert!(
        !result.lem_source.contains("uses IToken"),
        "should NOT contain 'uses IToken', got:\n{}",
        result.lem_source
    );
    parse_lem(&result.lem_source);
}

/// 5. `onlyOwner` modifier → `@onlyOwner` decorator in Lem output.
#[test]
fn e2e_erc20_with_onlyowner_modifier_transpiles() {
    let result = lemma_transpiler::transpile(ERC20_WITH_ONLYOWNER).expect("should transpile");
    assert_eq!(result.contract_name, "OwnableToken");
    // `onlyOwner` modifier usage → `@onlyOwner` decorator in Lem.
    assert!(
        result.lem_source.contains("@onlyOwner"),
        "expected '@onlyOwner' decorator in output, got:\n{}",
        result.lem_source
    );
    parse_lem(&result.lem_source);
}

/// 6. Contract with inline assembly block → W001 warning in result.
#[test]
fn e2e_erc20_inline_assembly_emits_w001_warning() {
    let result = lemma_transpiler::transpile(ERC20_WITH_ASSEMBLY).expect("should transpile");
    assert_eq!(result.contract_name, "AssemblyToken");
    // Inline assembly → exactly one W001 warning.
    let w001_count = result
        .warnings
        .iter()
        .filter(|w| w.code == WarningCode::InlineAssembly)
        .count();
    assert_eq!(
        w001_count,
        1,
        "expected exactly 1 W001 warning, got {} warnings: {:?}",
        result.warnings.len(),
        result.warnings
    );
    // Output must still parse — assembly block is skipped, not fatal.
    parse_lem(&result.lem_source);
}

/// 7. Contract with overloaded `transfer` → W002 warning + renamed function.
#[test]
fn e2e_erc20_overloaded_fn_emits_w002_warning() {
    let result = lemma_transpiler::transpile(ERC20_WITH_OVERLOAD).expect("should transpile");
    assert_eq!(result.contract_name, "OverloadToken");
    // Overloaded function → exactly one W002 warning.
    let w002_count = result
        .warnings
        .iter()
        .filter(|w| w.code == WarningCode::FunctionOverloading)
        .count();
    assert_eq!(
        w002_count,
        1,
        "expected exactly 1 W002 warning, got {} warnings: {:?}",
        result.warnings.len(),
        result.warnings
    );
    // The renamed function (`transfer_2`) must appear in the output.
    assert!(
        result.lem_source.contains("transfer_2"),
        "expected renamed 'transfer_2' in output, got:\n{}",
        result.lem_source
    );
    // Output must still parse — overload rename is non-fatal.
    parse_lem(&result.lem_source);
}

/// 8. Full OpenZeppelin-style ERC-20 (all standard functions + events + constructor) transpiles.
#[test]
fn e2e_full_openzeppelin_style_erc20_transpiles() {
    let result = lemma_transpiler::transpile(FULL_OZ_ERC20).expect("should transpile");
    assert_eq!(result.contract_name, "FullERC20");

    // All six standard ERC-20 functions must appear in the output.
    for fn_name in &[
        "totalSupply",
        "balanceOf",
        "transfer",
        "allowance",
        "approve",
        "transferFrom",
    ] {
        assert!(
            result.lem_source.contains(fn_name),
            "expected function '{}' in output, got:\n{}",
            fn_name,
            result.lem_source
        );
    }

    // Both standard events must appear.
    assert!(
        result.lem_source.contains("event Transfer"),
        "expected 'event Transfer' in output, got:\n{}",
        result.lem_source
    );
    assert!(
        result.lem_source.contains("event Approval"),
        "expected 'event Approval' in output, got:\n{}",
        result.lem_source
    );

    // Constructor → `init(...)` keyword form (not `fn init`).
    assert!(
        result.lem_source.contains("init("),
        "expected 'init(' constructor in output, got:\n{}",
        result.lem_source
    );
    assert!(
        !result.lem_source.contains("fn init("),
        "constructor should NOT use 'fn init(', got:\n{}",
        result.lem_source
    );

    // IERC20 → implements IToken.
    assert!(
        result.lem_source.contains("implements IToken"),
        "expected 'implements IToken' in output, got:\n{}",
        result.lem_source
    );

    // Full round-trip: output must parse without error.
    parse_lem(&result.lem_source);
}

// ── Structural assertions ─────────────────────────────────────────────────────

/// Verify that `TranspileResult` fields are all populated for a successful transpile.
#[test]
fn e2e_transpile_result_fields_populated() {
    let TranspileResult {
        lem_source,
        warnings,
        contract_name,
    } = lemma_transpiler::transpile(SIMPLE_ERC20).expect("should transpile");
    assert_eq!(contract_name, "SimpleToken");
    assert!(!lem_source.is_empty(), "lem_source must not be empty");
    // Warnings vec is present (may be empty for a clean contract).
    let _ = warnings; // accessed to confirm field exists
}

/// Verify that the Lem output contains a `contract` keyword (may be preceded by preamble comment).
#[test]
fn e2e_lem_output_contains_contract_keyword() {
    let result = lemma_transpiler::transpile(SIMPLE_ERC20).expect("should transpile");
    assert!(
        result.lem_source.contains("contract "),
        "Lem output must contain 'contract ', got:\n{}",
        &result.lem_source[..result.lem_source.len().min(200)]
    );
}
