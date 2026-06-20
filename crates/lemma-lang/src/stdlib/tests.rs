use super::*;

#[test]
fn get_returns_token_module() {
    let reg = StdLibRegistry::new();
    assert!(reg.get("token").is_some());
}

#[test]
fn get_returns_access_module() {
    let reg = StdLibRegistry::new();
    assert!(reg.get("access").is_some());
}

#[test]
fn get_returns_interfaces_module() {
    let reg = StdLibRegistry::new();
    assert!(reg.get("interfaces").is_some());
}

#[test]
fn get_returns_none_for_unknown_module() {
    let reg = StdLibRegistry::new();
    assert!(reg.get("nonexistent").is_none());
}

#[test]
fn available_modules_lists_all() {
    let reg = StdLibRegistry::new();
    let modules = reg.available_modules();
    assert!(modules.contains(&"token"));
    assert!(modules.contains(&"access"));
    assert!(modules.contains(&"interfaces"));
    assert_eq!(modules.len(), 3);
}

#[test]
fn default_equals_new() {
    let a = StdLibRegistry::new();
    let b = StdLibRegistry::default();
    assert_eq!(a.available_modules(), b.available_modules());
}

#[test]
fn get_returns_nonempty_source() {
    let reg = StdLibRegistry::new();
    // Each embedded .lem file should contain at least a comment.
    for module in reg.available_modules() {
        let src = reg.get(module).expect("module should exist");
        assert!(!src.is_empty(), "{module} source should not be empty");
    }
}

#[test]
fn available_modules_sorted() {
    let reg = StdLibRegistry::new();
    let modules = reg.available_modules();
    // BTreeMap guarantees sorted order — verify the contract.
    let mut sorted = modules.clone();
    sorted.sort();
    assert_eq!(modules, sorted);
}

// ── symbol_kind export map ────────────────────────────────────────────────────

#[test]
fn symbol_kind_returns_contract_for_token() {
    let reg = StdLibRegistry::new();
    assert_eq!(
        reg.symbol_kind("token", "Token"),
        Some(SymbolKind::Contract),
    );
}

#[test]
fn symbol_kind_returns_contract_for_tax_token() {
    let reg = StdLibRegistry::new();
    assert_eq!(
        reg.symbol_kind("token", "TaxToken"),
        Some(SymbolKind::Contract),
    );
}

#[test]
fn symbol_kind_returns_interface_for_itoken() {
    let reg = StdLibRegistry::new();
    assert_eq!(
        reg.symbol_kind("interfaces", "IToken"),
        Some(SymbolKind::Interface),
    );
}

#[test]
fn symbol_kind_returns_trait_for_ownable() {
    let reg = StdLibRegistry::new();
    assert_eq!(
        reg.symbol_kind("access", "Ownable"),
        Some(SymbolKind::Trait),
    );
}

#[test]
fn symbol_kind_returns_struct_for_approval_opts() {
    let reg = StdLibRegistry::new();
    assert_eq!(
        reg.symbol_kind("interfaces", "ApprovalOpts"),
        Some(SymbolKind::Struct),
    );
}

#[test]
fn symbol_kind_returns_none_for_unknown_name() {
    let reg = StdLibRegistry::new();
    assert_eq!(reg.symbol_kind("token", "Nonexistent"), None);
}

#[test]
fn symbol_kind_returns_none_for_unknown_module() {
    let reg = StdLibRegistry::new();
    assert_eq!(reg.symbol_kind("nonexistent", "Token"), None);
}

// ── module_name / is_std_module ───────────────────────────────────────────────

#[test]
fn module_name_extracts_from_std_path() {
    assert_eq!(StdLibRegistry::module_name("@std/token"), Some("token"));
}

#[test]
fn module_name_extracts_nested_path() {
    assert_eq!(
        StdLibRegistry::module_name("@std/interfaces"),
        Some("interfaces"),
    );
}

#[test]
fn module_name_returns_none_for_non_std() {
    assert_eq!(StdLibRegistry::module_name("./local"), None);
}

#[test]
fn module_name_returns_none_for_bare_name() {
    assert_eq!(StdLibRegistry::module_name("token"), None);
}

#[test]
fn is_std_module_true_for_std_path() {
    assert!(StdLibRegistry::is_std_module("@std/token"));
}

#[test]
fn is_std_module_false_for_relative_path() {
    assert!(!StdLibRegistry::is_std_module("./local"));
}

#[test]
fn is_std_module_false_for_bare_name() {
    assert!(!StdLibRegistry::is_std_module("token"));
}

// ── base_members ──────────────────────────────────────────────────────────────

#[test]
fn base_members_returns_token_fields_and_functions() {
    let members = StdLibRegistry::base_members("Token").expect("Token should have base members");
    let field_names: Vec<&str> = members.state_fields.iter().map(|f| f.name).collect();
    assert!(
        field_names.contains(&"balances"),
        "Token should have balances"
    );
    assert!(
        field_names.contains(&"totalSupply"),
        "Token should have totalSupply"
    );
    assert!(field_names.contains(&"owner"), "Token should have owner");
    assert!(
        field_names.contains(&"allowances"),
        "Token should have allowances"
    );

    let fn_names: Vec<&str> = members.functions.iter().map(|f| f.name).collect();
    assert!(fn_names.contains(&"transfer"), "Token should have transfer");
    assert!(fn_names.contains(&"approve"), "Token should have approve");
    assert!(fn_names.contains(&"mint"), "Token should have mint");
}

#[test]
fn base_members_returns_tax_token_includes_token_fields() {
    let members =
        StdLibRegistry::base_members("TaxToken").expect("TaxToken should have base members");
    let field_names: Vec<&str> = members.state_fields.iter().map(|f| f.name).collect();
    // Token fields:
    assert!(
        field_names.contains(&"balances"),
        "TaxToken should inherit balances"
    );
    assert!(
        field_names.contains(&"owner"),
        "TaxToken should inherit owner"
    );
    // TaxToken-specific:
    assert!(
        field_names.contains(&"taxPool"),
        "TaxToken should have taxPool"
    );
    assert!(field_names.contains(&"pairs"), "TaxToken should have pairs");
}

#[test]
fn base_members_returns_ownable_fields_and_functions() {
    let members =
        StdLibRegistry::base_members("Ownable").expect("Ownable should have base members");
    let field_names: Vec<&str> = members.state_fields.iter().map(|f| f.name).collect();
    assert_eq!(field_names, vec!["owner"]);

    let fn_names: Vec<&str> = members.functions.iter().map(|f| f.name).collect();
    assert!(fn_names.contains(&"transferOwnership"));
    assert!(fn_names.contains(&"renounceOwnership"));
    assert!(fn_names.contains(&"isRenounced"));
}

#[test]
fn base_members_returns_pausable_fields_and_functions() {
    let members =
        StdLibRegistry::base_members("Pausable").expect("Pausable should have base members");
    let field_names: Vec<&str> = members.state_fields.iter().map(|f| f.name).collect();
    assert_eq!(field_names, vec!["paused"]);

    let fn_names: Vec<&str> = members.functions.iter().map(|f| f.name).collect();
    assert!(fn_names.contains(&"pause"));
    assert!(fn_names.contains(&"unpause"));
}

#[test]
fn base_members_returns_access_control_fields_and_functions() {
    let members = StdLibRegistry::base_members("AccessControl")
        .expect("AccessControl should have base members");
    let field_names: Vec<&str> = members.state_fields.iter().map(|f| f.name).collect();
    assert_eq!(field_names, vec!["roles"]);

    let fn_names: Vec<&str> = members.functions.iter().map(|f| f.name).collect();
    assert!(fn_names.contains(&"hasRole"));
    assert!(fn_names.contains(&"grantRole"));
    assert!(fn_names.contains(&"revokeRole"));
}

#[test]
fn base_members_returns_none_for_unknown() {
    assert!(StdLibRegistry::base_members("UnknownBase").is_none());
}
