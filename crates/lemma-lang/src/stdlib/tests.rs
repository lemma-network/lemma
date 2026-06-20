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
