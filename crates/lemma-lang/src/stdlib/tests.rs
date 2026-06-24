use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::lexer::token::Token;
use crate::lexer::tokenize;

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
    assert!(modules.contains(&"agent"));
    assert!(modules.contains(&"interfaces"));
    assert_eq!(modules.len(), 4);
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

// ── base_members ↔ .lem source sync guard (AGENTS §2: one canonical way) ───────
//
// The `.lem` files are the CANONICAL source of the @std standard; `base_members()`
// is a hand-maintained mirror used for symbol resolution until full re-entrant
// parse+check of the `.lem` files lands (P3-own-1 / @std-field-schema-1 — Phase 4).
// These two MUST agree. This guard extracts the member names of the relevant
// contract / token / trait from each embedded `.lem` and asserts BIDIRECTIONAL
// equality against `base_members()`:
//   - every member in `base_members()` exists in the `.lem` source, and
//   - every member declared in the `.lem` source exists in `base_members()`.
// It also asserts the `is_public` flag matches the `.lem` `pub` modifier.
//
// `distributeTaxes` / `isTaxable` are dev-implemented (WF-014), so they are
// intentionally absent from BOTH sides — they live in user code, not the base.
//
// ## Why a token-stream extractor, not full `parse()`?
//
// The `.lem` standard files cannot yet be fully parsed by `parse()`: the parser
// does not accept `event` members inside `trait` bodies (`TraitMember` has no
// Event variant) nor newline-separated struct-literal bodies inside function
// bodies — both are part of the deferred re-entrant-parse work (P3-own-1, Phase
// 4). Rather than block this sync guard on that larger parser effort, we extract
// member NAMES directly from the lexer token stream (the lexer DOES handle the
// full files). This is the focused name-extraction the standard sanctions for
// exactly this case. When full `.lem` parse lands, this extractor can be replaced
// by an AST walk — the assertions are unchanged.

/// The member declarations of a `.lem` contract/token/trait, extracted from the
/// token stream. Fields and functions are tracked separately because a name can
/// legitimately be BOTH a state field and a function (e.g. `totalSupply`).
#[derive(Debug, Default)]
struct LemMembers {
    /// State-field names.
    fields: BTreeSet<String>,
    /// Function name → whether it is declared `pub` / `external`.
    functions: BTreeMap<String, bool>,
}

impl LemMembers {
    /// All member names (fields ∪ functions) — the set `base_members` mirrors.
    fn all_names(&self) -> BTreeSet<String> {
        self.fields
            .iter()
            .cloned()
            .chain(self.functions.keys().cloned())
            .collect()
    }
}

/// Names of every member (state field + function) `base_members(name)` injects.
fn map_member_names(name: &str) -> BTreeSet<String> {
    let members =
        StdLibRegistry::base_members(name).unwrap_or_else(|| panic!("{name} has base members"));
    members
        .state_fields
        .iter()
        .map(|f| f.name.to_string())
        .chain(members.functions.iter().map(|f| f.name.to_string()))
        .collect()
}

/// Extract the member declarations (state fields + functions, with `pub` flag)
/// of the top-level item named `item_name` from a `.lem` module's token stream.
///
/// Scans for the `contract` / `token` / `trait` keyword followed by `item_name`,
/// then walks its top-level `{ ... }` body. At body brace-depth 1 it records:
///   - field names inside a `state { ... }` block, and
///   - function names following `fn` (visibility derived from a preceding `pub`).
///
/// Events, modifiers, config/metadata, struct/enum members, and anything nested
/// deeper than the item body are ignored — matching `base_members`' member set.
fn lem_members(module: &str, item_name: &str) -> LemMembers {
    let tokens = lem_tokens(module);
    let body = item_body_tokens(&tokens, item_name)
        .unwrap_or_else(|| panic!("item `{item_name}` not found in {module}.lem"));

    let mut out = LemMembers::default();
    let mut i = 0;
    // `pub`/`external` seen since the last member boundary (applies to next fn).
    let mut pending_public = false;
    while i < body.len() {
        match &body[i] {
            Token::Pub | Token::External => {
                pending_public = true;
                i += 1;
            }
            // `state { f1: T, f2: T }` — collect field names at the block's depth.
            Token::State => {
                i = collect_state_fields(body, i, &mut out.fields);
                pending_public = false;
            }
            Token::Fn => {
                if let Some(Token::Identifier(name)) = body.get(i + 1) {
                    out.functions.insert(name.clone(), pending_public);
                }
                pending_public = false;
                i += 2;
            }
            // Any other top-level keyword (event, modifier, annotation, …) ends a
            // pending visibility run without producing a member.
            _ => {
                pending_public = false;
                i += 1;
            }
        }
    }
    assert!(
        !out.fields.is_empty() || !out.functions.is_empty(),
        "no members extracted for {item_name} in {module}.lem — \
         item missing or token shape changed"
    );
    out
}

/// Tokenize a `.lem` module, stripping comments and newlines (neither affects
/// member structure and both add noise to the linear scan).
fn lem_tokens(module: &str) -> Vec<Token> {
    let reg = StdLibRegistry::new();
    let src = reg
        .get(module)
        .unwrap_or_else(|| panic!("@std/{module} should be registered"));
    tokenize(src)
        .unwrap_or_else(|e| panic!("{module}.lem must tokenize: {e:?}"))
        .into_iter()
        .map(|(t, _)| t)
        .filter(|t| {
            !matches!(
                t,
                Token::LineComment(_)
                    | Token::BlockComment(_)
                    | Token::DocComment(_)
                    | Token::Newline
            )
        })
        .collect()
}

/// Return the token slice strictly inside the body braces of the top-level
/// `contract`/`token`/`trait` named `item_name`, or `None` if not found.
fn item_body_tokens<'a>(tokens: &'a [Token], item_name: &str) -> Option<&'a [Token]> {
    let mut i = 0;
    while i < tokens.len() {
        let is_item_kw = matches!(tokens[i], Token::Contract | Token::Token_ | Token::Trait);
        if is_item_kw {
            // Name follows the keyword (for `token Foo extends Bar`, name is still
            // the token right after the keyword).
            if let Some(Token::Identifier(name)) = tokens.get(i + 1) {
                if name == item_name {
                    // Advance to the opening brace of the body.
                    let mut j = i + 2;
                    while j < tokens.len() && tokens[j] != Token::LBrace {
                        j += 1;
                    }
                    let body_start = j + 1;
                    // Find the matching close brace.
                    let mut depth = 1usize;
                    let mut k = body_start;
                    while k < tokens.len() && depth > 0 {
                        match tokens[k] {
                            Token::LBrace => depth += 1,
                            Token::RBrace => depth -= 1,
                            _ => {}
                        }
                        if depth == 0 {
                            return Some(&tokens[body_start..k]);
                        }
                        k += 1;
                    }
                    return None;
                }
            }
        }
        i += 1;
    }
    None
}

/// Starting at the `state` keyword in `body[start]`, collect the field names
/// declared directly inside the `state { ... }` block. Returns the index just
/// past the block's closing brace.
///
/// A field name is an identifier at the block's top depth immediately followed
/// by `:` (the type annotation). Nested braces (e.g. a `fees { ... }` block, or
/// `Map<...>` has no braces) are skipped via depth tracking.
fn collect_state_fields(body: &[Token], start: usize, out: &mut BTreeSet<String>) -> usize {
    // Advance to the opening brace.
    let mut i = start + 1;
    while i < body.len() && body[i] != Token::LBrace {
        i += 1;
    }
    if i >= body.len() {
        return body.len();
    }
    let mut depth = 0usize;
    while i < body.len() {
        match &body[i] {
            Token::LBrace => depth += 1,
            Token::RBrace => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            Token::Identifier(name) if depth == 1 => {
                // A field is `name :` at the block's top level.
                if matches!(body.get(i + 1), Some(Token::Colon)) {
                    out.insert(name.clone());
                }
            }
            _ => {}
        }
        i += 1;
    }
    i
}

/// Assert `base_members(base)` and the corresponding `.lem` item agree exactly
/// on member names AND on the `is_public` flag of every function.
fn assert_members_in_sync(base: &str, module: &str, item_name: &str) {
    let map = StdLibRegistry::base_members(base)
        .unwrap_or_else(|| panic!("{base} should have base members"));
    let from_map = map_member_names(base);
    let lem = lem_members(module, item_name);
    let from_lem = lem.all_names();

    let only_in_map: Vec<&String> = from_map.difference(&from_lem).collect();
    let only_in_lem: Vec<&String> = from_lem.difference(&from_map).collect();

    assert!(
        only_in_map.is_empty(),
        "{base}: base_members() declares members NOT in {module}.lem (phantom \
         members — resolver would inject names with no body): {only_in_map:?}"
    );
    assert!(
        only_in_lem.is_empty(),
        "{base}: {module}.lem declares members NOT in base_members() (missing \
         from the resolver mirror): {only_in_lem:?}"
    );

    // Visibility must match for every function present in the map. A name may be
    // both a field and a function (e.g. `totalSupply`); only the function carries
    // a visibility, so look it up in the function map specifically.
    for func in &map.functions {
        let lem_is_pub = *lem
            .functions
            .get(func.name)
            .unwrap_or_else(|| panic!("{base}::{} missing from {module}.lem fns", func.name));
        assert_eq!(
            func.is_public, lem_is_pub,
            "{base}::{} is_public={} in base_members() but pub={} in {module}.lem",
            func.name, func.is_public, lem_is_pub
        );
    }
}

#[test]
fn base_members_match_lem_source_token() {
    assert_members_in_sync("Token", "token", "Token");
}

#[test]
fn base_members_match_lem_source_tax_token() {
    assert_members_in_sync("TaxToken", "token", "TaxToken");
}

#[test]
fn base_members_match_lem_source_ownable() {
    assert_members_in_sync("Ownable", "access", "Ownable");
}

#[test]
fn base_members_match_lem_source_pausable() {
    assert_members_in_sync("Pausable", "access", "Pausable");
}

#[test]
fn base_members_match_lem_source_access_control() {
    assert_members_in_sync("AccessControl", "access", "AccessControl");
}

// ── @std/agent module ─────────────────────────────────────────────────────────

#[test]
fn get_returns_agent_module() {
    let reg = StdLibRegistry::new();
    assert!(reg.get("agent").is_some());
}

#[test]
fn agent_module_source_is_nonempty() {
    let reg = StdLibRegistry::new();
    let src = reg.get("agent").expect("agent module should exist");
    assert!(!src.is_empty(), "agent.lem source should not be empty");
}

#[test]
fn symbol_kind_returns_struct_for_agent_policy() {
    let reg = StdLibRegistry::new();
    assert_eq!(
        reg.symbol_kind("agent", "AgentPolicy"),
        Some(SymbolKind::Struct),
    );
}

#[test]
fn symbol_kind_returns_struct_for_auto_revoke() {
    let reg = StdLibRegistry::new();
    assert_eq!(
        reg.symbol_kind("agent", "AutoRevoke"),
        Some(SymbolKind::Struct),
    );
}

#[test]
fn symbol_kind_returns_enum_for_kya_tier() {
    let reg = StdLibRegistry::new();
    assert_eq!(reg.symbol_kind("agent", "KyaTier"), Some(SymbolKind::Enum),);
}

#[test]
fn symbol_kind_returns_none_for_unknown_agent_export() {
    let reg = StdLibRegistry::new();
    assert_eq!(reg.symbol_kind("agent", "Nonexistent"), None);
}
