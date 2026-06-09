// Well-formedness pass tests — Family A: Storage & Initialization (WF-001..003),
// Family B: Control-Flow (WF-004..007), Family C: Structural-Completeness
// (WF-008..011), and Family D: Schema & Effect (WF-012..015).
//
// Follows AGENTS §11.2: tests in a separate submodule file (never inline).
// Naming convention: `check_<rule>_<expected_outcome>`.
//
// Each rule has: positive (valid contract passes), negative (violation detected),
// and boundary (edge case) tests.
//
// Pipeline: tokenize → parse → check (which runs wellformed::check internally).
// We call `crate::type_checker::check` and inspect the resulting LangError.
//
// ## Lem init syntax
//
// `init` is a keyword in Lem — the constructor syntax is:
//   `init(params) { body }`         — plain init (mutability: Default)
//   `payable init(params) { body }` — payable init (mutability: Payable) — VALID
//
// The parser hardcodes `visibility: Private` and `return_type: None` for init.
// `payable` is the ONE permitted modifier on init (§9, WF-003 clause 3).
// Visibility violations (`pub init`, `external init`) and return-type violations
// (`init -> T`) are parse-time errors — they never reach the WF pass.
// See parser/decl/tests.rs for those parse-error tests.
// WF-003 checks: duplicate init, token missing init, banned annotations.
//
// ## Token config syntax (WF-014)
//
// All token tests that must pass WF-014 use a complete mandatory config:
//   `config { name: "T" symbol: "T" decimals: 18 maxSupply: 1000000 }`
// TaxToken tests additionally include the mandatory `fees` block:
//   `fees: { burn: 0 holders: 0 others: 0 }`

use crate::error::LangError;
use crate::type_checker::error::TypeErrorKind;
use crate::{check, parse, tokenize};

// ─── Helper ───────────────────────────────────────────────────────────────────

/// Run the full tokenize → parse → type-check pipeline on `src`.
///
/// Returns `Ok(TypedAst)` on success or `Err(LangError)` on any error
/// (type error, parse error, or well-formedness violation).
fn check_src(src: &str) -> Result<crate::type_checker::TypedAst, LangError> {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    check(ast)
}

/// Assert that `check_src(src)` succeeds (no errors).
fn assert_passes(src: &str) {
    let result = check_src(src);
    assert!(
        result.is_ok(),
        "expected program to pass well-formedness check, got: {result:?}\n\nsrc:\n{src}"
    );
}

/// Assert that `check_src(src)` fails with a `LangError::WellFormed` containing
/// at least one violation matching `predicate`.
fn assert_wf_error<F>(src: &str, predicate: F)
where
    F: Fn(&TypeErrorKind) -> bool,
{
    let result = check_src(src);
    match result {
        Err(LangError::WellFormed(violations)) => {
            let found = violations.iter().any(|v| predicate(&v.kind));
            assert!(
                found,
                "expected a matching WellFormed violation, got: {violations:?}\n\nsrc:\n{src}"
            );
        }
        Err(other) => {
            panic!("expected LangError::WellFormed, got: {other:?}\n\nsrc:\n{src}");
        }
        Ok(_) => {
            panic!("expected well-formedness error, but check passed\n\nsrc:\n{src}");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-001: State field initialization
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf001_accepts_state_field_with_default_initializer() {
    // A state field with a default value is always initialized — no init needed.
    assert_passes(
        r#"
        contract Vault {
            state {
                balance: u128 = 0
                paused: bool = false
            }
        }
        "#,
    );
}

#[test]
fn check_wf001_accepts_state_field_assigned_in_init_body() {
    // A state field without a default is OK if init assigns it unconditionally.
    // Lem init syntax: `init(params) { body }` (no `fn` keyword).
    assert_passes(
        r#"
        contract Vault {
            state {
                owner: Address
            }
            init(owner: Address) {
                self.owner = owner
            }
        }
        "#,
    );
}

#[test]
fn check_wf001_accepts_mixed_default_and_init_assignment() {
    // Some fields have defaults, others are assigned in init — all OK.
    assert_passes(
        r#"
        contract Vault {
            state {
                balance: u128 = 0
                owner: Address
            }
            init(owner: Address) {
                self.owner = owner
            }
        }
        "#,
    );
}

#[test]
fn check_wf001_accepts_empty_state_block() {
    // No state fields → nothing to check.
    assert_passes(
        r#"
        contract Empty {
            state {}
        }
        "#,
    );
}

#[test]
fn check_wf001_accepts_contract_with_no_state_block() {
    // No state block at all → WF-001 does not apply.
    assert_passes("contract NoState {}");
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf001_rejects_state_field_with_no_default_and_no_init() {
    // A state field with no default and no init function → UninitializedStateField.
    assert_wf_error(
        r#"
        contract Vault {
            state {
                owner: Address
            }
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::UninitializedStateField { field, .. } if field == "owner"),
    );
}

#[test]
fn check_wf001_rejects_state_field_not_assigned_in_init() {
    // init exists but does not assign the field → UninitializedStateField.
    assert_wf_error(
        r#"
        contract Vault {
            state {
                owner: Address
                balance: u128
            }
            init(owner: Address) {
                self.owner = owner
            }
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::UninitializedStateField { field, .. } if field == "balance"),
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf001_rejects_field_assigned_in_only_one_if_branch() {
    // Field assigned in `if` branch but not in `else` → not all paths → reject.
    assert_wf_error(
        r#"
        contract Vault {
            state {
                owner: Address
            }
            init(flag: bool, owner: Address) {
                if (flag) {
                    self.owner = owner
                }
            }
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::UninitializedStateField { field, .. } if field == "owner"),
    );
}

#[test]
fn check_wf001_accepts_field_assigned_in_both_if_else_branches() {
    // Field assigned in both branches of if/else → all paths covered → OK.
    assert_passes(
        r#"
        contract Vault {
            state {
                owner: Address
            }
            init(flag: bool, a: Address, b: Address) {
                if (flag) {
                    self.owner = a
                } else {
                    self.owner = b
                }
            }
        }
        "#,
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-002: immutable set exactly once in init
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf002_accepts_immutable_set_exactly_once_in_init() {
    // Immutable set once at the top level of init → OK.
    assert_passes(
        r#"
        contract Vault {
            immutable asset: Address
            init(asset: Address) {
                self.asset = asset
            }
        }
        "#,
    );
}

#[test]
fn check_wf002_accepts_multiple_immutables_each_set_once() {
    // Multiple immutables, each set exactly once → OK.
    assert_passes(
        r#"
        contract Vault {
            immutable asset: Address
            immutable fee: u128
            init(asset: Address, fee: u128) {
                self.asset = asset
                self.fee = fee
            }
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf002_rejects_immutable_never_set() {
    // Immutable declared but never assigned in init → ImmutableNotSetOnce { found_assignments: 0 }.
    assert_wf_error(
        r#"
        contract Vault {
            immutable asset: Address
            init() {
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::ImmutableNotSetOnce {
                    field,
                    found_assignments: 0,
                    ..
                } if field == "asset"
            )
        },
    );
}

#[test]
fn check_wf002_rejects_immutable_set_twice_in_init() {
    // Immutable assigned twice at the top level of init → ImmutableNotSetOnce { found_assignments: 2 }.
    assert_wf_error(
        r#"
        contract Vault {
            immutable asset: Address
            init(a: Address, b: Address) {
                self.asset = a
                self.asset = b
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::ImmutableNotSetOnce {
                    field,
                    found_assignments,
                    ..
                } if field == "asset" && *found_assignments >= 2
            )
        },
    );
}

#[test]
fn check_wf002_rejects_immutable_never_set_no_init() {
    // Immutable declared but no init function at all → ImmutableNotSetOnce { found_assignments: 0 }.
    assert_wf_error(
        r#"
        contract Vault {
            immutable asset: Address
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::ImmutableNotSetOnce {
                    field,
                    found_assignments: 0,
                    ..
                } if field == "asset"
            )
        },
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf002_rejects_immutable_set_in_only_one_init_branch() {
    // Immutable set in `if` branch but not `else` → min_count = 0 → reject.
    assert_wf_error(
        r#"
        contract Vault {
            immutable asset: Address
            init(flag: bool, a: Address) {
                if (flag) {
                    self.asset = a
                }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::ImmutableNotSetOnce {
                    field,
                    found_assignments: 0,
                    ..
                } if field == "asset"
            )
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-003: init constructor well-formedness
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf003_accepts_single_plain_init() {
    // A single, plain init (no annotations, no return type) → OK.
    // Lem syntax: `init() { body }` (no `fn` keyword).
    assert_passes(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            init() {}
        }
        "#,
    );
}

#[test]
fn check_wf003_accepts_contract_with_all_defaulted_state_and_no_init() {
    // Non-token contract with all state fields defaulted and no init → OK.
    // (WF-001 is satisfied by defaults; WF-003 does not require init for non-tokens.)
    assert_passes(
        r#"
        contract Vault {
            state {
                balance: u128 = 0
                paused: bool = false
            }
        }
        "#,
    );
}

#[test]
fn check_wf003_accepts_init_with_default_params_and_no_return() {
    // init with default-valued params and no return type → OK (boundary).
    // Lem syntax: `init(fee: u128 = 30) { body }`.
    assert_passes(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            init(fee: u128 = 30) {}
        }
        "#,
    );
}

#[test]
fn check_wf003_accepts_payable_init() {
    // (pos) payable init — the ONE permitted modifier on init (§9, WF-003 clause 3).
    // `payable init(params) { body }` is valid: allows deploy-with-funding.
    // The parser sets mutability=Payable; WF-003 does not reject it.
    assert_passes(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            payable init(seed: u128 = 0) {}
        }
        "#,
    );
}

#[test]
fn check_wf003_accepts_token_with_init() {
    // Token with an init function → OK (WF-003 clause 2 satisfied).
    // registry.register is no longer required here — auto-injected by codegen (DB-A48).
    // Uses a complete Token config (name, symbol, decimals, maxSupply) per WF-014.
    assert_passes(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
            }
            init() {}
        }
        "#,
    );
}

// Note: `pub init` and `external init` are PARSE-TIME errors — they never reach
// the WF pass. Parser tests for those cases live in parser/decl/tests.rs.
// Similarly, `init -> T` (return type on init) is a parse-time error.

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf003_rejects_two_init_functions() {
    // Two init functions → rejected.
    // The type-checker's duplicate-name pass (Pass 1) fires before WF-003,
    // so the error is DuplicateDeclaration rather than MalformedInit.
    // Either error correctly rejects the program — we accept both.
    let result = check_src(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            init() {}
            init() {}
        }
        "#,
    );
    assert!(
        result.is_err(),
        "two init functions must be rejected; got Ok"
    );
    match result {
        Err(LangError::WellFormed(violations)) => {
            assert!(
                violations.iter().any(|v| matches!(
                    &v.kind,
                    TypeErrorKind::MalformedInit { reason, .. } if reason.contains("duplicate")
                )),
                "expected MalformedInit(duplicate) in WellFormed violations; got {violations:?}"
            );
        }
        Err(LangError::Type(e)) => {
            assert!(
                matches!(&e.kind, TypeErrorKind::DuplicateDeclaration { name } if name == "init"),
                "expected DuplicateDeclaration(init); got {:?}",
                e.kind
            );
        }
        other => panic!("expected rejection of two init functions, got: {other:?}"),
    }
}

#[test]
fn check_wf003_rejects_onlyowner_init() {
    // `@onlyOwner init` → MalformedInit.
    // Annotations are parsed before the `init` keyword and passed to parse_init.
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            @onlyOwner
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::MalformedInit { reason, .. }
                    if reason.contains("onlyOwner")
            )
        },
    );
}

#[test]
fn check_wf003_rejects_token_without_init() {
    // Token with no init → MalformedInit.
    // Uses a complete Token config per WF-014 so only the WF-003 violation fires.
    assert_wf_error(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::MalformedInit { reason, .. }
                    if reason.contains("init") || reason.contains("state initialization")
            )
        },
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf003_accepts_init_with_default_param_no_return() {
    // init(fee: u128 = 0) with no return type → OK (boundary).
    // This exercises the "default params are allowed" clause.
    assert_passes(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            init(fee: u128 = 0) {}
        }
        "#,
    );
}

#[test]
fn check_wf003_rejects_onlyrole_init() {
    // @onlyRole is also a banned access guard on init.
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            @onlyRole("admin")
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::MalformedInit { reason, .. }
                    if reason.contains("onlyRole")
            )
        },
    );
}

#[test]
fn check_wf003_rejects_whennotpaused_init() {
    // @whenNotPaused is also a banned access guard on init.
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            @whenNotPaused
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::MalformedInit { reason, .. }
                    if reason.contains("whenNotPaused")
            )
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-004: Return-path completeness
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf004_accepts_function_with_explicit_return_on_all_paths() {
    // A function with a single unconditional `return` → all paths complete.
    assert_passes(
        r#"
        contract Vault {
            fn getValue() -> u128 {
                return 42u128
            }
        }
        "#,
    );
}

#[test]
fn check_wf004_accepts_if_else_both_returning() {
    // Both branches of if/else return → all paths complete.
    assert_passes(
        r#"
        contract Vault {
            fn pick(flag: bool) -> u128 {
                if (flag) {
                    return 1u128
                } else {
                    return 2u128
                }
            }
        }
        "#,
    );
}

#[test]
fn check_wf004_accepts_match_all_arms_returning() {
    // All arms of a match return → all paths complete.
    // Uses bool match (two arms: true, false).
    assert_passes(
        r#"
        contract Vault {
            fn pick(flag: bool) -> u128 {
                match (flag) {
                    true => { return 1u128 }
                    false => { return 2u128 }
                }
            }
        }
        "#,
    );
}

#[test]
fn check_wf004_accepts_revert_as_path_terminator() {
    // `revert` counts as completing a path — the function never falls off.
    assert_passes(
        r#"
        contract Vault {
            fn mustBePositive(x: u128) -> u128 {
                if (x == 0u128) {
                    revert("zero not allowed")
                } else {
                    return x
                }
            }
        }
        "#,
    );
}

#[test]
fn check_wf004_accepts_infinite_loop_as_path_terminator() {
    // An infinite `loop {}` with no `break` counts as completing a path.
    assert_passes(
        r#"
        contract Vault {
            fn runForever() -> u128 {
                loop {
                    let x = 1u128
                }
            }
        }
        "#,
    );
}

#[test]
fn check_wf004_accepts_unit_function_with_no_return() {
    // A function with no return type (Unit) is not checked by WF-004.
    assert_passes(
        r#"
        contract Vault {
            fn doNothing() {
                let x = 1u128
            }
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf004_rejects_function_with_no_return() {
    // A non-unit function that falls off the end → MissingReturn.
    assert_wf_error(
        r#"
        contract Vault {
            fn getValue() -> u128 {
                let x = 42u128
            }
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::MissingReturn { func, .. } if func == "getValue"),
    );
}

#[test]
fn check_wf004_rejects_if_without_else_returning() {
    // `if` returns but no `else` → the else path falls off → MissingReturn.
    assert_wf_error(
        r#"
        contract Vault {
            fn getValue(flag: bool) -> u128 {
                if (flag) {
                    return 1u128
                }
            }
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::MissingReturn { func, .. } if func == "getValue"),
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf004_rejects_loop_with_break_as_not_terminating() {
    // A `loop` with a `break` inside is NOT an infinite loop → not a terminator.
    // The function falls off after the loop → MissingReturn.
    assert_wf_error(
        r#"
        contract Vault {
            fn getValue() -> u128 {
                loop {
                    break
                }
            }
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::MissingReturn { func, .. } if func == "getValue"),
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-005: match exhaustiveness
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf005_accepts_bool_match_with_both_arms() {
    // Match on bool with both `true` and `false` arms → exhaustive.
    assert_passes(
        r#"
        contract Vault {
            fn pick(flag: bool) -> u128 {
                match (flag) {
                    true => { return 1u128 }
                    false => { return 2u128 }
                }
            }
        }
        "#,
    );
}

#[test]
fn check_wf005_accepts_match_with_wildcard_arm() {
    // A wildcard `_` arm makes any match exhaustive.
    assert_passes(
        r#"
        contract Vault {
            fn pick(flag: bool) -> u128 {
                match (flag) {
                    true => { return 1u128 }
                    _ => { return 0u128 }
                }
            }
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf005_rejects_bool_match_missing_false_arm() {
    // Match on bool with only `true` arm and no `_` → NonExhaustiveMatch.
    assert_wf_error(
        r#"
        contract Vault {
            fn pick(flag: bool) {
                match (flag) {
                    true => { let x = 1u128 }
                }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::NonExhaustiveMatch { missing, .. }
                    if missing.contains(&"false".to_string())
            )
        },
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf005_accepts_bool_match_with_all_variants_and_wildcard() {
    // All variants present AND `_` → passes (redundant wildcard is allowed).
    assert_passes(
        r#"
        contract Vault {
            fn pick(flag: bool) -> u128 {
                match (flag) {
                    true => { return 1u128 }
                    false => { return 2u128 }
                    _ => { return 0u128 }
                }
            }
        }
        "#,
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-006: placeholder only in modifier bodies
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf006_accepts_placeholder_in_modifier_body() {
    // `_` inside a modifier body → valid.
    assert_passes(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            modifier onlyPositive() {
                _
            }
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf006_rejects_placeholder_in_regular_function_body() {
    // `_` in a regular function body → PlaceholderOutsideModifier.
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            fn doSomething() {
                _
            }
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::PlaceholderOutsideModifier { .. }),
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf006_rejects_two_placeholders_in_same_modifier() {
    // Two `_` in the same modifier body → PlaceholderOutsideModifier (second one).
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            modifier onlyPositive() {
                _
                _
            }
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::PlaceholderOutsideModifier { .. }),
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-007: break/continue only inside loops
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf007_accepts_break_inside_loop() {
    // `break` inside a `loop` → valid.
    assert_passes(
        r#"
        contract Vault {
            fn run() {
                loop {
                    break
                }
            }
        }
        "#,
    );
}

#[test]
fn check_wf007_accepts_continue_inside_loop() {
    // `continue` inside a `loop` → valid.
    assert_passes(
        r#"
        contract Vault {
            fn run() {
                loop {
                    continue
                }
            }
        }
        "#,
    );
}

#[test]
fn check_wf007_accepts_break_inside_while_loop() {
    // `break` inside a `while` loop → valid.
    assert_passes(
        r#"
        contract Vault {
            fn run(flag: bool) {
                while (flag) {
                    break
                }
            }
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf007_rejects_break_outside_any_loop() {
    // `break` in a bare function body (no enclosing loop) → ControlFlowOutsideLoop.
    assert_wf_error(
        r#"
        contract Vault {
            fn run() {
                break
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::ControlFlowOutsideLoop { kind, .. }
                    if kind == "break"
            )
        },
    );
}

#[test]
fn check_wf007_rejects_continue_outside_any_loop() {
    // `continue` in a bare function body (no enclosing loop) → ControlFlowOutsideLoop.
    assert_wf_error(
        r#"
        contract Vault {
            fn run() {
                continue
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::ControlFlowOutsideLoop { kind, .. }
                    if kind == "continue"
            )
        },
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf007_accepts_break_in_inner_loop_of_nested_loops() {
    // `break` inside an inner `loop` nested inside an outer `loop` → valid.
    // The inner break exits the inner loop; the outer loop is still valid.
    assert_passes(
        r#"
        contract Vault {
            fn run() {
                loop {
                    loop {
                        break
                    }
                    break
                }
            }
        }
        "#,
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// Expression-position traversal tests (WF-005, WF-006, WF-007)
// These tests verify that the walkers descend into Expr::If_ and Expr::Match_
// bodies — the cases the original Stmt-only walkers missed.
// ═══════════════════════════════════════════════════════════════════════════════

// ── BLOCKER-1 regression: MatchBody::Expr arm bodies ──────────────────────────

#[test]
fn check_wf007_rejects_break_inside_match_expr_arm_outside_loop() {
    // BLOCKER-1: `break` inside a MatchBody::Expr arm body (not a block arm)
    // that is outside any loop must be rejected.
    //
    // `let x = match (flag) { _ => if (flag) { break } else { break } }`
    //
    // The arm body is MatchBody::Expr(Expr::If_{ then: [break], else_: [break] }).
    // The old walker only handled MatchBody::Block arms and silently skipped
    // MatchBody::Expr arms — so the `break` inside the if-expression was missed.
    //
    // Both branches of the if-expression are `break` (type `()`), so the
    // if-expression has type `()` and the match has type `()` — type-checks OK.
    assert_wf_error(
        r#"
        contract Vault {
            fn run(flag: bool) {
                let x = match (flag) {
                    _ => if (flag) { break } else { break }
                }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::ControlFlowOutsideLoop { kind, .. }
                    if kind == "break"
            )
        },
    );
}

// ── BLOCKER-2 regression: break inside emit field expression ──────────────────

#[test]
fn check_wf007_rejects_break_inside_emit_field_outside_loop() {
    // BLOCKER-2: `break` inside an `emit` field expression that is outside any
    // loop must be rejected.
    //
    // `emit Transfer { amount: if (flag) { break } else { break } }`
    //
    // The old `walk_stmt_expr_bodies` only extracted expressions from
    // Stmt::Let / Stmt::Assign / Stmt::Expr / Stmt::Return — it did NOT handle
    // Stmt::Emit.  So a `break` inside an emit field expression was silently
    // accepted.
    //
    // Both branches of the if-expression are `break` (type `()`), so the
    // if-expression has type `()` — type-checks OK.
    assert_wf_error(
        r#"
        contract Vault {
            fn run(flag: bool) {
                emit Transfer { amount: if (flag) { break } else { break } }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::ControlFlowOutsideLoop { kind, .. }
                    if kind == "break"
            )
        },
    );
}

#[test]
fn check_wf005_rejects_nonexhaustive_match_in_expression_position() {
    // A match expression used as a value (in a let binding) that is non-exhaustive
    // must be rejected — the original walker only checked Stmt::Match, not Expr::Match_.
    // `let v = match (flag) { true => { 1u128 } }` — missing `false` arm, no wildcard.
    assert_wf_error(
        r#"
        contract Vault {
            fn pick(flag: bool) {
                let v = match (flag) {
                    true => { 1u128 }
                }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::NonExhaustiveMatch { missing, .. }
                    if missing.contains(&"false".to_string())
            )
        },
    );
}

#[test]
fn check_wf007_rejects_break_inside_expression_if_outside_loop() {
    // A `break` inside an expression-`if` body (Expr::If_) that is not enclosed
    // by any loop must be rejected — the original walker only checked Stmt::If,
    // not Expr::If_ in value position.
    // Both branches are unit-typed so the type checker accepts the program;
    // WF-007 must then catch the `break` outside any loop.
    assert_wf_error(
        r#"
        contract Vault {
            fn run(cond: bool) {
                let x = if (cond) { break } else { break }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::ControlFlowOutsideLoop { kind, .. }
                    if kind == "break"
            )
        },
    );
}

#[test]
fn check_wf006_rejects_placeholder_inside_expression_match_in_regular_fn() {
    // A `_` placeholder inside an expression-match arm body (Expr::Match_) in a
    // regular function must be rejected — the original walker only checked
    // Stmt::Match arms, not Expr::Match_ arms in value position.
    // `let v = match (x) { _ => { _ } }` — Placeholder inside expression-match
    // in a regular fn body → PlaceholderOutsideModifier.
    assert_wf_error(
        r#"
        contract Vault {
            fn foo(x: bool) {
                let v = match (x) {
                    _ => { _ }
                }
            }
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::PlaceholderOutsideModifier { .. }),
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-008: Interface implementation completeness
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf008_accepts_contract_with_all_interface_methods_present() {
    // (pos) Contract provides all methods declared by the interface → passes.
    assert_passes(
        r#"
        interface IVault {
            fn deposit(amount: u128)
            fn withdraw(amount: u128)
        }
        contract Vault implements IVault {
            fn deposit(amount: u128) {}
            fn withdraw(amount: u128) {}
        }
        "#,
    );
}

#[test]
fn check_wf008_accepts_contract_with_methods_provided_via_uses_trait() {
    // (pos) Some interface methods are provided via a `uses` trait → passes.
    // The `uses` trait provides `withdraw`; the contract provides `deposit` directly.
    assert_passes(
        r#"
        interface IVault {
            fn deposit(amount: u128)
            fn withdraw(amount: u128)
        }
        trait Withdrawable {
            fn withdraw(amount: u128) {}
        }
        contract Vault implements IVault uses Withdrawable {
            fn deposit(amount: u128) {}
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf008_rejects_contract_missing_one_interface_method() {
    // (neg) Contract declares `implements IVault` but is missing `withdraw` → IncompleteInterface.
    assert_wf_error(
        r#"
        interface IVault {
            fn deposit(amount: u128)
            fn withdraw(amount: u128)
        }
        contract Vault implements IVault {
            fn deposit(amount: u128) {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::IncompleteInterface { interface, missing, .. }
                    if interface == "IVault" && missing.contains(&"withdraw".to_string())
            )
        },
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf008_accepts_method_present_with_different_return_type_name_only_check() {
    // (boundary) WF-008 is name-presence only (per Phase 1 CR note).
    // A method with the same name but a different return type still PASSES WF-008
    // (signature-level checking is deferred to a later phase).
    assert_passes(
        r#"
        interface IVault {
            fn getValue() -> u128
        }
        contract Vault implements IVault {
            fn getValue() -> u64 {
                return 0u64
            }
        }
        "#,
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-009: Trait `uses` completeness
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf009_accepts_contract_providing_all_required_trait_members() {
    // (pos) Contract provides all required (body-less) methods and state fields → passes.
    // Uses `balance: u128` as the required state field (avoids Address literal syntax).
    assert_passes(
        r#"
        trait Fundable {
            state {
                balance: u128
            }
            fn deposit(amount: u128)
        }
        contract Vault uses Fundable {
            state {
                balance: u128 = 0
            }
            fn deposit(amount: u128) {}
        }
        "#,
    );
}

#[test]
fn check_wf009_accepts_contract_not_providing_default_trait_method() {
    // (pos) Trait has a default method (has body) — contract does NOT provide it → passes.
    // Default methods are not required; the contract inherits the default.
    assert_passes(
        r#"
        trait Greetable {
            fn greet() -> u128 {
                return 42u128
            }
        }
        contract Vault uses Greetable {
            state { balance: u128 = 0 }
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf009_rejects_contract_missing_required_trait_method() {
    // (neg) Contract uses a trait but is missing a required (body-less) method → IncompleteTrait.
    assert_wf_error(
        r#"
        trait Ownable {
            fn transferOwnership(newOwner: Address)
        }
        contract Vault uses Ownable {
            state { balance: u128 = 0 }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::IncompleteTrait { trait_name, missing, .. }
                    if trait_name == "Ownable"
                    && missing.contains(&"transferOwnership".to_string())
            )
        },
    );
}

#[test]
fn check_wf009_rejects_contract_missing_required_trait_state_field() {
    // (neg) Contract uses a trait but is missing a required state field → IncompleteTrait.
    assert_wf_error(
        r#"
        trait Ownable {
            state {
                owner: Address
            }
        }
        contract Vault uses Ownable {
            state { balance: u128 = 0 }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::IncompleteTrait { trait_name, missing, .. }
                    if trait_name == "Ownable"
                    && missing.contains(&"owner".to_string())
            )
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-010: receive/fallback uniqueness
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf010_accepts_one_receive_and_one_fallback() {
    // (pos) One receive + one fallback → passes.
    assert_passes(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            receive() {}
            fallback() {}
        }
        "#,
    );
}

#[test]
fn check_wf010_accepts_contract_with_neither_receive_nor_fallback() {
    // (pos) Neither receive nor fallback → passes (both are optional).
    assert_passes(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf010_rejects_two_receive_functions() {
    // (neg) Two receive() → DuplicateSpecialFunction { kind: "receive" }.
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            receive() {}
            receive() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::DuplicateSpecialFunction { kind, .. }
                    if kind == "receive"
            )
        },
    );
}

#[test]
fn check_wf010_rejects_two_fallback_functions() {
    // (neg) Two fallback() → DuplicateSpecialFunction { kind: "fallback" }.
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            fallback() {}
            fallback() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::DuplicateSpecialFunction { kind, .. }
                    if kind == "fallback"
            )
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-011: Recursive (by-value) type detection
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf011_accepts_struct_with_option_self_reference() {
    // (pos) `struct Node { next: Option<Node> }` → passes (Option breaks the cycle).
    assert_passes(
        r#"
        struct Node {
            value: u128
            next: Option<Node>
        }
        contract Vault {}
        "#,
    );
}

#[test]
fn check_wf011_accepts_struct_with_array_self_reference() {
    // (pos) `struct Tree { children: Array<Tree> }` → passes (Array breaks the cycle).
    assert_passes(
        r#"
        struct Tree {
            value: u128
            children: Array<Tree>
        }
        contract Vault {}
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf011_rejects_direct_self_reference_struct() {
    // (neg) `struct A { a: A }` → RecursiveType (direct self-reference by value).
    assert_wf_error(
        r#"
        struct A {
            a: A
        }
        contract Vault {}
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::RecursiveType { type_name, .. }
                    if type_name == "A"
            )
        },
    );
}

#[test]
fn check_wf011_rejects_mutual_recursive_structs() {
    // (neg) `struct A { b: B }` + `struct B { a: A }` → RecursiveType (mutual cycle).
    assert_wf_error(
        r#"
        struct A {
            b: B
        }
        struct B {
            a: A
        }
        contract Vault {}
        "#,
        |kind| matches!(kind, TypeErrorKind::RecursiveType { .. }),
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf011_accepts_struct_with_map_containing_self() {
    // (boundary) `struct A { m: Map<u128, A> }` → passes (Map breaks the cycle).
    assert_passes(
        r#"
        struct Registry {
            entries: Map<u128, Registry>
        }
        contract Vault {}
        "#,
    );
}

// ── WF-011 Tuple/FixedArray regression tests (WF-011 bug fix) ─────────────────
//
// These tests verify that Tuple and FixedArray are correctly treated as
// by-value inline types — NOT cycle-breakers.  Before the fix, `by_value_named_id`
// returned `None` for both, so cycles through them were silently accepted.
//
// Tests A, B, C must be RED before the fix and GREEN after.
// Test D (positive boundary) must be GREEN both before and after.

#[test]
fn check_wf011_rejects_fixed_array_self_reference() {
    // (neg — WF-011 Tuple/FixedArray fix) `struct A { arr: [A; 4] }` must be
    // rejected: `[T; N]` is by-value inline (NOT on the §30.C exemption list).
    // Before the fix, FixedArray returned None from by_value_named_id, so this
    // cycle was silently accepted.
    assert_wf_error(
        r#"
        struct A {
            arr: [A; 4]
        }
        contract Vault {}
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::RecursiveType { type_name, .. }
                    if type_name == "A"
            )
        },
    );
}

#[test]
fn check_wf011_rejects_tuple_self_reference() {
    // (neg — WF-011 Tuple/FixedArray fix) `struct A { t: (A, u128) }` must be
    // rejected: tuples are by-value inline (NOT on the §30.C exemption list).
    // Before the fix, Tuple returned None from by_value_named_id, so this
    // cycle was silently accepted.
    assert_wf_error(
        r#"
        struct A {
            t: (A, u128)
        }
        contract Vault {}
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::RecursiveType { type_name, .. }
                    if type_name == "A"
            )
        },
    );
}

#[test]
fn check_wf011_rejects_indirect_cycle_via_tuple() {
    // (neg — WF-011 Tuple/FixedArray fix) Indirect cycle: `struct A { b: B }` +
    // `struct B { t: (A, u64) }` must be rejected.
    // The cycle is A → B (direct Named field) → A (via Tuple element).
    // Before the fix, the Tuple element was invisible to the cycle detector.
    assert_wf_error(
        r#"
        struct A {
            b: B
        }
        struct B {
            t: (A, u64)
        }
        contract Vault {}
        "#,
        |kind| matches!(kind, TypeErrorKind::RecursiveType { .. }),
    );
}

#[test]
fn check_wf011_accepts_tuple_and_fixed_array_of_primitives() {
    // (boundary — WF-011 Tuple/FixedArray fix) Tuple and FixedArray of primitive
    // types must pass: no user-defined type is embedded, so no cycle is possible.
    // `struct Point { coords: (u128, u128) }` and `struct Grid { cells: [u8; 256] }`
    // are both valid — u128 and u8 are primitives with no SymbolId.
    assert_passes(
        r#"
        struct Point {
            coords: (u128, u128)
        }
        struct Grid {
            cells: [u8; 256]
        }
        contract Vault {}
        "#,
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-012: emit ↔ event-schema validation
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf012_accepts_emit_matching_schema_exactly() {
    // (pos) emit with all fields matching the declared event schema → passes.
    assert_passes(
        r#"
        contract Vault {
            event Transfer { from: Address, to: Address, amount: u128 }
            fn transfer(from: Address, to: Address, amount: u128) {
                emit Transfer { from: from, to: to, amount: amount }
            }
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf012_rejects_emit_unknown_event_name() {
    // (neg) emit references an event that is not declared → EmitMismatch.
    assert_wf_error(
        r#"
        contract Vault {
            fn transfer(from: Address, to: Address, amount: u128) {
                emit Transfer { from: from, to: to, amount: amount }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::EmitMismatch { event, reason, .. }
                    if event == "Transfer" && reason.contains("unknown event")
            )
        },
    );
}

#[test]
fn check_wf012_rejects_emit_missing_field() {
    // (neg) emit omits a required field → EmitMismatch.
    assert_wf_error(
        r#"
        contract Vault {
            event Transfer { from: Address, to: Address, amount: u128 }
            fn transfer(from: Address, to: Address) {
                emit Transfer { from: from, to: to }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::EmitMismatch { event, reason, .. }
                    if event == "Transfer" && reason.contains("missing field")
            )
        },
    );
}

#[test]
fn check_wf012_rejects_emit_wrong_field_type() {
    // (neg) emit provides a field with the wrong type → EmitMismatch.
    // `amount` is declared as u128 but we emit a bool.
    assert_wf_error(
        r#"
        contract Vault {
            event Transfer { from: Address, to: Address, amount: u128 }
            fn transfer(from: Address, to: Address, flag: bool) {
                emit Transfer { from: from, to: to, amount: flag }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::EmitMismatch { event, reason, .. }
                    if event == "Transfer" && reason.contains("wrong type")
            )
        },
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf012_rejects_emit_unknown_field_key() {
    // (boundary) emit provides a field key not in the schema → EmitMismatch.
    assert_wf_error(
        r#"
        contract Vault {
            event Transfer { from: Address, to: Address, amount: u128 }
            fn transfer(from: Address, to: Address, amount: u128, extra: u128) {
                emit Transfer { from: from, to: to, amount: amount, extra: extra }
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::EmitMismatch { event, reason, .. }
                    if event == "Transfer" && reason.contains("unknown field")
            )
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-013: Const-expression evaluability
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf013_accepts_const_arithmetic_expression() {
    // (pos) `const X = 10 * 60` — arithmetic over literals → passes.
    assert_passes(
        r#"
        const X: u128 = 10 * 60
        contract Vault {}
        "#,
    );
}

#[test]
fn check_wf013_accepts_const_referencing_another_const() {
    // (pos) `const Y = X + 1` where X is another const → passes.
    assert_passes(
        r#"
        const X: u128 = 10
        const Y: u128 = X + 1
        contract Vault {}
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf013_rejects_const_with_state_read() {
    // (neg) `const X = self.balance` — state read in const initializer → NonConstExpr.
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            const X: u128 = self.balance
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::NonConstExpr { .. }),
    );
}

#[test]
fn check_wf013_rejects_const_with_function_call() {
    // (neg) `const X = someCall()` — function call in const initializer → NonConstExpr.
    assert_wf_error(
        r#"
        fn someCall() -> u128 { return 42u128 }
        contract Vault {
            const X: u128 = someCall()
        }
        "#,
        |kind| matches!(kind, TypeErrorKind::NonConstExpr { .. }),
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-014: Token config {} validation
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf014_accepts_full_valid_token_config() {
    // (pos) Full valid Token config with all mandatory keys → passes.
    assert_passes(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
            }
            init() {}
        }
        "#,
    );
}

#[test]
fn check_wf014_accepts_token_config_with_optional_key_absent() {
    // (pos) Optional key absent → feature off → passes.
    // `maxWallet` is optional; omitting it is valid.
    assert_passes(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
            }
            init() {}
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf014_rejects_token_config_missing_mandatory_key() {
    // (neg) Missing mandatory key `decimals` → InvalidTokenConfig.
    assert_wf_error(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                maxSupply: 1000000
            }
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::InvalidTokenConfig { reason, .. }
                    if reason.contains("decimals")
            )
        },
    );
}

#[test]
fn check_wf014_rejects_token_config_wrong_value_type() {
    // (neg) `decimals: "eighteen"` — wrong type (Str instead of Int) → InvalidTokenConfig.
    assert_wf_error(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: "eighteen"
                maxSupply: 1000000
            }
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::InvalidTokenConfig { reason, .. }
                    if reason.contains("decimals")
            )
        },
    );
}

#[test]
fn check_wf014_rejects_token_config_unknown_key() {
    // (neg) Unknown config key `fooBar` → InvalidTokenConfig.
    assert_wf_error(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
                fooBar: 42
            }
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::InvalidTokenConfig { reason, .. }
                    if reason.contains("fooBar")
            )
        },
    );
}

// ── Boundary tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf014_rejects_taxtoken_fees_others_without_distribute_taxes() {
    // (boundary) TaxToken with fees.others > 0 but no distributeTaxes function
    // → InvalidTokenConfig.
    assert_wf_error(
        r#"
        token MyToken extends TaxToken {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
                fees: { burn: 0 holders: 0 others: 100 }
            }
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::InvalidTokenConfig { reason, .. }
                    if reason.contains("distributeTaxes")
            )
        },
    );
}

// ── Spec §24.1 canonical example (pins schema against spec) ───────────────────

#[test]
fn check_wf014_accepts_spec_canonical_token_example() {
    // Uses the exact config from docs/03-LANGUAGE_SPEC.md §24.1.
    // If this test breaks, WF-014 has diverged from the spec's own example.
    // antiHoneypot: true is the spec's canonical anti-scam flag (§24.1, SAFETY-001).
    assert_passes(
        r#"
        token MyToken extends Token {
            config {
                name: "Example Token"
                symbol: "EXT"
                decimals: 18
                maxSupply: 1000000000

                antiHoneypot: true

                approvalExpiry: 86400
                approvalOneTime: true

                mintable: false
                pausable: false
                freezable: false
                upgradeable: false
            }
            init() {}
        }
        "#,
    );
}

#[test]
fn check_wf014_accepts_token_with_anti_honeypot_false() {
    // antiHoneypot: false is also a valid Bool value — passes schema check.
    assert_passes(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
                antiHoneypot: false
            }
            init() {}
        }
        "#,
    );
}

#[test]
fn check_wf014_rejects_anti_honeypot_wrong_type_int() {
    // (neg) antiHoneypot: 1 — Int instead of Bool → InvalidTokenConfig.
    assert_wf_error(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
                antiHoneypot: 1
            }
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::InvalidTokenConfig { reason, .. }
                    if reason.contains("antiHoneypot")
            )
        },
    );
}

#[test]
fn check_wf014_rejects_anti_honeypot_wrong_type_str() {
    // (neg) antiHoneypot: "yes" — Str instead of Bool → InvalidTokenConfig.
    assert_wf_error(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
                antiHoneypot: "yes"
            }
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::InvalidTokenConfig { reason, .. }
                    if reason.contains("antiHoneypot")
            )
        },
    );
}

#[test]
fn check_wf014_accepts_taxtoken_with_anti_honeypot() {
    // (pos) TaxToken also accepts antiHoneypot: true — it is a shared Token optional key.
    assert_passes(
        r#"
        token MyToken extends TaxToken {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
                antiHoneypot: true
                fees: { burn: 0 holders: 0 others: 0 }
            }
            init() {}
        }
        "#,
    );
}

#[test]
fn check_wf014_accepts_token_with_fair_launch() {
    // (pos) Token with fairLaunch block (§24.8 — available to both Token and TaxToken).
    assert_passes(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
                fairLaunch: {
                    cooldownBetweenBuys: 30
                    antiSnipeBlocks: 3
                }
            }
            init() {}
        }
        "#,
    );
}

#[test]
fn check_wf014_rejects_token_fair_launch_missing_mandatory_key() {
    // (neg) Token fairLaunch block missing cooldownBetweenBuys → InvalidTokenConfig.
    assert_wf_error(
        r#"
        token MyToken extends Token {
            config {
                name: "MyToken"
                symbol: "MTK"
                decimals: 18
                maxSupply: 1000000
                fairLaunch: {
                    antiSnipeBlocks: 3
                }
            }
            init() {}
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::InvalidTokenConfig { reason, .. }
                    if reason.contains("cooldownBetweenBuys")
            )
        },
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// WF-015: pure/view effect conformance
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf015_accepts_pure_fn_over_params_only() {
    // (pos) pure fn that only uses parameters (no state access) → passes.
    assert_passes(
        r#"
        contract Vault {
            pure fn add(a: u128, b: u128) -> u128 {
                return a + b
            }
        }
        "#,
    );
}

#[test]
fn check_wf015_accepts_view_fn_reading_state() {
    // (pos) view fn that reads state (allowed for view) → passes.
    assert_passes(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            view fn getBalance() -> u128 {
                return self.balance
            }
        }
        "#,
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn check_wf015_rejects_pure_fn_reading_self_field() {
    // (neg) pure fn reads self.field → EffectViolation { declared: "pure" }.
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            pure fn getBalance() -> u128 {
                return self.balance
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::EffectViolation { func, declared, .. }
                    if func == "getBalance" && declared == "pure"
            )
        },
    );
}

#[test]
fn check_wf015_rejects_view_fn_writing_self_field() {
    // (neg) view fn writes self.field → EffectViolation { declared: "view" }.
    assert_wf_error(
        r#"
        contract Vault {
            state { balance: u128 = 0 }
            view fn reset() {
                self.balance = 0
            }
        }
        "#,
        |kind| {
            matches!(
                kind,
                TypeErrorKind::EffectViolation { func, declared, .. }
                    if func == "reset" && declared == "view"
            )
        },
    );
}
