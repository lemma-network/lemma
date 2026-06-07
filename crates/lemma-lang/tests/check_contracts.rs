//! Integration tests — P3·Step 3h type-checker acceptance proof.
//!
//! These tests exercise the full tokenize→parse→check pipeline against
//! realistic Lem contracts, proving the acceptance criterion:
//! **"Type checker catches type errors"** (`04-BUILD_GUIDE.md` P3·Step 3).
//!
//! Every positive test proves a realistic contract passes the full pipeline and
//! that the resulting [`TypedContract`] projection carries the data Step 4 needs.
//! Every negative test proves a type error surfaces as `Err(LangError::Type(…))`
//! and never as a panic or a silent pass.
//!
//! ## Layout
//!
//! - `check_*_accepts` — positive e2e: realistic contracts that MUST type-check
//! - `check_*_rejects` / `check_*_carries_*` — negative e2e: deliberate errors
//! - `typed_contract_*` — `TypedContract` projection asserted against known input
//!
//! ## Step 4 contract
//!
//! These tests verify the data contract `TypedContract` exposes to the Step 4
//! safety analyzer (`analyze_safety(contract: &TypedContract)`).  A `TypedContract`
//! produced by a passing `check()` call must correctly report:
//! - contract name and `is_token` flag
//! - `state {}` field names + resolved types + `is_immutable` flag
//! - `config {}` entries for token contracts
//! - all functions with their names and return types

use lemma_lang::error::LangError;
use lemma_lang::type_checker::error::TypeErrorKind;
use lemma_lang::type_checker::types::ResolvedType;
use lemma_lang::type_checker::TypedAst;
use lemma_lang::{check, parse, tokenize};

// ─── Pipeline helper ──────────────────────────────────────────────────────────

/// Run the full `tokenize → parse → check` pipeline.
///
/// `tokenize` and `parse` are expected to succeed (already proven by
/// `parse_contracts.rs`).  Only `check` may return `Err`.
fn pipeline(src: &str) -> Result<TypedAst, LangError> {
    let tokens = tokenize(src).expect("tokenize failed in integration test");
    let ast = parse(tokens).expect("parse failed in integration test");
    check(ast)
}

// ─── Positive e2e tests ───────────────────────────────────────────────────────

/// Scenario 1 — minimal token (config only, no state, no functions).
///
/// Proves the simplest possible token contract passes the full pipeline.
/// Config-only tokens are the Lemma equivalent of a vanilla transfer-only
/// deploy — no state mutations, no hooks.
#[test]
fn check_minimal_token_accepts() {
    let result = pipeline(
        r#"token MinimalToken extends Token {
config {
name: "Minimal"
symbol: "MIN"
decimals: 18
maxSupply: 1000000
}
}"#,
    );
    assert!(
        result.is_ok(),
        "minimal token should type-check; got: {:?}",
        result.err()
    );
}

/// Scenario 2 — token with Map state and a `view` function reading from it.
///
/// Proves Map<Address, u128> state resolves correctly and that a function
/// returning `self.state[arg]` passes the return-type check end-to-end.
#[test]
fn check_token_with_state_and_view_function_accepts() {
    let result = pipeline(
        r#"token ExtendedToken extends Token {
config {
name: "Extended Token"
symbol: "EXT2"
decimals: 18
maxSupply: 500000000
}
state {
snapshots: Map<Address, u128>
}
pub view fn getSnapshot(holder: Address) -> u128 {
return self.snapshots[holder]
}
}"#,
    );
    assert!(
        result.is_ok(),
        "token with state + view fn should type-check; got: {:?}",
        result.err()
    );
}

/// Scenario 3 — AMM/DEX contract with state, annotations, and arithmetic
/// across multiple functions.
///
/// Proves: multi-function contracts with u128 arithmetic, Map index
/// reads/writes, bool state, and `@nonReentrant` / `@whenNotPaused`
/// annotations all pass the full type-checker pipeline.
///
/// Note: `msg` (transaction context) is a blockchain global not yet wired into
/// the checker's built-in namespace — it is deferred to the node integration
/// layer (Step 7).  This contract uses explicit `provider: Address` params
/// instead, which exercises the same Map-indexing and state-mutation paths.
#[test]
fn check_contract_dex_amm_accepts() {
    let result = pipeline(
        r#"contract SimpleAMM {
state {
pub reserves0: u128
pub reserves1: u128
pub totalLiquidity: u128
liquidity: Map<Address, u128>
pub paused: bool
}
@nonReentrant
@whenNotPaused
pub fn swap(amountIn: u128, zeroForOne: bool) -> u128 {
let amountOut = amountIn * self.reserves1 / (self.reserves0 + amountIn)
self.reserves0 = self.reserves0 + amountIn
self.reserves1 = self.reserves1 - amountOut
return amountOut
}
@nonReentrant
pub fn addLiquidity(amount0: u128, amount1: u128) -> u128 {
self.reserves0 = self.reserves0 + amount0
self.reserves1 = self.reserves1 + amount1
self.totalLiquidity = self.totalLiquidity + amount0
return amount0
}
pub view fn quote(amountIn: u128, reserveIn: u128, reserveOut: u128) -> u128 {
return amountIn * reserveOut / reserveIn
}
pub fn removeLiquidity(provider: Address, shares: u128) {
self.liquidity[provider] = self.liquidity[provider] - shares
self.totalLiquidity = self.totalLiquidity - shares
}
}"#,
    );
    assert!(
        result.is_ok(),
        "DEX AMM contract should type-check; got: {:?}",
        result.err()
    );
}

// ─── TypedContract projection tests ──────────────────────────────────────────

/// Proves `TypedContract::name()` and `is_token()` return correct values for
/// both `token` and plain `contract` items.
#[test]
fn typed_contract_name_and_is_token_flags_correct() {
    // Token contract — is_token must be true
    let typed = pipeline(
        r#"token MyToken extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1 }
}"#,
    )
    .expect("pipeline failed");
    let contracts = typed.contracts();
    assert_eq!(contracts.len(), 1, "expected one contract");
    assert_eq!(contracts[0].name(), "MyToken");
    assert!(
        contracts[0].is_token(),
        "token_ item must report is_token=true"
    );

    // Plain contract — is_token must be false
    let typed = pipeline(r#"contract MyContract {}"#).expect("pipeline failed");
    let contracts = typed.contracts();
    assert_eq!(contracts.len(), 1, "expected one contract");
    assert_eq!(contracts[0].name(), "MyContract");
    assert!(
        !contracts[0].is_token(),
        "plain contract must report is_token=false"
    );
}

/// Proves `TypedContract::state_fields()` returns fields with correctly
/// resolved types in declaration order.
///
/// The three canonical state field types used by the safety analyzer are:
/// - `u128` — token amounts, balances
/// - `bool` — flags (paused, frozen, etc.)
/// - `Address` — owners, recipients, operators
#[test]
fn typed_contract_state_fields_resolved_types_correct() {
    let typed = pipeline(
        r#"contract TypesTest {
state {
count: u128
flag: bool
owner: Address
}
}"#,
    )
    .expect("pipeline failed");

    let contracts = typed.contracts();
    assert_eq!(contracts.len(), 1);
    let fields = contracts[0].state_fields();
    assert_eq!(fields.len(), 3, "expected 3 state fields");

    // Names in declaration order
    assert_eq!(fields[0].name, "count");
    assert_eq!(fields[1].name, "flag");
    assert_eq!(fields[2].name, "owner");

    // Resolved types — what Step 4 uses for semantic analysis
    assert_eq!(*fields[0].ty, ResolvedType::U128, "count should be U128");
    assert_eq!(*fields[1].ty, ResolvedType::Bool, "flag should be Bool");
    assert_eq!(
        *fields[2].ty,
        ResolvedType::AddressTy,
        "owner should be AddressTy"
    );

    // None of these are immutable declarations
    assert!(
        !fields[0].is_immutable && !fields[1].is_immutable && !fields[2].is_immutable,
        "state {{ }} fields must have is_immutable=false"
    );
}

/// Proves `TypedContract::config()` returns `Some` for token contracts
/// (with at least one entry) and `None` for plain contracts.
///
/// The Step 4 safety analyzer reads `config()` to access `maxFeePercent`
/// for fee-cap enforcement (09-SAFETY_ANALYZER_SPEC §1).
#[test]
fn typed_contract_config_present_for_token_absent_for_contract() {
    // Token — config must be Some with entries
    let typed = pipeline(
        r#"token Tk extends Token {
config { name: "T" symbol: "T" decimals: 18 maxSupply: 1 }
}"#,
    )
    .expect("pipeline failed");
    let contracts = typed.contracts();
    let config = contracts[0]
        .config()
        .expect("token contract must expose config()");
    assert!(!config.is_empty(), "config must have entries");

    // Plain contract — config must be None
    let typed = pipeline(r#"contract C {}"#).expect("pipeline failed");
    let contracts = typed.contracts();
    assert!(
        contracts[0].config().is_none(),
        "plain contract must return None for config()"
    );
}

/// Proves `TypedContract::functions()` returns all functions with correct
/// names and resolved return types.
///
/// The Step 4 safety analyzer iterates functions to check reentrancy, fee
/// hooks, and mint guards (09-SAFETY_ANALYZER_SPEC §1).
#[test]
fn typed_contract_functions_names_and_return_types_correct() {
    let typed = pipeline(
        r#"contract FnTest {
state {
count: u128
}
pub view fn getCount() -> u128 {
return self.count
}
pub fn setCount(val: u128) {
self.count = val
}
}"#,
    )
    .expect("pipeline failed");

    let contracts = typed.contracts();
    assert_eq!(contracts.len(), 1);
    let fns = contracts[0].functions();
    assert_eq!(fns.len(), 2, "expected getCount + setCount");

    // getCount — explicit return type u128
    assert_eq!(fns[0].name, "getCount");
    assert_eq!(
        fns[0].return_type,
        Some(ResolvedType::U128),
        "getCount must have return_type U128"
    );

    // setCount — no return annotation → Unit
    assert_eq!(fns[1].name, "setCount");
    assert_eq!(
        fns[1].return_type,
        Some(ResolvedType::Unit),
        "setCount (no annotation) must have return_type Unit"
    );
}

/// Proves `TypedAst::contracts()` yields all contract/token items in
/// declaration order when a source file contains multiple top-level contracts.
#[test]
fn check_multiple_contracts_projected_in_declaration_order() {
    let typed = pipeline(
        r#"contract Alpha {}
contract Beta {}
contract Gamma {}"#,
    )
    .expect("pipeline failed");

    let contracts = typed.contracts();
    let names: Vec<&str> = contracts.iter().map(|c| c.name()).collect();
    assert_eq!(
        names,
        ["Alpha", "Beta", "Gamma"],
        "contracts must be projected in declaration order"
    );
}

// ─── Negative e2e tests ───────────────────────────────────────────────────────

/// Proves an undefined name surfaces as `LangError::Type(UndefinedName)`.
///
/// The full pipeline must not panic on a name-resolution failure; it must
/// return a typed error with the offending name recorded.
#[test]
fn check_undefined_name_rejects() {
    let result = pipeline(
        r#"contract Bad {
pub fn f() -> u128 {
return unknownVariable
}
}"#,
    );
    assert!(result.is_err(), "undefined name must produce an error");
    match result.unwrap_err() {
        LangError::Type(e) => assert!(
            matches!(e.kind, TypeErrorKind::UndefinedName { .. }),
            "expected UndefinedName, got {:?}",
            e.kind
        ),
        other => panic!("expected LangError::Type, got {:?}", other),
    }
}

/// Proves a return-type mismatch surfaces as `LangError::Type(TypeMismatch)`.
///
/// The full pipeline must identify the mismatch between the function's
/// return annotation and the returned expression's inferred type.
#[test]
fn check_type_mismatch_in_return_rejects() {
    let result = pipeline(
        r#"contract Bad {
pub fn f() -> bool {
return 42
}
}"#,
    );
    assert!(
        result.is_err(),
        "return type mismatch must produce an error"
    );
    match result.unwrap_err() {
        LangError::Type(e) => assert!(
            matches!(e.kind, TypeErrorKind::ReturnTypeMismatch { .. }),
            "expected ReturnTypeMismatch, got {:?}",
            e.kind
        ),
        other => panic!("expected LangError::Type, got {:?}", other),
    }
}

/// Proves a duplicate top-level declaration surfaces as `DuplicateDeclaration`.
///
/// Lem forbids two top-level items sharing a name in the same compilation unit.
#[test]
fn check_duplicate_declaration_rejects() {
    let result = pipeline(
        r#"contract A {}
contract A {}"#,
    );
    assert!(
        result.is_err(),
        "duplicate declaration must produce an error"
    );
    match result.unwrap_err() {
        LangError::Type(e) => assert!(
            matches!(e.kind, TypeErrorKind::DuplicateDeclaration { .. }),
            "expected DuplicateDeclaration, got {:?}",
            e.kind
        ),
        other => panic!("expected LangError::Type, got {:?}", other),
    }
}

/// Proves type errors carry a non-trivial source span.
///
/// The span is what the Lemma CLI and IDEs use to position the error cursor.
/// A span of all-zeros would mean the error is unlocatable in the source file.
#[test]
fn check_type_error_carries_non_trivial_span() {
    // Undefined name — span must point at the offending identifier.
    let result = pipeline(
        r#"contract C {
pub fn f() -> u128 {
return missingIdent
}
}"#,
    );
    let err = result.expect_err("should fail on undefined name");
    match err {
        LangError::Type(e) => {
            assert!(
                e.span.line > 0 || e.span.col > 0,
                "error span must be non-trivial; got line={} col={}",
                e.span.line,
                e.span.col
            );
        }
        other => panic!("expected LangError::Type, got {:?}", other),
    }
}
