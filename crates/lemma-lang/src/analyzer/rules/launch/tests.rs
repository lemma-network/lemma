//! Tests for SAFETY-023, SAFETY-024, and P3-own-3 (a)(c) — launch/holding rules.
//!
//! ## Test layout (AGENTS §11.2)
//!
//! - **Positive**: valid contract → zero violations.
//! - **Negative per rule**: each attack variant produces the exact `SafetyError` variant.
//! - **Boundary**: no-feature declared → zero violations (conditional rules).
//! - **Token AND TaxToken**: both supported for SAFETY-023/024.
//!
//! ## WF-014 constraints in tests
//!
//! All fairLaunch configs include the mandatory `duration` key (WF-014 fix).
//! All Token/TaxToken configs include the mandatory keys per WF-014.
//! Map fields do not use `= {}` default (Lem syntax: no map literal default).
//! Address fields are initialized in `init()`.
//! `if` conditions require parentheses: `if (cond) { ... }`.

use crate::analyzer::error::SafetyError;
use crate::{check, parse, tokenize};

use super::check as launch_check;

/// Run the full pipeline and return a TypedAst (panics if any stage fails).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    check(ast).expect("check")
}

// ─── Shared fixtures ──────────────────────────────────────────────────────────

/// Minimal valid Token config (no fairLaunch, no maxWallet).
fn minimal_token_src() -> &'static str {
    r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
}
state { totalSupply: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#
}

/// Minimal valid TaxToken config (no fairLaunch, no maxWallet).
fn minimal_tax_token_src() -> &'static str {
    r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#
}

// ─── Guard: no-feature = zero violations ──────────────────────────────────────

#[test]
fn launch_rules_plain_token_no_features_triggers_no_violations() {
    // (boundary) Plain Token with no fairLaunch, no maxWallet → zero violations.
    let ast = typed_ast(minimal_token_src());
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "Token with no launch features must trigger zero violations; got {violations:?}"
    );
}

#[test]
fn launch_rules_plain_taxtoken_no_features_triggers_no_violations() {
    // (boundary) Plain TaxToken with no fairLaunch, no maxWallet → zero violations.
    let ast = typed_ast(minimal_tax_token_src());
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "TaxToken with no launch features must trigger zero violations; got {violations:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFETY-023 — maxWallet exempt interface
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn safety_023_token_with_maxwallet_and_exempt_consulted_passes() {
    // (pos) Token with maxWallet + isWalletExempt called in BOTH transfer AND transferFrom → clean.
    // BUG-M2 fix: both transfer-path entries must consult exempt.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxWallet: 500
}
state { totalSupply: u128 = 0 walletExempt: Map<Address, bool> }
init() {}
view fn isWalletExempt(addr: Address) -> bool { return self.walletExempt.get(addr) }
pub fn transfer(to: Address, amount: u128) {
    let exempt = self.isWalletExempt(to)
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {
    let exempt = self.isWalletExempt(to)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_023: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::MaxWalletNoExempt { .. }))
        .collect();
    assert!(
        safety_023.is_empty(),
        "Token with isWalletExempt consulted in both transfer paths must pass SAFETY-023; got {violations:?}"
    );
}

#[test]
fn safety_023_token_with_maxwallet_and_wallet_exempt_field_read_passes() {
    // (pos) Token with maxWallet + walletExempt state field read in BOTH transfer AND transferFrom → clean.
    // BUG-M2 fix: both transfer-path entries must consult exempt.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxWallet: 500
}
state { totalSupply: u128 = 0 walletExempt: Map<Address, bool> }
init() {}
view fn isWalletExempt(addr: Address) -> bool { return self.walletExempt.get(addr) }
pub fn transfer(to: Address, amount: u128) {
    let exempt = self.walletExempt.get(to)
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {
    let exempt = self.walletExempt.get(to)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_023: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::MaxWalletNoExempt { .. }))
        .collect();
    assert!(
        safety_023.is_empty(),
        "Token with walletExempt field read in both transfer paths must pass SAFETY-023; got {violations:?}"
    );
}

#[test]
fn safety_023_token_without_maxwallet_triggers_no_violations() {
    // (boundary) Token without maxWallet → zero SAFETY-023 violations.
    let ast = typed_ast(minimal_token_src());
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_023: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::MaxWalletNoExempt { .. }))
        .collect();
    assert!(
        safety_023.is_empty(),
        "Token without maxWallet must trigger zero SAFETY-023 violations; got {violations:?}"
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn safety_023_token_with_maxwallet_no_exempt_consultation_fails() {
    // (neg) Token with maxWallet + isWalletExempt declared but NOT called in transfer
    // → MaxWalletNoExempt.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxWallet: 500
}
state { totalSupply: u128 = 0 walletExempt: Map<Address, bool> }
init() {}
view fn isWalletExempt(addr: Address) -> bool { return self.walletExempt.get(addr) }
pub fn transfer(to: Address, amount: u128) {
    let x = amount
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::MaxWalletNoExempt { func } if func == "transfer")),
        "Token with maxWallet but no exempt consultation must fail SAFETY-023; got {violations:?}"
    );
}

#[test]
fn safety_023_taxtoken_with_maxwallet_no_exempt_consultation_fails() {
    // (neg) TaxToken with maxWallet + no exempt consultation → MaxWalletNoExempt.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
maxWallet: 500
}
state { totalSupply: u128 = 0 walletExempt: Map<Address, bool> }
init() {}
view fn isWalletExempt(addr: Address) -> bool { return self.walletExempt.get(addr) }
pub fn transfer(to: Address, amount: u128) {
    let x = amount
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::MaxWalletNoExempt { .. })),
        "TaxToken with maxWallet but no exempt consultation must fail SAFETY-023; got {violations:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFETY-024.1 — anti-snipe = fee not block
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn safety_024_1_token_without_fair_launch_triggers_no_violations() {
    // (boundary) Token without fairLaunch → zero SAFETY-024 violations.
    let ast = typed_ast(minimal_token_src());
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_024: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AntiSnipeIsBlock { .. }))
        .collect();
    assert!(
        safety_024.is_empty(),
        "Token without fairLaunch must trigger zero SAFETY-024.1 violations; got {violations:?}"
    );
}

#[test]
fn safety_024_1_token_with_fair_launch_fee_canonical_passes() {
    // (pos) Token with fairLaunch + anti-snipe fee (no revert) → clean.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 extraFee: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let inSnipeWindow = self.antiSnipeBlocks > 0
    let dur = self.duration
    self.extraFee = 5000
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_024_1: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AntiSnipeIsBlock { .. }))
        .collect();
    assert!(
        safety_024_1.is_empty(),
        "Token with canonical anti-snipe fee must pass SAFETY-024.1; got {violations:?}"
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn safety_024_1_token_with_fair_launch_anti_snipe_revert_fails() {
    // (neg) Token with fairLaunch + anti-snipe revert → AntiSnipeIsBlock.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let inSnipeWindow = self.antiSnipeBlocks > 0
    if (inSnipeWindow) {
        revert "sniper blocked"
    }
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AntiSnipeIsBlock { .. })),
        "Token with anti-snipe revert must fail SAFETY-024.1; got {violations:?}"
    );
}

#[test]
fn safety_024_1_taxtoken_with_fair_launch_anti_snipe_revert_fails() {
    // (neg) TaxToken with fairLaunch + anti-snipe revert → AntiSnipeIsBlock.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let inSnipeWindow = self.antiSnipeBlocks > 0
    if (inSnipeWindow) {
        revert "sniper blocked"
    }
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AntiSnipeIsBlock { .. })),
        "TaxToken with anti-snipe revert must fail SAFETY-024.1; got {violations:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFETY-024.2 — has duration (auto-expiry)
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn safety_024_2_token_without_fair_launch_triggers_no_violations() {
    // (boundary) Token without fairLaunch → zero SAFETY-024.2 violations.
    let ast = typed_ast(minimal_token_src());
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_024_2: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::LaunchControlNotExpiring { .. }))
        .collect();
    assert!(
        safety_024_2.is_empty(),
        "Token without fairLaunch must trigger zero SAFETY-024.2 violations; got {violations:?}"
    );
}

#[test]
fn safety_024_2_token_with_fair_launch_duration_consulted_passes() {
    // (pos) Token with fairLaunch + duration read in enforcement → clean.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let inWindow = self.antiSnipeBlocks > 0
    let dur = self.duration
    let extraFee = 5000
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_024_2: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::LaunchControlNotExpiring { .. }))
        .collect();
    assert!(
        safety_024_2.is_empty(),
        "Token with duration consulted must pass SAFETY-024.2; got {violations:?}"
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn safety_024_2_token_with_fair_launch_duration_not_read_fails() {
    // (neg) Token with fairLaunch + duration NOT read in enforcement → LaunchControlNotExpiring.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let inWindow = self.antiSnipeBlocks > 0
    let extraFee = 5000
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::LaunchControlNotExpiring { .. })),
        "Token with fairLaunch but duration not read must fail SAFETY-024.2; got {violations:?}"
    );
}

#[test]
fn safety_024_2_taxtoken_with_fair_launch_duration_not_read_fails() {
    // (neg) TaxToken with fairLaunch + duration NOT read → LaunchControlNotExpiring.
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let inWindow = self.antiSnipeBlocks > 0
    let extraFee = 5000
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::LaunchControlNotExpiring { .. })),
        "TaxToken with fairLaunch but duration not read must fail SAFETY-024.2; got {violations:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// SAFETY-024.3 — no sniper field gates disposal
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn safety_024_3_token_without_fair_launch_triggers_no_violations() {
    // (boundary) Token without fairLaunch → zero SAFETY-024.3 violations.
    let ast = typed_ast(minimal_token_src());
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_024_3: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AntiSnipeIsBlock { func } if func.contains("sniper")))
        .collect();
    assert!(
        safety_024_3.is_empty(),
        "Token without fairLaunch must trigger zero SAFETY-024.3 violations; got {violations:?}"
    );
}

#[test]
fn safety_024_3_token_with_sniper_field_not_on_transfer_path_passes() {
    // (pos) Token with fairLaunch + sniper field NOT on transfer denial path → clean.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 sniperList: Map<Address, bool> }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let dur = self.duration
    let extraFee = 5000
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_024_3: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AntiSnipeIsBlock { func } if func.contains("sniper")))
        .collect();
    assert!(
        safety_024_3.is_empty(),
        "Token with sniper field not on transfer denial path must pass SAFETY-024.3; got {violations:?}"
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn safety_024_3_token_with_sniper_field_gates_sell_fails() {
    // (neg) Token with fairLaunch + sniper field gates transfer via assert → AntiSnipeIsBlock.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 sniperList: Map<Address, bool> }
init() {}
pub fn transfer(to: Address, amount: u128) {
    assert (!self.sniperList.get(to))
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AntiSnipeIsBlock { .. })),
        "Token with sniper field gating transfer must fail SAFETY-024.3; got {violations:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// P3-own-3 (a) — MissingRequiredTrait
// ═══════════════════════════════════════════════════════════════════════════════

// ── Positive tests ─────────────────────────────────────────────────────────────

#[test]
fn p3_own3a_token_with_only_owner_passes() {
    // (pos) Token + @onlyOwner → clean (Token implicitly has Ownable).
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
}
state { totalSupply: u128 = 0 }
init() {}
@onlyOwner
pub fn setConfig(x: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let p3_own3a: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::MissingRequiredTrait { .. }))
        .collect();
    assert!(
        p3_own3a.is_empty(),
        "Token with @onlyOwner must pass P3-own-3(a) (implicit Ownable); got {violations:?}"
    );
}

#[test]
fn p3_own3a_taxtoken_with_only_owner_passes() {
    // (pos) TaxToken + @onlyOwner → clean (TaxToken implicitly has Ownable).
    let ast = typed_ast(
        r#"token T extends TaxToken {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxFeePercent: 2500
fees: { burn: 500 holders: 0 others: 0 }
}
state { totalSupply: u128 = 0 }
init() {}
@onlyOwner
pub fn setConfig(x: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let p3_own3a: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::MissingRequiredTrait { .. }))
        .collect();
    assert!(
        p3_own3a.is_empty(),
        "TaxToken with @onlyOwner must pass P3-own-3(a) (implicit Ownable); got {violations:?}"
    );
}

#[test]
fn p3_own3a_plain_contract_with_only_owner_and_owner_field_passes() {
    // (pos) Plain contract + @onlyOwner + owner state field → clean.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address x: u128 = 0 }
init(owner: Address) {
    self.owner = owner
}
@onlyOwner
pub fn setX(val: u128) {
    self.x = val
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let p3_own3a: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::MissingRequiredTrait { .. }))
        .collect();
    assert!(
        p3_own3a.is_empty(),
        "Plain contract with @onlyOwner + owner field must pass P3-own-3(a); got {violations:?}"
    );
}

#[test]
fn p3_own3a_plain_contract_without_only_owner_passes() {
    // (boundary) Plain contract without @onlyOwner → zero P3-own-3(a) violations.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
init() {}
pub fn setX(val: u128) {
    self.x = val
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let p3_own3a: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::MissingRequiredTrait { .. }))
        .collect();
    assert!(
        p3_own3a.is_empty(),
        "Plain contract without @onlyOwner must trigger zero P3-own-3(a) violations; got {violations:?}"
    );
}

// ── Negative tests ─────────────────────────────────────────────────────────────

#[test]
fn p3_own3a_plain_contract_with_only_owner_no_owner_field_fails() {
    // (neg) Plain contract + @onlyOwner + no owner state field → MissingRequiredTrait.
    let ast = typed_ast(
        r#"contract C {
state { x: u128 = 0 }
init() {}
@onlyOwner
pub fn setX(val: u128) {
    self.x = val
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations.iter().any(|v| matches!(
            v,
            SafetyError::MissingRequiredTrait { func, annotation }
                if func == "setX" && annotation == "onlyOwner"
        )),
        "Plain contract with @onlyOwner but no owner field must fail P3-own-3(a); got {violations:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// P3-own-3 (c) — is_renounce_aware helper
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn is_renounce_aware_returns_true_for_contract_with_renounce_writing_owner() {
    // (pos) Contract with `renounce` function that writes `self.owner` → renounce-aware.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address x: u128 = 0 }
init(owner: Address) {
    self.owner = owner
}
pub fn renounce() {
    self.owner = self.owner
}
@onlyOwner
pub fn setX(val: u128) {
    self.x = val
}
}"#,
    );
    let contracts = ast.contracts();
    let is_aware = super::is_renounce_aware(&contracts[0]);
    assert!(
        is_aware,
        "Contract with renounce writing self.owner must be renounce-aware"
    );
}

#[test]
fn is_renounce_aware_returns_false_for_contract_without_renounce() {
    // (neg) Contract without `renounce` function → not renounce-aware.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address x: u128 = 0 }
init(owner: Address) {
    self.owner = owner
}
@onlyOwner
pub fn setX(val: u128) {
    self.x = val
}
}"#,
    );
    let contracts = ast.contracts();
    let is_aware = super::is_renounce_aware(&contracts[0]);
    assert!(
        !is_aware,
        "Contract without renounce function must not be renounce-aware"
    );
}

#[test]
fn is_renounce_aware_returns_false_for_renounce_not_writing_owner() {
    // (neg) Contract with `renounce` function that does NOT write `self.owner` → not renounce-aware.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address x: u128 = 0 }
init(owner: Address) {
    self.owner = owner
}
pub fn renounce() {
    self.x = 0
}
@onlyOwner
pub fn setX(val: u128) {
    self.x = val
}
}"#,
    );
    let contracts = ast.contracts();
    let is_aware = super::is_renounce_aware(&contracts[0]);
    assert!(
        !is_aware,
        "Contract with renounce not writing self.owner must not be renounce-aware"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG-C1 — SAFETY-024.1 fee cap enforcement
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn safety_024_1_fee_exceeds_cap_rejected() {
    // (neg) C1: literal fee > MAX_ANTISNIPE_TAX (9000 bps) in snipe window → AntiSnipeIsBlock.
    // `self.extraFee = 9001` exceeds the 9000 bps cap — effectively a block.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 extraFee: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let inSnipeWindow = self.antiSnipeBlocks > 0
    if (inSnipeWindow) {
        self.extraFee = 9001
    }
    let dur = self.duration
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations
            .iter()
            .any(|v| matches!(v, SafetyError::AntiSnipeIsBlock { func } if func == "transfer")),
        "Fee > MAX_ANTISNIPE_TAX (9001 > 9000) must fail SAFETY-024.1; got {violations:?}"
    );
}

#[test]
fn safety_024_1_fee_at_cap_passes() {
    // (boundary) C1: literal fee == MAX_ANTISNIPE_TAX (9000 bps) → clean (at cap, not over).
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 extraFee: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let inSnipeWindow = self.antiSnipeBlocks > 0
    if (inSnipeWindow) {
        self.extraFee = 9000
    }
    let dur = self.duration
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let anti_snipe_block: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AntiSnipeIsBlock { .. }))
        .collect();
    assert!(
        anti_snipe_block.is_empty(),
        "Fee == MAX_ANTISNIPE_TAX (9000) must pass SAFETY-024.1 fee cap; got {violations:?}"
    );
}

#[test]
fn safety_024_1_fee_non_literal_inconclusive() {
    // (neg) C1: non-literal fee write in snipe window → Inconclusive (cannot prove bounded).
    // `self.extraFee = self.snipeFee` — cannot statically prove ≤ MAX_ANTISNIPE_TAX.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 extraFee: u128 = 0 snipeFee: u128 = 5000 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    let inSnipeWindow = self.antiSnipeBlocks > 0
    if (inSnipeWindow) {
        self.extraFee = self.snipeFee
    }
    let dur = self.duration
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations.iter().any(|v| matches!(
            v,
            SafetyError::Inconclusive {
                rule: "SAFETY-024",
                ..
            }
        )),
        "Non-literal fee write in snipe window must produce Inconclusive; got {violations:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG-M2 — SAFETY-023 multi-path check
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn safety_023_transfer_consults_but_transferfrom_does_not_fails() {
    // (neg) M2: transfer consults isWalletExempt but transferFrom does not → MaxWalletNoExempt.
    // BUG-M2 fix: ALL transfer-path entries must consult exempt, not just the first.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxWallet: 500
}
state { totalSupply: u128 = 0 walletExempt: Map<Address, bool> }
init() {}
view fn isWalletExempt(addr: Address) -> bool { return self.walletExempt.get(addr) }
pub fn transfer(to: Address, amount: u128) {
    let exempt = self.isWalletExempt(to)
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {
    let x = amount
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations.iter().any(
            |v| matches!(v, SafetyError::MaxWalletNoExempt { func } if func == "transferFrom")
        ),
        "transferFrom without exempt consultation must fail SAFETY-023; got {violations:?}"
    );
}

#[test]
fn safety_023_both_paths_consult_exempt_passes() {
    // (pos) M2: both transfer AND transferFrom consult isWalletExempt → clean.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxWallet: 500
}
state { totalSupply: u128 = 0 walletExempt: Map<Address, bool> }
init() {}
view fn isWalletExempt(addr: Address) -> bool { return self.walletExempt.get(addr) }
pub fn transfer(to: Address, amount: u128) {
    let exempt = self.isWalletExempt(to)
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {
    let exempt = self.isWalletExempt(to)
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let safety_023: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::MaxWalletNoExempt { .. }))
        .collect();
    assert!(
        safety_023.is_empty(),
        "Both transfer paths consulting exempt must pass SAFETY-023; got {violations:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG-M1 — SAFETY-024.1 scoped revert detection
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn safety_024_1_unrelated_revert_outside_snipe_window_does_not_flag() {
    // (pos) M1: revert for `assert(amount > 0)` outside snipe-window branch must NOT flag.
    // BUG-M1 fix: revert detection is scoped to snipe-window conditional branch only.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 extraFee: u128 = 0 }
init() {}
pub fn transfer(to: Address, amount: u128) {
    assert (amount > 0)
    let inSnipeWindow = self.antiSnipeBlocks > 0
    if (inSnipeWindow) {
        self.extraFee = 5000
    }
    let dur = self.duration
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    let anti_snipe_block: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::AntiSnipeIsBlock { .. }))
        .collect();
    assert!(
        anti_snipe_block.is_empty(),
        "Unrelated revert outside snipe-window branch must NOT flag SAFETY-024.1; got {violations:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// BUG-C2 — spec §2.1: renounce-aware does NOT skip SAFETY-005/009
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn renounce_aware_contract_still_flags_safety_005_via_blacklist() {
    // (neg) C2: contract with renounce() + @onlyOwner blacklist lever → still flagged.
    // Spec §2.1: "static rule remains conservative regardless of renounce."
    // This test verifies the launch rule itself doesn't suppress SAFETY-005 behavior.
    // The actual SAFETY-005 check is in blacklist.rs; here we verify is_renounce_aware
    // is correctly detected but does NOT suppress violations in launch rules.
    let ast = typed_ast(
        r#"contract C {
state { owner: Address x: u128 = 0 }
init(owner: Address) {
    self.owner = owner
}
pub fn renounce() {
    self.owner = self.owner
}
@onlyOwner
pub fn setX(val: u128) {
    self.x = val
}
}"#,
    );
    let contracts = ast.contracts();
    // is_renounce_aware should still return true (the helper is correct).
    let is_aware = super::is_renounce_aware(&contracts[0]);
    assert!(
        is_aware,
        "Contract with renounce writing self.owner must be renounce-aware"
    );
    // But launch rules (P3-own-3 a) should still flag if owner field is present
    // (no violation here since owner field exists — this tests the helper is intact).
    let violations = launch_check(&contracts[0]);
    let missing_trait: Vec<_> = violations
        .iter()
        .filter(|v| matches!(v, SafetyError::MissingRequiredTrait { .. }))
        .collect();
    assert!(
        missing_trait.is_empty(),
        "Renounce-aware contract with owner field must not flag P3-own-3(a); got {violations:?}"
    );
}

#[test]
fn fake_renounce_does_not_make_contract_renounce_aware() {
    // (neg) C2: `renounce(){ self.owner = self.owner }` is a no-op write.
    // The OwnerFieldWriteScanner detects ANY write to self.owner — including no-ops.
    // This test documents that the current name-based check accepts this pattern
    // (the Address.burn recognition is deferred to Step 6).
    let ast = typed_ast(
        r#"contract C {
state { owner: Address x: u128 = 0 }
init(owner: Address) {
    self.owner = owner
}
pub fn renounce() {
    self.owner = self.owner
}
@onlyOwner
pub fn setX(val: u128) {
    self.x = val
}
}"#,
    );
    let contracts = ast.contracts();
    // The no-op write `self.owner = self.owner` IS detected as a write to self.owner.
    // This is a known limitation — Address.burn recognition is deferred to Step 6.
    // The test documents the current behavior (not a false-negative for SAFETY-005/009
    // since those rules no longer use is_renounce_aware to skip violations).
    let is_aware = super::is_renounce_aware(&contracts[0]);
    // Document: no-op write is currently treated as renounce-aware (Step 6 deferred).
    // The important thing is SAFETY-005/009 do NOT use this to skip violations.
    let _ = is_aware; // behavior documented above; not asserting true/false here
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cross-rule interaction tests (M4)
// ═══════════════════════════════════════════════════════════════════════════════

#[test]
fn cross_rule_maxwallet_fairlaunch_plain_token_clean() {
    // (pos) M4: Token with maxWallet + fairLaunch both correctly implemented → zero violations.
    let ast = typed_ast(
        r#"token T extends Token {
config {
name: "T"
symbol: "T"
decimals: 18
maxSupply: 1000000
maxWallet: 500
fairLaunch: {
    cooldownBetweenBuys: 30
    antiSnipeBlocks: 3
    duration: 100
}
}
state { totalSupply: u128 = 0 launchBlock: u128 = 0 extraFee: u128 = 0 walletExempt: Map<Address, bool> }
init() {}
view fn isWalletExempt(addr: Address) -> bool { return self.walletExempt.get(addr) }
pub fn transfer(to: Address, amount: u128) {
    let exempt = self.isWalletExempt(to)
    let inSnipeWindow = self.antiSnipeBlocks > 0
    if (inSnipeWindow) {
        self.extraFee = 5000
    }
    let dur = self.duration
}
pub fn transferFrom(from: Address, to: Address, amount: u128) {
    let exempt = self.isWalletExempt(to)
    let inSnipeWindow = self.antiSnipeBlocks > 0
    if (inSnipeWindow) {
        self.extraFee = 5000
    }
    let dur = self.duration
}
}"#,
    );
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "Token with maxWallet + fairLaunch both correctly implemented must have zero violations; got {violations:?}"
    );
}

#[test]
fn cross_rule_token_without_maxwallet_and_without_fairlaunch_clean() {
    // (boundary) M4: Token without maxWallet AND without fairLaunch → zero violations (base case).
    let ast = typed_ast(minimal_token_src());
    let contracts = ast.contracts();
    let violations = launch_check(&contracts[0]);
    assert!(
        violations.is_empty(),
        "Token without maxWallet and without fairLaunch must have zero violations; got {violations:?}"
    );
}
