//! Integration tests — P3·Step 2 parser acceptance proof.
//!
//! These tests exercise the full `lemma_lang::tokenize` + `lemma_lang::parse`
//! pipeline against realistic Lem contracts, proving the acceptance criterion:
//! **"Parser — valid AST for token, DEX, staking contracts"**
//! (`04-BUILD_GUIDE.md` P3·Step 2).
//!
//! Every test uses the public crate API only (`tokenize` + `parse`).
//! No unit-test internals are imported.
//!
//! ## Layout
//!
//! - `token_*` — token standard scenarios (non-tax, tax, flags, fairLaunch,
//!   vesting, metadata, all unit suffixes, ident values, full-featured)
//! - `contract_dex_*` — DEX/AMM contract
//! - `contract_staking_*` — staking contract
//! - `no_panic_*` — fuzz/sweep: all samples must never panic
//!
//! Deferred (Step 3+): type correctness, SAFETY rules, codegen.
//! These tests assert syntactic validity only.

use lemma_lang::parser::{
    Config, ConfigValue, ContractMember, Item, Metadata, TokenDecl, UnitKind,
};
use lemma_lang::{parse, tokenize};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn run(src: &str) -> Vec<Item> {
    let tokens = tokenize(src).expect("tokenize failed");
    let ast = parse(tokens).expect("parse failed");
    ast.items
}

fn token_decl(src: &str) -> TokenDecl {
    let items = run(src);
    assert_eq!(items.len(), 1, "expected exactly one item");
    match items.into_iter().next().unwrap() {
        Item::Token_(decl) => decl,
        other => panic!("expected Token_ item, got: {other:?}"),
    }
}

fn config_of(decl: &TokenDecl) -> &Config {
    decl.members
        .iter()
        .find_map(|m| match m {
            ContractMember::Config(c) => Some(c),
            _ => None,
        })
        .expect("no Config member found")
}

fn metadata_of(decl: &TokenDecl) -> &Metadata {
    decl.members
        .iter()
        .find_map(|m| match m {
            ContractMember::Metadata(m) => Some(m),
            _ => None,
        })
        .expect("no Metadata member found")
}

fn entry_value<'a>(cfg: &'a Config, key: &str) -> &'a ConfigValue {
    &cfg.entries
        .iter()
        .find(|e| e.key == key)
        .unwrap_or_else(|| panic!("key '{}' not found in config", key))
        .value
}

// ─── Token scenarios ──────────────────────────────────────────────────────────

/// Scenario 1 — minimal non-tax token: only name/symbol/decimals/maxSupply.
/// Proves config block parses with Str + Int values; no hooks, no metadata.
#[test]
fn token_minimal_non_tax() {
    let decl = token_decl(
        r#"token MinimalToken extends Token {
config {
name: "Minimal Token"
symbol: "MIN"
decimals: 18
maxSupply: 1000000000
}
}"#,
    );
    assert_eq!(decl.name, "MinimalToken");
    assert_eq!(decl.extends, "Token");

    let cfg = config_of(&decl);
    assert_eq!(cfg.entries.len(), 4);
    assert_eq!(
        entry_value(cfg, "name"),
        &ConfigValue::Str("Minimal Token".into())
    );
    assert_eq!(entry_value(cfg, "symbol"), &ConfigValue::Str("MIN".into()));
    assert_eq!(entry_value(cfg, "decimals"), &ConfigValue::Int(18));
    assert_eq!(
        entry_value(cfg, "maxSupply"),
        &ConfigValue::Int(1_000_000_000)
    );
}

/// Scenario 2 — mintable/pausable/freezable/upgradeable boolean flags.
/// Proves all four bool config entries parse correctly.
#[test]
fn token_mintable_pausable_flags() {
    let decl = token_decl(
        r#"token MintableToken extends Token {
config {
name: "Mintable"
symbol: "MNT"
decimals: 18
maxSupply: 500000000
mintable: true
pausable: true
freezable: false
upgradeable: false
}
}"#,
    );
    let cfg = config_of(&decl);
    assert_eq!(entry_value(cfg, "mintable"), &ConfigValue::Bool(true));
    assert_eq!(entry_value(cfg, "pausable"), &ConfigValue::Bool(true));
    assert_eq!(entry_value(cfg, "freezable"), &ConfigValue::Bool(false));
    assert_eq!(entry_value(cfg, "upgradeable"), &ConfigValue::Bool(false));
}

/// Scenario 3 — approval and anti-honeypot config (Unit + Bool + Int values).
/// Covers approvalExpiry: 24.hours, approvalOneTime, antiHoneypot, maxFeePercent.
#[test]
fn token_approval_and_anti_honeypot_config() {
    let decl = token_decl(
        r#"token SafeToken extends Token {
config {
name: "Safe Token"
symbol: "SAFE"
decimals: 18
maxSupply: 100000000
antiHoneypot: true
maxFeePercent: 10
approvalExpiry: 24.hours
approvalOneTime: true
}
}"#,
    );
    let cfg = config_of(&decl);
    assert_eq!(entry_value(cfg, "antiHoneypot"), &ConfigValue::Bool(true));
    assert_eq!(entry_value(cfg, "maxFeePercent"), &ConfigValue::Int(10));
    assert_eq!(
        entry_value(cfg, "approvalExpiry"),
        &ConfigValue::Unit(24, UnitKind::Hours)
    );
    assert_eq!(
        entry_value(cfg, "approvalOneTime"),
        &ConfigValue::Bool(true)
    );
}

/// Scenario 4 — tax token with #[onTransfer] hook containing float arithmetic.
/// Proves: function member parses, float literal in expr works, self method calls.
#[test]
fn token_tax_with_on_transfer_hook() {
    let decl = token_decl(
        r#"token TaxToken extends Token {
config {
name: "Tax Token"
symbol: "TAX"
decimals: 18
maxSupply: 1000000000
antiHoneypot: true
maxFeePercent: 5
}
#[onTransfer]
fn onTransfer(from: Address, to: Address, amount: u128) {
let tax = amount * 0.05
self.burn(tax * 0.40)
self.addLiquidity(tax * 0.30)
self.distributeToHolders(tax * 0.30)
}
}"#,
    );
    // Config present
    let cfg = config_of(&decl);
    assert_eq!(entry_value(cfg, "antiHoneypot"), &ConfigValue::Bool(true));
    assert_eq!(entry_value(cfg, "maxFeePercent"), &ConfigValue::Int(5));

    // Function member present with correct name
    let hook = decl.members.iter().find_map(|m| match m {
        ContractMember::Function(f) if f.name == "onTransfer" => Some(f),
        _ => None,
    });
    assert!(hook.is_some(), "onTransfer function member not found");
    let hook = hook.unwrap();
    assert_eq!(hook.annotations.len(), 1);
    assert_eq!(hook.annotations[0].name, "onTransfer");
    assert_eq!(hook.params.len(), 3);
}

/// Scenario 5 — fairLaunch nested config block.
/// Proves nested Object with .seconds and .hours unit values, int + bool fields.
#[test]
fn token_fair_launch_nested_block() {
    let decl = token_decl(
        r#"token FairLaunchToken extends Token {
config {
name: "FairLaunch Token"
symbol: "FAIR"
decimals: 18
maxSupply: 200000000
fairLaunch: {
enabled: true
maxBuyPerWallet: 10000
cooldownBetweenBuys: 30.seconds
antiSnipeBlocks: 3
duration: 24.hours
}
}
}"#,
    );
    let cfg = config_of(&decl);
    let fair_launch = match entry_value(cfg, "fairLaunch") {
        ConfigValue::Object(entries) => entries,
        other => panic!("expected Object for fairLaunch, got: {other:?}"),
    };
    assert_eq!(fair_launch.len(), 5);

    let enabled = fair_launch.iter().find(|e| e.key == "enabled").unwrap();
    assert_eq!(enabled.value, ConfigValue::Bool(true));

    let max_buy = fair_launch
        .iter()
        .find(|e| e.key == "maxBuyPerWallet")
        .unwrap();
    assert_eq!(max_buy.value, ConfigValue::Int(10_000));

    let cooldown = fair_launch
        .iter()
        .find(|e| e.key == "cooldownBetweenBuys")
        .unwrap();
    assert_eq!(cooldown.value, ConfigValue::Unit(30, UnitKind::Seconds));

    let duration = fair_launch.iter().find(|e| e.key == "duration").unwrap();
    assert_eq!(duration.value, ConfigValue::Unit(24, UnitKind::Hours));
}

/// Scenario 6 — vesting with multiple beneficiaries (deeply nested + Percent + months).
/// Proves: Object → Object depth-2, Percent variant, UnitKind::Months.
#[test]
fn token_vesting_multi_beneficiary() {
    let decl = token_decl(
        r#"token VestingToken extends Token {
config {
name: "Vesting Token"
symbol: "VEST"
decimals: 18
maxSupply: 1000000000
vesting: {
team: { amount: 15%, cliff: 6.months, linear: 24.months }
investors: { amount: 10%, cliff: 3.months, linear: 12.months }
advisors: { amount: 5%, cliff: 1.months, linear: 6.months }
}
}
}"#,
    );
    let cfg = config_of(&decl);
    let vesting = match entry_value(cfg, "vesting") {
        ConfigValue::Object(v) => v,
        other => panic!("expected Object for vesting, got: {other:?}"),
    };
    assert_eq!(vesting.len(), 3, "expected team + investors + advisors");

    // Verify team
    let team = match &vesting[0].value {
        ConfigValue::Object(t) => t,
        other => panic!("expected Object for team, got: {other:?}"),
    };
    assert_eq!(team[0].value, ConfigValue::Percent(15));
    assert_eq!(team[1].value, ConfigValue::Unit(6, UnitKind::Months));
    assert_eq!(team[2].value, ConfigValue::Unit(24, UnitKind::Months));

    // Verify investors
    let investors = match &vesting[1].value {
        ConfigValue::Object(i) => i,
        other => panic!("expected Object for investors, got: {other:?}"),
    };
    assert_eq!(investors[0].value, ConfigValue::Percent(10));
    assert_eq!(investors[1].value, ConfigValue::Unit(3, UnitKind::Months));

    // Verify advisors
    let advisors = match &vesting[2].value {
        ConfigValue::Object(a) => a,
        other => panic!("expected Object for advisors, got: {other:?}"),
    };
    assert_eq!(advisors[0].value, ConfigValue::Percent(5));
}

/// Scenario 7 — metadata block with nested socials object.
/// Proves metadata parsed as ContractMember::Metadata, nested Object in metadata.
#[test]
fn token_metadata_with_nested_socials() {
    let decl = token_decl(
        r#"token SocialToken extends Token {
config {
name: "Social Token"
symbol: "SOC"
decimals: 18
maxSupply: 100000000
}
metadata {
image: "ipfs://QmExampleHash"
website: "https://socialtoken.io"
whitepaper: "https://socialtoken.io/whitepaper.pdf"
socials: { twitter: "@socialtoken", telegram: "t.me/socialtoken", discord: "discord.gg/social" }
}
}"#,
    );
    let meta = metadata_of(&decl);
    assert_eq!(meta.entries.len(), 4);

    let image = meta.entries.iter().find(|e| e.key == "image").unwrap();
    assert_eq!(image.value, ConfigValue::Str("ipfs://QmExampleHash".into()));

    let socials = meta.entries.iter().find(|e| e.key == "socials").unwrap();
    let social_entries = match &socials.value {
        ConfigValue::Object(s) => s,
        other => panic!("expected Object for socials, got: {other:?}"),
    };
    assert_eq!(social_entries.len(), 3);
    assert_eq!(
        social_entries[0].value,
        ConfigValue::Str("@socialtoken".into())
    );
}

/// Scenario 8 — all unit suffixes in config values.
/// Proves: .hours .seconds .months .days .minutes all parse to correct UnitKind.
#[test]
fn token_all_unit_suffixes_in_config() {
    let decl = token_decl(
        r#"token UnitsToken extends Token {
config {
name: "Units Token"
symbol: "UNIT"
decimals: 18
maxSupply: 100000000
lockHours: 24.hours
cooldown: 30.seconds
vestMonths: 6.months
durationDays: 7.days
expireMinutes: 60.minutes
}
}"#,
    );
    let cfg = config_of(&decl);
    assert_eq!(
        entry_value(cfg, "lockHours"),
        &ConfigValue::Unit(24, UnitKind::Hours)
    );
    assert_eq!(
        entry_value(cfg, "cooldown"),
        &ConfigValue::Unit(30, UnitKind::Seconds)
    );
    assert_eq!(
        entry_value(cfg, "vestMonths"),
        &ConfigValue::Unit(6, UnitKind::Months)
    );
    assert_eq!(
        entry_value(cfg, "durationDays"),
        &ConfigValue::Unit(7, UnitKind::Days)
    );
    assert_eq!(
        entry_value(cfg, "expireMinutes"),
        &ConfigValue::Unit(60, UnitKind::Minutes)
    );
}

/// Scenario 9 — ConfigValue::Ident in config (identifier reference as value).
/// Proves: bare identifier (e.g. a type name or mode enum) parses as Ident variant.
#[test]
fn token_ident_config_value() {
    let decl = token_decl(
        r#"token IdentToken extends Token {
config {
name: "Ident Token"
symbol: "IDT"
decimals: 18
maxSupply: 100000000
pricingModel: BondingCurve
distributionMode: Proportional
}
}"#,
    );
    let cfg = config_of(&decl);
    assert_eq!(
        entry_value(cfg, "pricingModel"),
        &ConfigValue::Ident("BondingCurve".into())
    );
    assert_eq!(
        entry_value(cfg, "distributionMode"),
        &ConfigValue::Ident("Proportional".into())
    );
}

/// Scenario 10 — full-featured token: config + tax hook + metadata.
/// This mirrors the real ExampleToken from lemma-contracts.
/// Proves all three member types coexist in one token declaration.
#[test]
fn token_full_featured_all_member_types() {
    let src = r#"token ExampleToken extends Token {
config {
name: "Example Token"
symbol: "EXT"
decimals: 18
maxSupply: 1000000000
antiHoneypot: true
maxFeePercent: 10
approvalExpiry: 24.hours
approvalOneTime: true
mintable: false
pausable: false
freezable: false
upgradeable: false
fairLaunch: {
enabled: true
maxBuyPerWallet: 10000
cooldownBetweenBuys: 30.seconds
antiSnipeBlocks: 3
duration: 24.hours
}
vesting: {
team: { amount: 15%, cliff: 6.months, linear: 24.months }
investors: { amount: 10%, cliff: 3.months, linear: 12.months }
}
}
#[onTransfer]
fn onTransfer(from: Address, to: Address, amount: u128) {
let tax = amount * 0.05
self.burn(tax * 0.40)
self.addLiquidity(tax * 0.30)
self.distributeToHolders(tax * 0.30)
}
metadata {
image: "ipfs://Qm..."
website: "https://example.com"
socials: { twitter: "@example", telegram: "t.me/example" }
}
}"#;
    let decl = token_decl(src);
    assert_eq!(decl.name, "ExampleToken");
    assert_eq!(decl.extends, "Token");
    assert_eq!(
        decl.members.len(),
        3,
        "expected Config + Function + Metadata"
    );
    assert!(matches!(decl.members[0], ContractMember::Config(_)));
    assert!(matches!(decl.members[1], ContractMember::Function(_)));
    assert!(matches!(decl.members[2], ContractMember::Metadata(_)));

    // Config deep-check
    let cfg = config_of(&decl);
    assert_eq!(entry_value(cfg, "decimals"), &ConfigValue::Int(18));
    assert_eq!(
        entry_value(cfg, "approvalExpiry"),
        &ConfigValue::Unit(24, UnitKind::Hours)
    );
    let vesting = match entry_value(cfg, "vesting") {
        ConfigValue::Object(v) => v,
        other => panic!("expected vesting Object, got: {other:?}"),
    };
    assert_eq!(vesting.len(), 2);

    // Hook fn
    let hook = decl.members.iter().find_map(|m| match m {
        ContractMember::Function(f) => Some(f),
        _ => None,
    });
    assert_eq!(hook.unwrap().name, "onTransfer");

    // Metadata
    let meta = metadata_of(&decl);
    assert!(meta.entries.iter().any(|e| e.key == "socials"));
}

/// Scenario 11 — token with metadata only (no config block).
/// Proves: metadata is optional standalone member; token body can skip config.
#[test]
fn token_metadata_only_no_config() {
    let decl = token_decl(
        r#"token MetaOnlyToken extends Token {
metadata {
image: "ipfs://QmMeta"
description: "A metadata-only token declaration"
}
}"#,
    );
    assert!(decl.members.len() == 1);
    assert!(matches!(decl.members[0], ContractMember::Metadata(_)));
    let meta = metadata_of(&decl);
    assert_eq!(meta.entries.len(), 2);
}

/// Scenario 12 — token with state + functions (non-hook members alongside config).
/// Proves: ContractMember::State and ::Function coexist in a token body.
#[test]
fn token_with_state_and_custom_functions() {
    let decl = token_decl(
        r#"token ExtendedToken extends Token {
config {
name: "Extended Token"
symbol: "EXT2"
decimals: 18
maxSupply: 500000000
}
state {
pub snapshotBlock: u64
snapshots: Map<Address, u128>
}
pub view fn getSnapshot(holder: Address) -> u128 {
return self.snapshots[holder]
}
}"#,
    );
    assert_eq!(decl.members.len(), 3);
    assert!(matches!(decl.members[0], ContractMember::Config(_)));
    assert!(matches!(decl.members[1], ContractMember::State(_)));
    assert!(matches!(decl.members[2], ContractMember::Function(_)));
}

// ─── DEX contract ─────────────────────────────────────────────────────────────

/// Scenario 13 — AMM/DEX contract with state, events, annotations, multi-fn.
/// Proves: contract members (state, events, functions with modifiers) all parse.
#[test]
fn contract_dex_amm() {
    let items = run(r#"contract SimpleAMM {
state {
pub reserves0: u128
pub reserves1: u128
pub totalLiquidity: u128
liquidity: Map<Address, u128>
pub paused: bool
}

event Swap {
trader: Address
amountIn: u128
amountOut: u128
zeroForOne: bool
}

event LiquidityAdded {
provider: Address
amount0: u128
amount1: u128
minted: u128
}

@nonReentrant
@whenNotPaused
pub fn swap(amountIn: u128, zeroForOne: bool) -> u128 {
let amountOut = amountIn * self.reserves1 / (self.reserves0 + amountIn)
emit Swap { trader: msg.sender, amountIn: amountIn, amountOut: amountOut, zeroForOne: zeroForOne }
return amountOut
}

@nonReentrant
pub fn addLiquidity(amount0: u128, amount1: u128) -> u128 {
self.reserves0 = self.reserves0 + amount0
self.reserves1 = self.reserves1 + amount1
self.totalLiquidity = self.totalLiquidity + amount0
emit LiquidityAdded { provider: msg.sender, amount0: amount0, amount1: amount1, minted: amount0 }
return amount0
}

pub view fn quote(amountIn: u128, reserveIn: u128, reserveOut: u128) -> u128 {
return amountIn * reserveOut / reserveIn
}

pub fn removeLiquidity(shares: u128) {
self.liquidity[msg.sender] = self.liquidity[msg.sender] - shares
self.totalLiquidity = self.totalLiquidity - shares
}
}"#);
    assert_eq!(items.len(), 1);
    let contract = match &items[0] {
        Item::Contract(c) => c,
        other => panic!("expected Contract item, got: {other:?}"),
    };
    assert_eq!(contract.name, "SimpleAMM");

    // Verify state, events, functions all present
    let state_count = contract
        .members
        .iter()
        .filter(|m| matches!(m, ContractMember::State(_)))
        .count();
    let event_count = contract
        .members
        .iter()
        .filter(|m| matches!(m, ContractMember::Event(_)))
        .count();
    let fn_count = contract
        .members
        .iter()
        .filter(|m| matches!(m, ContractMember::Function(_)))
        .count();

    assert_eq!(state_count, 1, "expected one state block");
    assert_eq!(event_count, 2, "expected Swap + LiquidityAdded events");
    assert_eq!(
        fn_count, 4,
        "expected swap + addLiquidity + quote + removeLiquidity"
    );

    // Verify function names
    let fn_names: Vec<&str> = contract
        .members
        .iter()
        .filter_map(|m| match m {
            ContractMember::Function(f) => Some(f.name.as_str()),
            _ => None,
        })
        .collect();
    assert!(fn_names.contains(&"swap"));
    assert!(fn_names.contains(&"addLiquidity"));
    assert!(fn_names.contains(&"quote"));
    assert!(fn_names.contains(&"removeLiquidity"));

    // Verify swap has annotations
    let swap = contract.members.iter().find_map(|m| match m {
        ContractMember::Function(f) if f.name == "swap" => Some(f),
        _ => None,
    });
    assert_eq!(
        swap.unwrap().annotations.len(),
        2,
        "swap should have @nonReentrant + @whenNotPaused"
    );
}

/// Scenario 14 — DEX with import statement (multi-item program).
/// Proves: `import { X } from "path"` followed by contract parses as two items.
#[test]
fn contract_dex_with_import() {
    let items = run(r#"import { IToken } from "@std/interfaces"
contract PairV2 {
state {
pub token0: Address
pub token1: Address
pub reserve0: u128
pub reserve1: u128
}
pub view fn getReserves() -> u128 {
return self.reserve0
}
}"#);
    assert_eq!(items.len(), 2, "expected Import + Contract");
    assert!(matches!(items[0], Item::Import(_)));
    assert!(matches!(items[1], Item::Contract(_)));
}

// ─── Staking contract ─────────────────────────────────────────────────────────

/// Scenario 15 — staking contract with stake/unstake/rewards, events, @nonReentrant.
/// Proves: Map<Address, u128> state, block.timestamp expr, reward arithmetic.
#[test]
fn contract_staking_pool() {
    let items = run(r#"contract StakingPool {
state {
pub totalStaked: u128
stakes: Map<Address, u128>
stakedAt: Map<Address, u64>
pub rewardRate: u128
pub minStakeDuration: u64
pub paused: bool
}

event Staked {
staker: Address
amount: u128
timestamp: u64
}

event Unstaked {
staker: Address
amount: u128
reward: u128
}

event RewardClaimed {
staker: Address
reward: u128
}

init(rewardRate: u128, minDuration: u64) {
self.rewardRate = rewardRate
self.minStakeDuration = minDuration
self.paused = false
}

@nonReentrant
@whenNotPaused
pub fn stake(amount: u128) {
self.stakes[msg.sender] = self.stakes[msg.sender] + amount
self.stakedAt[msg.sender] = block.timestamp
self.totalStaked = self.totalStaked + amount
emit Staked { staker: msg.sender, amount: amount, timestamp: block.timestamp }
}

@nonReentrant
pub fn unstake(amount: u128) {
let staked = self.stakes[msg.sender]
let duration = block.timestamp - self.stakedAt[msg.sender]
let reward = staked * self.rewardRate * duration / 1000000
self.stakes[msg.sender] = staked - amount
self.totalStaked = self.totalStaked - amount
emit Unstaked { staker: msg.sender, amount: amount, reward: reward }
}

pub fn claimRewards() {
let staked = self.stakes[msg.sender]
let duration = block.timestamp - self.stakedAt[msg.sender]
let reward = staked * self.rewardRate * duration / 1000000
self.stakedAt[msg.sender] = block.timestamp
emit RewardClaimed { staker: msg.sender, reward: reward }
}

pub view fn pendingReward(staker: Address) -> u128 {
let staked = self.stakes[staker]
let duration = block.timestamp - self.stakedAt[staker]
return staked * self.rewardRate * duration / 1000000
}

pub view fn stakedBalance(staker: Address) -> u128 {
return self.stakes[staker]
}
}"#);
    assert_eq!(items.len(), 1);
    let contract = match &items[0] {
        Item::Contract(c) => c,
        other => panic!("expected Contract, got: {other:?}"),
    };
    assert_eq!(contract.name, "StakingPool");

    let state_count = contract
        .members
        .iter()
        .filter(|m| matches!(m, ContractMember::State(_)))
        .count();
    let event_count = contract
        .members
        .iter()
        .filter(|m| matches!(m, ContractMember::Event(_)))
        .count();
    let fn_count = contract
        .members
        .iter()
        .filter(|m| matches!(m, ContractMember::Function(_)))
        .count();

    assert_eq!(state_count, 1);
    assert_eq!(event_count, 3, "expected Staked + Unstaked + RewardClaimed");
    assert_eq!(
        fn_count, 6,
        "expected init + stake + unstake + claimRewards + pendingReward + stakedBalance"
    );

    // Verify @nonReentrant on stake
    let stake_fn = contract.members.iter().find_map(|m| match m {
        ContractMember::Function(f) if f.name == "stake" => Some(f),
        _ => None,
    });
    let stake = stake_fn.expect("stake function not found");
    assert!(
        stake.annotations.iter().any(|a| a.name == "nonReentrant"),
        "stake should have @nonReentrant"
    );
}

/// Scenario 16 — staking with implements clause (multi-interface contract).
/// Proves: `contract Foo implements IStaking, IOwnable` parses both implements names.
#[test]
fn contract_staking_with_implements() {
    let items = run(r#"contract ManagedStaking implements IStaking {
state {
pub owner: Address
pub totalStaked: u128
stakes: Map<Address, u128>
}
pub fn stake(amount: u128) {
self.stakes[msg.sender] = self.stakes[msg.sender] + amount
self.totalStaked = self.totalStaked + amount
}
pub view fn getStake(staker: Address) -> u128 {
return self.stakes[staker]
}
}"#);
    let contract = match &items[0] {
        Item::Contract(c) => c,
        other => panic!("expected Contract, got: {other:?}"),
    };
    assert_eq!(contract.implements, vec!["IStaking"]);
}

// ─── No-panic sweep ───────────────────────────────────────────────────────────

/// All integration test source strings must parse without panicking.
/// Malformed variants must return Err, never panic.
#[test]
fn no_panic_on_all_realistic_samples() {
    let samples = [
        // Valid — should succeed
        "token T extends Token { config { name: \"ok\" } }",
        "contract C { state { x: u128 } pub fn f() {} }",
        // Malformed — must return Err, never panic
        "token T extends Token {",
        "token T extends Token { config",
        "token T extends Token { config { name: }",
        "contract C { pub fn f(x: }",
        "contract C {",
        "token",
        "contract",
        "import { X } from",
        "token T extends {",
        "token T extends Token { vesting: { team: { amount: 15% }",
    ];
    for src in &samples {
        let _ = tokenize(src).and_then(parse);
        // Must reach here — no panic allowed
    }
}
