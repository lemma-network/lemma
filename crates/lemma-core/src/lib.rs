//! # lemma-core
//!
//! Foundational types for the Lemma blockchain.
//!
//! This crate is the **single source of truth** for all shared domain types.
//! Every other crate in the workspace imports from here — never duplicate types.
//!
//! ## Modules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`address`] | [`Address`], [`AddressType`] — 20-byte Bech32m identifiers |
//! | [`amount`] | [`Amount`] — token quantity in Drop (1 LEM = 10¹⁸ Drop) |
//! | [`cert`]   | [`QuorumCert`] — 2f+1 finality certificate (shared by consensus + network) |
//! | [`block`] | [`Block`] — finalized block (header + transactions + receipts) |
//! | [`error`] | Typed error enums for every domain |
//! | [`genesis`] | [`GenesisConfig`] — chain bootstrap configuration |
//! | [`hash`] | [`Hash`] — 32-byte Blake3 hash newtype |
//! | [`header`] | [`BlockHeader`] — block metadata commitment |
//! | [`limits`] | Protocol hard limits — [`MAX_CONTRACT_WASM_SIZE`] etc. |
//! | [`signature`] | [`Signature`] — Classical / PostQuantum / Hybrid wrapper |
//! | [`transaction`] | [`Transaction`], [`TxType`], [`TransactionReceipt`], [`Log`] |
//! | [`validator`] | [`Validator`], [`ValidatorStatus`], [`ConsensusKey`], [`Stake`], [`VotingPower`] |
//! | [`validator_set`] | [`ValidatorSet`], [`Member`] — epoch committee |
//! | [`epoch`] | [`Epoch`] — validator-set era |
//! | [`feature_gate`] | [`FeatureId`], [`FEATURE_HOST_ABI_V2`] — epoch-boundary upgrade activation (P3·Step 20) |
//!
//! ## Build order
//!
//! See `docs/04-BUILD_GUIDE.md` Section 2.1.

// ── Modules ──────────────────────────────────────────────────────────────────

pub mod address;
pub mod agent;
pub mod amount;
pub mod block;
pub mod cert;
pub mod epoch;
pub mod error;
/// Feature-gate types for epoch-boundary upgrade activation (P3·Step 20, DB-A63).
pub mod feature_gate;
pub mod genesis;
pub mod hash;
pub mod header;
pub mod limits;
pub mod signature;
pub mod transaction;
pub mod validator;
pub mod validator_set;

// ── Crate-root re-exports ────────────────────────────────────────────────────
// Allows `use lemma_core::Address` instead of `use lemma_core::address::Address`.
// Re-exports are ordered: primitives → errors → blockchain types (alpha within group).

pub use address::{Address, AddressType, HRP_DEVNET, HRP_MAINNET, HRP_TESTNET};
pub use agent::{
    Action, ActionMask, AgentPolicy, AllowList, AutoRevoke, CategoryBudget, CategoryCaps,
    EpochRange, KyaTier, PolicyViolation, WardenOutcome, MAX_CATEGORIES,
};
pub use amount::{Amount, DRIPS_PER_LEM, DROPS_PER_DRIP, DROPS_PER_LEM};
pub use feature_gate::{FeatureId, FEATURE_HOST_ABI_V2};
pub use hash::Hash;
pub use limits::MAX_CONTRACT_WASM_SIZE;
pub use signature::Signature;

// ── Host-ABI versioning anchor (S3-1, 17-VERSIONING_SPEC §3) ────────────────

/// Current host-ABI version for the Lemma protocol.
///
/// **Single source of truth** for the host-function ABI version. Both the
/// compiler emitter (`lemma-lang` `HOST_ABI_VERSION`) and the VM ceiling
/// (`lemma-vm` `MAX_SUPPORTED_HOST_ABI`) reference this constant, ensuring
/// they cannot drift apart (S3-1 audit fix).
///
/// Versioning scheme: monotonic u32 integer.
/// - `1` = initial 17-fn set (P3·Step 6b-vm-2).
/// - Future bumps require epoch feature-gate activation (P4·Step 12).
///
/// See `docs/17-VERSIONING_SPEC.md §3`.
pub const CURRENT_HOST_ABI_VERSION: u32 = 1;

pub use error::{
    AddressError, AmountError, BlockError, CoreError, HashError, SerializationError,
    TransactionError, ValidatorError,
};

pub use block::Block;
pub use cert::QuorumCert;
pub use epoch::Epoch;
pub use genesis::GenesisConfig;
pub use header::BlockHeader;
pub use transaction::{Log, Transaction, TransactionReceipt, TxType};
pub use validator::{ConsensusKey, Stake, UnbondingEntry, Validator, ValidatorStatus, VotingPower};
pub use validator_set::{Member, ValidatorSet};
