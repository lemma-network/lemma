//! Error types for `lemma-core`.
//!
//! Each domain has its own typed error enum (thiserror). [`CoreError`] is the
//! top-level wrapper used when a single error type is needed across modules.
//!
//! ## Usage
//!
//! Prefer domain-specific errors in internal code:
//! ```ignore
//! use lemma_core::error::AddressError;
//! fn parse(raw: &[u8]) -> Result<(), AddressError> { /* ... */ Ok(()) }
//! ```
//!
//! Use [`CoreError`] only at trait boundaries requiring a single error type:
//! ```ignore
//! use lemma_core::error::CoreError;
//! // impl SomeTrait for MyType { type Error = CoreError; }
//! ```

use thiserror::Error;

use crate::address::Address;

// ─── Address ─────────────────────────────────────────────────────────────────

/// Errors that can occur when parsing or encoding a Lemma [`Address`](crate::Address).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AddressError {
    /// Raw byte slice had the wrong length (must be 20 bytes).
    #[error("invalid address length: expected 20 bytes, got {got}")]
    InvalidLength { got: usize },

    /// The Bech32m string failed to decode (bad checksum, invalid chars, etc.).
    #[error("invalid Bech32m encoding: {reason}")]
    InvalidBech32 { reason: String },

    /// The human-readable part did not match an expected network prefix.
    ///
    /// Expected one of: `"lem"` (mainnet), `"tlem"` (testnet), `"dlem"` (devnet).
    #[error("invalid HRP: expected one of [lem, tlem, dlem], got \"{got}\"")]
    InvalidHrp { got: String },

    /// The leading type byte in the decoded data was not a known [`AddressType`](crate::AddressType).
    ///
    /// Known values: `0x00` (Regular), `0xC0` (Contract), `0x10` (Shielded), `0x6E` (Burn).
    #[error("unknown address type byte: 0x{byte:02x}")]
    UnknownAddressType { byte: u8 },

    /// The decoded data payload had the wrong length (type byte + 20 address bytes = 21).
    #[error("invalid decoded payload length: expected 21 bytes, got {got}")]
    InvalidPayloadLength { got: usize },
}

// ─── Hash ─────────────────────────────────────────────────────────────────────

/// Errors that can occur when parsing a Lemma [`Hash`](crate::Hash).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HashError {
    /// Input hex string had the wrong length (must decode to exactly 32 bytes).
    #[error("invalid hash length: expected 32 bytes, got {got}")]
    InvalidLength { got: usize },

    /// Input string contained non-hex characters.
    #[error("invalid hex encoding: {reason}")]
    InvalidHex { reason: String },
}

// ─── Amount ───────────────────────────────────────────────────────────────────

/// Errors that can occur during [`Amount`](crate::Amount) arithmetic.
///
/// All variants carry the operand(s) that triggered the failure so that callers
/// can log the exact values without re-running the computation.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AmountError {
    /// Addition or multiplication would overflow `u128`.
    #[error("amount overflow: operands {lhs} and {rhs}")]
    Overflow { lhs: u128, rhs: u128 },

    /// Subtraction would underflow (result would be negative).
    #[error("amount underflow: {lhs} - {rhs} would be negative")]
    Underflow { lhs: u128, rhs: u128 },

    /// Division by zero.
    #[error("amount division by zero: {lhs} / 0")]
    DivisionByZero { lhs: u128 },
}

// ─── Transaction ──────────────────────────────────────────────────────────────

/// Errors that can occur when constructing or validating a [`Transaction`](crate::Transaction).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TransactionError {
    /// A `ContractCall` or `Transfer` transaction had no `to` address.
    // TODO(lemmachain): replace tx_type: String with TxType once the circular-import path is
    // resolved (TransactionError → TxType → error). Track: issue #1.
    #[error("transaction of type {tx_type} requires a recipient address")]
    MissingRecipient { tx_type: String },

    /// A `ContractDeploy` transaction must not have a `to` address.
    #[error("contract deploy transaction must not have a recipient address")]
    UnexpectedRecipient,

    /// The transaction had no calldata but the type requires it.
    // TODO(lemmachain): replace tx_type: String with TxType — same circular-import issue as
    // MissingRecipient above. Track: issue #1.
    #[error("transaction of type {tx_type} requires calldata")]
    MissingCalldata { tx_type: String },

    /// Gas limit was zero, which is always invalid.
    #[error("gas limit must be greater than zero")]
    ZeroGasLimit,

    /// The stored hash does not match the recomputed hash of the transaction body.
    ///
    /// Stored as hex strings so this variant remains `Clone + PartialEq + Eq`
    /// until the `Hash` newtype is available.
    // TODO(lemmachain): upgrade stored/computed to Hash once hash.rs is wired. Track: issue #2.
    #[error("transaction hash mismatch: stored {stored}, computed {computed}")]
    HashMismatch { stored: String, computed: String },
}

// ─── Block ────────────────────────────────────────────────────────────────────

/// Errors that can occur when constructing or validating a [`Block`](crate::Block).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum BlockError {
    /// `gas_limit` was zero, which is always invalid.
    ///
    /// A zero `gas_limit` makes the block unable to include any transaction and
    /// causes division-by-zero in the Burn Fee Model target calculation.
    #[error("gas limit must be greater than zero")]
    GasLimitZero,

    /// The block height was invalid in context (e.g. not exactly parent + 1).
    #[error("invalid block height: expected {expected}, got {got}")]
    InvalidHeight { expected: u64, got: u64 },

    /// `gas_used` exceeded `gas_limit`.
    #[error("gas used ({used}) exceeds gas limit ({limit})")]
    GasExceeded { used: u64, limit: u64 },

    /// The receipt count did not match the transaction count.
    #[error("receipt count ({receipts}) does not match transaction count ({transactions})")]
    ReceiptCountMismatch {
        transactions: usize,
        receipts: usize,
    },

    /// `header.gas_used` does not equal the sum of all receipt `gas_used` values.
    ///
    /// A consistent block must have its header gas accounting match the actual
    /// per-transaction gas consumed. A mismatch indicates a tampered or
    /// incorrectly assembled block.
    #[error(
        "gas accounting mismatch: header claims {header_gas_used} gas used, \
         but receipts sum to {receipts_gas_used}"
    )]
    GasAccountingMismatch {
        header_gas_used: u64,
        receipts_gas_used: u64,
    },
}

// ─── Serialization ────────────────────────────────────────────────────────────

/// Errors that can occur during serialization or deserialization.
///
/// `serde_json::Error` is eagerly converted to its `Display` string so this
/// enum remains `Clone + PartialEq + Eq` — required for consistency across
/// all error types in this crate.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SerializationError {
    /// A JSON serialization or deserialization error.
    #[error("JSON serialization error: {reason}")]
    Json { reason: String },

    /// A binary codec (bincode) error.
    #[error("binary codec error: {reason}")]
    Binary { reason: String },
}

impl From<serde_json::Error> for SerializationError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json {
            reason: e.to_string(),
        }
    }
}

// ─── Validator ───────────────────────────────────────────────────────────────

/// Errors that can occur during validator or epoch operations.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ValidatorError {
    /// The genesis validator set is empty — epoch 0 cannot be bootstrapped.
    #[error("genesis validator set is empty: cannot bootstrap epoch 0")]
    EmptyGenesisValidators,

    /// A genesis validator has zero active stake.
    #[error("genesis validator {address} has zero active stake")]
    ZeroGenesisStake { address: String },

    /// Voting-power accumulation overflowed while building a `ValidatorSet`.
    ///
    /// Surfaced by [`ValidatorSet::from_active_validators`] when either
    /// `Validator::voting_power()` or the running `total_power` sum overflows
    /// `u128`. Practically unreachable given the LEM supply cap, but propagated
    /// as `Result` per AGENTS.md §7.4 (no silent overflow).
    #[error("voting-power overflow for validator {address}: {source}")]
    PowerOverflow {
        /// The validator whose power contribution caused the overflow.
        address: Address,
        /// Underlying arithmetic error.
        #[source]
        source: AmountError,
    },

    /// The active-validator set is empty for `epoch`.
    ///
    /// Returned by [`ValidatorSet::from_active_validators`] when no validator
    /// passes the `is_active()` filter. The caller must handle this — the
    /// chain cannot progress without a committee.
    #[error("epoch {epoch}: no active validators — committee would be empty")]
    EmptyValidatorSet { epoch: u64 },
}

// ─── Top-level ────────────────────────────────────────────────────────────────

/// Top-level error type for `lemma-core`.
///
/// Wraps all domain-specific errors so callers that need a single error type
/// (e.g. trait implementations) can use this instead of a generic.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreError {
    /// An error originating from [`AddressError`] operations.
    #[error("address error: {0}")]
    Address(#[from] AddressError),

    /// An error originating from [`HashError`] operations.
    #[error("hash error: {0}")]
    Hash(#[from] HashError),

    /// An error originating from [`AmountError`] arithmetic.
    #[error("amount error: {0}")]
    Amount(#[from] AmountError),

    /// An error originating from [`TransactionError`] validation.
    #[error("transaction error: {0}")]
    Transaction(#[from] TransactionError),

    /// An error originating from [`BlockError`] validation.
    #[error("block error: {0}")]
    Block(#[from] BlockError),

    /// An error originating from [`SerializationError`] codec operations.
    #[error("serialization error: {0}")]
    Serialization(#[from] SerializationError),

    /// An error originating from [`ValidatorError`] operations.
    #[error("validator error: {0}")]
    Validator(#[from] ValidatorError),
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
