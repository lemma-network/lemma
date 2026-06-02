//! Error types for `lemma-mempool`.
//!
//! Every failure path returns a typed `MempoolError` variant — no `unwrap()`,
//! no `panic!()`, no error-swallowing (AGENTS.md §12). The error hierarchy
//! mirrors the crate's modules so a caller can match on the specific subsystem.
//!
//! # Design
//!
//! - **`#[non_exhaustive]`** on the top-level enum: adding a variant is not a
//!   breaking change for downstream crates.
//! - **Structured fields** on variants where the context is diagnostic: callers
//!   see *what* was wrong, not just *that* something was wrong.
//! - **Predicate helpers** group related variants so callers can make policy
//!   decisions without matching every arm (e.g. "is this a caller error or an
//!   internal fault?").

use lemma_core::{address::Address, hash::Hash};

// ── Top-level error ───────────────────────────────────────────────────────────

/// Errors produced by the `lemma-mempool` crate.
///
/// Variants cover ingress validation failures, pool capacity/replacement
/// policy, rate limiting, and circuit-breaker admission rejections.
///
/// # Variant naming
///
/// Follows the canonical verb list in `AGENTS.md §2.3`:
/// - `Invalid*` — caller supplied bad data.
/// - `Rejected*` — policy rejected an otherwise valid submission.
/// - `*NotFound` — a requested item does not exist in the pool.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MempoolError {
    // ── Signature / auth ─────────────────────────────────────────────────────
    /// Transaction signature failed hybrid Ed25519 + ML-DSA verification.
    ///
    /// The transaction was either unsigned, classically-only signed, or the
    /// signature did not match the transaction body.
    #[error("invalid transaction signature for tx {tx_hash}")]
    InvalidSignature { tx_hash: Hash },

    // ── Nonce ────────────────────────────────────────────────────────────────
    /// Transaction nonce is lower than the account's current nonce.
    ///
    /// A replayed or stale transaction that has already been executed.
    #[error("stale nonce for {sender}: tx nonce {tx_nonce} < account nonce {account_nonce}")]
    NonceTooLow {
        sender: Address,
        tx_nonce: u64,
        account_nonce: u64,
    },

    /// Transaction nonce is too far ahead of the account's current nonce.
    ///
    /// The mempool enforces a maximum nonce gap (`MAX_NONCE_GAP`) to prevent
    /// unbounded future-nonce queuing that would stall the sender's current
    /// transactions.
    #[error("nonce gap too large for {sender}: tx nonce {tx_nonce}, account nonce {account_nonce}, max gap {max_gap}")]
    NonceGapTooLarge {
        sender: Address,
        tx_nonce: u64,
        account_nonce: u64,
        max_gap: u64,
    },

    // ── Balance / gas ─────────────────────────────────────────────────────────
    /// Account does not have enough liquid balance to cover `gas_limit ×
    /// gas_price + value`.
    ///
    /// `required` and `available` are both in Drop (1 LEM = 10¹⁸ Drop).
    #[error(
        "insufficient balance for {sender}: required {required} Drop, available {available} Drop"
    )]
    InsufficientBalance {
        sender: Address,
        /// Total cost of the transaction in Drop: `gas_limit × gas_price + value`.
        required: u128,
        /// Liquid LEM balance of the sender at validation time, in Drop.
        available: u128,
    },

    /// `gas_limit` is zero — no transaction can execute in zero gas.
    #[error("gas_limit must be > 0 for tx {tx_hash}")]
    ZeroGasLimit { tx_hash: Hash },

    /// The effective `gas_price` is below the current base fee.
    ///
    /// The transaction would be unable to pay its base fee and cannot be
    /// included in a block under current network conditions.
    #[error(
        "gas_price too low for tx {tx_hash}: provided {provided} Drop/gas, base fee {base_fee} Drop/gas"
    )]
    GasPriceTooLow {
        tx_hash: Hash,
        /// Gas price offered by the sender, in Drop per gas unit.
        provided: u128,
        /// Current global base fee, in Drop per gas unit.
        base_fee: u128,
    },

    // ── Chain ID ─────────────────────────────────────────────────────────────
    /// Transaction `chain_id` does not match this node's chain.
    ///
    /// Replay-protection guard: a transaction signed for testnet is rejected
    /// on mainnet and vice-versa.
    #[error(
        "chain_id mismatch for tx {tx_hash}: tx has {tx_chain_id}, expected {expected_chain_id}"
    )]
    ChainIdMismatch {
        tx_hash: Hash,
        tx_chain_id: u64,
        expected_chain_id: u64,
    },

    // ── Size ─────────────────────────────────────────────────────────────────
    /// Serialized transaction exceeds the maximum allowed size.
    #[error("transaction {tx_hash} too large: {size} bytes, max {max_size} bytes")]
    TransactionTooLarge {
        tx_hash: Hash,
        size: usize,
        max_size: usize,
    },

    // ── Pool capacity / replacement ───────────────────────────────────────────
    /// The pool has reached its capacity limit and the incoming transaction
    /// does not have a high enough priority to evict the lowest-priority entry.
    #[error("mempool is full ({capacity} txs); tx {tx_hash} priority too low to evict")]
    PoolFull { tx_hash: Hash, capacity: usize },

    /// A replacement transaction for `(sender, nonce)` was rejected because
    /// its `gas_price` did not exceed the existing transaction's price by the
    /// minimum replacement bump (`MIN_REPLACE_BUMP_BPS` basis points).
    #[error(
        "replacement rejected for ({sender}, nonce {nonce}): \
         new gas_price {new_price} Drop/gas must exceed old {old_price} Drop/gas \
         by at least {min_bump_bps} bps"
    )]
    ReplacementUnderpriced {
        sender: Address,
        nonce: u64,
        old_price: u128,
        new_price: u128,
        min_bump_bps: u32,
    },

    // ── Rate limiting ─────────────────────────────────────────────────────────
    /// Sender has exceeded the per-account submission rate limit.
    ///
    /// The token bucket for this sender is empty. The caller should back off
    /// and retry after `retry_after_ms` milliseconds.
    #[error("rate limit exceeded for {sender}; retry after {retry_after_ms} ms")]
    RateLimited {
        sender: Address,
        /// Approximate milliseconds until the token bucket refills enough for
        /// one submission.
        retry_after_ms: u64,
    },

    // ── Circuit breaker ───────────────────────────────────────────────────────
    /// The circuit breaker rejected the transaction type for the current load
    /// tier.
    ///
    /// Under high load, only essential transaction types are admitted (see
    /// `circuit_breaker::NetworkTier`).
    #[error("tx {tx_hash} rejected by circuit breaker: {reason}")]
    CircuitBreakerRejected {
        tx_hash: Hash,
        /// Human-readable rejection reason (e.g. "Busy tier: only transfers and
        /// staking allowed").
        reason: &'static str,
    },

    // ── Not found ─────────────────────────────────────────────────────────────
    /// The requested transaction does not exist in the pending pool.
    #[error("transaction {tx_hash} not found in mempool")]
    TransactionNotFound { tx_hash: Hash },

    // ── State access ─────────────────────────────────────────────────────────
    /// Failed to retrieve account state from the world state during validation.
    ///
    /// This is an internal/storage error, not a caller error.
    #[error("state lookup failed for {address}: {source}")]
    StateLookupFailed {
        address: Address,
        #[source]
        source: lemma_storage::StorageError,
    },

    // ── Crypto ───────────────────────────────────────────────────────────────
    /// Signature verification returned a crypto-layer error (e.g. malformed
    /// key material, unexpected signature format).
    ///
    /// Distinguished from `InvalidSignature` which means the signature is
    /// structurally valid but does not verify against the transaction body.
    #[error("crypto error during tx validation for {tx_hash}: {source}")]
    CryptoError {
        tx_hash: Hash,
        #[source]
        source: lemma_crypto::CryptoError,
    },
}

// ── Predicate helpers ─────────────────────────────────────────────────────────

impl MempoolError {
    /// Returns `true` for errors that represent a **caller mistake** — the
    /// transaction itself is invalid and should not be retried as-is.
    ///
    /// Used by the RPC layer to return a 4xx-equivalent response rather than
    /// triggering an internal alert.
    ///
    /// Includes `ReplacementUnderpriced` — an underpriced replacement is a
    /// permanent caller mistake (same category as `GasPriceTooLow`): the
    /// caller must increase the gas price by at least `MIN_REPLACE_BUMP_BPS`
    /// basis points; no amount of waiting will change the outcome.
    #[must_use]
    pub fn is_invalid_tx(&self) -> bool {
        matches!(
            self,
            Self::InvalidSignature { .. }
                | Self::NonceTooLow { .. }
                | Self::NonceGapTooLarge { .. }
                | Self::InsufficientBalance { .. }
                | Self::ZeroGasLimit { .. }
                | Self::GasPriceTooLow { .. }
                | Self::ChainIdMismatch { .. }
                | Self::TransactionTooLarge { .. }
                | Self::ReplacementUnderpriced { .. }
        )
    }

    /// Returns `true` for errors where the caller **may succeed by retrying**
    /// (pool full, rate limited, circuit breaker — transient conditions).
    #[must_use]
    pub fn is_retriable(&self) -> bool {
        matches!(
            self,
            Self::PoolFull { .. } | Self::RateLimited { .. } | Self::CircuitBreakerRejected { .. }
        )
    }

    /// Returns `true` for errors caused by an **internal/storage fault**,
    /// not a property of the transaction itself.
    #[must_use]
    pub fn is_internal(&self) -> bool {
        matches!(
            self,
            Self::StateLookupFailed { .. } | Self::CryptoError { .. }
        )
    }
}

#[cfg(test)]
mod tests;
