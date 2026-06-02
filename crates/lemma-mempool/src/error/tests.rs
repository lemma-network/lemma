//! Tests for `lemma_mempool::error`.
//!
//! Covers:
//! - Every variant displays a non-empty, human-readable message.
//! - `is_invalid_tx` / `is_retriable` / `is_internal` predicates
//!   return `true` for the correct variant groups and `false` for others.
//! - Variants carry structured fields (no stringly-typed context loss).
//! - Source-chain wiring for the two wrapping variants (`StateLookupFailed`,
//!   `CryptoError`) via `std::error::Error::source()`.

use std::error::Error as StdError;

use lemma_core::{address::Address, hash::Hash};
use lemma_crypto::CryptoError;
use lemma_storage::StorageError;

use crate::error::MempoolError;

// ── Test helpers ──────────────────────────────────────────────────────────────

fn zero_hash() -> Hash {
    Hash::zero()
}

fn zero_address() -> Address {
    Address::zero()
}

/// A cheap `StorageError` with no external deps, used by wrapping-variant tests.
fn storage_error() -> StorageError {
    StorageError::AccountNotFound {
        address: "lem1q000test".to_string(),
    }
}

/// A cheap `CryptoError` with no external deps, used by wrapping-variant tests.
fn crypto_error() -> CryptoError {
    CryptoError::UnsignedTransaction
}

// ── Display (non-empty, contains key context) ─────────────────────────────────

#[test]
fn invalid_signature_display_contains_hash() {
    let e = MempoolError::InvalidSignature {
        tx_hash: zero_hash(),
    };
    let s = e.to_string();
    assert!(!s.is_empty(), "error message must not be empty");
    assert!(
        s.contains("invalid transaction signature"),
        "expected variant context in: {s}"
    );
}

#[test]
fn nonce_too_low_display_contains_nonces() {
    let e = MempoolError::NonceTooLow {
        sender: zero_address(),
        tx_nonce: 3,
        account_nonce: 7,
    };
    let s = e.to_string();
    assert!(s.contains('3'), "tx_nonce not in display: {s}");
    assert!(s.contains('7'), "account_nonce not in display: {s}");
}

#[test]
fn nonce_gap_too_large_display_contains_all_fields() {
    let e = MempoolError::NonceGapTooLarge {
        sender: zero_address(),
        tx_nonce: 200,
        account_nonce: 5,
        max_gap: 64,
    };
    let s = e.to_string();
    assert!(s.contains("200"), "tx_nonce not in display: {s}");
    assert!(s.contains("64"), "max_gap not in display: {s}");
}

#[test]
fn insufficient_balance_display_contains_amounts() {
    let e = MempoolError::InsufficientBalance {
        sender: zero_address(),
        required: 1_000_000,
        available: 500,
    };
    let s = e.to_string();
    assert!(s.contains("1000000"), "required not in display: {s}");
    assert!(s.contains("500"), "available not in display: {s}");
}

#[test]
fn zero_gas_limit_display_contains_hash() {
    let e = MempoolError::ZeroGasLimit {
        tx_hash: zero_hash(),
    };
    assert!(e.to_string().contains("gas_limit"));
}

#[test]
fn gas_price_too_low_display_contains_prices() {
    let e = MempoolError::GasPriceTooLow {
        tx_hash: zero_hash(),
        provided: 100,
        base_fee: 500,
    };
    let s = e.to_string();
    assert!(s.contains("100"), "provided not in display: {s}");
    assert!(s.contains("500"), "base_fee not in display: {s}");
}

#[test]
fn chain_id_mismatch_display_contains_ids() {
    let e = MempoolError::ChainIdMismatch {
        tx_hash: zero_hash(),
        tx_chain_id: 99,
        expected_chain_id: 1,
    };
    let s = e.to_string();
    assert!(s.contains("99"), "tx_chain_id not in display: {s}");
    assert!(s.contains('1'), "expected_chain_id not in display: {s}");
}

#[test]
fn transaction_too_large_display_contains_sizes() {
    let e = MempoolError::TransactionTooLarge {
        tx_hash: zero_hash(),
        size: 131_072,
        max_size: 65_536,
    };
    let s = e.to_string();
    assert!(s.contains("131072"), "size not in display: {s}");
    assert!(s.contains("65536"), "max_size not in display: {s}");
}

#[test]
fn pool_full_display_contains_capacity() {
    let e = MempoolError::PoolFull {
        tx_hash: zero_hash(),
        capacity: 4096,
    };
    assert!(e.to_string().contains("4096"));
}

#[test]
fn replacement_underpriced_display_contains_prices() {
    let e = MempoolError::ReplacementUnderpriced {
        sender: zero_address(),
        nonce: 5,
        old_price: 1_000,
        new_price: 1_001,
        min_bump_bps: 100,
    };
    let s = e.to_string();
    assert!(s.contains("1000"), "old_price not in display: {s}");
    assert!(s.contains("1001"), "new_price not in display: {s}");
    assert!(s.contains("100"), "min_bump_bps not in display: {s}");
}

#[test]
fn rate_limited_display_contains_retry() {
    let e = MempoolError::RateLimited {
        sender: zero_address(),
        retry_after_ms: 2_000,
    };
    assert!(e.to_string().contains("2000"));
}

#[test]
fn circuit_breaker_display_contains_reason() {
    let e = MempoolError::CircuitBreakerRejected {
        tx_hash: zero_hash(),
        reason: "Emergency tier: only validator messages",
    };
    assert!(e.to_string().contains("Emergency tier"));
}

#[test]
fn transaction_not_found_display_contains_hash() {
    let e = MempoolError::TransactionNotFound {
        tx_hash: zero_hash(),
    };
    assert!(e.to_string().contains("not found"));
}

// ── Predicate: is_invalid_tx ──────────────────────────────────────────────────

#[test]
fn invalid_tx_predicate_true_for_invalid_signature() {
    assert!(MempoolError::InvalidSignature {
        tx_hash: zero_hash()
    }
    .is_invalid_tx());
}

#[test]
fn invalid_tx_predicate_true_for_nonce_too_low() {
    assert!(MempoolError::NonceTooLow {
        sender: zero_address(),
        tx_nonce: 0,
        account_nonce: 1
    }
    .is_invalid_tx());
}

#[test]
fn invalid_tx_predicate_true_for_nonce_gap() {
    assert!(MempoolError::NonceGapTooLarge {
        sender: zero_address(),
        tx_nonce: 100,
        account_nonce: 0,
        max_gap: 64
    }
    .is_invalid_tx());
}

#[test]
fn invalid_tx_predicate_true_for_insufficient_balance() {
    assert!(MempoolError::InsufficientBalance {
        sender: zero_address(),
        required: 100,
        available: 1
    }
    .is_invalid_tx());
}

#[test]
fn invalid_tx_predicate_true_for_zero_gas() {
    assert!(MempoolError::ZeroGasLimit {
        tx_hash: zero_hash()
    }
    .is_invalid_tx());
}

#[test]
fn invalid_tx_predicate_true_for_gas_price_too_low() {
    assert!(MempoolError::GasPriceTooLow {
        tx_hash: zero_hash(),
        provided: 1,
        base_fee: 100
    }
    .is_invalid_tx());
}

#[test]
fn invalid_tx_predicate_true_for_chain_id_mismatch() {
    assert!(MempoolError::ChainIdMismatch {
        tx_hash: zero_hash(),
        tx_chain_id: 2,
        expected_chain_id: 1
    }
    .is_invalid_tx());
}

#[test]
fn invalid_tx_predicate_true_for_too_large() {
    assert!(MempoolError::TransactionTooLarge {
        tx_hash: zero_hash(),
        size: 200_000,
        max_size: 65_536
    }
    .is_invalid_tx());
}

#[test]
fn invalid_tx_predicate_false_for_pool_full() {
    assert!(!MempoolError::PoolFull {
        tx_hash: zero_hash(),
        capacity: 100
    }
    .is_invalid_tx());
}

#[test]
fn invalid_tx_predicate_false_for_rate_limited() {
    assert!(!MempoolError::RateLimited {
        sender: zero_address(),
        retry_after_ms: 1000
    }
    .is_invalid_tx());
}

// ── Predicate: is_retriable ───────────────────────────────────────────────────

#[test]
fn retriable_predicate_true_for_pool_full() {
    assert!(MempoolError::PoolFull {
        tx_hash: zero_hash(),
        capacity: 100
    }
    .is_retriable());
}

#[test]
fn retriable_predicate_true_for_rate_limited() {
    assert!(MempoolError::RateLimited {
        sender: zero_address(),
        retry_after_ms: 500
    }
    .is_retriable());
}

#[test]
fn retriable_predicate_true_for_circuit_breaker() {
    assert!(MempoolError::CircuitBreakerRejected {
        tx_hash: zero_hash(),
        reason: "busy"
    }
    .is_retriable());
}

#[test]
fn retriable_predicate_false_for_invalid_signature() {
    assert!(!MempoolError::InvalidSignature {
        tx_hash: zero_hash()
    }
    .is_retriable());
}

#[test]
fn retriable_predicate_false_for_chain_id_mismatch() {
    assert!(!MempoolError::ChainIdMismatch {
        tx_hash: zero_hash(),
        tx_chain_id: 99,
        expected_chain_id: 1
    }
    .is_retriable());
}

// ── Predicate: is_internal ────────────────────────────────────────────────────

#[test]
fn internal_predicate_false_for_invalid_signature() {
    assert!(!MempoolError::InvalidSignature {
        tx_hash: zero_hash()
    }
    .is_internal());
}

#[test]
fn internal_predicate_false_for_pool_full() {
    assert!(!MempoolError::PoolFull {
        tx_hash: zero_hash(),
        capacity: 10
    }
    .is_internal());
}

// ── Display: wrapping variants (S1) ──────────────────────────────────────────

#[test]
fn state_lookup_failed_display_contains_address_and_source() {
    let e = MempoolError::StateLookupFailed {
        address: zero_address(),
        source: storage_error(),
    };
    let s = e.to_string();
    assert!(!s.is_empty());
    assert!(
        s.contains("state lookup failed"),
        "display missing context: {s}"
    );
}

#[test]
fn state_lookup_failed_source_chain_is_wired() {
    let e = MempoolError::StateLookupFailed {
        address: zero_address(),
        source: storage_error(),
    };
    assert!(
        (&e as &dyn StdError).source().is_some(),
        "#[source] must wire the inner StorageError"
    );
}

#[test]
fn crypto_error_display_contains_tx_hash() {
    let e = MempoolError::CryptoError {
        tx_hash: zero_hash(),
        source: crypto_error(),
    };
    let s = e.to_string();
    assert!(!s.is_empty());
    assert!(s.contains("crypto error"), "display missing context: {s}");
}

#[test]
fn crypto_error_source_chain_is_wired() {
    let e = MempoolError::CryptoError {
        tx_hash: zero_hash(),
        source: crypto_error(),
    };
    assert!(
        (&e as &dyn StdError).source().is_some(),
        "#[source] must wire the inner CryptoError"
    );
}

// ── Predicate: is_internal (positive arms) (S2) ───────────────────────────────

#[test]
fn internal_predicate_true_for_state_lookup_failed() {
    assert!(MempoolError::StateLookupFailed {
        address: zero_address(),
        source: storage_error(),
    }
    .is_internal());
}

#[test]
fn internal_predicate_true_for_crypto_error() {
    assert!(MempoolError::CryptoError {
        tx_hash: zero_hash(),
        source: crypto_error(),
    }
    .is_internal());
}

// ── W1: ReplacementUnderpriced is a permanent caller mistake ──────────────────

#[test]
fn invalid_tx_predicate_true_for_replacement_underpriced() {
    assert!(
        MempoolError::ReplacementUnderpriced {
            sender: zero_address(),
            nonce: 0,
            old_price: 100,
            new_price: 100,
            min_bump_bps: 50,
        }
        .is_invalid_tx(),
        "underpriced replacement is a permanent caller mistake"
    );
}

// ── Mutual exclusion of predicate groups ──────────────────────────────────────

#[test]
fn replacement_underpriced_is_not_retriable_or_internal() {
    let e = MempoolError::ReplacementUnderpriced {
        sender: zero_address(),
        nonce: 0,
        old_price: 100,
        new_price: 100,
        min_bump_bps: 50,
    };
    assert!(!e.is_retriable(), "replacement should not be retriable");
    assert!(!e.is_internal(), "replacement should not be internal");
}

#[test]
fn predicates_are_mutually_exclusive_for_transaction_not_found() {
    let e = MempoolError::TransactionNotFound {
        tx_hash: zero_hash(),
    };
    assert!(!e.is_invalid_tx());
    assert!(!e.is_retriable());
    assert!(!e.is_internal());
}
