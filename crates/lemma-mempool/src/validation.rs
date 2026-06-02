//! Transaction ingress validation for `lemma-mempool`.
//!
//! # Design
//!
//! [`validate_transaction`] is the single entry-point for all ingress checks.
//! It accepts an **explicit `sender_pubkey`** because Ed25519 and ML-DSA-65
//! signatures are not public-key-recoverable — the mempool cannot reconstruct
//! the pubkey from `(sender_address, signature)` alone. The caller (RPC or
//! P2P ingress handler) supplies the pubkey; validation verifies that the pubkey
//! derives to `tx.sender` as its very first check, rejecting attacker-supplied
//! mis-matched pubkeys before any expensive cryptography runs.
//!
//! # Validation order (cheap → expensive)
//!
//! 1. `gas_limit > 0` — trivially free
//! 2. `chain_id` match — one integer compare
//! 3. serialized size ≤ `MAX_TX_SIZE` — `bincode::serialized_size`, O(1)
//! 4. pubkey → address derivation matches `tx.sender` — one Blake3 hash
//! 5. hybrid signature verification — Ed25519 + ML-DSA-65 (most expensive)
//! 6. nonce ≥ account nonce (one RocksDB read, shared with step 7)
//! 7. nonce − account nonce ≤ `MAX_NONCE_GAP`
//! 8. balance ≥ `gas_limit × gas_price + value` (checked arithmetic)
//! 9. `gas_price ≥ base_fee`
//!
//! All arithmetic uses `checked_*` operations. Integer overflow in the cost
//! calculation is treated as an unaffordable transaction (AGENTS.md §7.4).
//!
//! # Determinism note (spec §1.1)
//!
//! Validation reads local world state (nonces, balances) which can differ
//! between nodes during normal operation. This is intentional — the mempool's
//! admission decision is **local policy only**, not consensus. Consensus (07)
//! owns the committed order and re-validates at execution time.

use lemma_core::{amount::Amount, transaction::Transaction};
use lemma_crypto::{verify_transaction, CryptoError, PublicKey};
use lemma_storage::WorldState;

use crate::error::MempoolError;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum serialized transaction size in bytes (128 KiB).
///
/// Aligns with the network layer's `MAX_GOSSIP_DECODE_BYTES` (1 MiB) with
/// headroom: a gossip message may batch multiple transactions; keeping each tx
/// well below the gossip cap prevents a single tx from filling a message.
pub const MAX_TX_SIZE: usize = 128 * 1024;

/// Maximum allowed gap between `tx.nonce` and the sender's current on-chain
/// nonce.
///
/// Prevents unbounded future-nonce queuing: if an account has nonce 5, the
/// pool accepts tx nonces 5..=69. Nonce 70+ is rejected with
/// `MempoolError::NonceGapTooLarge` until earlier nonces are consumed.
pub const MAX_NONCE_GAP: u64 = 64;

// ── Validation context ────────────────────────────────────────────────────────

/// Immutable per-block parameters passed into [`validate_transaction`].
///
/// Separating the "what does this tx look like" check from the "what does the
/// current chain state look like" context makes the validation function
/// independently testable and avoids hidden global state.
#[derive(Debug, Clone)]
pub struct ValidationContext {
    /// This node's chain identifier.
    ///
    /// Transactions carrying a different `chain_id` are rejected
    /// (`MempoolError::ChainIdMismatch`) — replay-protection guard.
    pub chain_id: u64,

    /// Current global base fee in Drop per gas unit.
    ///
    /// Transactions with `gas_price < base_fee` cannot be included in the next
    /// block and are rejected upfront (`MempoolError::GasPriceTooLow`).
    pub base_fee: Amount,
}

// ── Entry-point ───────────────────────────────────────────────────────────────

/// Validate a transaction at mempool ingress.
///
/// Returns `Ok(())` if and only if every check passes. Returns the **first**
/// failing `MempoolError` immediately (fail-fast: no need to accumulate all
/// errors for a rejection).
///
/// # Parameters
///
/// - `tx` — the transaction to validate.
/// - `sender_pubkey` — the Ed25519 + ML-DSA-65 public key of the sender,
///   supplied by the caller (RPC / P2P handler). Validation confirms that
///   this pubkey derives to `tx.sender` before running expensive crypto.
/// - `state` — current world state for nonce and balance lookups.
/// - `ctx` — chain-level parameters (chain_id, base_fee).
///
/// # Errors
///
/// See [`MempoolError`] for the full set of rejection reasons.
pub fn validate_transaction(
    tx: &Transaction,
    sender_pubkey: &PublicKey,
    state: &WorldState,
    ctx: &ValidationContext,
) -> Result<(), MempoolError> {
    // Step 1 — gas_limit > 0 (free, fail fast)
    if tx.gas_limit == 0 {
        return Err(MempoolError::ZeroGasLimit { tx_hash: tx.hash });
    }

    // Step 2 — chain_id match (replay protection)
    if tx.chain_id != ctx.chain_id {
        return Err(MempoolError::ChainIdMismatch {
            tx_hash: tx.hash,
            tx_chain_id: tx.chain_id,
            expected_chain_id: ctx.chain_id,
        });
    }

    // Step 3 — serialized size cap
    validate_size(tx)?;

    // Step 4 — pubkey must derive to tx.sender (before expensive crypto)
    validate_pubkey_matches_sender(tx, sender_pubkey)?;

    // Step 5 — hybrid signature (Ed25519 + ML-DSA-65)
    validate_signature(tx, sender_pubkey)?;

    // Steps 6–7 — nonce (one state read, shared with balance read below)
    let account =
        state
            .get_account(&tx.sender)
            .map_err(|source| MempoolError::StateLookupFailed {
                address: tx.sender,
                source,
            })?;

    let (account_nonce, account_balance) = account
        .map(|a| (a.nonce, a.balance))
        .unwrap_or((0, Amount::zero()));

    validate_nonce(tx, account_nonce)?;

    // Steps 8–9 — balance and gas price
    validate_balance(tx, account_balance)?;
    validate_gas_price(tx, ctx.base_fee)?;

    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Check that the serialized transaction does not exceed [`MAX_TX_SIZE`].
fn validate_size(tx: &Transaction) -> Result<(), MempoolError> {
    // bincode::serialized_size is O(1) for fixed-layout types — does not
    // allocate or traverse the full type graph; it walks the schema once.
    //
    // `unwrap_or(u64::MAX)`: bincode::serialized_size returns Err only when
    // the type contains unsupported fields (e.g. sequences longer than u64::MAX).
    // In practice Transaction always serializes cleanly, but if the call ever
    // fails that is an internal fault — we map it to `u64::MAX` so the tx is
    // conservatively rejected as TransactionTooLarge (caller-visible) rather
    // than surfacing an internal error for a tx that may well be garbage.
    // The key contract is: *no panic*. The misclassification (internal fault →
    // caller error) is acceptable because a tx that cannot be serialized is
    // always correctly rejected, regardless of the diagnostic.
    //
    // Compare in u64 space to avoid `as usize` truncation on hypothetical
    // 32-bit targets (clippy::cast_possible_truncation).
    let size_u64 = bincode::serialized_size(tx).unwrap_or(u64::MAX);
    if size_u64 > MAX_TX_SIZE as u64 {
        return Err(MempoolError::TransactionTooLarge {
            tx_hash: tx.hash,
            // Safe: we only reach this branch when size_u64 > MAX_TX_SIZE
            // (128 KiB = 131_072), which fits in usize on every supported target.
            size: size_u64 as usize,
            max_size: MAX_TX_SIZE,
        });
    }
    Ok(())
}

/// Verify that the supplied `sender_pubkey` derives to `tx.sender`.
///
/// Rejects attacker-supplied keys before running the more expensive
/// `verify_transaction` call.
fn validate_pubkey_matches_sender(
    tx: &Transaction,
    sender_pubkey: &PublicKey,
) -> Result<(), MempoolError> {
    let derived = sender_pubkey
        .to_address()
        .ok_or(MempoolError::InvalidSignature { tx_hash: tx.hash })?;

    if derived != tx.sender {
        return Err(MempoolError::InvalidSignature { tx_hash: tx.hash });
    }
    Ok(())
}

/// Run the full hybrid signature verification (Ed25519 + ML-DSA-65).
fn validate_signature(tx: &Transaction, sender_pubkey: &PublicKey) -> Result<(), MempoolError> {
    verify_transaction(tx, sender_pubkey).map_err(|source| match source {
        // These crypto errors mean the signature itself is structurally
        // invalid or doesn't verify — report as InvalidSignature so the
        // caller sees a clean rejection reason, not an internal fault.
        //
        // Note: both classical and quantum length errors are bucketed here
        // (not to the internal catch-all) because a bad-length sig arriving
        // at the mempool boundary is a malformed *caller submission*, regardless
        // of which component the length error belongs to.
        CryptoError::ClassicalVerificationFailed
        | CryptoError::QuantumVerificationFailed
        | CryptoError::UnsignedTransaction
        | CryptoError::HybridSignatureRequired { .. }
        | CryptoError::InvalidClassicalSignatureLength { .. }
        | CryptoError::InvalidQuantumSignatureLength { .. }
        | CryptoError::InvalidPublicKeyBytes { .. }
        | CryptoError::InvalidQuantumPublicKeyBytes { .. } => {
            MempoolError::InvalidSignature { tx_hash: tx.hash }
        }
        // Other CryptoErrors (e.g. SerializationFailed, KeyGenerationFailed)
        // are internal/structural faults unrelated to the caller's submission.
        source => MempoolError::CryptoError {
            tx_hash: tx.hash,
            source,
        },
    })
}

/// Validate that `tx.nonce` is within the accepted window relative to the
/// account's current nonce.
fn validate_nonce(tx: &Transaction, account_nonce: u64) -> Result<(), MempoolError> {
    if tx.nonce < account_nonce {
        return Err(MempoolError::NonceTooLow {
            sender: tx.sender,
            tx_nonce: tx.nonce,
            account_nonce,
        });
    }

    let gap = tx.nonce - account_nonce;
    if gap > MAX_NONCE_GAP {
        return Err(MempoolError::NonceGapTooLarge {
            sender: tx.sender,
            tx_nonce: tx.nonce,
            account_nonce,
            max_gap: MAX_NONCE_GAP,
        });
    }

    Ok(())
}

/// Validate that `account_balance >= gas_limit × gas_price + value`.
///
/// All arithmetic is checked. Integer overflow in the cost calculation is
/// treated as "balance insufficient" (AGENTS.md §7.4): an overflow would only
/// occur at astronomically large `gas_limit × gas_price` values that no real
/// account could fund.
fn validate_balance(tx: &Transaction, account_balance: Amount) -> Result<(), MempoolError> {
    // gas_cost = gas_limit (u64) × gas_price (Amount/u128)
    let gas_cost = tx
        .gas_price
        .checked_mul(tx.gas_limit as u128)
        .map_err(|_| MempoolError::InsufficientBalance {
            sender: tx.sender,
            required: u128::MAX,
            available: account_balance.as_drop(),
        })?;

    // total_cost = gas_cost + value
    let total_cost =
        gas_cost
            .checked_add(tx.value)
            .map_err(|_| MempoolError::InsufficientBalance {
                sender: tx.sender,
                required: u128::MAX,
                available: account_balance.as_drop(),
            })?;

    if account_balance.as_drop() < total_cost.as_drop() {
        return Err(MempoolError::InsufficientBalance {
            sender: tx.sender,
            required: total_cost.as_drop(),
            available: account_balance.as_drop(),
        });
    }

    Ok(())
}

/// Validate that `tx.gas_price >= base_fee`.
fn validate_gas_price(tx: &Transaction, base_fee: Amount) -> Result<(), MempoolError> {
    if tx.gas_price.as_drop() < base_fee.as_drop() {
        return Err(MempoolError::GasPriceTooLow {
            tx_hash: tx.hash,
            provided: tx.gas_price.as_drop(),
            base_fee: base_fee.as_drop(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
