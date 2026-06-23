//! Transaction signing and verification — the public cryptographic API for Lemma.
//!
//! This module composes [`hashing`] and [`keypair`] into the three operations
//! the mempool and VM need:
//!
//! | Function | Who calls it |
//! |---|---|
//! | [`compute_tx_hash`] | Wallet/SDK — before or after signing to obtain the canonical tx hash |
//! | [`sign_transaction`] | Wallet/SDK — fills `tx.hash` and `tx.signature` in one call |
//! | [`verify_transaction`] | Mempool ingress — enforces `Signature::Hybrid` and checks both sigs |
//!
//! # Signing payload
//!
//! The payload that is signed (and hashed) is a `TxSigningBody` containing every
//! `Transaction` field **except** `hash` (the output of hashing) and `signature`
//! (the output of signing). Including either would be circular. All other 9
//! fields — including `chain_id` — are bound into the payload, so a signature
//! made for one chain cannot be replayed on another (AGENTS.md §7.1 determinism;
//! `docs/11-MEMPOOL_SHIELD_SPEC §1`; `docs/13-VALIDATOR_EPOCH_SPEC §5.2`).
//!
//! # Hybrid-only enforcement
//!
//! Lemma requires **both** Ed25519 and ML-DSA-65 signatures on every transaction.
//! [`verify_transaction`] rejects `Classical`, `PostQuantum`, and `Unsigned`
//! variants with [`CryptoError::HybridSignatureRequired`] or
//! [`CryptoError::UnsignedTransaction`] (AGENTS.md §7.3).
//!
//! # Determinism
//!
//! `TxSigningBody` is serialized with `bincode::serialize` (v1, fixint,
//! little-endian) — the same deterministic path used by `hashing::hash<T>`.
//! Never use `bincode::DefaultOptions` here (AGENTS.md §7.1).

use serde::Serialize;

use lemma_core::{
    transaction::{Transaction, TxType},
    Address, Amount, Hash, Signature,
};

use crate::{
    hash,
    keypair::{verify, HybridSignature, KeyPair, PublicKey},
    CryptoError,
};

// ─── Signing payload ─────────────────────────────────────────────────────────

/// The canonical signing payload for a [`Transaction`].
///
/// Contains every field of `Transaction` except `hash` (the hash of *this*
/// struct) and `signature` (the signature over *this* struct). Serialized with
/// `bincode` v1 for deterministic byte output on every node.
///
/// `chain_id` is included, binding the signature to a specific chain and
/// preventing replay attacks across networks.
///
/// `session_key` is included (P3·Step 13) so that an agent transaction's
/// session key selector is authenticated. Without it, a relay/mempool node
/// could attach, strip, or swap the session key field to bypass Warden
/// or point the tx at a different, more permissive policy.
#[derive(Serialize)]
struct TxSigningBody<'a> {
    sender: &'a Address,
    to: &'a Option<Address>,
    nonce: u64,
    chain_id: u64,
    value: &'a Amount,
    gas_limit: u64,
    gas_price: &'a Amount,
    tx_type: TxType,
    data: &'a [u8],
    /// Session key public key bytes for agent transactions (P3·Step 13).
    /// `None` for owner-signed transactions. Bound into the signed body so
    /// that the session key selector cannot be tampered with.
    session_key: &'a Option<Vec<u8>>,
}

impl<'a> TxSigningBody<'a> {
    fn from_tx(tx: &'a Transaction) -> Self {
        Self {
            sender: &tx.sender,
            to: &tx.to,
            nonce: tx.nonce,
            chain_id: tx.chain_id,
            value: &tx.value,
            gas_limit: tx.gas_limit,
            gas_price: &tx.gas_price,
            tx_type: tx.tx_type,
            data: &tx.data,
            session_key: &tx.session_key,
        }
    }
}

// ─── compute_tx_hash ─────────────────────────────────────────────────────────

/// Compute the canonical Blake3 hash of a transaction's signing body.
///
/// The hash covers every field **except** `hash` (the output of this function)
/// and `signature` (the output of signing). Use this to fill `tx.hash` after
/// construction; [`sign_transaction`] calls this internally.
///
/// # Determinism
///
/// The hash is computed via `bincode::serialize` (v1, fixint, little-endian) →
/// Blake3 — the canonical deterministic path for all typed hashing in Lemma
/// (AGENTS.md §7.1). Every node produces the same hash for the same transaction.
///
/// # Errors
///
/// [`CryptoError::SerializationFailed`] if the signing body cannot be
/// serialized (should never occur for well-formed types; bincode v1 succeeds
/// on all `Serialize` implementors that do not contain maps with non-string keys).
///
/// # Examples
///
/// ```no_run
/// use lemma_crypto::compute_tx_hash;
/// use lemma_core::{Address, Amount, Hash, Signature, transaction::{Transaction, TxType}};
///
/// let tx = Transaction::new(
///     Hash::zero(), Address::zero(), Some(Address::zero()), 0, 0,
///     Amount::zero(), 1_000_000, Amount::from_drop(1_000_000_000),
///     TxType::Transfer, vec![], Signature::Unsigned,
/// ).unwrap();
/// let h = compute_tx_hash(&tx).unwrap();
/// assert!(!h.is_zero());
/// ```
pub fn compute_tx_hash(tx: &Transaction) -> Result<Hash, CryptoError> {
    hash(&TxSigningBody::from_tx(tx))
}

// ─── sign_transaction ────────────────────────────────────────────────────────

/// Sign a transaction with a hybrid keypair, filling `tx.hash` and `tx.signature`.
///
/// After this call the transaction carries:
/// - `tx.hash` = `compute_tx_hash(tx)` (Blake3 of the signing body)
/// - `tx.signature` = `Signature::Hybrid { classical, quantum }`
///
/// The signature is computed over the signing body **before** any previous
/// `hash` or `signature` value — those fields are excluded from the payload
/// regardless of their current state (AGENTS.md §7.1).
///
/// # Errors
///
/// [`CryptoError::SerializationFailed`] if bincode serialization fails (rare).
///
/// # Examples
///
/// ```no_run
/// use lemma_crypto::{KeyPair, sign_transaction, verify_transaction};
/// use lemma_core::{Address, Amount, Hash, Signature, transaction::{Transaction, TxType}};
///
/// let kp = KeyPair::generate().unwrap();
/// let mut tx = Transaction::new(
///     Hash::zero(), *kp.address(), Some(Address::zero()), 0, 1,
///     Amount::zero(), 1_000_000, Amount::from_drop(1_000_000_000),
///     TxType::Transfer, vec![], Signature::Unsigned,
/// ).unwrap();
/// sign_transaction(&mut tx, &kp).unwrap();
///
/// assert!(tx.is_signed());
/// assert!(verify_transaction(&tx, &kp.public_key()).is_ok());
/// ```
pub fn sign_transaction(tx: &mut Transaction, keypair: &KeyPair) -> Result<(), CryptoError> {
    let body = TxSigningBody::from_tx(tx);

    // Hash the body — this becomes tx.hash.
    let tx_hash = hash(&body)?;

    // Sign the hash bytes (not the body directly) — this matches verify_transaction
    // which also signs over the hash bytes. A single canonical 32-byte message
    // is preferable to re-serializing the body in verify.
    let sig = keypair.sign(tx_hash.as_bytes());

    tx.hash = tx_hash;
    tx.signature = sig.to_lemma_signature();
    Ok(())
}

// ─── verify_transaction ──────────────────────────────────────────────────────

/// Verify the hybrid signature on a transaction.
///
/// # Hybrid-only enforcement
///
/// Only [`Signature::Hybrid`] is accepted. Callers with `Classical`,
/// `PostQuantum`, or `Unsigned` signatures receive:
/// - `Unsigned` → [`CryptoError::UnsignedTransaction`]
/// - `Classical` / `PostQuantum` / any other → [`CryptoError::HybridSignatureRequired`]
///
/// # Verification
///
/// Recomputes `compute_tx_hash(tx)` and verifies **both** the Ed25519 classical
/// signature and the ML-DSA-65 quantum signature over the hash bytes.
/// Both must pass (AGENTS.md §7.3).
///
/// # Errors
///
/// | Error | Cause |
/// |---|---|
/// | [`CryptoError::UnsignedTransaction`] | `tx.signature` is `Unsigned` |
/// | [`CryptoError::HybridSignatureRequired`] | Non-hybrid signature variant |
/// | [`CryptoError::SerializationFailed`] | Hash computation failed |
/// | [`CryptoError::ClassicalVerificationFailed`] | Ed25519 sig invalid |
/// | [`CryptoError::QuantumVerificationFailed`] | ML-DSA-65 sig invalid |
/// | (others) | Propagated from [`verify`](keypair::verify) |
///
/// # Examples
///
/// ```no_run
/// use lemma_crypto::{KeyPair, sign_transaction, verify_transaction};
/// # // setup omitted
/// # let kp = KeyPair::generate().unwrap();
/// # use lemma_core::{Address, Amount, Hash, Signature, transaction::{Transaction, TxType}};
/// # let mut tx = Transaction::new(Hash::zero(), *kp.address(), Some(Address::zero()), 0, 1, Amount::zero(),
/// #     1_000_000, Amount::from_drop(1_000_000_000), TxType::Transfer, vec![], Signature::Unsigned).unwrap();
/// sign_transaction(&mut tx, &kp).unwrap();
/// assert!(verify_transaction(&tx, &kp.public_key()).is_ok());
/// ```
pub fn verify_transaction(tx: &Transaction, pubkey: &PublicKey) -> Result<(), CryptoError> {
    // ── Hybrid-only guard ────────────────────────────────────────────────────
    let hybrid_sig = match &tx.signature {
        Signature::Unsigned => return Err(CryptoError::UnsignedTransaction),

        Signature::Classical { .. } => {
            return Err(CryptoError::HybridSignatureRequired { got: "Classical" })
        }

        Signature::PostQuantum { .. } => {
            return Err(CryptoError::HybridSignatureRequired { got: "PostQuantum" })
        }

        Signature::Hybrid { classical, quantum } => HybridSignature {
            classical: classical.clone(),
            quantum: quantum.clone(),
        },

        // Signature is #[non_exhaustive] — catch future variants.
        _ => return Err(CryptoError::HybridSignatureRequired { got: "Unknown" }),
    };

    // ── Recompute signing payload hash ───────────────────────────────────────
    let tx_hash = compute_tx_hash(tx)?;

    // ── Verify both signatures over the hash bytes ───────────────────────────
    verify(pubkey, tx_hash.as_bytes(), &hybrid_sig)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
