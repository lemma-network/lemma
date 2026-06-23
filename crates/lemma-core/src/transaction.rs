//! Transaction types — the core unit of state change in Lemma.
//!
//! This module defines four types:
//!
//! - [`TxType`] — discriminates what the transaction does.
//! - [`Log`] — a single event emitted by a contract during execution.
//! - [`Transaction`] — a fully-formed, optionally-signed transaction.
//! - [`TransactionReceipt`] — the execution result attached to a finalized block.
//!
//! # Design notes
//!
//! `lemma-core` owns the **type definitions** only. Hash computation (Blake3
//! over the serialized body) and signature verification live in `lemma-crypto`.
//!
//! All token arithmetic is deferred to [`Amount`]; no raw `u128` arithmetic is
//! performed here.
//!
//! See `docs/04-BUILD_GUIDE.md` Section 2.1.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    address::Address, amount::Amount, error::TransactionError, hash::Hash, signature::Signature,
};

// ─── TxType ──────────────────────────────────────────────────────────────────

/// Discriminant that controls validation rules for a [`Transaction`].
///
/// # Why `#[non_exhaustive]`
///
/// Future transaction types (e.g. governance votes, validator slashing proofs)
/// will be added as new variants. `#[non_exhaustive]` lets us add them without
/// breaking downstream `match` arms in SDK or explorer code.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TxType {
    /// Transfer native LEM to another account.
    Transfer,
    /// Call a function on an already-deployed contract.
    ContractCall,
    /// Deploy new contract bytecode to a fresh contract address.
    ContractDeploy,
    /// Stake LEM with a validator.
    Stake,
    /// Withdraw previously staked LEM from a validator.
    Unstake,
    /// Cast a vote on an on-chain governance proposal.
    ///
    /// # Phase staging
    ///
    /// The **`TxType` variant** exists from Phase 1 (Foundation) so that
    /// the mempool, circuit-breaker, and serialization layers handle
    /// governance transactions consistently from day one.
    ///
    /// The **governance execution logic** — proposals, vote tallying,
    /// quorum thresholds, timelock enforcement, and the `@std/governance`
    /// Lem standard library — is a **Phase 3 (Lem Language + Compiler)**
    /// deliverable.  A Phase 1/2 node will accept, validate, and gossip
    /// `GovernanceVote` transactions but has no executor yet. Until Phase 3
    /// ships the governance system contract, admission of `GovernanceVote`
    /// transactions should be gated at the mempool layer (the circuit breaker
    /// or pool policy) to prevent accepting-but-not-executing transactions
    /// from occupying block space without effect.
    ///
    /// # Wire format
    ///
    /// - `to`: the governance system-contract address (required).
    /// - `data`: ABI-encoded `(proposal_id: u64, choice: u8)` vote payload
    ///   (required, non-empty).
    /// - `value`: typically zero (votes carry no LEM value).
    GovernanceVote,
}

impl fmt::Display for TxType {
    /// Human-readable variant name, used in error messages.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NOTE: update this match when adding new variants — exhaustive within the crate.
        let name = match self {
            Self::Transfer => "Transfer",
            Self::ContractCall => "ContractCall",
            Self::ContractDeploy => "ContractDeploy",
            Self::Stake => "Stake",
            Self::Unstake => "Unstake",
            Self::GovernanceVote => "GovernanceVote",
        };
        f.write_str(name)
    }
}

impl TxType {
    /// Returns `true` if this type creates a new contract on-chain.
    ///
    /// When `true`, the transaction must have no `to` address, and the `data`
    /// field carries the constructor bytecode.
    #[must_use]
    pub fn is_contract_deploy(&self) -> bool {
        matches!(self, Self::ContractDeploy)
    }

    /// Returns `true` if this type requires a non-`None` recipient address.
    ///
    /// `ContractDeploy` is the only type that must NOT have a `to` —
    /// the address is computed by the VM (CREATE formula).
    /// All other types, including `GovernanceVote` (sent to the governance
    /// system-contract address), require an explicit `to`.
    #[must_use]
    pub fn requires_recipient(&self) -> bool {
        // NOTE: update this match when adding new variants.
        !matches!(self, Self::ContractDeploy)
    }

    /// Returns `true` if this type requires non-empty `data`.
    ///
    /// `ContractCall` needs at least a 4-byte function selector.
    /// `ContractDeploy` needs bytecode.
    /// `GovernanceVote` carries `(proposal_id: u64, choice: u8)` — required.
    /// `Transfer`, `Stake`, and `Unstake` may have empty `data`.
    #[must_use]
    pub fn requires_calldata(&self) -> bool {
        matches!(
            self,
            Self::ContractCall | Self::ContractDeploy | Self::GovernanceVote
        )
    }
}

// ─── Log ─────────────────────────────────────────────────────────────────────

/// A single event emitted by a contract during transaction execution.
///
/// The first topic (index 0) conventionally holds the hash of the event
/// signature (e.g. `Transfer(address,address,uint256)`). The exact hash
/// function is determined by the ABI encoding layer in `lemma-vm`. Subsequent
/// topics carry indexed parameters. Non-indexed parameters are ABI-encoded in
/// `data`.
///
/// `lemma-core` stores topics as [`Hash`] values (32 bytes each). The encoding
/// and decoding of `data` is handled by the SDK ABI layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Log {
    /// The contract address that emitted this log.
    pub address: Address,
    /// Indexed event parameters (up to 4 by convention; first is the event
    /// signature hash).
    pub topics: Vec<Hash>,
    /// ABI-encoded non-indexed event parameters.
    pub data: Vec<u8>,
}

impl Log {
    /// Construct a `Log` from its constituent parts.
    ///
    /// `topics[0]` conventionally holds the event signature hash;
    /// see the `lemma-vm` ABI layer for encoding details.
    pub fn new(address: Address, topics: Vec<Hash>, data: Vec<u8>) -> Self {
        Self {
            address,
            topics,
            data,
        }
    }

    /// Return the topic at `index`, or `None` if out of bounds.
    #[must_use]
    pub fn topic(&self, index: usize) -> Option<&Hash> {
        self.topics.get(index)
    }
}

// ─── Transaction ─────────────────────────────────────────────────────────────

/// A fully-formed Lemma transaction.
///
/// Constructed via [`Transaction::new`], which validates structural constraints.
/// Cryptographic validation (hash computation, signature verification) is
/// performed by `lemma-crypto` — `lemma-core` does not import any crypto crate.
///
/// # Serde
///
/// Serialized as a flat JSON object. `hash` is a lowercase hex string;
/// `value` and `gas_price` are decimal strings (see [`Amount`] serde format).
///
/// # Examples
///
/// ```no_run
/// use lemma_core::{Address, Amount, Hash, Signature, transaction::{Transaction, TxType}};
///
/// let tx = Transaction::new(
///     Hash::zero(),
///     Address::burn(),
///     Some(Address::burn()),
///     0,
///     1,
///     Amount::zero(),
///     21_000,
///     Amount::from_drop(1_000_000_000),
///     TxType::Transfer,
///     vec![],
///     Signature::Unsigned,
/// ).unwrap();
/// assert!(!tx.is_signed());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction hash — the Blake3 hash of the canonical serialized body.
    ///
    /// Set by the caller (or by `lemma-crypto`). `lemma-core` does not
    /// recompute it; `lemma-crypto` provides a `compute_tx_hash` function.
    pub hash: Hash,
    /// The account that authorized this transaction.
    pub sender: Address,
    /// Recipient address.
    ///
    /// `None` for [`TxType::ContractDeploy`]; `Some` for all other types.
    pub to: Option<Address>,
    /// Sender nonce — must equal the on-chain account nonce at inclusion time.
    pub nonce: u64,
    /// Network identifier this transaction is bound to (replay protection).
    ///
    /// Must match the chain's `GenesisConfig::chain_id`. A transaction signed for
    /// one network (e.g. testnet) cannot be replayed on another. Bound into the
    /// signed body by `lemma-crypto`. See docs/11-MEMPOOL_SHIELD_SPEC §1 (mempool
    /// validates this at ingress) and docs/13-VALIDATOR_EPOCH_SPEC §5.2.
    pub chain_id: u64,
    /// Native LEM value transferred with this transaction (in Drop).
    pub value: Amount,
    /// Maximum gas units the sender is willing to spend.
    ///
    /// Must be > 0. Execution is aborted (and gas consumed) if this limit is
    /// reached before completion.
    pub gas_limit: u64,
    /// Price per gas unit, in Drop.
    ///
    /// Must be ≥ the block's base fee for inclusion.
    pub gas_price: Amount,
    /// Transaction type — controls validation rules and routing in the VM.
    pub tx_type: TxType,
    /// Calldata or constructor bytecode.
    ///
    /// Required (non-empty) for [`TxType::ContractCall`] and
    /// [`TxType::ContractDeploy`]; may be empty for other types.
    pub data: Vec<u8>,
    /// Authorization — must be [`Signature::Hybrid`] for mempool acceptance.
    pub signature: Signature,

    /// Session key public key bytes, if this transaction is signed by an
    /// agent's session key (14-AGENT_LAYER §2).
    ///
    /// When `Some`, the Warden policy enforcement system checks the transaction
    /// against the agent's on-chain policy before execution:
    /// - `sender` = the owner address (funds, nonce)
    /// - `session_key` = the public key that signed (not the owner's primary key)
    /// - Policy is looked up by `(sender, session_key)` in Warden state
    ///
    /// When `None`, the transaction is a normal owner-signed transaction and
    /// Warden is not invoked.
    ///
    /// Added in P3·Step 13 (Warden policy enforcement).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_key: Option<Vec<u8>>,

    /// Owner co-signature for co-sign step-up (14 §2.3.4, P3·Step 14).
    ///
    /// Required when `tx.value >= policy.cosign_threshold`. The owner signs
    /// the transaction hash with their primary key; this field carries the
    /// resulting signature bytes. Cryptographic verification is the mempool's
    /// responsibility (same as the primary signature) — Warden only checks
    /// presence (`has_owner_cosignature()`).
    ///
    /// NOT included in `TxSigningBody` — it is a counter-signature that
    /// endorses the already-signed transaction hash, not a field of the
    /// body being signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_cosignature: Option<Vec<u8>>,
}

impl Transaction {
    /// Create and validate a new `Transaction`.
    ///
    /// # Errors
    ///
    /// - [`TransactionError::ZeroGasLimit`] — `gas_limit` is 0.
    /// - [`TransactionError::MissingRecipient`] — type requires `to` but it is `None`.
    /// - [`TransactionError::UnexpectedRecipient`] — `ContractDeploy` has a `to`.
    /// - [`TransactionError::MissingCalldata`] — type requires `data` but it is empty.
    //
    // `too_many_arguments`: `Transaction` is a primitive blockchain type. All 11 fields
    // are distinct, required, and cannot be grouped without introducing premature
    // abstraction. A builder pattern would add complexity with no structural benefit
    // for a single constructor call site.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        hash: Hash,
        sender: Address,
        to: Option<Address>,
        nonce: u64,
        chain_id: u64,
        value: Amount,
        gas_limit: u64,
        gas_price: Amount,
        tx_type: TxType,
        data: Vec<u8>,
        signature: Signature,
    ) -> Result<Self, TransactionError> {
        let tx = Self {
            hash,
            sender,
            to,
            nonce,
            chain_id,
            value,
            gas_limit,
            gas_price,
            tx_type,
            data,
            signature,
            session_key: None,
            owner_cosignature: None,
        };
        tx.validate()?;
        Ok(tx)
    }

    /// Validate structural constraints without re-constructing the transaction.
    ///
    /// Called automatically by [`Transaction::new`]. Exposed publicly so that
    /// deserialized transactions can be re-validated after round-tripping.
    ///
    /// Checks run in order: gas limit → recipient presence → recipient absence
    /// (deploy) → calldata presence. The first failing check short-circuits;
    /// only one error is returned even if multiple constraints are violated.
    ///
    /// # Errors
    ///
    /// See [`Transaction::new`] error docs.
    pub fn validate(&self) -> Result<(), TransactionError> {
        if self.gas_limit == 0 {
            return Err(TransactionError::ZeroGasLimit);
        }
        if self.tx_type.requires_recipient() && self.to.is_none() {
            return Err(TransactionError::MissingRecipient {
                tx_type: self.tx_type.to_string(),
            });
        }
        if self.tx_type.is_contract_deploy() && self.to.is_some() {
            return Err(TransactionError::UnexpectedRecipient);
        }
        if self.tx_type.requires_calldata() && self.data.is_empty() {
            return Err(TransactionError::MissingCalldata {
                tx_type: self.tx_type.to_string(),
            });
        }
        Ok(())
    }

    /// Returns `true` if the transaction carries a non-`Unsigned` signature.
    ///
    /// Does **not** verify cryptographic correctness — use `lemma-crypto` for that.
    #[must_use]
    pub fn is_signed(&self) -> bool {
        self.signature.is_signed()
    }

    /// Returns `true` if this is a [`TxType::ContractDeploy`] transaction.
    #[must_use]
    pub fn is_contract_deploy(&self) -> bool {
        self.tx_type.is_contract_deploy()
    }

    /// Returns `true` if the transaction carries an owner co-signature.
    ///
    /// Used by Warden's co-sign step-up check (14 §2.3.4, P3·Step 14):
    /// when `tx.value >= policy.cosign_threshold`, the transaction must carry
    /// the owner's co-signature for autonomous execution. Without it, Warden
    /// returns `Ok(WardenOutcome::PendingOwnerCosign)`.
    ///
    /// Cryptographic correctness of the co-signature is the mempool's
    /// responsibility — Warden only checks presence.
    #[must_use]
    pub fn has_owner_cosignature(&self) -> bool {
        self.owner_cosignature.is_some()
    }
}

// ─── TransactionReceipt ──────────────────────────────────────────────────────

/// The outcome of executing a single transaction, included in the block.
///
/// `#[must_use]` — ignoring a receipt is almost certainly a bug; callers
/// should check [`TransactionReceipt::is_success`] or inspect `logs`.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionReceipt {
    /// Hash of the transaction this receipt belongs to.
    pub tx_hash: Hash,
    /// `true` if execution completed without reverting; `false` otherwise.
    ///
    /// Even failed transactions consume gas — `gas_used` reflects actual usage.
    pub success: bool,
    /// Gas units consumed during execution (always ≤ the transaction's
    /// `gas_limit`).
    pub gas_used: u64,
    /// Events emitted by contracts during execution.
    ///
    /// Empty when `success` is `false` (reverted state changes discard logs).
    pub logs: Vec<Log>,
}

impl TransactionReceipt {
    /// Construct a receipt from the execution outcome of a single transaction.
    ///
    /// `gas_used` must be ≤ the originating transaction's `gas_limit`.
    /// Per the Lemma execution model, `logs` must be empty when `success` is
    /// `false` — reverted execution discards all emitted events. This invariant
    /// is enforced by `lemma-vm`; `lemma-core` stores the receipt as-is.
    pub fn new(tx_hash: Hash, success: bool, gas_used: u64, logs: Vec<Log>) -> Self {
        Self {
            tx_hash,
            success,
            gas_used,
            logs,
        }
    }

    /// Returns `true` if the transaction executed successfully.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.success
    }

    /// Returns the number of logs emitted during execution.
    #[must_use]
    pub fn log_count(&self) -> usize {
        self.logs.len()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
