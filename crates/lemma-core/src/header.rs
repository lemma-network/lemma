//! BlockHeader — the metadata record that identifies a block in the chain.
//!
//! A `BlockHeader` is the minimal commitment that lets any node:
//! 1. Chain blocks deterministically (`parent_hash`).
//! 2. Verify the transaction set (`transactions_root`).
//! 3. Verify post-execution state (`state_root`, `receipts_root`).
//! 4. Validate gas accounting (`gas_limit`, `gas_used`, `base_fee`).
//!
//! The full transaction list lives in [`Block`](crate::Block).
//! Headers are hashed by `lemma-crypto` to produce block hashes.
//!
//! # Determinism
//!
//! All fields use deterministic types — no `HashMap`, no floats, no
//! `SystemTime`. Timestamps are set by consensus, not the local clock.
//! See `docs/04-BUILD_GUIDE.md` Section 2.1 and AGENTS.md §7.1.

use serde::{Deserialize, Serialize};

use crate::{address::Address, amount::Amount, error::BlockError, hash::Hash};

// ─── BlockHeader ─────────────────────────────────────────────────────────────

/// Metadata for a single block — everything except the transaction list.
///
/// Hashed by `lemma-crypto::hash_header` to produce the canonical block hash.
/// All root hashes (`transactions_root`, `state_root`, `receipts_root`) are
/// Blake3-based Merkle roots computed by `lemma-storage`.
///
/// # Genesis block
///
/// The genesis header has `height = 0`, `parent_hash = Hash::zero()`,
/// `gas_used = 0`, `epoch = 0`, `dag_round = 0`, and `dag_anchor` /
/// `validators_hash` / `next_validators_hash` all `Hash::zero()`. The `base_fee`
/// for block 1 is the protocol-defined initial value from
/// [`GenesisConfig`](crate::GenesisConfig).
///
/// # Examples
///
/// ```no_run
/// use lemma_core::{Address, Amount, Hash, header::BlockHeader};
///
/// let header = BlockHeader::new(
///     0,
///     1_700_000_000,
///     Hash::zero(),
///     Hash::zero(),
///     Hash::zero(),
///     Hash::zero(),
///     Address::zero(),
///     0,               // epoch
///     1,               // protocol_version (genesis = 1)
///     0,
///     Hash::zero(),
///     Hash::zero(),
///     Hash::zero(),
///     30_000_000,
///     0,
///     Amount::from_drop(1_000_000_000),
///     vec![],
/// ).unwrap();
/// assert!(header.is_genesis());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height — 0 for genesis, strictly `parent.height + 1` thereafter.
    pub height: u64,
    /// Unix timestamp in seconds, set by the consensus layer.
    ///
    /// Never read from `SystemTime` — doing so would introduce non-determinism
    /// across nodes. All nodes derive this from the finalized DAG certificate.
    pub timestamp: u64,
    /// Hash of the parent block's header.
    ///
    /// `Hash::zero()` for the genesis block (height 0).
    pub parent_hash: Hash,
    /// Blake3 Merkle root of all transactions in this block.
    ///
    /// `Hash::zero()` for empty blocks.
    pub transactions_root: Hash,
    /// Blake3 root of the state trie after executing all transactions.
    pub state_root: Hash,
    /// Blake3 Merkle root of all transaction receipts in this block.
    ///
    /// `Hash::zero()` for empty blocks.
    pub receipts_root: Hash,
    /// Address of the validator that proposed this block.
    ///
    /// `Address::zero()` for the genesis block (no proposer).
    pub proposer: Address,
    /// Epoch number this block belongs to (validator-set era).
    ///
    /// The committee is fixed for an epoch; this links the block to the
    /// `ValidatorSet` that may sign it. See docs/13-VALIDATOR_EPOCH_SPEC §4.4.
    pub epoch: u64,
    /// Protocol version number for this block (DB-A63, docs/17-VERSIONING_SPEC §7).
    ///
    /// A coarse version for changes that CANNOT be feature-gated (header format,
    /// consensus algorithm, QC/serialization). Monotonic non-decreasing; constant
    /// within an epoch; changes only at epoch boundaries (§7.5).
    ///
    /// Genesis = 1. Validators sign this field as part of `header_digest` →
    /// `QuorumCert` (§7.2). Detection: `StructuralVerifier` rejects blocks with
    /// `protocol_version > MAX_SUPPORTED_PROTOCOL_VERSION` (§7.3, anti-split).
    pub protocol_version: u32,
    /// DAG round of the consensus commit that produced this block.
    ///
    /// The committed leader's anchor round (the `Commit`'s index) — lets light
    /// clients and explorers verify consensus provenance. See docs/07-CONSENSUS_SPEC §5.2.
    pub dag_round: u64,
    /// Digest of the DAG anchor (committed leader) for this block.
    ///
    /// `Hash::zero()` for the genesis block. See docs/07-CONSENSUS_SPEC §5.2.
    pub dag_anchor: Hash,
    /// Hash of the validator set (committee) that is authorized to sign this block.
    ///
    /// Authenticates the current committee for light-client quorum-cert
    /// verification. See docs/13-VALIDATOR_EPOCH_SPEC §4.4 and docs/12-NETWORK_SYNC_SPEC §3.
    pub validators_hash: Hash,
    /// Hash of the NEXT epoch's validator set, authorized by this block.
    ///
    /// On an end-of-epoch boundary block this commits the next committee, forming
    /// the epoch-change proof light clients walk. Equals `validators_hash` within
    /// an epoch. See docs/13-VALIDATOR_EPOCH_SPEC §4.4.
    pub next_validators_hash: Hash,
    /// Maximum total gas units this block may consume.
    ///
    /// Must be > 0. Adjusted per block by the Burn Fee Model to target 50%
    /// utilization.
    pub gas_limit: u64,
    /// Total gas consumed by all transactions in this block.
    ///
    /// Must be ≤ `gas_limit`. Enforced by [`BlockHeader::validate`].
    pub gas_used: u64,
    /// Base fee per gas unit for this block, in Drop.
    ///
    /// Computed from the parent's `gas_used` / `gas_limit` ratio by the
    /// Burn Fee Model. All base fees are burned (sent to `Address::burn()`).
    pub base_fee: Amount,
    /// Arbitrary proposer-supplied bytes (e.g. client version string).
    ///
    /// `lemma-core` stores this as-is. `lemma-vm` enforces a ≤32 byte limit
    /// at block validation time.
    pub extra_data: Vec<u8>,
}

impl BlockHeader {
    /// Create and validate a new `BlockHeader`.
    ///
    /// # Errors
    ///
    /// - [`BlockError::GasLimitZero`] — `gas_limit` is 0.
    /// - [`BlockError::GasExceeded`] — `gas_used > gas_limit`.
    // `too_many_arguments`: `BlockHeader` is a primitive blockchain type. All 17 fields
    // are required and distinct; a builder pattern would add complexity for no structural
    // benefit.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        height: u64,
        timestamp: u64,
        parent_hash: Hash,
        transactions_root: Hash,
        state_root: Hash,
        receipts_root: Hash,
        proposer: Address,
        epoch: u64,
        protocol_version: u32,
        dag_round: u64,
        dag_anchor: Hash,
        validators_hash: Hash,
        next_validators_hash: Hash,
        gas_limit: u64,
        gas_used: u64,
        base_fee: Amount,
        extra_data: Vec<u8>,
    ) -> Result<Self, BlockError> {
        let header = Self {
            height,
            timestamp,
            parent_hash,
            transactions_root,
            state_root,
            receipts_root,
            proposer,
            epoch,
            protocol_version,
            dag_round,
            dag_anchor,
            validators_hash,
            next_validators_hash,
            gas_limit,
            gas_used,
            base_fee,
            extra_data,
        };
        header.validate()?;
        Ok(header)
    }

    /// Validate structural invariants.
    ///
    /// Called automatically by [`BlockHeader::new`]. Exposed publicly so that
    /// deserialized headers can be re-validated after round-tripping.
    ///
    /// Checks run in order: gas_limit > 0 → gas_used ≤ gas_limit.
    ///
    /// # Errors
    ///
    /// - [`BlockError::GasLimitZero`] — `gas_limit` is 0.
    /// - [`BlockError::GasExceeded`] — `gas_used > gas_limit`.
    pub fn validate(&self) -> Result<(), BlockError> {
        if self.gas_limit == 0 {
            return Err(BlockError::GasLimitZero);
        }
        if self.gas_used > self.gas_limit {
            return Err(BlockError::GasExceeded {
                used: self.gas_used,
                limit: self.gas_limit,
            });
        }
        Ok(())
    }

    /// Returns `true` if this is the genesis block (height 0).
    ///
    /// The genesis block is identified solely by height — not by `parent_hash`.
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.height == 0
    }

    /// Returns `true` if this block consumed more than 50% of `gas_limit`.
    ///
    /// The Burn Fee Model uses this to determine whether the base fee should
    /// increase (>50%) or decrease (<50%) for the next block.
    #[must_use]
    pub fn is_above_target_gas(&self) -> bool {
        // Target = gas_limit / 2 (integer division, truncates toward zero).
        // Odd gas_limit rounds the target down, biasing the Burn Fee Model
        // slightly toward fee increases — acceptable since gas_limit is set
        // by the protocol in multiples of 1_000_000 in practice.
        // Floating point is banned in consensus code per AGENTS.md §7.1.
        self.gas_used > self.gas_limit / 2
    }

    /// Returns the gas headroom remaining in this block.
    ///
    /// `gas_limit - gas_used`. Always ≥ 0 (enforced by [`BlockHeader::validate`]).
    #[must_use]
    pub fn gas_remaining(&self) -> u64 {
        // validate() ensures gas_used <= gas_limit, so this cannot underflow.
        self.gas_limit - self.gas_used
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
