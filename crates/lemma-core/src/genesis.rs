//! GenesisConfig — the bootstrap configuration for a new Lemma chain.
//!
//! `GenesisConfig` is loaded from a JSON file at node startup and used to
//! produce the genesis [`Block`](crate::Block) (height 0). It defines:
//!
//! - The chain's unique identifier (`chain_id`).
//! - The Unix timestamp of the genesis block.
//! - Initial account balances (pre-funded accounts).
//! - Initial gas parameters (gas limit and base fee for block 1).
//!
//! # Determinism
//!
//! All nodes bootstrapping the same chain MUST use identical `GenesisConfig`
//! values — any difference produces a different genesis block hash and an
//! incompatible chain. The config is therefore validated at load time.
//!
//! # Serde
//!
//! Serializes and deserializes as JSON. Used in:
//! - `config/genesis.json` — mainnet/testnet/devnet genesis files
//! - `lemma-node` — loaded at startup via `--genesis` flag
//!
//! See `docs/04-BUILD_GUIDE.md` Section 2.1.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    address::Address,
    amount::Amount,
    error::{CoreError, ValidatorError},
    validator::Validator,
};

// ─── GenesisConfig ────────────────────────────────────────────────────────────

/// Bootstrap configuration for a Lemma chain, loaded from `genesis.json`.
///
/// Every field is required. Nodes reject a genesis file with missing or
/// invalid fields before producing the genesis block.
///
/// # Ordering
///
/// `initial_balances` uses [`BTreeMap`] (not `HashMap`) to guarantee
/// deterministic iteration order across all nodes — required for computing
/// a reproducible genesis state root. See AGENTS.md §7.1.
///
/// # Examples
///
/// ```no_run
/// use lemma_core::{Address, Amount, genesis::GenesisConfig};
///
/// let json = r#"{
///   "chain_id": 1,
///   "genesis_timestamp": 1700000000,
///   "initial_gas_limit": 30000000,
///   "initial_base_fee": "1000000000",
///   "initial_balances": {},
///   "genesis_validators": {}
/// }"#;
///
/// let config: GenesisConfig =
///     serde_json::from_str(json).expect("valid genesis JSON");
/// assert_eq!(config.chain_id, 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Network identifier — distinguishes mainnet (1), testnet (2), devnet (3),
    /// and private chains (≥1000) at the protocol level.
    ///
    /// Transaction signing includes the chain ID to prevent replay attacks
    /// across networks.
    pub chain_id: u64,

    /// Unix timestamp (seconds) of the genesis block.
    ///
    /// All nodes must use the same value — a difference produces a different
    /// genesis block hash and an incompatible chain.
    pub genesis_timestamp: u64,

    /// Gas limit for the genesis block and the starting cap for block 1.
    ///
    /// Must be > 0. The Burn Fee Model adjusts this per block thereafter.
    pub initial_gas_limit: u64,

    /// Base fee per gas unit for block 1, in Drop.
    ///
    /// The genesis block itself has no gas consumption; this value is the
    /// starting base fee that applies to all transactions in block 1.
    pub initial_base_fee: Amount,

    /// Pre-funded account balances at genesis, keyed by address.
    ///
    /// Entries represent the LEM allocated to each address before any
    /// transactions are processed (e.g. team allocations, investor vesting
    /// contracts, faucet accounts on testnet/devnet).
    ///
    /// [`BTreeMap`] guarantees deterministic iteration order for state root
    /// computation — a [`HashMap`] would produce different roots on different
    /// nodes due to random hash seed variation. See AGENTS.md §7.1.
    pub initial_balances: BTreeMap<Address, Amount>,

    /// Initial validator set at genesis — the **out-of-band trust root** from
    /// which the committee hash-chain begins.
    ///
    /// Epoch 0 starts from this set. Light clients bootstrap from the genesis
    /// validator set and walk the chain of quorum-certified epoch-boundary
    /// headers to advance the committee forward
    /// (`docs/13-VALIDATOR_EPOCH_SPEC §4.4`, `docs/12-NETWORK_SYNC_SPEC §3.5`).
    ///
    /// [`BTreeMap`] keyed by operator [`Address`] for deterministic iteration
    /// (AGENTS.md §7.1) — follows the same pattern as `initial_balances`.
    pub genesis_validators: BTreeMap<Address, Validator>,
}

impl GenesisConfig {
    /// Validate structural constraints on the genesis configuration.
    ///
    /// Called by the node at startup before producing the genesis block.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::Block(BlockError::GasLimitZero)`](crate::error::BlockError::GasLimitZero)
    /// if `initial_gas_limit` is 0.
    ///
    /// Note: `initial_base_fee == 0` is permitted — chains may start with zero
    /// base fee. `calculate_base_fee` (lemma-consensus) clamps output to
    /// `MIN_BASE_FEE_DROP` (1 Drip), so the floor takes effect from block 1
    /// regardless of the genesis seed value.
    /// # Errors
    ///
    /// - [`CoreError::Block(BlockError::GasLimitZero)`](crate::error::BlockError::GasLimitZero)
    ///   if `initial_gas_limit` is 0.
    /// - [`CoreError::Validator(ValidatorError::EmptyGenesisValidators)`]
    ///   if `genesis_validators` is empty.
    /// - [`CoreError::Validator(ValidatorError::ZeroGenesisStake)`]
    ///   if any genesis validator has zero active stake.
    #[must_use = "ignoring this result means an invalid genesis config may be used to boot the node"]
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.initial_gas_limit == 0 {
            return Err(CoreError::Block(crate::error::BlockError::GasLimitZero));
        }
        if self.genesis_validators.is_empty() {
            return Err(CoreError::Validator(ValidatorError::EmptyGenesisValidators));
        }
        for (addr, val) in &self.genesis_validators {
            if val.self_stake.active == Amount::zero() {
                return Err(CoreError::Validator(ValidatorError::ZeroGenesisStake {
                    address: addr.to_string(),
                }));
            }
        }
        Ok(())
    }

    /// Returns `true` if the genesis config has no pre-funded accounts.
    ///
    /// An empty genesis (no initial balances) is valid — used for private
    /// devnets where accounts are funded via the faucet after boot.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.initial_balances.is_empty()
    }

    /// Returns the number of pre-funded accounts at genesis.
    #[must_use]
    pub fn account_count(&self) -> usize {
        self.initial_balances.len()
    }

    /// Look up the genesis balance for `address`.
    ///
    /// Returns `None` if the address has no genesis allocation.
    #[must_use]
    pub fn balance_of(&self, address: &Address) -> Option<&Amount> {
        self.initial_balances.get(address)
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
