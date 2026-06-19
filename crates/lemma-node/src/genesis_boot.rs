//! Genesis chain initialisation.
//!
//! [`init_chain`] boots a fresh Lemma node from a [`GenesisConfig`]:
//! writes pre-funded account balances to the world-state trie, assembles
//! and persists the genesis block (height 0), and records chain metadata.
//!
//! The function is **idempotent**: a second call on an already-initialised
//! database returns [`InitOutcome::AlreadyInitialized`] without touching
//! any state.
//!
//! ## Orchestration sequence
//!
//! ```text
//! 1.  genesis.validate()                       — boundary-check the config
//! 2.  ChainStore::new(&db).latest_height()     — idempotency guard
//! 3.  WorldState::new(db)                      — empty trie
//! 4.  put_account() × initial_balances         — credit genesis allocations
//! 4b. put_account() × system contracts         — native_lem + registry (DB-A54)
//! 5.  state_root = state.state_root()          — trie root (None → Hash::zero())
//! 6.  db = state.into_db()                     — reclaim DB handle
//! 7.  ValidatorSet::from_active_validators(0)  — validators_hash = vset.hash()
//! 8.  BlockHeader::new(height=0, …)            — genesis header
//! 9.  Block::new(header, [], [])               — no txs / receipts
//! 10. hash_bytes(serde_json(block))            — canonical Blake3 hash
//! 11. ChainStore::new(&db).put_block(…)        — atomic persist (§16.2)
//! 12. return InitOutcome::Initialized
//! ```

use std::sync::Arc;

use lemma_core::{
    address::Address, block::Block, genesis::GenesisConfig, hash::Hash, header::BlockHeader,
    validator_set::ValidatorSet, Amount,
};
use lemma_storage::{account::Account, state::WorldState, ChainStore, LemmaDb};

use crate::error::NodeError;

// ── Public types ──────────────────────────────────────────────────────────────

/// Outcome of a successful [`init_chain`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum InitOutcome {
    /// The chain was freshly initialised from the genesis config.
    Initialized {
        /// Blake3 hash of the genesis block.
        genesis_hash: Hash,
        /// Number of pre-funded accounts written to the state trie.
        accounts: usize,
    },
    /// The chain was already initialised — no state was modified.
    AlreadyInitialized {
        /// Height read from chain metadata (0 for a single-boot DB).
        height: u64,
    },
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Initialise the Lemma chain from `genesis`, persisting all state to `db`.
///
/// **Idempotent**: if the chain is already initialised (metadata contains
/// `latest_height`), returns [`InitOutcome::AlreadyInitialized`] immediately
/// without modifying any state.
///
/// `db` is consumed and embedded in the intermediate [`WorldState`]; the DB
/// handle is reclaimed via [`WorldState::into_db`] before block writes. Block
/// persistence is delegated to [`ChainStore`] (the canonical write path).
///
/// # Errors
///
/// - [`NodeError::Core`] — genesis config validation failed.
/// - [`NodeError::Storage`] — RocksDB read or write failure.
/// - [`NodeError::Block`] — [`BlockHeader`] or [`Block`] construction failed.
pub fn init_chain(db: LemmaDb, genesis: &GenesisConfig) -> Result<InitOutcome, NodeError> {
    // Step 1: validate the genesis config at the boundary.
    genesis.validate()?;

    // Step 2: idempotency guard via ChainStore (canonical metadata read path).
    if let Some(height) = ChainStore::new(&db).latest_height()? {
        return Ok(InitOutcome::AlreadyInitialized { height });
    }

    // Steps 3–4: write pre-funded genesis accounts to the world-state trie.
    // BTreeMap iteration is deterministic (AGENTS §7.1) — same state root on
    // every node for identical genesis configs.
    // Wrap db in Arc so WorldState can hold a shared reference; the Arc is
    // local to init_chain — it is not shared with any other task here.
    let accounts = genesis.initial_balances.len();
    let db = Arc::new(db);
    let mut state = WorldState::new(Arc::clone(&db));
    for (addr, amount) in &genesis.initial_balances {
        state.put_account(addr, &Account::new_eoa(*amount))?;
    }

    // Step 4b: write protocol-level system contract accounts (DB-A54).
    // These are reserved addresses established at genesis — not WASM contracts
    // (code_hash = Hash::zero()), not pre-funded (balance = Amount::zero()).
    // Written as EOAs (code_hash = Hash::zero()) because no bytecode exists at
    // genesis; the executor populates their state namespaces at deploy time.
    // They are NOT counted in `accounts` — that field tracks user allocations.
    state.put_account(&Address::native_lem(), &Account::new_eoa(Amount::zero()))?;
    state.put_account(&Address::registry(), &Account::new_eoa(Amount::zero()))?;

    // Step 5: capture the state root (None when initial_balances is empty).
    let state_root = state.state_root().unwrap_or(Hash::zero());

    // Step 7: build ValidatorSet for epoch 0 using the canonical constructor
    // (AGENTS §2.2/§2.4 — same filter + overflow handling as advance_epoch).
    let vset = ValidatorSet::from_active_validators(0, &genesis.genesis_validators)?;
    let validators_hash = vset.hash();

    // Step 8: assemble the genesis block header.
    let header = BlockHeader::new(
        0,                         // height = 0
        genesis.genesis_timestamp, // timestamp
        Hash::zero(),              // parent_hash — no predecessor
        Hash::zero(),              // transactions_root — no transactions
        state_root,
        Hash::zero(),    // receipts_root — no receipts
        Address::zero(), // proposer — none at genesis
        0,               // epoch = 0
        0,               // dag_round = 0
        Hash::zero(),    // dag_anchor — none at genesis
        validators_hash,
        validators_hash, // next_validators_hash = same set (epoch 0)
        genesis.initial_gas_limit,
        0, // gas_used = 0
        genesis.initial_base_fee,
        vec![],
    )?;

    // Step 9: assemble the genesis block (no transactions, no receipts).
    // Genesis block has no quorum certificate — it is the chain anchor.
    let block = Block::new(header, vec![], vec![], None)?;

    // Step 10: compute the genesis block hash (canonical Blake3, AGENTS §2.2).
    // serde_json is used (not bincode) because Block contains Signature with
    // an internally-tagged serde format (#[serde(tag = "type")]) that bincode
    // cannot deserialize. The genesis block has quorum_cert = None so bincode
    // would technically work here, but using serde_json keeps the serializer
    // consistent with ChainStore::put_block and compute_block_hash (sync.rs).
    let block_bytes =
        serde_json::to_vec(&block).map_err(|e| NodeError::Serialization(e.to_string()))?;
    let genesis_hash = lemma_crypto::hash_bytes(&block_bytes);

    // Step 11: persist atomically via ChainStore (the canonical block-write path).
    // ChainStore::put_block handles CF_BLOCKS + CF_BLOCK_HASH + CF_METADATA in
    // one WriteBatch and advances tip metadata (AGENTS §16.2).
    //
    // Note: genesis_boot pre-serializes to compute the hash, then
    // ChainStore::put_block re-serializes internally. This is one extra
    // serde_json call for genesis only (cold path, called once per chain).
    // If this ever matters: expose a put_block_raw(bytes, hash) on ChainStore.
    ChainStore::new(&db).put_block(&block, genesis_hash)?;

    Ok(InitOutcome::Initialized {
        genesis_hash,
        accounts,
    })
}

#[cfg(test)]
mod tests;
