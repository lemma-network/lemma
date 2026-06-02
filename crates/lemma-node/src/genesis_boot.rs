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
//! 1.  genesis.validate()                   — boundary-check the config (lemma-core)
//! 2.  read CF_METADATA latest_height       — idempotency guard
//! 3.  WorldState::new(db)                  — empty trie
//! 4.  put_account() × initial_balances     — credit genesis allocations (BTreeMap = deterministic §7.1)
//! 5.  state_root = state.state_root()      — trie root (None → Hash::zero() for empty-balance devnet)
//! 6.  db = state.into_db()                 — reclaim DB handle for block writes
//! 7.  ValidatorSet from genesis_validators — validators_hash = vset.hash()
//! 8.  BlockHeader::new(height=0, …)        — genesis header
//! 9.  Block::new(header, [], [])           — no txs / receipts at genesis
//! 10. block_bytes = bincode::serialize(&block); genesis_hash = hash_bytes(block_bytes)
//! 11. WriteBatch: CF_BLOCKS + CF_BLOCK_HASH + CF_METADATA — atomic persist (§16.2)
//! 12. return InitOutcome::Initialized
//! ```

use lemma_core::{
    address::Address,
    block::Block,
    genesis::GenesisConfig,
    hash::Hash,
    header::BlockHeader,
    validator_set::ValidatorSet,
};
use lemma_storage::{
    account::Account,
    db::{CF_BLOCK_HASH, CF_BLOCKS, CF_METADATA},
    state::WorldState,
    LemmaDb,
};

use crate::error::NodeError;

// ── Metadata key constants ────────────────────────────────────────────────────

/// `CF_METADATA` key for the latest committed block height (`u64` big-endian).
///
/// Big-endian preserves numeric order in lexicographic scans (AGENTS §7.1).
const META_LATEST_HEIGHT: &[u8] = b"latest_height";

/// `CF_METADATA` key for the latest committed block hash (32 bytes).
const META_LATEST_HASH: &[u8] = b"latest_hash";

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
/// **Idempotent**: if `CF_METADATA` already contains `latest_height`, returns
/// [`InitOutcome::AlreadyInitialized`] immediately without modifying any state.
///
/// `db` is consumed and embedded in the intermediate [`WorldState`]; the DB
/// handle is reclaimed via [`WorldState::into_db`] before block writes.
///
/// # Errors
///
/// - [`NodeError::Core`] — genesis config validation failed.
/// - [`NodeError::Storage`] — RocksDB read or write failure.
/// - [`NodeError::Block`] — [`BlockHeader`] or [`Block`] construction failed.
/// - [`NodeError::Crypto`] — block hashing failed (unreachable for well-formed blocks).
/// - [`NodeError::Serialization`] — bincode encoding of the genesis block failed.
pub fn init_chain(db: LemmaDb, genesis: &GenesisConfig) -> Result<InitOutcome, NodeError> {
    // Step 1: validate the genesis config at the boundary.
    genesis.validate()?;

    // Step 2: idempotency guard.
    if let Some(height) = read_latest_height(&db)? {
        return Ok(InitOutcome::AlreadyInitialized { height });
    }

    // Steps 3–4: write pre-funded genesis accounts to the world-state trie.
    let accounts = genesis.initial_balances.len();
    let mut state = WorldState::new(db);
    for (addr, amount) in &genesis.initial_balances {
        // BTreeMap iteration is deterministic (AGENTS §7.1) — same state root
        // on every node for identical genesis configs.
        state.put_account(addr, &Account::new_eoa(*amount))?;
    }

    // Step 5: capture the state root (None when initial_balances is empty).
    let state_root = state.state_root().unwrap_or(Hash::zero());

    // Step 6: reclaim the DB handle for block and metadata writes.
    let db = state.into_db();

    // Step 7: build ValidatorSet for epoch 0 and hash it.
    // Uses the canonical lemma-core constructor — same filter (is_active),
    // same overflow handling as advance_epoch step 5 (AGENTS §2.2/§2.4).
    let vset = ValidatorSet::from_active_validators(0, &genesis.genesis_validators)?;
    let validators_hash = vset.hash();

    // Step 8: assemble the genesis block header.
    let header = BlockHeader::new(
        0,                          // height = 0
        genesis.genesis_timestamp,  // timestamp
        Hash::zero(),               // parent_hash — no predecessor
        Hash::zero(),               // transactions_root — no transactions
        state_root,                 // state_root — funded trie (or zero)
        Hash::zero(),               // receipts_root — no receipts
        Address::zero(),            // proposer — none at genesis
        0,                          // epoch = 0
        0,                          // dag_round = 0
        Hash::zero(),               // dag_anchor — none at genesis
        validators_hash,            // validators_hash
        validators_hash,            // next_validators_hash = same (epoch 0)
        genesis.initial_gas_limit,
        0,                          // gas_used = 0
        genesis.initial_base_fee,
        vec![],                     // extra_data
    )?;

    // Step 9: assemble the genesis block (no transactions, no receipts).
    let block = Block::new(header, vec![], vec![])?;

    // Step 10–11: serialize block once, then compute hash from the bytes
    // (avoids double-serialization vs lemma_crypto::hash(&block)) and persist
    // atomically in one WriteBatch (AGENTS §16.2).
    let block_bytes = bincode::serialize(&block)
        .map_err(|e| NodeError::Serialization(e.to_string()))?;
    // hash_bytes computes Blake3 over the already-serialized bytes — identical
    // result to hash(&block) but with one fewer bincode round-trip.
    let genesis_hash = lemma_crypto::hash_bytes(&block_bytes);

    let mut batch = db.new_batch();
    db.batch_put(&mut batch, CF_BLOCKS,     &0u64.to_be_bytes(),         &block_bytes)?;
    db.batch_put(&mut batch, CF_BLOCK_HASH, genesis_hash.as_bytes(),     &block_bytes)?;
    db.batch_put(&mut batch, CF_METADATA,   META_LATEST_HEIGHT,          &0u64.to_be_bytes())?;
    db.batch_put(&mut batch, CF_METADATA,   META_LATEST_HASH,            genesis_hash.as_bytes())?;
    db.write_batch(batch)?;

    Ok(InitOutcome::Initialized { genesis_hash, accounts })
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Read `latest_height` from `CF_METADATA`.
///
/// Returns `Ok(None)` for a fresh (uninitialised) database.
fn read_latest_height(db: &LemmaDb) -> Result<Option<u64>, NodeError> {
    let Some(bytes) = db.get(CF_METADATA, META_LATEST_HEIGHT)? else {
        return Ok(None);
    };
    let arr: [u8; 8] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| NodeError::Serialization(
            format!("latest_height: expected 8 bytes, got {}", bytes.len())
        ))?;
    Ok(Some(u64::from_be_bytes(arr)))
}



#[cfg(test)]
mod tests;
