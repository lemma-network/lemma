//! Balance query: `lemma balance <address>`.
//!
//! ## Phase 1 implementation (DB-direct read)
//!
//! In Phase 1, `lemma-rpc` is an empty stub (Phase 4). The CLI reads the
//! balance directly from the chain database using `WorldState::get_balance`.
//!
//! This is a **read-only** operation — it opens the DB in read-only mode
//! alongside the running node (safe: RocksDB supports concurrent readers).
//!
//! ## Phase 4 forward note
//!
//! Replace `query_balance_from_db` with an RPC call:
//! ```text
//! POST <node_url>/rpc  {"method":"lem_getBalance","params":["<address>","latest"]}
//! ```
//! The RPC API is defined in `docs/05-RPC_SPEC.md`. This function is the
//! single replacement point — the calling CLI code stays unchanged.

use std::path::Path;

use lemma_core::Address;
use lemma_storage::{db::LemmaDb, ChainStore, WorldState};

use crate::error::LemmaCliError;

/// Query the balance of `address` directly from the chain database at `data_dir`.
///
/// Opens the DB, wraps it in a [`WorldState`], and calls `get_balance`.
/// Returns a formatted string like `"1.5 LEM"` (using `Amount`'s `Display` impl).
///
/// ## Phase 4 hook
///
/// Replace this function body with an RPC call to `lem_getBalance` once
/// `lemma-rpc` is implemented (Phase 4, `docs/05-RPC_SPEC.md`).
///
/// # Errors
///
/// - [`LemmaCliError::Storage`] — database I/O error.
/// - [`LemmaCliError::ChainNotInitialised`] — genesis block has never been
///   written (the node has not been run yet).
pub fn query_balance_from_db(data_dir: &Path, address: &Address) -> Result<String, LemmaCliError> {
    let db = LemmaDb::open(data_dir)?;
    let chain = ChainStore::new(&db);

    // Verify the chain is initialised (genesis written). get_balance returns
    // Amount::zero() for unknown accounts — fail fast for uninitialised DBs.
    let tip_block = match chain.tip()? {
        None => {
            return Err(LemmaCliError::ChainNotInitialised {
                path: data_dir.to_path_buf(),
            })
        }
        Some((h, _)) => {
            chain
                .get_block_by_height(h)?
                .ok_or_else(|| LemmaCliError::ChainNotInitialised {
                    path: data_dir.to_path_buf(),
                })?
        }
    };

    // Resume WorldState from the tip block's state_root so we read the
    // persisted account trie (WorldState::new starts with an empty trie).
    let state_root = tip_block.header.state_root;
    let balance = WorldState::with_state_root(db, state_root).get_balance(address)?;
    Ok(balance.to_string())
}
