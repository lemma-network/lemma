//! Fee handlers: `lem_gasPrice`.
//!
//! Returns the current base fee from the chain tip header.

use serde_json::{json, Value};

use lemma_storage::chain::ChainStore;

use crate::{error::RpcError, server::NodeHandle};

// ── lem_gasPrice ──────────────────────────────────────────────────────────────

/// `lem_gasPrice` — return the current base fee in Drop as a hex string.
///
/// Reads the `base_fee` field from the latest committed block header.
/// Returns `"0x0"` when the chain has no committed blocks yet.
///
/// # Errors
///
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn gas_price(handle: &NodeHandle) -> Result<Value, RpcError> {
    let chain = ChainStore::new(&handle.db);

    let base_fee_drop: u128 = match chain.tip()? {
        None => 0,
        Some((_, hash)) => match chain.get_block_by_hash(&hash)? {
            None => 0,
            Some(block) => block.header.base_fee.as_drop(),
        },
    };

    Ok(json!(format!("0x{base_fee_drop:x}")))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
