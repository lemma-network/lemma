//! Chain handlers: `lem_blockNumber`, `lem_getBlock`, `lem_getLogs`.
//!
//! These handlers read from the committed chain store (block index, receipts).
//! All reads are via [`ChainStore`] over the shared [`LemmaDb`].

use serde_json::{json, Value};

use lemma_core::{block::Block, transaction::Log};
use lemma_storage::chain::ChainStore;

use crate::{error::RpcError, server::NodeHandle};

// ── lem_blockNumber ───────────────────────────────────────────────────────────

/// `lem_blockNumber` — return the current chain tip height as a hex string.
///
/// Returns `"0x0"` when the chain has no committed blocks yet (genesis not
/// yet written). This matches the Ethereum convention of returning `"0x0"`
/// for an empty chain.
///
/// # Errors
///
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn block_number(handle: &NodeHandle) -> Result<Value, RpcError> {
    let chain = ChainStore::new(&handle.db);
    let height = chain.latest_height()?.unwrap_or(0);
    Ok(json!(format!("0x{height:x}")))
}

// ── lem_getBlock ──────────────────────────────────────────────────────────────

/// `lem_getBlock` — return a block by height or hash.
///
/// # Params
///
/// `[height_or_hash: string | number, include_txs: bool]`
///
/// - `height_or_hash`: decimal or hex block height, OR 64-char hex block hash.
/// - `include_txs`: if `true`, include full transaction objects; if `false`,
///   include only transaction hashes.
///
/// Returns `null` if the block is not found.
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — params are missing or malformed.
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn get_block(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = params_array(params, "lem_getBlock")?;

    let height_or_hash = arr.first().ok_or_else(|| RpcError::InvalidParams {
        reason: "lem_getBlock: missing first param (height or hash)".into(),
    })?;

    let include_txs = arr.get(1).and_then(Value::as_bool).unwrap_or(false);

    let chain = ChainStore::new(&handle.db);

    // Resolve to (Block, Hash) — the hash is known for the by-hash path (it's
    // the lookup key itself) and for the by-height path (computed from the
    // stored bytes by get_block_with_hash_by_height).
    let block_and_hash: Option<(Block, lemma_core::hash::Hash)> =
        if let Some(s) = height_or_hash.as_str() {
            // Determine if it's a hash (64 hex chars) or a height.
            if s.len() == 64 || (s.starts_with("0x") && s.len() == 66) {
                // Block hash lookup — the hash is the lookup key itself.
                let hash_bytes = parse_hex_hash(s)?;
                let hash = lemma_core::hash::Hash::from_bytes(hash_bytes);
                chain.get_block_by_hash(&hash)?.map(|block| (block, hash))
            } else {
                // Height string (decimal or hex) — fetch block + computed hash.
                let height = parse_height(s)?;
                chain.get_block_with_hash_by_height(height)?
            }
        } else if let Some(n) = height_or_hash.as_u64() {
            chain.get_block_with_hash_by_height(n)?
        } else {
            return Err(RpcError::InvalidParams {
            reason:
                "lem_getBlock: first param must be a height (number/string) or hash (hex string)"
                    .into(),
        });
        };

    match block_and_hash {
        None => Ok(Value::Null),
        Some((block, hash)) => Ok(serialize_block(&block, include_txs, hash)),
    }
}

// ── lem_getLogs ───────────────────────────────────────────────────────────────

/// `lem_getLogs` — return event logs matching a filter.
///
/// # Params
///
/// `[{ fromBlock?: number, toBlock?: number, address?: string, topics?: string[] }]`
///
/// Scans receipts in the block range `[fromBlock, toBlock]` (inclusive) and
/// returns logs that match the optional `address` and `topics` filters.
///
/// Returns an empty array if no logs match.
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — filter object is malformed.
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn get_logs(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = params_array(params, "lem_getLogs")?;

    let filter = arr.first().cloned().unwrap_or(json!({}));

    // Parse fromBlock/toBlock: absent → default (0 / chain tip); present-but-
    // non-integer → InvalidParams (silent coercion to 0 would silently scan
    // from genesis on malformed input — AGENTS §15.2 validate at boundary).
    let from_block = parse_optional_block_height(&filter, "fromBlock")?;

    let chain = ChainStore::new(&handle.db);

    let to_block = match filter.get("toBlock") {
        None => chain.latest_height()?.unwrap_or(0),
        Some(v) => v.as_u64().ok_or_else(|| RpcError::InvalidParams {
            reason: "toBlock must be a non-negative integer".into(),
        })?,
    };

    // Bound the scan to prevent DoS (max 1000 blocks per call).
    const MAX_LOG_RANGE: u64 = 1_000;
    let to_block = to_block.min(from_block.saturating_add(MAX_LOG_RANGE));

    let filter_address: Option<lemma_core::address::Address> = filter
        .get("address")
        .and_then(Value::as_str)
        .map(parse_address)
        .transpose()?;

    // Parse topics: any malformed hex entry returns InvalidParams rather than
    // silently dropping the topic (silent drop would produce wrong results —
    // the caller's filter would be partially applied without warning).
    let filter_topics: Vec<lemma_core::hash::Hash> =
        match filter.get("topics").and_then(Value::as_array) {
            None => Vec::new(),
            Some(raw_topics) => raw_topics
                .iter()
                .filter_map(Value::as_str)
                .map(|s| {
                    parse_hex_hash(s)
                        .map(lemma_core::hash::Hash::from_bytes)
                        .map_err(|_| RpcError::InvalidParams {
                            reason: format!("invalid topic hex: {s:?}"),
                        })
                })
                .collect::<Result<Vec<_>, _>>()?,
        };

    let mut logs: Vec<Value> = Vec::new();

    for height in from_block..=to_block {
        let Some(block) = chain.get_block_by_height(height)? else {
            break; // stop at first gap
        };

        for (tx_idx, receipt) in block.receipts.iter().enumerate() {
            for log in &receipt.logs {
                if matches_log_filter(log, &filter_address, &filter_topics) {
                    logs.push(serialize_log(log, height, tx_idx));
                }
            }
        }
    }

    Ok(json!(logs))
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Serialize a [`Block`] to JSON.
///
/// `hash` is the canonical block hash as stored in `CF_BLOCK_HASH` — either
/// the lookup key (by-hash path) or the value computed by
/// [`ChainStore::get_block_with_hash_by_height`] (by-height path).
///
/// When `include_txs` is `false`, transactions are represented as their hash
/// hex strings only. When `true`, full transaction objects are included.
///
/// # Infallibility note
///
/// `serde_json::to_value(tx)` is used for the full-tx path. `Transaction` is
/// infallibly `Serialize` (all fields are primitive or serde-derived types with
/// no custom serializers that can fail), so `unwrap_or(Value::Null)` is safe
/// here. If serialization ever fails it indicates a bug in the `Transaction`
/// type, not a runtime condition — the `Value::Null` fallback is a last-resort
/// guard, not a silent swallow of a real error.
fn serialize_block(block: &Block, include_txs: bool, hash: lemma_core::hash::Hash) -> Value {
    let txs: Value = if include_txs {
        // Transaction is infallibly Serialize (all fields are primitive/serde types).
        json!(block
            .transactions
            .iter()
            .map(|tx| serde_json::to_value(tx).unwrap_or(Value::Null))
            .collect::<Vec<_>>())
    } else {
        json!(block
            .transactions
            .iter()
            .map(|tx| format!("0x{}", hex::encode(tx.hash.as_bytes())))
            .collect::<Vec<_>>())
    };

    json!({
        "height": block.header.height,
        "hash": format!("0x{}", hex::encode(hash.as_bytes())),
        "parentHash": format!("0x{}", hex::encode(block.header.parent_hash.as_bytes())),
        "timestamp": block.header.timestamp,
        "proposer": block.header.proposer.to_string(),
        "gasLimit": block.header.gas_limit,
        "gasUsed": block.header.gas_used,
        "baseFee": block.header.base_fee.as_drop().to_string(),
        "stateRoot": format!("0x{}", hex::encode(block.header.state_root.as_bytes())),
        "transactionsRoot": format!("0x{}", hex::encode(block.header.transactions_root.as_bytes())),
        "receiptsRoot": format!("0x{}", hex::encode(block.header.receipts_root.as_bytes())),
        "transactions": txs,
        "transactionCount": block.transactions.len(),
    })
}

/// Serialize a [`Log`] to JSON with block context.
fn serialize_log(log: &Log, block_height: u64, tx_index: usize) -> Value {
    json!({
        "address": log.address.to_string(),
        "topics": log.topics.iter()
            .map(|t| format!("0x{}", hex::encode(t.as_bytes())))
            .collect::<Vec<_>>(),
        "data": format!("0x{}", hex::encode(&log.data)),
        "blockHeight": block_height,
        "transactionIndex": tx_index,
    })
}

/// Returns `true` if `log` matches the optional address and topics filters.
fn matches_log_filter(
    log: &Log,
    address: &Option<lemma_core::address::Address>,
    topics: &[lemma_core::hash::Hash],
) -> bool {
    // Address filter: if specified, log.address must match.
    if let Some(addr) = address {
        if &log.address != addr {
            return false;
        }
    }
    // Topics filter: each specified topic must appear in log.topics at the same index.
    for (i, topic) in topics.iter().enumerate() {
        match log.topics.get(i) {
            Some(t) if t == topic => {}
            _ => return false,
        }
    }
    true
}

/// Parse an optional block height from a filter object.
///
/// - Key absent → `Ok(0)` (default to genesis / chain tip depending on caller).
/// - Key present, value is a non-negative integer → `Ok(value)`.
/// - Key present, value is not a non-negative integer → `Err(InvalidParams)`.
///
/// This prevents malformed input (e.g. `"fromBlock": "latest"`) from silently
/// coercing to 0 and scanning from genesis (AGENTS §15.2 — validate at boundary).
fn parse_optional_block_height(filter: &Value, key: &str) -> Result<u64, RpcError> {
    match filter.get(key) {
        None => Ok(0),
        Some(v) => v.as_u64().ok_or_else(|| RpcError::InvalidParams {
            reason: format!("{key} must be a non-negative integer"),
        }),
    }
}

/// Parse a block height from a decimal or `0x`-prefixed hex string.
fn parse_height(s: &str) -> Result<u64, RpcError> {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|_| RpcError::InvalidParams {
            reason: format!("invalid hex height: {s:?}"),
        })
    } else {
        s.parse::<u64>().map_err(|_| RpcError::InvalidParams {
            reason: format!("invalid decimal height: {s:?}"),
        })
    }
}

/// Parse a 32-byte hash from a hex string (with or without `0x` prefix).
pub(crate) fn parse_hex_hash(s: &str) -> Result<[u8; 32], RpcError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).map_err(|_| RpcError::InvalidParams {
        reason: format!("invalid hex hash: {s:?}"),
    })?;
    let len = bytes.len();
    bytes.try_into().map_err(|_| RpcError::InvalidParams {
        reason: format!("hash must be 32 bytes, got {len} bytes from {s:?}"),
    })
}

/// Parse a 20-byte address from a hex string (with or without `0x` prefix).
pub(crate) fn parse_address(s: &str) -> Result<lemma_core::address::Address, RpcError> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped).map_err(|_| RpcError::InvalidParams {
        reason: format!("invalid hex address: {s:?}"),
    })?;
    let len = bytes.len();
    let arr: [u8; 20] = bytes.try_into().map_err(|_| RpcError::InvalidParams {
        reason: format!("address must be 20 bytes, got {len} bytes: {s:?}"),
    })?;
    Ok(lemma_core::address::Address::from_raw_bytes(arr))
}

/// Extract the params array from a JSON-RPC params value.
///
/// Returns an empty slice if params is `null` or absent.
pub(crate) fn params_array<'a>(
    params: &'a Value,
    method: &str,
) -> Result<&'a Vec<Value>, RpcError> {
    match params {
        Value::Array(arr) => Ok(arr),
        Value::Null => {
            // Return a static empty vec reference via a trick: we need to return
            // a reference but can't return a reference to a local. Use a static.
            static EMPTY: std::sync::OnceLock<Vec<Value>> = std::sync::OnceLock::new();
            Ok(EMPTY.get_or_init(Vec::new))
        }
        _ => Err(RpcError::InvalidParams {
            reason: format!("{method}: params must be an array"),
        }),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
