//! Transaction handlers: `lem_sendTransaction`, `lem_getTransactionReceipt`.
//!
//! `lem_sendTransaction` admits a transaction to the mempool and broadcasts it
//! via the P2P gossip layer. `lem_getTransactionReceipt` scans committed blocks
//! for a receipt matching the given transaction hash.

use serde_json::{json, Value};

use lemma_core::{amount::Amount, transaction::Transaction, validator::ConsensusKey};
use lemma_crypto::PublicKey;
use lemma_mempool::pool::AdmitContext;
use lemma_network::service::NetworkHandle;
use lemma_storage::{chain::ChainStore, state::WorldState};

use crate::{
    error::RpcError,
    handlers::chain::{params_array, parse_hex_hash},
    server::NodeHandle,
};

// ── lem_sendTransaction ───────────────────────────────────────────────────────

/// `lem_sendTransaction` — submit a signed transaction to the mempool.
///
/// # Params
///
/// `[{ tx: object, sender_pubkey: { classical: string, quantum: string } }]`
///
/// - `tx`: a JSON-encoded [`Transaction`] object.
/// - `sender_pubkey`: the sender's hybrid public key.
///   - `classical`: hex-encoded Ed25519 public key bytes (32 bytes).
///   - `quantum`: hex-encoded ML-DSA-65 public key bytes (1952 bytes).
///
/// Returns the transaction hash as a `0x`-prefixed hex string on success.
///
/// # Why carry `sender_pubkey`?
///
/// Ed25519 and ML-DSA-65 do NOT support key recovery from signatures — the
/// public key cannot be derived from the signature bytes alone. The mempool
/// needs the public key to call `verify_transaction`. Clients must supply it
/// alongside the transaction (same pattern as the P2P gossip path, D·15d).
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — params are missing or malformed.
/// - [`RpcError::TransactionRejected`] — mempool admission failed.
/// - [`RpcError::StorageError`] — chain state read failed.
pub async fn send_transaction(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = params_array(params, "lem_sendTransaction")?;

    let obj = arr.first().ok_or_else(|| RpcError::InvalidParams {
        reason: "lem_sendTransaction: missing param object".into(),
    })?;

    // Deserialize the transaction from the JSON object.
    let tx_value = obj.get("tx").ok_or_else(|| RpcError::InvalidParams {
        reason: "lem_sendTransaction: missing 'tx' field".into(),
    })?;

    let tx: Transaction =
        serde_json::from_value(tx_value.clone()).map_err(|e| RpcError::InvalidParams {
            reason: format!("lem_sendTransaction: invalid transaction: {e}"),
        })?;

    // Deserialize the sender public key.
    let pubkey_obj = obj
        .get("sender_pubkey")
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_sendTransaction: missing 'sender_pubkey' field".into(),
        })?;

    let classical_hex = pubkey_obj
        .get("classical")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_sendTransaction: missing sender_pubkey.classical".into(),
        })?;

    let quantum_hex = pubkey_obj
        .get("quantum")
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_sendTransaction: missing sender_pubkey.quantum".into(),
        })?;

    let classical_bytes = hex::decode(classical_hex.strip_prefix("0x").unwrap_or(classical_hex))
        .map_err(|_| RpcError::InvalidParams {
            reason: "lem_sendTransaction: invalid hex in sender_pubkey.classical".into(),
        })?;

    let quantum_bytes = hex::decode(quantum_hex.strip_prefix("0x").unwrap_or(quantum_hex))
        .map_err(|_| RpcError::InvalidParams {
            reason: "lem_sendTransaction: invalid hex in sender_pubkey.quantum".into(),
        })?;

    // Build the PublicKey via ConsensusKey (AGENTS §8 build-order: node layer
    // converts ConsensusKey → PublicKey, same as the gossip path in network_runner.rs).
    let consensus_key = ConsensusKey {
        classical: classical_bytes,
        quantum: quantum_bytes,
    };
    let sender_pubkey = PublicKey::from(consensus_key.clone());

    let tx_hash = tx.hash;

    // Read the current chain tip state root for WorldState construction.
    // If the chain is not yet initialized, use an empty state (genesis phase).
    let world = {
        let chain = ChainStore::new(&handle.db);
        match chain.tip() {
            Ok(Some((_, hash))) => match chain.get_block_by_hash(&hash) {
                Ok(Some(block)) => WorldState::with_state_root(
                    std::sync::Arc::clone(&handle.db),
                    block.header.state_root,
                ),
                _ => WorldState::new(std::sync::Arc::clone(&handle.db)),
            },
            _ => WorldState::new(std::sync::Arc::clone(&handle.db)),
        }
    };

    // Build the admission context.
    let ctx = AdmitContext {
        chain_id: handle.chain_id,
        // Use zero base fee for devnet (Burn Fee Model calibration deferred).
        base_fee: Amount::zero(),
        now: std::time::Instant::now(),
    };

    // Admit to the mempool (requires write lock).
    // AdmitOutcome (Inserted/Replaced) is intentionally ignored here — the
    // caller only needs the tx_hash on success; the outcome is for gossip
    // deduplication which is handled by the network layer.
    let _outcome = handle
        .mempool
        .write()
        .await
        .admit(
            tx.clone(),
            &sender_pubkey,
            Amount::zero(), // sender_stake: zero for non-staked accounts
            None,           // no Express hint from RPC path
            &world,
            &ctx,
        )
        .map_err(RpcError::from)?;

    // Broadcast via P2P gossip (best-effort — non-fatal if network is down).
    broadcast_transaction(&handle.network, tx, consensus_key).await;

    Ok(json!(format!("0x{}", hex::encode(tx_hash.as_bytes()))))
}

// ── lem_getTransactionReceipt ─────────────────────────────────────────────────

/// `lem_getTransactionReceipt` — return the receipt for a committed transaction.
///
/// # Params
///
/// `[tx_hash_hex: string]`
///
/// Scans committed blocks from the chain tip backwards to find the receipt.
/// Returns `null` if the transaction has not been committed yet (still pending
/// in the mempool or not submitted).
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — tx_hash is missing or malformed.
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn get_transaction_receipt(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = params_array(params, "lem_getTransactionReceipt")?;

    let hash_str = arr
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_getTransactionReceipt: missing tx_hash param".into(),
        })?;

    let hash_bytes = parse_hex_hash(hash_str)?;
    let target_hash = lemma_core::hash::Hash::from_bytes(hash_bytes);

    let chain = ChainStore::new(&handle.db);

    // Scan from the tip downward to find the receipt.
    // Bound the scan to prevent DoS (max 10_000 blocks).
    const MAX_SCAN_BLOCKS: u64 = 10_000;

    let tip_height = match chain.latest_height()? {
        None => return Ok(Value::Null), // no blocks committed yet
        Some(h) => h,
    };

    let scan_from = tip_height.saturating_sub(MAX_SCAN_BLOCKS);

    for height in (scan_from..=tip_height).rev() {
        let Some(block) = chain.get_block_by_height(height)? else {
            continue;
        };

        for (tx_idx, (tx, receipt)) in block
            .transactions
            .iter()
            .zip(block.receipts.iter())
            .enumerate()
        {
            if tx.hash == target_hash {
                return Ok(json!({
                    "txHash": format!("0x{}", hex::encode(receipt.tx_hash.as_bytes())),
                    "blockHeight": height,
                    "transactionIndex": tx_idx,
                    "success": receipt.success,
                    "gasUsed": receipt.gas_used,
                    "logs": receipt.logs.iter().map(|log| json!({
                        "address": log.address.to_string(),
                        "topics": log.topics.iter()
                            .map(|t| format!("0x{}", hex::encode(t.as_bytes())))
                            .collect::<Vec<_>>(),
                        "data": format!("0x{}", hex::encode(&log.data)),
                    })).collect::<Vec<_>>(),
                }));
            }
        }
    }

    Ok(Value::Null)
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Broadcast a transaction via the network handle (best-effort, non-fatal).
///
/// The network handle's command channel is bounded; if it is full, the
/// broadcast is silently dropped. This is acceptable for RPC-submitted
/// transactions — the client can resubmit if needed.
async fn broadcast_transaction(
    network: &NetworkHandle,
    tx: Transaction,
    sender_pubkey: ConsensusKey,
) {
    // Non-fatal: if the network service is down, the tx is still in the mempool.
    let _ = network.broadcast_transaction(tx, sender_pubkey).await;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
