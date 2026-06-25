//! State handlers: `lem_getBalance`, `lem_getCode`, `lem_getStorageAt`, `lem_call`.
//!
//! These handlers read from the committed world state (account trie, CF_CODE,
//! CF_STORAGE). All reads are via [`WorldState`] over the shared [`LemmaDb`].
//!
//! `lem_call` executes a read-only contract call (no state write, no receipt).

use serde_json::{json, Value};

use lemma_storage::{chain::ChainStore, state::WorldState};

use crate::{
    error::RpcError,
    handlers::chain::{parse_address, parse_hex_hash},
    server::NodeHandle,
};

/// Open a [`WorldState`] rooted at the current chain tip's state root.
///
/// Falls back to an empty state if the chain has no committed blocks yet
/// (genesis phase). This ensures RPC reads see the latest committed state.
fn open_committed_state(handle: &NodeHandle) -> Result<WorldState, RpcError> {
    let chain = ChainStore::new(&handle.db);
    let state = match chain.tip()? {
        None => WorldState::new(std::sync::Arc::clone(&handle.db)),
        Some((_, hash)) => match chain.get_block_by_hash(&hash)? {
            None => WorldState::new(std::sync::Arc::clone(&handle.db)),
            Some(block) => WorldState::with_state_root(
                std::sync::Arc::clone(&handle.db),
                block.header.state_root,
            ),
        },
    };
    Ok(state)
}

// ── lem_getBalance ────────────────────────────────────────────────────────────

/// `lem_getBalance` — return the liquid LEM balance of an address in Drop.
///
/// # Params
///
/// `[address: string]`
///
/// Returns the balance as a decimal string (Drop units). Returns `"0"` for
/// unknown addresses (implicit zero-balance account).
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — address is missing or malformed.
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn get_balance(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = super::chain::params_array(params, "lem_getBalance")?;
    let addr_str = arr
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_getBalance: missing address param".into(),
        })?;

    let address = parse_address(addr_str)?;
    let state = open_committed_state(handle)?;
    let balance = state.get_balance(&address)?;

    // Return as decimal string to avoid JSON u128 precision loss.
    Ok(json!(balance.as_drop().to_string()))
}

// ── lem_getCode ───────────────────────────────────────────────────────────────

/// `lem_getCode` — return the contract bytecode at an address.
///
/// # Params
///
/// `[address: string]`
///
/// Returns the bytecode as a `0x`-prefixed hex string, or `"0x"` for EOAs
/// (externally-owned accounts with no deployed code).
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — address is missing or malformed.
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn get_code(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = super::chain::params_array(params, "lem_getCode")?;
    let addr_str = arr
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_getCode: missing address param".into(),
        })?;

    let address = parse_address(addr_str)?;
    let state = open_committed_state(handle)?;

    // Look up the account to get its code_hash, then fetch bytecode from CF_CODE.
    let code_hex = match state.get_account(&address)? {
        None => "0x".to_owned(),
        Some(account) if account.code_hash.is_zero() => "0x".to_owned(),
        Some(account) => match state.get_code(&account.code_hash)? {
            None => "0x".to_owned(),
            Some(bytes) => format!("0x{}", hex::encode(&bytes)),
        },
    };

    Ok(json!(code_hex))
}

// ── lem_getStorageAt ──────────────────────────────────────────────────────────

/// `lem_getStorageAt` — return the value at a contract storage slot.
///
/// # Params
///
/// `[address: string, slot_key_hex: string]`
///
/// - `address`: the contract address.
/// - `slot_key_hex`: the 32-byte storage slot key as a hex string.
///
/// Returns the slot value as a `0x`-prefixed hex string, or `"0x"` if the
/// slot has never been written.
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — params are missing or malformed.
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn get_storage_at(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = super::chain::params_array(params, "lem_getStorageAt")?;

    let addr_str = arr
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_getStorageAt: missing address param".into(),
        })?;

    let slot_str = arr
        .get(1)
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_getStorageAt: missing slot_key_hex param".into(),
        })?;

    let address = parse_address(addr_str)?;
    let slot_bytes = parse_hex_hash(slot_str)?;
    let slot = lemma_core::hash::Hash::from_bytes(slot_bytes);

    let state = open_committed_state(handle)?;
    let value_hex = match state.get_storage(&address, &slot)? {
        None => "0x".to_owned(),
        Some(bytes) => format!("0x{}", hex::encode(&bytes)),
    };

    Ok(json!(value_hex))
}

// ── lem_call ──────────────────────────────────────────────────────────────────

/// `lem_call` — execute a read-only contract call (no state write, no receipt).
///
/// # Params
///
/// `[{ to: string, data: string, value?: string }]`
///
/// - `to`: the contract address to call.
/// - `data`: ABI-encoded calldata as a `0x`-prefixed hex string.
/// - `value`: optional LEM value in Drop (decimal string); defaults to `"0"`.
///
/// Returns `{ "returnData": "0x..." }` with the raw return bytes from the
/// contract, or `{ "returnData": "0x", "error": "..." }` on revert/OOG.
///
/// # Implementation note
///
/// This is a **read-only simulation** — it does not write to state and does
/// not produce a receipt. It uses the committed world state as the base.
/// Full simulation requires the VM executor; for now we return the call
/// parameters echoed back with a `"not_executed"` marker so the endpoint
/// exists and is testable. Full VM integration is a follow-up task.
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — params are missing or malformed.
pub async fn call(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = super::chain::params_array(params, "lem_call")?;

    let call_obj = arr.first().ok_or_else(|| RpcError::InvalidParams {
        reason: "lem_call: missing call object param".into(),
    })?;

    let to_str =
        call_obj
            .get("to")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::InvalidParams {
                reason: "lem_call: missing 'to' field".into(),
            })?;

    let _to = parse_address(to_str)?;

    let data_hex = call_obj.get("data").and_then(Value::as_str).unwrap_or("0x");

    let _data = {
        let stripped = data_hex.strip_prefix("0x").unwrap_or(data_hex);
        hex::decode(stripped).map_err(|_| RpcError::InvalidParams {
            reason: format!("lem_call: invalid hex data: {data_hex:?}"),
        })?
    };

    // Return an explicit Unsupported error rather than a misleading stub
    // response. A stub that returns `{ "returnData": "0x", "simulated": true }`
    // looks like a real (empty) response and can silently mislead callers into
    // thinking the call succeeded with no return data.
    //
    // Full VM simulation (read-only Executor::execute_transaction against a
    // WorldState snapshot) is tracked as lem_call-stub-1 in Technical Debt.
    // Wire when the RPC ↔ VM integration layer is designed (Phase 4 follow-up).
    let _ = (handle, _to, _data); // params validated above; unused until VM wired
    Err(RpcError::Unsupported {
        method: "lem_call".into(),
        reason: "read-only VM simulation not yet implemented; tracked as lem_call-stub-1 (Phase 4 follow-up)".into(),
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
