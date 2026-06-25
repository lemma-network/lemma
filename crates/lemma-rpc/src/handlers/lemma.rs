//! Lemma-specific handlers: `lem_safetyScore`, `lem_stateAccess`.
//!
//! These endpoints expose Lemma-native metadata embedded in the `"lemma.meta"`
//! WASM custom section of deployed contracts.
//!
//! - `lem_safetyScore` — returns the safety score (0–100) derived from the
//!   contract's [`SafetyManifest`] constraint count.
//! - `lem_stateAccess` — returns the state-access hints from the contract's
//!   [`ContractHints`] (function read/write sets).

use serde_json::{json, Value};

use lemma_storage::{chain::ChainStore, state::WorldState};
use lemma_vm::{parse_hints_from_wasm, parse_safety_manifest};

use crate::{error::RpcError, handlers::chain::parse_address, server::NodeHandle};

// ── Safety score constants ────────────────────────────────────────────────────

/// Maximum safety score (no constraints violated).
const MAX_SAFETY_SCORE: u32 = 100;

/// Score deduction per safety constraint in the manifest.
///
/// A contract with 0 constraints scores 100 (fully safe).
/// Each constraint reduces the score by this amount, flooring at 0.
/// This is a devnet placeholder — final scoring requires post-testnet
/// calibration against real contract patterns.
const SCORE_DEDUCTION_PER_CONSTRAINT: u32 = 10;

// ── Shared helper ─────────────────────────────────────────────────────────────

/// Open a [`WorldState`] rooted at the current chain tip's state root.
///
/// Falls back to an empty state if the chain has no committed blocks yet.
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

// ── lem_safetyScore ───────────────────────────────────────────────────────────

/// `lem_safetyScore` — return the safety score for a deployed contract.
///
/// # Params
///
/// `[address: string]`
///
/// Reads the contract bytecode from `CF_CODE`, parses the `"lemma.meta"` WASM
/// custom section, and derives a safety score (0–100) from the
/// [`SafetyManifest`] constraint count.
///
/// Returns `null` for:
/// - EOAs (no deployed code).
/// - Contracts compiled before P3·Step 18 (no `"lemma.meta"` section).
/// - Unknown addresses.
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — address is missing or malformed.
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn safety_score(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = super::chain::params_array(params, "lem_safetyScore")?;

    let addr_str = arr
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_safetyScore: missing address param".into(),
        })?;

    let address = parse_address(addr_str)?;
    let state = open_committed_state(handle)?;

    // Look up the account to get its code_hash.
    let account = match state.get_account(&address)? {
        None => return Ok(Value::Null),
        Some(a) => a,
    };

    // EOA — no code deployed.
    if account.code_hash.is_zero() {
        return Ok(Value::Null);
    }

    // Fetch the bytecode from CF_CODE.
    let bytecode = match state.get_code(&account.code_hash)? {
        None => return Ok(Value::Null),
        Some(b) => b,
    };

    // Parse the safety manifest from the "lemma.meta" WASM custom section.
    let manifest = parse_safety_manifest(&bytecode);

    // Derive a score: 100 − (constraint_count × deduction), floored at 0.
    let deduction =
        (manifest.constraints.len() as u32).saturating_mul(SCORE_DEDUCTION_PER_CONSTRAINT);
    let score = MAX_SAFETY_SCORE.saturating_sub(deduction);

    Ok(json!({
        "address": addr_str,
        "safetyScore": score,
        "constraintCount": manifest.constraints.len(),
        "constraints": manifest.constraints.iter().map(|c| {
            serde_json::to_value(c).unwrap_or(Value::Null)
        }).collect::<Vec<_>>(),
    }))
}

// ── lem_stateAccess ───────────────────────────────────────────────────────────

/// `lem_stateAccess` — return state-access hints for a deployed contract.
///
/// # Params
///
/// `[address: string]`
///
/// Reads the contract bytecode from `CF_CODE`, parses the `"lemma.meta"` WASM
/// custom section, and returns the per-function read/write access hints.
///
/// Returns `null` for EOAs, unknown addresses, or contracts without hints.
///
/// # Errors
///
/// - [`RpcError::InvalidParams`] — address is missing or malformed.
/// - [`RpcError::StorageError`] — RocksDB read failed.
pub fn state_access(handle: &NodeHandle, params: &Value) -> Result<Value, RpcError> {
    let arr = super::chain::params_array(params, "lem_stateAccess")?;

    let addr_str = arr
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| RpcError::InvalidParams {
            reason: "lem_stateAccess: missing address param".into(),
        })?;

    let address = parse_address(addr_str)?;
    let state = open_committed_state(handle)?;

    // Look up the account to get its code_hash.
    let account = match state.get_account(&address)? {
        None => return Ok(Value::Null),
        Some(a) => a,
    };

    // EOA — no code deployed.
    if account.code_hash.is_zero() {
        return Ok(Value::Null);
    }

    // Fetch the bytecode from CF_CODE.
    let bytecode = match state.get_code(&account.code_hash)? {
        None => return Ok(Value::Null),
        Some(b) => b,
    };

    // Parse the state-access hints from the "lemma.meta" WASM custom section.
    let hints = match parse_hints_from_wasm(&bytecode) {
        None => return Ok(Value::Null),
        Some(h) => h,
    };

    // Serialize the hints to JSON.
    let functions: Vec<Value> = hints
        .functions
        .iter()
        .map(|(name, hint)| {
            json!({
                "function": name,
                "reads": hint.reads.iter().collect::<Vec<_>>(),
                "writes": hint.writes.iter().collect::<Vec<_>>(),
                "isExpressEligible": hint.is_express_eligible,
            })
        })
        .collect();

    Ok(json!({
        "address": addr_str,
        "functions": functions,
    }))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
