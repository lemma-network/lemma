//! Block execution: pull pending txs, run Flux, apply writes to world state.
//!
//! [`execute_committed_block`] is the single entry point that bridges the
//! DAG consensus layer (`Commit`) to the VM execution layer (Flux +
//! LemmaVM). It implements step 5 of the DAG consensus flow
//! (04-BUILD_GUIDE.md §3, line: "committed sub-DAG linearized → ordered
//! batch refs → Flux execution → chain Block"):
//!
//! ```text
//! parent state_root ──► WorldStateView (read-only base)
//!                              │
//!                         Flux (execute_block_parallel)
//!                              │
//!                     BlockOutput { receipts, writes }
//!                              │
//!                     apply_writes() → WorldState → new state_root
//!                              │
//!                     BlockExecutionOutput { txs, receipts, state_root, … }
//! ```
//!
//! ## State-root correctness (C·Step 13)
//!
//! Balance, nonce, and code writes are applied to the account trie and
//! included in `state_root` (consensus-critical commitment).
//!
//! Contract storage writes are persisted to `CF_STORAGE` for intra-block
//! read-through but do NOT yet update `Account.storage_root` — this is
//! **C·Step 13-residual** — `Account.storage_root` wire-up (newly unblocked):
//! - **M3 CLOSED (P3·Step 6b-vm-1)**: `BlockContext.contract` field added;
//!   host storage ops now use the executing contract's address (not `msg_sender`).
//! - **Remaining blocker**: `apply_writes` does not yet call `WorldState::put_storage`
//!   via a contract trie and update `Account.storage_root`. Until this lands,
//!   storage does NOT contribute to `state_root`. Record as newly-unblocked debt.
//! - This is intentional-deferred (dependency now resolved), NOT silent loss.
//!
//! ## Determinism (AGENTS §7.1)
//!
//! - `pending_by_priority` returns txs in deterministic priority order.
//! - Flux `execute_block_parallel` produces a result identical to sequential
//!   execution for the same ordered block.
//! - `apply_writes` iterates the `BTreeMap<StateKey, StateValue>` in
//!   deterministic `StateKey` order. `StateKey` derives `Ord`, which sorts by
//!   **variant first** (Storage=0 < Balance=1 < Nonce=2 < Code=3), then by
//!   fields. Writes are therefore grouped **by field kind, not by address** —
//!   all Storage writes, then all Balance writes (by addr), then all Nonce, etc.
//!   Per-account correctness does not require adjacency: every write does a full
//!   read-modify-write round-trip via `put_account`, so later writes to the same
//!   account see the already-committed earlier write.
//! - `hash_list` uses `bincode::serialize` (deterministic field order).
//!
//! ## Panic-free settlement boundary (AGENTS §7.2, §9.3)
//!
//! Flux's `execute_block_parallel` never returns `Err` — every tx produces a
//! receipt. `execute_committed_block` propagates storage errors from
//! `apply_writes` as `NodeError::Storage` (fatal — chain integrity required),
//! consistent with the Sui-stall lesson (AGENTS §9.3).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use lemma_consensus::Commit;
use lemma_core::{
    address::Address,
    amount::Amount,
    block::Block,
    hash::Hash,
    transaction::{Transaction, TransactionReceipt},
};
use lemma_storage::{db::LemmaDb, state::WorldState};
use lemma_vm::{
    executor::Executor,
    gas::GasSchedule,
    host::BlockContext,
    parallel::{
        execute_block_parallel,
        mvstate::{StateKey, StateValue},
        BlockOutput, FluxConfig,
    },
    runtime::LemmaEngine,
};
use tracing::warn;

use crate::{error::NodeError, state_view::WorldStateView};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum transactions pulled from the mempool per block.
///
/// Conservative interim ceiling: `initial_gas_limit (30M) / tx_base (21K) ≈ 1428`.
/// Phase 4 will derive this dynamically from `parent.header.gas_limit`.
pub const MAX_TXS_PER_BLOCK: usize = 256;

// ── BlockExecutionOutput ──────────────────────────────────────────────────────

/// Output of executing one committed block's pending transactions.
///
/// Returned by [`execute_committed_block`] and consumed by
/// [`dag_driver::build_block_from_commit`] to assemble the final chain block.
#[derive(Debug)]
pub struct BlockExecutionOutput {
    /// Ordered transactions executed in this block (pulled from the mempool).
    pub txs: Vec<Transaction>,
    /// Per-transaction receipts, in block order.
    pub receipts: Vec<TransactionReceipt>,
    /// New state root after applying all writes to the committed world state.
    pub state_root: Hash,
    /// Blake3 hash of the bincode-serialized transaction list.
    pub transactions_root: Hash,
    /// Blake3 hash of the bincode-serialized receipt list.
    pub receipts_root: Hash,
    /// Total gas consumed by all transactions in this block.
    pub gas_used: u64,
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Execute `txs` against the committed parent state, returning a
/// [`BlockExecutionOutput`] ready for block header assembly.
///
/// ## Arguments
///
/// * `txs` — pending transactions pulled from the mempool by the caller
///   (see `Mempool::pending_by_priority`). Empty vec → no-op execution.
/// * `parent` — the parent chain block (provides committed `state_root`,
///   `timestamp`, `gas_limit`).
/// * `commit` — the Pulse commit that determined block height + timestamp.
/// * `proposer` — the validator address (used in `BlockContext::msg_sender`
///   and `tx_origin`; per-tx origin is a Phase 3 refinement).
/// * `db` — shared database handle for `WorldStateView` and `apply_writes`.
///
/// ## Errors
///
/// - [`NodeError::Config`] — wasmtime engine init failed (pathological).
/// - [`NodeError::Storage`] — trie or RocksDB write failed during `apply_writes`.
/// - [`NodeError::Serialization`] — bincode failed serializing tx/receipt list.
pub fn execute_committed_block(
    txs: Vec<Transaction>,
    parent: &Block,
    commit: &Commit,
    proposer: Address,
    db: Arc<LemmaDb>,
) -> Result<BlockExecutionOutput, NodeError> {
    // BlockContext: deterministic, sourced from consensus (AGENTS §7.1).
    // msg_sender + tx_origin = proposer (Phase 2: per-tx origin is Phase 3).
    let height = commit.index;
    let timestamp = (commit.timestamp_ms / 1_000).max(parent.header.timestamp + 1);
    let block_ctx = BlockContext {
        height,
        timestamp,
        msg_sender: proposer,
        msg_value: Amount::zero(),
        tx_origin: proposer,
        // contract is set per-call by execute_call (M3 fix); proposer is a safe placeholder.
        contract: proposer,
        // Epoch from the parent block header — deterministic (AGENTS §7.1).
        // Warden uses this for policy expiry checks (14-AGENT_LAYER §3).
        epoch: parent.header.epoch,
    };

    // Base state: read-only view of committed state from the parent block.
    let parent_state_root = parent.header.state_root;
    let base = Arc::new(WorldStateView::new(Arc::clone(&db), parent_state_root));

    // Run Flux parallel execution (fast-path skip when mempool is empty).
    let output = if txs.is_empty() {
        BlockOutput {
            receipts: vec![],
            writes: BTreeMap::new(),
        }
    } else {
        // LemmaEngine init: infallible in practice (deterministic config);
        // map to NodeError::Config on the pathological failure path.
        let engine = LemmaEngine::new()
            .map_err(|e| NodeError::Config(format!("LemmaEngine init failed: {e}")))?;
        let executor = Executor::new(engine, GasSchedule::devnet());
        // hints = None: no compiler state-access hints available at this call
        // site yet (B5-3b wiring deferred to P3·Step 7 deploy pipeline).
        // Conservative mode: assume all conflicts. MVCC re-validates regardless.
        execute_block_parallel(
            &executor,
            &txs,
            &block_ctx,
            base,
            FluxConfig::default(),
            None,
        )
    };

    // Apply BlockOutput.writes to the committed world state → new state_root.
    let new_state_root = apply_writes(Arc::clone(&db), parent_state_root, &output.writes)?;

    // Root hashes: Blake3 of bincode-serialized collections.
    // Empty list → Hash::zero() (consistent with genesis block convention).
    let transactions_root = hash_list(&txs)?;
    let receipts_root = hash_list(&output.receipts)?;
    let gas_used: u64 = output.receipts.iter().map(|r| r.gas_used).sum();

    Ok(BlockExecutionOutput {
        txs,
        receipts: output.receipts,
        state_root: new_state_root,
        transactions_root,
        receipts_root,
        gas_used,
    })
}

// ── apply_writes ──────────────────────────────────────────────────────────────

/// Apply `BlockOutput.writes` to the committed world state, return new state_root.
///
/// Iterates in deterministic `StateKey` order (AGENTS §7.1 — `BTreeMap`).
/// `StateKey` derives `Ord`, which sorts by **variant discriminant first**:
/// `Storage(0) < Balance(1) < Nonce(2) < Code(3)`, then by fields within each
/// variant. Writes are grouped by **field kind** across all addresses, NOT by
/// address. For example, with addresses A and B: `Balance(A), Balance(B), ...,
/// Nonce(A), Nonce(B), ...` — the two Balance writes precede both Nonce writes.
///
/// ## Correctness (commutative multi-field updates)
///
/// Per-account correctness does NOT require writes to the same account to be
/// adjacent. Each `apply_one_write` does a full `get_account → mutate one
/// field → put_account` round-trip that commits to the trie immediately.
/// When `Nonce(A)` is processed later, `get_account(A)` reads the updated
/// account that already has the new `balance` from `Balance(A)`. All field
/// updates to one account therefore commute correctly, regardless of the gap
/// between them in iteration order.
///
/// ## Storage + Account.storage_root (C·Step 13-residual)
///
/// `StateKey::Storage` writes are persisted to `CF_STORAGE` for intra-block
/// read-through correctness. `Account.storage_root` is NOT updated here —
/// **M3 is now CLOSED** (`BlockContext.contract` landed in P3·Step 6b-vm-1).
/// The remaining work is the storage_root trie wire-up (C·Step 13-residual,
/// newly unblocked). Storage does not yet contribute to `state_root`.
fn apply_writes(
    db: Arc<LemmaDb>,
    base_state_root: Hash,
    writes: &BTreeMap<StateKey, StateValue>,
) -> Result<Hash, NodeError> {
    if writes.is_empty() {
        return Ok(base_state_root);
    }

    let mut world = if base_state_root.is_zero() {
        WorldState::new(Arc::clone(&db))
    } else {
        WorldState::with_state_root(Arc::clone(&db), base_state_root)
    };

    for (key, value) in writes {
        apply_one_write(&mut world, key, value)?;
    }

    // state_root() is None only on a completely empty trie (all txs were storage-only
    // with no balance/nonce/code changes). In that rare case, preserve the parent root.
    Ok(world.state_root().unwrap_or(base_state_root))
}

/// Apply one (StateKey, StateValue) write to the committed [`WorldState`].
///
/// Mismatched key/value variants (e.g. `Balance(addr)` paired with `Nonce(n)`)
/// cannot occur in correct Flux output — logged as a warning and skipped
/// rather than panicking (consensus path must not halt on unexpected data).
fn apply_one_write(
    world: &mut WorldState,
    key: &StateKey,
    value: &StateValue,
) -> Result<(), NodeError> {
    match (key, value) {
        // ── Balance ──────────────────────────────────────────────────────────
        (StateKey::Balance(addr), StateValue::Balance(amount)) => {
            let mut account = world.get_account(addr)?.unwrap_or_default();
            account.balance = *amount;
            world.put_account(addr, &account)?;
        }

        // ── Nonce ─────────────────────────────────────────────────────────────
        (StateKey::Nonce(addr), StateValue::Nonce(nonce)) => {
            let mut account = world.get_account(addr)?.unwrap_or_default();
            account.nonce = *nonce;
            world.put_account(addr, &account)?;
        }

        // ── Code ──────────────────────────────────────────────────────────────
        (StateKey::Code(addr), StateValue::Code(Some(bytecode))) => {
            // Compute code_hash = blake3(bytecode) — canonical Blake3 primitive
            // (AGENTS §2.2). Used as both the CF_CODE key and the account pointer.
            let code_hash = lemma_crypto::hash_bytes(bytecode);

            // Store bytecode in CF_CODE (content-addressed, append-only).
            // WorldState::put_code is idempotent: if code_hash already exists,
            // it returns Ok(()) immediately without overwriting (DB-A23).
            // This closes the TODO(Phase 3) that was here: bytecode is now
            // persisted in CF_CODE so execute_call can load it on ContractCall
            // via account.code_hash → CF_CODE[code_hash] → bytecode.
            // StorageError → NodeError via #[from] (error.rs).
            world.put_code(&code_hash, bytecode)?;

            // Record code_hash in the account trie (included in state_root).
            // The account holds only the 32-byte thin pointer (DB-A22); the
            // full bytecode lives in CF_CODE keyed by code_hash.
            let mut account = world.get_account(addr)?.unwrap_or_default();
            account.code_hash = code_hash;
            world.put_account(addr, &account)?;
        }
        (StateKey::Code(addr), StateValue::Code(None)) => {
            // Contract deleted — clear code_hash in account leaf.
            let mut account = world.get_account(addr)?.unwrap_or_default();
            account.code_hash = Hash::zero();
            world.put_account(addr, &account)?;
        }

        // ── Storage ───────────────────────────────────────────────────────────
        // Persist to CF_STORAGE for read-through correctness within the block.
        // Account.storage_root NOT updated — C·Step 13-residual (M3 CLOSED; storage_root wire-up is the remaining work).
        (
            StateKey::Storage {
                contract,
                key: slot_key,
            },
            StateValue::Storage(Some(val)),
        ) => {
            let slot = lemma_crypto::hash_bytes(slot_key);
            world.put_storage(contract, &slot, val)?;
        }
        (
            StateKey::Storage {
                contract,
                key: slot_key,
            },
            StateValue::Storage(None),
        ) => {
            let slot = lemma_crypto::hash_bytes(slot_key);
            world.delete_storage(contract, &slot)?;
        }

        // ── Mismatched variants (Flux invariant violation) ────────────────────
        _ => {
            // This should never occur in correct Flux output. Log and continue
            // rather than returning an error that would halt the consensus path
            // (AGENTS §7.2: no panics in consensus; storage errors are fatal but
            // a malformed write map is Flux-internal logic, not storage failure).
            warn!(
                key = ?key,
                value = ?value,
                "block_exec: mismatched StateKey/StateValue variant — skipped \
                 (Flux invariant violation; should not occur)"
            );
        }
    }
    Ok(())
}

// ── Root hash helpers ─────────────────────────────────────────────────────────

/// Compute the Blake3 hash of a bincode-serialized list.
///
/// Empty list → [`Hash::zero()`] (genesis block convention for absent roots).
/// This is the canonical root hash for transaction and receipt sets in Phase 2.
/// Phase 3 will replace this with a Merkle tree over individual item hashes
/// when light-client proof generation is required.
fn hash_list<T: serde::Serialize>(items: &[T]) -> Result<Hash, NodeError> {
    if items.is_empty() {
        return Ok(Hash::zero());
    }
    let bytes = bincode::serialize(items)
        .map_err(|e| NodeError::Serialization(format!("hash_list: {e}")))?;
    Ok(lemma_crypto::hash_bytes(&bytes))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;

// ── on_new_block re-export ────────────────────────────────────────────────────

/// Drive per-block mempool maintenance: remove executed txs, tick rate-limiter.
///
/// Called by `dag_driver` after a block is committed. Removes `committed_tx_hashes`
/// from the pool (they're now on-chain) and ticks `on_new_block`.
///
/// ## Design note
///
/// Tx removal is done here (not inside `execute_committed_block`) because the
/// caller (`dag_driver`) holds the async write lock on the mempool. This keeps
/// `execute_committed_block` synchronous and free of async concerns.
pub fn collect_committed_hashes(txs: &[Transaction]) -> Vec<lemma_core::hash::Hash> {
    txs.iter().map(|t| t.hash).collect()
}

/// Tick mempool maintenance after a committed block.
///
/// Use together with `Mempool::remove` in the dag_driver commit loop.
#[inline]
pub fn mempool_post_commit(
    pool: &mut lemma_mempool::pool::Mempool,
    committed_hashes: &[lemma_core::hash::Hash],
    now: Instant,
) {
    for &hash in committed_hashes {
        pool.remove(hash);
    }
    pool.on_new_block(now);
}
