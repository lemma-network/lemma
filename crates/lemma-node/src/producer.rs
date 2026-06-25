//! Single-node block producer (Phase 1 — no consensus, no VM execution).
//!
//! [`run`] is an async loop that fires every [`ProducerConfig::block_interval_ms`],
//! builds the next block chained to the current tip, persists it via
//! [`ChainStore`], and ticks the mempool's per-block maintenance.
//!
//! ## Phase 1 scope — empty blocks
//!
//! The producer builds **empty blocks** (no transactions, no receipts). This is
//! not a simplification error — it is the correct Phase-1 slice:
//! - [`Block::validate`] requires `header.gas_used == Σ receipt.gas_used`; that
//!   sum comes only from *executing* transactions in the VM.
//! - [`lemma-vm`] is Phase 2 (currently an empty stub).
//!
//! Pooled transactions stay in the mempool. The `on_new_block` tick still runs
//! each interval, exercising mempool maintenance (rate-limiter pruning, local
//! fee-market tick). Phase 2 wires `lemma-vm` execution into this loop and the
//! producer starts including txs with real `gas_used` + state-root updates.
//!
//! **Phase 2 forward hook**: `build_next_block` returns `(Block, Hash)` —
//! Phase 2 replaces this function with one that takes a validated tx batch,
//! calls the VM executor, and returns `(Block, Hash, NewStateRoot, Receipts)`.
//! The `run` loop's structure stays the same.
//!
//! ## Concurrency model
//!
//! The producer is the **sole writer** for `ChainStore::put_block` (Phase 1).
//! It calls `put_block` directly via a `&LemmaDb` borrow from the shared
//! `Arc<LemmaDb>`. The `Arc<RwLock<Mempool>>` is established here so the N4
//! network-ingress task can write-lock the mempool to admit incoming txs
//! without needing any wiring change.
//!
//! See `chain.rs` module doc: N3 MUST be the sole `put_block` caller, or
//! callers must serialize under a common write lock.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::Duration;
use tracing::{debug, info, warn};

use lemma_consensus::calculate_base_fee;
use lemma_core::{
    address::Address, block::Block, error::CoreError, hash::Hash, header::BlockHeader,
};
use lemma_mempool::pool::Mempool;
use lemma_storage::{ChainStore, LemmaDb};

use crate::sync::compute_block_hash;

use crate::error::NodeError;

// ── Configuration ─────────────────────────────────────────────────────────────

/// Configuration for the single-node block producer.
#[derive(Debug, Clone)]
pub struct ProducerConfig {
    /// How often the producer fires, in milliseconds.
    ///
    /// Controls the block cadence. Default: 500 ms (≈2 blocks/second).
    /// Phase 2 replaces this interval with the Surge/Pulse consensus clock.
    pub block_interval_ms: u64,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            block_interval_ms: 500,
        }
    }
}

// ── Pure block-assembly core ──────────────────────────────────────────────────

/// Build the next empty block chained to the current chain tip.
///
/// **Synchronous and side-effect-free** — reads the tip from `chain` but
/// does NOT persist anything. Callers commit with [`commit_block`].
///
/// ## Phase 1: empty blocks
///
/// Produces `Block::new(header, vec![], vec![])` — no transactions, no
/// receipts, `gas_used = 0`. The new block inherits the parent's `state_root`
/// (no execution → no state change). See module-level docs for the Phase 2
/// forward hook.
///
/// ## Timestamp monotonicity
///
/// `timestamp` is clamped to `parent.timestamp + 1` so the chain never has
/// two blocks at the same second (a determinism/light-client requirement).
///
/// ## Base fee
///
/// Computed from the parent header via the consensus Burn Fee Model
/// (`lemma_consensus::calculate_base_fee`). The same function is used by the
/// full consensus path (AGENTS.md §2.2 — one canonical fee calculation).
///
/// # Errors
///
/// - [`NodeError::Config`] — chain is uninitialised (call [`init_chain`]
///   first) or parent block is unexpectedly missing from storage.
/// - [`NodeError::Block`] — [`BlockHeader`] or [`Block`] construction failed
///   (e.g. `gas_limit = 0` in the parent; would indicate DB corruption).
/// - [`NodeError::Core`] — base-fee arithmetic overflowed (unreachable given
///   the LEM supply cap, but propagated per AGENTS.md §7.4).
/// - [`NodeError::Serialization`] — `serde_json` encoding of the block failed.
///
/// [`init_chain`]: crate::genesis_boot::init_chain
pub fn build_next_block(
    chain: &ChainStore<'_>,
    proposer: Address,
    timestamp: u64,
) -> Result<(Block, Hash), NodeError> {
    // Read the current chain tip — must exist (genesis must be initialised).
    let (parent_height, parent_hash) = chain.tip()?.ok_or_else(|| {
        NodeError::Config(
            "chain not initialised — call init_chain before starting the producer".into(),
        )
    })?;

    // Fetch the parent block for its header fields (base_fee, state_root, etc.).
    let parent = chain.get_block_by_height(parent_height)?.ok_or_else(|| {
        NodeError::Config(format!(
            "tip block at height {parent_height} not found in storage — DB may be corrupt"
        ))
    })?;

    // Compute the next block's base fee from the parent (Burn Fee Model).
    let base_fee =
        calculate_base_fee(&parent.header).map_err(|e| NodeError::Core(CoreError::from(e)))?;

    // Clamp timestamp: must be strictly greater than the parent's timestamp to
    // guarantee chain monotonicity (light-client requirement, 12-SPEC §3.2).
    let timestamp = timestamp.max(parent.header.timestamp + 1);

    // Assemble the genesis block header for this height.
    // Phase 1: state_root unchanged (no execution), dag_round/dag_anchor = 0
    // (no consensus yet), epoch unchanged (no advance_epoch in single-node mode).
    let header = BlockHeader::new(
        parent_height + 1, // height
        timestamp,
        parent_hash,              // parent_hash
        Hash::zero(),             // transactions_root (no txs)
        parent.header.state_root, // state_root — unchanged (no VM)
        Hash::zero(),             // receipts_root (no receipts)
        proposer,
        parent.header.epoch,                // epoch — unchanged
        parent.header.protocol_version,     // inherit from parent (within-epoch invariant, §7.5)
        0,                                  // dag_round (no consensus)
        Hash::zero(),                       // dag_anchor (no consensus)
        parent.header.validators_hash,      // validators_hash — unchanged
        parent.header.next_validators_hash, // next_validators_hash — unchanged
        parent.header.gas_limit,            // gas_limit — unchanged (Phase 1)
        0,                                  // gas_used = 0 (no execution)
        base_fee,
        vec![], // extra_data
    )?;

    // Build the empty block. Block::validate checks:
    //   receipts.len() == transactions.len() (both 0 ✓)
    //   gas_used == Σ receipt.gas_used      (0 == 0 ✓)
    // Phase 1 producer blocks have no quorum certificate (QC is a DAG-consensus
    // artifact; Phase 1 uses a timer-based producer). D·15b wires Some(qc).
    let block = Block::new(header, vec![], vec![], None)?;

    // Compute the canonical block hash (AGENTS §2.2: one canonical hash path).
    // compute_block_hash is the single definition; calling it here ensures the
    // producer and the range-sync consumer always derive identical hashes.
    let hash = compute_block_hash(&block).map_err(|e| NodeError::Serialization(e.to_string()))?;

    Ok((block, hash))
}

/// Persist a produced block via [`ChainStore`].
///
/// This is the **sole-writer path** for `put_block` in Phase 1. See the
/// module-level concurrency note and `chain.rs` module doc for the write-
/// serialization requirement in N4+ multi-task scenarios.
///
/// # Errors
///
/// - [`NodeError::Storage`] — RocksDB write failure.
pub fn commit_block(chain: &ChainStore<'_>, block: &Block, hash: Hash) -> Result<(), NodeError> {
    chain.put_block(block, hash).map_err(NodeError::from)
}

// ── Async producer loop ───────────────────────────────────────────────────────

/// Run the single-node block producer until `shutdown` is signalled.
///
/// Fires every [`ProducerConfig::block_interval_ms`], calling
/// [`build_next_block`] → [`commit_block`] → mempool tick → emit on
/// `block_tx` in sequence.
///
/// ## Committed-block channel (`block_tx`)
///
/// After each successful `commit_block`, the producer emits the committed
/// `Block` onto `block_tx` (if `Some`). A separate [`run_block_broadcaster`]
/// task drains this channel and gossips the block to peers via the network.
///
/// The producer does **not** hold a `NetworkHandle` — the dependency goes
/// one way: node-layer wiring owns both the producer and the network handle;
/// only the committed-block channel crosses the boundary (AGENTS §8).
///
/// This mirrors the Sui Mysticeti `CoreSignals` pattern: the consensus core
/// emits onto a channel; subscribers handle dissemination independently.
/// The channel seam survives into Phase 2 unchanged — the DAG consensus
/// driver replaces the timer loop but keeps the same `block_tx` output.
///
/// ## Error policy
///
/// - **Build errors** (e.g. transient serialization hiccup): logged as
///   `WARN` and the tick is skipped — the loop continues. A single failed
///   tick does not stop the node.
/// - **Persist errors**: returned as `Err` and the loop terminates. A failed
///   write means chain-state integrity is compromised; the caller should
///   restart or alert. (Matches the Sui-stall lesson: don't silently swallow
///   settlement-path failures — AGENTS.md §9.3 rule 6.)
/// - **Channel send errors** (`block_tx.send` fails): logged as `DEBUG` and
///   ignored — the broadcaster may have exited first (e.g. during shutdown).
///   Non-fatal: gossip delivery is best-effort.
///
/// ## Shutdown
///
/// `shutdown` is a `tokio::sync::watch::Receiver<bool>`. Send `true` to
/// trigger a clean shutdown. The producer finishes the in-progress tick
/// before returning `Ok(())`.
///
/// ## Write-lock contract
///
/// `write_lock` is shared with the range-sync consumer (`run_network_dispatch`).
/// Both acquire it before calling `put_block` to prevent a tip-race
/// (see `chain.rs` §Tip race under concurrent writers). The lock is held only
/// for the duration of one RocksDB write batch — negligible overhead.
///
/// ## Phase 2 hook
///
/// Replace `build_next_block` with a variant that accepts a validated tx
/// batch and calls `lemma-vm`. The `block_tx` channel seam is preserved.
/// A SEPARATE channel for `DagBlock` gossip (the P2P unit in Phase 2) is
/// added alongside — mirroring Sui's dual-channel pattern.
pub async fn run(
    db: Arc<LemmaDb>,
    mempool: Arc<RwLock<Mempool>>,
    cfg: ProducerConfig,
    proposer: Address,
    block_tx: Option<mpsc::Sender<Block>>,
    write_lock: Arc<Mutex<()>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), NodeError> {
    let mut interval = tokio::time::interval(Duration::from_millis(cfg.block_interval_ms));
    // Skip ticks that fire while we're still processing the previous one —
    // avoids a burst of catch-up blocks after a slow tick.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let chain = ChainStore::new(&db);
                let ts    = current_unix_secs();

                let (block, hash) = match build_next_block(&chain, proposer, ts) {
                    Ok(pair) => pair,
                    Err(e) => {
                        // Transient build failure — log and skip this tick.
                        warn!(error = %e, "producer: build_next_block failed, skipping tick");
                        continue;
                    }
                };

                let height = block.height();

                // Persist under the shared write-lock (serializes with the
                // range-sync consumer's apply_synced_block writes).
                // The lock is held only for one RocksDB write batch.
                {
                    let _guard = write_lock.lock().await;
                    commit_block(&chain, &block, hash)?;
                }

                // Emit committed block for network dissemination (best-effort).
                // The broadcaster task drains this channel and gossips to peers.
                if let Some(tx) = &block_tx {
                    match tx.try_send(block) {
                        Ok(()) => {}
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            // Broadcaster has exited (shutdown in progress) — non-fatal.
                            debug!(height, "block_tx closed — broadcaster gone, skipping gossip");
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            // Broadcaster is lagging the producer — block dropped from gossip.
                            // Increase BLOCK_CHANNEL_CAPACITY or investigate broadcast stalls.
                            warn!(
                                height,
                                "block_tx full — committed block NOT gossiped (broadcaster lagging); \
                                 increase BLOCK_CHANNEL_CAPACITY if persistent"
                            );
                        }
                    }
                }

                // Drive per-block mempool maintenance (rate-limiter prune,
                // local fee-market tick) — same as a full node would do.
                mempool.write().await.on_new_block(Instant::now());

                info!(height, "produced block");
            }

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("producer: shutdown signal received — stopping");
                    break;
                }
            }
        }
    }

    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Return the current time as Unix seconds.
///
/// Used as the block timestamp. Returns 0 on clock failures (pathological;
/// `timestamp.max(parent.timestamp + 1)` in `build_next_block` ensures
/// monotonicity regardless.
fn current_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests;
