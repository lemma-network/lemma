//! DAG consensus driver — Phase 2 replacement for the timer-based producer.
//!
//! [`run_dag_driver`] replaces [`super::producer::run`]: instead of firing a
//! timer each 500 ms, it drives the Surge dissemination loop via
//! [`SurgeDriver`], building chain blocks **from Pulse commits** rather than
//! from a wall-clock tick.
//!
//! ## Surge loop (single-node, Phase 2)
//!
//! ```text
//! bootstrap: propose DagBlock at round 0
//!   → on_block → SurgeOutput
//!   → new_round = Some(r) → propose DagBlock at round r
//!   → ... (repeats until commit ready)
//!   → commits non-empty
//!       → for each Commit → build_block_from_commit → commit to chain
//!       → emit on block_tx (gossip seam)
//! ```
//!
//! In single-node mode a single validator holds 100% stake, so every DagBlock
//! instantly satisfies the `>2f+1` quorum and advances the clock. The first
//! chain block is produced after 6 DAG rounds:
//! - Rounds 0–2: foundation wave (strong-link ancestors for round 3).
//! - Rounds 3–5: wave 1 (leader @ 3, voting @ 4, decision @ 5).
//!
//! After round 5, `try_decide` can directly commit the wave-1 leader.
//!
//! ## DagBlock signing (Phase 2 vs Phase 3)
//!
//! Phase 2 uses `Signature::Unsigned` + `sig_ok = true` (single-node; the
//! node trusts its own proposals). Phase 3 will sign DagBlocks with the
//! validator's consensus `KeyPair` before broadcasting, and the network layer
//! will verify + inject `sig_ok`. This is the DB-12 pattern (consensus never
//! calls `lemma-crypto` directly — sig_ok is always injected).
//!
//! ## Commit → BlockHeader mapping (spec §5.2)
//!
//! Each `Commit` maps to one chain `Block`:
//! - `header.height`     = `commit.index`
//! - `header.timestamp`  = `commit.timestamp_ms / 1000`  (ms → seconds)
//! - `header.dag_round`  = `commit.leader.round`
//! - `header.dag_anchor` = `commit.leader.digest`
//!
//! Empty txs/receipts (no VM execution yet — Phase 3 wires `lemma-vm`).
//!
//! ## Gossip seams (Phase 2 → Phase 3)
//!
//! - `block_tx`: committed chain blocks → network broadcaster (same as Phase 1).
//! - `dag_block_tx`: raw JSON-encoded DagBlocks → `NetworkHandle::broadcast_dag_proposal`
//!   (closes H1 — `DagProposal` gossip on `lemma/dag/1`). Phase 3 incoming
//!   DagBlocks arrive via `NetworkEvent::DagProposalReceived` and are fed back
//!   into `on_block` after sig verification.
//!
//! ## Write-lock contract
//!
//! `commit_block` (from `producer.rs`) and `apply_synced_block` both acquire
//! `write_lock: Arc<Mutex<()>>` before calling `ChainStore::put_block`.
//! The DAG driver uses the same shared lock (same single-writer contract).

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

use lemma_consensus::{
    dag::block::{DagBlock, DagBlockBody, DagBlockRef},
    Commit, SurgeDriver,
};
use lemma_core::{
    address::Address, block::Block, error::CoreError, hash::Hash, header::BlockHeader,
    signature::Signature, transaction::Transaction, validator_set::ValidatorSet,
};
use lemma_mempool::pool::Mempool;
use lemma_storage::{ChainStore, LemmaDb};

use crate::{
    block_exec::{
        collect_committed_hashes, execute_committed_block, mempool_post_commit, MAX_TXS_PER_BLOCK,
    },
    error::NodeError,
    producer::commit_block,
    sync::compute_block_hash,
};

// ── DagConfig ─────────────────────────────────────────────────────────────────

/// Configuration for the DAG consensus driver.
///
/// In Phase 2 (single-node), the `validator_set` contains exactly one member
/// (the local node), which trivially satisfies all 2f+1 quorum checks.
/// Phase 3 will extend this with a real `KeyPair` for DagBlock signing.
#[derive(Debug, Clone)]
pub struct DagConfig {
    /// Current validator-set epoch.
    pub epoch: u64,
    /// The address of the local validator (used as the DagBlock `author`).
    pub proposer: Address,
    /// The validator set for the current epoch (includes at least the proposer).
    pub validator_set: ValidatorSet,
}

// ── Pure helpers ──────────────────────────────────────────────────────────────

/// Build a new `DagBlock` at `round` by `author`, referencing `ancestors`.
///
/// **Phase 2**: uses `Signature::Unsigned` (single-node; self-authored blocks
/// are trusted; `sig_ok = true` is passed to `SurgeDriver::on_block`).
/// Phase 3 replaces this with a real Ed25519+ML-DSA-65 signature.
///
/// The payload is empty (no transaction batches — batch dissemination is
/// Phase 3). `commit_votes` is empty (piggybacking is a Phase 3 optimization).
#[must_use]
pub fn build_dag_block(
    round: u64,
    author: Address,
    ancestors: Vec<DagBlockRef>,
    epoch: u64,
    timestamp_ms: u64,
) -> DagBlock {
    DagBlock::new(
        DagBlockBody {
            epoch,
            round,
            author,
            timestamp_ms,
            ancestors,
            payload: vec![],
            commit_votes: vec![],
        },
        Signature::Unsigned,
    )
}

/// Map a [`Commit`] to a chain [`Block`] (spec §5.2), executing pending txs
/// from the mempool against the parent state.
///
/// ## Commit → BlockHeader mapping
///
/// - `header.height`            = `commit.index`
/// - `header.timestamp`         = `commit.timestamp_ms / 1000` (ms → seconds,
///   clamped to be strictly > parent timestamp for chain monotonicity)
/// - `header.dag_round`         = `commit.leader.round`
/// - `header.dag_anchor`        = `commit.leader.digest`
/// - `header.state_root`        = new state root after executing `txs`
/// - `header.transactions_root` = Blake3 hash of serialized `txs`
/// - `header.receipts_root`     = Blake3 hash of serialized receipts
/// - `header.gas_used`          = total gas consumed by `txs`
///
/// ## `txs` parameter
///
/// The caller is responsible for pulling `txs` from the mempool before
/// calling this function. Pass an empty `Vec` to produce an empty block
/// (the fast path used in tests and when the mempool is empty).
///
/// # Errors
///
/// - [`NodeError::Config`] — chain tip missing (call `init_chain` first),
///   or wasmtime engine init failed.
/// - [`NodeError::Block`] — `BlockHeader` or `Block` construction failed.
/// - [`NodeError::Core`] — base-fee arithmetic overflow.
/// - [`NodeError::Storage`] — world-state write failed during execution.
/// - [`NodeError::Serialization`] — block hash encoding failed.
pub fn build_block_from_commit(
    commit: &Commit,
    chain: &ChainStore<'_>,
    proposer: Address,
    db: Arc<LemmaDb>,
    txs: Vec<Transaction>,
) -> Result<(Block, Hash), NodeError> {
    use lemma_consensus::calculate_base_fee;

    // Read chain tip — must exist (genesis must be initialised).
    let (parent_height, parent_hash) = chain.tip()?.ok_or_else(|| {
        NodeError::Config(
            "chain not initialised — call init_chain before starting the dag driver".into(),
        )
    })?;

    // Fetch parent block for inherited fields (state_root, gas_limit, etc.).
    let parent = chain.get_block_by_height(parent_height)?.ok_or_else(|| {
        NodeError::Config(format!(
            "tip block at height {parent_height} not found — DB may be corrupt"
        ))
    })?;

    // Burn Fee Model: derive base_fee from parent (same as producer.rs).
    let base_fee =
        calculate_base_fee(&parent.header).map_err(|e| NodeError::Core(CoreError::from(e)))?;

    // Convert commit timestamp: ms (consensus) → seconds (chain header).
    // Clamp for monotonicity: must be strictly > parent timestamp.
    let timestamp = (commit.timestamp_ms / 1_000).max(parent.header.timestamp + 1);

    // Execute pending transactions against committed parent state (C·Step 13).
    let exec_out = execute_committed_block(txs, &parent, commit, proposer, db)?;

    let header = BlockHeader::new(
        commit.index, // height = commit index
        timestamp,
        parent_hash, // parent_hash from chain tip
        exec_out.transactions_root,
        exec_out.state_root, // new state root (was parent.header.state_root)
        exec_out.receipts_root,
        proposer,
        parent.header.epoch,
        commit.leader.round,  // dag_round — leader round of this commit
        commit.leader.digest, // dag_anchor — leader block digest
        parent.header.validators_hash,
        parent.header.next_validators_hash,
        parent.header.gas_limit,
        exec_out.gas_used, // was 0
        base_fee,
        vec![], // extra_data
    )?;

    let block = Block::new(header, exec_out.txs, exec_out.receipts)?;
    let hash = compute_block_hash(&block).map_err(|e| NodeError::Serialization(e.to_string()))?;

    Ok((block, hash))
}

// ── Async DAG driver loop ─────────────────────────────────────────────────────

/// Run the DAG consensus driver until `shutdown` is signalled.
///
/// ## Single-node Surge loop
///
/// 1. **Bootstrap**: propose DagBlock at round 0 → feed into `SurgeDriver::on_block`.
/// 2. **Round advancement**: when `SurgeOutput::new_round = Some(r)`, collect
///    accepted ancestors at round r-1, build DagBlock at round r, call
///    `on_block` again. Also encode + send via `dag_block_tx` for gossip.
/// 3. **Commits**: for each `Commit` in `SurgeOutput::commits`, call
///    `build_block_from_commit` → `commit_block` (under `write_lock`) → emit
///    on `block_tx` for the network broadcaster.
/// 4. **Equivocations**: logged. Evidence construction + broadcasting is Phase 3.
///
/// ## Phase 3 hook
///
/// Incoming DagBlocks from peers arrive via `NetworkEvent::DagProposalReceived`
/// in `network_runner.rs`. The dispatch loop decodes them and calls
/// `on_dag_proposal(bytes, from_peer)` — to be added in Phase 3 alongside real
/// signature verification. For now (Phase 2, single-node), all DagBlocks are
/// self-proposed and trivially trusted.
///
/// ## Error policy
///
/// - **`SurgeDriver` fatal errors** (`ByzantineInvariantBreach`,
///   `DecidedLeaderMissing`, `StakeOverflow`): returned as `Err` — the node
///   should restart or alert. A BFT invariant breach means the committed order
///   is unsafe.
/// - **Build errors** (`build_block_from_commit` failures): logged as `WARN`,
///   the current round is skipped. Transient storage hiccups should not stop
///   the consensus loop.
/// - **Persist errors** (`commit_block` failures): returned as `Err` — chain
///   integrity compromised (Sui-stall lesson: don't swallow settlement failures).
pub async fn run_dag_driver(
    db: Arc<LemmaDb>,
    mempool: Arc<RwLock<Mempool>>,
    cfg: DagConfig,
    block_tx: Option<mpsc::Sender<Block>>,
    dag_block_tx: Option<mpsc::Sender<Vec<u8>>>,
    write_lock: Arc<Mutex<()>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), NodeError> {
    // Construct the per-epoch SurgeDriver. With a single-validator committee,
    // every DagBlock immediately crosses the >2/3 quorum threshold.
    let mut driver = SurgeDriver::new(cfg.validator_set.clone())
        .map_err(|e| NodeError::Config(format!("SurgeDriver::new failed: {e}")))?;

    info!(
        epoch    = cfg.epoch,
        proposer = %cfg.proposer,
        "dag_driver: starting single-node Surge loop"
    );

    // Bootstrap: propose the genesis DAG round (round 0, no ancestors required).
    let boot_ts = current_unix_millis();
    let boot_block = build_dag_block(0, cfg.proposer, vec![], cfg.epoch, boot_ts);
    let mut next_block = Some(boot_block);

    loop {
        // Check shutdown at the top of EVERY iteration so the loop can be
        // stopped even when blocks are continuously being produced (single-node
        // mode self-drives indefinitely — never reaches an idle state).
        if shutdown.has_changed().unwrap_or(false) && *shutdown.borrow() {
            info!("dag_driver: shutdown signal received — stopping");
            break;
        }

        // Process ONE DagBlock per iteration, then yield to the tokio scheduler
        // so other tasks (network, mempool, block_rx receivers in tests) get CPU.
        // This prevents the busy loop from starving the runtime.
        let dag_block = match next_block.take() {
            Some(b) => b,
            None => {
                // No block to propose — idle; wait for shutdown or external input.
                // Phase 3: this branch receives incoming DagBlocks from peers via
                // a channel passed into this function.
                tokio::select! {
                    _ = shutdown.changed() => {
                        if *shutdown.borrow() {
                            info!("dag_driver: shutdown signal received — stopping");
                            break;
                        }
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(10)) => {}
                }
                continue;
            }
        };

        let current_round = dag_block.round;

        // Gossip the DagBlock to peers (Phase 2: non-fatal; no peers in single-node).
        if let Some(ref tx) = dag_block_tx {
            match serde_json::to_vec(&dag_block) {
                Ok(bytes) => {
                    if let Err(e) = tx.try_send(bytes) {
                        debug!(error = ?e, round = current_round, "dag_block_tx send failed (non-fatal)");
                    }
                }
                Err(e) => {
                    warn!(error = %e, round = current_round, "DagBlock JSON encode failed (non-fatal)");
                }
            }
        }

        // Feed into SurgeDriver. sig_ok = true (Phase 2: self-authored, trusted).
        let output = match driver.on_block(dag_block, true) {
            Ok(out) => out,
            Err(e) => {
                if e.is_fatal() {
                    return Err(NodeError::Config(format!(
                        "SurgeDriver fatal error (node must halt): {e}"
                    )));
                }
                warn!(error = %e, "dag_driver: on_block returned non-fatal error");
                continue;
            }
        };

        // Log equivocations. Evidence construction deferred to Phase 3.
        for equiv in &output.equivocations {
            warn!(equivocation = ?equiv, "dag_driver: equivocation detected — evidence deferred to Phase 3");
        }

        // Process commits: pull txs from mempool, execute, build chain blocks.
        let chain = ChainStore::new(&db);
        for commit in &output.commits {
            // Pull txs from mempool under a short read-lock (non-blocking).
            // Cloned out before calling build_block_from_commit (sync path).
            let txs: Vec<Transaction> = mempool
                .read()
                .await
                .pending_by_priority(MAX_TXS_PER_BLOCK)
                .into_iter()
                .cloned()
                .collect();

            match build_block_from_commit(commit, &chain, cfg.proposer, Arc::clone(&db), txs) {
                Ok((block, hash)) => {
                    let height = block.height();
                    let committed_hashes = collect_committed_hashes(&block.transactions);

                    {
                        let _guard = write_lock.lock().await;
                        commit_block(&chain, &block, hash)?;
                    }

                    if let Some(ref tx) = block_tx {
                        match tx.try_send(block) {
                            Ok(()) => {}
                            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                debug!(height, "block_tx closed — broadcaster gone");
                            }
                            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                warn!(height, "block_tx full — committed block NOT gossiped");
                            }
                        }
                    }

                    // Remove committed txs from pool + tick maintenance.
                    mempool_post_commit(
                        &mut *mempool.write().await,
                        &committed_hashes,
                        Instant::now(),
                    );

                    info!(
                        height,
                        dag_round = commit.leader.round,
                        commit_idx = commit.index,
                        tx_count = committed_hashes.len(),
                        "dag_driver: chain block committed from DAG consensus"
                    );
                }
                Err(e) => {
                    warn!(
                        commit_index = commit.index,
                        error = %e,
                        "dag_driver: build_block_from_commit failed — skipping"
                    );
                }
            }
        }

        // If this block triggered a clock advance, prepare the next DagBlock.
        // We store it in `next_block` and YIELD first so other tasks can run.
        if let Some(new_round) = output.new_round {
            let ancestors: Vec<DagBlockRef> = driver
                .dag()
                .blocks_at_round(new_round - 1)
                .map(|b| b.reference())
                .collect();
            let ts = current_unix_millis();
            next_block = Some(build_dag_block(
                new_round,
                cfg.proposer,
                ancestors,
                cfg.epoch,
                ts,
            ));
        }

        // Yield to the tokio scheduler so other tasks (block_rx receiver,
        // network dispatch, mempool writes) can run between DAG rounds.
        tokio::task::yield_now().await;
    }

    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Current time as Unix milliseconds.
///
/// Used for `DagBlock::timestamp_ms` (advisory wall-clock; consensus uses the
/// stake-weighted median for commit timestamps — spec §5.1).
/// Returns 0 on clock failures (pathological; the DAG driver continues).
fn current_unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests;
