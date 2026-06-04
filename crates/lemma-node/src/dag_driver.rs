//! DAG consensus driver — Phase 2 replacement for the timer-based producer.
//!
//! [`run_dag_driver`] replaces [`super::producer::run`]: instead of firing a
//! timer each 500 ms, it drives the Surge dissemination loop via
//! [`SurgeDriver`], building chain blocks **from Pulse commits** rather than
//! from a wall-clock tick.
//!
//! ## Surge loop (single-node, Phase 2 + C·Step 14)
//!
//! ```text
//! bootstrap: build Batch from mempool → pin in BatchStore → broadcast on lemma/batch/1
//!   → build DagBlock with payload=[batch.to_ref()] at round 0
//!   → on_block → SurgeOutput
//!   → new_round = Some(r) → build new Batch → DagBlock at round r
//!   → ... (repeats until commit ready)
//!   → commits non-empty
//!       → for each Commit:
//!           resolve_committed_txs(commit, dag, store) → Vec<Transaction>
//!           → execute → build chain block
//!           → emit on block_tx (gossip seam)
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
//! ## Batch dissemination (C·Step 14)
//!
//! Before proposing each DagBlock, the driver:
//! 1. Drains the mempool into a [`Batch`].
//! 2. Pins the batch in [`BatchStore`] (keyed by digest).
//! 3. Broadcasts the JSON-encoded batch on `lemma/batch/1`.
//! 4. Sets `DagBlock.payload = [batch.to_ref()]` (or `[]` if the batch is empty).
//!
//! At commit time, [`resolve_committed_txs`] walks `Commit.blocks` in
//! deterministic `(round ASC, author ASC)` order, looks up each `DagBlock` in
//! the driver's DAG, resolves `TxBatchRef → Vec<Transaction>` via the
//! `BatchStore`, deduplicates by tx hash, and hands the ordered list to Flux.
//! This replaces the old `mempool.pending_by_priority()` shortcut, which would
//! diverge across nodes in multi-validator mode.
//!
//! ## Gossip seams (Phase 2 → Phase 3)
//!
//! - `block_tx`: committed chain blocks → network broadcaster (same as Phase 1).
//! - `dag_block_tx`: raw JSON-encoded DagBlocks → `NetworkHandle::broadcast_dag_proposal`
//!   (closes H1 — `DagProposal` gossip on `lemma/dag/1`).
//! - `batch_tx`: raw JSON-encoded Batches → `NetworkHandle::broadcast_batch`
//!   (C·Step 14 — `TxBatch` gossip on `lemma/batch/1`).
//!   Phase 3 incoming batches arrive via `NetworkEvent::BatchReceived` and
//!   are pinned in `BatchStore` by `network_runner`.
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
use lemma_crypto::KeyPair;
use lemma_mempool::pool::Mempool;
use lemma_storage::{ChainStore, LemmaDb};

use crate::{
    batch::{resolve_committed_txs, Batch, BatchStore},
    block_exec::{collect_committed_hashes, execute_committed_block, mempool_post_commit},
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
/// Signs the block body digest with the validator's hybrid keypair
/// (Ed25519 + ML-DSA-65). The signature is stored as [`Signature::Hybrid`].
///
/// ## Signing approach
///
/// `compute_digest` is crate-private in `lemma-consensus`. We derive the
/// digest by constructing a temporary `DagBlock::new(body.clone(), Signature::Unsigned)` —
/// `DagBlock::new` always recomputes the digest from the body, so both calls
/// produce the same digest. We then sign `block.digest.as_bytes()` and build
/// the real block with the hybrid signature.
///
/// `payload` carries the [`TxBatchRef`]s for this round (C·Step 14 — set by
/// the caller after building and pinning the batch). Pass `vec![]` for empty
/// rounds (mempool was empty when the block was proposed).
/// `commit_votes` is empty (piggybacking is a Phase 3 optimization).
///
/// # Errors
///
/// Returns [`NodeError::Config`] if `keypair.address() != &author` — signing
/// a block whose `author` field differs from the signing key is a forgery
/// (a peer running `CertifiedVerifier`, D·15c, will reject it). Caught here
/// at the production site rather than silently emitting an invalid block.
///
/// Signing itself is infallible — `KeyPair::sign` never fails.
pub fn build_dag_block(
    round: u64,
    author: Address,
    ancestors: Vec<DagBlockRef>,
    payload: Vec<lemma_consensus::dag::block::TxBatchRef>,
    epoch: u64,
    timestamp_ms: u64,
    keypair: &KeyPair,
) -> Result<DagBlock, NodeError> {
    // Guard: the signing key must match the declared author address.
    // A mismatch would produce a block that CertifiedVerifier (D·15c) will
    // reject — better to surface it immediately at the producer.
    if keypair.address() != &author {
        return Err(NodeError::Config(format!(
            "build_dag_block: keypair address {kp} does not match author {author} \
             (signing a block with a mismatched key produces an unverifiable signature)",
            kp = keypair.address(),
        )));
    }

    let body = DagBlockBody {
        epoch,
        round,
        author,
        timestamp_ms,
        ancestors,
        payload,
        commit_votes: vec![],
    };

    // Derive the body digest via a temporary unsigned block.
    // DagBlock::new always recomputes the digest from the body fields —
    // both the temporary and the final block produce the same digest.
    // compute_digest is pub(crate) in lemma-consensus; the temp-block pattern
    // is the cleanest cross-crate approach until D·15a debt (living-notes) is
    // closed by exposing a DagBlock::body_digest() helper.
    let tmp = DagBlock::new(body.clone(), Signature::Unsigned);
    let sig = keypair.sign_to_lemma(tmp.digest.as_bytes());

    Ok(DagBlock::new(body, sig))
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

    // quorum_cert is None here — D·15b will assemble the QC from the commit's
    // leader signatures and pass Some(qc). For now, blocks are uncertified.
    let block = Block::new(header, exec_out.txs, exec_out.receipts, None)?;
    let hash = compute_block_hash(&block).map_err(|e| NodeError::Serialization(e.to_string()))?;

    Ok((block, hash))
}

// ── Async DAG driver loop ─────────────────────────────────────────────────────

/// Run the DAG consensus driver until `shutdown` is signalled.
///
/// ## Single-node Surge loop (C·Step 14 — batch dissemination)
///
/// 1. **Bootstrap**: build [`Batch`] from mempool → pin in `batch_store` →
///    broadcast on `lemma/batch/1` → propose DagBlock at round 0 with
///    `payload = [batch.to_ref()]` (or `[]` if mempool empty).
/// 2. **Round advancement**: when `SurgeOutput::new_round = Some(r)`, build a
///    new batch, gossip it, build DagBlock at round r with the batch ref, call
///    `on_block` again. Also encode + send DagBlock via `dag_block_tx`.
/// 3. **Commits**: for each `Commit` in `SurgeOutput::commits`:
///    - [`resolve_committed_txs`] walks `commit.blocks`, looks up each
///      `DagBlock` in the driver's DAG, resolves `TxBatchRef → Vec<Transaction>`
///      via `batch_store`, deduplicates by tx hash.
///    - Passes the resolved txs to `build_block_from_commit` → Flux execution.
///    - This replaces the old `mempool.pending_by_priority()` shortcut, which
///      would diverge across nodes in multi-validator mode.
/// 4. **Equivocations**: logged. Evidence construction + broadcasting is Phase 3.
///
/// ## Batch availability miss
///
/// If a `TxBatchRef` is not in `batch_store` at commit time, the ref is
/// skipped (logged as WARN). The block is still produced with the available
/// txs. A dedicated fetch-on-miss path is deferred to D·Step 15.
///
/// ## Incoming peer DagBlocks (D·15b-1)
///
/// Incoming DagBlocks from peers arrive via `incoming_dag_block_rx: Receiver<(DagBlock, bool)>`.
/// The `bool` is the sig-verification result injected by `run_network_dispatch`
/// (B3-2 pattern: consensus never calls lemma-crypto directly).
/// When `next_block` is `None` (idle), the driver selects on both shutdown and
/// the incoming channel, feeding peer blocks into `SurgeDriver::on_block`.
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
#[allow(clippy::too_many_arguments)]
pub async fn run_dag_driver(
    db: Arc<LemmaDb>,
    mempool: Arc<RwLock<Mempool>>,
    cfg: DagConfig,
    keypair: Arc<KeyPair>,
    batch_store: BatchStore,
    block_tx: Option<mpsc::Sender<Block>>,
    dag_block_tx: Option<mpsc::Sender<Vec<u8>>>,
    batch_tx: Option<mpsc::Sender<Vec<u8>>>,
    write_lock: Arc<Mutex<()>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    mut incoming_dag_block_rx: Option<mpsc::Receiver<(DagBlock, bool)>>,
) -> Result<(), NodeError> {
    // Construct the per-epoch SurgeDriver. With a single-validator committee,
    // every DagBlock immediately crosses the >2/3 quorum threshold.
    let mut driver = SurgeDriver::new(cfg.validator_set.clone())
        .map_err(|e| NodeError::Config(format!("SurgeDriver::new failed: {e}")))?;

    info!(
        epoch    = cfg.epoch,
        proposer = %cfg.proposer,
        "dag_driver: starting Surge loop with batch dissemination (C·Step 14)"
    );

    // Bootstrap: build batch at round 0, pin, broadcast, then propose DagBlock.
    let boot_ts = current_unix_millis();
    let boot_payload = build_and_gossip_batch(
        &mempool,
        cfg.proposer,
        &batch_store,
        &batch_tx,
        0, // round 0
    )
    .await;
    let boot_block = build_dag_block(
        0,
        cfg.proposer,
        vec![],
        boot_payload,
        cfg.epoch,
        boot_ts,
        &keypair,
    )
    .map_err(|e| NodeError::Config(format!("build_dag_block at round 0 failed: {e}")))?;
    let mut next_block = Some(boot_block);

    loop {
        // Check shutdown at the top of EVERY iteration so the loop can be
        // stopped even when blocks are continuously being produced (single-node
        // mode self-drives indefinitely — never reaches an idle state).
        if shutdown.has_changed().unwrap_or(false) && *shutdown.borrow() {
            info!("dag_driver: shutdown signal received — stopping");
            break;
        }

        // ── Drain peer blocks (non-blocking, every iteration) ───────────────
        //
        // `try_recv()` is non-blocking: drains one peer DagBlock if available,
        // then returns immediately. This runs BEFORE the self-authored block so
        // peer blocks are serviced even while the node self-drives (single-node
        // mode always has `next_block = Some(...)` — the idle branch below would
        // never be reached without this). CodeReviewer CR-1 fix (D·15b-1).
        if let Some(ref mut rx) = incoming_dag_block_rx {
            match rx.try_recv() {
                Ok((peer_block, peer_sig_ok)) => {
                    let peer_round = peer_block.round;
                    match driver.on_block(peer_block, peer_sig_ok) {
                        Ok(out) => {
                            process_surge_output(
                                out,
                                &mut next_block,
                                &db,
                                &mempool,
                                &batch_store,
                                &batch_tx,
                                &block_tx,
                                &write_lock,
                                &cfg,
                                &keypair,
                                &mut driver,
                            )
                            .await?;
                        }
                        Err(e) => {
                            if e.is_fatal() {
                                return Err(NodeError::Config(format!(
                                    "SurgeDriver fatal error on peer block round {peer_round}: {e}"
                                )));
                            }
                            warn!(error = %e, round = peer_round,
                                  "dag_driver: peer block on_block error (non-fatal)");
                        }
                    }
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                    // No peer block available right now — continue to self-authored path.
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    info!("dag_driver: incoming_dag_block channel closed — stopping");
                    break;
                }
            }
        }

        // Process ONE self-authored DagBlock per iteration, then yield to the
        // tokio scheduler so other tasks get CPU.
        let dag_block = match next_block.take() {
            Some(b) => b,
            None => {
                // No self-authored block to propose — idle.
                // Peer blocks (if any) are still drained above on next iteration.
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

        // Feed into SurgeDriver. sig_ok = true (self-authored, trusted).
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

        // Process commits + new_round from self-authored block output.
        process_surge_output(
            output,
            &mut next_block,
            &db,
            &mempool,
            &batch_store,
            &batch_tx,
            &block_tx,
            &write_lock,
            &cfg,
            &keypair,
            &mut driver,
        )
        .await?;

        // Yield to the tokio scheduler so other tasks can run between DAG rounds.
        tokio::task::yield_now().await;
    }

    Ok(())
}

// ── process_surge_output ──────────────────────────────────────────────────────

/// Process the output of a `SurgeDriver::on_block` call.
///
/// Handles:
/// 1. **Equivocations** — logged; evidence deferred to Phase 3.
/// 2. **Commits** — for each commit: resolve txs → execute → build chain block
///    → persist → gossip → mempool post-commit.
/// 3. **New round** — build ancestors, gossip batch, build DagBlock → set `next_block`.
///
/// Called from BOTH the self-authored path AND the peer-block path (DRY — AGENTS §2.1).
///
/// ## Error policy
///
/// - Persist errors (`commit_block`) → `Err` (fatal — Sui-stall lesson).
/// - Build errors (`build_block_from_commit`) → `WARN` + skip (transient).
/// - `build_dag_block` errors → `WARN` + skip (non-fatal for round advancement).
///
/// # Errors
///
/// Returns [`NodeError`] only for fatal persist errors.
#[allow(clippy::too_many_arguments)]
async fn process_surge_output(
    output: lemma_consensus::SurgeOutput,
    next_block: &mut Option<DagBlock>,
    db: &Arc<LemmaDb>,
    mempool: &Arc<RwLock<Mempool>>,
    batch_store: &BatchStore,
    batch_tx: &Option<mpsc::Sender<Vec<u8>>>,
    block_tx: &Option<mpsc::Sender<Block>>,
    write_lock: &Arc<Mutex<()>>,
    cfg: &DagConfig,
    keypair: &Arc<KeyPair>,
    driver: &mut SurgeDriver,
) -> Result<(), NodeError> {
    // Log equivocations. Evidence construction deferred to Phase 3.
    for equiv in &output.equivocations {
        warn!(equivocation = ?equiv, "dag_driver: equivocation detected — evidence deferred to Phase 3");
    }

    // Process commits: resolve txs from sub-DAG, execute, build chain blocks.
    let chain = ChainStore::new(db);
    for commit in &output.commits {
        // Resolve txs from the committed sub-DAG (C·Step 14).
        // Takes a read-lock snapshot of the store (non-blocking).
        let txs: Vec<Transaction> = {
            let store = batch_store.read().await;
            resolve_committed_txs(commit, driver.dag(), &store)
        };

        match build_block_from_commit(commit, &chain, cfg.proposer, Arc::clone(db), txs) {
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

    // If this block triggered a clock advance, build the next round's batch
    // + DagBlock. We store it in `next_block` and YIELD first so other
    // tasks (block_rx receiver, network dispatch, mempool writes) can run.
    if let Some(new_round) = output.new_round {
        let ancestors: Vec<DagBlockRef> = driver
            .dag()
            .blocks_at_round(new_round - 1)
            .map(|b| b.reference())
            .collect();
        let ts = current_unix_millis();

        // Build + gossip batch for the new round, then embed its ref.
        let payload =
            build_and_gossip_batch(mempool, cfg.proposer, batch_store, batch_tx, new_round).await;

        match build_dag_block(
            new_round,
            cfg.proposer,
            ancestors,
            payload,
            cfg.epoch,
            ts,
            keypair,
        ) {
            Ok(b) => *next_block = Some(b),
            Err(e) => {
                warn!(
                    round = new_round,
                    error = %e,
                    "dag_driver: build_dag_block failed — skipping round"
                );
            }
        }
    }

    Ok(())
}

// ── Private helpers ───────────────────────────────────────────────────────────

/// Drain the mempool into a [`Batch`], pin it in `batch_store`, gossip it on
/// `lemma/batch/1` (via `batch_tx`), and return the `TxBatchRef` payload for
/// the next `DagBlock`.
///
/// Returns `vec![]` when the mempool is empty (an empty batch advances the
/// clock with no execution overhead — no need to gossip zero-tx batches).
///
/// Failures are non-fatal and logged:
/// - `Batch::to_ref()` errors (serialization) → `warn!`, return `[]`.
/// - `batch_tx.try_send()` overflow / closure → `debug!` (no peers in Phase 2).
async fn build_and_gossip_batch(
    mempool: &RwLock<Mempool>,
    author: Address,
    batch_store: &BatchStore,
    batch_tx: &Option<mpsc::Sender<Vec<u8>>>,
    round: u64,
) -> Vec<lemma_consensus::dag::block::TxBatchRef> {
    use crate::block_exec::MAX_TXS_PER_BLOCK;

    // Drain mempool under a short read-lock (non-blocking).
    let txs: Vec<Transaction> = mempool
        .read()
        .await
        .pending_by_priority(MAX_TXS_PER_BLOCK)
        .into_iter()
        .cloned()
        .collect();

    if txs.is_empty() {
        // Empty round — no batch needed.
        return vec![];
    }

    let batch = Batch::new(author, txs);

    // Build the ref (digest + author + size).
    let batch_ref = match batch.to_ref() {
        Ok(r) => r,
        Err(e) => {
            warn!(round, error = %e, "dag_driver: batch.to_ref failed — empty payload");
            return vec![];
        }
    };

    let digest = batch_ref.digest;

    // Pin in store before gossiping — resolvers look up by digest.
    batch_store.write().await.insert(digest, batch.clone());

    // Gossip the batch on lemma/batch/1 (non-fatal: no peers in single-node).
    if let Some(ref tx) = batch_tx {
        match serde_json::to_vec(&batch) {
            Ok(bytes) => {
                if let Err(e) = tx.try_send(bytes) {
                    debug!(round, error = ?e, "batch_tx send failed (non-fatal)");
                }
            }
            Err(e) => {
                warn!(round, error = %e, "Batch JSON encode failed (non-fatal)");
            }
        }
    }

    debug!(
        round,
        tx_count = batch.txs.len(),
        digest   = %digest.to_hex(),
        "dag_driver: batch built and pinned"
    );

    vec![batch_ref]
}

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

/// Receive from the optional incoming DagBlock channel.
#[cfg(test)]
mod tests;
