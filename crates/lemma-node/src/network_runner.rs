//! Network event-dispatch loop for the Lemma node.
//!
//! ## Responsibilities
//!
//! [`run_network_dispatch`] bridges [`NetworkEvent`]s emitted by the P2P
//! swarm to the node's local state (chain store + mempool):
//!
//! | Event | Action |
//! |-------|--------|
//! | `BlockReceived` | Update highest-seen; apply if next height; issue range request if gap |
//! | `RangeRequest` | Serve blocks from `ChainStore::get_range` → `SendRangeResponse` |
//! | `TransactionReceived` | Convert ConsensusKey→PublicKey; `Mempool::admit` (D·15d) |
//! | `DagProposalReceived` | Decode → DagBlock; verify hybrid sig; forward `(block, sig_ok)` to dag_driver |
//! | `BatchReceived` | Decode → Batch; verify per-tx hash + sig gate (D·15d); pin in BatchStore |
//! | `CommitAckReceived` | Decode → CommitAckPayload; verify hybrid sig; forward `(ack, sig_ok)` to dag_driver (P4·Step 9) |
//! | `PeerConnected` / `PeerDisconnected` | Log peer lifecycle |
//! | `ListeningOn` | Log local listen address |
//!
//! [`run_block_broadcaster`] drains the committed-block channel from the
//! producer and forwards each block to the gossip mesh.
//!
//! ## Range-sync consumer (N6)
//!
//! `BlockReceived` now drives catch-up:
//! 1. Every received block (gossip or range-response fan-out) updates the
//!    [`SyncTracker`] `highest_seen` watermark.
//! 2. If `block.height() == local_tip + 1` → [`apply_synced_block`] (structural
//!    verify + write under shared write-lock).
//! 3. If `block.height() > local_tip + 1` and gap not already in flight →
//!    `NetworkHandle::request_range` to the peer that announced the gap.
//!
//! Both gossiped blocks and range-response blocks arrive as `BlockReceived`
//! (the network service fans out each block in a `RangeResponse` individually).
//! The same handler covers both paths.
//!
//! ## Gossip tx admission (D·15d — CLOSED)
//!
//! **`TransactionReceived` now calls `Mempool::admit`**: `GossipMessage::NewTransaction`
//! carries `sender_pubkey: ConsensusKey` (D·15d). The node layer converts
//! `ConsensusKey → PublicKey` (AGENTS §8 build-order) and calls `Mempool::admit`,
//! which runs the full 8-step pipeline including Ed25519 + ML-DSA-65 sig verify.
//! Admission errors are non-fatal — logged at debug, node continues.
//! C·Step 13-residual-2 is CLOSED.
//!
//! ## DAG proposal dispatch (D·15b-1)
//!
//! `DagProposalReceived` is now fully handled:
//! 1. Decode JSON bytes → `DagBlock`.
//! 2. Look up the block's `author` in `vset` (the current epoch's `ValidatorSet`).
//! 3. Verify the hybrid signature (Ed25519 + ML-DSA-65) via `lemma_crypto::verify`.
//!    Unknown authors and `Signature::Unsigned` blocks yield `sig_ok = false`.
//! 4. Forward `(block, sig_ok)` to `incoming_dag_block_tx` for the DAG driver.
//!
//! The `bool` injection pattern (B3-2) keeps `lemma-consensus` crypto-free:
//! the consensus layer never calls `lemma-crypto` directly.
//!
//! **`BlockReceived` apply uses `CertifiedVerifier`** (D·15c): structural
//! checks + QuorumCert 2f+1 verification. Peers serving invalid QC are
//! demoted via `PeerEvent::InvalidQuorumCert` (spec 12 §5).
//!
//! ## Write-lock contract
//!
//! `apply_synced_block` and the producer's `commit_block` both acquire
//! `write_lock: Arc<Mutex<()>>` before writing. This serializes the two
//! concurrent writers (per `chain.rs` §Tip race under concurrent writers).

use std::sync::Arc;

use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

use lemma_consensus::{commit_ack::CommitAckPayload, dag::block::DagBlock};
use lemma_core::{block::Block, signature::Signature, validator_set::ValidatorSet};
use lemma_crypto::{verify as verify_hybrid, HybridSignature, PublicKey};
use lemma_mempool::pool::Mempool;
use lemma_network::{
    config::DEFAULT_MAX_RANGE,
    messages::RangeRequest,
    service::{NetworkEvent, NetworkHandle},
};
use lemma_storage::{chain::ChainStore, db::LemmaDb, state::WorldState};

use crate::{
    batch::{Batch, BatchStore},
    error::NodeError,
    sync::{apply_synced_block, ApplyOutcome, BlockVerifier, CertifiedVerifier, SyncTracker},
};

use lemma_crypto::compute_tx_hash;

// ── run_network_dispatch ──────────────────────────────────────────────────────

/// Sync-retry interval: re-issue a range request even if no new `BlockReceived`
/// arrives (handles partial responses and short-served chunks).
///
/// 5 s is conservative for Phase 1 (a producing node makes a block every 0.5 s).
/// Phase 2 can tune this downward once the sync mechanism is load-tested.
const SYNC_RETRY_INTERVAL_MS: u64 = 5_000;

/// Drive the `NetworkEvent` dispatch loop until `event_rx` closes or shutdown.
///
/// ## Sync retry tick
///
/// In addition to reacting to `BlockReceived` events, the loop fires a
/// periodic `sync_tick` every [`SYNC_RETRY_INTERVAL_MS`] milliseconds.
/// On each tick it re-evaluates `SyncTracker::next_request` against the
/// current local tip and re-issues a range request if a gap remains.
///
/// This prevents catch-up from wedging on partial responses (a peer that
/// serves only a prefix of the requested range) or on missing events
/// (12-NETWORK_SYNC_SPEC §2.2: "request timeout, re-requested elsewhere").
/// The design mirrors Aptos `continuous_syncer::drive_progress` and Sui's
/// `maybe_start_checkpoint_summary_sync_task` periodic re-triggers.
///
/// ## DAG proposal dispatch (D·15b-1)
///
/// `vset` is the current epoch's `ValidatorSet`. It is used to look up the
/// author's `ConsensusKey` for hybrid signature verification. Unknown authors
/// yield `sig_ok = false` (not a crash — AGENTS §7.2).
///
/// `incoming_dag_block_tx` carries `(DagBlock, sig_ok)` to the DAG driver.
/// Pass `None` to disable DAG proposal forwarding (single-node mode or tests
/// that don't need it).
///
/// # Parameters
///
/// - `write_lock` — shared with the producer; serializes `put_block` writes.
///
/// Returns `Ok(())` when `event_rx` closes (all `NetworkHandle` clones
/// dropped → `NetworkService` stopped → channel closed).
///
/// # Errors
///
/// Returns [`NodeError`] if a `SendRangeResponse` command dispatch fails.
/// Apply errors from structural verify failure are logged and non-fatal.
#[allow(clippy::too_many_arguments)] // 10 params: db + mempool + batch_store + handle + write_lock + event_rx + shutdown + vset + dag_block_tx + commit_ack_tx; no natural grouping without a dedicated context struct (deferred to Phase 3 refactor)
pub async fn run_network_dispatch(
    db: Arc<LemmaDb>,
    mempool: Arc<RwLock<Mempool>>,
    batch_store: BatchStore,
    handle: NetworkHandle,
    write_lock: Arc<Mutex<()>>,
    mut event_rx: mpsc::Receiver<NetworkEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    vset: ValidatorSet,
    incoming_dag_block_tx: Option<mpsc::Sender<(DagBlock, bool)>>,
    // Channel for forwarding decoded + sig-verified `CommitAckPayload`s to
    // the DAG driver (P4·Step 9). Pass `None` in single-node mode or tests
    // that don't need commit-ack gossip.
    incoming_commit_ack_tx: Option<mpsc::Sender<(CommitAckPayload, bool)>>,
) -> Result<(), NodeError> {
    let verifier = CertifiedVerifier::new(vset.clone());
    let mut tracker = SyncTracker::new();
    let mut sync_tick =
        tokio::time::interval(std::time::Duration::from_millis(SYNC_RETRY_INTERVAL_MS));
    // Skip missed ticks: if the loop was busy, don't burst catch-up requests.
    sync_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            event = event_rx.recv() => {
                match event {
                    Some(e) => {
                        handle_network_event(
                            e, &db, &mempool, &batch_store, &handle,
                            &write_lock, &verifier, &mut tracker,
                            &vset, &incoming_dag_block_tx, &incoming_commit_ack_tx,
                        ).await?;
                    }
                    None => {
                        info!("network_runner: event channel closed — stopping dispatch");
                        break;
                    }
                }
            }

            _ = sync_tick.tick() => {
                // Periodic retry: re-issue a range request if we're still behind.
                // This unsticks catch-up after a partial response or lost block.
                // Uses the last-seen peer from tracker (Phase 1: any peer works;
                // Phase 2 will add peer scoring for selection).
                if let Some(last_peer) = tracker.last_seen_peer() {
                    if let Ok(Some((tip_h, _))) = ChainStore::new(&db).tip() {
                        maybe_request_range(tip_h, &last_peer, &mut tracker, &handle).await;
                    }
                }
            }

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("network_runner: shutdown signal received — stopping dispatch");
                    break;
                }
            }
        }
    }

    Ok(())
}

// ── run_block_broadcaster ─────────────────────────────────────────────────────

/// Forward committed blocks from the producer channel to the gossip mesh.
///
/// See module-level doc for the Sui-CoreSignals channel-seam rationale.
pub async fn run_block_broadcaster(
    handle: NetworkHandle,
    mut block_rx: mpsc::Receiver<Block>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            block = block_rx.recv() => {
                match block {
                    Some(b) => {
                        let height = b.height();
                        if let Err(e) = handle.broadcast_block(b).await {
                            debug!(height, error = %e, "broadcast_block failed (non-fatal)");
                        } else {
                            debug!(height, "block gossiped to mesh");
                        }
                    }
                    None => {
                        info!("network_runner: block channel closed — stopping broadcaster");
                        break;
                    }
                }
            }

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("network_runner: shutdown — stopping broadcaster");
                    break;
                }
            }
        }
    }
}

// ── run_commit_ack_broadcaster ────────────────────────────────────────────────

/// Forward own commit-ack bytes from the dag_driver to the gossip mesh
/// (P4·Step 9 — multi-signer QuorumCert).
///
/// Drains `commit_ack_rx` (JSON-encoded `CommitAckPayload` bytes produced by
/// `dag_driver`) and calls `NetworkHandle::broadcast_commit_ack` to publish on
/// `lemma/commit-ack/1`. Same pattern as `run_batch_broadcaster` (C·Step 14).
///
/// Non-fatal: broadcast failures are logged at `debug` and the loop continues.
pub async fn run_commit_ack_broadcaster(
    handle: NetworkHandle,
    mut commit_ack_rx: mpsc::Receiver<Vec<u8>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            bytes = commit_ack_rx.recv() => {
                match bytes {
                    Some(b) => {
                        if let Err(e) = handle.broadcast_commit_ack(b).await {
                            debug!(error = %e, "broadcast_commit_ack failed (non-fatal)");
                        }
                    }
                    None => {
                        info!("network_runner: commit_ack channel closed — stopping broadcaster");
                        break;
                    }
                }
            }

            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    info!("network_runner: shutdown — stopping commit-ack broadcaster");
                    break;
                }
            }
        }
    }
}

// ── Event handlers ────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)] // 11 params: event + shared-state refs + DAG dispatch + commit-ack; no natural grouping
async fn handle_network_event(
    event: NetworkEvent,
    db: &Arc<LemmaDb>,
    mempool: &Arc<RwLock<Mempool>>,
    batch_store: &BatchStore,
    handle: &NetworkHandle,
    write_lock: &Arc<Mutex<()>>,
    verifier: &dyn BlockVerifier,
    tracker: &mut SyncTracker,
    vset: &ValidatorSet,
    incoming_dag_block_tx: &Option<mpsc::Sender<(DagBlock, bool)>>,
    incoming_commit_ack_tx: &Option<mpsc::Sender<(CommitAckPayload, bool)>>,
) -> Result<(), NodeError> {
    match event {
        // ── Block received (gossip or range-response fan-out) ─────────────────
        NetworkEvent::BlockReceived { from, block } => {
            handle_block_received(from, *block, db, handle, write_lock, verifier, tracker).await?;
        }

        // ── Inbound range request — serve from ChainStore ────────────────────
        NetworkEvent::RangeRequest {
            from,
            request,
            channel,
        } => {
            serve_range_request(from, request, channel, db, handle).await?;
        }

        // ── Inbound transaction — gossip admission (D·15d — CLOSED) ─────────
        //
        // `GossipMessage::NewTransaction` now carries `sender_pubkey` (D·15d).
        // Convert `ConsensusKey → PublicKey` at the node layer (AGENTS §8
        // build-order: lemma-network cannot depend on lemma-crypto).
        // Admission errors are non-fatal — log at debug and continue.
        // A rejected tx is not a node error; the peer may retry or the tx
        // may be invalid (bad sig, wrong chain_id, insufficient balance, etc.).
        NetworkEvent::TransactionReceived {
            from,
            tx,
            sender_pubkey,
        } => {
            // Deref Box<ConsensusKey> → ConsensusKey for the handler.
            handle_transaction_received(from, *tx, *sender_pubkey, db, mempool).await;
        }

        // ── Inbound DAG proposal — decode + sig-verify + forward (D·15b-1) ───
        //
        // 1. Decode JSON bytes → DagBlock.
        // 2. Look up author in vset → ConsensusKey → PublicKey.
        // 3. Verify hybrid signature (Ed25519 + ML-DSA-65).
        //    Unknown author or Signature::Unsigned → sig_ok = false.
        // 4. Forward (block, sig_ok) to dag_driver via incoming_dag_block_tx.
        //
        // B3-2 pattern: consensus never calls lemma-crypto directly.
        // All failure paths log + continue — no crash on malformed peer input
        // (AGENTS §7.2 / spec 12 §1.2).
        NetworkEvent::DagProposalReceived { from, bytes } => {
            handle_dag_proposal_received(from, bytes, vset, incoming_dag_block_tx).await;
        }

        // ── Inbound batch — verify + pin in BatchStore (C·Step 14 + D·15d) ──
        //
        // Decode JSON bytes → Batch, verify per-tx hash integrity + envelope
        // digest, then pin by digest key. Peers must receive and pin batches
        // BEFORE the referencing DagBlock is committed, so TxBatchRef →
        // Vec<Transaction> resolution succeeds at commit time.
        //
        // D·15d SECURITY GATE: `Signature::Unsigned` txs in a batch are
        // rejected (the whole batch is dropped). For validator-set senders,
        // full sig verify is performed via ConsensusKey → PublicKey → verify.
        // For non-vset senders (regular users), hash integrity is verified
        // (already done) but full sig verify requires the sender's pubkey
        // which is not in the batch wire format — documented limitation for
        // Phase 2 (batch txs from gossip must come from the proposer's mempool
        // where they were already sig-verified at admission time).
        NetworkEvent::BatchReceived { from, bytes } => {
            handle_batch_received(from, bytes, batch_store, vset).await;
        }

        // ── Inbound batch-fetch request — serve from BatchStore (D·15e) ──────
        //
        // A peer is requesting a batch by digest. Look it up in the local
        // BatchStore and respond with the JSON bytes (or None if not available).
        // Non-fatal: if the batch is not available, respond with None so the
        // requester can try another peer.
        NetworkEvent::BatchFetchRequest {
            from,
            digest,
            channel,
        } => {
            serve_batch_fetch_request(from, digest, channel, batch_store, handle).await;
        }

        // ── Inbound batch-fetch response — decode + verify + pin (D·15e) ─────
        //
        // A peer responded to our batch-fetch request. Decode, verify per-tx
        // hash integrity, and pin in BatchStore (same verification as
        // handle_batch_received, but using the known digest as the store key).
        NetworkEvent::BatchFetchResponse {
            from,
            digest,
            batch_bytes,
        } => {
            handle_batch_fetch_response(from, digest, batch_bytes, batch_store).await;
        }

        // ── Inbound commit-ack — decode + sig-verify + forward (P4·Step 9) ──
        //
        // 1. Decode JSON bytes → CommitAckPayload.
        // 2. Look up signer in vset → ConsensusKey → PublicKey.
        // 3. Verify hybrid signature (Ed25519 + ML-DSA-65) over the
        //    domain-separated message: blake3(b"commit-ack" || height_le || digest).
        //    Unknown signer or Signature::Unsigned → sig_ok = false.
        // 4. Forward (ack, sig_ok) to dag_driver via incoming_commit_ack_tx.
        //
        // B3-2 pattern: consensus never calls lemma-crypto directly.
        // All failure paths log + continue — no crash on malformed peer input
        // (AGENTS §7.2 / spec 12 §1.2).
        NetworkEvent::CommitAckReceived { from, bytes } => {
            handle_commit_ack_received(from, bytes, vset, incoming_commit_ack_tx).await;
        }

        // ── Peer lifecycle ────────────────────────────────────────────────────
        NetworkEvent::PeerConnected(peer_id) => {
            info!(peer = %peer_id, "peer connected");
        }
        NetworkEvent::PeerDisconnected(peer_id) => {
            info!(peer = %peer_id, "peer disconnected");
        }
        NetworkEvent::ListeningOn(addr) => {
            info!(addr = %addr, "node listening on {addr}");
        }
    }

    Ok(())
}

// ── Block-received handler (N6 range-sync consumer) ──────────────────────────

/// Handle a `BlockReceived` event — the core of the N6 catch-up logic.
///
/// 1. Update `tracker.highest_seen`.
/// 2. If `height == local_tip + 1` → apply (structural + QC verify + write).
/// 3. If `height > local_tip + 1` and gap not in flight → issue `RequestRange`.
/// 4. If `height <= local_tip` → already have it, skip.
///
/// ## QC failure handling (D·15c)
///
/// If `apply_synced_block` returns `NodeError::InvalidQC`, the serving peer
/// is demoted via `NetworkHandle::report_peer(PeerEvent::InvalidQuorumCert)`.
/// This is non-fatal — the block is discarded and the node retries from
/// another peer (spec 12 §5).
async fn handle_block_received(
    from: libp2p::PeerId,
    block: Block,
    db: &Arc<LemmaDb>,
    handle: &NetworkHandle,
    write_lock: &Arc<Mutex<()>>,
    verifier: &dyn BlockVerifier,
    tracker: &mut SyncTracker,
) -> Result<(), NodeError> {
    use lemma_network::peer::PeerEvent;

    let height = block.height();
    tracker.observe(height, from);

    // Read local tip (lightweight, outside lock).
    let local_tip = ChainStore::new(db).tip()?;
    let tip_height = local_tip.map(|(h, _)| h).unwrap_or(0);

    match height.cmp(&(tip_height + 1)) {
        std::cmp::Ordering::Equal => {
            // Block is exactly the next expected height — try to apply.
            match apply_synced_block(&block, db, write_lock, verifier).await {
                Ok(ApplyOutcome::Applied { height: h, .. }) => {
                    info!(height = h, peer = %from, "applied synced block");
                    tracker.on_tip_advanced(h);
                    // After applying, check if still behind and need more.
                    maybe_request_range(tip_height + 1, &from, tracker, handle).await;
                }
                Ok(ApplyOutcome::Stale) => {
                    debug!(height, "block stale — producer advanced while verifying");
                }
                Ok(ApplyOutcome::NoTip) => {
                    debug!(height, "no chain tip — genesis not yet written");
                }
                Err(NodeError::InvalidQC(_)) => {
                    // QC verification failed — demote the serving peer.
                    // Non-fatal: discard block, retry from another peer.
                    warn!(height, peer = %from, "invalid QC from peer — demoting");
                    if let Err(e) = handle.report_peer(from, PeerEvent::InvalidQuorumCert).await {
                        debug!(error = %e, "report_peer failed (non-fatal — node shutting down)");
                    }
                }
                Err(NodeError::Verify(_)) => {
                    // Structural verify failed — already logged in apply_synced_block.
                    // Non-fatal: discard, potentially demote peer.
                }
                Err(e) => {
                    // Storage error — fatal.
                    return Err(e);
                }
            }
        }
        std::cmp::Ordering::Greater => {
            // Gap detected — request missing blocks from the announcing peer.
            maybe_request_range(tip_height, &from, tracker, handle).await;
        }
        std::cmp::Ordering::Less => {
            // Already have this height.
            debug!(
                height,
                local_tip = tip_height,
                "received block already in chain"
            );
        }
    }

    Ok(())
}

/// Issue a `RequestRange` to `peer` for the next chunk of missing blocks,
/// if the tracker determines one is needed.
async fn maybe_request_range(
    local_tip: u64,
    peer: &libp2p::PeerId,
    tracker: &mut SyncTracker,
    handle: &NetworkHandle,
) {
    if let Some((from_h, to_h)) = tracker.next_request(local_tip, DEFAULT_MAX_RANGE) {
        let req = RangeRequest::new(from_h, to_h);
        // Validate before dispatch: contract from NetworkHandle::request_range doc
        // (AGENTS §15.2). next_request clamps to DEFAULT_MAX_RANGE by construction,
        // so this should always pass — but the API demands an explicit check.
        if let Err(e) = req.validate(DEFAULT_MAX_RANGE) {
            warn!(
                from = from_h, to = to_h,
                error = %e,
                "BUG: next_request produced invalid range — skipping"
            );
            tracker.on_tip_advanced(local_tip); // reset watermark so retry is possible
            return;
        }
        match handle.request_range(*peer, req).await {
            Ok(()) => {
                info!(
                    from = from_h, to = to_h,
                    peer = %peer,
                    "issued range request"
                );
            }
            Err(e) => {
                warn!(
                    from = from_h, to = to_h,
                    peer = %peer,
                    error = %e,
                    "request_range failed (non-fatal — will retry on next block)"
                );
                // Reset the watermark so the request will be retried.
                tracker.on_tip_advanced(local_tip);
            }
        }
    }
}

// ── Range-request serve path ──────────────────────────────────────────────────

async fn serve_range_request(
    from: libp2p::PeerId,
    request: lemma_network::messages::RangeRequest,
    channel: libp2p::request_response::ResponseChannel<lemma_network::messages::RangeResponse>,
    db: &Arc<LemmaDb>,
    handle: &NetworkHandle,
) -> Result<(), NodeError> {
    use lemma_network::messages::RangeResponse;

    let blocks = fetch_range(db, &request);
    let block_count = blocks.len();
    let response = RangeResponse::new(blocks);

    handle.send_range_response(channel, response).await?;

    debug!(
        peer        = %from,
        from        = request.from_height,
        to          = request.to_height,
        block_count,
        "served range request"
    );

    Ok(())
}

/// Fetch blocks for a range request — pure storage helper.
///
/// Storage errors yield an empty response (non-fatal — requester retries).
pub(crate) fn fetch_range(
    db: &LemmaDb,
    request: &lemma_network::messages::RangeRequest,
) -> Vec<lemma_core::block::Block> {
    match ChainStore::new(db).get_range(request.from_height, request.to_height) {
        Ok(blocks) => blocks,
        Err(e) => {
            warn!(
                from  = request.from_height,
                to    = request.to_height,
                error = %e,
                "get_range failed — sending empty response"
            );
            vec![]
        }
    }
}

// ── DAG-proposal handler (D·15b-1) ───────────────────────────────────────────

/// Decode, sig-verify, and forward an inbound DAG proposal (D·15b-1).
///
/// ## Verification
///
/// 1. **Decode**: JSON bytes → `DagBlock`. Malformed bytes → drop + warn.
/// 2. **Author lookup**: `vset.members.get(&block.author)` → `ConsensusKey`.
///    Unknown author → `sig_ok = false` (not a crash).
/// 3. **Signature check**: only `Signature::Hybrid` is valid for consensus.
///    `Signature::Unsigned` or `Signature::Classical` → `sig_ok = false`.
///    Hybrid sig verified via `lemma_crypto::verify` (Ed25519 + ML-DSA-65).
/// 4. **Forward**: `(block, sig_ok)` sent to `incoming_dag_block_tx`.
///    Channel full → warn + drop (non-fatal; peer can re-gossip).
///    No channel wired → log only (single-node mode).
///
/// ## No panics
///
/// All failure paths return `()` after logging. A crafted payload must never
/// crash the node (AGENTS §7.2).
async fn handle_dag_proposal_received(
    from: libp2p::PeerId,
    bytes: Vec<u8>,
    vset: &ValidatorSet,
    incoming_dag_block_tx: &Option<mpsc::Sender<(DagBlock, bool)>>,
) {
    // ── 1. Decode JSON → DagBlock ─────────────────────────────────────────────
    let block: DagBlock = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                peer  = %from,
                error = %e,
                "DagProposalReceived: JSON decode failed — block dropped"
            );
            return;
        }
    };

    // ── 2. Author lookup + sig verification ───────────────────────────────────
    // Unknown author → sig_ok = false (not in current epoch's committee).
    // Signature::Unsigned or non-Hybrid → sig_ok = false (invalid for consensus).
    let sig_ok = match vset.members.get(&block.author) {
        None => {
            debug!(
                peer   = %from,
                author = %block.author,
                round  = block.round,
                "DagProposalReceived: author not in validator set — sig_ok=false"
            );
            false
        }
        Some(member) => {
            // Convert ConsensusKey → PublicKey for crypto verification.
            let pk = PublicKey::from(member.consensus_pubkey.clone());
            match &block.signature {
                Signature::Hybrid { classical, quantum } => {
                    let hybrid = HybridSignature {
                        classical: classical.clone(),
                        quantum: quantum.clone(),
                    };
                    verify_hybrid(&pk, block.digest.as_bytes(), &hybrid).is_ok()
                }
                // Unsigned or Classical-only = invalid for consensus.
                _ => {
                    debug!(
                        peer   = %from,
                        author = %block.author,
                        round  = block.round,
                        "DagProposalReceived: non-Hybrid signature — sig_ok=false"
                    );
                    false
                }
            }
        }
    };

    debug!(
        peer    = %from,
        round   = block.round,
        author  = %block.author,
        sig_ok,
        "DAG proposal received from peer"
    );

    // ── 3. Forward to dag_driver ──────────────────────────────────────────────
    if let Some(ref tx) = incoming_dag_block_tx {
        match tx.try_send((block, sig_ok)) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    peer  = %from,
                    "DagProposalReceived: incoming_dag_block channel full — block dropped (non-fatal)"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                debug!(peer = %from, "DagProposalReceived: dag_driver channel closed — block dropped");
            }
        }
    }
}

// ── Transaction-received handler (D·15d) ─────────────────────────────────────

/// Admit an inbound gossiped transaction into the local mempool (D·15d).
///
/// ## Verification
///
/// 1. **Key conversion**: `ConsensusKey → PublicKey` at the node layer
///    (AGENTS §8 build-order: lemma-network cannot depend on lemma-crypto).
/// 2. **Admission**: `Mempool::admit` runs the full 8-step pipeline including
///    `verify_transaction` (Ed25519 + ML-DSA-65 sig check, nonce, balance, etc.).
///    Rejection is non-fatal — log at debug and continue.
///
/// ## No panics
///
/// All failure paths return `()` after logging. A crafted payload must never
/// crash the node (AGENTS §7.2).
async fn handle_transaction_received(
    from: libp2p::PeerId,
    tx: lemma_core::transaction::Transaction,
    sender_pubkey: lemma_core::validator::ConsensusKey,
    db: &Arc<LemmaDb>,
    mempool: &Arc<RwLock<Mempool>>,
) {
    // Convert ConsensusKey → PublicKey (node layer, AGENTS §8 build-order).
    let pk = PublicKey::from(sender_pubkey);

    // Read current tip state root for WorldState.
    // If the chain is not yet initialized, discard the tx (non-fatal).
    let state_root = {
        let chain = ChainStore::new(db);
        match chain.tip() {
            Ok(Some((_, hash))) => match chain.get_block_by_hash(&hash) {
                Ok(Some(block)) => block.header.state_root,
                _ => {
                    debug!(
                        peer = %from,
                        tx   = %tx.hash.to_hex(),
                        "TransactionReceived: no tip block — discarding"
                    );
                    return;
                }
            },
            _ => {
                debug!(
                    peer = %from,
                    tx   = %tx.hash.to_hex(),
                    "TransactionReceived: chain not initialized — discarding"
                );
                return;
            }
        }
    };

    let world = WorldState::with_state_root(Arc::clone(db), state_root);
    let ctx = lemma_mempool::pool::AdmitContext {
        chain_id: tx.chain_id,
        // Phase 2: zero base fee (Burn Fee Model calibration deferred to Phase 3).
        base_fee: lemma_core::amount::Amount::zero(),
        now: std::time::Instant::now(),
    };

    match mempool.write().await.admit(
        tx,
        &pk,
        // sender_stake: zero for non-staked accounts (Phase 2 — no staking queries).
        lemma_core::amount::Amount::zero(),
        None::<&lemma_mempool::express::ExpressHint>, // no Express hint from gossip path
        &world,
        &ctx,
    ) {
        Ok(outcome) => {
            debug!(peer = %from, "TransactionReceived: admitted {:?}", outcome);
        }
        Err(e) => {
            debug!(
                peer  = %from,
                error = %e,
                "TransactionReceived: rejected by mempool (non-fatal)"
            );
        }
    }
}

// ── Batch-received handler ────────────────────────────────────────────────────

/// Decode, verify, and pin an inbound gossip batch (C·Step 14 + D·15d).
///
/// ## Verification layers
///
/// 1. **Size guard** (upstream): `GossipMessage::decode` enforces
///    `MAX_GOSSIP_DECODE_BYTES` before JSON parsing begins — this function
///    never sees an oversized payload (AGENTS §15.1).
/// 2. **Envelope integrity**: recomputes the batch digest from the decoded
///    struct and uses it as the store key. This closes the envelope-level
///    store-poisoning vector (peer sends a valid batch under a forged key).
/// 3. **Per-tx hash integrity**: recomputes each `Transaction.hash` from the
///    transaction body via [`compute_tx_hash`] and compares against the
///    wire value. A mismatch causes the whole batch to be rejected — this
///    makes `tx.hash` a trustworthy dedup key and prevents the
///    consensus-divergence vector described in `batch.rs` §Trust model.
/// 4. **Signature gate (D·15d — CLOSED)**:
///    - `Signature::Unsigned` txs → whole batch dropped (provably wrong).
///    - Validator-set senders: full Ed25519 + ML-DSA-65 sig verify via
///      `ConsensusKey → PublicKey → lemma_crypto::verify_transaction`.
///    - Non-vset senders (regular users): hash integrity verified (step 3);
///      full sig verify requires the sender's pubkey which is not in the
///      batch wire format. This is an intentional Phase 2 limitation:
///      batch txs from gossip come from the proposer's own mempool where
///      they were already sig-verified at admission time. Non-vset txs
///      submitted via RPC (Phase 4) will be sig-verified at the RPC layer.
///
/// ## No panics
///
/// All failure paths return `()` after logging. A crafted payload must never
/// crash the node (AGENTS §7.2).
async fn handle_batch_received(
    from: libp2p::PeerId,
    bytes: Vec<u8>,
    batch_store: &BatchStore,
    vset: &ValidatorSet,
) {
    // ── 1. Decode JSON → Batch ────────────────────────────────────────────────
    // Input is already bounded to ≤ MAX_GOSSIP_DECODE_BYTES by the upstream
    // `GossipMessage::decode` call in `NetworkService::handle_gossip_message`.
    let batch: Batch = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                peer  = %from,
                error = %e,
                "BatchReceived: JSON decode failed — batch dropped (peer misbehaviour)"
            );
            return;
        }
    };

    // ── 2. Per-tx hash integrity check ────────────────────────────────────────
    // Recompute each tx's canonical hash and compare against the wire value.
    // This makes `tx.hash` trustworthy as a dedup key in resolve_committed_txs.
    // A mismatch on ANY tx causes the WHOLE batch to be rejected — partial
    // acceptance would leave the store in an inconsistent state.
    for tx in &batch.txs {
        let expected = match compute_tx_hash(tx) {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    peer  = %from,
                    error = %e,
                    tx    = %tx.hash.to_hex(),
                    "BatchReceived: tx hash computation failed — batch dropped"
                );
                return;
            }
        };
        if expected != tx.hash {
            warn!(
                peer     = %from,
                expected = %expected.to_hex(),
                got      = %tx.hash.to_hex(),
                "BatchReceived: tx hash mismatch — batch dropped (forged tx.hash, \
                 peer misbehaviour — potential consensus-divergence attack)"
            );
            return;
        }
    }
    // ── SECURITY GATE (D·15d — CLOSED): per-tx signature verification ────────
    //
    // Layer 1: reject any tx with Signature::Unsigned — provably wrong.
    // Layer 2: for validator-set senders, full Ed25519 + ML-DSA-65 sig verify.
    // Layer 3: for non-vset senders, hash integrity is sufficient for Phase 2
    //          (batch txs come from the proposer's mempool, already sig-verified).
    for tx in &batch.txs {
        match &tx.signature {
            Signature::Unsigned => {
                // Unsigned tx in a batch is provably wrong — a well-formed
                // proposer never includes unsigned txs. Drop the whole batch.
                warn!(
                    peer = %from,
                    tx   = %tx.hash.to_hex(),
                    "BatchReceived: unsigned tx in batch — batch dropped (SECURITY GATE D·15d)"
                );
                return;
            }
            Signature::Hybrid { classical, quantum } => {
                // For validator-set senders: full sig verify.
                // For non-vset senders: hash integrity already verified above.
                if let Some(member) = vset.members.get(&tx.sender) {
                    let pk = PublicKey::from(member.consensus_pubkey.clone());
                    let hybrid = HybridSignature {
                        classical: classical.clone(),
                        quantum: quantum.clone(),
                    };
                    if verify_hybrid(&pk, tx.hash.as_bytes(), &hybrid).is_err() {
                        warn!(
                            peer   = %from,
                            tx     = %tx.hash.to_hex(),
                            sender = %tx.sender,
                            "BatchReceived: sig verify failed for vset sender — batch dropped (SECURITY GATE D·15d)"
                        );
                        return;
                    }
                }
                // Non-vset sender: hash integrity verified in step 2 above.
                // Full sig verify requires sender_pubkey not present in batch wire.
                // Intentional Phase 2 limitation — see function doc.
            }
            // Classical-only or PostQuantum-only: accepted for Phase 2 (non-vset
            // senders may use classical-only during transition). Hash integrity
            // already verified above.
            _ => {}
        }
    }

    // ── 3. Envelope digest → store key ───────────────────────────────────────
    // Recompute the batch digest AFTER per-tx hash validation so the digest is
    // computed over a batch whose tx hashes we've already verified.
    let digest = match batch.digest() {
        Ok(d) => d,
        Err(e) => {
            warn!(
                peer  = %from,
                error = %e,
                "BatchReceived: digest computation failed — batch dropped"
            );
            return;
        }
    };

    // ── 4. Pin in store (idempotent — same digest twice is harmless) ──────────
    let tx_count = batch.txs.len();
    batch_store.write().await.insert(digest, batch);

    debug!(
        peer      = %from,
        digest    = %digest.to_hex(),
        tx_count,
        "BatchReceived: batch verified and pinned in store"
    );
}

// ── Batch fetch-on-miss handlers (D·15e) ─────────────────────────────────────

/// Serve an inbound batch-fetch request from a peer.
///
/// Looks up the requested batch by digest in the local `BatchStore`.
/// Responds with the JSON-encoded batch bytes, or `None` if not available.
///
/// ## No panics
///
/// All failure paths are non-fatal — a failed response send is logged at
/// `debug` and the function returns `()`. A peer that times out or closes
/// the channel is not an error (AGENTS §7.2).
async fn serve_batch_fetch_request(
    from: libp2p::PeerId,
    digest: lemma_core::hash::Hash,
    channel: libp2p::request_response::ResponseChannel<lemma_network::messages::BatchFetchResponse>,
    batch_store: &BatchStore,
    handle: &NetworkHandle,
) {
    use lemma_network::messages::BatchFetchResponse;

    // Look up the batch in the local store (read-lock, non-blocking).
    let batch_bytes = {
        let store = batch_store.read().await;
        store
            .get(&digest)
            .and_then(|batch| serde_json::to_vec(batch).ok())
    };

    let available = batch_bytes.is_some();
    let response = BatchFetchResponse {
        digest,
        batch_bytes,
    };

    if let Err(e) = handle.send_batch_fetch_response(channel, response).await {
        // Non-fatal: channel may have closed if the requester timed out.
        debug!(
            peer      = %from,
            digest    = %digest.to_hex(),
            available,
            error     = %e,
            "serve_batch_fetch_request: send_batch_fetch_response failed (non-fatal)"
        );
    } else {
        debug!(
            peer      = %from,
            digest    = %digest.to_hex(),
            available,
            "batch_fetch: served request"
        );
    }
}

/// Handle an inbound batch-fetch response from a peer.
///
/// Decodes the batch bytes, verifies per-tx hash integrity (same as
/// `handle_batch_received`), and pins the batch in `BatchStore` using the
/// known digest as the key.
///
/// ## No panics
///
/// All failure paths return `()` after logging. A crafted payload must never
/// crash the node (AGENTS §7.2).
async fn handle_batch_fetch_response(
    from: libp2p::PeerId,
    digest: lemma_core::hash::Hash,
    batch_bytes: Option<Vec<u8>>,
    batch_store: &BatchStore,
) {
    let Some(bytes) = batch_bytes else {
        // Peer does not have the batch — try another peer (non-fatal).
        debug!(
            peer   = %from,
            digest = %digest.to_hex(),
            "batch_fetch: peer has no batch — try another peer"
        );
        return;
    };

    // ── Decode JSON → Batch ───────────────────────────────────────────────────
    let batch: crate::batch::Batch = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(e) => {
            warn!(
                peer   = %from,
                digest = %digest.to_hex(),
                error  = %e,
                "batch_fetch response: JSON decode failed — batch dropped"
            );
            return;
        }
    };

    // ── Per-tx hash integrity check ───────────────────────────────────────────
    // Recompute each tx's canonical hash and compare against the wire value.
    // Same verification as handle_batch_received — makes tx.hash trustworthy.
    for tx in &batch.txs {
        let expected = match compute_tx_hash(tx) {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    peer   = %from,
                    digest = %digest.to_hex(),
                    error  = %e,
                    "batch_fetch response: tx hash computation failed — batch dropped"
                );
                return;
            }
        };
        if expected != tx.hash {
            warn!(
                peer     = %from,
                digest   = %digest.to_hex(),
                expected = %expected.to_hex(),
                got      = %tx.hash.to_hex(),
                "batch_fetch response: tx hash mismatch — batch dropped (forged tx.hash)"
            );
            return;
        }
    }

    // ── Pin in store using the known digest as key ────────────────────────────
    // We already know the digest from the request, so we use it directly as the
    // store key (avoids re-serializing the batch just to recompute the digest).
    let tx_count = batch.txs.len();
    batch_store.write().await.insert(digest, batch);

    debug!(
        peer      = %from,
        digest    = %digest.to_hex(),
        tx_count,
        "batch_fetch: batch pinned from fetch response"
    );
}

// ── Commit-ack handler (P4·Step 9) ───────────────────────────────────────────

/// Decode, sig-verify, and forward an inbound commit-ack (P4·Step 9).
///
/// ## Verification
///
/// 1. **Decode**: JSON bytes → `CommitAckPayload`. Malformed bytes → drop + warn.
/// 2. **Signer lookup**: `vset.members.get(&ack.signer)` → `ConsensusKey`.
///    Unknown signer → `sig_ok = false` (not a crash).
/// 3. **Signature check**: only `Signature::Hybrid` is valid for consensus.
///    `Signature::Unsigned` or `Signature::Classical` → `sig_ok = false`.
///    Hybrid sig verified via `lemma_crypto::verify` over the domain-separated
///    message: `blake3(b"commit-ack" || height_le_u64 || header_digest)`.
/// 4. **Forward**: `(ack, sig_ok)` sent to `incoming_commit_ack_tx`.
///    Channel full → warn + drop (non-fatal; peer can re-gossip).
///    No channel wired → log only (single-node mode).
///
/// ## No panics (AGENTS §7.2)
///
/// All failure paths return `()` after logging. A crafted payload must never
/// crash the node.
async fn handle_commit_ack_received(
    from: libp2p::PeerId,
    bytes: Vec<u8>,
    vset: &ValidatorSet,
    incoming_commit_ack_tx: &Option<mpsc::Sender<(CommitAckPayload, bool)>>,
) {
    use lemma_consensus::commit_ack::commit_ack_message;

    // ── 1. Decode JSON → CommitAckPayload ────────────────────────────────────
    let ack: CommitAckPayload = match serde_json::from_slice(&bytes) {
        Ok(a) => a,
        Err(e) => {
            warn!(
                peer  = %from,
                error = %e,
                "CommitAckReceived: JSON decode failed — ack dropped"
            );
            return;
        }
    };

    // ── 2. Signer lookup + sig verification ──────────────────────────────────
    // Unknown signer → sig_ok = false (not in current epoch's committee).
    // Signature::Unsigned or non-Hybrid → sig_ok = false (invalid for consensus).
    let sig_ok = match vset.members.get(&ack.signer) {
        None => {
            debug!(
                peer   = %from,
                signer = %ack.signer,
                height = ack.height,
                "CommitAckReceived: signer not in validator set — sig_ok=false"
            );
            false
        }
        Some(member) => {
            // Compute the domain-separated message the signer should have signed.
            let msg = commit_ack_message(ack.height, &ack.header_digest);

            // Convert ConsensusKey → PublicKey for crypto verification.
            let pk = PublicKey::from(member.consensus_pubkey.clone());
            match &ack.signature {
                Signature::Hybrid { classical, quantum } => {
                    let hybrid = HybridSignature {
                        classical: classical.clone(),
                        quantum: quantum.clone(),
                    };
                    verify_hybrid(&pk, &msg, &hybrid).is_ok()
                }
                // Unsigned or Classical-only = invalid for consensus.
                _ => {
                    debug!(
                        peer   = %from,
                        signer = %ack.signer,
                        height = ack.height,
                        "CommitAckReceived: non-Hybrid signature — sig_ok=false"
                    );
                    false
                }
            }
        }
    };

    debug!(
        peer    = %from,
        signer  = %ack.signer,
        height  = ack.height,
        sig_ok,
        "commit-ack received from peer"
    );

    // ── 3. Forward to dag_driver ──────────────────────────────────────────────
    if let Some(ref tx) = incoming_commit_ack_tx {
        match tx.try_send((ack, sig_ok)) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    peer  = %from,
                    "CommitAckReceived: incoming_commit_ack channel full — ack dropped (non-fatal)"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                debug!(peer = %from, "CommitAckReceived: dag_driver channel closed — ack dropped");
            }
        }
    }
}

#[cfg(test)]
mod tests;
