//! Network event-dispatch loop for the Lemma node.
//!
//! ## Responsibilities
//!
//! [`run_network_dispatch`] bridges [`NetworkEvent`]s emitted by the P2P
//! swarm to the node's local state (chain store + mempool):
//!
//! | Event | Phase 1 action |
//! |-------|---------------|
//! | `BlockReceived` | Update highest-seen; apply if next height; issue range request if gap |
//! | `RangeRequest` | Serve blocks from `ChainStore::get_range` → `SendRangeResponse` |
//! | `TransactionReceived` | Log only — Phase 2 hook (needs WorldState context) |
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
//! ## Phase 1 scope limits
//!
//! **`TransactionReceived` is log-only**: [`Mempool::admit`] requires
//! `WorldState`, sender `PublicKey`, `sender_stake`, and `AdmitContext`
//! (`base_fee`, `chain_id`) — not available here until Phase 2 (VM live).
//!
//! **`BlockReceived` apply is structural-only** (no QC): the `BlockVerifier`
//! trait seam is in `sync.rs`; Phase 2 adds `CertifiedVerifier`.
//!
//! ## Write-lock contract
//!
//! `apply_synced_block` and the producer's `commit_block` both acquire
//! `write_lock: Arc<Mutex<()>>` before writing. This serializes the two
//! concurrent writers (per `chain.rs` §Tip race under concurrent writers).

use std::sync::Arc;

use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, info, warn};

use lemma_core::block::Block;
use lemma_mempool::pool::Mempool;
use lemma_network::{
    config::DEFAULT_MAX_RANGE,
    messages::RangeRequest,
    service::{NetworkEvent, NetworkHandle},
};
use lemma_storage::db::LemmaDb;

use crate::{
    error::NodeError,
    sync::{apply_synced_block, ApplyOutcome, StructuralVerifier, SyncTracker},
};

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
pub async fn run_network_dispatch(
    db: Arc<LemmaDb>,
    mempool: Arc<RwLock<Mempool>>,
    handle: NetworkHandle,
    write_lock: Arc<Mutex<()>>,
    mut event_rx: mpsc::Receiver<NetworkEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), NodeError> {
    let verifier = StructuralVerifier;
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
                            e, &db, &mempool, &handle,
                            &write_lock, &verifier, &mut tracker,
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
                    use lemma_storage::chain::ChainStore;
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

// ── Event handlers ────────────────────────────────────────────────────────────

async fn handle_network_event(
    event: NetworkEvent,
    db: &Arc<LemmaDb>,
    _mempool: &Arc<RwLock<Mempool>>,
    handle: &NetworkHandle,
    write_lock: &Arc<Mutex<()>>,
    verifier: &StructuralVerifier,
    tracker: &mut SyncTracker,
) -> Result<(), NodeError> {
    match event {
        // ── Block received (gossip or range-response fan-out) ─────────────────
        NetworkEvent::BlockReceived { from, block } => {
            handle_block_received(from, block, db, handle, write_lock, verifier, tracker).await?;
        }

        // ── Inbound range request — serve from ChainStore ────────────────────
        NetworkEvent::RangeRequest {
            from,
            request,
            channel,
        } => {
            serve_range_request(from, request, channel, db, handle).await?;
        }

        // ── Inbound transaction — Phase 1: log only ───────────────────────────
        //
        // Phase 2 forward note: full admission requires WorldState + sender
        // PublicKey + sender_stake + AdmitContext { chain_id, base_fee }.
        NetworkEvent::TransactionReceived { from, tx } => {
            debug!(
                peer = %from,
                tx   = %tx.hash.to_hex(),
                "gossiped tx received (not admitted — Phase 2 hook)"
            );
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
/// 2. If `height == local_tip + 1` → apply (structural verify + write).
/// 3. If `height > local_tip + 1` and gap not in flight → issue `RequestRange`.
/// 4. If `height <= local_tip` → already have it, skip.
async fn handle_block_received(
    from: libp2p::PeerId,
    block: Block,
    db: &Arc<LemmaDb>,
    handle: &NetworkHandle,
    write_lock: &Arc<Mutex<()>>,
    verifier: &StructuralVerifier,
    tracker: &mut SyncTracker,
) -> Result<(), NodeError> {
    use lemma_storage::chain::ChainStore;

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
                Err(NodeError::Verify(_)) => {
                    // Structural verify failed — already logged in apply_synced_block.
                    // Non-fatal: discard, potentially demote peer (Phase 2).
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
    use lemma_storage::chain::ChainStore;

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

#[cfg(test)]
mod tests;
