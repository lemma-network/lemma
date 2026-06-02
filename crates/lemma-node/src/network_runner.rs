//! Network event-dispatch loop for the Lemma node.
//!
//! ## Responsibilities
//!
//! [`run_network_dispatch`] bridges [`NetworkEvent`]s emitted by the P2P
//! swarm to the node's local state:
//!
//! | Event | Phase 1 action | Phase 2 |
//! |-------|---------------|---------|
//! | `TransactionReceived` | Log only — see Phase 2 note | Full `Mempool::admit` with state |
//! | `RangeRequest` | Serve from `ChainStore::get_range` | Same |
//! | `BlockReceived` | Log only — no QC verify | Verify QC → extend chain |
//! | `PeerConnected` / `PeerDisconnected` | Log peer lifecycle | Same |
//! | `ListeningOn` | Log local listen address | Same |
//!
//! A companion task ([`run_block_broadcaster`]) drains the committed-block
//! channel filled by the producer and forwards each block to the gossip mesh
//! via `NetworkHandle::broadcast_block`.
//!
//! ## Phase 1 scope limits
//!
//! **`TransactionReceived` is log-only in Phase 1.**
//! [`Mempool::admit`] requires `WorldState` (nonce/balance check), the
//! sender's `PublicKey` (signature verify), `sender_stake`, and an
//! [`AdmitContext`](lemma_mempool::pool::AdmitContext) with `base_fee` and
//! `chain_id`. None of these are available in the network-dispatch task
//! without wiring `WorldState` through. Since Phase 1 blocks are empty
//! (no VM execution), admitted txs do not participate in block building
//! anyway — full gossiped-tx ingestion is a Phase 2 hook.
//!
//! **`BlockReceived` is log-only in Phase 1.**
//! Applying a gossiped block requires verifying the `QuorumCert` (Phase 2:
//! see `07-CONSENSUS_SPEC §4.3`). Until then, gossip is treated as a hint.
//!
//! ## Separation of concerns
//!
//! - **Producer** → emits committed `Block`s onto an `mpsc::Sender<Block>`.
//!   It does NOT import or hold a `NetworkHandle` (AGENTS §8 dependency
//!   direction: producer depends on core types only).
//! - **`run_block_broadcaster`** → bridges the committed-block channel to the
//!   network. Owns the `NetworkHandle` clone for block gossip.
//! - **`run_network_dispatch`** → owns the event receiver and handles inbound
//!   P2P events. Owns a `NetworkHandle` clone for `SendRangeResponse`.
//!
//! This mirrors the Sui Mysticeti pattern (`CoreSignals`/`CoreSignalsReceivers`):
//! the production unit is emitted onto a channel; subscribers handle
//! dissemination independently.
//!
//! ## Phase 2 forward note
//!
//! In Phase 2, the producer loop is replaced by the Surge/Pulse DAG consensus
//! driver. The `mpsc::Sender<Block>` channel established here carries the
//! committed-execution result — this is the surviving seam.
//! A SEPARATE broadcast channel for `DagBlock` (the gossip unit) will be
//! added alongside it, mirroring Sui's dual-channel pattern.
//!
//! ## DoS contract
//!
//! - `RangeRequest` handling: already validated by `NetworkService` before
//!   emitting the event; only stored blocks are returned.
//! - `TransactionReceived` / `BlockReceived`: log-only, no allocation
//!   proportional to payload size.

use std::sync::Arc;

use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, warn};

use lemma_core::block::Block;
use lemma_mempool::pool::Mempool;
use lemma_network::{
    service::{NetworkEvent, NetworkHandle},
};
use lemma_storage::db::LemmaDb;

use crate::error::NodeError;

// ── run_network_dispatch ──────────────────────────────────────────────────────

/// Drive the `NetworkEvent` dispatch loop until `event_rx` closes or shutdown.
///
/// Handles all inbound P2P events — see module-level table for per-event
/// Phase 1 behaviour. Returns `Ok(())` when `event_rx` closes (all
/// `NetworkHandle` clones dropped → `NetworkService` stopped → channel closed).
///
/// # Errors
///
/// Returns [`NodeError::Network`] if a `SendRangeResponse` command dispatch
/// fails (command channel closed — indicates the network service has stopped).
pub async fn run_network_dispatch(
    db: Arc<LemmaDb>,
    mempool: Arc<RwLock<Mempool>>,
    handle: NetworkHandle,
    mut event_rx: mpsc::Receiver<NetworkEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), NodeError> {
    loop {
        tokio::select! {
            event = event_rx.recv() => {
                match event {
                    Some(e) => handle_network_event(e, &db, &mempool, &handle).await?,
                    // Channel closed: NetworkService has stopped → clean exit.
                    None => {
                        info!("network_runner: event channel closed — stopping dispatch");
                        break;
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
/// The producer emits each committed `Block` onto `block_rx`; this task
/// drains the channel and calls `NetworkHandle::broadcast_block` for each.
///
/// Broadcast failures are logged but non-fatal: peers may not yet be
/// subscribed (startup), or the network service may be shutting down.
/// Returns when `block_rx` closes (producer stopped) or shutdown fires.
///
/// ## Why a separate task
///
/// The producer is network-agnostic (no `NetworkHandle` import). Separating
/// broadcast into this task preserves the AGENTS §8 dependency direction and
/// mirrors the Sui `CoreSignals` pattern: the consensus core emits onto a
/// channel; a dedicated subscriber handles dissemination.
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
                            // Non-fatal: peers may not be subscribed yet, or
                            // the service is shutting down.
                            debug!(height, error = %e, "broadcast_block failed (non-fatal)");
                        } else {
                            debug!(height, "block gossiped to mesh");
                        }
                    }
                    // Producer stopped → broadcaster exits cleanly.
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

/// Dispatch a single [`NetworkEvent`] to the appropriate handler.
async fn handle_network_event(
    event: NetworkEvent,
    db: &Arc<LemmaDb>,
    _mempool: &Arc<RwLock<Mempool>>,
    handle: &NetworkHandle,
) -> Result<(), NodeError> {
    match event {
        // ── Inbound transaction — Phase 1: log only ───────────────────────────
        //
        // Phase 2 forward note: full admission requires:
        //   - WorldState (sender nonce + balance check)
        //   - sender PublicKey (signature verify)
        //   - sender_stake (circuit-breaker tier)
        //   - AdmitContext { chain_id, base_fee }
        // Wire these through once VM execution is live (Phase 2).
        NetworkEvent::TransactionReceived { from, tx } => {
            debug!(
                peer = %from,
                tx   = %tx.hash.to_hex(),
                "gossiped tx received (not admitted — Phase 2 hook: state context needed)"
            );
        }

        // ── Inbound range request — serve from ChainStore ────────────────────
        NetworkEvent::RangeRequest { from, request, channel } => {
            serve_range_request(from, request, channel, db, handle).await?;
        }

        // ── Gossiped block — Phase 1: log only (no QC verify) ────────────────
        //
        // Phase 2 forward note: verify QC (07-CONSENSUS_SPEC §4.3), verify
        // parent_hash continuity, then extend chain via ChainStore::put_block.
        NetworkEvent::BlockReceived { from, block } => {
            info!(
                peer   = %from,
                height = block.height(),
                "gossiped block received (not applied — Phase 2 hook: QC verify required)"
            );
        }

        // ── Peer lifecycle ────────────────────────────────────────────────────
        NetworkEvent::PeerConnected(peer_id) => {
            info!(peer = %peer_id, "peer connected");
        }

        NetworkEvent::PeerDisconnected(peer_id) => {
            info!(peer = %peer_id, "peer disconnected");
        }

        // ── Local listen address ──────────────────────────────────────────────
        NetworkEvent::ListeningOn(addr) => {
            info!(addr = %addr, "node listening on {addr}");
        }
    }

    Ok(())
}

/// Fetch the requested block range from storage and send the response.
///
/// Validates that the range is within stored bounds, fetches blocks via
/// `ChainStore::get_range`, and dispatches `SendRangeResponse`. Partial
/// responses (range extends beyond local tip) are valid — the requester
/// checks continuity on their side (12-NETWORK_SYNC_SPEC §2.2).
///
/// Storage errors yield an empty (not an error) response — the requesting
/// peer can retry against a different node. An error here would close the
/// event loop, which is too aggressive for a non-critical serve path.
async fn serve_range_request(
    from: libp2p::PeerId,
    request: lemma_network::messages::RangeRequest,
    channel: libp2p::request_response::ResponseChannel<lemma_network::messages::RangeResponse>,
    db: &Arc<LemmaDb>,
    handle: &NetworkHandle,
) -> Result<(), NodeError> {
    use lemma_network::messages::RangeResponse;

    let blocks      = fetch_range(db, &request);
    let block_count = blocks.len();
    let response    = RangeResponse::new(blocks);

    handle
        .send_range_response(channel, response)
        .await?;

    debug!(
        peer        = %from,
        from        = request.from_height,
        to          = request.to_height,
        block_count,
        "served range request"
    );

    Ok(())
}

/// Fetch the blocks for a range request from local storage.
///
/// Returns the contiguous prefix `[from_height, to_height]` found in the
/// local chain store. Storage errors yield an empty vec — the requesting peer
/// can retry against a different node. This policy keeps `serve_range_request`
/// non-fatal: a bad disk read for one peer's request should not crash the
/// node's network dispatch loop.
///
/// Extracted as a pure helper so it can be unit-tested independently of the
/// live swarm's `ResponseChannel`.
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
