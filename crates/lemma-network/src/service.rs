//! NetworkService — the swarm event loop that wires all `lemma-network` modules
//! into a running P2P node.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐  NetworkCommand  ┌──────────────────────────────┐
//! │  NetworkHandle  │ ─────(mpsc)────► │  NetworkService              │
//! │  (Clone-able)   │                  │  owns Swarm<LemmaBehaviour>  │
//! │                 │ ◄────(mpsc)───── │  runs tokio event loop       │
//! └─────────────────┘  NetworkEvent    └──────────────────────────────┘
//! ```
//!
//! - **[`NetworkHandle`]** — cheap, `Clone`-able handle given to the rest of
//!   the node (consensus, mempool, RPC). Used to send commands and receive
//!   network events without touching the swarm directly.
//! - **[`NetworkService`]** — owns the `Swarm` and all state (peer table, topics).
//!   Created once via [`NetworkService::new`], then consumed by [`NetworkService::run`].
//!
//! ## Startup sequence
//!
//! 1. [`NetworkService::new`]: builds swarm, subscribes to gossip topics,
//!    dials all bootstrap peers from `NetworkConfig::bootstrap_peers`.
//! 2. [`NetworkService::run`]: drives the `tokio::select!` loop until all
//!    `NetworkHandle` clones are dropped.
//!
//! ## Shutdown
//!
//! Dropping all `NetworkHandle` clones closes the command `mpsc::Sender` side,
//! which causes `command_rx.recv()` to return `None` → the loop breaks → `run`
//! returns cleanly (no force-kill needed).
//!
//! ## Phase 1 milestone (04-BUILD_GUIDE §2.6)
//!
//! This service implementation targets:
//! - `[ ] lemma-network: 2 nodes discover each other via mDNS`
//! - `[ ] lemma-network: gossipsub broadcasts messages`

use futures::StreamExt as _;
use libp2p::{
    gossipsub, identify, noise,
    request_response::{self},
    swarm::SwarmEvent,
    tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use tokio::sync::mpsc;

use lemma_core::{block::Block, transaction::Transaction};

use crate::{
    behaviour::{build_behaviour, LemmaBehaviour, LemmaBehaviourEvent},
    config::NetworkConfig,
    discovery,
    error::NetworkError,
    gossip::{self, GossipTopics},
    messages::{BatchFetchRequest, BatchFetchResponse, GossipMessage, RangeRequest, RangeResponse},
    peer::{PeerEvent, PeerTable},
};

// ── Channel capacity ──────────────────────────────────────────────────────────

/// Capacity of the command channel (handle → service).
///
/// Backpressure: if the service is busy, senders block at this depth.
/// 256 is generous for a single-node setup; tune if profiling shows pressure.
pub const COMMAND_CHANNEL_CAPACITY: usize = 256;

/// Capacity of the event channel (service → subscribers).
///
/// Events that overflow the buffer are dropped with a `tracing::warn!`.
pub const EVENT_CHANNEL_CAPACITY: usize = 256;

// ── NetworkCommand ────────────────────────────────────────────────────────────

/// Commands the rest of the node sends to the network service.
///
/// Sent via [`NetworkHandle`] over a bounded mpsc channel.
#[derive(Debug)]
pub enum NetworkCommand {
    /// Broadcast a newly finalized block to all gossip mesh peers.
    ///
    /// The block is encoded as a `GossipMessage::NewBlock` and published
    /// on `lemma/blocks/1`. Gossip is a *hint* — receivers verify the QC.
    BroadcastBlock(Box<Block>),

    /// Broadcast a pending transaction to all gossip mesh peers.
    ///
    /// Published on `lemma/tx/1`. Carries `sender_pubkey` so receivers can
    /// call `Mempool::admit` (Ed25519/ML-DSA-65 have no key recovery —
    /// the public key must travel with the transaction, C·Step 13-residual-2,
    /// closed in D·15d). `sender_pubkey` is stored as
    /// [`lemma_core::validator::ConsensusKey`] (raw bytes) to avoid a
    /// build-order dependency on `lemma-crypto` (AGENTS §8).
    BroadcastTransaction {
        /// The pending transaction.
        tx: Transaction,
        /// Hybrid Ed25519 + ML-DSA-65 public key of `tx.sender`.
        /// Boxed to avoid large_enum_variant (ConsensusKey is ~1984 bytes).
        sender_pubkey: Box<lemma_core::validator::ConsensusKey>,
    },

    /// Broadcast a DAG block proposal to all gossip mesh peers.
    ///
    /// The payload is a JSON-serialized `DagBlock` (opaque bytes — `lemma-network`
    /// does not depend on `lemma-consensus`; the node layer handles encode/decode).
    /// Published on `lemma/dag/1` via [`GossipMessage::DagProposal`].
    ///
    /// Phase 2 (single-node): self-proposes one DagBlock per round.
    /// Phase 3+: broadcasted to all validator peers.
    BroadcastDagProposal(Vec<u8>),

    /// Broadcast a Surge transaction batch to all gossip mesh peers (C·Step 14).
    ///
    /// The payload is a JSON-serialized `Batch` (opaque bytes — `lemma-network`
    /// does not depend on `lemma-node`; the node layer handles encode/decode).
    /// Published on `lemma/batch/1` via [`GossipMessage::TxBatch`].
    ///
    /// Must be broadcast BEFORE the `DagBlock` that references this batch via
    /// `DagBlock.payload: Vec<TxBatchRef>` — peers must be able to resolve the
    /// ref to actual transactions at commit time.
    BroadcastBatch(Vec<u8>),

    /// Send a bounded range request to a specific peer (partition-heal path,
    /// 12-NETWORK_SYNC_SPEC §2.2).
    RequestRange {
        /// Target peer.
        peer: PeerId,
        /// The range to fetch (must satisfy `request.validate(config.max_range)`).
        request: RangeRequest,
    },

    /// Send a range response back through an open request-response channel.
    ///
    /// The channel comes from a [`NetworkEvent::RangeRequest`]; the node
    /// fetches the blocks from storage and sends them back here.
    SendRangeResponse {
        /// The response channel from the inbound request.
        channel: request_response::ResponseChannel<RangeResponse>,
        /// The blocks to send (already validated against the request bounds).
        response: RangeResponse,
    },

    /// Request a specific batch from a peer (availability pull, D·Step 15e).
    ///
    /// Sent when `resolve_block_payload` detects a `TxBatchRef` not pinned
    /// locally. The response arrives as [`NetworkEvent::BatchFetchResponse`].
    RequestBatchFetch {
        /// Target peer to request the batch from.
        peer: PeerId,
        /// Blake3 digest of the requested batch.
        digest: lemma_core::hash::Hash,
    },

    /// Serve a batch-fetch response through an open request-response channel.
    ///
    /// The channel comes from a [`NetworkEvent::BatchFetchRequest`]; the node
    /// layer looks up the batch in `BatchStore` and sends the response here.
    SendBatchFetchResponse {
        /// The response channel from the inbound request.
        channel: request_response::ResponseChannel<BatchFetchResponse>,
        /// The response to send (batch bytes or None if not available).
        response: BatchFetchResponse,
    },

    /// Dial an address (bootstrap or peer discovered out-of-band).
    Dial(Multiaddr),

    /// Report a peer scoring event to the peer table (app-specific score,
    /// 12-NETWORK_SYNC_SPEC §5).
    ///
    /// Used by the node layer to demote peers that serve invalid blocks or bad
    /// QC certs. The network service applies the delta to the peer's
    /// app-specific score.
    ReportPeer {
        /// The peer to report.
        peer: PeerId,
        /// The scoring event (see [`PeerEvent`]).
        event: PeerEvent,
    },
}

// ── NetworkEvent ──────────────────────────────────────────────────────────────

/// Events the network service emits to the rest of the node.
///
/// Received via the `mpsc::Receiver<NetworkEvent>` returned by
/// [`NetworkService::new`].
#[derive(Debug)]
pub enum NetworkEvent {
    /// A gossiped block was received and decoded successfully.
    ///
    /// **The block is NOT verified here.** The consensus layer MUST verify
    /// the quorum certificate before extending the chain
    /// (12-NETWORK_SYNC_SPEC §2.1: "gossip is a hint, the QC is the proof").
    BlockReceived {
        /// The peer that propagated the block (not necessarily the proposer).
        from: PeerId,
        /// The decoded block.
        block: Box<Block>,
    },

    /// A gossiped transaction was received.
    ///
    /// Carries `sender_pubkey` so the node layer can call `Mempool::admit`
    /// without key recovery (Ed25519/ML-DSA-65 do not support it).
    /// `sender_pubkey` is [`lemma_core::validator::ConsensusKey`] (raw bytes)
    /// to avoid a build-order dependency on `lemma-crypto` (AGENTS §8).
    TransactionReceived {
        /// The peer that forwarded the transaction.
        from: PeerId,
        /// The decoded transaction.
        tx: Transaction,
        /// Hybrid Ed25519 + ML-DSA-65 public key of `tx.sender`.
        /// Boxed to avoid large_enum_variant (ConsensusKey is ~1984 bytes).
        sender_pubkey: Box<lemma_core::validator::ConsensusKey>,
    },

    /// An inbound range request arrived from a peer.
    ///
    /// The node must look up the requested blocks from storage and call
    /// [`NetworkCommand::SendRangeResponse`] to reply.
    RangeRequest {
        /// The requesting peer.
        from: PeerId,
        /// The range being requested.
        request: RangeRequest,
        /// The response channel — must be consumed via `SendRangeResponse`.
        channel: request_response::ResponseChannel<RangeResponse>,
    },

    /// A DAG block proposal was received from a peer.
    ///
    /// The payload is a JSON-serialized `DagBlock` (opaque bytes — decoding
    /// happens at the node layer where `lemma-consensus` is available). The
    /// node layer verifies the hybrid signature and injects `sig_ok: bool`
    /// before calling `SurgeDriver::on_block` (DB-12 — consensus never calls
    /// lemma-crypto directly).
    DagProposalReceived {
        /// The peer that propagated the proposal.
        from: PeerId,
        /// Raw JSON-serialized `DagBlock` bytes.
        bytes: Vec<u8>,
    },

    /// A Surge transaction batch was received from a peer (C·Step 14).
    ///
    /// The payload is a JSON-serialized `Batch` (opaque bytes — decoding
    /// happens at the node layer). The node layer decodes it, verifies the
    /// batch digest, and pins it in the local `BatchStore` so that
    /// `TxBatchRef → Vec<Transaction>` resolution succeeds at commit time.
    BatchReceived {
        /// The peer that propagated the batch.
        from: PeerId,
        /// Raw JSON-serialized `Batch` bytes.
        bytes: Vec<u8>,
    },

    /// An inbound batch-fetch request arrived — node layer must serve it.
    ///
    /// The node layer looks up the batch in `BatchStore` and calls
    /// [`NetworkCommand::SendBatchFetchResponse`] to reply. Non-fatal if the
    /// batch is not available — respond with `batch_bytes: None`.
    BatchFetchRequest {
        /// The peer that sent the request.
        from: PeerId,
        /// Blake3 digest of the requested batch.
        digest: lemma_core::hash::Hash,
        /// The response channel — must be consumed via `SendBatchFetchResponse`.
        channel: request_response::ResponseChannel<BatchFetchResponse>,
    },

    /// A batch-fetch response arrived from a peer (D·Step 15e).
    ///
    /// `batch_bytes` is `None` if the peer does not have the batch.
    /// The node layer decodes, verifies, and pins the batch in `BatchStore`.
    BatchFetchResponse {
        /// The peer that served the response.
        from: PeerId,
        /// Blake3 digest of the requested batch (echoed from request).
        digest: lemma_core::hash::Hash,
        /// The batch bytes (JSON-encoded `Batch`), or `None` if not available.
        batch_bytes: Option<Vec<u8>>,
    },

    /// A connection to a new peer was established.
    PeerConnected(PeerId),

    /// A connection to a peer was closed.
    PeerDisconnected(PeerId),

    /// The swarm started listening on a local address.
    ListeningOn(Multiaddr),
}

// ── NetworkHandle ─────────────────────────────────────────────────────────────

/// A cheap, `Clone`-able handle to the running [`NetworkService`].
///
/// The rest of the node holds one or more handles to send commands and does
/// not interact with the swarm directly. Dropping all handles signals the
/// service to shut down.
#[derive(Clone, Debug)]
pub struct NetworkHandle {
    command_tx: mpsc::Sender<NetworkCommand>,
}

impl NetworkHandle {
    /// Broadcast a finalized block to the gossip mesh.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed
    /// (i.e. the service has stopped).
    pub async fn broadcast_block(&self, block: Block) -> Result<(), NetworkError> {
        self.send(NetworkCommand::BroadcastBlock(Box::new(block)))
            .await
    }

    /// Broadcast a pending transaction to the gossip mesh.
    ///
    /// `sender_pubkey` must be the hybrid Ed25519 + ML-DSA-65 public key of
    /// `tx.sender`. Receivers use it to call `Mempool::admit` — Ed25519 and
    /// ML-DSA-65 have no key recovery, so the key must travel with the tx
    /// (C·Step 13-residual-2, closed in D·15d).
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed.
    pub async fn broadcast_transaction(
        &self,
        tx: Transaction,
        sender_pubkey: lemma_core::validator::ConsensusKey,
    ) -> Result<(), NetworkError> {
        self.send(NetworkCommand::BroadcastTransaction {
            tx,
            sender_pubkey: Box::new(sender_pubkey),
        })
        .await
    }

    /// Broadcast a DAG block proposal to the gossip mesh.
    ///
    /// `bytes` must be a JSON-serialized `DagBlock` (produced via
    /// `serde_json::to_vec(&dag_block)`). The network layer routes it to the
    /// `lemma/dag/1` topic without interpreting the payload.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed.
    pub async fn broadcast_dag_proposal(&self, bytes: Vec<u8>) -> Result<(), NetworkError> {
        self.send(NetworkCommand::BroadcastDagProposal(bytes)).await
    }

    /// Broadcast a Surge transaction batch to the gossip mesh (C·Step 14).
    ///
    /// `bytes` must be a JSON-serialized `Batch` (produced via
    /// `serde_json::to_vec(&batch)`). The network layer routes it to the
    /// `lemma/batch/1` topic without interpreting the payload.
    ///
    /// Must be called BEFORE [`broadcast_dag_proposal`](Self::broadcast_dag_proposal)
    /// for the `DagBlock` that references this batch — peers must pin the batch
    /// before they can resolve `TxBatchRef → Vec<Transaction>` at commit time.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed.
    pub async fn broadcast_batch(&self, bytes: Vec<u8>) -> Result<(), NetworkError> {
        self.send(NetworkCommand::BroadcastBatch(bytes)).await
    }

    /// Send a bounded range request to a specific peer (partition-heal path).
    ///
    /// The response arrives as one or more [`NetworkEvent::BlockReceived`]
    /// events (the network service fans out each block individually).
    /// Call [`RangeRequest::validate`] before dispatching — an unchecked range
    /// is a memory-exhaustion vector on the responding peer
    /// (12-NETWORK_SYNC_SPEC §2.2, AGENTS.md §15.2).
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed.
    pub async fn request_range(
        &self,
        peer: PeerId,
        request: crate::messages::RangeRequest,
    ) -> Result<(), NetworkError> {
        self.send(NetworkCommand::RequestRange { peer, request })
            .await
    }

    /// Send a range response back through an open request-response channel.
    ///
    /// The `channel` comes from a [`NetworkEvent::RangeRequest`] event; the
    /// node fetches blocks from storage and calls this to reply. The channel
    /// is consumed — calling this more than once for the same request is a
    /// no-op on the second call (the channel will be closed).
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed.
    pub async fn send_range_response(
        &self,
        channel: request_response::ResponseChannel<crate::messages::RangeResponse>,
        response: crate::messages::RangeResponse,
    ) -> Result<(), NetworkError> {
        self.send(NetworkCommand::SendRangeResponse { channel, response })
            .await
    }

    /// Request a specific batch from a peer (availability pull, D·Step 15e).
    ///
    /// The response arrives as [`NetworkEvent::BatchFetchResponse`]. Non-fatal
    /// if the peer does not have the batch — `batch_bytes` will be `None`.
    ///
    /// ## Phase 3 note (open wire-up — tracked in living-notes Technical Debt)
    ///
    /// This method has zero production call sites in Phase 2. `process_surge_output`
    /// records availability misses as `(digest, author: Address)`, but triggering
    /// a fetch requires an `Address → PeerId` mapping (validator-set ↔ peer-table
    /// wiring) that is deferred to Phase 3. The full transport + verification is
    /// built; only the peer-selection wire is missing.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed.
    pub async fn request_batch_fetch(
        &self,
        peer: PeerId,
        digest: lemma_core::hash::Hash,
    ) -> Result<(), NetworkError> {
        self.send(NetworkCommand::RequestBatchFetch { peer, digest })
            .await
    }

    /// Send a batch-fetch response through an open request-response channel.
    ///
    /// The `channel` comes from a [`NetworkEvent::BatchFetchRequest`] event.
    /// The channel is consumed — calling this more than once for the same
    /// request is a no-op on the second call (the channel will be closed).
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed.
    pub async fn send_batch_fetch_response(
        &self,
        channel: request_response::ResponseChannel<BatchFetchResponse>,
        response: BatchFetchResponse,
    ) -> Result<(), NetworkError> {
        self.send(NetworkCommand::SendBatchFetchResponse { channel, response })
            .await
    }

    /// Dial a bootstrap or peer address.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed.
    pub async fn dial(&self, addr: Multiaddr) -> Result<(), NetworkError> {
        self.send(NetworkCommand::Dial(addr)).await
    }

    /// Report a scoring event for `peer` to the peer table.
    ///
    /// Callers may safely ignore the returned `Err` — it only fires when the
    /// command channel is closed (i.e. the network service is already shutting
    /// down). Log at `debug` if the event matters for diagnostics.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if the command channel is closed.
    pub async fn report_peer(&self, peer: PeerId, event: PeerEvent) -> Result<(), NetworkError> {
        self.send(NetworkCommand::ReportPeer { peer, event }).await
    }

    /// Send a command to the service.
    async fn send(&self, cmd: NetworkCommand) -> Result<(), NetworkError> {
        self.command_tx.send(cmd).await.map_err(|_| {
            NetworkError::transport(std::io::Error::other(
                "command channel closed — NetworkService has stopped",
            ))
        })
    }
}

// ── NetworkService ────────────────────────────────────────────────────────────

/// The P2P network service — owns the `Swarm` and drives the event loop.
///
/// Created via [`NetworkService::new`]; consumed by [`NetworkService::run`].
/// Do not call `run` more than once.
pub struct NetworkService {
    swarm: Swarm<LemmaBehaviour>,
    topics: GossipTopics,
    peers: PeerTable,
    command_rx: mpsc::Receiver<NetworkCommand>,
    event_tx: mpsc::Sender<NetworkEvent>,
}

impl NetworkService {
    /// Build the swarm, subscribe to gossip topics, and dial bootstrap peers.
    ///
    /// Returns `(service, handle, event_rx)`:
    /// - `service` — call `service.run().await` to start the event loop.
    /// - `handle` — clone and distribute to node subsystems.
    /// - `event_rx` — receive network events (blocks, txs, peer changes).
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Transport`] if swarm construction, listening, or
    /// gossip subscription fails.
    pub fn new(
        key: libp2p::identity::Keypair,
        config: &NetworkConfig,
    ) -> Result<(Self, NetworkHandle, mpsc::Receiver<NetworkEvent>), NetworkError> {
        // Build swarm: identity → tokio → tcp/noise/yamux → behaviour → config.
        // `with_behaviour` accepts `Result<B, Box<dyn Error + Send + Sync>>` via
        // the `TryIntoBehaviour` trait impl in libp2p 0.56.
        let mut swarm = SwarmBuilder::with_existing_identity(key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| {
                NetworkError::transport(std::io::Error::other(format!("TCP transport: {e}")))
            })?
            .with_behaviour(|k| {
                build_behaviour(k, config)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            })
            .map_err(|e| {
                NetworkError::transport(std::io::Error::other(format!("LemmaBehaviour: {e}")))
            })?
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(config.idle_timeout))
            .build();

        // Start listening on all configured addresses.
        for addr in &config.listen_addrs {
            swarm.listen_on(addr.clone()).map_err(|e| {
                NetworkError::transport(std::io::Error::other(format!("listen_on {addr}: {e}")))
            })?;
        }

        // Subscribe to all three Lemma gossip topics.
        let topics = GossipTopics::new();
        gossip::subscribe_all(swarm.behaviour_mut().gossipsub_mut(), &topics)?;

        // Dial bootstrap peers (best-effort — failures are logged, not fatal).
        let bootstrap_pairs = discovery::parse_bootstrap_peers(&config.bootstrap_peers);
        for (peer_id, addr) in &bootstrap_pairs {
            swarm
                .behaviour_mut()
                .kademlia
                .add_address(peer_id, addr.clone());
            if let Err(e) = swarm.dial(addr.clone()) {
                tracing::warn!(addr = %addr, error = ?e, "bootstrap dial failed (non-fatal)");
            }
        }

        // Build mpsc channels.
        let (command_tx, command_rx) = mpsc::channel(COMMAND_CHANNEL_CAPACITY);
        let (event_tx, event_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);

        let handle = NetworkHandle { command_tx };
        let service = NetworkService {
            swarm,
            topics,
            peers: PeerTable::new(),
            command_rx,
            event_tx,
        };

        Ok((service, handle, event_rx))
    }

    /// Run the event loop until all [`NetworkHandle`] clones are dropped.
    ///
    /// Calls `tokio::select!` on:
    /// - Swarm events (from peers and the transport layer).
    /// - Incoming commands (from [`NetworkHandle`]).
    ///
    /// Returns when the command channel closes (all handles dropped).
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event);
                }
                cmd = self.command_rx.recv() => {
                    match cmd {
                        Some(c) => self.handle_command(c),
                        // All NetworkHandle clones dropped → clean shutdown.
                        None => {
                            tracing::info!("NetworkService: all handles dropped, shutting down");
                            break;
                        }
                    }
                }
            }
        }
    }

    // ── Swarm event dispatch ──────────────────────────────────────────────────

    fn handle_swarm_event(&mut self, event: SwarmEvent<LemmaBehaviourEvent>) {
        match event {
            // ── Behaviour events (sub-behaviour dispatch) ─────────────────────
            SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(behaviour_event);
            }

            // ── Connection lifecycle ──────────────────────────────────────────
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                self.peers.add_peer(peer_id);
                self.peers.mark_connected(&peer_id);
                self.emit(NetworkEvent::PeerConnected(peer_id));
            }

            SwarmEvent::ConnectionClosed {
                peer_id,
                num_established,
                ..
            } => {
                // Only mark disconnected when the last connection to this peer closes.
                if num_established == 0 {
                    self.peers.mark_disconnected(&peer_id);
                    self.emit(NetworkEvent::PeerDisconnected(peer_id));
                }
            }

            SwarmEvent::NewListenAddr { address, .. } => {
                tracing::info!(addr = %address, "NetworkService: listening on {address}");
                self.emit(NetworkEvent::ListeningOn(address));
            }

            SwarmEvent::IncomingConnectionError { error, .. } => {
                tracing::warn!(error = ?error, "incoming connection error (non-fatal)");
            }

            SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                tracing::warn!(
                    peer = ?peer_id,
                    error = ?error,
                    "outgoing connection error (non-fatal)"
                );
            }

            // Other swarm events (address changes, expired listeners, etc.) ignored.
            _ => {}
        }
    }

    fn handle_behaviour_event(&mut self, event: LemmaBehaviourEvent) {
        match event {
            // ── Gossipsub ─────────────────────────────────────────────────────
            LemmaBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message,
                ..
            }) => {
                self.handle_gossip_message(propagation_source, &message.data);
            }

            LemmaBehaviourEvent::Gossipsub(_) => {
                // Subscription confirmations, graft/prune etc. — not actionable.
            }

            // ── Request-response (range sync) ─────────────────────────────────
            LemmaBehaviourEvent::Sync(request_response::Event::Message {
                peer, message, ..
            }) => {
                self.handle_sync_message(peer, message);
            }

            LemmaBehaviourEvent::Sync(request_response::Event::OutboundFailure {
                peer,
                error,
                ..
            }) => {
                tracing::warn!(
                    peer = %peer,
                    error = ?error,
                    "range sync outbound failure — peer demoted"
                );
                self.peers.record_event(&peer, PeerEvent::Timeout);
                self.apply_peer_score(&peer);
            }

            LemmaBehaviourEvent::Sync(_) => {}

            // ── Batch fetch-on-miss (request-response) ────────────────────────
            LemmaBehaviourEvent::BatchFetch(request_response::Event::Message {
                peer,
                message,
                ..
            }) => {
                self.handle_batch_fetch_message(peer, message);
            }

            LemmaBehaviourEvent::BatchFetch(request_response::Event::OutboundFailure {
                peer,
                error,
                ..
            }) => {
                // Non-fatal: batch fetch failure means the peer doesn't have the
                // batch or timed out. The requester should try another peer.
                tracing::debug!(
                    peer = %peer,
                    error = ?error,
                    "batch_fetch outbound failure (non-fatal — try another peer)"
                );
            }

            LemmaBehaviourEvent::BatchFetch(_) => {}

            // ── Kademlia ──────────────────────────────────────────────────────
            LemmaBehaviourEvent::Kademlia(kad_event) => {
                discovery::handle_kademlia_event(&kad_event, &mut self.peers);
            }

            // ── mDNS ──────────────────────────────────────────────────────────
            LemmaBehaviourEvent::Mdns(mdns_event) => {
                let newly_discovered = discovery::handle_mdns_event(&mdns_event, &mut self.peers);
                // Dial newly discovered LAN peers.
                for peer_id in newly_discovered {
                    if let Some(info) = self.peers.peer_info(&peer_id) {
                        for addr in info.addresses.clone() {
                            if let Err(e) = self.swarm.dial(addr.clone()) {
                                tracing::debug!(
                                    peer = %peer_id,
                                    addr = %addr,
                                    error = ?e,
                                    "mDNS dial failed (non-fatal)"
                                );
                            }
                        }
                    }
                }
            }

            // ── Identify ──────────────────────────────────────────────────────
            LemmaBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                // Add all listen addresses reported by the peer via identify.
                // This lets Kademlia use them for routing-table entries.
                for addr in &info.listen_addrs {
                    self.peers.add_peer(peer_id);
                    self.peers.add_address(&peer_id, addr.clone());
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }
            }

            LemmaBehaviourEvent::Identify(_) => {}

            // ── Ping ──────────────────────────────────────────────────────────
            LemmaBehaviourEvent::Ping(_) => {
                // Ping is handled internally by libp2p (keepalive).
                // Application-level timeout scoring happens on request failures.
            }
        }
    }

    // ── Gossip message handling ───────────────────────────────────────────────

    fn handle_gossip_message(&mut self, from: PeerId, data: &[u8]) {
        match gossip::decode_incoming(&from, data) {
            Ok(GossipMessage::NewBlock(block)) => {
                // Score: receiving a decodable block is a positive signal.
                self.peers.record_event(&from, PeerEvent::ValidBlock);
                self.apply_peer_score(&from);
                self.emit(NetworkEvent::BlockReceived { from, block });
            }

            Ok(GossipMessage::NewTransaction { tx, sender_pubkey }) => {
                // sender_pubkey is Box<ConsensusKey> from GossipMessage, flows into NetworkEvent.
                self.emit(NetworkEvent::TransactionReceived {
                    from,
                    tx,
                    sender_pubkey,
                });
            }

            Ok(GossipMessage::DagProposal(bytes)) => {
                // Emit raw bytes — the node layer decodes into DagBlock,
                // verifies the hybrid signature, and injects sig_ok (DB-12).
                self.emit(NetworkEvent::DagProposalReceived { from, bytes });
            }

            Ok(GossipMessage::TxBatch(bytes)) => {
                // Emit raw bytes — the node layer decodes into Batch,
                // verifies the digest, and pins in BatchStore (C·Step 14).
                self.emit(NetworkEvent::BatchReceived { from, bytes });
            }

            Err(err) => {
                // Malformed message — demote sender.
                tracing::warn!(
                    peer = %from,
                    error = %err,
                    "gossip decode failed — peer demoted"
                );
                self.peers.record_event(&from, PeerEvent::InvalidMessage);
                self.apply_peer_score(&from);
            }
        }
    }

    // ── Batch fetch message handling ──────────────────────────────────────────

    /// Handle an inbound or outbound batch-fetch request-response message.
    ///
    /// - **Inbound request**: emit [`NetworkEvent::BatchFetchRequest`] so the
    ///   node layer can look up the batch in `BatchStore` and respond.
    /// - **Inbound response**: validate size, then emit
    ///   [`NetworkEvent::BatchFetchResponse`] for the node layer to decode and pin.
    fn handle_batch_fetch_message(
        &mut self,
        from: PeerId,
        message: request_response::Message<BatchFetchRequest, BatchFetchResponse>,
    ) {
        match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                // Emit to node layer — it will look up the batch and respond.
                self.emit(NetworkEvent::BatchFetchRequest {
                    from,
                    digest: request.digest,
                    channel,
                });
            }

            request_response::Message::Response { response, .. } => {
                // Validate response size before emitting (DoS guard — AGENTS §15.1).
                if let Some(ref bytes) = response.batch_bytes {
                    if bytes.len() > BatchFetchResponse::MAX_BYTES {
                        tracing::warn!(
                            peer = %from,
                            size = bytes.len(),
                            max  = BatchFetchResponse::MAX_BYTES,
                            "batch_fetch response too large — dropped (AGENTS §15.1)"
                        );
                        self.peers.record_event(&from, PeerEvent::InvalidMessage);
                        self.apply_peer_score(&from);
                        return;
                    }
                }
                self.emit(NetworkEvent::BatchFetchResponse {
                    from,
                    digest: response.digest,
                    batch_bytes: response.batch_bytes,
                });
            }
        }
    }

    // ── Range sync message handling ───────────────────────────────────────────

    fn handle_sync_message(
        &mut self,
        from: PeerId,
        message: request_response::Message<RangeRequest, RangeResponse>,
    ) {
        match message {
            request_response::Message::Request {
                request, channel, ..
            } => {
                // Validate before emitting — reject malformed requests immediately.
                if let Err(e) = request.validate(crate::config::DEFAULT_MAX_RANGE) {
                    tracing::warn!(
                        peer = %from,
                        error = %e,
                        "invalid range request — peer demoted"
                    );
                    self.peers.record_event(&from, PeerEvent::InvalidMessage);
                    self.apply_peer_score(&from);
                    return;
                }
                self.emit(NetworkEvent::RangeRequest {
                    from,
                    request,
                    channel,
                });
            }

            request_response::Message::Response { response, .. } => {
                // Validate response size before processing.
                if let Err(e) = response.validate_size(crate::config::DEFAULT_MAX_RESPONSE_BYTES) {
                    tracing::warn!(
                        peer = %from,
                        error = %e,
                        "range response too large — peer demoted"
                    );
                    self.peers.record_event(&from, PeerEvent::InvalidMessage);
                    self.apply_peer_score(&from);
                    return;
                }
                // Valid response received — positive signal.
                self.peers.record_event(&from, PeerEvent::ValidBlock);
                self.apply_peer_score(&from);

                // Emit blocks individually so the consensus layer processes them.
                for block in response.blocks {
                    self.emit(NetworkEvent::BlockReceived {
                        from,
                        block: Box::new(block),
                    });
                }
            }
        }
    }

    // ── Command handling ──────────────────────────────────────────────────────

    fn handle_command(&mut self, cmd: NetworkCommand) {
        match cmd {
            NetworkCommand::BroadcastBlock(block) => {
                let msg = GossipMessage::NewBlock(block);
                if let Err(e) = gossip::publish(
                    self.swarm.behaviour_mut().gossipsub_mut(),
                    &self.topics,
                    &msg,
                ) {
                    // NoPeersSubscribedToTopic is expected during startup.
                    tracing::debug!(error = %e, "BroadcastBlock publish failed (non-fatal)");
                }
            }

            NetworkCommand::BroadcastTransaction { tx, sender_pubkey } => {
                let msg = GossipMessage::NewTransaction { tx, sender_pubkey };
                if let Err(e) = gossip::publish(
                    self.swarm.behaviour_mut().gossipsub_mut(),
                    &self.topics,
                    &msg,
                ) {
                    tracing::debug!(error = %e, "BroadcastTransaction publish failed (non-fatal)");
                }
            }

            NetworkCommand::BroadcastDagProposal(bytes) => {
                // Symmetric size guard with the decode side (MAX_GOSSIP_DECODE_BYTES = 1 MiB).
                // A DagBlock with empty payload should be a few hundred bytes; exceeding
                // 1 MiB indicates a bug in the encode path or an unexpected payload growth.
                if bytes.len() > crate::messages::MAX_GOSSIP_DECODE_BYTES {
                    tracing::warn!(
                        size = bytes.len(),
                        max = crate::messages::MAX_GOSSIP_DECODE_BYTES,
                        "BroadcastDagProposal: oversized — rejected (AGENTS §15.1)"
                    );
                    return; // do not publish
                }
                let msg = GossipMessage::DagProposal(bytes);
                if let Err(e) = gossip::publish(
                    self.swarm.behaviour_mut().gossipsub_mut(),
                    &self.topics,
                    &msg,
                ) {
                    // NoPeersSubscribedToTopic is expected in single-node mode.
                    tracing::debug!(error = %e, "BroadcastDagProposal publish failed (non-fatal)");
                }
            }

            NetworkCommand::BroadcastBatch(bytes) => {
                // Symmetric 1 MiB size guard — a batch approaching this limit is
                // already pathological under gas limits (AGENTS §15.1).
                if bytes.len() > crate::messages::MAX_GOSSIP_DECODE_BYTES {
                    tracing::warn!(
                        size = bytes.len(),
                        max = crate::messages::MAX_GOSSIP_DECODE_BYTES,
                        "BroadcastBatch: oversized — rejected (AGENTS §15.1)"
                    );
                    return; // do not publish
                }
                let msg = GossipMessage::TxBatch(bytes);
                if let Err(e) = gossip::publish(
                    self.swarm.behaviour_mut().gossipsub_mut(),
                    &self.topics,
                    &msg,
                ) {
                    // NoPeersSubscribedToTopic is expected in single-node mode.
                    tracing::debug!(error = %e, "BroadcastBatch publish failed (non-fatal)");
                }
            }

            NetworkCommand::RequestRange { peer, request } => {
                self.swarm.behaviour_mut().sync.send_request(&peer, request);
            }

            NetworkCommand::SendRangeResponse { channel, response } => {
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .sync
                    .send_response(channel, response)
                {
                    tracing::warn!(error = ?e, "SendRangeResponse failed (channel may have closed)");
                }
            }

            NetworkCommand::RequestBatchFetch { peer, digest } => {
                self.swarm
                    .behaviour_mut()
                    .batch_fetch
                    .send_request(&peer, BatchFetchRequest { digest });
            }

            NetworkCommand::SendBatchFetchResponse { channel, response } => {
                if let Err(e) = self
                    .swarm
                    .behaviour_mut()
                    .batch_fetch
                    .send_response(channel, response)
                {
                    // Non-fatal: channel may have closed if the requester timed out.
                    tracing::debug!(error = ?e, "SendBatchFetchResponse failed (channel may have closed — non-fatal)");
                }
            }

            NetworkCommand::Dial(addr) => {
                if let Err(e) = self.swarm.dial(addr.clone()) {
                    tracing::warn!(addr = %addr, error = ?e, "Dial command failed (non-fatal)");
                }
            }

            NetworkCommand::ReportPeer { peer, event } => {
                self.peers.record_event(&peer, event);
                self.apply_peer_score(&peer);
                tracing::debug!(peer = %peer, event = ?event, "peer score event recorded");
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Emit a `NetworkEvent` to subscribers, dropping it if the channel is full.
    ///
    /// Uses `try_send` (non-async) to avoid holding `&self` across an await
    /// point — `NetworkService` is not `Sync` (Swarm contains non-Sync types),
    /// so `&self` cannot be held across `.await` in a `Send` future.
    fn emit(&self, event: NetworkEvent) {
        if let Err(e) = self.event_tx.try_send(event) {
            tracing::warn!(
                error = ?e,
                "NetworkEvent dropped — event channel full \
                 (consumer too slow; increase EVENT_CHANNEL_CAPACITY if persistent)"
            );
        }
    }

    /// Apply the peer's current app-specific score to gossipsub.
    ///
    /// Called after every [`PeerTable::record_event`] so gossipsub's mesh
    /// management (pruning, grafting, graylist) stays in sync with our
    /// observed misbehaviour signals (12-NETWORK_SYNC_SPEC §5).
    fn apply_peer_score(&mut self, peer: &PeerId) {
        if let Some(score) = self.peers.score(peer) {
            // Returns false if scoring is not active (no PeerScoreParams set).
            // This is expected for nodes without peer-scoring configured.
            let _ = self
                .swarm
                .behaviour_mut()
                .gossipsub_mut()
                .set_application_score(peer, score);
        }
    }
}

// ── gossipsub_mut accessor ────────────────────────────────────────────────────

/// Extension trait to give `LemmaBehaviour` a `gossipsub_mut()` accessor.
///
/// The `#[derive(NetworkBehaviour)]` macro makes the `gossipsub` field `pub`,
/// so this is just a convenience method to avoid verbose field access at
/// call sites and keep the borrow checker happy (takes `&mut self` once,
/// returns the sub-behaviour reference).
trait GossipsubMut {
    fn gossipsub_mut(&mut self) -> &mut gossipsub::Behaviour;
}

impl GossipsubMut for LemmaBehaviour {
    fn gossipsub_mut(&mut self) -> &mut gossipsub::Behaviour {
        &mut self.gossipsub
    }
}

#[cfg(test)]
mod tests;
