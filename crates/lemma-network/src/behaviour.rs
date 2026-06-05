//! LemmaBehaviour — the composed libp2p [`NetworkBehaviour`] for the Lemma P2P stack.
//!
//! Composes seven sub-behaviours into one unified type via the
//! `#[derive(NetworkBehaviour)]` macro, following the transport table in
//! `12-NETWORK_SYNC_SPEC.md §1`:
//!
//! | Field | Sub-behaviour | Role |
//! |-------|---------------|------|
//! | `gossipsub` | `gossipsub::Behaviour` | Push: blocks, DAG msgs, txs |
//! | `sync` | `request_response::cbor::Behaviour` | Pull: range backfill |
//! | `batch_fetch` | `request_response::cbor::Behaviour` | Pull: batch fetch-on-miss |
//! | `kademlia` | `kad::Behaviour<MemoryStore>` | DHT peer discovery |
//! | `identify` | `identify::Behaviour` | Peer metadata exchange |
//! | `mdns` | `mdns::tokio::Behaviour` | LAN peer discovery |
//! | `ping` | `ping::Behaviour` | Liveness / keepalive |
//!
//! ## Construction
//!
//! Call [`build_behaviour`] with a keypair and [`NetworkConfig`]. The function
//! configures each sub-behaviour from the config and returns a ready-to-use
//! `LemmaBehaviour` that can be passed to a [`libp2p::Swarm`].
//!
//! ## Gossipsub configuration (spec-mandated)
//!
//! Per `12-NETWORK_SYNC_SPEC §2.1`:
//! - `ValidationMode::Strict` + `MessageAuthenticity::Signed` — only signed
//!   messages accepted (anti-spoofing).
//! - Content-addressed `message_id` via Blake3 of message bytes — deduplicates
//!   the same block across mesh links without per-sender state.
//! - `flood_publish(true)` — pushes new blocks to **all** above-threshold peers
//!   regardless of mesh membership, countering eclipse attacks.
//!
//! ## Event type
//!
//! The `#[derive(NetworkBehaviour)]` macro generates `LemmaBehaviourEvent`
//! automatically, with one variant per field (e.g. `Gossipsub`, `Sync`,
//! `Kademlia`, `Identify`, `Mdns`, `Ping`). The service event loop
//! pattern-matches on these variants to dispatch messages.

use libp2p::{
    gossipsub, identify, identity,
    kad::{self, store::MemoryStore},
    mdns, ping,
    request_response::{self, cbor, ProtocolSupport},
    swarm::NetworkBehaviour,
    StreamProtocol,
};

use crate::{
    config::{self, NetworkConfig},
    error::NetworkError,
    messages::{BatchFetchRequest, BatchFetchResponse, RangeRequest, RangeResponse},
};

// ── Message ID ────────────────────────────────────────────────────────────────

/// Compute a Blake3 content-addressed gossipsub [`MessageId`] for the given bytes.
///
/// Same data always produces the same ID — deduplicating a block that arrives
/// over multiple mesh links without any per-sender state (12-NETWORK_SYNC_SPEC §2.1).
///
/// This is a standalone function (not a closure) so it can be independently
/// unit-tested and referenced in the gossipsub [`ConfigBuilder`] without
/// capturing any environment.
///
/// [`MessageId`]: gossipsub::MessageId
/// [`ConfigBuilder`]: gossipsub::ConfigBuilder
pub(crate) fn compute_message_id(data: &[u8]) -> gossipsub::MessageId {
    // Blake3 always produces 32 bytes regardless of input length.
    gossipsub::MessageId::from(blake3::hash(data).as_bytes().to_vec())
}

// ── LemmaBehaviour ────────────────────────────────────────────────────────────

/// The composed libp2p `NetworkBehaviour` for the Lemma P2P stack.
///
/// Do not construct directly — use [`build_behaviour`] which wires each
/// sub-behaviour to the correct protocol strings and configuration values.
///
/// The `#[derive(NetworkBehaviour)]` macro generates `LemmaBehaviourEvent`
/// with variants `Gossipsub`, `Sync`, `BatchFetch`, `Kademlia`, `Identify`,
/// `Mdns`, `Ping`.
#[derive(NetworkBehaviour)]
pub struct LemmaBehaviour {
    /// Gossipsub v1.1 — push dissemination for blocks, transactions, DAG messages.
    ///
    /// Configured with `ValidationMode::Strict`, `MessageAuthenticity::Signed`,
    /// Blake3 content-addressed `message_id`, and `flood_publish(true)`.
    pub gossipsub: gossipsub::Behaviour,

    /// Request-response over CBOR — bounded range/backfill sync (`/lemma/sync/1`).
    ///
    /// The partition-heal path (12-NETWORK_SYNC_SPEC §2.2, 07-CONSENSUS_SPEC §8):
    /// a stalled minority reconnects and pulls the missed block range.
    pub sync: cbor::Behaviour<RangeRequest, RangeResponse>,

    /// Request-response over CBOR — batch fetch-on-miss (`/lemma/batch-fetch/1`).
    ///
    /// Used when a validator's `resolve_block_payload` detects a `TxBatchRef`
    /// not pinned locally (availability miss). The requesting node pulls the
    /// batch bytes from a peer that has it (D·Step 15e).
    pub batch_fetch: cbor::Behaviour<BatchFetchRequest, BatchFetchResponse>,

    /// Kademlia DHT — public peer discovery (`/lemma/kad/1`).
    ///
    /// Uses `MemoryStore` (no persistence between restarts). Populated on startup
    /// from [`NetworkConfig::bootstrap_peers`] by the discovery module.
    pub kademlia: kad::Behaviour<MemoryStore>,

    /// Identify — peer metadata exchange (public key, listen addresses, protocols).
    ///
    /// Enables the discovery module to learn a peer's listen addresses and
    /// update the peer table after connection establishment.
    pub identify: identify::Behaviour,

    /// mDNS — LAN peer discovery (tokio-backed, v1 staging).
    ///
    /// Finds peers on the local network without bootstrap seeds. Ships in v1;
    /// Kademlia covers public discovery.
    pub mdns: mdns::tokio::Behaviour,

    /// Ping — liveness check and connection keepalive.
    ///
    /// Detects stalled connections; keepalive prevents Yamux from timing out
    /// idle connections that are still logically live.
    pub ping: ping::Behaviour,
}

// ── build_behaviour ───────────────────────────────────────────────────────────

/// Construct a fully-configured [`LemmaBehaviour`] from a keypair and network config.
///
/// All sub-behaviour parameters are derived from `config` — no hardcoded values.
/// This function must be called from within a Tokio runtime context because
/// `mdns::tokio::Behaviour::new` spawns Tokio tasks internally.
///
/// # Errors
///
/// Returns [`NetworkError::Transport`] if any sub-behaviour fails to initialize.
/// In practice this means:
/// - Gossipsub `ConfigBuilder::build()` failed (contradictory parameters — a
///   programming error since parameters come from validated `NetworkConfig`).
/// - `gossipsub::Behaviour::new` failed (e.g. key incompatibility).
/// - `mdns::tokio::Behaviour::new` failed (e.g. socket bind error).
///
/// # Examples
///
/// ```no_run
/// use libp2p::identity;
/// use lemma_network::{behaviour::build_behaviour, config::NetworkConfig};
///
/// #[tokio::main]
/// async fn main() {
///     let key = identity::Keypair::generate_ed25519();
///     let config = NetworkConfig::default();
///     let behaviour = build_behaviour(&key, &config).expect("behaviour must build");
/// }
/// ```
pub fn build_behaviour(
    key: &identity::Keypair,
    config: &NetworkConfig,
) -> Result<LemmaBehaviour, NetworkError> {
    let local_peer_id = key.public().to_peer_id();

    // ── Gossipsub ─────────────────────────────────────────────────────────────
    // spec: ValidationMode::Strict + MessageAuthenticity::Signed +
    //       content-addressed message_id (Blake3) + flood_publish = true
    // (12-NETWORK_SYNC_SPEC §2.1)
    let gossip_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(config.gossip_heartbeat)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .flood_publish(true) // eclipse resistance: push to all above-threshold peers
        .message_id_fn(|msg: &gossipsub::Message| compute_message_id(&msg.data))
        .build()
        .map_err(|e| {
            NetworkError::transport(std::io::Error::other(format!(
                "gossipsub ConfigBuilder failed: {e}"
            )))
        })?;

    let gossipsub = gossipsub::Behaviour::new(
        // Signed: only messages from verified keypair owners are accepted.
        gossipsub::MessageAuthenticity::Signed(key.clone()),
        gossip_config,
    )
    .map_err(|e| {
        NetworkError::transport(std::io::Error::other(format!(
            "gossipsub Behaviour::new failed: {e}"
        )))
    })?;

    // ── Request-response (range sync, /lemma/sync/1) ─────────────────────────
    // CBOR codec: serialization handled automatically by libp2p; our types need
    // only Serialize + Deserialize. Timeout from config — no hardcoded values.
    let sync = cbor::Behaviour::<RangeRequest, RangeResponse>::new(
        [(
            StreamProtocol::new(config::PROTOCOL_SYNC),
            ProtocolSupport::Full, // both send and receive range requests
        )],
        request_response::Config::default().with_request_timeout(config.request_timeout),
    );

    // ── Request-response (batch fetch-on-miss, /lemma/batch-fetch/1) ─────────
    // Mirrors the `sync` pattern exactly (same CBOR codec, same timeout).
    // Used when a validator's resolve_block_payload detects a TxBatchRef not
    // pinned locally — it pulls the batch from a peer that has it (D·Step 15e).
    let batch_fetch = cbor::Behaviour::<BatchFetchRequest, BatchFetchResponse>::new(
        [(
            StreamProtocol::new(config::PROTOCOL_BATCH_FETCH),
            ProtocolSupport::Full, // both send and receive batch-fetch requests
        )],
        request_response::Config::default().with_request_timeout(config.request_timeout),
    );

    // ── Kademlia DHT (/lemma/kad/1) ──────────────────────────────────────────
    // kad::Config::new(StreamProtocol) sets the single protocol name for this
    // Kademlia instance. Custom protocol so Lemma nodes do not join or pollute
    // the IPFS DHT (12-NETWORK_SYNC_SPEC §1 transport table).
    // MemoryStore: no disk persistence — peer routing table rebuilds on restart
    // from bootstrap seeds (acceptable for v1; archival nodes can swap in a
    // persistent store later).
    let kad_config = kad::Config::new(StreamProtocol::new(config::PROTOCOL_KAD));
    let store = MemoryStore::new(local_peer_id);
    let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);

    // ── Identify ─────────────────────────────────────────────────────────────
    // The protocol version string "/lemma/1.0.0" is advertised to other nodes.
    // The public key enables authenticated peer metadata exchange.
    // identify::Config::new requires String (not &str) in libp2p-identify 0.47.
    let identify = identify::Behaviour::new(identify::Config::new(
        "/lemma/1.0.0".to_string(),
        key.public(),
    ));

    // ── mDNS (LAN discovery, tokio-only) ─────────────────────────────────────
    // Requires a tokio runtime — must be called within a tokio context.
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
        .map_err(NetworkError::transport)?;

    // ── Ping (liveness) ──────────────────────────────────────────────────────
    let ping = ping::Behaviour::default();

    Ok(LemmaBehaviour {
        gossipsub,
        sync,
        batch_fetch,
        kademlia,
        identify,
        mdns,
        ping,
    })
}

#[cfg(test)]
mod tests;
