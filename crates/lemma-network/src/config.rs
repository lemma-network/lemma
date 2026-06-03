//! Network configuration — limits, timeouts, topics, and bootstrap peers.
//!
//! [`NetworkConfig`] is the single source of truth for all tunable parameters
//! in `lemma-network`. Every bound, timeout, and topic string is derived from
//! this struct so that tests and production code share the same values.
//!
//! ## Safety contract
//!
//! All limits here are **DoS defences** (12-NETWORK_SYNC_SPEC §2.2, §5).
//! Removing or raising them requires an explicit reviewer justification — a
//! resource-unbounded network handler is a memory-exhaustion attack vector.
//!
//! ## Protocol string conventions
//!
//! Two distinct namespaces exist — they look similar but follow different rules:
//!
//! - **gossipsub topics** (`TOPIC_*`): no leading slash — arbitrary pub-sub
//!   topic strings, not multistream-select protocol IDs.
//! - **request-response protocol IDs** (`PROTOCOL_*`): leading slash — follow
//!   the libp2p multistream-select convention `/namespace/name/version`.
//! - **Kademlia** (`PROTOCOL_KAD`): leading slash — same multistream convention.
//!
//! The trailing integer on every string is the **version suffix** for
//! forward-compatibility (12-NETWORK_SYNC_SPEC §1): shipping `/lemma/sync/2`
//! later lets old peers continue to speak `/lemma/sync/1` during migration.
//!
//! ## Default values
//!
//! [`NetworkConfig::default`] is suitable for a single-host devnet. For
//! testnet/mainnet, override `listen_addrs` and populate `bootstrap_peers`.

use std::time::Duration;

use libp2p::Multiaddr;
use thiserror::Error;

// ── Protocol string constants ─────────────────────────────────────────────────

/// gossipsub topic — finalized blocks pushed by the proposer.
///
/// No leading slash: gossipsub topics are arbitrary pub-sub strings, not
/// libp2p multistream-select protocol IDs (see module-level doc).
///
/// `ValidationMode::Strict` + `MessageAuthenticity::Signed` required.
/// Content-addressed `message_id` via Blake3 of block bytes deduplicates
/// across mesh links (12-NETWORK_SYNC_SPEC §2.1).
pub const TOPIC_BLOCKS: &str = "lemma/blocks/1";

/// gossipsub topic — DAG consensus messages (DagProposal, DagVote).
///
/// All validators publish here; the gossipsub mesh propagates to all peers.
pub const TOPIC_DAG: &str = "lemma/dag/1";

/// gossipsub topic — pending transactions from the mempool.
///
/// Shield (encrypted mempool) transactions are published here in encrypted
/// form; decryption happens after ordering (11-MEMPOOL_SHIELD_SPEC).
pub const TOPIC_TX: &str = "lemma/tx/1";

/// gossipsub topic — Surge transaction batches (batch dissemination, C·Step 14).
///
/// Validators broadcast serialized [`Batch`](lemma_node::batch) payloads here
/// before proposing a `DagBlock` that references them. Peers pin received batches
/// in their local `BatchStore` so `TxBatchRef` → `Vec<Transaction>` resolution
/// succeeds at commit time.
///
/// The payload is opaque bytes at the network layer (`lemma-network` does not
/// import `lemma-node`) — the node layer handles encode/decode (same DB-A12
/// pattern as `TOPIC_DAG`).
///
/// `ValidationMode::Strict` is required (same as all Lemma gossip topics).
pub const TOPIC_BATCH: &str = "lemma/batch/1";

/// request-response protocol — bounded range/backfill sync.
///
/// Leading slash: libp2p multistream-select convention (see module-level doc).
///
/// A node behind by a bounded gap pulls missing blocks via
/// [`RangeRequest`](crate::messages::RangeRequest) /
/// [`RangeResponse`](crate::messages::RangeResponse) over this protocol.
/// This is the partition-heal path (12-NETWORK_SYNC_SPEC §2.2, 07 §8).
pub const PROTOCOL_SYNC: &str = "/lemma/sync/1";

/// request-response protocol — fast state-sync (v2, trie chunking).
///
/// Leading slash: libp2p multistream-select convention (see module-level doc).
///
/// Used for bulk state transfer during initial sync. Not yet implemented
/// (v2 feature — blocked on `lemma-consensus::QuorumCert`).
pub const PROTOCOL_STATE: &str = "/lemma/state/1";

/// Kademlia DHT protocol identifier for peer discovery.
///
/// Leading slash: libp2p multistream-select convention (see module-level doc).
pub const PROTOCOL_KAD: &str = "/lemma/kad/1";

// ── Limit defaults ────────────────────────────────────────────────────────────

/// Maximum number of blocks a single range request may span.
///
/// Bounding this prevents O(n) allocations on the responding peer and caps
/// the memory a malicious requester can force the responder to allocate
/// (12-NETWORK_SYNC_SPEC §2.2, "Resource exhaustion" row).
pub const DEFAULT_MAX_RANGE: u64 = 256;

/// Maximum size in bytes for a single request-response reply.
///
/// Applies to both range sync responses and (v2) state-sync chunks.
/// A response exceeding this is dropped and yields
/// [`NetworkError::ResponseTooLarge`](crate::error::NetworkError::ResponseTooLarge).
/// Caps per-response memory allocation regardless of peer behaviour
/// (12-NETWORK_SYNC_SPEC §2.2).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024; // 8 MiB

/// Maximum number of concurrent inbound request-response substreams (global).
///
/// This is a **global** cap across all peers combined, not per-peer.
/// Per-peer rate limiting is enforced separately via the gossipsub peer scorer
/// and request-response `Config::set_connection_keep_alive` (spec §5).
///
/// Caps total inbound substreams to prevent file-descriptor exhaustion from
/// a coordinated connection-flood attack (12-NETWORK_SYNC_SPEC §5).
pub const DEFAULT_MAX_INBOUND_SUBSTREAMS: usize = 64;

/// Maximum number of simultaneous outbound connections.
///
/// Caps outbound connections to prevent fd exhaustion and limit the blast
/// radius of a peer-churn attack. Combined with `DEFAULT_MAX_CONNECTIONS_IN`
/// this bounds total fd usage (12-NETWORK_SYNC_SPEC §5,
/// "Resource exhaustion" row).
pub const DEFAULT_MAX_CONNECTIONS_OUT: u32 = 50;

/// Maximum number of simultaneous inbound connections.
///
/// Caps inbound connections to prevent fd exhaustion from a connection-flood
/// attack. A hostile peer opening connections faster than the scoring system
/// can prune is bounded here (12-NETWORK_SYNC_SPEC §5).
pub const DEFAULT_MAX_CONNECTIONS_IN: u32 = 50;

/// Default request-response timeout per request.
///
/// 30 s is generous relative to expected sub-second block times, but short
/// enough to detect a stalled or malicious peer before the sync layer retries
/// against a different peer. On expiry the call returns
/// [`NetworkError::Timeout`](crate::error::NetworkError::Timeout)
/// (12-NETWORK_SYNC_SPEC §2.2).
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Default connection idle timeout before Yamux closes the stream.
///
/// 60 s keeps connections alive across gossip heartbeat cycles (1 s default)
/// without holding file-descriptor resources for truly dead peers. Matches
/// the libp2p SwarmBuilder recommended idle timeout for always-on nodes.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Default gossipsub heartbeat interval.
///
/// Controls mesh maintenance frequency (mesh grafts, prunes, IHAVEs).
/// 1 s matches the gossipsub v1.1 reference implementation default and is
/// fast enough to recover a degraded mesh within a few block times.
pub const DEFAULT_GOSSIP_HEARTBEAT: Duration = Duration::from_secs(1);

/// How often a devnet/default node produces a state snapshot (in blocks).
///
/// `0` disables snapshot production — default nodes do not serve fast
/// state-sync unless explicitly configured (12-NETWORK_SYNC_SPEC §4.5).
pub const DEFAULT_SNAPSHOT_INTERVAL: u64 = 0;

/// How often a testnet node produces a state snapshot (in blocks).
///
/// 1000 blocks is a reasonable interval for testnet: frequent enough to make
/// fast state-sync useful, infrequent enough not to dominate disk I/O.
/// Non-zero values should ideally be multiples of the epoch length
/// (13-VALIDATOR_EPOCH_SPEC — exact value TBD).
pub const DEFAULT_TESTNET_SNAPSHOT_INTERVAL: u64 = 1_000;

// ── ConfigError ───────────────────────────────────────────────────────────────

/// Typed validation errors for [`NetworkConfig`].
///
/// Per `AGENTS.md §4.2`, library crates use `thiserror` typed errors.
/// Each variant corresponds to exactly one guard in [`NetworkConfig::validate`],
/// making caller `match` arms robust and refactor-safe.
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    /// `max_range` was set to zero, disabling the range-request DoS guard.
    #[error("max_range must be > 0 (DoS guard — caps O(n) allocation on responder, 12-NETWORK_SYNC_SPEC §2.2)")]
    ZeroMaxRange,

    /// `max_response_bytes` was set to zero, allowing unlimited response sizes.
    #[error("max_response_bytes must be > 0 (DoS guard — caps per-response memory allocation)")]
    ZeroMaxResponseBytes,

    /// `max_inbound_substreams` was set to zero, allowing unlimited inbound substreams.
    #[error("max_inbound_substreams must be > 0 (DoS guard — prevents fd exhaustion)")]
    ZeroMaxInboundSubstreams,

    /// `max_connections_out` was set to zero, preventing all outbound connections.
    #[error("max_connections_out must be > 0 (a zero value prevents all outbound connections)")]
    ZeroMaxConnectionsOut,

    /// `max_connections_in` was set to zero, preventing all inbound connections.
    #[error("max_connections_in must be > 0 (DoS guard — caps connection-flood attack)")]
    ZeroMaxConnectionsIn,

    /// `request_timeout` was set to zero, disabling request timeouts.
    #[error(
        "request_timeout must be > 0 (a zero timeout causes all requests to immediately fail)"
    )]
    ZeroRequestTimeout,

    /// `idle_timeout` was set to zero, causing connections to close immediately.
    #[error("idle_timeout must be > 0 (a zero timeout closes connections before they can exchange data)")]
    ZeroIdleTimeout,

    /// `gossip_heartbeat` was set to zero, disabling mesh maintenance.
    #[error("gossip_heartbeat must be > 0 (a zero heartbeat disables gossipsub mesh maintenance)")]
    ZeroGossipHeartbeat,

    /// `listen_addrs` was empty — the node has nowhere to accept connections.
    #[error("listen_addrs must not be empty (the node must have at least one local address to listen on)")]
    EmptyListenAddrs,
}

// ── NetworkConfig ─────────────────────────────────────────────────────────────

/// All tunable parameters for the `lemma-network` P2P stack.
///
/// Construct via [`NetworkConfig::default`] and override fields as needed,
/// or use [`NetworkConfig::testnet`] for a pre-tuned profile.
///
/// # Examples
///
/// ```
/// use lemma_network::config::NetworkConfig;
///
/// // Devnet with defaults
/// let cfg = NetworkConfig::default();
/// assert_eq!(cfg.max_range, 256);
///
/// // Customised: smaller range limit for testing
/// let cfg = NetworkConfig { max_range: 16, ..NetworkConfig::default() };
/// assert_eq!(cfg.max_range, 16);
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkConfig {
    // ── Addresses ─────────────────────────────────────────────────────────
    /// Local addresses the swarm will listen on.
    ///
    /// Defaults to all interfaces on a random OS-assigned TCP port
    /// (`/ip4/0.0.0.0/tcp/0`). Override with a fixed port for persistent
    /// node identities (e.g. `/ip4/0.0.0.0/tcp/30303`).
    pub listen_addrs: Vec<Multiaddr>,

    /// Seed peers to dial on startup for initial network discovery.
    ///
    /// Each `Multiaddr` **MUST** include the `/p2p/<peer-id>` component
    /// (e.g. `/ip4/1.2.3.4/tcp/30303/p2p/QmFoo`) — Kademlia bootstrap
    /// requires the peer ID to authenticate the connection. A bare IP/port
    /// address will dial but cannot complete DHT bootstrap because libp2p
    /// cannot verify the remote identity without the embedded peer ID.
    ///
    /// Empty by default (devnet / local testing relies on mDNS).
    /// Mainnet/testnet configs MUST populate this with at least one trusted
    /// bootstrap node.
    pub bootstrap_peers: Vec<Multiaddr>,

    // ── Bounds / DoS limits ────────────────────────────────────────────────
    /// Maximum number of blocks a range request may span.
    ///
    /// Requests exceeding this yield
    /// [`NetworkError::RangeTooWide`](crate::error::NetworkError::RangeTooWide)
    /// before any data is fetched. See [`DEFAULT_MAX_RANGE`].
    pub max_range: u64,

    /// Maximum response body size in bytes.
    ///
    /// Responses exceeding this yield
    /// [`NetworkError::ResponseTooLarge`](crate::error::NetworkError::ResponseTooLarge)
    /// and are discarded without processing. See [`DEFAULT_MAX_RESPONSE_BYTES`].
    pub max_response_bytes: usize,

    /// Maximum concurrent inbound request-response substreams (global across all peers).
    ///
    /// Per-peer rate limiting is a separate concern handled by the gossipsub
    /// peer scorer. See [`DEFAULT_MAX_INBOUND_SUBSTREAMS`].
    pub max_inbound_substreams: usize,

    /// Maximum total outbound connections. See [`DEFAULT_MAX_CONNECTIONS_OUT`].
    pub max_connections_out: u32,

    /// Maximum total inbound connections. See [`DEFAULT_MAX_CONNECTIONS_IN`].
    pub max_connections_in: u32,

    // ── Timeouts ───────────────────────────────────────────────────────────
    /// Timeout for a single request-response call. See [`DEFAULT_REQUEST_TIMEOUT`].
    pub request_timeout: Duration,

    /// Idle connection timeout before Yamux closes the multiplexed stream.
    /// See [`DEFAULT_IDLE_TIMEOUT`].
    pub idle_timeout: Duration,

    /// gossipsub heartbeat interval (mesh maintenance frequency).
    /// See [`DEFAULT_GOSSIP_HEARTBEAT`].
    pub gossip_heartbeat: Duration,

    // ── Snapshots ─────────────────────────────────────────────────────────
    /// How often (in blocks) to produce a state snapshot for fast sync.
    ///
    /// `0` disables snapshot production. Snapshots are taken only at
    /// **finalized** heights (12-NETWORK_SYNC_SPEC §4.5).
    ///
    /// Non-zero values should be multiples of the epoch length
    /// (TODO(network): enforce once epoch length is available from
    /// 13-VALIDATOR_EPOCH_SPEC).
    pub snapshot_interval: u64,
}

impl Default for NetworkConfig {
    /// Returns a configuration suitable for local devnet / single-host testing.
    ///
    /// - Listens on all interfaces, random port (`/ip4/0.0.0.0/tcp/0`).
    /// - No bootstrap peers (relies on mDNS for local discovery).
    /// - Snapshot production disabled (`snapshot_interval = 0`).
    /// - All limits set to the module-level `DEFAULT_*` constants.
    fn default() -> Self {
        NetworkConfig {
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/0"
                .parse()
                .expect("static listen addr is always valid")],
            bootstrap_peers: vec![],
            max_range: DEFAULT_MAX_RANGE,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            max_inbound_substreams: DEFAULT_MAX_INBOUND_SUBSTREAMS,
            max_connections_out: DEFAULT_MAX_CONNECTIONS_OUT,
            max_connections_in: DEFAULT_MAX_CONNECTIONS_IN,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            gossip_heartbeat: DEFAULT_GOSSIP_HEARTBEAT,
            snapshot_interval: DEFAULT_SNAPSHOT_INTERVAL,
        }
    }
}

impl NetworkConfig {
    /// Returns a configuration tuned for a fixed-port testnet node.
    ///
    /// - Listens on `/ip4/0.0.0.0/tcp/30303` — a deterministic port that
    ///   survives process restarts, enabling static bootstrap lists.
    /// - Enables snapshot production at [`DEFAULT_TESTNET_SNAPSHOT_INTERVAL`].
    /// - All other limits inherit from [`NetworkConfig::default`].
    ///
    /// Bootstrap peers are left empty and should be populated by the caller.
    pub fn testnet() -> Self {
        NetworkConfig {
            listen_addrs: vec!["/ip4/0.0.0.0/tcp/30303"
                .parse()
                .expect("static testnet addr is always valid")],
            snapshot_interval: DEFAULT_TESTNET_SNAPSHOT_INTERVAL,
            ..NetworkConfig::default()
        }
    }

    /// Validates that all configured values are within acceptable bounds.
    ///
    /// Returns `Ok(())` if the configuration is valid. Call this once at
    /// node startup — invalid configurations are programming errors, not
    /// runtime-recoverable conditions.
    ///
    /// # Errors
    ///
    /// Returns a [`ConfigError`] variant for the first invalid field found.
    /// Each variant corresponds to exactly one guard so callers can match
    /// on the specific failure without string parsing.
    ///
    /// # Note on `snapshot_interval`
    ///
    /// This validator does not enforce that `snapshot_interval` is a multiple
    /// of the epoch length — epoch length is not yet available here.
    /// TODO(network): add epoch-alignment check once 13-VALIDATOR_EPOCH_SPEC
    /// defines the epoch length constant.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_range == 0 {
            return Err(ConfigError::ZeroMaxRange);
        }
        if self.max_response_bytes == 0 {
            return Err(ConfigError::ZeroMaxResponseBytes);
        }
        if self.max_inbound_substreams == 0 {
            return Err(ConfigError::ZeroMaxInboundSubstreams);
        }
        if self.max_connections_out == 0 {
            return Err(ConfigError::ZeroMaxConnectionsOut);
        }
        if self.max_connections_in == 0 {
            return Err(ConfigError::ZeroMaxConnectionsIn);
        }
        if self.request_timeout.is_zero() {
            return Err(ConfigError::ZeroRequestTimeout);
        }
        if self.idle_timeout.is_zero() {
            return Err(ConfigError::ZeroIdleTimeout);
        }
        if self.gossip_heartbeat.is_zero() {
            return Err(ConfigError::ZeroGossipHeartbeat);
        }
        if self.listen_addrs.is_empty() {
            return Err(ConfigError::EmptyListenAddrs);
        }
        Ok(())
    }

    /// Returns `true` if snapshot production is enabled for this node.
    ///
    /// Snapshot production is disabled when [`Self::snapshot_interval`] is `0`
    /// (the [`default`](NetworkConfig::default) profile).
    pub fn snapshots_enabled(&self) -> bool {
        self.snapshot_interval > 0
    }
}

#[cfg(test)]
mod tests;
