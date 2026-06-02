//! Peer table and app-specific scoring for the Lemma P2P stack.
//!
//! ## Responsibility
//!
//! This module tracks the node's **local view** of each connected peer:
//! identity, known addresses, connection state, and an **app-specific score**
//! that accumulates evidence of misbehaviour. It does NOT touch gossipsub
//! directly — the score is computed here and **applied** by the service layer
//! (Step 8) via `gossipsub::Behaviour::set_application_score`.
//!
//! ## Scoring model (12-NETWORK_SYNC_SPEC §5)
//!
//! gossipsub v1.1 maintains its own mesh-quality score (time-in-mesh, message
//! delivery rate, etc.) — that is owned by libp2p. We own the **app-specific
//! score**: a floating-point value in `[MIN_APP_SCORE, MAX_APP_SCORE]` that
//! accumulates penalties for misbehaviour events and small bonuses for correct
//! service. Peers whose score falls below [`DEFAULT_GRAYLIST_THRESHOLD`] are
//! considered graylisted — the service disconnects them and excludes them from
//! sync selection.
//!
//! | Event | Delta | Rationale |
//! |-------|-------|-----------|
//! | `InvalidBlock` | −10 | Serving an unverifiable block is deliberate or faulty |
//! | `InvalidStateChunk` | −10 | Bad Blake3 range proof (§4.2) — Cosmos pitfall |
//! | `InvalidQuorumCert` | −20 | QC failure is the most serious — possible attack |
//! | `InvalidMessage` | −5 | Malformed wire message — could be version mismatch |
//! | `ValidBlock` | +1 | Positive reinforcement for correct service |
//! | `Timeout` | −1 | Mild — could be transient network condition |
//!
//! A peer that serves one invalid QC cert (`-20`) reaches the graylist threshold
//! (`-20`) but is **not yet graylisted** — the threshold is a strict less-than
//! (`score < threshold`), so `score == threshold` is still allowed. One additional
//! small penalty (e.g. a `Timeout`, −1) crosses the boundary and triggers
//! graylisting. A peer that repeatedly times out takes 21 timeouts to graylist.
//! A valid-block peer recovers from one malformed message in 5 blocks.
//!
//! ## Determinism boundary (12-NETWORK_SYNC_SPEC §1.1)
//!
//! Networking is OUTSIDE the deterministic settlement path. This module freely
//! uses `HashMap` (AGENTS.md §7.1 only bites in consensus/VM/state code) and
//! `Instant` (wall-clock time). Neither `HashMap` iteration order nor timestamps
//! influence block ordering or state transitions.

use std::{collections::HashMap, time::Instant};

use libp2p::{Multiaddr, PeerId};

// ── Score constants ───────────────────────────────────────────────────────────

/// Initial app-specific score for a newly discovered peer.
pub const INITIAL_APP_SCORE: f64 = 0.0;

/// Maximum app-specific score. A "clean" peer never exceeds this.
pub const MAX_APP_SCORE: f64 = 100.0;

/// Minimum app-specific score. A heavily penalised peer saturates here.
pub const MIN_APP_SCORE: f64 = -100.0;

/// Peers whose score falls strictly below this threshold are graylisted.
///
/// Value chosen so that a single `InvalidQuorumCert` event (`-20`) immediately
/// triggers graylisting (spec §5: "low-score peers are pruned/graylisted").
///
/// TODO(network): move to `NetworkConfig::graylist_threshold` when per-deployment
/// tuning is needed (blocked on: no operational experience yet).
pub const DEFAULT_GRAYLIST_THRESHOLD: f64 = -20.0;

// ── Per-event score deltas ────────────────────────────────────────────────────
// `pub(crate)` so tests can assert exact delta values without magic numbers.

/// Score delta applied for each [`PeerEvent`] variant.
pub(crate) const DELTA_INVALID_BLOCK: f64 = -10.0;
pub(crate) const DELTA_INVALID_STATE_CHUNK: f64 = -10.0;
pub(crate) const DELTA_INVALID_QUORUM_CERT: f64 = -20.0;
pub(crate) const DELTA_INVALID_MESSAGE: f64 = -5.0;
pub(crate) const DELTA_VALID_BLOCK: f64 = 1.0;
pub(crate) const DELTA_TIMEOUT: f64 = -1.0;

// ── PeerEvent ─────────────────────────────────────────────────────────────────

/// An observable event that feeds into a peer's app-specific score.
///
/// Each variant carries a constant score delta (see [`PeerEvent::delta`]).
/// Misbehaviour variants have negative deltas; good service has a positive delta.
///
/// `#[non_exhaustive]` — future protocol additions (e.g. equivocation evidence,
/// state-sync chunk results) will add variants without breaking existing `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerEvent {
    /// The peer served a block that failed signature or structural validation.
    ///
    /// Maps to [`NetworkError::InvalidBlock`](crate::error::NetworkError::InvalidBlock).
    InvalidBlock,

    /// The peer served a state chunk whose Blake3 range proof failed against the
    /// anchored `state_root` (12-NETWORK_SYNC_SPEC §4.2).
    ///
    /// Maps to [`NetworkError::InvalidStateChunk`](crate::error::NetworkError::InvalidStateChunk).
    InvalidStateChunk,

    /// The peer served a header with a quorum certificate that failed the 2f+1
    /// voting-power threshold check. This is the most severe misbehaviour signal.
    ///
    /// Maps to [`NetworkError::InvalidQuorumCert`](crate::error::NetworkError::InvalidQuorumCert).
    InvalidQuorumCert,

    /// The peer sent a wire message that failed to deserialize or violated a
    /// structural invariant (e.g. truncated, wrong format version).
    ///
    /// Maps to [`NetworkError::InvalidMessage`](crate::error::NetworkError::InvalidMessage).
    InvalidMessage,

    /// The peer returned a valid, verifiable block in response to a request.
    ///
    /// Small positive delta — correct service slowly recovers mild penalties.
    ValidBlock,

    /// A request to this peer timed out before a response arrived.
    ///
    /// Mild penalty — timeouts can be transient network conditions, not
    /// necessarily deliberate. 20 consecutive timeouts trigger graylisting.
    Timeout,
}

impl PeerEvent {
    /// The score delta applied when this event is recorded for a peer.
    ///
    /// Negative for misbehaviour (penalties), positive for correct service.
    /// See the module-level scoring table for the full rationale.
    pub(crate) fn delta(self) -> f64 {
        match self {
            Self::InvalidBlock => DELTA_INVALID_BLOCK,
            Self::InvalidStateChunk => DELTA_INVALID_STATE_CHUNK,
            Self::InvalidQuorumCert => DELTA_INVALID_QUORUM_CERT,
            Self::InvalidMessage => DELTA_INVALID_MESSAGE,
            Self::ValidBlock => DELTA_VALID_BLOCK,
            Self::Timeout => DELTA_TIMEOUT,
        }
    }

    /// Returns `true` if this event indicates deliberate peer misbehaviour
    /// (as opposed to transient network conditions).
    ///
    /// Use this to gate **error reporting** (e.g. emitting a
    /// [`NetworkError::InvalidMessage`](crate::error::NetworkError::InvalidMessage)).
    ///
    /// **Distinct from [`is_penalty`](Self::is_penalty):**
    /// [`PeerEvent::Timeout`] is a penalty (`is_penalty() == true`) but NOT
    /// misbehaviour — it may be a transient network condition. Use `is_penalty()`
    /// to gate score demotions; use `is_misbehaviour()` to gate error reporting
    /// and peer blame attribution.
    pub fn is_misbehaviour(self) -> bool {
        matches!(
            self,
            Self::InvalidBlock
                | Self::InvalidStateChunk
                | Self::InvalidQuorumCert
                | Self::InvalidMessage
        )
    }

    /// Returns `true` if this event's score delta is negative (penalty).
    pub fn is_penalty(self) -> bool {
        self.delta() < 0.0
    }
}

// ── PeerInfo ──────────────────────────────────────────────────────────────────

/// All state the local node tracks for a single remote peer.
///
/// Populated incrementally as the peer is discovered, connected, and
/// observed over time. The `app_score` field is the value the service
/// layer pushes to `gossipsub::Behaviour::set_application_score`.
#[derive(Debug)]
pub struct PeerInfo {
    /// libp2p peer identity.
    pub peer_id: PeerId,

    /// Known network addresses for this peer (from mDNS, identify, bootstrap).
    ///
    /// Deduplicated — each `Multiaddr` appears at most once.
    pub addresses: Vec<Multiaddr>,

    /// App-specific score in `[MIN_APP_SCORE, MAX_APP_SCORE]`.
    ///
    /// Starts at [`INITIAL_APP_SCORE`]. Decremented by misbehaviour events,
    /// incremented by correct service. Clamped by [`PeerTable::record_event`].
    pub app_score: f64,

    /// Whether the swarm currently has an open connection to this peer.
    pub connected: bool,

    /// Wall-clock time when this peer was first added to the table.
    ///
    /// Networking is outside the deterministic path (§1.1), so `Instant`
    /// (wall-clock) is acceptable here.
    pub first_seen: Instant,

    /// Wall-clock time of the most recent [`PeerTable::record_event`] call.
    pub last_seen: Instant,
}

impl PeerInfo {
    fn new(peer_id: PeerId) -> Self {
        let now = Instant::now();
        PeerInfo {
            peer_id,
            addresses: Vec::new(),
            app_score: INITIAL_APP_SCORE,
            connected: false,
            first_seen: now,
            last_seen: now,
        }
    }

    /// Apply a score delta, clamping the result to `[MIN_APP_SCORE, MAX_APP_SCORE]`.
    fn apply_delta(&mut self, delta: f64) {
        self.app_score = (self.app_score + delta).clamp(MIN_APP_SCORE, MAX_APP_SCORE);
        self.last_seen = Instant::now();
    }
}

// ── PeerTable ─────────────────────────────────────────────────────────────────

/// The node's complete view of all known remote peers.
///
/// ## Usage
///
/// ```
/// use lemma_network::peer::{PeerTable, PeerEvent};
/// use libp2p::PeerId;
///
/// let mut table = PeerTable::new();
/// let peer = PeerId::random();
///
/// table.add_peer(peer);
/// table.record_event(&peer, PeerEvent::InvalidBlock);
/// assert!(!table.is_graylisted(&peer)); // one bad block is not enough
///
/// table.record_event(&peer, PeerEvent::InvalidQuorumCert);
/// assert!(table.is_graylisted(&peer)); // QC failure pushes over threshold
/// ```
pub struct PeerTable {
    peers: HashMap<PeerId, PeerInfo>,

    /// Score threshold below which a peer is considered graylisted.
    ///
    /// Configurable via [`PeerTable::with_graylist_threshold`] for tests.
    graylist_threshold: f64,
}

impl Default for PeerTable {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerTable {
    /// Create a new peer table using [`DEFAULT_GRAYLIST_THRESHOLD`].
    pub fn new() -> Self {
        PeerTable {
            peers: HashMap::new(),
            graylist_threshold: DEFAULT_GRAYLIST_THRESHOLD,
        }
    }

    /// Create a peer table with a custom graylist threshold.
    ///
    /// Useful in tests where a non-default threshold is needed to exercise
    /// boundary conditions without accumulating many events.
    pub fn with_graylist_threshold(threshold: f64) -> Self {
        PeerTable {
            peers: HashMap::new(),
            graylist_threshold: threshold,
        }
    }

    // ── Peer lifecycle ────────────────────────────────────────────────────────

    /// Add a peer to the table.
    ///
    /// **Idempotent** — calling `add_peer` a second time for the same peer does
    /// nothing. Existing score, addresses, and state are preserved. This ensures
    /// that re-discovery via mDNS or identify does not reset a peer's score.
    pub fn add_peer(&mut self, peer_id: PeerId) {
        self.peers
            .entry(peer_id)
            .or_insert_with(|| PeerInfo::new(peer_id));
    }

    /// Remove a peer from the table and return its info, or `None` if unknown.
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.peers.remove(peer_id)
    }

    /// Mark a peer as having an active connection.
    ///
    /// No-op if the peer is not in the table. Call [`add_peer`] first.
    ///
    /// [`add_peer`]: Self::add_peer
    pub fn mark_connected(&mut self, peer_id: &PeerId) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.connected = true;
        }
    }

    /// Mark a peer as no longer connected.
    ///
    /// No-op if the peer is not in the table. Does NOT remove the peer —
    /// score history and addresses are preserved for reconnection.
    pub fn mark_disconnected(&mut self, peer_id: &PeerId) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.connected = false;
        }
    }

    // ── Address management ────────────────────────────────────────────────────

    /// Add a network address for a known peer.
    ///
    /// **Deduplicates** — if `addr` is already known for this peer, it is not
    /// added again. No-op if the peer is not in the table.
    ///
    /// The dedup check is O(n) over existing addresses. Acceptable because peers
    /// typically have ≤ 5 addresses. If address counts grow significantly (e.g.
    /// many relay addresses), consider switching to `HashSet<Multiaddr>` internally.
    pub fn add_address(&mut self, peer_id: &PeerId, addr: Multiaddr) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            if !info.addresses.contains(&addr) {
                info.addresses.push(addr);
            }
        }
    }

    // ── Scoring ───────────────────────────────────────────────────────────────

    /// Record a scoring event for a peer.
    ///
    /// Applies the event's score delta (see [`PeerEvent::delta`]), clamps the
    /// result to `[MIN_APP_SCORE, MAX_APP_SCORE]`, and updates `last_seen`.
    ///
    /// **No-op if the peer is not in the table.** The caller must `add_peer`
    /// before recording events. This prevents phantom entries from being created
    /// by misbehaviour events for peers we've never connected to.
    pub fn record_event(&mut self, peer_id: &PeerId, event: PeerEvent) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.apply_delta(event.delta());
        }
    }

    /// Returns the current app-specific score for a peer, or `None` if unknown.
    pub fn score(&self, peer_id: &PeerId) -> Option<f64> {
        self.peers.get(peer_id).map(|p| p.app_score)
    }

    /// Returns `true` if the peer's score is strictly below the graylist threshold.
    ///
    /// Returns `false` for unknown peers — absence from the table is not
    /// treated as a graylisting signal.
    pub fn is_graylisted(&self, peer_id: &PeerId) -> bool {
        self.peers
            .get(peer_id)
            .map(|p| p.app_score < self.graylist_threshold)
            .unwrap_or(false)
    }

    // ── Inspection ────────────────────────────────────────────────────────────

    /// Returns a reference to the [`PeerInfo`] for a known peer, or `None`.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Returns the total number of peers in the table (connected + disconnected).
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Returns an iterator over all currently connected peers.
    pub fn connected_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        self.peers.values().filter(|p| p.connected)
    }

    /// Returns an iterator over all graylisted peers.
    pub fn graylisted_peers(&self) -> impl Iterator<Item = &PeerInfo> {
        let threshold = self.graylist_threshold;
        self.peers.values().filter(move |p| p.app_score < threshold)
    }

    /// Returns an iterator of `(peer_id, score)` for **all** peers in the table.
    ///
    /// Consumed by the service layer to call
    /// `gossipsub::Behaviour::set_application_score(peer_id, score)` for each
    /// peer, feeding the app-specific score back into the gossipsub peer scorer
    /// (12-NETWORK_SYNC_SPEC §5). The service calls this periodically or after
    /// each `record_event` to keep gossipsub's scoring in sync.
    pub fn scores_to_apply(&self) -> impl Iterator<Item = (&PeerId, f64)> {
        self.peers.iter().map(|(id, info)| (id, info.app_score))
    }
}

#[cfg(test)]
mod tests;
