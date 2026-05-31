//! # lemma-network
//!
//! P2P networking for the Lemma blockchain.
//!
//! Built on **libp2p 0.56** (tokio-only, Noise encryption, Yamux multiplexing).
//! Implements the transport, discovery, gossip, and sync layers specified in
//! `12-NETWORK_SYNC_SPEC.md`.
//!
//! ## Architecture
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | [`error`]     | `NetworkError` — typed errors, never panics on peer input |
//! | [`config`]    | `NetworkConfig` — bounds, timeouts, topics, bootstrap peers |
//! | [`messages`]  | Wire types: `RangeRequest`, `RangeResponse`, `GossipMessage` |
//! | [`behaviour`] | `LemmaBehaviour` — composed libp2p `NetworkBehaviour` |
//! | [`peer`]      | `PeerTable`, `PeerInfo`, `PeerEvent` — app-specific scoring |
//! | [`discovery`] | `handle_mdns_event`, `handle_kademlia_event`, `parse_bootstrap_peers` |
//! | [`gossip`]    | `GossipTopics`, `subscribe_all`, `publish`, `decode_incoming` |
//! | [`service`]   | `NetworkService`, `NetworkHandle`, `NetworkCommand`, `NetworkEvent` |
//!
//! ## Safety contract
//!
//! **No handler panics on peer input.** Every decode, validation step, and
//! sync operation returns `Result<_, NetworkError>`. A crafted malformed packet
//! results in a dropped message and a peer demotion, never a process crash
//! (12-NETWORK_SYNC_SPEC §1.2, AGENTS.md §7.2).
//!
//! ## Determinism boundary
//!
//! Networking is **outside** the deterministic settlement path. This crate
//! may freely use `HashMap`, wall-clock time, and randomness for peer selection
//! (12-NETWORK_SYNC_SPEC §1.1). Determinism requirements (AGENTS.md §7.1)
//! apply only when data crosses into `lemma-consensus` / `lemma-vm` / state.
//!
//! ## Build guide
//!
//! See `docs/04-BUILD_GUIDE.md` Section 2.4 and `docs/12-NETWORK_SYNC_SPEC.md`
//! Section 7 for the full module layout and implementation requirements.

// ── Modules ───────────────────────────────────────────────────────────────────

pub mod behaviour;
pub mod config;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod messages;
pub mod peer;
pub mod service;

// ── Crate-root re-exports ─────────────────────────────────────────────────────

pub use config::NetworkConfig;
pub use error::NetworkError;
