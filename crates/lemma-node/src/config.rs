//! Node runtime configuration.
//!
//! [`NodeConfig`] holds the startup parameters for a Lemma node. Phase 1
//! includes data directory, genesis file path, block interval, and network
//! parameters (listen address, bootstrap peers). All fields with sensible
//! defaults use `#[serde(default)]` so existing config files remain valid
//! when new optional fields are added.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::NodeError;

/// Runtime configuration for a Lemma full node.
///
/// Loaded from a JSON file via [`NodeConfig::load`] or constructed directly
/// (e.g. in tests). Fields are `pub` so callers can inspect them; mutation
/// after construction is intentionally unsupported — create a new config.
///
/// ## Network fields
///
/// `listen_addr` and `bootstrap_peers` are optional in the JSON file.
/// Omitting them gives sensible Phase-1 defaults (random port, mDNS-only
/// discovery). Populate them for persistent or multi-node setups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Path to the directory where the chain database is stored.
    ///
    /// Created on first boot if it does not exist. Must not be empty.
    pub data_dir: PathBuf,

    /// Path to the genesis configuration JSON file.
    ///
    /// See [`lemma_core::genesis::GenesisConfig`] for the expected format.
    /// Must not be empty.
    pub genesis_path: PathBuf,

    /// Block production interval in milliseconds.
    ///
    /// Controls how often the single-node producer attempts to build and
    /// commit the next block. Default: 500 ms (≈2 blocks/second).
    ///
    /// Phase 1 target is ~0.5 s/block (04-BUILD_GUIDE §1 stress-test
    /// baseline). Phase 2 replaces this timer with the Surge/Pulse
    /// consensus driver when multi-validator DAG consensus is added.
    ///
    /// Optional in the config JSON — defaults to `500` if absent.
    #[serde(default = "default_block_interval_ms")]
    pub block_interval_ms: u64,

    /// Local address for the P2P swarm to listen on, as a libp2p multiaddr
    /// string (e.g. `"/ip4/0.0.0.0/tcp/30303"`).
    ///
    /// Optional — defaults to `/ip4/0.0.0.0/tcp/0` (all interfaces, random
    /// OS-assigned port). Override with a fixed port for persistent node
    /// identities or multi-node testnet setups.
    ///
    /// The string is parsed into a `libp2p::Multiaddr` at startup;
    /// invalid strings produce [`NodeError::Config`] during validation.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,

    /// Bootstrap peer multiaddr strings for initial network discovery.
    ///
    /// Each entry **must** include the `/p2p/<peer-id>` component
    /// (e.g. `"/ip4/1.2.3.4/tcp/30303/p2p/QmFoo..."`) — Kademlia bootstrap
    /// requires the peer ID to authenticate the connection (12-NETWORK_SYNC_SPEC §2.1).
    ///
    /// Optional — defaults to empty (devnet / local testing relies on mDNS).
    /// Mainnet/testnet configs should populate this with at least one trusted
    /// bootstrap node.
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
}

fn default_block_interval_ms() -> u64 {
    500
}

fn default_listen_addr() -> String {
    "/ip4/0.0.0.0/tcp/0".to_string()
}

impl NodeConfig {
    /// Load a [`NodeConfig`] from the JSON file at `path`.
    ///
    /// # Errors
    ///
    /// - [`NodeError::Config`] — `path` cannot be read, or the JSON is
    ///   structurally invalid.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, NodeError> {
        let contents = std::fs::read_to_string(path.as_ref())
            .map_err(|e| NodeError::Config(format!("cannot read config: {e}")))?;
        serde_json::from_str(&contents)
            .map_err(|e| NodeError::Config(format!("invalid config JSON: {e}")))
    }

    /// Validate structural constraints.
    ///
    /// Called by the node at startup before opening the database.
    ///
    /// # Errors
    ///
    /// - [`NodeError::Config`] — `data_dir` or `genesis_path` is an empty
    ///   path component, `block_interval_ms` is zero, or `listen_addr` /
    ///   any `bootstrap_peers` entry is not a valid libp2p multiaddr.
    pub fn validate(&self) -> Result<(), NodeError> {
        if self.data_dir.as_os_str().is_empty() {
            return Err(NodeError::Config("data_dir must not be empty".into()));
        }
        if self.genesis_path.as_os_str().is_empty() {
            return Err(NodeError::Config("genesis_path must not be empty".into()));
        }
        if self.block_interval_ms == 0 {
            return Err(NodeError::Config("block_interval_ms must be > 0".into()));
        }
        // Validate multiaddr strings early so startup fails fast with a clear message.
        self.listen_addr
            .parse::<libp2p::Multiaddr>()
            .map_err(|e| NodeError::Config(format!("invalid listen_addr '{}': {e}", self.listen_addr)))?;
        for peer in &self.bootstrap_peers {
            peer.parse::<libp2p::Multiaddr>()
                .map_err(|e| NodeError::Config(format!("invalid bootstrap peer '{peer}': {e}")))?;
        }
        Ok(())
    }

    /// Parse `listen_addr` into a [`libp2p::Multiaddr`].
    ///
    /// Assumes [`Self::validate`] has already passed — panics with `expect`
    /// on parse failure (programming error; validate ensures the string is
    /// well-formed before this is called).
    pub fn parsed_listen_addr(&self) -> libp2p::Multiaddr {
        self.listen_addr
            .parse()
            .expect("listen_addr validated before use")
    }

    /// Parse all `bootstrap_peers` into a `Vec<libp2p::Multiaddr>`.
    ///
    /// Assumes [`Self::validate`] has already passed.
    pub fn parsed_bootstrap_peers(&self) -> Vec<libp2p::Multiaddr> {
        self.bootstrap_peers
            .iter()
            .map(|s| s.parse().expect("bootstrap_peers validated before use"))
            .collect()
    }
}

#[cfg(test)]
mod tests;
