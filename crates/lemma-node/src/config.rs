//! Node runtime configuration.
//!
//! [`NodeConfig`] holds the startup parameters for a Lemma node. Phase 1
//! requires only a data directory and a genesis file path. Network parameters
//! (listen address, bootstrap peers) are added in step N4.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::NodeError;

/// Runtime configuration for a Lemma full node.
///
/// Loaded from a JSON file via [`NodeConfig::load`] or constructed directly
/// (e.g. in tests). Fields are `pub` so callers can inspect them; mutation
/// after construction is intentionally unsupported — create a new config.
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
}

fn default_block_interval_ms() -> u64 {
    500
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
    ///   path component.
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
        Ok(())
    }
}

#[cfg(test)]
mod tests;
