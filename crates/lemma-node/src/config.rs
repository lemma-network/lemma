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
        Ok(())
    }
}

#[cfg(test)]
mod tests;
