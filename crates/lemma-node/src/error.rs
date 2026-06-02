//! Node-layer error type.
//!
//! [`NodeError`] is the single error enum for all node startup and operation
//! failures. Library crates surface their own errors via the `#[from]`
//! conversions below — callers get precise context without wrapping by hand.

use lemma_core::error::{BlockError, CoreError};
use lemma_crypto::error::CryptoError;
use lemma_storage::StorageError;

/// All errors that can occur during Lemma node startup and operation.
///
/// Uses [`thiserror`] for ergonomic `Display` + `From` derivation.
/// `#[non_exhaustive]` allows future variants without breaking callers.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NodeError {
    /// Storage-layer error from `lemma-storage`.
    #[error("storage: {0}")]
    Storage(#[from] StorageError),

    /// Core-type error from `lemma-core`.
    #[error("core: {0}")]
    Core(#[from] CoreError),

    /// Block or block-header construction failed.
    ///
    /// Surfaced when assembling the genesis block or any produced block.
    #[error("block: {0}")]
    Block(#[from] BlockError),

    /// Hashing failure from `lemma-crypto`.
    ///
    /// Unreachable in practice for well-formed blocks — included for
    /// exhaustive error propagation.
    #[error("crypto: {0}")]
    Crypto(#[from] CryptoError),

    /// Node configuration is invalid or could not be loaded from disk.
    #[error("config: {0}")]
    Config(String),

    /// The genesis JSON file could not be read or parsed.
    #[error("genesis: {0}")]
    GenesisJson(String),

    /// Serialization failure (block or metadata encoding/decoding).
    #[error("serialization: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests;
