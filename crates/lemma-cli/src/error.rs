//! CLI error type.
//!
//! [`LemmaCliError`] is the single error enum for all `lemma` CLI failures.
//! Each variant corresponds to one failure domain (I/O, crypto, storage) so
//! users see precise, actionable error messages without internal crate names.

use lemma_crypto::CryptoError;
use lemma_storage::StorageError;

/// All errors that can occur during CLI operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LemmaCliError {
    /// A keystore file could not be read or written.
    ///
    /// Includes the file path in the message for user-actionable context.
    #[error("keystore I/O error ({path}): {source}")]
    KeystoreIo {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Cryptographic operation failed (key generation or keystore parsing).
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Storage / database error when reading chain state.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// An address string could not be parsed as a valid Lemma bech32m address.
    #[error("invalid address '{input}': {reason}")]
    InvalidAddress { input: String, reason: String },

    /// The chain database at the given path has not been initialised yet.
    ///
    /// The user should run `lemma-node` once to perform genesis initialisation
    /// before querying balances directly from the DB.
    #[error("chain database at '{path}' is not initialised (no genesis block found)")]
    ChainNotInitialised { path: std::path::PathBuf },
}
