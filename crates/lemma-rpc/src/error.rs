//! RPC error types for `lemma-rpc`.
//!
//! [`RpcError`] is the single error type for all RPC handler failures.
//! It maps to JSON-RPC 2.0 error codes in [`crate::types::JsonRpcError`].
//!
//! # Design
//!
//! - `#[non_exhaustive]` on the top-level enum: adding a variant is not a
//!   breaking change for downstream crates.
//! - Structured fields on variants where the context is diagnostic.
//! - Standard JSON-RPC 2.0 error codes (see [`RpcError::code`]).

use thiserror::Error;

// ── Standard JSON-RPC 2.0 error codes ────────────────────────────────────────

/// JSON-RPC 2.0 standard error code: parse error.
pub const CODE_PARSE_ERROR: i64 = -32700;
/// JSON-RPC 2.0 standard error code: invalid request.
pub const CODE_INVALID_REQUEST: i64 = -32600;
/// JSON-RPC 2.0 standard error code: method not found.
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC 2.0 standard error code: invalid params.
pub const CODE_INVALID_PARAMS: i64 = -32602;
/// JSON-RPC 2.0 standard error code: internal error.
pub const CODE_INTERNAL_ERROR: i64 = -32603;

// ── RpcError ──────────────────────────────────────────────────────────────────

/// Errors produced by the `lemma-rpc` crate.
///
/// Every variant maps to a JSON-RPC 2.0 error code via [`RpcError::code`].
/// Handlers return `Result<serde_json::Value, RpcError>` and the server
/// converts errors to `JsonRpcResponse { error: Some(...) }`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RpcError {
    // ── Request-level errors ─────────────────────────────────────────────────
    /// The request body could not be parsed as JSON.
    #[error("parse error: {reason}")]
    ParseError { reason: String },

    /// The JSON-RPC envelope is invalid (missing `jsonrpc`, wrong version, etc.).
    #[error("invalid request: {reason}")]
    InvalidRequest { reason: String },

    /// The requested method does not exist.
    #[error("method not found: {method}")]
    MethodNotFound { method: String },

    /// The method parameters are invalid or missing.
    #[error("invalid params: {reason}")]
    InvalidParams { reason: String },

    // ── Storage / state errors ────────────────────────────────────────────────
    /// A storage read failed (RocksDB I/O error, trie corruption, etc.).
    #[error("storage error: {reason}")]
    StorageError { reason: String },

    // ── Mempool errors ────────────────────────────────────────────────────────
    /// The transaction was rejected by the mempool admission pipeline.
    #[error("transaction rejected: {reason}")]
    TransactionRejected { reason: String },

    // ── Not-yet-implemented errors ────────────────────────────────────────────
    /// The method exists but is not yet implemented.
    ///
    /// Used for stubs that are intentionally deferred (e.g. `lem_call` VM
    /// simulation). Maps to JSON-RPC code `-32601` (Method not found) so
    /// callers can detect the gap without treating it as an internal error.
    #[error("method not implemented: {method} — {reason}")]
    Unsupported { method: String, reason: String },

    // ── Internal errors ───────────────────────────────────────────────────────
    /// An unexpected internal error occurred.
    #[error("internal error: {reason}")]
    Internal { reason: String },
}

impl RpcError {
    /// Map this error to a JSON-RPC 2.0 error code.
    ///
    /// Standard codes:
    /// - `-32700` Parse error
    /// - `-32600` Invalid request
    /// - `-32601` Method not found
    /// - `-32602` Invalid params
    /// - `-32603` Internal error
    #[must_use]
    pub fn code(&self) -> i64 {
        match self {
            Self::ParseError { .. } => CODE_PARSE_ERROR,
            Self::InvalidRequest { .. } => CODE_INVALID_REQUEST,
            // Unsupported maps to MethodNotFound so callers can detect
            // deferred stubs without treating them as internal errors.
            Self::MethodNotFound { .. } | Self::Unsupported { .. } => CODE_METHOD_NOT_FOUND,
            Self::InvalidParams { .. } => CODE_INVALID_PARAMS,
            Self::StorageError { .. }
            | Self::TransactionRejected { .. }
            | Self::Internal { .. } => CODE_INTERNAL_ERROR,
        }
    }
}

// ── From conversions ──────────────────────────────────────────────────────────

impl From<lemma_storage::StorageError> for RpcError {
    fn from(e: lemma_storage::StorageError) -> Self {
        Self::StorageError {
            reason: e.to_string(),
        }
    }
}

impl From<lemma_mempool::error::MempoolError> for RpcError {
    fn from(e: lemma_mempool::error::MempoolError) -> Self {
        Self::TransactionRejected {
            reason: e.to_string(),
        }
    }
}

impl From<serde_json::Error> for RpcError {
    fn from(e: serde_json::Error) -> Self {
        Self::ParseError {
            reason: e.to_string(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
