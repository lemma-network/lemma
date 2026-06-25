//! JSON-RPC 2.0 envelope types.
//!
//! Implements the JSON-RPC 2.0 wire protocol:
//! - [`JsonRpcRequest`] — inbound request envelope.
//! - [`JsonRpcResponse`] — outbound response envelope.
//! - [`JsonRpcError`] — error object embedded in a failed response.
//!
//! # JSON-RPC 2.0 spec
//!
//! - Request: `{ "jsonrpc": "2.0", "method": "...", "params": [...], "id": ... }`
//! - Success response: `{ "jsonrpc": "2.0", "result": ..., "id": ... }`
//! - Error response: `{ "jsonrpc": "2.0", "error": { "code": N, "message": "..." }, "id": ... }`
//!
//! See <https://www.jsonrpc.org/specification>.

use serde::{Deserialize, Serialize};

use crate::error::RpcError;

// ── JsonRpcRequest ────────────────────────────────────────────────────────────

/// Inbound JSON-RPC 2.0 request envelope.
///
/// The `params` field is kept as a raw [`serde_json::Value`] so each handler
/// can deserialize it into the specific type it expects.
#[derive(Debug, Clone, Deserialize)]
pub struct JsonRpcRequest {
    /// Must be exactly `"2.0"`.
    pub jsonrpc: String,
    /// The method name (e.g. `"lem_blockNumber"`).
    pub method: String,
    /// Method parameters — array or object, or `null` if absent.
    #[serde(default)]
    pub params: serde_json::Value,
    /// Request identifier — echoed back in the response.
    ///
    /// May be a string, number, or `null` (per JSON-RPC 2.0 spec).
    pub id: serde_json::Value,
}

impl JsonRpcRequest {
    /// Validate that `jsonrpc == "2.0"`.
    ///
    /// Returns `Err(RpcError::InvalidRequest)` if the version is wrong.
    ///
    /// # Errors
    ///
    /// - [`RpcError::InvalidRequest`] — `jsonrpc` field is not `"2.0"`.
    pub fn validate_version(&self) -> Result<(), RpcError> {
        if self.jsonrpc != "2.0" {
            return Err(RpcError::InvalidRequest {
                reason: format!("jsonrpc must be \"2.0\", got {:?}", self.jsonrpc),
            });
        }
        Ok(())
    }
}

// ── JsonRpcResponse ───────────────────────────────────────────────────────────

/// Outbound JSON-RPC 2.0 response envelope.
///
/// Exactly one of `result` or `error` is `Some`; the other is `None`.
/// Both are skipped in serialization when `None` (per JSON-RPC 2.0 spec).
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcResponse {
    /// Always `"2.0"`.
    pub jsonrpc: &'static str,
    /// Successful result value. `None` on error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error object. `None` on success.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
    /// Request identifier echoed from the request.
    pub id: serde_json::Value,
}

impl JsonRpcResponse {
    /// Construct a successful response.
    #[must_use]
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0",
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Construct an error response from an [`RpcError`].
    #[must_use]
    pub fn error(id: serde_json::Value, err: RpcError) -> Self {
        Self {
            jsonrpc: "2.0",
            result: None,
            error: Some(JsonRpcError {
                code: err.code(),
                message: err.to_string(),
            }),
            id,
        }
    }
}

// ── JsonRpcError ──────────────────────────────────────────────────────────────

/// JSON-RPC 2.0 error object embedded in a failed response.
#[derive(Debug, Clone, Serialize)]
pub struct JsonRpcError {
    /// Standard JSON-RPC 2.0 error code (e.g. `-32601` for method not found).
    pub code: i64,
    /// Human-readable error message.
    pub message: String,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
