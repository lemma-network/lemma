//! JSON-RPC HTTP server — axum router, bind, serve.
//!
//! [`start_server`] binds an axum HTTP server on the configured address and
//! routes all POST requests to the JSON-RPC dispatcher. The server is
//! stateless per-request; shared state is passed via [`NodeHandle`].
//!
//! ## Architecture
//!
//! ```text
//! POST /  →  dispatch_request  →  route_method  →  handler fn
//!                                                       │
//!                                                  NodeHandle (Arc)
//!                                                  ├── db: Arc<LemmaDb>
//!                                                  ├── mempool: Arc<RwLock<Mempool>>
//!                                                  └── network: NetworkHandle
//! ```
//!
//! ## CORS
//!
//! [`tower_http::cors::CorsLayer`] is applied with permissive defaults for
//! devnet. Production deployments should restrict origins.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{debug, warn};

use lemma_mempool::pool::Mempool;
use lemma_network::service::NetworkHandle;
use lemma_storage::db::LemmaDb;

use crate::{
    error::RpcError,
    handlers,
    types::{JsonRpcRequest, JsonRpcResponse},
    RpcConfig,
};

// ── NodeHandle ────────────────────────────────────────────────────────────────

/// Shared node state passed to every RPC handler.
///
/// Wraps the database, mempool, and network handle in `Arc` so the axum
/// router can clone it cheaply per-request. The mempool is behind an
/// `Arc<RwLock<Mempool>>` because `Mempool::admit` requires `&mut self`.
///
/// # Construction
///
/// Build with [`NodeHandle::new`] and pass to [`start_server`].
#[derive(Clone)]
pub struct NodeHandle {
    /// Shared RocksDB handle — all storage reads go through this.
    pub db: Arc<LemmaDb>,
    /// Pending-transaction pool — `admit` requires write lock.
    pub mempool: Arc<RwLock<Mempool>>,
    /// Network handle — used to broadcast admitted transactions.
    pub network: NetworkHandle,
    /// Chain identifier for replay-protection checks.
    pub chain_id: u64,
}

impl NodeHandle {
    /// Construct a new `NodeHandle`.
    #[must_use]
    pub fn new(
        db: Arc<LemmaDb>,
        mempool: Arc<RwLock<Mempool>>,
        network: NetworkHandle,
        chain_id: u64,
    ) -> Self {
        Self {
            db,
            mempool,
            network,
            chain_id,
        }
    }
}

// ── Request dispatcher ────────────────────────────────────────────────────────

/// Axum handler: parse the JSON-RPC envelope and dispatch to the right handler.
///
/// Returns a JSON-RPC 2.0 response in all cases — errors are encoded as
/// `{ "error": { "code": N, "message": "..." } }`, never as HTTP error codes
/// (per JSON-RPC 2.0 spec: HTTP 200 for all application-level responses).
async fn dispatch_request(State(handle): State<NodeHandle>, body: axum::body::Bytes) -> Response {
    // Parse the raw body as JSON.
    let req: JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            let resp = JsonRpcResponse::error(
                serde_json::Value::Null,
                RpcError::ParseError {
                    reason: e.to_string(),
                },
            );
            return (StatusCode::OK, Json(resp)).into_response();
        }
    };

    let id = req.id.clone();

    // Validate JSON-RPC version.
    if let Err(e) = req.validate_version() {
        let resp = JsonRpcResponse::error(id, e);
        return (StatusCode::OK, Json(resp)).into_response();
    }

    debug!(method = %req.method, "rpc dispatch");

    // Route to the appropriate handler.
    let result = route_method(&handle, &req).await;

    let resp = match result {
        Ok(value) => JsonRpcResponse::success(id, value),
        Err(e) => {
            if matches!(e, RpcError::Internal { .. } | RpcError::StorageError { .. }) {
                warn!(error = %e, method = %req.method, "rpc internal error");
            }
            JsonRpcResponse::error(id, e)
        }
    };

    (StatusCode::OK, Json(resp)).into_response()
}

/// Route a validated request to the correct handler function.
///
/// Returns `Err(RpcError::MethodNotFound)` for unknown methods.
async fn route_method(
    handle: &NodeHandle,
    req: &JsonRpcRequest,
) -> Result<serde_json::Value, RpcError> {
    match req.method.as_str() {
        // ── Chain handlers ────────────────────────────────────────────────────
        "lem_blockNumber" => handlers::chain::block_number(handle),
        "lem_getBlock" => handlers::chain::get_block(handle, &req.params),
        "lem_getLogs" => handlers::chain::get_logs(handle, &req.params),

        // ── State handlers ────────────────────────────────────────────────────
        "lem_getBalance" => handlers::state::get_balance(handle, &req.params),
        "lem_getCode" => handlers::state::get_code(handle, &req.params),
        "lem_getStorageAt" => handlers::state::get_storage_at(handle, &req.params),
        "lem_call" => handlers::state::call(handle, &req.params).await,

        // ── Transaction handlers ──────────────────────────────────────────────
        "lem_sendTransaction" => handlers::tx::send_transaction(handle, &req.params).await,
        "lem_getTransactionReceipt" => handlers::tx::get_transaction_receipt(handle, &req.params),

        // ── Fee handlers ──────────────────────────────────────────────────────
        "lem_gasPrice" => handlers::fee::gas_price(handle),

        // ── Lemma-specific handlers ───────────────────────────────────────────
        "lem_safetyScore" => handlers::lemma::safety_score(handle, &req.params),
        "lem_stateAccess" => handlers::lemma::state_access(handle, &req.params),

        // ── Unknown method ────────────────────────────────────────────────────
        method => Err(RpcError::MethodNotFound {
            method: method.to_owned(),
        }),
    }
}

// ── Server startup ────────────────────────────────────────────────────────────

/// Start the JSON-RPC HTTP server and serve until the process exits.
///
/// Binds on `config.listen_addr`, applies CORS middleware, and runs the
/// axum event loop. This function does not return under normal operation.
///
/// # Errors
///
/// Returns [`RpcError::Internal`] if the TCP listener cannot be bound.
pub async fn start_server(handle: NodeHandle, config: &RpcConfig) -> Result<(), RpcError> {
    let cors = CorsLayer::permissive();

    let app = Router::new()
        .route("/", post(dispatch_request))
        .layer(cors)
        .with_state(handle);

    let listener = tokio::net::TcpListener::bind(&config.listen_addr)
        .await
        .map_err(|e| RpcError::Internal {
            reason: format!("failed to bind {}: {e}", config.listen_addr),
        })?;

    tracing::info!(addr = %config.listen_addr, "lemma-rpc listening");

    axum::serve(listener, app)
        .await
        .map_err(|e| RpcError::Internal {
            reason: format!("server error: {e}"),
        })
}
