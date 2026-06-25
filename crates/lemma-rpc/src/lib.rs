//! # lemma-rpc
//!
//! JSON-RPC 2.0 HTTP server for the Lemma blockchain.
//!
//! Exposes the `lem_*` method set that wallets, SDKs, and dApps use to
//! interact with the chain. This is the **primary external ingress** for
//! transaction submission and state queries.
//!
//! ## Module structure
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`error`]      | [`RpcError`] — typed errors, JSON-RPC 2.0 codes |
//! | [`types`]      | [`JsonRpcRequest`], [`JsonRpcResponse`], [`JsonRpcError`] |
//! | [`server`]     | axum router, [`NodeHandle`], [`start_server`] |
//! | [`handlers`]   | Per-method handler functions |
//! | [`middleware`] | CORS, rate-limit stub |
//!
//! ## Endpoints
//!
//! | Method | Handler | Description |
//! |--------|---------|-------------|
//! | `lem_blockNumber` | `handlers::chain` | Current chain tip height |
//! | `lem_getBlock` | `handlers::chain` | Block by height or hash |
//! | `lem_getLogs` | `handlers::chain` | Event logs with filter |
//! | `lem_getBalance` | `handlers::state` | Account balance in Drop |
//! | `lem_getCode` | `handlers::state` | Contract bytecode |
//! | `lem_getStorageAt` | `handlers::state` | Contract storage slot |
//! | `lem_call` | `handlers::state` | Read-only contract call |
//! | `lem_sendTransaction` | `handlers::tx` | Submit tx → mempool → gossip |
//! | `lem_getTransactionReceipt` | `handlers::tx` | Receipt by tx hash |
//! | `lem_gasPrice` | `handlers::fee` | Current base fee |
//! | `lem_safetyScore` | `handlers::lemma` | Contract safety score |
//! | `lem_stateAccess` | `handlers::lemma` | Contract state-access hints |
//!
//! ## Usage
//!
//! ```no_run
//! use std::sync::Arc;
//! use tokio::sync::RwLock;
//! use lemma_rpc::{RpcConfig, server::{NodeHandle, start_server}};
//!
//! # async fn example() -> Result<(), lemma_rpc::error::RpcError> {
//! // Build a NodeHandle from your node's shared state.
//! // let handle = NodeHandle::new(db, mempool, network, chain_id);
//! // let config = RpcConfig { listen_addr: "127.0.0.1:8545".into() };
//! // start_server(handle, &config).await?;
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod handlers;
pub mod middleware;
pub mod server;
pub mod types;

pub use error::RpcError;
pub use server::{start_server, NodeHandle};
pub use types::{JsonRpcError, JsonRpcRequest, JsonRpcResponse};

// ── RpcConfig ─────────────────────────────────────────────────────────────────

/// Configuration for the JSON-RPC HTTP server.
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// TCP address to bind the HTTP server on (e.g. `"127.0.0.1:8545"`).
    pub listen_addr: String,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:8545".into(),
        }
    }
}
