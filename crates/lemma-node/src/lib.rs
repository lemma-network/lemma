//! # lemma-node
//!
//! Lemma full-node binary and library.
//!
//! ## Module structure
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | `config` | [`NodeConfig`] — data dir, genesis path, parsed from JSON file |
//! | `error` | [`NodeError`] — all node-layer error variants |
//! | `genesis_boot` | Genesis chain initialisation — idempotent, deterministic |
//!
//! Networking, mempool wiring, and the async block-production loop are added
//! in subsequent Phase-1 steps (N2–N5).

pub mod config;
pub mod error;
pub mod genesis_boot;

pub use config::NodeConfig;
pub use error::NodeError;
pub use genesis_boot::{init_chain, InitOutcome};
