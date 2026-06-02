//! # lemma-node
//!
//! Lemma full-node binary and library.
//!
//! ## Module structure
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | `config` | [`NodeConfig`] — data dir, genesis path, block interval |
//! | `error` | [`NodeError`] — all node-layer error variants |
//! | `genesis_boot` | Genesis chain initialisation — idempotent, deterministic |
//! | `producer` | Single-node async block-production loop (Phase 1, empty blocks) |
//!
//! Networking, P2P sync, and CLI are added in subsequent Phase-1 steps (N4–N7).
//! Phase 2 replaces the producer with the Surge/Pulse DAG consensus driver.

pub mod config;
pub mod error;
pub mod genesis_boot;
pub mod producer;

pub use config::NodeConfig;
pub use error::NodeError;
pub use genesis_boot::{init_chain, InitOutcome};
pub use producer::{ProducerConfig, build_next_block, commit_block, run as run_producer};
