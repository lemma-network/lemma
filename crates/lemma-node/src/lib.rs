//! # lemma-node
//!
//! Lemma full-node binary and library.
//!
//! ## Module structure
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | `config` | [`NodeConfig`] — data dir, genesis path, block interval, network params |
//! | `error` | [`NodeError`] — all node-layer error variants |
//! | `genesis_boot` | Genesis chain initialisation — idempotent, deterministic |
//! | `network_runner` | Network event-dispatch loop + block broadcaster + range-sync consumer |
//! | `producer` | Single-node async block-production loop (Phase 1, empty blocks) |
//! | `shield_orchestrator` | [`run_epoch_shield`], [`apply_withholding_slashes`] — Shield DKG/reshare + withholding slashes |
//! | `sync` | [`BlockVerifier`] trait, [`StructuralVerifier`], [`SyncTracker`], [`apply_synced_block`] |
//!
//! P2P range-sync catch-up and CLI are added in Phase-1 steps N6–N7.
//! Phase 2 replaces the producer with the Surge/Pulse DAG consensus driver.

pub mod config;
pub mod error;
pub mod genesis_boot;
pub mod network_runner;
pub mod producer;
pub mod shield_orchestrator;
pub mod sync;

pub use config::NodeConfig;
pub use error::NodeError;
pub use genesis_boot::{init_chain, InitOutcome};
pub use network_runner::{run_block_broadcaster, run_network_dispatch};
pub use producer::{build_next_block, commit_block, run as run_producer, ProducerConfig};
pub use shield_orchestrator::{
    apply_withholding_slashes, run_epoch_shield, EpochShieldOutcome, ShieldOrchestratorError,
    TransparentReason, WithholdingSlashOutcome,
};
pub use sync::{apply_synced_block, ApplyOutcome, BlockVerifier, StructuralVerifier, SyncTracker};
