//! # lemma-node
//!
//! Lemma full-node binary and library.
//!
//! ## Module structure
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | `config` | [`NodeConfig`] — data dir, genesis path, block interval, network params |
//! | `dag_driver` | **Phase 2** — DAG consensus driver ([`run_dag_driver`]): Surge loop, Commit→block |
//! | `error` | [`NodeError`] — all node-layer error variants |
//! | `genesis_boot` | Genesis chain initialisation — idempotent, deterministic |
//! | `network_runner` | Network event-dispatch loop + block broadcaster + range-sync consumer |
//! | `producer` | **Phase 1** — timer-based empty-block producer (superseded by `dag_driver` in Phase 2) |
//! | `shield_orchestrator` | [`run_epoch_shield`], [`apply_withholding_slashes`] — Shield DKG/reshare + withholding slashes |
//! | `sync` | [`BlockVerifier`] trait, [`StructuralVerifier`], [`SyncTracker`], [`apply_synced_block`] |
//!
//! Phase 2 (Track A Step 12): `dag_driver` replaces `producer` as the block-
//! production engine. The Surge dissemination loop drives the DAG, Pulse decides
//! committed leaders, and each `Commit` maps to one chain `Block` (spec §5.2).

pub mod block_exec;
pub mod config;
pub mod dag_driver;
pub mod error;
pub mod genesis_boot;
pub mod network_runner;
pub mod producer;
pub mod shield_orchestrator;
pub mod state_view;
pub mod sync;

pub use config::NodeConfig;
pub use dag_driver::{build_block_from_commit, build_dag_block, run_dag_driver, DagConfig};
pub use error::NodeError;
pub use genesis_boot::{init_chain, InitOutcome};
pub use network_runner::{run_block_broadcaster, run_network_dispatch};
pub use producer::{build_next_block, commit_block, run as run_producer, ProducerConfig};
pub use shield_orchestrator::{
    apply_withholding_slashes, run_epoch_shield, EpochShieldOutcome, ShieldOrchestratorError,
    TransparentReason, WithholdingSlashOutcome,
};
pub use sync::{apply_synced_block, ApplyOutcome, BlockVerifier, StructuralVerifier, SyncTracker};
