//! DAG types and structures for the Surge dissemination layer.
//!
//! # Modules
//!
//! | Module | Role |
//! |--------|------|
//! | `block`           | [`DagBlock`], [`DagBlockRef`], [`Slot`], [`TxBatchRef`], [`CommitVote`] |
//! | `graph`           | [`Dag`] store — insert, queries, GC, epoch advance |
//! | `validity`        | Pure validity-check functions (spec §3 rules 1–6) |
//! | `threshold_clock` | [`ThresholdClock`] — Surge round advancement (spec §2.3) |
//! | `surge`           | [`SurgeDriver`] — per-epoch consensus orchestrator (spec §11) |

pub mod block;
pub mod graph;
pub mod surge;
pub mod threshold_clock;
pub(crate) mod validity;

pub use block::{CommitVote, DagBlock, DagBlockBody, DagBlockRef, Slot, TxBatchRef};
pub use graph::{Dag, InsertOutcome};
pub use surge::{SurgeDriver, SurgeOutput};
pub use threshold_clock::ThresholdClock;
