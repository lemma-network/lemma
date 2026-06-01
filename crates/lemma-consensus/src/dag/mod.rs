//! DAG types and structures for the Surge dissemination layer.
//!
//! # Modules
//!
//! | Module | Role |
//! |--------|------|
//! | `block` | [`DagBlock`], [`DagBlockRef`], [`Slot`], [`TxBatchRef`], [`CommitVote`] |
//!
//! Future modules (`graph`, `threshold_clock`) live in later steps.

pub mod block;

pub use block::{CommitVote, DagBlock, DagBlockBody, DagBlockRef, Slot, TxBatchRef};
