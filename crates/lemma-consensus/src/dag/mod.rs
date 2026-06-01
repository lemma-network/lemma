//! DAG types and structures for the Surge dissemination layer.
//!
//! # Modules
//!
//! | Module | Role |
//! |--------|------|
//! | `block`    | [`DagBlock`], [`DagBlockRef`], [`Slot`], [`TxBatchRef`], [`CommitVote`] |
//! | `graph`    | [`Dag`] store — insert, queries, GC, epoch advance |
//! | `validity` | Pure validity-check functions (spec §3 rules 1–6) |

pub mod block;
pub mod graph;
pub(crate) mod validity;

pub use block::{CommitVote, DagBlock, DagBlockBody, DagBlockRef, Slot, TxBatchRef};
pub use graph::{Dag, InsertOutcome};
