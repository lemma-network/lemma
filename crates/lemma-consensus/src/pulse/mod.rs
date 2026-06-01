//! # Pulse — deterministic commit rule (spec §4–6)
//!
//! Pulse is the ordering layer of Lemma consensus. It is a **pure function of
//! the DAG**: given the same set of accepted blocks, every honest validator
//! arrives at the identical committed prefix (deterministic finality,
//! `docs/07-CONSENSUS_SPEC.md §7`).
//!
//! ## Modules
//!
//! | Module | Role |
//! |--------|------|
//! | `committer` | Commit rule §4: votes/certs/blame, direct/indirect/driver |
//! | `leader`    | Leader schedule §6: round-robin + reputation swap (Step 7) |
//! | `linearizer`| Sub-DAG flatten + total order §5 (Step 8) |

pub mod committer;

pub use committer::{LeaderStatus, try_decide};
