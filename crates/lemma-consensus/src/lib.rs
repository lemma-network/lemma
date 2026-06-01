//! # lemma-consensus
//!
//! DAG-based BFT consensus for the Lemma blockchain:
//! **Surge** (data-availability / dissemination layer) +
//! **Pulse** (deterministic ordering / commit rule).
//!
//! ## Protocol
//!
//! Lemma adopts the **Mysticeti uncertified-DAG** model
//! (`docs/07-CONSENSUS_SPEC.md §0`):
//! - One unified DAG carries both data availability (Surge) and ordering (Pulse).
//! - Blocks are signed by their author only — no separate certification round.
//! - Common-case finality: **3 rounds** (~0.5 s WAN).
//! - Fault threshold: Byzantine stake `< S/3` (`2f+1` quorum throughout).
//!
//! ## Module layout
//!
//! | Module | Role |
//! |--------|------|
//! | `error` | Typed errors for all consensus failure paths |
//! | `stake` | `StakeAggregator` — stake-weighted quorum/validity checks (§1.1) |
//! | `dag`   | DAG types, store, validity rules, threshold clock (§2–3) |
//! | `pulse` | Commit rule, leader schedule, linearizer (§4–6) |
//! | `commit`| `Commit` / `CommittedSubDag`, commit-chain digest (§5) |
//! | `reputation` | `ReputationScores` / `LeaderSwapTable` (§6) |
//! | `fee`   | Burn Fee Model: base-fee calc + distribution (§fee) |
//!
//! Validator-set management, epoch transitions, slashing, and rewards live in
//! later steps of this crate (`docs/13-VALIDATOR_EPOCH_SPEC.md`), reusing
//! `stake` and `reputation` from above.
//!
//! ## Determinism invariants
//!
//! Every node MUST produce identical results from identical inputs
//! (`docs/07-CONSENSUS_SPEC.md §12`):
//! - All ordered maps are `BTreeMap` / `BTreeSet` — never `HashMap`.
//! - Commit timestamp = stake-weighted median of leader parents; never `SystemTime`.
//! - All token / stake arithmetic uses `checked_*` (AGENTS.md §7.4).
//! - No `f64` / `f32` anywhere in the commit path.

pub mod error;

pub use error::ConsensusError;
