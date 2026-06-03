//! # lemma-vm
//!
//! LemmaVM: deterministic WASM execution engine for the Lemma blockchain.
//!
//! ## Module structure
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | `error`    | [`VmError`] — all VM failure paths |
//! | `runtime`  | [`LemmaEngine`] + deterministic wasmtime Config (08-EXEC §2.1) |
//! | `gas`      | [`GasMeter`] trait + [`FuelMeter`] impl (B2) |
//! | `host`     | Host functions + [`HostState`] (B3) |
//! | `executor` | Single-tx execution + panic-free settlement (B4) |
//! | `parallel` | Flux: Block-STM parallel executor (B5) |
//!
//! ## Determinism contract
//!
//! Every validator must produce identical receipts and state roots from identical
//! ordered transactions (08-EXECUTION_SPEC §0 / AGENTS.md §7.1).
//! - wasmtime Config is identical on all validators (§2.1).
//! - No `SystemTime`, no `rand`, no float arithmetic outside wasmtime fuel.
//! - State root built over `BTreeMap` (sorted) — never `DashMap` iteration order.
//!
//! ## No-panic settlement contract (Sui-stall lesson)
//!
//! No panic converts an ordered transaction into state. Every failure —
//! OOG, trap, `InsufficientFunds`, invalid WASM — produces a failed
//! `TransactionReceipt`, never a node halt (08-EXECUTION_SPEC §5,
//! AGENTS.md §9.3 "no panics in the settlement path").

pub mod error;
pub mod runtime;
// B2–B5 modules added as they are built:
// pub mod gas;
// pub mod host;
// pub mod executor;
// pub mod parallel;

pub use error::VmError;
pub use runtime::{deterministic_config, LemmaEngine, MAX_CALL_DEPTH, MAX_WASM_STACK};
