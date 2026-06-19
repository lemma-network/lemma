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
//! | `parallel` | Flux: Block-STM parallel executor (B5) + compiler hints (B5-3b) |
//! | `safety_manifest` | [`SafetyManifest`] + [`SafetyConstraint`] — runtime honeypot invariants (P3·Step 18) |
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
pub mod executor;
pub mod gas;
pub mod host;
pub mod parallel;
pub mod runtime;
pub mod safety_manifest;
pub mod state;

pub use error::VmError;
pub use executor::Executor;
pub use gas::{gas_used, FuelMeter, Gas, GasMeter, GasSchedule};
pub use host::{BlockContext, CallContext, HostFunctions, HostState};
pub use parallel::{
    execute_block_parallel, execute_block_sequential, parse_hints_from_wasm,
    tx_is_express_eligible, BlockOutput, BlockScheduler, ContractHints, FluxConfig, FunctionHint,
    HintMap, MvState, ParallelScheduler, SequentialScheduler, StateKey, StateValue,
};
pub use runtime::{deterministic_config, LemmaEngine, MAX_CALL_DEPTH, MAX_WASM_STACK};
pub use safety_manifest::{SafetyConstraint, SafetyManifest};
pub use state::{ContractStateView, InMemoryStateView};
