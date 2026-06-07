//! Safety analyzer for the Lem language.
//!
//! Entry point: [`analyze_safety`].  Consumes a [`TypedContract`] (the output
//! of the type checker) and enforces the **SAFETY-001…013** compile-time rules
//! that make honeypots, unlimited mints, fee-to-100%, reentrancy, and nine
//! other attack patterns impossible to compile.
//!
//! ## Pipeline position
//!
//! ```text
//! tokenize → parse → check → [analyze_safety] → (state-access) → (codegen)
//!                                   │
//!                     rejects with Vec<SafetyError> (no WASM emitted)
//! ```
//!
//! ## Design: collect-all, never fail-fast
//!
//! `analyze_safety` returns **all** violations found in a single pass.
//! Returning on the first error is friendlier but requires a re-compile after
//! each fix; collecting every violation lets the developer fix them all at once.
//! A non-empty `Vec<SafetyError>` fails compilation.
//!
//! ## Two-tier safety model
//!
//! - **Tier 1 (this module)**: compile-time rules — decidable, sound, blocking.
//!   If `analyze_safety` returns `Ok(())`, the enforced decidable properties hold.
//! - **Tier 2 (runtime score)**: the undecidable residue observed post-deployment
//!   (sell-success rate, holder concentration, etc.).  Not implemented here — the
//!   runtime score is a Phase 4 / RPC concern.
//!
//! ## Rule scope
//!
//! SAFETY-001…013 — token safety rules.  SAFETY-014…019 (agent-safety, Warden)
//! are Track C, P3·Step 11; they are **not** part of this module.
//!
//! ## Implementation status
//!
//! - **4a** (this step): `SafetyError` enum + `analyze_safety` stub (returns `Ok(())`).
//! - **4b**: foundational analyses — `authset` (Auth/EffAuth), `cfg` (CFG/Ext(f)).
//! - **4c**: `dataflow` (totalSupply reachability, fee sup-bound, restriction links).
//! - **4d**: rules batch 1 — SAFETY-004/012/008/011.
//! - **4e**: rules batch 2 — SAFETY-002/003/006/013.
//! - **4f**: rules batch 3 — SAFETY-005/009/001/007/010.
//! - **4g**: integration + fuzz + pipeline wiring + docs closeout.

pub(crate) mod authset;
pub(crate) mod cfg;
pub mod error;
pub(crate) mod safety;

pub use error::SafetyError;
pub use safety::analyze_safety;
