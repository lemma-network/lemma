//! Code generation orchestrator — Lem typed AST → WASM binary.
//!
//! This module is the entry point for P3·Step 6 (Lem → WASM codegen).
//! It accepts a [`TypedContract`] (the output of the type checker + safety
//! analyzer pipeline) and emits a valid WebAssembly binary (`Vec<u8>`).
//!
//! ## Pipeline position
//!
//! ```text
//! tokenize → parse → check → analyze_safety → analyze_state_access
//!                                                         ↓
//!                                               codegen::compile  ← HERE
//!                                                         ↓
//!                                               Vec<u8>  (WASM binary)
//! ```
//!
//! ## Sub-modules
//!
//! - [`wasm`]     — WASM section builder (wasm-encoder backend, DB-A52)
//! - [`abi`]      — ABI emission stub (full implementation in P3·Step 6i)
//! - [`metadata`] — Custom-section metadata stub (full implementation in P3·Step 6i)
//! - [`types`]    — Lem → WASM type mapping (P3·Step 6c)
//!
//! ## Phase status
//!
//! - **6a** (this file): skeleton + minimal valid WASM with `call` entry point.
//! - **6c**: expression lowering (literals, checked arithmetic, comparison, local var read).
//! - **6d–6e**: statement/function lowering (not yet implemented).
//! - **6i**: ABI + metadata emission.
//! - **6j**: wire into `lib.rs` public pipeline.
//!
//! ## Wiring note
//!
//! `pub(crate) mod codegen` is declared in `lib.rs` but `compile` is NOT yet
//! re-exported at the crate root — that is P3·Step 6j's job. Do not add a
//! `pub use codegen::compile` to `lib.rs` until 6j.

pub(crate) mod abi;
pub(crate) mod metadata;
pub(crate) mod types;
pub(crate) mod wasm;

use crate::error::LangError;
use crate::type_checker::typed_contract::TypedContract;

/// Compile a type-checked Lem contract to a WASM binary.
///
/// Accepts a [`TypedContract`] — the output of the full compiler pipeline
/// (tokenize → parse → check → analyze_safety). The contract MUST be
/// well-formed (P3·Step 4e-bis gate, DB-A38); codegen trusts its input
/// and does not re-validate.
///
/// # Returns
///
/// A `Vec<u8>` containing a valid WebAssembly binary, or a
/// [`LangError::Codegen`] if WASM emission fails.
///
/// # Phase note
///
/// In P3·Step 6a this emits a **minimal valid placeholder** WASM module
/// containing only the `call` entry-point export (no real lowering yet).
/// Real expression/statement/function lowering lands in 6c–6e.
// consumer: lib.rs public pipeline re-export (P3·Step 6j)
#[allow(dead_code)]
pub(crate) fn compile(contract: &TypedContract<'_>) -> Result<Vec<u8>, LangError> {
    wasm::emit_module(contract)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
