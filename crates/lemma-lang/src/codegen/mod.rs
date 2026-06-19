//! Code generation orchestrator — Lem typed AST → WASM binary.
//!
//! This module is the entry point for P3·Step 6 (Lem → WASM codegen).
//! It accepts a [`TypedContract`] (the output of the type checker + safety
//! analyzer pipeline) and emits a valid WebAssembly binary (`Vec<u8>`).
//!
//! ## Pipeline position
//!
//! ```text
//! tokenize → parse → check (WF + safety)
//!                        ↓
//!                  TypedAst::contracts()
//!                        ↓
//!              codegen::compile(&TypedContract)  ← HERE
//!                        ↓
//!               Vec<u8>  (WASM binary with
//!                         "lemma.abi" + "lemma.meta"
//!                          custom sections)
//! ```
//!
//! ## Sub-modules
//!
//! - [`wasm`] — WASM section builder (wasm-encoder, DB-A52). Full lowering:
//!   expressions, statements, functions, storage dispatch, modifiers, Address
//!   constants (6c–6g). Custom section embed (6i).
//! - [`abi`] — ABI descriptor emission: JSON `[{name, selector, params, returns}]` (6i).
//! - [`metadata`] — `"lemma.meta"` custom section: contract name, compiler
//!   version, per-function state-access hints for Flux/Express (B5-3, 6i).
//! - [`types`] — Lem → WASM type mapping (6c).
//!
//! ## Phase status
//!
//! Steps 6a–6j complete (P3·Step 6 ✅). Re-exported at the crate root as
//! `lemma_lang::compile`.

pub(crate) mod abi;
pub(crate) mod metadata;
pub(crate) mod types;
pub(crate) mod wasm;

use crate::error::LangError;
use crate::type_checker::typed_contract::TypedContract;

/// Compile a type-checked Lem contract to a WASM binary.
///
/// Accepts a [`TypedContract`] — the output of the full compiler pipeline
/// (`tokenize → parse → check`). The contract MUST be well-formed
/// (WF gate, DB-A38); `check()` enforces this. Codegen trusts its input
/// and does not re-validate.
///
/// The emitted binary is a self-describing WASM module that contains:
/// - Full function lowering (all supported expression/statement forms)
/// - Storage read/write dispatch (NEAR-style register model, DB-A53)
/// - Built-in `Address` constants in linear memory (DB-A37)
/// - `"lemma.abi"` custom section: JSON function descriptors (DB-A56)
/// - `"lemma.meta"` custom section: state-access hints for Flux/Express
///   (B5-3 part-a, DB-A56)
///
/// # Errors
///
/// Returns [`LangError::Codegen`] if WASM emission fails (e.g. an
/// expression or type that is not yet supported by the current codegen).
/// All type and well-formedness errors are caught earlier by `check()`.
///
/// # Examples
///
/// ```ignore
/// use lemma_lang::{tokenize, parse, check, compile};
///
/// let tokens = tokenize("contract Foo {}")?;
/// let ast = parse(tokens)?;
/// let typed = check(ast)?;
/// for contract in typed.contracts() {
///     let wasm: Vec<u8> = compile(&contract)?;
/// }
/// ```
pub fn compile(contract: &TypedContract<'_>) -> Result<Vec<u8>, LangError> {
    wasm::emit_module(contract)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
