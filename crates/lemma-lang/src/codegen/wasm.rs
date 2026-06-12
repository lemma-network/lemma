//! WASM binary emitter — wasm-encoder backend.
//!
//! Emits a minimal valid WASM module. Phase-3 placeholder — real lowering
//! lands in 6c–6e (expressions), 6d (statements/control-flow), 6e (functions
//! + storage host calls).
//!
//! ## Backend choice
//!
//! Uses `wasm-encoder = "=0.251.0"` (bytecodealliance, decisions-log DB-A52).
//! Chosen for determinism: identical input → identical output bytes, no global
//! state, no RNG, no hash-map iteration in the emit path (AGENTS §7.1).
//!
//! ## Section ordering
//!
//! Canonical WASM section order (per WebAssembly spec §5.5.2):
//! Type → Import → Function → Table → Memory → Global → Export →
//! Start → Element → DataCount → Code → Data → Custom
//!
//! This module emits: Type → Function → Export → Code (minimal subset).
//! Import/Memory/Global/Data sections are added in later sub-steps (6b–6e).
//!
//! ## Determinism guarantee (AGENTS §7.1)
//!
//! - No `HashMap`/`HashSet` — `BTreeMap`/`BTreeSet` only (not yet needed in 6a).
//! - No `SystemTime`, `rand`, or floating-point in the emit path.
//! - Section/function/export ordering is fully deterministic (fixed constants).
//! - `wasm-encoder` itself is a purely syntactic byte emitter with no internal
//!   non-determinism.

use wasm_encoder::{
    CodeSection, ExportKind, ExportSection, Function, FunctionSection, Module, TypeSection,
};

use crate::error::LangError;
use crate::type_checker::typed_contract::TypedContract;

// ─── Constants ────────────────────────────────────────────────────────────────

/// The WASM export name for the contract entry point.
///
/// Every Lem contract exposes a single `call` function as its dispatch entry
/// point. The VM executor looks for this export by name (lemma-vm executor.rs
/// `ENTRY_POINT = "call"`). See 08-EXECUTION_SPEC §1.
const ENTRY_POINT: &str = "call";

/// Type index for the `call` function signature: `[] -> []` (no params, no return).
///
/// In P3·Step 6a this is a placeholder. Real ABI (calldata ptr/len in linear
/// memory) is defined in P3·Step 6b.
const CALL_TYPE_INDEX: u32 = 0;

/// Function index for the `call` function body (the sole defined function in 6a).
///
/// In 6a there are no imported functions, so the first defined function is
/// index 0. When imports are added in 6b, this index will shift — the emitter
/// must account for the import count offset at that point.
const CALL_FUNC_INDEX: u32 = 0;

// ─── Public API ───────────────────────────────────────────────────────────────

/// Emit a minimal valid WASM module for the given contract.
///
/// In P3·Step 6a this is a **placeholder** that emits the smallest possible
/// valid WASM binary: one type (`[] -> []`), one function body (empty, just
/// `end`), and one export (`"call"` → function 0).
///
/// The `_contract` parameter is unused in 6a — real lowering (expressions,
/// statements, functions, storage) is implemented in P3·Steps 6c–6e.
///
/// # Returns
///
/// `Ok(Vec<u8>)` — a valid WebAssembly binary, or
/// `Err(LangError::Codegen)` if section assembly fails.
///
/// # Determinism
///
/// Calling this function twice with the same input produces byte-identical
/// output. See module-level doc for the determinism guarantee.
// consumer: codegen::compile orchestrator (P3·Step 6a+); lib.rs pipeline (P3·Step 6j)
#[allow(dead_code)]
pub(crate) fn emit_module(_contract: &TypedContract<'_>) -> Result<Vec<u8>, LangError> {
    let mut module = Module::new();

    // ── 1. Type section ───────────────────────────────────────────────────────
    // Declare the `call` function type: [] -> [] (no params, no return value).
    // In P3·Step 6b this will be extended with the real ABI signature
    // (calldata ptr/len in linear memory per 08-EXECUTION_SPEC §1).
    let mut types = TypeSection::new();
    types.ty().function([], []);
    module.section(&types);

    // ── 2. Function section ───────────────────────────────────────────────────
    // Declare one function referencing type index 0 (`call`).
    let mut functions = FunctionSection::new();
    functions.function(CALL_TYPE_INDEX);
    module.section(&functions);

    // ── 3. Export section ─────────────────────────────────────────────────────
    // Export the `call` function so the VM executor can find the entry point.
    let mut exports = ExportSection::new();
    exports.export(ENTRY_POINT, ExportKind::Func, CALL_FUNC_INDEX);
    module.section(&exports);

    // ── 4. Code section ───────────────────────────────────────────────────────
    // One function body: no locals, single `end` instruction.
    // Every WASM function body MUST end with `end` (wasm spec §5.4.1).
    let mut codes = CodeSection::new();
    let mut call_fn = Function::new(vec![]);
    call_fn.instruction(&wasm_encoder::Instruction::End);
    codes.function(&call_fn);
    module.section(&codes);

    Ok(module.finish())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
