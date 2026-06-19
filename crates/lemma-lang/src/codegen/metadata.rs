//! `"lemma.meta"` WASM custom-section builder (P3·Step 6i).
//!
//! Builds the metadata payload embedded by `emit_module` as the
//! `"lemma.meta"` custom section (last in the WASM binary per §5.5.2).
//!
//! ## Content
//!
//! JSON object:
//! ```json
//! {
//!   "contract": "TokenX",
//!   "compiler": "lemma-lang/0.1.0",
//!   "functions": [
//!     {
//!       "name": "transfer",
//!       "reads": [{"SenderSlot": "balances"}],
//!       "writes": [{"SenderSlot": "balances"}],
//!       "is_express_eligible": true,
//!       "estimated_gas": 4
//!     }
//!   ]
//! }
//! ```
//!
//! ## Consumer
//!
//! LemmaVM reads this section at deploy time to:
//! - Pre-seed the Flux dependency graph with per-function read/write sets
//!   (B5-3 part-a, P3·Step 7)
//! - Classify transactions for the Express mempool fast-path
//!   (`is_express_eligible` flag, 08-EXECUTION_SPEC §1.7)
//!
//! The custom section is ignored by WASM validators and execution engines;
//! only the VM host reads it.

use serde::Serialize;

use crate::analyzer::{analyze_state_access, StateAccessInfo};
use crate::parser::Visibility;
use crate::type_checker::typed_contract::TypedContract;

/// Compiler version string embedded in every `"lemma.meta"` section.
///
/// Lets the VM and tooling detect incompatible metadata formats across
/// compiler versions. Format: `"lemma-lang/{CARGO_PKG_VERSION}"`.
const COMPILER_VERSION: &str = concat!("lemma-lang/", env!("CARGO_PKG_VERSION"));

// ── Serializable structures ───────────────────────────────────────────────────

/// Per-function metadata entry embedded in `"lemma.meta"`.
///
/// The `#[serde(flatten)]` on `hint` inlines `reads`, `writes`,
/// `is_express_eligible`, and `estimated_gas` directly into the JSON object
/// alongside `name` — producing a flat, readable structure per function.
#[derive(Serialize)]
struct FnMeta {
    name: String,
    #[serde(flatten)]
    hint: StateAccessInfo,
}

/// Top-level `"lemma.meta"` payload.
#[derive(Serialize)]
struct ContractMetadata<'a> {
    /// Contract name from the source declaration.
    contract: &'a str,
    /// Compiler version that produced this artifact (e.g. `"lemma-lang/0.1.0"`).
    compiler: &'static str,
    /// Per-function state-access hints — one entry per public function.
    functions: Vec<FnMeta>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Build the `"lemma.meta"` custom-section payload as UTF-8 JSON bytes.
///
/// Calls [`analyze_state_access`] for each public function (visibility `pub`
/// or `external`) and serializes the results alongside the contract name and
/// compiler version.
///
/// ## Determinism
///
/// - Functions emitted in source declaration order (from `contract.functions()`).
/// - `StateAccessInfo.reads`/`writes` use `BTreeSet` → deterministic JSON arrays
///   (AGENTS §7.1).
/// - The JSON serializer is deterministic for structs (no hash-map iteration).
// consumer: codegen/wasm.rs "lemma.meta" custom-section embed (P3·Step 6i)
pub(crate) fn build_metadata(contract: &TypedContract<'_>) -> Vec<u8> {
    let functions: Vec<FnMeta> = contract
        .functions()
        .into_iter()
        .filter(|f| matches!(f.visibility, Visibility::Pub | Visibility::External))
        .map(|func| {
            let hint = analyze_state_access(contract, &func);
            FnMeta {
                name: func.name.to_owned(),
                hint,
            }
        })
        .collect();

    let meta = ContractMetadata {
        contract: contract.name(),
        compiler: COMPILER_VERSION,
        functions,
    };

    // Serialize to JSON bytes. Infallible for our fully-serializable types.
    serde_json::to_vec(&meta).unwrap_or_default()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
