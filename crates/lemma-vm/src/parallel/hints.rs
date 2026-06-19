//! # Compiler state-access hints for Flux pre-seeding (B5-3 part-b)
//!
//! Reads the `"lemma.meta"` WASM custom section embedded by the Lem compiler
//! (P3·Step 6i) and exposes per-function read/write hints to the Flux scheduler.
//!
//! ## Purpose
//!
//! The Lem compiler embeds per-function state-access hints in every compiled
//! WASM artifact as a `"lemma.meta"` custom section (JSON). At block-execution
//! time, the Flux scheduler reads these hints to:
//!
//! 1. **Pre-seed the dependency graph** — transactions whose called functions
//!    are proven disjoint (no overlapping write sets) can be scheduled without
//!    speculation, cutting abort rates.
//! 2. **Classify Express-eligible transactions** — functions where every write
//!    is a sender-owned slot (`is_express_eligible = true`) feed the Express
//!    mempool fast-path (08-EXECUTION_SPEC §1.7).
//!
//! ## Hints are optimization-only (AGENTS §7.1)
//!
//! A wrong or absent hint only costs a re-execution; MVCC re-validates every
//! transaction regardless. The scheduler ALWAYS falls back to conservative mode
//! (assume conflict) when hints are absent or unparseable. Correctness is never
//! contingent on hint accuracy.
//!
//! ## Dependency direction (AGENTS §8)
//!
//! `lemma-vm` must NOT import `lemma-lang` types. [`ContractHints`] and
//! [`FunctionHint`] are VM-native types that mirror the JSON structure produced
//! by `lemma-lang`'s `build_metadata()`. The JSON is the stable interface.
//!
//! ## Custom section format
//!
//! The `"lemma.meta"` section contains UTF-8 JSON:
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

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use tracing::warn;

use lemma_core::address::Address;

// ── Public types ─────────────────────────────────────────────────────────────

/// Per-contract state-access hints extracted from the `"lemma.meta"` WASM
/// custom section.
///
/// Keyed by function name (from the contract's public API). Functions absent
/// from the map are treated conservatively (assume conflict, not Express-eligible).
///
/// Uses [`BTreeMap`] for deterministic iteration (AGENTS §7.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContractHints {
    /// Per-function hints, keyed by function name.
    pub functions: BTreeMap<String, FunctionHint>,
}

/// State-access hint for a single contract function.
///
/// `reads` and `writes` are serialized [`AccessKey`] strings from the compiler.
/// The Flux scheduler uses these to detect disjointness between transactions.
///
/// Uses [`BTreeSet`] for deterministic iteration (AGENTS §7.1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionHint {
    /// Serialized read keys (AccessKey JSON strings from the compiler).
    pub reads: BTreeSet<String>,
    /// Serialized write keys (AccessKey JSON strings from the compiler).
    pub writes: BTreeSet<String>,
    /// `true` if every write is a sender-owned slot and there is no external
    /// call — the Express mempool fast-path proof (08-EXECUTION_SPEC §1.7).
    pub is_express_eligible: bool,
}

impl FunctionHint {
    /// Returns `true` if this function's write set is provably disjoint from
    /// `other`'s write set AND neither touches the other's read set.
    ///
    /// Disjointness is conservative: if either set is empty (no hints), returns
    /// `false` (assume conflict). This ensures the fallback is always safe.
    ///
    /// Used by the Flux scheduler to skip speculative execution for proven-
    /// disjoint transaction pairs.
    pub fn is_disjoint_from(&self, other: &FunctionHint) -> bool {
        // Empty sets mean "no hint available" — conservatively assume conflict.
        if self.writes.is_empty() && self.reads.is_empty() {
            return false;
        }
        if other.writes.is_empty() && other.reads.is_empty() {
            return false;
        }
        // Write-write conflict: any shared write key → not disjoint.
        if !self.writes.is_disjoint(&other.writes) {
            return false;
        }
        // Write-read conflict: self writes something other reads → not disjoint.
        if !self.writes.is_disjoint(&other.reads) {
            return false;
        }
        // Read-write conflict: other writes something self reads → not disjoint.
        if !other.writes.is_disjoint(&self.reads) {
            return false;
        }
        true
    }
}

// ── Hint map type alias ───────────────────────────────────────────────────────

/// Map from contract address to its compiled state-access hints.
///
/// Passed optionally to [`crate::parallel::execute_block_parallel`]. When
/// `None`, the scheduler runs in conservative mode (assume all conflicts).
///
/// Uses [`BTreeMap`] for deterministic iteration (AGENTS §7.1).
pub type HintMap = BTreeMap<Address, ContractHints>;

// ── WASM custom section parser ────────────────────────────────────────────────

/// Parse the `"lemma.meta"` custom section from `wasm_bytes` into
/// [`ContractHints`].
///
/// Returns `None` (with a warning log) if:
/// - The WASM module cannot be parsed.
/// - The `"lemma.meta"` section is absent.
/// - The JSON is malformed or missing required fields.
///
/// Callers MUST treat `None` as "no hints available" and fall back to
/// conservative scheduling — this is an optimization path, never a correctness
/// requirement (AGENTS §7.1).
pub fn parse_hints_from_wasm(wasm_bytes: &[u8]) -> Option<ContractHints> {
    let payload = find_lemma_meta_section(wasm_bytes)?;
    parse_hints_from_json(&payload)
}

/// Extract the raw bytes of the `"lemma.meta"` custom section from WASM bytes.
///
/// Iterates WASM sections using `wasmparser` (a transitive dependency of
/// wasmtime — no new crate needed) to find the custom section named
/// `"lemma.meta"`. Returns `None` if absent or if the WASM is malformed.
///
/// `wasmparser` is used directly rather than `wasmtime::Module` because
/// `Module::custom_sections` was removed in wasmtime 0.20+ and is not
/// available in wasmtime 45.x. `wasmparser` is already linked transitively
/// (AGENTS §9.3 — minimize dep count).
fn find_lemma_meta_section(wasm_bytes: &[u8]) -> Option<Vec<u8>> {
    use wasmparser::{Parser, Payload};

    for payload in Parser::new(0).parse_all(wasm_bytes) {
        match payload {
            Ok(Payload::CustomSection(reader)) => {
                if reader.name() == "lemma.meta" {
                    return Some(reader.data().to_vec());
                }
            }
            Ok(_) => {} // skip non-custom sections
            Err(e) => {
                warn!(
                    error = %e,
                    "lemma.meta: WASM parse error while scanning for custom section — \
                     falling back to conservative scheduling"
                );
                return None;
            }
        }
    }
    // Section not found — no hints available (not an error).
    None
}

/// Parse [`ContractHints`] from raw JSON bytes (the `"lemma.meta"` payload).
///
/// Returns `None` with a warning if the JSON is malformed.
///
/// `pub(crate)` for testing — the public API is [`parse_hints_from_wasm`].
pub(crate) fn parse_hints_from_json(json_bytes: &[u8]) -> Option<ContractHints> {
    let raw: RawContractMetadata = serde_json::from_slice(json_bytes)
        .map_err(|e| {
            warn!(
                error = %e,
                "lemma.meta: JSON parse failed — falling back to conservative scheduling"
            );
        })
        .ok()?;

    let functions: BTreeMap<String, FunctionHint> = raw
        .functions
        .into_iter()
        .map(|f| {
            let hint = FunctionHint {
                reads: serialize_access_keys(&f.reads),
                writes: serialize_access_keys(&f.writes),
                is_express_eligible: f.is_express_eligible,
            };
            (f.name, hint)
        })
        .collect();

    Some(ContractHints { functions })
}

/// Serialize a slice of raw [`RawAccessKey`] values into canonical string keys.
///
/// The string representation is the stable interface between the compiler's
/// `AccessKey` enum and the VM's hint consumer. Each variant serializes to a
/// unique, deterministic string that the scheduler uses for set-intersection
/// disjointness checks.
fn serialize_access_keys(keys: &[RawAccessKey]) -> BTreeSet<String> {
    keys.iter()
        .map(|k| match k {
            RawAccessKey::Field(f) => format!("Field:{f}"),
            RawAccessKey::SenderSlot(f) => format!("SenderSlot:{f}"),
            RawAccessKey::ParamSlot { field, key } => format!("ParamSlot:{field}:{key}"),
            RawAccessKey::DynamicSlot(f) => format!("DynamicSlot:{f}"),
        })
        .collect()
}

// ── Deserialization types (mirrors lemma-lang's JSON output) ──────────────────

/// Raw deserialized `"lemma.meta"` top-level payload.
///
/// Mirrors `lemma-lang`'s `ContractMetadata` struct. The `contract` and
/// `compiler` fields are informational; only `functions` is consumed.
#[derive(Deserialize)]
struct RawContractMetadata {
    /// Per-function state-access hints.
    functions: Vec<RawFnMeta>,
}

/// Raw deserialized per-function metadata entry.
///
/// Mirrors `lemma-lang`'s `FnMeta` struct (with `#[serde(flatten)]` on hint).
/// `estimated_gas` is present in the JSON (emitted by the compiler) but not
/// consumed by the scheduler — serde ignores unknown fields by default, so
/// it is silently dropped without needing a field declaration.
#[derive(Deserialize)]
struct RawFnMeta {
    name: String,
    reads: Vec<RawAccessKey>,
    writes: Vec<RawAccessKey>,
    is_express_eligible: bool,
}

/// Raw deserialized `AccessKey` variant.
///
/// Mirrors `lemma-lang`'s `AccessKey` enum serialization. The compiler derives
/// `Serialize` with serde's default externally-tagged representation:
/// - `Field("balances")` → `{"Field": "balances"}`
/// - `SenderSlot("balances")` → `{"SenderSlot": "balances"}`
/// - `ParamSlot { field, key }` → `{"ParamSlot": {"field": "...", "key": "..."}}`
/// - `DynamicSlot("balances")` → `{"DynamicSlot": "balances"}`
///
/// We use the same externally-tagged representation here (serde default for
/// enums) to match the compiler's output exactly.
#[derive(Deserialize)]
enum RawAccessKey {
    /// Whole-field access: `{"Field": "fieldName"}`.
    Field(String),
    /// Sender-keyed slot: `{"SenderSlot": "fieldName"}`.
    SenderSlot(String),
    /// Parameter-keyed slot: `{"ParamSlot": {"field": "...", "key": "..."}}`.
    ParamSlot { field: String, key: String },
    /// Dynamic/unprovable key (conservative): `{"DynamicSlot": "fieldName"}`.
    DynamicSlot(String),
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
