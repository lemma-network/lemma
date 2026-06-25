//! `"lemma.meta"` WASM custom-section builder (P3·Step 6i, Step 18, Step 19, Step 20).
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
//!   "safety_ruleset": "1.0.0",
//!   "host_abi": 1,
//!   "functions": [
//!     {
//!       "name": "transfer",
//!       "reads": [{"SenderSlot": "balances"}],
//!       "writes": [{"SenderSlot": "balances"}],
//!       "is_express_eligible": true,
//!       "estimated_gas": 4
//!     }
//!   ],
//!   "safety_constraints": [
//!     {"type": "ratchet_off", "key": [109,105,110,116,97,98,108,101]},
//!     {"type": "fee_cap", "fee_keys": [...], "max_sum_bps": 2500}
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
//! - Enforce runtime safety constraints (honeypot prevention, DB-A51,
//!   P3·Step 18)
//!
//! The custom section is ignored by WASM validators and execution engines;
//! only the VM host reads it.

use serde::Serialize;

use crate::analyzer::{analyze_state_access, StateAccessInfo};
use crate::parser::{ConfigValue, Visibility};
use crate::type_checker::typed_contract::TypedContract;

/// Compiler version string embedded in every `"lemma.meta"` section.
///
/// Lets the VM and tooling detect incompatible metadata formats across
/// compiler versions. Format: `"lemma-lang/{CARGO_PKG_VERSION}"`.
const COMPILER_VERSION: &str = concat!("lemma-lang/", env!("CARGO_PKG_VERSION"));

/// Safety-ruleset version embedded in every `"lemma.meta"` section (DB-A58 L1).
///
/// Identifies the safety ruleset that verified the contract. Tokens verified
/// under an older/weaker ruleset are visibly older → feeds Tier-2 safety score.
/// See `docs/17-VERSIONING_SPEC.md` §2.
///
/// Versioning scheme (semver):
/// - MAJOR: rule weakened/removed (guarantee shrinks)
/// - MINOR: rule added/strengthened (guarantee grows)
/// - PATCH: implementation fix (no guarantee change)
///
/// `1.0.0` = post-DB-A57 de-LARP (22 active rules: 001-012, 014-023, 025).
const SAFETY_RULESET_VERSION: &str = "1.0.0";

/// Host-ABI version embedded in every `"lemma.meta"` section (DB-A58 L2).
///
/// References the single source of truth in `lemma-core::CURRENT_HOST_ABI_VERSION`
/// (S3-1 audit fix — no bare unconnected literal in two crates).
///
/// Identifies the host-function ABI version the contract was compiled against.
/// The LemmaVM uses this to dispatch to the correct host-function implementation
/// (see `docs/17-VERSIONING_SPEC.md §3`).
///
/// `parse_host_abi()` in `lemma-vm` defaults to `1` if this field is absent
/// (backward compatibility for pre-Step-20 compiled contracts).
const HOST_ABI_VERSION: u32 = lemma_core::CURRENT_HOST_ABI_VERSION;

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

/// A safety constraint for the runtime honeypot invariant (DB-A51).
///
/// Serialized into `"lemma.meta"` for the VM to enforce post-execution.
/// These mirror the VM's `SafetyConstraint` enum but are Serialize-only
/// (the VM deserializes its own version — no cross-crate type dependency,
/// AGENTS §8).
///
/// `pub` for cross-crate pin tests (S3-2): `lemma-vm` dev-depends on
/// `lemma-lang` and serializes these variants to verify the emit→parse
/// mirror stays in sync. Constructor methods are provided for test ergonomics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type")]
pub enum SafetyConstraintMeta {
    // Deleted: RatchetBool variant (P3 audit subtask 10).
    // Consumer `@std/token enableTrading` (Step 8) never materialized — no
    // extraction logic ever constructed this variant.  If needed later, add it
    // back with a real emitter in `extract_safety_constraints`.
    /// Ratchet-off capability flag: may disable but never re-enable.
    /// E.g. `mintable: true → false` allowed; reverse blocked.
    #[serde(rename = "ratchet_off")]
    RatchetOff {
        /// Storage key prefix identifying this capability flag.
        key: Vec<u8>,
    },

    /// Fee cap: sum of fee component storage values must not exceed a cap.
    /// E.g. `fees.burn + fees.holders + fees.others ≤ maxFeePercent`.
    #[serde(rename = "fee_cap")]
    FeeCap {
        /// Storage key prefixes for each fee component field.
        fee_keys: Vec<Vec<u8>>,
        /// Maximum allowed sum in basis points (bps).
        max_sum_bps: u16,
    },

    /// Ratchet-up: storage value may only increase, never decrease.
    /// E.g. `maxWallet` can be raised (loosened) but never lowered.
    #[serde(rename = "ratchet_up")]
    RatchetUp {
        /// Storage key prefix identifying this field.
        key: Vec<u8>,
    },
}

impl SafetyConstraintMeta {
    /// Build a `RatchetOff` constraint (S3-2 cross-crate test helper).
    pub fn ratchet_off(key: &[u8]) -> Self {
        Self::RatchetOff { key: key.to_vec() }
    }

    /// Build a `FeeCap` constraint (S3-2 cross-crate test helper).
    pub fn fee_cap(fee_keys: &[&[u8]], max_sum_bps: u16) -> Self {
        Self::FeeCap {
            fee_keys: fee_keys.iter().map(|k| k.to_vec()).collect(),
            max_sum_bps,
        }
    }

    /// Build a `RatchetUp` constraint (S3-2 cross-crate test helper).
    pub fn ratchet_up(key: &[u8]) -> Self {
        Self::RatchetUp { key: key.to_vec() }
    }
}

/// Top-level `"lemma.meta"` payload.
#[derive(Serialize)]
struct ContractMetadata<'a> {
    /// Contract name from the source declaration.
    contract: &'a str,
    /// Compiler version that produced this artifact (e.g. `"lemma-lang/0.1.0"`).
    compiler: &'static str,
    /// Safety-ruleset semver that verified this contract (DB-A58 L1).
    safety_ruleset: &'static str,
    /// Host-ABI version this contract was compiled against (DB-A58 L2).
    /// Parsed by the LemmaVM at deploy/call time to select the correct
    /// host-function dispatch table.
    host_abi: u32,
    /// Per-function state-access hints — one entry per public function.
    functions: Vec<FnMeta>,
    /// Safety constraints for the VM runtime honeypot invariant (DB-A51).
    /// Empty for non-token contracts or contracts with no constrainable config.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    safety_constraints: Vec<SafetyConstraintMeta>,
}

// ── Safety constraint extraction ──────────────────────────────────────────────

/// Config keys that represent ratchet-off capabilities (may disable, never re-enable).
const RATCHET_OFF_KEYS: &[&str] = &["mintable", "pausable", "freezable", "upgradeable"];

/// Fee component storage key prefixes for TaxToken fee cap constraints.
const FEE_COMPONENT_KEYS: &[&[u8]] = &[b"fees.burn", b"fees.holders", b"fees.others"];

/// Extract safety constraints from a token contract's config (DB-A51).
///
/// Only processes token contracts (`contract.is_token()`). Plain contracts
/// return an empty vec. Constraints are deterministic derivatives of the
/// config — no new analysis needed, just extraction.
///
/// ## Constraint mapping
///
/// | Config entry | Condition | Constraint |
/// |---|---|---|
/// | `mintable: true` | Feature enabled | `RatchetOff` |
/// | `pausable: true` | Feature enabled | `RatchetOff` |
/// | `freezable: true` | Feature enabled | `RatchetOff` |
/// | `upgradeable: true` | Feature enabled | `RatchetOff` |
/// | `maxWallet: <N>` | Any int value | `RatchetUp` |
/// | `maxFeePercent: <N>` | TaxToken only | `FeeCap` |
fn extract_safety_constraints(contract: &TypedContract<'_>) -> Vec<SafetyConstraintMeta> {
    if !contract.is_token() {
        return Vec::new();
    }

    let config = match contract.config() {
        Some(entries) => entries,
        None => return Vec::new(),
    };

    let is_tax_token = contract.base_standard() == Some("TaxToken");
    let mut constraints = Vec::new();

    for entry in config {
        // Ratchet-off: capability flags that are currently enabled.
        if RATCHET_OFF_KEYS.contains(&entry.key.as_str())
            && matches!(entry.value, ConfigValue::Bool(true))
        {
            constraints.push(SafetyConstraintMeta::RatchetOff {
                key: entry.key.as_bytes().to_vec(),
            });
        }

        // Ratchet-up: maxWallet can only be raised, never lowered.
        if entry.key == "maxWallet" && matches!(entry.value, ConfigValue::Int(_)) {
            constraints.push(SafetyConstraintMeta::RatchetUp {
                key: b"maxWallet".to_vec(),
            });
        }

        // Fee cap: TaxToken maxFeePercent bounds the sum of fee components.
        if is_tax_token && entry.key == "maxFeePercent" {
            if let ConfigValue::Int(bps) = entry.value {
                constraints.push(SafetyConstraintMeta::FeeCap {
                    fee_keys: FEE_COMPONENT_KEYS.iter().map(|k| k.to_vec()).collect(),
                    max_sum_bps: bps as u16,
                });
            }
        }
    }

    constraints
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Build the `"lemma.meta"` custom-section payload as UTF-8 JSON bytes.
///
/// Calls [`analyze_state_access`] for each public function (visibility `pub`
/// or `external`) and serializes the results alongside the contract name and
/// compiler version. Extracts safety constraints from token config for
/// runtime honeypot invariant enforcement (DB-A51, P3·Step 18).
///
/// ## Determinism
///
/// - Functions emitted in source declaration order (from `contract.functions()`).
/// - `StateAccessInfo.reads`/`writes` use `BTreeSet` → deterministic JSON arrays
///   (AGENTS §7.1).
/// - Safety constraints emitted in config declaration order (deterministic).
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

    let safety_constraints = extract_safety_constraints(contract);

    let meta = ContractMetadata {
        contract: contract.name(),
        compiler: COMPILER_VERSION,
        safety_ruleset: SAFETY_RULESET_VERSION,
        host_abi: HOST_ABI_VERSION,
        functions,
        safety_constraints,
    };

    // Serialize to JSON bytes. Our types are fully serializable (no maps with
    // non-string keys, no recursive references) — failure here is a bug, not a
    // runtime condition. LOUD failure over silent-empty for a security payload
    // the VM enforces at runtime (L-7, AGENTS §12).
    serde_json::to_vec(&meta).expect("contract metadata is infallibly serializable")
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
