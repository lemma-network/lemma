//! Feature-gate types for Lemma's epoch-boundary upgrade activation (DB-A63).
//!
//! Lemma upgrades along TWO axes (see `docs/17-VERSIONING_SPEC.md §7`):
//! - **Coarse `protocol_version`** (`BlockHeader.protocol_version`, P3·Step 23):
//!   for changes that cannot be feature-gated (header format, consensus algorithm).
//! - **Feature gates** (this module, P3·Step 20 + P4·Step 12):
//!   for ~95% of changes (new host fns, gas reprice, new tx type, host-ABI bumps).
//!
//! ## Build status
//!
//! P3·Step 20 ships the **types + wiring** (`FeatureId`, `BlockContext.active_features`).
//! The **registry + activation** (`BTreeMap<FeatureId, ActivationEpoch>`, governance
//! proposals, epoch-boundary activation logic) is P4·Step 12.
//!
//! Until P4·Step 12 ships, `active_features` in `BlockContext` is always an
//! empty `BTreeSet` — no features are active, which is correct (ABI v1 is the
//! baseline, not a feature gate).

use serde::{Deserialize, Serialize};

/// Identifies a Lemma protocol feature that can be activated at an epoch boundary.
///
/// Feature IDs are monotonically assigned integers. Once a `FeatureId` is
/// activated on a live chain, it MUST NOT be reused for a different feature
/// (activation is irreversible per `docs/17-VERSIONING_SPEC.md §7.5`).
///
/// ## Known feature IDs
///
/// | ID | Feature | Activation | Spec |
/// |----|---------|------------|------|
/// | 1  | Host-ABI v2 (first ABI bump) | P4·Step 12 | DB-A58 L2 + §7.6 |
///
/// ID 0 is reserved and must never be used (guards against zero-initialization bugs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FeatureId(pub u32);

/// Feature ID for the first host-ABI version bump (ABI v1 → v2).
///
/// When this feature is active, contracts compiled against host-ABI v2 can be
/// deployed and called. The VM dispatches to `build_linker_v2` (P4·Step 12).
/// Until activation, only ABI v1 is accepted (`MAX_SUPPORTED_HOST_ABI = 1`).
///
/// Interlock with L2 (docs/17-VERSIONING_SPEC.md §7.6): an L2 ABI bump IS one
/// `FeatureId` — this is the concrete instance.
pub const FEATURE_HOST_ABI_V2: FeatureId = FeatureId(1);

#[cfg(test)]
mod tests;
