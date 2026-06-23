//! # Agent Identity Registry interface (14 §7.1, P3·Step 16)
//!
//! Provides deterministic read/write access to the Agent Identity Registry,
//! which lives in the Lemma registry system contract namespace (`Address::registry()`).
//!
//! ## Storage layout
//!
//! Identity records are keyed by the agent's session-key **address** (20 bytes),
//! stored under the registry contract address:
//!
//! ```text
//! (contract = Address::registry(), key = b"agent:identity:" ++ agent.as_bytes())
//!   → JSON-serialized AgentIdentity
//! ```
//!
//! This reuses the registry system contract namespace (DB-A54) exactly as the
//! token auto-registration does in the executor (`try_write_registry_entry`),
//! keeping a single authoritative namespace for all on-chain indices.
//!
//! ## Determinism (AGENTS §7.1)
//!
//! All key construction is deterministic: `b"agent:identity:"` (fixed) ++
//! `agent.as_bytes()` (20-byte fixed-length address). No `HashMap`, no RNG,
//! no wall-clock in this module.
//!
//! ## Write side (DEFERRED — `kill-switch-write-gap` mirror)
//!
//! `write_agent_identity` is `#[cfg(test)]` — the owner-authorized registration
//! transaction handler has not been built yet. Technical debt: `agent-identity-write-gap`.
//! Remove `#[cfg(test)]` when the registration-tx handler lands.

use lemma_core::{address::Address, agent::AgentIdentity};

use crate::state::ContractStateView;

// ── Key prefix ────────────────────────────────────────────────────────────────

/// Storage key prefix for Agent Identity Registry entries.
///
/// Full key layout (deterministic, AGENTS §7.1):
/// ```text
/// b"agent:identity:" ++ agent.as_bytes() (20 bytes) = 35 bytes total
/// ```
///
/// Stored under `Address::registry()` — same system contract namespace as the
/// token registry (DB-A54), ensuring a single authoritative on-chain index.
const AGENT_IDENTITY_KEY_PREFIX: &[u8] = b"agent:identity:";

// ── Key builder ───────────────────────────────────────────────────────────────

/// Build the registry storage key for an agent identity record.
///
/// Key = `AGENT_IDENTITY_KEY_PREFIX` ++ `agent.as_bytes()` (35 bytes).
/// Deterministic for the same input (AGENTS §7.1).
fn agent_identity_key(agent: &Address) -> Vec<u8> {
    let addr_bytes = agent.as_bytes();
    let mut key = Vec::with_capacity(AGENT_IDENTITY_KEY_PREFIX.len() + addr_bytes.len());
    key.extend_from_slice(AGENT_IDENTITY_KEY_PREFIX);
    key.extend_from_slice(addr_bytes);
    key
}

// ── Registry I/O ──────────────────────────────────────────────────────────────

/// Read an agent's identity record from the Identity Registry.
///
/// Returns `None` if no record exists for `agent` (unregistered) or if the
/// stored bytes are corrupt (with a warning log — corrupt bytes are treated as
/// "not registered" to avoid halting the settlement path, per AGENTS §7.2).
///
/// ## Determinism (AGENTS §7.1)
///
/// Reads only committed state; no wall-clock, no RNG, no `HashMap`.
/// Deserializes JSON exactly as `read_policy` in `warden.rs` does.
pub(crate) fn read_agent_identity<S: ContractStateView>(
    state: &S,
    agent: &Address,
) -> Option<AgentIdentity> {
    let key = agent_identity_key(agent);
    let registry = lemma_core::address::Address::registry();
    let bytes = state.read(&registry, &key)?;
    match serde_json::from_slice::<AgentIdentity>(&bytes) {
        Ok(identity) => Some(identity),
        Err(e) => {
            tracing::warn!(
                agent = %agent,
                error = %e,
                "agent_registry: corrupt identity JSON — treating as unregistered"
            );
            None
        }
    }
}

/// Write (or update) an agent's identity record in the Identity Registry.
///
/// ## Production caller (DEFERRED — agent-identity-write-gap)
///
/// The owner-authorized registration transaction handler has not been built.
/// This function is `#[cfg(test)]` — verified by `agent_registry/tests.rs`
/// and records the correct API contract. Remove `#[cfg(test)]` when the
/// registration-tx handler lands (mirrors `write_owner_paused` Step 15 pattern,
/// `kill-switch-write-gap`).
///
/// ## No-panic guarantee (AGENTS §7.2)
///
/// `serde_json::to_vec` cannot fail for `AgentIdentity` (all fields are
/// JSON-serializable plain data). The `expect` is justified by construction.
/// If serialization fails (future struct with non-serializable fields),
/// the function logs a warning and skips the write — never panics.
#[cfg(test)]
pub(crate) fn write_agent_identity<S: ContractStateView>(
    state: &mut S,
    agent: &Address,
    identity: &AgentIdentity,
) {
    let key = agent_identity_key(agent);
    let registry = lemma_core::address::Address::registry();
    match serde_json::to_vec(identity) {
        Ok(bytes) => state.write(&registry, &key, bytes),
        Err(e) => {
            tracing::warn!(
                agent = %agent,
                error = %e,
                "agent_registry: failed to serialize AgentIdentity — skipping write"
            );
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
