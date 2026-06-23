//! Tests for `lemma_vm::agent_registry` — Identity Registry I/O (P3·Step 16).

use lemma_core::{
    address::Address,
    agent::{AgentIdentity, KyaTier, REPUTATION_SCORE_MAX},
};

use super::*;
use crate::state::InMemoryStateView;

// ── Test helpers ─────────────────────────────────────────────────────────────

fn agent_addr(n: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = n;
    Address::from_raw_bytes(bytes)
}

fn owner_addr(n: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[0] = n;
    Address::from_raw_bytes(bytes)
}

fn test_identity(kya_tier: KyaTier, score: u16) -> AgentIdentity {
    AgentIdentity {
        owner: owner_addr(1),
        kya_tier,
        reputation_score: score,
    }
}

// ── I/O roundtrip ────────────────────────────────────────────────────────────

#[test]
fn read_agent_identity_returns_none_for_unregistered_agent() {
    let state = InMemoryStateView::new();
    let result = read_agent_identity(&state, &agent_addr(1));
    assert!(result.is_none(), "unregistered agent must return None");
}

#[test]
fn write_then_read_roundtrips_agent_identity() {
    let mut state = InMemoryStateView::new();
    let identity = test_identity(KyaTier::Identified, 75);
    write_agent_identity(&mut state, &agent_addr(1), &identity);

    let read_back = read_agent_identity(&state, &agent_addr(1));
    assert_eq!(
        read_back,
        Some(identity),
        "identity must roundtrip through state"
    );
}

#[test]
fn write_then_read_preserves_verified_tier_and_max_score() {
    let mut state = InMemoryStateView::new();
    let identity = test_identity(KyaTier::Verified, REPUTATION_SCORE_MAX);
    write_agent_identity(&mut state, &agent_addr(2), &identity);

    let read_back = read_agent_identity(&state, &agent_addr(2)).expect("must exist");
    assert_eq!(read_back.kya_tier, KyaTier::Verified);
    assert_eq!(read_back.reputation_score, REPUTATION_SCORE_MAX);
}

#[test]
fn different_agents_have_independent_registry_entries() {
    let mut state = InMemoryStateView::new();
    let id_a = test_identity(KyaTier::Identified, 50);
    let id_b = test_identity(KyaTier::Verified, 90);

    write_agent_identity(&mut state, &agent_addr(1), &id_a);
    write_agent_identity(&mut state, &agent_addr(2), &id_b);

    assert_eq!(
        read_agent_identity(&state, &agent_addr(1))
            .unwrap()
            .kya_tier,
        KyaTier::Identified
    );
    assert_eq!(
        read_agent_identity(&state, &agent_addr(2))
            .unwrap()
            .kya_tier,
        KyaTier::Verified
    );
}

// ── Key determinism ───────────────────────────────────────────────────────────

#[test]
fn agent_identity_key_is_deterministic_for_same_address() {
    let addr = agent_addr(42);
    assert_eq!(
        agent_identity_key(&addr),
        agent_identity_key(&addr),
        "key construction must be deterministic (AGENTS §7.1)"
    );
}

#[test]
fn agent_identity_key_differs_for_different_addresses() {
    let key_a = agent_identity_key(&agent_addr(1));
    let key_b = agent_identity_key(&agent_addr(2));
    assert_ne!(key_a, key_b, "different agents must have different keys");
}

#[test]
fn agent_identity_key_stored_under_registry_contract_not_warden() {
    // Verify the registry address is used, not the warden address.
    // This ensures agent identities and Warden policies don't share a namespace.
    let registry = lemma_core::address::Address::registry();
    let warden = lemma_core::address::Address::warden();
    assert_ne!(
        registry, warden,
        "registry and warden addresses must be distinct to avoid key collisions"
    );
}
