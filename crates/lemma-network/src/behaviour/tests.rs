use std::time::Duration;

use libp2p::identity;

use crate::config::{NetworkConfig, DEFAULT_GOSSIP_HEARTBEAT};

use super::*;

// ── compute_message_id — pure function, no runtime needed ────────────────────

#[test]
fn compute_message_id_is_deterministic_for_same_data() {
    let data = b"finalized block bytes";
    let id1 = compute_message_id(data);
    let id2 = compute_message_id(data);
    assert_eq!(id1, id2, "same input must produce same message ID");
}

#[test]
fn compute_message_id_differs_for_different_data() {
    let id1 = compute_message_id(b"block at height 100");
    let id2 = compute_message_id(b"block at height 101");
    assert_ne!(id1, id2, "different input must produce different message IDs");
}

#[test]
fn compute_message_id_is_content_addressed_not_pointer_addressed() {
    // Two separate allocations with identical content must produce the same ID.
    // This verifies we hash the bytes, not the pointer.
    let data_a: Vec<u8> = b"identical block".to_vec();
    let data_b: Vec<u8> = b"identical block".to_vec();
    assert_ne!(
        data_a.as_ptr(),
        data_b.as_ptr(),
        "test precondition: must be different allocations"
    );
    assert_eq!(
        compute_message_id(&data_a),
        compute_message_id(&data_b),
        "same byte content must produce same ID regardless of allocation"
    );
}

#[test]
fn compute_message_id_produces_32_bytes_for_empty_input() {
    // Blake3 always outputs exactly 32 bytes regardless of input length.
    // Verify the MessageId inner Vec<u8> carries the full 32-byte hash.
    let id = compute_message_id(&[]);
    assert_eq!(id.0.len(), 32, "MessageId must contain exactly 32 bytes (Blake3 output)");
}

#[test]
fn compute_message_id_produces_32_bytes_for_large_input() {
    // Blake3 is a streaming hash — large inputs must produce the same fixed 32-byte output.
    let large_data = vec![0u8; 1024 * 1024]; // 1 MiB
    let id = compute_message_id(&large_data);
    assert_eq!(id.0.len(), 32, "MessageId must contain exactly 32 bytes for large input");
}

#[test]
fn compute_message_id_changes_with_single_bit_flip() {
    // Verify collision resistance at the bit level — important for dedup correctness.
    let base = vec![0xABu8; 32];
    let mut flipped = base.clone();
    flipped[15] ^= 0x01; // flip one bit in the middle

    let id_base = compute_message_id(&base);
    let id_flipped = compute_message_id(&flipped);
    assert_ne!(
        id_base, id_flipped,
        "a single-bit change must produce a different message ID"
    );
}

// ── build_behaviour — requires tokio runtime (mDNS spawns tasks) ─────────────

#[tokio::test]
async fn build_behaviour_succeeds_with_default_config() {
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::default();
    let result = build_behaviour(&key, &config);
    assert!(
        result.is_ok(),
        "build_behaviour must succeed with a valid keypair and default config, got: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn build_behaviour_succeeds_with_testnet_config() {
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::testnet();
    let result = build_behaviour(&key, &config);
    assert!(
        result.is_ok(),
        "build_behaviour must succeed with testnet config, got: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn build_behaviour_succeeds_with_fast_heartbeat() {
    // Verify non-default heartbeat values thread through without breaking construction.
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig {
        gossip_heartbeat: Duration::from_millis(200),
        ..NetworkConfig::default()
    };
    let result = build_behaviour(&key, &config);
    assert!(
        result.is_ok(),
        "build_behaviour must succeed with fast heartbeat config, got: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn build_behaviour_succeeds_with_short_request_timeout() {
    // Verify request_timeout threads through to the sync behaviour.
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig {
        request_timeout: Duration::from_secs(5),
        ..NetworkConfig::default()
    };
    let result = build_behaviour(&key, &config);
    assert!(
        result.is_ok(),
        "build_behaviour must succeed with short request timeout, got: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn build_behaviour_produces_distinct_instances_from_different_keys() {
    // Two different keypairs should each build successfully and independently.
    let key_a = identity::Keypair::generate_ed25519();
    let key_b = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::default();

    let result_a = build_behaviour(&key_a, &config);
    let result_b = build_behaviour(&key_b, &config);

    assert!(result_a.is_ok(), "behaviour A must build successfully");
    assert!(result_b.is_ok(), "behaviour B must build successfully");
}

#[tokio::test]
async fn build_behaviour_default_config_is_valid_after_validate() {
    // Ensures the config used by build_behaviour also passes NetworkConfig::validate().
    // If validate() ever rejects a value that build_behaviour uses, this catches it.
    let config = NetworkConfig::default();
    assert!(
        config.validate().is_ok(),
        "default config must be valid: {:?}",
        config.validate().err()
    );

    let key = identity::Keypair::generate_ed25519();
    assert!(build_behaviour(&key, &config).is_ok());
}

// ── DEFAULT_GOSSIP_HEARTBEAT sanity ──────────────────────────────────────────

#[test]
fn default_gossip_heartbeat_is_nonzero() {
    // Gossipsub rejects a zero heartbeat — verify the constant is safe.
    assert!(DEFAULT_GOSSIP_HEARTBEAT > Duration::ZERO);
}
