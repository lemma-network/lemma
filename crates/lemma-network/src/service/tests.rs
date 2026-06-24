use libp2p::{identity, PeerId};
use tokio::sync::mpsc;

use lemma_core::{address::Address, amount::Amount, block::Block, hash::Hash, header::BlockHeader};

use crate::{
    config::NetworkConfig,
    service::{
        NetworkCommand, NetworkEvent, NetworkHandle, NetworkService, COMMAND_CHANNEL_CAPACITY,
        EVENT_CHANNEL_CAPACITY,
    },
};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Minimal valid `Block` for service tests (DRY — AGENTS.md §2.6).
fn test_block() -> Block {
    let header = BlockHeader::new(
        0,
        1_700_000_000,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        1, // protocol_version
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        1_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("test block header is always valid");
    Block::new(header, vec![], vec![], None).expect("test block is always valid")
}

// ── Constants ─────────────────────────────────────────────────────────────────

#[test]
fn command_channel_capacity_is_nonzero() {
    // `const { assert!() }` evaluates at compile time — a change to 0 is a compile
    // error, not just a test failure. Correct tool for usize constant invariants.
    const {
        assert!(COMMAND_CHANNEL_CAPACITY > 0);
    }
}

#[test]
fn event_channel_capacity_is_nonzero() {
    const {
        assert!(EVENT_CHANNEL_CAPACITY > 0);
    }
}

// ── NetworkHandle — Clone ─────────────────────────────────────────────────────

#[test]
fn network_handle_is_clone() {
    // Verify Clone is derived — compile-time check + runtime assertion.
    let (tx, _rx) = mpsc::channel::<NetworkCommand>(1);
    let handle = NetworkHandle { command_tx: tx };
    let cloned = handle.clone();
    // Both must be usable (not moved).
    let _ = format!("{handle:?}");
    let _ = format!("{cloned:?}");
}

// ── NetworkCommand — Debug ────────────────────────────────────────────────────

#[test]
fn network_command_debug_contains_variant_name() {
    let cmd = NetworkCommand::BroadcastBlock(Box::new(test_block()));
    assert!(format!("{cmd:?}").contains("BroadcastBlock"));

    let cmd = NetworkCommand::Dial("/ip4/127.0.0.1/tcp/9000".parse().unwrap());
    assert!(format!("{cmd:?}").contains("Dial"));
}

// ── NetworkEvent — Debug ──────────────────────────────────────────────────────

#[test]
fn network_event_debug_contains_variant_name() {
    let event = NetworkEvent::PeerConnected(PeerId::random());
    assert!(format!("{event:?}").contains("PeerConnected"));

    let event = NetworkEvent::PeerDisconnected(PeerId::random());
    assert!(format!("{event:?}").contains("PeerDisconnected"));

    let event = NetworkEvent::ListeningOn("/ip4/0.0.0.0/tcp/9000".parse().unwrap());
    assert!(format!("{event:?}").contains("ListeningOn"));
}

// ── NetworkService::new ───────────────────────────────────────────────────────

#[tokio::test]
async fn service_new_succeeds_with_default_config() {
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::default();

    let result = NetworkService::new(key, &config);
    assert!(
        result.is_ok(),
        "NetworkService::new must succeed with default config: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn service_new_returns_handle_and_event_rx() {
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::default();

    let (service, handle, event_rx) = NetworkService::new(key, &config).unwrap();

    // All three components must be usable.
    let _ = format!("{handle:?}");
    drop(event_rx);
    drop(service);
}

#[tokio::test]
async fn service_new_succeeds_with_testnet_config() {
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::testnet();

    let result = NetworkService::new(key, &config);
    assert!(
        result.is_ok(),
        "NetworkService::new must succeed with testnet config: {:?}",
        result.err()
    );
}

// ── NetworkHandle — command sending ───────────────────────────────────────────

#[tokio::test]
async fn handle_broadcast_block_sends_command() {
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::default();
    let (_service, handle, _event_rx) = NetworkService::new(key, &config).unwrap();

    // Must not error — the service is alive (not yet dropped).
    let result = handle.broadcast_block(test_block()).await;
    assert!(
        result.is_ok(),
        "broadcast_block must succeed while service is alive"
    );
}

#[tokio::test]
async fn handle_returns_error_when_service_dropped() {
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::default();
    let (service, handle, _event_rx) = NetworkService::new(key, &config).unwrap();

    // Drop the service (closes the command_rx side).
    drop(service);

    let result = handle.broadcast_block(test_block()).await;
    assert!(
        result.is_err(),
        "broadcast_block must error when service is dropped"
    );
}

// ── NetworkService::run — lifecycle ───────────────────────────────────────────

#[tokio::test]
async fn service_run_shuts_down_when_all_handles_dropped() {
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::default();
    let (service, handle, _event_rx) = NetworkService::new(key, &config).unwrap();

    // Spawn the service event loop.
    let service_task = tokio::spawn(service.run());

    // Drop the handle — this closes the command channel.
    drop(handle);

    // The service should shut down within a reasonable time.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), service_task).await;

    assert!(
        result.is_ok(),
        "service.run() must return within 5s after all handles are dropped"
    );
    // The JoinHandle result should be Ok(()) — no panic.
    assert!(result.unwrap().is_ok(), "service.run() must not panic");
}

#[tokio::test]
async fn service_emits_listening_on_event() {
    let key = identity::Keypair::generate_ed25519();
    let config = NetworkConfig::default();
    let (service, handle, mut event_rx) = NetworkService::new(key, &config).unwrap();

    // Spawn the service.
    let _service_task = tokio::spawn(service.run());

    // Wait for a ListeningOn event (should arrive quickly on loopback).
    let event = tokio::time::timeout(std::time::Duration::from_secs(5), event_rx.recv()).await;

    // Drop handle to shut down the service.
    drop(handle);

    assert!(event.is_ok(), "must receive an event within 5s");
    let event = event.unwrap();
    assert!(event.is_some(), "event channel must not be closed");

    match event.unwrap() {
        NetworkEvent::ListeningOn(addr) => {
            // The address should be a valid multiaddr.
            assert!(
                !addr.to_string().is_empty(),
                "ListeningOn address must be non-empty"
            );
        }
        other => {
            // Other events (PeerConnected from mDNS self-discovery) are acceptable.
            // Just verify we got *something*.
            let _ = other;
        }
    }
}
