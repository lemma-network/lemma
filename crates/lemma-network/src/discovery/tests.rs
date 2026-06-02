use libp2p::{
    kad::{Addresses, Event as KadEvent, KBucketDistance, U256},
    mdns::Event as MdnsEvent,
    multiaddr::Protocol,
    Multiaddr, PeerId,
};

use crate::peer::PeerTable;

use super::*;

// ── Test port constants ───────────────────────────────────────────────────────

const TEST_PORT_A: u16 = 9000;
const TEST_PORT_B: u16 = 9001;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Deterministic test peer A (seed = all-zeros).
fn peer_a() -> PeerId {
    use libp2p::identity::{ed25519, Keypair};
    // try_from_bytes zeroes the slice after consuming it; `mut` is intentional.
    let mut seed = [0u8; 32];
    let secret = ed25519::SecretKey::try_from_bytes(&mut seed).expect("fixed seed is always valid");
    Keypair::from(ed25519::Keypair::from(secret))
        .public()
        .to_peer_id()
}

/// Deterministic test peer B (seed = all-ones).
fn peer_b() -> PeerId {
    use libp2p::identity::{ed25519, Keypair};
    // try_from_bytes zeroes the slice after consuming it; `mut` is intentional.
    let mut seed = [1u8; 32];
    let secret = ed25519::SecretKey::try_from_bytes(&mut seed).expect("fixed seed is always valid");
    Keypair::from(ed25519::Keypair::from(secret))
        .public()
        .to_peer_id()
}

/// A loopback TCP multiaddr without a peer-id component.
fn addr_no_peer() -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{TEST_PORT_A}").parse().unwrap()
}

/// A second loopback TCP multiaddr (different port) without a peer-id component.
fn addr_no_peer_b() -> Multiaddr {
    format!("/ip4/127.0.0.1/tcp/{TEST_PORT_B}").parse().unwrap()
}

/// A loopback TCP multiaddr WITH an embedded /p2p/<peer_id> component.
fn addr_with_peer(peer_id: PeerId) -> Multiaddr {
    addr_no_peer().with(Protocol::P2p(peer_id))
}

/// Construct a zero-valued `KBucketDistance` for `RoutingUpdated` tests.
///
/// `KBucketDistance(pub U256)` — `U256::from(0u64)` is the zero value.
fn zero_distance() -> KBucketDistance {
    KBucketDistance(U256::from(0u64))
}

// ── handle_mdns_event — Discovered ───────────────────────────────────────────

#[test]
fn mdns_discovered_adds_peer_to_table() {
    let mut table = PeerTable::new();
    let peer = peer_a();
    let addr = addr_no_peer();

    let event = MdnsEvent::Discovered(vec![(peer, addr.clone())]);
    handle_mdns_event(&event, &mut table);

    assert!(
        table.peer_info(&peer).is_some(),
        "peer must be in table after Discovered"
    );
}

#[test]
fn mdns_discovered_adds_address_for_peer() {
    let mut table = PeerTable::new();
    let peer = peer_a();
    let addr = addr_no_peer();

    let event = MdnsEvent::Discovered(vec![(peer, addr.clone())]);
    handle_mdns_event(&event, &mut table);

    let info = table.peer_info(&peer).unwrap();
    assert!(
        info.addresses.contains(&addr),
        "discovered address must be in peer info"
    );
}

#[test]
fn mdns_discovered_returns_new_peer_id() {
    let mut table = PeerTable::new();
    let peer = peer_a();

    let event = MdnsEvent::Discovered(vec![(peer, addr_no_peer())]);
    let newly_added = handle_mdns_event(&event, &mut table);

    assert_eq!(
        newly_added,
        vec![peer],
        "newly discovered peer must be in returned list"
    );
}

#[test]
fn mdns_discovered_duplicate_does_not_return_peer_again() {
    let mut table = PeerTable::new();
    let peer = peer_a();
    let event = MdnsEvent::Discovered(vec![(peer, addr_no_peer())]);

    // First discovery — new peer.
    let first = handle_mdns_event(&event, &mut table);
    assert_eq!(first.len(), 1);

    // Second discovery (same peer) — already known, must not re-add.
    let second = handle_mdns_event(&event, &mut table);
    assert!(
        second.is_empty(),
        "re-discovered peer must NOT appear in newly_added"
    );
}

#[test]
fn mdns_discovered_multiple_peers_all_added() {
    let mut table = PeerTable::new();
    let event = MdnsEvent::Discovered(vec![
        (peer_a(), addr_no_peer()),
        (peer_b(), addr_no_peer_b()),
    ]);

    let newly_added = handle_mdns_event(&event, &mut table);

    assert_eq!(table.peer_count(), 2, "both peers must be in table");
    assert_eq!(newly_added.len(), 2, "both must be returned as newly added");
}

#[test]
fn mdns_discovered_returns_only_new_peers_from_mixed_batch() {
    // Peer A already known; peer B is new. Discovered fires for both.
    let mut table = PeerTable::new();
    let a = peer_a();
    let b = peer_b();

    // Pre-add A.
    table.add_peer(a);

    let event = MdnsEvent::Discovered(vec![(a, addr_no_peer()), (b, addr_no_peer_b())]);
    let newly_added = handle_mdns_event(&event, &mut table);

    assert_eq!(
        newly_added,
        vec![b],
        "only B must be reported as newly added"
    );
}

#[test]
fn mdns_discovered_empty_list_returns_empty() {
    let mut table = PeerTable::new();
    let event = MdnsEvent::Discovered(vec![]);
    let newly_added = handle_mdns_event(&event, &mut table);
    assert!(newly_added.is_empty());
    assert_eq!(table.peer_count(), 0);
}

// ── handle_mdns_event — Expired ───────────────────────────────────────────────

#[test]
fn mdns_expired_does_not_remove_peer_from_table() {
    let mut table = PeerTable::new();
    let peer = peer_a();
    let addr = addr_no_peer();

    // Discover then expire.
    handle_mdns_event(
        &MdnsEvent::Discovered(vec![(peer, addr.clone())]),
        &mut table,
    );
    handle_mdns_event(&MdnsEvent::Expired(vec![(peer, addr)]), &mut table);

    assert!(
        table.peer_info(&peer).is_some(),
        "Expired must NOT remove peer from table (may still be reachable)"
    );
}

#[test]
fn mdns_expired_returns_empty_vec() {
    let mut table = PeerTable::new();
    let peer = peer_a();
    let addr = addr_no_peer();

    handle_mdns_event(
        &MdnsEvent::Discovered(vec![(peer, addr.clone())]),
        &mut table,
    );
    let result = handle_mdns_event(&MdnsEvent::Expired(vec![(peer, addr)]), &mut table);

    assert!(
        result.is_empty(),
        "Expired must return empty newly_added list"
    );
}

#[test]
fn mdns_expired_empty_list_is_noop() {
    let mut table = PeerTable::new();
    let result = handle_mdns_event(&MdnsEvent::Expired(vec![]), &mut table);
    assert!(result.is_empty());
    assert_eq!(table.peer_count(), 0);
}

// ── handle_kademlia_event — RoutablePeer ─────────────────────────────────────

#[test]
fn kad_routable_peer_adds_peer_and_address() {
    let mut table = PeerTable::new();
    let peer = peer_a();
    let addr = addr_no_peer();

    let event = KadEvent::RoutablePeer {
        peer,
        address: addr.clone(),
    };
    handle_kademlia_event(&event, &mut table);

    assert!(
        table.peer_info(&peer).is_some(),
        "RoutablePeer must add peer to table"
    );
    assert!(
        table.peer_info(&peer).unwrap().addresses.contains(&addr),
        "RoutablePeer must add address to peer info"
    );
}

// ── handle_kademlia_event — PendingRoutablePeer ───────────────────────────────

#[test]
fn kad_pending_routable_peer_adds_peer_and_address() {
    let mut table = PeerTable::new();
    let peer = peer_a();
    let addr = addr_no_peer();

    let event = KadEvent::PendingRoutablePeer {
        peer,
        address: addr.clone(),
    };
    handle_kademlia_event(&event, &mut table);

    assert!(
        table.peer_info(&peer).is_some(),
        "PendingRoutablePeer must add peer"
    );
    assert!(
        table.peer_info(&peer).unwrap().addresses.contains(&addr),
        "PendingRoutablePeer must add address"
    );
}

// ── handle_kademlia_event — UnroutablePeer ────────────────────────────────────

#[test]
fn kad_unroutable_peer_does_not_add_to_table() {
    let mut table = PeerTable::new();
    let peer = peer_a();

    let event = KadEvent::UnroutablePeer { peer };
    handle_kademlia_event(&event, &mut table);

    // No address known → do not add to table (can't dial without address).
    assert!(
        table.peer_info(&peer).is_none(),
        "UnroutablePeer must NOT add peer to table (no address to dial)"
    );
}

// ── handle_kademlia_event — RoutingUpdated ────────────────────────────────────

#[test]
fn kad_routing_updated_adds_peer_and_all_addresses() {
    let mut table = PeerTable::new();
    let peer = peer_a();
    let addr = addr_no_peer();

    let event = KadEvent::RoutingUpdated {
        peer,
        is_new_peer: true,
        addresses: Addresses::new(addr.clone()),
        bucket_range: (zero_distance(), zero_distance()),
        old_peer: None,
    };
    handle_kademlia_event(&event, &mut table);

    assert!(
        table.peer_info(&peer).is_some(),
        "RoutingUpdated must add peer"
    );
    assert!(
        table.peer_info(&peer).unwrap().addresses.contains(&addr),
        "RoutingUpdated must add the address"
    );
}

#[test]
fn kad_routing_updated_existing_peer_adds_address() {
    let mut table = PeerTable::new();
    let peer = peer_a();
    let addr_first = addr_no_peer();
    let addr_second = addr_no_peer_b();

    // Add peer initially.
    table.add_peer(peer);
    table.add_address(&peer, addr_first.clone());

    // RoutingUpdated brings a fresh address.
    let event = KadEvent::RoutingUpdated {
        peer,
        is_new_peer: false,
        addresses: Addresses::new(addr_second.clone()),
        bucket_range: (zero_distance(), zero_distance()),
        old_peer: None,
    };
    handle_kademlia_event(&event, &mut table);

    let info = table.peer_info(&peer).unwrap();
    assert!(
        info.addresses.contains(&addr_first),
        "original address must be retained"
    );
    assert!(
        info.addresses.contains(&addr_second),
        "new address from RoutingUpdated must be added"
    );
}

#[test]
fn kad_routing_updated_adds_all_addresses_from_single_event() {
    // Covers the multi-address iteration path: `for addr in addresses.iter()`.
    let mut table = PeerTable::new();
    let peer = peer_a();
    let addr1 = addr_no_peer();
    let addr2 = addr_no_peer_b();

    let mut addresses = Addresses::new(addr1.clone());
    addresses.insert(addr2.clone()); // Addresses::insert adds if not already present

    let event = KadEvent::RoutingUpdated {
        peer,
        is_new_peer: true,
        addresses,
        bucket_range: (zero_distance(), zero_distance()),
        old_peer: None,
    };
    handle_kademlia_event(&event, &mut table);

    let info = table.peer_info(&peer).unwrap();
    assert!(
        info.addresses.contains(&addr1),
        "first address from RoutingUpdated must be added"
    );
    assert!(
        info.addresses.contains(&addr2),
        "second address from RoutingUpdated must be added"
    );
    assert_eq!(info.addresses.len(), 2, "both addresses must be present");
}

// ── handle_kademlia_event — other events are ignored ─────────────────────────

#[test]
fn kad_inbound_request_is_ignored() {
    use libp2p::kad::InboundRequest;

    let mut table = PeerTable::new();

    // Construct an InboundRequest event (GetProvider is the simplest variant).
    let event = KadEvent::InboundRequest {
        request: InboundRequest::FindNode {
            num_closer_peers: 0,
        },
    };

    // Must not panic or modify the table.
    handle_kademlia_event(&event, &mut table);
    assert_eq!(table.peer_count(), 0);
}

// ── parse_bootstrap_peers ─────────────────────────────────────────────────────

#[test]
fn parse_bootstrap_peers_extracts_peer_id_from_valid_address() {
    let peer = peer_a();
    let addr = addr_with_peer(peer);

    let result = parse_bootstrap_peers(&[addr.clone()]);

    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].0, peer,
        "extracted PeerId must match embedded /p2p/ component"
    );
    assert_eq!(result[0].1, addr, "Multiaddr must be returned unchanged");
}

#[test]
fn parse_bootstrap_peers_skips_address_without_peer_id() {
    let addr = addr_no_peer(); // no /p2p/ component

    let result = parse_bootstrap_peers(&[addr]);

    assert!(result.is_empty(), "address without /p2p/ must be skipped");
}

#[test]
fn parse_bootstrap_peers_returns_only_valid_from_mixed_list() {
    let valid_peer = peer_a();
    let valid_addr = addr_with_peer(valid_peer);
    let invalid_addr = addr_no_peer();

    let result = parse_bootstrap_peers(&[valid_addr.clone(), invalid_addr]);

    assert_eq!(result.len(), 1, "only valid address must be returned");
    assert_eq!(result[0].0, valid_peer);
    assert_eq!(result[0].1, valid_addr);
}

#[test]
fn parse_bootstrap_peers_returns_all_when_all_valid() {
    let addr_a = addr_with_peer(peer_a());
    let addr_b = addr_with_peer(peer_b());

    let result = parse_bootstrap_peers(&[addr_a, addr_b]);

    assert_eq!(result.len(), 2, "both valid addresses must be returned");
}

#[test]
fn parse_bootstrap_peers_returns_empty_for_empty_input() {
    let result = parse_bootstrap_peers(&[]);
    assert!(result.is_empty());
}

#[test]
fn parse_bootstrap_peers_returns_empty_when_all_invalid() {
    let addrs = vec![addr_no_peer(), addr_no_peer()];
    let result = parse_bootstrap_peers(&addrs);
    assert!(result.is_empty());
}

// ── peer_id_from_multiaddr (internal, tested via parse_bootstrap_peers) ───────

#[test]
fn bootstrap_addr_with_p2p_component_is_accepted() {
    // Verify the /p2p/<peer-id> extraction round-trips correctly through
    // Multiaddr encoding. This guards against any multiaddr encoding changes.
    let original = peer_a();
    let addr = addr_with_peer(original);
    let result = parse_bootstrap_peers(&[addr]);

    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].0, original,
        "PeerId must survive Multiaddr encoding roundtrip"
    );
}
