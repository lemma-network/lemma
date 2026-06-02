//! Peer discovery event handlers for the Lemma P2P stack.
//!
//! ## Responsibility
//!
//! This module translates raw libp2p discovery events into [`PeerTable`] updates.
//! It is **pure data-flow** — no `Swarm`, no networking I/O, no async code.
//! The service layer (Step 8) drives the swarm event loop and calls these
//! handlers as events arrive.
//!
//! ## Discovery sources (12-NETWORK_SYNC_SPEC §1, staging)
//!
//! | Source | Scope | Handler |
//! |--------|-------|---------|
//! | **mDNS** | LAN — finds peers on the same local network without seeds | [`handle_mdns_event`] |
//! | **Kademlia DHT** | Public — global peer routing via `/lemma/kad/1` | [`handle_kademlia_event`] |
//! | **Bootstrap peers** | Startup seeds from `NetworkConfig::bootstrap_peers` | [`parse_bootstrap_peers`] |
//!
//! All three sources update the same peer table. mDNS and Kademlia routing events
//! call [`PeerTable::add_peer`] + [`PeerTable::add_address`] when an address is
//! known. [`kad::Event::UnroutablePeer`] is the sole exception — no address means
//! no dial target, so neither call is made (see [`handle_kademlia_event`]).
//!
//! ## mDNS expiry policy
//!
//! When mDNS emits `Event::Expired`, the peer is **not removed** from the table.
//! mDNS expiry means "not seen in the local multicast window" — the peer may
//! still be reachable via Kademlia or a direct TCP connection. Score history
//! and addresses are preserved for reconnection.
//!
//! ## Bootstrap address format
//!
//! Bootstrap peers **must** include the `/p2p/<peer-id>` multiaddr component.
//! Addresses without it are silently skipped with a `tracing::warn!` — the
//! rest of the list is processed. See [`parse_bootstrap_peers`].

use libp2p::{kad, mdns, multiaddr::Protocol, Multiaddr, PeerId};

use crate::peer::PeerTable;

// ── mDNS discovery ────────────────────────────────────────────────────────────

/// Handle an mDNS discovery event, updating the peer table.
///
/// ## `Discovered`
///
/// For each `(peer_id, addr)` pair: calls [`PeerTable::add_peer`] (idempotent)
/// and [`PeerTable::add_address`] (deduplicating). Returns the `PeerId`s of
/// **newly added** peers (those not previously in the table) so the service
/// layer can initiate dials.
///
/// ## `Expired`
///
/// Does **not** remove the peer. mDNS expiry ≠ unreachable. See module-level
/// expiry policy.
pub fn handle_mdns_event(event: &mdns::Event, table: &mut PeerTable) -> Vec<PeerId> {
    match event {
        mdns::Event::Discovered(peers) => {
            let mut newly_added = Vec::new();
            for (peer_id, addr) in peers {
                let is_new = table.peer_info(peer_id).is_none();
                table.add_peer(*peer_id);
                table.add_address(peer_id, addr.clone());
                if is_new {
                    newly_added.push(*peer_id);
                }
            }
            newly_added
        }

        mdns::Event::Expired(peers) => {
            // Log expiry but do NOT evict — peer may be reachable via other paths.
            for (peer_id, _addr) in peers {
                tracing::debug!(
                    peer = %peer_id,
                    "mDNS announcement expired — peer kept in table \
                     (may still be reachable via Kademlia or direct connection)"
                );
            }
            Vec::new()
        }
    }
}

// ── Kademlia discovery ────────────────────────────────────────────────────────

/// Handle a Kademlia routing-table event, updating the peer table.
///
/// | Event | Action |
/// |-------|--------|
/// | `RoutingUpdated` | Add peer + all known addresses from `addresses` |
/// | `RoutablePeer` | Add peer + the reported address |
/// | `PendingRoutablePeer` | Add peer + the reported address (optimistic) |
/// | `UnroutablePeer` | No-op — no address to add |
/// | Other | Ignored — query progress, inbound requests are service concerns |
pub fn handle_kademlia_event(event: &kad::Event, table: &mut PeerTable) {
    match event {
        kad::Event::RoutingUpdated {
            peer, addresses, ..
        } => {
            // A peer's routing entry was created or refreshed.
            // `addresses` holds all currently-known addresses for this peer.
            table.add_peer(*peer);
            for addr in addresses.iter() {
                table.add_address(peer, addr.clone());
            }
        }

        kad::Event::RoutablePeer { peer, address } => {
            // Connected peer has a listen address and is in the routing table.
            table.add_peer(*peer);
            table.add_address(peer, address.clone());
        }

        kad::Event::PendingRoutablePeer { peer, address } => {
            // Connected peer is pending routing-table insertion.
            // Add optimistically — if insertion succeeds, a `RoutingUpdated`
            // event will follow confirming the peer.
            table.add_peer(*peer);
            table.add_address(peer, address.clone());
        }

        kad::Event::UnroutablePeer { peer } => {
            // No listen address known — cannot add to table (no dial target).
            // This is the only Kademlia variant that does NOT call add_peer;
            // a RoutingUpdated or RoutablePeer event will follow if the peer
            // later advertises a listen address.
            tracing::debug!(
                peer = %peer,
                "Kademlia: unroutable peer (no listen address known yet)"
            );
        }

        // Ignore query progress, inbound requests, and other non-discovery events.
        _ => {}
    }
}

// ── Bootstrap peer parsing ────────────────────────────────────────────────────

/// Extract `(PeerId, Multiaddr)` pairs from bootstrap seed addresses.
///
/// Iterates the `bootstrap_peers` from [`NetworkConfig`] and extracts the
/// embedded `PeerId` from each `/p2p/<peer-id>` multiaddr component.
///
/// **Addresses without `/p2p/` are silently skipped** with `tracing::warn!` —
/// Kademlia cannot authenticate a peer without its ID. The rest of the list is
/// always processed so a single misconfigured seed does not block startup.
///
/// The returned pairs are passed to the service layer, which calls
/// `swarm.dial()` + `kademlia.add_address()` for each during startup.
///
/// See `config.rs::NetworkConfig::bootstrap_peers` doc for the required format:
/// `/ip4/<addr>/tcp/<port>/p2p/<peer-id>`.
///
/// [`NetworkConfig`]: crate::config::NetworkConfig
pub fn parse_bootstrap_peers(addrs: &[Multiaddr]) -> Vec<(PeerId, Multiaddr)> {
    addrs
        .iter()
        .filter_map(|addr| match peer_id_from_multiaddr(addr) {
            Some(peer_id) => Some((peer_id, addr.clone())),
            None => {
                tracing::warn!(
                    addr = %addr,
                    "bootstrap peer address is missing /p2p/<peer-id> component — \
                     skipping (Kademlia cannot authenticate without a peer ID). \
                     Required format: /ip4/<addr>/tcp/<port>/p2p/<peer-id>"
                );
                None
            }
        })
        .collect()
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Extract the `PeerId` from a `/p2p/<peer-id>` multiaddr component.
///
/// Returns `None` if the address contains no `/p2p/` protocol. Does not
/// modify or strip the address — the original `Multiaddr` is returned
/// alongside the `PeerId` by callers (e.g. [`parse_bootstrap_peers`]).
fn peer_id_from_multiaddr(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|proto| match proto {
        Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

#[cfg(test)]
mod tests;
