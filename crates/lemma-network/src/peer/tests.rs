use libp2p::{Multiaddr, PeerId};

use super::*;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Deterministic test peer derived from a fixed seed (zero bytes).
/// See the same pattern in error/tests.rs — consistent across the crate.
fn test_peer() -> PeerId {
    use libp2p::identity::{ed25519, Keypair};
    let mut seed = [0u8; 32];
    let secret =
        ed25519::SecretKey::try_from_bytes(&mut seed).expect("fixed seed is always valid");
    let kp = Keypair::from(ed25519::Keypair::from(secret));
    kp.public().to_peer_id()
}

/// A second deterministic test peer (seed = [1u8; 32]).
fn test_peer_b() -> PeerId {
    use libp2p::identity::{ed25519, Keypair};
    let mut seed = [1u8; 32];
    let secret =
        ed25519::SecretKey::try_from_bytes(&mut seed).expect("fixed seed is always valid");
    let kp = Keypair::from(ed25519::Keypair::from(secret));
    kp.public().to_peer_id()
}

/// A test multiaddr — loopback TCP on port 9000.
fn test_addr() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/9000".parse().expect("valid test addr")
}

/// A second test multiaddr — loopback TCP on port 9001.
fn test_addr_b() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/9001".parse().expect("valid test addr")
}

// ── PeerEvent — delta values ──────────────────────────────────────────────────

#[test]
fn peer_event_invalid_block_has_negative_delta() {
    assert!(PeerEvent::InvalidBlock.delta() < 0.0);
    assert_eq!(PeerEvent::InvalidBlock.delta(), DELTA_INVALID_BLOCK);
}

#[test]
fn peer_event_invalid_state_chunk_has_negative_delta() {
    assert!(PeerEvent::InvalidStateChunk.delta() < 0.0);
    assert_eq!(PeerEvent::InvalidStateChunk.delta(), DELTA_INVALID_STATE_CHUNK);
}

#[test]
fn peer_event_invalid_quorum_cert_has_most_negative_delta() {
    // QC failure is the most severe — its delta must be more negative than all others.
    let qc_delta = PeerEvent::InvalidQuorumCert.delta();
    assert!(qc_delta < PeerEvent::InvalidBlock.delta());
    assert!(qc_delta < PeerEvent::InvalidStateChunk.delta());
    assert!(qc_delta < PeerEvent::InvalidMessage.delta());
    assert!(qc_delta < PeerEvent::Timeout.delta());
    assert_eq!(qc_delta, DELTA_INVALID_QUORUM_CERT);
}

#[test]
fn peer_event_invalid_message_has_negative_delta() {
    assert!(PeerEvent::InvalidMessage.delta() < 0.0);
    assert_eq!(PeerEvent::InvalidMessage.delta(), DELTA_INVALID_MESSAGE);
}

#[test]
fn peer_event_valid_block_has_positive_delta() {
    assert!(PeerEvent::ValidBlock.delta() > 0.0);
    assert_eq!(PeerEvent::ValidBlock.delta(), DELTA_VALID_BLOCK);
}

#[test]
fn peer_event_timeout_has_negative_delta() {
    assert!(PeerEvent::Timeout.delta() < 0.0);
    assert_eq!(PeerEvent::Timeout.delta(), DELTA_TIMEOUT);
}

// ── PeerEvent — is_misbehaviour ───────────────────────────────────────────────

#[test]
fn peer_event_invalid_block_is_misbehaviour() {
    assert!(PeerEvent::InvalidBlock.is_misbehaviour());
}

#[test]
fn peer_event_invalid_state_chunk_is_misbehaviour() {
    assert!(PeerEvent::InvalidStateChunk.is_misbehaviour());
}

#[test]
fn peer_event_invalid_quorum_cert_is_misbehaviour() {
    assert!(PeerEvent::InvalidQuorumCert.is_misbehaviour());
}

#[test]
fn peer_event_invalid_message_is_misbehaviour() {
    assert!(PeerEvent::InvalidMessage.is_misbehaviour());
}

#[test]
fn peer_event_valid_block_is_not_misbehaviour() {
    assert!(!PeerEvent::ValidBlock.is_misbehaviour());
}

#[test]
fn peer_event_timeout_is_not_misbehaviour() {
    // Timeout may be a transient network condition, not deliberate.
    assert!(!PeerEvent::Timeout.is_misbehaviour());
}

// ── PeerEvent — is_penalty ────────────────────────────────────────────────────

#[test]
fn misbehaviour_events_are_penalties() {
    let penalties = [
        PeerEvent::InvalidBlock,
        PeerEvent::InvalidStateChunk,
        PeerEvent::InvalidQuorumCert,
        PeerEvent::InvalidMessage,
        PeerEvent::Timeout,
    ];
    for event in penalties {
        assert!(event.is_penalty(), "{event:?} must be a penalty");
    }
}

#[test]
fn valid_block_is_not_penalty() {
    assert!(!PeerEvent::ValidBlock.is_penalty());
}

// ── PeerTable — add / remove ──────────────────────────────────────────────────

#[test]
fn add_peer_creates_entry_with_initial_score() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    assert_eq!(table.score(&peer), Some(INITIAL_APP_SCORE));
}

#[test]
fn add_peer_is_idempotent_and_preserves_score() {
    let mut table = PeerTable::new();
    let peer = test_peer();

    table.add_peer(peer);
    table.record_event(&peer, PeerEvent::InvalidBlock); // score = INITIAL + DELTA_INVALID_BLOCK
    let score_after_event = table.score(&peer).unwrap();

    // Adding the same peer again must NOT reset the score.
    table.add_peer(peer);
    assert_eq!(
        table.score(&peer),
        Some(score_after_event),
        "add_peer must not reset an existing peer's score"
    );
}

#[test]
fn remove_peer_returns_info_for_known_peer() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    let info = table.remove_peer(&peer);
    assert!(info.is_some(), "remove_peer must return Some for a known peer");
    assert_eq!(info.unwrap().peer_id, peer);
}

#[test]
fn remove_peer_returns_none_for_unknown_peer() {
    let mut table = PeerTable::new();
    let peer = test_peer();

    assert!(table.remove_peer(&peer).is_none());
}

#[test]
fn remove_peer_decrements_peer_count() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);
    assert_eq!(table.peer_count(), 1);

    table.remove_peer(&peer);
    assert_eq!(table.peer_count(), 0);
}

#[test]
fn peer_count_reflects_multiple_peers() {
    let mut table = PeerTable::new();
    table.add_peer(test_peer());
    table.add_peer(test_peer_b());
    assert_eq!(table.peer_count(), 2);
}

// ── PeerTable — record_event & scoring ───────────────────────────────────────

#[test]
fn record_event_applies_correct_delta_for_invalid_block() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.record_event(&peer, PeerEvent::InvalidBlock);
    assert_eq!(
        table.score(&peer),
        Some(INITIAL_APP_SCORE + DELTA_INVALID_BLOCK)
    );
}

#[test]
fn record_event_applies_correct_delta_for_invalid_quorum_cert() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.record_event(&peer, PeerEvent::InvalidQuorumCert);
    assert_eq!(
        table.score(&peer),
        Some(INITIAL_APP_SCORE + DELTA_INVALID_QUORUM_CERT)
    );
}

#[test]
fn record_event_applies_correct_delta_for_valid_block() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.record_event(&peer, PeerEvent::ValidBlock);
    assert_eq!(
        table.score(&peer),
        Some(INITIAL_APP_SCORE + DELTA_VALID_BLOCK)
    );
}

#[test]
fn record_multiple_events_accumulate_correctly() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.record_event(&peer, PeerEvent::InvalidBlock);   // -10
    table.record_event(&peer, PeerEvent::InvalidMessage); // -5
    table.record_event(&peer, PeerEvent::ValidBlock);     // +1

    let expected = INITIAL_APP_SCORE
        + DELTA_INVALID_BLOCK
        + DELTA_INVALID_MESSAGE
        + DELTA_VALID_BLOCK;
    assert_eq!(table.score(&peer), Some(expected));
}

#[test]
fn record_event_on_unknown_peer_is_noop() {
    // A peer must be add_peer'd before events are recorded.
    // Recording an event for an unknown peer must not panic or create a phantom entry.
    let mut table = PeerTable::new();
    let peer = test_peer();

    table.record_event(&peer, PeerEvent::InvalidBlock); // no-op

    assert_eq!(table.score(&peer), None, "unknown peer must not appear in table");
    assert_eq!(table.peer_count(), 0);
}

#[test]
fn score_clamped_at_min_app_score() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    // Apply enough QC-cert failures to push past the minimum.
    // Each InvalidQuorumCert = -20. Need > 100 / 20 = 5 events to saturate.
    for _ in 0..10 {
        table.record_event(&peer, PeerEvent::InvalidQuorumCert);
    }

    assert_eq!(
        table.score(&peer),
        Some(MIN_APP_SCORE),
        "score must clamp at MIN_APP_SCORE, not go lower"
    );
}

#[test]
fn score_clamped_at_max_app_score() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    // Apply enough valid-block events to saturate the maximum.
    // Each ValidBlock = +1. Need > 100 events.
    for _ in 0..200 {
        table.record_event(&peer, PeerEvent::ValidBlock);
    }

    assert_eq!(
        table.score(&peer),
        Some(MAX_APP_SCORE),
        "score must clamp at MAX_APP_SCORE, not go higher"
    );
}

#[test]
fn score_returns_none_for_unknown_peer() {
    let table = PeerTable::new();
    assert_eq!(table.score(&test_peer()), None);
}

// ── PeerTable — graylist ──────────────────────────────────────────────────────

#[test]
fn is_graylisted_false_for_fresh_peer() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    assert!(!table.is_graylisted(&peer));
}

#[test]
fn is_graylisted_true_after_qc_failure() {
    // A single InvalidQuorumCert (-20) hits exactly the default threshold.
    // Threshold is STRICT: score < threshold triggers graylist.
    // -20 < -20 is FALSE — one QC failure lands AT the threshold, not below.
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.record_event(&peer, PeerEvent::InvalidQuorumCert); // score = -20.0

    // score == threshold → NOT graylisted (strict less-than)
    assert!(
        !table.is_graylisted(&peer),
        "score == threshold must NOT be graylisted (strict <)"
    );

    table.record_event(&peer, PeerEvent::Timeout); // score = -21.0 → below threshold

    assert!(
        table.is_graylisted(&peer),
        "score < threshold must be graylisted"
    );
}

#[test]
fn is_graylisted_false_for_unknown_peer() {
    // Unknown peers are not graylisted — absence is not suspicious.
    let table = PeerTable::new();
    assert!(!table.is_graylisted(&test_peer()));
}

#[test]
fn custom_graylist_threshold_is_respected() {
    // A tight threshold (-5) means one InvalidMessage triggers graylist.
    let mut table = PeerTable::with_graylist_threshold(-5.0);
    let peer = test_peer();
    table.add_peer(peer);

    table.record_event(&peer, PeerEvent::Timeout); // -1, score = -1 → not yet
    assert!(!table.is_graylisted(&peer));

    table.record_event(&peer, PeerEvent::InvalidMessage); // -5, score = -6 → graylisted
    assert!(table.is_graylisted(&peer));
}

#[test]
fn graylisted_peers_iterator_yields_only_graylisted() {
    let mut table = PeerTable::new();
    let good = test_peer();
    let bad = test_peer_b();

    table.add_peer(good);
    table.add_peer(bad);

    // Push 'bad' below the threshold.
    for _ in 0..3 {
        table.record_event(&bad, PeerEvent::InvalidQuorumCert); // -60 total → graylisted
    }

    let graylisted: Vec<PeerId> =
        table.graylisted_peers().map(|p| p.peer_id).collect();

    assert_eq!(graylisted.len(), 1);
    assert_eq!(graylisted[0], bad);
}

// ── PeerTable — addresses ─────────────────────────────────────────────────────

#[test]
fn add_address_appends_new_address_for_known_peer() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.add_address(&peer, test_addr());
    let info = table.peer_info(&peer).unwrap();
    assert_eq!(info.addresses.len(), 1);
    assert_eq!(info.addresses[0], test_addr());
}

#[test]
fn add_address_deduplicates() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.add_address(&peer, test_addr());
    table.add_address(&peer, test_addr()); // duplicate — must not grow
    table.add_address(&peer, test_addr()); // duplicate — must not grow

    let info = table.peer_info(&peer).unwrap();
    assert_eq!(
        info.addresses.len(),
        1,
        "duplicate addresses must not be added"
    );
}

#[test]
fn add_address_allows_multiple_distinct_addresses() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.add_address(&peer, test_addr());
    table.add_address(&peer, test_addr_b());

    let info = table.peer_info(&peer).unwrap();
    assert_eq!(info.addresses.len(), 2);
}

#[test]
fn add_address_on_unknown_peer_is_noop() {
    let mut table = PeerTable::new();
    let peer = test_peer();

    table.add_address(&peer, test_addr()); // no-op — peer not in table
    assert_eq!(table.peer_count(), 0);
}

// ── PeerTable — connected state ───────────────────────────────────────────────

#[test]
fn mark_connected_on_unknown_peer_is_noop() {
    // Must not panic or create a phantom entry for an unknown peer.
    let mut table = PeerTable::new();
    table.mark_connected(&test_peer());
    assert_eq!(table.peer_count(), 0);
}

#[test]
fn mark_disconnected_on_unknown_peer_is_noop() {
    // Must not panic or create a phantom entry for an unknown peer.
    let mut table = PeerTable::new();
    table.mark_disconnected(&test_peer());
    assert_eq!(table.peer_count(), 0);
}

#[test]
fn new_peer_starts_disconnected() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    let info = table.peer_info(&peer).unwrap();
    assert!(!info.connected);
}

#[test]
fn mark_connected_sets_connected_true() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.mark_connected(&peer);
    assert!(table.peer_info(&peer).unwrap().connected);
}

#[test]
fn mark_disconnected_sets_connected_false() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.mark_connected(&peer);
    table.mark_disconnected(&peer);
    assert!(!table.peer_info(&peer).unwrap().connected);
}

#[test]
fn connected_peers_iterator_yields_only_connected() {
    let mut table = PeerTable::new();
    let connected = test_peer();
    let disconnected = test_peer_b();

    table.add_peer(connected);
    table.add_peer(disconnected);
    table.mark_connected(&connected);

    let connected_ids: Vec<PeerId> =
        table.connected_peers().map(|p| p.peer_id).collect();

    assert_eq!(connected_ids.len(), 1);
    assert_eq!(connected_ids[0], connected);
}

#[test]
fn connected_peers_is_empty_when_no_connections() {
    let mut table = PeerTable::new();
    table.add_peer(test_peer());
    table.add_peer(test_peer_b());

    assert_eq!(table.connected_peers().count(), 0);
}

// ── PeerTable — scores_to_apply ───────────────────────────────────────────────

#[test]
fn scores_to_apply_yields_all_peers() {
    let mut table = PeerTable::new();
    let peer_a = test_peer();
    let peer_b = test_peer_b();

    table.add_peer(peer_a);
    table.add_peer(peer_b);

    let scores: Vec<(PeerId, f64)> =
        table.scores_to_apply().map(|(&id, s)| (id, s)).collect();

    assert_eq!(scores.len(), 2, "must yield one entry per peer");
}

#[test]
fn scores_to_apply_reflects_current_score() {
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);
    table.record_event(&peer, PeerEvent::InvalidBlock);

    let expected_score = INITIAL_APP_SCORE + DELTA_INVALID_BLOCK;
    let scores: Vec<(PeerId, f64)> =
        table.scores_to_apply().map(|(&id, s)| (id, s)).collect();

    assert_eq!(scores.len(), 1);
    assert_eq!(scores[0].1, expected_score);
}

#[test]
fn scores_to_apply_empty_for_empty_table() {
    let table = PeerTable::new();
    assert_eq!(table.scores_to_apply().count(), 0);
}

// ── PeerTable — last_seen monotonicity ───────────────────────────────────────

#[test]
fn record_event_does_not_rewind_last_seen() {
    // last_seen must be monotonically non-decreasing across consecutive events.
    let mut table = PeerTable::new();
    let peer = test_peer();
    table.add_peer(peer);

    table.record_event(&peer, PeerEvent::ValidBlock);
    let last_seen_1 = table.peer_info(&peer).unwrap().last_seen;

    table.record_event(&peer, PeerEvent::ValidBlock);
    let last_seen_2 = table.peer_info(&peer).unwrap().last_seen;

    assert!(
        last_seen_2 >= last_seen_1,
        "last_seen must be non-decreasing after consecutive events"
    );
}

// ── Score invariants ──────────────────────────────────────────────────────────

#[test]
fn initial_score_is_between_min_and_max() {
    // black_box prevents the compiler from folding these into `assert!(true)` and
    // optimizing the check away. The assertions run at runtime so CI catches any
    // constant change that violates the invariant.
    // Note: f64 comparisons cannot be used in `const { assert!() }` blocks because
    // `PartialOrd` is not a const trait — black_box is the correct tool here.
    assert!(std::hint::black_box(INITIAL_APP_SCORE) >= MIN_APP_SCORE);
    assert!(std::hint::black_box(INITIAL_APP_SCORE) <= MAX_APP_SCORE);
}

#[test]
fn graylist_threshold_is_between_min_and_max() {
    // Threshold must be reachable (> MIN) and not trigger at start (< INITIAL).
    // See black_box note in `initial_score_is_between_min_and_max`.
    assert!(std::hint::black_box(DEFAULT_GRAYLIST_THRESHOLD) > MIN_APP_SCORE);
    assert!(std::hint::black_box(DEFAULT_GRAYLIST_THRESHOLD) < INITIAL_APP_SCORE);
}

#[test]
fn invalid_quorum_cert_delta_reaches_graylist_in_one_or_two_events() {
    // Verify the design intent: a single QC failure gets a peer to the graylist
    // boundary; a second small penalty crosses it. This is an integration check
    // of the constant values.
    let score_after_one_qc = INITIAL_APP_SCORE + DELTA_INVALID_QUORUM_CERT;
    assert!(
        score_after_one_qc <= DEFAULT_GRAYLIST_THRESHOLD,
        "one QC failure must reach or cross the graylist threshold"
    );
}
