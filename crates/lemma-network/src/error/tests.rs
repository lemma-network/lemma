use lemma_core::Hash;
use libp2p::PeerId;

use super::*;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Returns a deterministic test `PeerId` derived from a fixed zero seed.
///
/// Uses an all-zero ed25519 secret key so every call in the test suite
/// produces the same `PeerId` — consistent with the determinism principle
/// for test fixtures (AGENTS.md §7.1).
fn test_peer() -> PeerId {
    use libp2p::identity::{ed25519, Keypair};
    let mut seed = [0u8; 32];
    let secret =
        ed25519::SecretKey::try_from_bytes(&mut seed).expect("fixed 32-byte seed is always valid");
    let kp = Keypair::from(ed25519::Keypair::from(secret));
    kp.public().to_peer_id()
}

/// Returns a zero `Hash` for use in error construction tests.
fn test_hash() -> Hash {
    Hash::zero()
}

// ── Display format tests ──────────────────────────────────────────────────────
// Regression-pin the human-readable messages so changes to error strings
// are caught explicitly, not silently.

#[test]
fn invalid_block_display_contains_height() {
    let err = NetworkError::InvalidBlock {
        peer: test_peer(),
        height: 42,
    };
    let msg = err.to_string();
    assert!(msg.contains("42"), "expected height in message, got: {msg}");
}

#[test]
fn invalid_block_display_contains_peer() {
    let peer = test_peer();
    let peer_str = peer.to_string();
    let err = NetworkError::InvalidBlock { peer, height: 0 };
    let msg = err.to_string();
    assert!(
        msg.contains(&peer_str),
        "expected peer id in message, got: {msg}"
    );
}

#[test]
fn invalid_quorum_cert_display_contains_height() {
    let err = NetworkError::InvalidQuorumCert { height: 100 };
    let msg = err.to_string();
    assert!(
        msg.contains("100"),
        "expected height in message, got: {msg}"
    );
}

#[test]
fn invalid_state_chunk_display_contains_root_hex() {
    let root = test_hash();
    let root_hex = root.to_string(); // 64-char lowercase hex
    let err = NetworkError::InvalidStateChunk { root };
    let msg = err.to_string();
    assert!(
        msg.contains(&root_hex),
        "expected root hex in message, got: {msg}"
    );
}

#[test]
fn response_too_large_display_contains_got_and_max() {
    let err = NetworkError::ResponseTooLarge {
        got: 2048,
        max: 1024,
    };
    let msg = err.to_string();
    assert!(msg.contains("2048"), "expected got in message, got: {msg}");
    assert!(msg.contains("1024"), "expected max in message, got: {msg}");
}

#[test]
fn range_too_wide_display_contains_got_and_max() {
    let err = NetworkError::RangeTooWide {
        got: 1000,
        max: 500,
    };
    let msg = err.to_string();
    assert!(msg.contains("1000"), "expected got in message, got: {msg}");
    assert!(msg.contains("500"), "expected max in message, got: {msg}");
}

#[test]
fn expired_display_contains_height() {
    let err = NetworkError::Expired { height: 999 };
    let msg = err.to_string();
    assert!(
        msg.contains("999"),
        "expected height in message, got: {msg}"
    );
}

#[test]
fn equivocation_display_contains_height() {
    let err = NetworkError::Equivocation { height: 77 };
    let msg = err.to_string();
    assert!(msg.contains("77"), "expected height in message, got: {msg}");
}

#[test]
fn timeout_display_contains_peer() {
    let peer = test_peer();
    let peer_str = peer.to_string();
    let err = NetworkError::Timeout { peer };
    let msg = err.to_string();
    assert!(
        msg.contains(&peer_str),
        "expected peer id in message, got: {msg}"
    );
}

#[test]
fn transport_display_contains_inner_message() {
    let err = NetworkError::transport(std::io::Error::other("connection refused"));
    let msg = err.to_string();
    assert!(
        msg.contains("connection refused"),
        "expected inner message, got: {msg}"
    );
}

#[test]
fn subscribe_display_contains_topic() {
    let err = NetworkError::Subscribe {
        topic: "lemma/blocks/1".to_string(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("lemma/blocks/1"),
        "expected topic in message, got: {msg}"
    );
}

#[test]
fn publish_display_contains_topic_and_reason() {
    let err = NetworkError::Publish {
        topic: "lemma/tx/1".to_string(),
        reason: "no peers in mesh".to_string(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains("lemma/tx/1"),
        "expected topic in message, got: {msg}"
    );
    assert!(
        msg.contains("no peers in mesh"),
        "expected reason in message, got: {msg}"
    );
}

#[test]
fn invalid_message_display_contains_peer_and_reason() {
    let peer = test_peer();
    let peer_str = peer.to_string();
    let err = NetworkError::InvalidMessage {
        peer,
        reason: "unexpected eof".to_string(),
    };
    let msg = err.to_string();
    assert!(
        msg.contains(&peer_str),
        "expected peer id in message, got: {msg}"
    );
    assert!(
        msg.contains("unexpected eof"),
        "expected reason in message, got: {msg}"
    );
}

// ── Debug trait ───────────────────────────────────────────────────────────────

#[test]
fn all_variants_debug_output_contains_variant_name() {
    // Verifies Debug output is identifiable per-variant — useful for log readability.
    let peer = test_peer();
    let cases: &[(&str, &dyn std::fmt::Debug)] = &[
        (
            "InvalidBlock",
            &NetworkError::InvalidBlock { peer, height: 0 },
        ),
        (
            "InvalidQuorumCert",
            &NetworkError::InvalidQuorumCert { height: 0 },
        ),
        (
            "InvalidStateChunk",
            &NetworkError::InvalidStateChunk { root: test_hash() },
        ),
        (
            "ResponseTooLarge",
            &NetworkError::ResponseTooLarge { got: 1, max: 0 },
        ),
        (
            "RangeTooWide",
            &NetworkError::RangeTooWide { got: 1, max: 0 },
        ),
        ("Expired", &NetworkError::Expired { height: 0 }),
        ("Equivocation", &NetworkError::Equivocation { height: 0 }),
        ("Timeout", &NetworkError::Timeout { peer: test_peer() }),
        (
            "Transport",
            &NetworkError::transport(std::io::Error::other("t")),
        ),
        (
            "Subscribe",
            &NetworkError::Subscribe {
                topic: "t".to_string(),
            },
        ),
        (
            "Publish",
            &NetworkError::Publish {
                topic: "t".to_string(),
                reason: "r".to_string(),
            },
        ),
        (
            "InvalidMessage",
            &NetworkError::InvalidMessage {
                peer: test_peer(),
                reason: "r".to_string(),
            },
        ),
    ];
    for (name, err) in cases {
        let debug_str = format!("{err:?}");
        assert!(
            debug_str.contains(name),
            "Debug output for {name} should contain variant name, got: {debug_str}"
        );
    }
}

// ── is_attack_signal ──────────────────────────────────────────────────────────

#[test]
fn equivocation_is_attack_signal() {
    let err = NetworkError::Equivocation { height: 1 };
    assert!(
        err.is_attack_signal(),
        "Equivocation must be classified as attack signal"
    );
}

#[test]
fn non_equivocation_errors_are_not_attack_signals() {
    let peer = test_peer();
    let non_attack: &[&dyn Fn() -> NetworkError] = &[
        &|| NetworkError::InvalidBlock { peer, height: 0 },
        &|| NetworkError::InvalidQuorumCert { height: 0 },
        &|| NetworkError::InvalidStateChunk { root: test_hash() },
        &|| NetworkError::ResponseTooLarge { got: 1, max: 0 },
        &|| NetworkError::RangeTooWide { got: 1, max: 0 },
        &|| NetworkError::Expired { height: 0 },
        &|| NetworkError::Timeout { peer: test_peer() },
        &|| NetworkError::transport(std::io::Error::other("t")),
        &|| NetworkError::Subscribe {
            topic: "t".to_string(),
        },
        &|| NetworkError::Publish {
            topic: "t".to_string(),
            reason: "r".to_string(),
        },
        &|| NetworkError::InvalidMessage {
            peer: test_peer(),
            reason: "r".to_string(),
        },
    ];
    for make_err in non_attack {
        let err = make_err();
        assert!(
            !err.is_attack_signal(),
            "{:?} should NOT be an attack signal",
            err
        );
    }
}

// ── is_peer_misbehaviour ──────────────────────────────────────────────────────

#[test]
fn invalid_block_is_peer_misbehaviour() {
    let err = NetworkError::InvalidBlock {
        peer: test_peer(),
        height: 0,
    };
    assert!(err.is_peer_misbehaviour());
}

#[test]
fn invalid_quorum_cert_is_peer_misbehaviour() {
    let err = NetworkError::InvalidQuorumCert { height: 0 };
    assert!(err.is_peer_misbehaviour());
}

#[test]
fn invalid_state_chunk_is_peer_misbehaviour() {
    let err = NetworkError::InvalidStateChunk { root: test_hash() };
    assert!(err.is_peer_misbehaviour());
}

#[test]
fn equivocation_is_peer_misbehaviour() {
    let err = NetworkError::Equivocation { height: 0 };
    assert!(err.is_peer_misbehaviour());
}

#[test]
fn invalid_message_is_peer_misbehaviour() {
    let err = NetworkError::InvalidMessage {
        peer: test_peer(),
        reason: "r".to_string(),
    };
    assert!(err.is_peer_misbehaviour());
}

#[test]
fn timeout_is_not_peer_misbehaviour() {
    // Timeout is a network condition, not deliberate misbehaviour.
    let err = NetworkError::Timeout { peer: test_peer() };
    assert!(!err.is_peer_misbehaviour());
}

#[test]
fn transport_is_not_peer_misbehaviour() {
    let err = NetworkError::transport(std::io::Error::other("t"));
    assert!(!err.is_peer_misbehaviour());
}

#[test]
fn subscribe_is_not_peer_misbehaviour() {
    // Subscribe failure is a local configuration error, not peer misbehaviour.
    let err = NetworkError::Subscribe {
        topic: "t".to_string(),
    };
    assert!(!err.is_peer_misbehaviour());
}

#[test]
fn publish_is_not_peer_misbehaviour() {
    // Publish failure may indicate no mesh peers — not deliberate misbehaviour.
    let err = NetworkError::Publish {
        topic: "t".to_string(),
        reason: "r".to_string(),
    };
    assert!(!err.is_peer_misbehaviour());
}

#[test]
fn expired_is_not_peer_misbehaviour() {
    // Expired may reflect local clock skew; conservatively not misbehaviour.
    let err = NetworkError::Expired { height: 0 };
    assert!(!err.is_peer_misbehaviour());
}

// ── is_bounds_violation ───────────────────────────────────────────────────────

#[test]
fn response_too_large_is_bounds_violation() {
    let err = NetworkError::ResponseTooLarge { got: 2, max: 1 };
    assert!(err.is_bounds_violation());
}

#[test]
fn range_too_wide_is_bounds_violation() {
    let err = NetworkError::RangeTooWide { got: 2, max: 1 };
    assert!(err.is_bounds_violation());
}

#[test]
fn invalid_block_is_not_bounds_violation() {
    let err = NetworkError::InvalidBlock {
        peer: test_peer(),
        height: 0,
    };
    assert!(!err.is_bounds_violation());
}

// ── Classification overlap contract ──────────────────────────────────────────
// is_attack_signal ⊂ is_peer_misbehaviour (attack signals are also misbehaviour).
// is_bounds_violation ∩ is_peer_misbehaviour = ∅ by current design.

#[test]
fn attack_signal_is_also_peer_misbehaviour() {
    let err = NetworkError::Equivocation { height: 0 };
    assert!(err.is_attack_signal());
    assert!(err.is_peer_misbehaviour());
    assert!(!err.is_bounds_violation());
}

#[test]
fn bounds_violation_is_not_peer_misbehaviour() {
    // Oversized responses may be accidental; not automatically misbehaviour.
    let err = NetworkError::ResponseTooLarge { got: 2, max: 1 };
    assert!(!err.is_peer_misbehaviour());
    assert!(!err.is_attack_signal());
    assert!(err.is_bounds_violation());
}

// ── transport constructor ─────────────────────────────────────────────────────

#[test]
fn transport_constructor_wraps_any_error() {
    let io_err = std::io::Error::other("broken pipe");
    let net_err = NetworkError::transport(io_err);
    assert!(net_err.to_string().contains("broken pipe"));
}

#[test]
fn transport_constructor_preserves_source_chain() {
    use std::error::Error;
    let io_err = std::io::Error::other("root cause");
    let net_err = NetworkError::transport(io_err);
    // Source chain must be preserved for structured logging / anyhow contexts.
    assert!(
        net_err.source().is_some(),
        "Transport must preserve error source chain"
    );
}

// ── Error propagation with ? operator ────────────────────────────────────────

#[test]
fn range_too_wide_propagates_via_question_mark() {
    fn validate_range(got: u64, max: u64) -> Result<(), NetworkError> {
        if got > max {
            return Err(NetworkError::RangeTooWide { got, max });
        }
        Ok(())
    }

    assert!(validate_range(100, 500).is_ok());
    assert!(validate_range(1000, 500).is_err());

    let err = validate_range(1000, 500).unwrap_err();
    assert!(matches!(
        err,
        NetworkError::RangeTooWide {
            got: 1000,
            max: 500
        }
    ));
}

#[test]
fn network_error_usable_as_boxed_std_error() {
    // Verifies usability in anyhow / Box<dyn std::error::Error> contexts.
    let err: Box<dyn std::error::Error> = Box::new(NetworkError::Equivocation { height: 7 });
    assert!(!err.to_string().is_empty());
    assert!(err.to_string().contains("7"));
}
