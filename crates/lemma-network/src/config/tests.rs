use std::time::Duration;

use super::*;

// ── Default field values ──────────────────────────────────────────────────────

#[test]
fn default_max_range_matches_constant() {
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.max_range, DEFAULT_MAX_RANGE);
}

#[test]
fn default_max_response_bytes_matches_constant() {
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
}

#[test]
fn default_max_inbound_substreams_matches_constant() {
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.max_inbound_substreams, DEFAULT_MAX_INBOUND_SUBSTREAMS);
}

#[test]
fn default_request_timeout_matches_constant() {
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.request_timeout, DEFAULT_REQUEST_TIMEOUT);
}

#[test]
fn default_idle_timeout_matches_constant() {
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.idle_timeout, DEFAULT_IDLE_TIMEOUT);
}

#[test]
fn default_gossip_heartbeat_matches_constant() {
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.gossip_heartbeat, DEFAULT_GOSSIP_HEARTBEAT);
}

#[test]
fn default_snapshot_interval_is_zero() {
    // Default nodes do not produce snapshots — they must opt in explicitly.
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.snapshot_interval, DEFAULT_SNAPSHOT_INTERVAL);
    assert_eq!(cfg.snapshot_interval, 0);
}

#[test]
fn default_bootstrap_peers_is_empty() {
    // Devnet: mDNS handles local discovery; no bootstrap seeds required.
    let cfg = NetworkConfig::default();
    assert!(cfg.bootstrap_peers.is_empty());
}

#[test]
fn default_listen_addrs_contains_wildcard_tcp() {
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.listen_addrs.len(), 1);
    assert_eq!(
        cfg.listen_addrs[0],
        "/ip4/0.0.0.0/tcp/0".parse::<Multiaddr>().unwrap()
    );
}

// ── validate() — acceptance ───────────────────────────────────────────────────

#[test]
fn validate_accepts_default_config() {
    assert!(
        NetworkConfig::default().validate().is_ok(),
        "default config must be valid"
    );
}

#[test]
fn validate_accepts_testnet_config() {
    assert!(
        NetworkConfig::testnet().validate().is_ok(),
        "testnet config must be valid"
    );
}

#[test]
fn validate_accepts_custom_valid_config() {
    let cfg = NetworkConfig {
        max_range: 64,
        max_response_bytes: 1024 * 1024,
        snapshot_interval: 500,
        ..NetworkConfig::default()
    };
    assert!(cfg.validate().is_ok());
}

// ── validate() — typed rejection (one test per guard) ────────────────────────
// Each guard is tested independently so a single failure maps to exactly one
// field. Tests match on the typed ConfigError variant, not a display string.

#[test]
fn validate_rejects_zero_max_range() {
    let cfg = NetworkConfig {
        max_range: 0,
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.validate(), Err(ConfigError::ZeroMaxRange));
}

#[test]
fn validate_rejects_zero_max_response_bytes() {
    let cfg = NetworkConfig {
        max_response_bytes: 0,
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.validate(), Err(ConfigError::ZeroMaxResponseBytes));
}

#[test]
fn validate_rejects_zero_max_inbound_substreams() {
    let cfg = NetworkConfig {
        max_inbound_substreams: 0,
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.validate(), Err(ConfigError::ZeroMaxInboundSubstreams));
}

#[test]
fn validate_rejects_zero_max_connections_out() {
    let cfg = NetworkConfig {
        max_connections_out: 0,
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.validate(), Err(ConfigError::ZeroMaxConnectionsOut));
}

#[test]
fn validate_rejects_zero_max_connections_in() {
    let cfg = NetworkConfig {
        max_connections_in: 0,
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.validate(), Err(ConfigError::ZeroMaxConnectionsIn));
}

#[test]
fn validate_rejects_zero_request_timeout() {
    let cfg = NetworkConfig {
        request_timeout: Duration::ZERO,
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.validate(), Err(ConfigError::ZeroRequestTimeout));
}

#[test]
fn validate_rejects_zero_idle_timeout() {
    let cfg = NetworkConfig {
        idle_timeout: Duration::ZERO,
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.validate(), Err(ConfigError::ZeroIdleTimeout));
}

#[test]
fn validate_rejects_zero_gossip_heartbeat() {
    let cfg = NetworkConfig {
        gossip_heartbeat: Duration::ZERO,
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.validate(), Err(ConfigError::ZeroGossipHeartbeat));
}

#[test]
fn validate_rejects_empty_listen_addrs() {
    let cfg = NetworkConfig {
        listen_addrs: vec![],
        ..NetworkConfig::default()
    };
    assert_eq!(cfg.validate(), Err(ConfigError::EmptyListenAddrs));
}

// ── snapshots_enabled ─────────────────────────────────────────────────────────

#[test]
fn snapshots_disabled_when_interval_is_zero() {
    let cfg = NetworkConfig {
        snapshot_interval: 0,
        ..NetworkConfig::default()
    };
    assert!(!cfg.snapshots_enabled());
}

#[test]
fn snapshots_enabled_when_interval_is_nonzero() {
    let cfg = NetworkConfig {
        snapshot_interval: DEFAULT_TESTNET_SNAPSHOT_INTERVAL,
        ..NetworkConfig::default()
    };
    assert!(cfg.snapshots_enabled());
}

// ── testnet() profile ─────────────────────────────────────────────────────────

#[test]
fn testnet_listens_on_fixed_port() {
    let cfg = NetworkConfig::testnet();
    assert_eq!(cfg.listen_addrs.len(), 1);
    assert_eq!(
        cfg.listen_addrs[0],
        "/ip4/0.0.0.0/tcp/30303".parse::<Multiaddr>().unwrap()
    );
}

#[test]
fn testnet_snapshot_interval_matches_constant() {
    let cfg = NetworkConfig::testnet();
    assert_eq!(cfg.snapshot_interval, DEFAULT_TESTNET_SNAPSHOT_INTERVAL);
    assert!(
        cfg.snapshots_enabled(),
        "testnet must have snapshots enabled"
    );
}

#[test]
fn testnet_inherits_default_limits() {
    // testnet() uses ..default() so numeric limits must match the default constants.
    let cfg = NetworkConfig::testnet();
    assert_eq!(cfg.max_range, DEFAULT_MAX_RANGE);
    assert_eq!(cfg.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
    assert_eq!(cfg.request_timeout, DEFAULT_REQUEST_TIMEOUT);
    assert_eq!(cfg.max_connections_out, DEFAULT_MAX_CONNECTIONS_OUT);
    assert_eq!(cfg.max_connections_in, DEFAULT_MAX_CONNECTIONS_IN);
}

// ── Topic / protocol string constants ────────────────────────────────────────

#[test]
fn topic_strings_have_version_suffix() {
    // Versioned strings enable forward-compat (12-NETWORK_SYNC_SPEC §1).
    assert!(
        TOPIC_BLOCKS.ends_with("/1"),
        "TOPIC_BLOCKS must end with version /1"
    );
    assert!(
        TOPIC_DAG.ends_with("/1"),
        "TOPIC_DAG must end with version /1"
    );
    assert!(
        TOPIC_TX.ends_with("/1"),
        "TOPIC_TX must end with version /1"
    );
    assert!(
        PROTOCOL_SYNC.ends_with("/1"),
        "PROTOCOL_SYNC must end with version /1"
    );
    assert!(
        PROTOCOL_STATE.ends_with("/1"),
        "PROTOCOL_STATE must end with version /1"
    );
    assert!(
        PROTOCOL_KAD.ends_with("/1"),
        "PROTOCOL_KAD must end with version /1"
    );
}

#[test]
fn gossipsub_topics_have_no_leading_slash() {
    // gossipsub topics are pub-sub strings, NOT multistream-select protocol IDs.
    // See module-level doc for the format convention explanation.
    assert!(
        !TOPIC_BLOCKS.starts_with('/'),
        "TOPIC_BLOCKS must not have a leading slash"
    );
    assert!(
        !TOPIC_DAG.starts_with('/'),
        "TOPIC_DAG must not have a leading slash"
    );
    assert!(
        !TOPIC_TX.starts_with('/'),
        "TOPIC_TX must not have a leading slash"
    );
}

#[test]
fn request_response_protocols_have_leading_slash() {
    // request-response and Kademlia protocol IDs follow the libp2p
    // multistream-select convention: /namespace/name/version.
    assert!(
        PROTOCOL_SYNC.starts_with('/'),
        "PROTOCOL_SYNC must have a leading slash"
    );
    assert!(
        PROTOCOL_STATE.starts_with('/'),
        "PROTOCOL_STATE must have a leading slash"
    );
    assert!(
        PROTOCOL_KAD.starts_with('/'),
        "PROTOCOL_KAD must have a leading slash"
    );
}

#[test]
fn all_strings_are_lemma_namespaced() {
    // All topics/protocols must use the lemma namespace to avoid collisions.
    assert!(TOPIC_BLOCKS.contains("lemma/"));
    assert!(TOPIC_DAG.contains("lemma/"));
    assert!(TOPIC_TX.contains("lemma/"));
    assert!(PROTOCOL_SYNC.contains("/lemma/"));
    assert!(PROTOCOL_STATE.contains("/lemma/"));
    assert!(PROTOCOL_KAD.contains("/lemma/"));
}

#[test]
fn all_topics_are_distinct() {
    let topics = [TOPIC_BLOCKS, TOPIC_DAG, TOPIC_TX];
    let protocols = [PROTOCOL_SYNC, PROTOCOL_STATE, PROTOCOL_KAD];
    for (i, a) in topics.iter().enumerate() {
        for (j, b) in topics.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "duplicate topic: {a}");
            }
        }
    }
    for (i, a) in protocols.iter().enumerate() {
        for (j, b) in protocols.iter().enumerate() {
            if i != j {
                assert_ne!(a, b, "duplicate protocol: {a}");
            }
        }
    }
}

// ── Clone + PartialEq ─────────────────────────────────────────────────────────

#[test]
fn network_config_clone_equals_original() {
    // PartialEq is derived, so this covers all 11 fields at once.
    let cfg = NetworkConfig::default();
    assert_eq!(cfg.clone(), cfg);
}

#[test]
fn testnet_clone_equals_original() {
    let cfg = NetworkConfig::testnet();
    assert_eq!(cfg.clone(), cfg);
}

// ── Struct update syntax ──────────────────────────────────────────────────────

#[test]
fn struct_update_overrides_single_field_and_inherits_rest() {
    let base = NetworkConfig::default();
    let custom = NetworkConfig {
        max_range: 42,
        ..NetworkConfig::default()
    };
    assert_eq!(custom.max_range, 42);
    assert_eq!(custom.max_response_bytes, base.max_response_bytes);
    assert_eq!(custom.request_timeout, base.request_timeout);
    assert_eq!(custom.snapshot_interval, base.snapshot_interval);
}

// ── ConfigError display ───────────────────────────────────────────────────────

#[test]
fn config_error_display_is_non_empty_for_all_variants() {
    let variants = [
        ConfigError::ZeroMaxRange,
        ConfigError::ZeroMaxResponseBytes,
        ConfigError::ZeroMaxInboundSubstreams,
        ConfigError::ZeroMaxConnectionsOut,
        ConfigError::ZeroMaxConnectionsIn,
        ConfigError::ZeroRequestTimeout,
        ConfigError::ZeroIdleTimeout,
        ConfigError::ZeroGossipHeartbeat,
        ConfigError::EmptyListenAddrs,
    ];
    for v in &variants {
        let msg = v.to_string();
        assert!(
            !msg.is_empty(),
            "ConfigError variant must have non-empty display: {v:?}"
        );
    }
}
