//! Tests for [`NodeConfig`].
//!
//! Covers: JSON load (happy + missing-file + malformed), validate (valid +
//! empty-data-dir + empty-genesis-path + zero-interval + bad-multiaddr),
//! network field defaults, round-trip serialisation.

use std::io::Write as _;
use std::path::PathBuf;

use tempfile::NamedTempFile;

use super::*;

// ── Fixtures ──────────────────────────────────────────────────────────────────

fn write_config_file(json: &str) -> NamedTempFile {
    let mut f = NamedTempFile::new().expect("NamedTempFile::new must succeed");
    write!(f, "{json}").expect("write to NamedTempFile must succeed");
    f
}

fn valid_config() -> NodeConfig {
    NodeConfig {
        data_dir: PathBuf::from("/tmp/lemma-data"),
        genesis_path: PathBuf::from("/tmp/genesis.json"),
        block_interval_ms: 500,
        listen_addr: "/ip4/0.0.0.0/tcp/0".to_string(),
        bootstrap_peers: vec![],
    }
}

// ── load ──────────────────────────────────────────────────────────────────────

#[test]
fn load_parses_valid_json() {
    let json = r#"{"data_dir":"/tmp/lemma-data","genesis_path":"/tmp/genesis.json"}"#;
    let f = write_config_file(json);
    let cfg = NodeConfig::load(f.path()).expect("valid JSON must parse");
    assert_eq!(cfg.data_dir, PathBuf::from("/tmp/lemma-data"));
    assert_eq!(cfg.genesis_path, PathBuf::from("/tmp/genesis.json"));
}

#[test]
fn load_rejects_missing_file() {
    let err = NodeConfig::load("/nonexistent/__lemma_test_config__.json")
        .expect_err("missing file must error");
    assert!(matches!(err, NodeError::Config(_)));
}

#[test]
fn load_rejects_malformed_json() {
    let f = write_config_file("{ not: valid }");
    let err = NodeConfig::load(f.path()).expect_err("malformed JSON must error");
    assert!(matches!(err, NodeError::Config(_)));
}

#[test]
fn load_rejects_missing_required_field() {
    // data_dir present but genesis_path missing.
    let f = write_config_file(r#"{"data_dir":"/tmp"}"#);
    let err = NodeConfig::load(f.path()).expect_err("missing field must error");
    assert!(matches!(err, NodeError::Config(_)));
}

// ── validate ─────────────────────────────────────────────────────────────────

#[test]
fn validate_accepts_valid_config() {
    valid_config().validate().expect("valid config must pass");
}

#[test]
fn validate_rejects_empty_data_dir() {
    let cfg = NodeConfig {
        data_dir: PathBuf::from(""),
        ..valid_config()
    };
    let err = cfg.validate().expect_err("empty data_dir must error");
    let msg = err.to_string();
    assert!(matches!(err, NodeError::Config(_)));
    assert!(msg.contains("data_dir"), "got: {msg}");
}

#[test]
fn validate_rejects_empty_genesis_path() {
    let cfg = NodeConfig {
        genesis_path: PathBuf::from(""),
        ..valid_config()
    };
    let err = cfg.validate().expect_err("empty genesis_path must error");
    assert!(matches!(err, NodeError::Config(_)));
}

// ── block_interval_ms ────────────────────────────────────────────────────────

#[test]
fn load_applies_default_block_interval_when_absent_from_json() {
    let json = r#"{"data_dir":"/tmp/d","genesis_path":"/tmp/g.json"}"#;
    let f = write_config_file(json);
    let cfg = NodeConfig::load(f.path()).expect("valid JSON must parse");
    assert_eq!(cfg.block_interval_ms, 500, "default must be 500 ms");
}

#[test]
fn load_accepts_explicit_block_interval() {
    let json = r#"{"data_dir":"/tmp/d","genesis_path":"/tmp/g.json","block_interval_ms":200}"#;
    let f = write_config_file(json);
    let cfg = NodeConfig::load(f.path()).expect("valid JSON must parse");
    assert_eq!(cfg.block_interval_ms, 200);
}

#[test]
fn validate_rejects_zero_block_interval() {
    let cfg = NodeConfig {
        block_interval_ms: 0,
        ..valid_config()
    };
    let err = cfg.validate().expect_err("zero interval must error");
    assert!(matches!(err, NodeError::Config(_)));
}

// ── network fields ────────────────────────────────────────────────────────────

#[test]
fn load_applies_default_listen_addr_when_absent() {
    let json = r#"{"data_dir":"/tmp/d","genesis_path":"/tmp/g.json"}"#;
    let f = write_config_file(json);
    let cfg = NodeConfig::load(f.path()).expect("valid JSON must parse");
    assert_eq!(cfg.listen_addr, "/ip4/0.0.0.0/tcp/0");
}

#[test]
fn load_applies_empty_bootstrap_peers_when_absent() {
    let json = r#"{"data_dir":"/tmp/d","genesis_path":"/tmp/g.json"}"#;
    let f = write_config_file(json);
    let cfg = NodeConfig::load(f.path()).expect("valid JSON must parse");
    assert!(cfg.bootstrap_peers.is_empty());
}

#[test]
fn load_accepts_explicit_listen_addr() {
    let json = r#"{"data_dir":"/tmp/d","genesis_path":"/tmp/g.json","listen_addr":"/ip4/0.0.0.0/tcp/30303"}"#;
    let f = write_config_file(json);
    let cfg = NodeConfig::load(f.path()).expect("valid JSON must parse");
    assert_eq!(cfg.listen_addr, "/ip4/0.0.0.0/tcp/30303");
}

#[test]
fn validate_rejects_invalid_listen_addr() {
    let cfg = NodeConfig {
        listen_addr: "not-a-multiaddr".to_string(),
        ..valid_config()
    };
    let err = cfg.validate().expect_err("invalid multiaddr must error");
    let msg = err.to_string();
    assert!(matches!(err, NodeError::Config(_)));
    assert!(msg.contains("listen_addr"), "got: {msg}");
}

#[test]
fn validate_rejects_invalid_bootstrap_peer() {
    let cfg = NodeConfig {
        bootstrap_peers: vec!["not-a-multiaddr".to_string()],
        ..valid_config()
    };
    let err = cfg
        .validate()
        .expect_err("invalid bootstrap peer must error");
    let msg = err.to_string();
    assert!(matches!(err, NodeError::Config(_)));
    assert!(msg.contains("bootstrap peer"), "got: {msg}");
}

#[test]
fn validate_accepts_valid_listen_addr_fixed_port() {
    let cfg = NodeConfig {
        listen_addr: "/ip4/0.0.0.0/tcp/30303".to_string(),
        ..valid_config()
    };
    cfg.validate()
        .expect("valid fixed-port listen_addr must pass");
}

#[test]
fn parsed_listen_addr_returns_multiaddr() {
    let cfg = valid_config();
    let addr = cfg.parsed_listen_addr();
    assert_eq!(addr.to_string(), "/ip4/0.0.0.0/tcp/0");
}

// ── round-trip ────────────────────────────────────────────────────────────────

#[test]
fn config_round_trips_through_json() {
    let cfg = valid_config();
    let json = serde_json::to_string(&cfg).expect("serialise must succeed");
    let cfg2: NodeConfig = serde_json::from_str(&json).expect("deserialise must succeed");
    assert_eq!(cfg, cfg2);
}
