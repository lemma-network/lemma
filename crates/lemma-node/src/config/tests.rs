//! Tests for [`NodeConfig`].
//!
//! Covers: JSON load (happy + missing-file + malformed), validate (valid +
//! empty-data-dir + empty-genesis-path), round-trip serialisation.

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
    let cfg = NodeConfig { data_dir: PathBuf::from(""), ..valid_config() };
    let err = cfg.validate().expect_err("empty data_dir must error");
    let msg = err.to_string();
    assert!(matches!(err, NodeError::Config(_)));
    assert!(msg.contains("data_dir"), "got: {msg}");
}

#[test]
fn validate_rejects_empty_genesis_path() {
    let cfg = NodeConfig { genesis_path: PathBuf::from(""), ..valid_config() };
    let err = cfg.validate().expect_err("empty genesis_path must error");
    assert!(matches!(err, NodeError::Config(_)));
}

// ── round-trip ────────────────────────────────────────────────────────────────

#[test]
fn config_round_trips_through_json() {
    let cfg = valid_config();
    let json = serde_json::to_string(&cfg).expect("serialise must succeed");
    let cfg2: NodeConfig = serde_json::from_str(&json).expect("deserialise must succeed");
    assert_eq!(cfg, cfg2);
}
