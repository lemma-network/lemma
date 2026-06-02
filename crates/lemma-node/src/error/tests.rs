//! Tests for [`NodeError`].
//!
//! Covers: `#[from]` conversions, `Display` messages, variant construction.

use super::*;

// ── From conversions ──────────────────────────────────────────────────────────

#[test]
fn node_error_from_storage_error() {
    let inner = StorageError::KeyNotFound { key: "k".into() };
    let err = NodeError::from(inner);
    assert!(matches!(err, NodeError::Storage(_)));
}

#[test]
fn node_error_from_block_error() {
    let inner = BlockError::GasLimitZero;
    let err = NodeError::from(inner);
    assert!(matches!(err, NodeError::Block(_)));
}

// ── Display messages ──────────────────────────────────────────────────────────

#[test]
fn node_error_config_contains_message() {
    let err = NodeError::Config("data_dir missing".into());
    assert!(err.to_string().contains("data_dir missing"));
}

#[test]
fn node_error_genesis_json_contains_message() {
    let err = NodeError::GenesisJson("unexpected token at line 1".into());
    assert!(err.to_string().contains("unexpected token"));
}

#[test]
fn node_error_serialization_contains_message() {
    let err = NodeError::Serialization("buffer too small".into());
    assert!(err.to_string().contains("buffer too small"));
}
