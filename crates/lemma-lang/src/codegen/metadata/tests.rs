//! Tests for `codegen::metadata::build_metadata`.
//!
//! Follows AGENTS §11.2: tests in a separate submodule file.
//! Test naming: `{action}_{outcome}` (AGENTS §11.3).
//!
//! In P3·Step 6a `build_metadata` is a stub returning `vec![]`.
//! These tests verify the stub contract and will be extended in P3·Step 6i.

use crate::codegen::metadata::build_metadata;

// ─── build_metadata — stub contract ──────────────────────────────────────────

#[test]
fn build_metadata_returns_empty_bytes_in_stub_phase() {
    // In P3·Step 6a the metadata emitter is a stub — it returns empty bytes.
    // Full metadata emission (state-access hints, compiler version, contract
    // metadata) is implemented in P3·Step 6i.
    let metadata_bytes = build_metadata();
    assert_eq!(
        metadata_bytes,
        vec![],
        "expected empty metadata bytes in stub phase, got {} bytes",
        metadata_bytes.len()
    );
}

#[test]
fn build_metadata_is_deterministic_in_stub_phase() {
    // Even the stub must be deterministic (AGENTS §7.1).
    let first = build_metadata();
    let second = build_metadata();
    assert_eq!(first, second, "build_metadata stub is not deterministic");
}
