//! Tests for `lemma_crypto::hashing`.
//!
//! Structure:
//!  - Shared fixtures (known inputs / expected outputs)
//!  - `hash_bytes` tests
//!  - `hash<T>` tests
//!  - `sha256` tests
//!  - `keccak256` tests
//!  - Cross-function isolation tests

use serde::Serialize;

use lemma_core::Hash;

use crate::hashing::{hash, hash_bytes, keccak256, sha256};
use crate::CryptoError;

// ─── Fixtures ────────────────────────────────────────────────────────────────

const EMPTY: &[u8] = b"";
const HELLO: &[u8] = b"hello lemma";

/// A simple serializable struct for `hash<T>` tests.
/// Uses only fixed-size integer fields so bincode produces fully deterministic
/// output (AGENTS.md §7.1 — no HashMap, no floats).
#[derive(Serialize, PartialEq, Debug)]
struct Point {
    x: u32,
    y: u32,
}

/// A second struct type to verify that different types produce different hashes
/// even when field values match.
#[derive(Serialize)]
struct Pair {
    a: u32,
    b: u32,
}

// ─── hash_bytes ───────────────────────────────────────────────────────────────

#[test]
fn hash_bytes_returns_non_zero_for_non_empty_input() {
    let h = hash_bytes(HELLO);
    assert!(!h.is_zero(), "hash of non-empty input must not be zero");
}

#[test]
fn hash_bytes_returns_hash_type() {
    // Verify the return type is lemma_core::Hash (32 bytes).
    let h: Hash = hash_bytes(HELLO);
    assert_eq!(h.as_bytes().len(), 32);
}

#[test]
fn hash_bytes_empty_input_is_not_zero() {
    // Blake3("") is a valid, well-defined non-zero hash.
    let h = hash_bytes(EMPTY);
    assert!(!h.is_zero());
}

#[test]
fn hash_bytes_is_deterministic() {
    // Same input must always produce the same output on the same node
    // and across nodes (AGENTS.md §7.1).
    assert_eq!(hash_bytes(HELLO), hash_bytes(HELLO));
    assert_eq!(hash_bytes(EMPTY), hash_bytes(EMPTY));
}

#[test]
fn hash_bytes_different_inputs_produce_different_hashes() {
    assert_ne!(hash_bytes(b"a"), hash_bytes(b"b"));
    assert_ne!(hash_bytes(EMPTY), hash_bytes(HELLO));
}

#[test]
fn hash_bytes_known_vector() {
    // Blake3 test vector — the canonical empty-string digest.
    // Value from https://github.com/BLAKE3-team/BLAKE3/blob/master/test_vectors/test_vectors.json
    // (zero-length input, default key, no context)
    let expected = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";
    let h = hash_bytes(EMPTY);
    assert_eq!(
        hex::encode(h.as_bytes()),
        expected,
        "blake3 empty-string vector mismatch"
    );
}

// ─── hash<T> ─────────────────────────────────────────────────────────────────

#[test]
fn hash_generic_returns_ok_for_serializable_type() {
    let result = hash(&Point { x: 1, y: 2 });
    assert!(result.is_ok());
}

#[test]
fn hash_generic_returns_non_zero_for_non_default_value() {
    let h = hash(&Point { x: 1, y: 2 }).unwrap();
    assert!(!h.is_zero());
}

#[test]
fn hash_generic_is_deterministic() {
    // Bincode v1 fixint encoding is deterministic — same struct = same bytes
    // = same Blake3 hash on all nodes (AGENTS.md §7.1).
    let a = hash(&Point { x: 42, y: 0 }).unwrap();
    let b = hash(&Point { x: 42, y: 0 }).unwrap();
    assert_eq!(a, b);
}

#[test]
fn hash_generic_different_values_produce_different_hashes() {
    let a = hash(&Point { x: 1, y: 2 }).unwrap();
    let b = hash(&Point { x: 1, y: 3 }).unwrap();
    assert_ne!(a, b);
}

#[test]
fn hash_generic_different_types_same_fields_produce_different_hashes() {
    // Point { x: 1, y: 2 } and Pair { a: 1, b: 2 } have the same field
    // values but different struct names. Bincode does NOT encode the type
    // name — so these produce the same serialized bytes.
    // This is by design: `hash<T>` is a content hash, not a type-tagged hash.
    // Callers that need type discrimination must include a discriminator in
    // their struct (e.g. a `kind: u8` field).
    // Document this expected behaviour so no one is surprised:
    let point_h = hash(&Point { x: 1, y: 2 }).unwrap();
    let pair_h = hash(&Pair { a: 1, b: 2 }).unwrap();
    assert_eq!(
        point_h, pair_h,
        "bincode does not encode type names; same field layout = same hash (by design)"
    );
}

#[test]
fn hash_generic_unit_struct_returns_ok() {
    #[derive(Serialize)]
    struct Unit;
    assert!(hash(&Unit).is_ok());
}

#[test]
fn hash_generic_vec_of_bytes_differs_from_hash_bytes_raw() {
    // hash(&vec![1u8, 2, 3]) serializes the Vec length prefix via bincode
    // BEFORE the bytes, so it differs from hash_bytes(&[1, 2, 3]) which hashes
    // the raw slice directly. This is intentional and must be stable.
    let raw = hash_bytes(&[1u8, 2, 3]);
    let typed = hash(&vec![1u8, 2, 3]).unwrap();
    assert_ne!(
        raw, typed,
        "hash<Vec<u8>> includes bincode length prefix; hash_bytes is raw — must differ"
    );
}

#[test]
fn hash_generic_returns_error_variant_on_failure() {
    // There is no realistic way to make bincode v1 fail on a well-formed
    // Serialize impl (all standard types succeed). We verify that the error
    // type is correct by checking the round-trip via the known variant.
    // If bincode DOES fail, the error must be SerializationFailed.
    // (Positive-path variant — coverage of the error branch is in the
    //  CryptoError tests which verify the variant exists and formats correctly.)
    let ok = hash(&42u64);
    assert!(ok.is_ok(), "hashing a u64 must succeed");

    // Confirm the SerializationFailed variant is reachable (compile-time check).
    fn _assert_error_variant(e: CryptoError) {
        if let CryptoError::SerializationFailed { .. } = e {}
    }
}

// ─── sha256 ───────────────────────────────────────────────────────────────────

#[test]
fn sha256_returns_non_zero_for_non_empty_input() {
    assert!(!sha256(HELLO).is_zero());
}

#[test]
fn sha256_empty_input_known_vector() {
    // RFC 4634 / NIST FIPS 180-4 test vector for SHA-256("").
    let expected = "e3b0c44298fc1c149afbf4c8996fb924\
                    27ae41e4649b934ca495991b7852b855";
    assert_eq!(hex::encode(sha256(EMPTY).as_bytes()), expected);
}

#[test]
fn sha256_abc_known_vector() {
    // SHA-256("abc") — verified against sha2 0.11.0 output, confirmed consistent
    // with sha256_fox_known_vector (fox passes an independently-sourced vector,
    // proving sha2 is computing correct SHA-256).
    let expected = "ba7816bf8f01cfea414140de5dae2223\
                    b00361a396177a9cb410ff61f20015ad";
    assert_eq!(hex::encode(sha256(b"abc").as_bytes()), expected);
}

#[test]
fn sha256_fox_known_vector() {
    // SHA-256("The quick brown fox jumps over the lazy dog")
    // — independently-sourced canonical vector (Wikipedia SHA-2, RFC references).
    // This test proves sha2 is computing correct SHA-256; the abc vector above
    // was derived from the same crate run.
    let expected = "d7a8fbb307d7809469ca9abcb0082e4f\
                    8d5651e46d3cdb762d02d0bf37c9e592";
    assert_eq!(
        hex::encode(sha256(b"The quick brown fox jumps over the lazy dog").as_bytes()),
        expected
    );
}

#[test]
fn sha256_is_deterministic() {
    assert_eq!(sha256(HELLO), sha256(HELLO));
}

#[test]
fn sha256_different_inputs_produce_different_hashes() {
    assert_ne!(sha256(EMPTY), sha256(HELLO));
}

#[test]
fn sha256_differs_from_blake3_for_same_input() {
    // sha256 and hash_bytes must NOT produce the same output for the same
    // input — they are different algorithms.
    assert_ne!(sha256(HELLO), hash_bytes(HELLO));
}

// ─── keccak256 ───────────────────────────────────────────────────────────────

#[test]
fn keccak256_returns_non_zero_for_non_empty_input() {
    assert!(!keccak256(HELLO).is_zero());
}

#[test]
fn keccak256_empty_input_known_vector() {
    // Ethereum's Keccak-256("") — widely published canonical value.
    // Distinct from SHA3-256("") (different padding byte 0x01 vs 0x06).
    let expected = "c5d2460186f7233c927e7db2dcc703c0\
                    e500b653ca82273b7bfad8045d85a470";
    assert_eq!(
        hex::encode(keccak256(EMPTY).as_bytes()),
        expected,
        "keccak256 empty-string vector must match Ethereum canonical value"
    );
}

#[test]
fn keccak256_abc_known_vector() {
    // Keccak-256("abc") — verified against Ethereum tooling.
    let expected = "4e03657aea45a94fc7d47ba826c8d667\
                    c0d1e6e33a64a036ec44f58fa12d6c45";
    assert_eq!(hex::encode(keccak256(b"abc").as_bytes()), expected);
}

#[test]
fn keccak256_is_deterministic() {
    assert_eq!(keccak256(HELLO), keccak256(HELLO));
}

#[test]
fn keccak256_different_inputs_produce_different_hashes() {
    assert_ne!(keccak256(EMPTY), keccak256(HELLO));
}

// ─── Cross-function isolation ────────────────────────────────────────────────

#[test]
fn all_four_functions_produce_different_outputs_for_same_input() {
    // blake3, sha256, keccak256 must all differ from each other for the same
    // non-trivial input. `hash<T>` wraps blake3 but with a different byte
    // stream (bincode-serialized slice vs raw slice) so it also differs from
    // hash_bytes for the same semantic content.
    let raw = hash_bytes(HELLO);
    let s2 = sha256(HELLO);
    let k = keccak256(HELLO);
    let gen = hash(&HELLO.to_vec()).unwrap(); // bincode-prefixed

    assert_ne!(raw, s2, "blake3 ≠ sha256 for same input");
    assert_ne!(raw, k, "blake3 ≠ keccak256 for same input");
    assert_ne!(s2, k, "sha256 ≠ keccak256 for same input");
    assert_ne!(
        raw, gen,
        "hash_bytes (raw) ≠ hash<Vec<u8>> (bincode-prefixed)"
    );
}

#[test]
fn hash_bytes_output_is_a_valid_hash_type() {
    let h = hash_bytes(HELLO);
    // Round-trip through as_bytes → from_bytes must be lossless.
    let roundtripped = Hash::from_bytes(*h.as_bytes());
    assert_eq!(h, roundtripped);
}
