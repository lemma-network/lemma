//! Tests for `shield::ciphertext`.
//!
//! Covers: ShieldAad encoding, Ciphertext roundtrip, subgroup checks,
//! payload bounds, truncation detection, and determinism.

use ark_bls12_381::{G1Affine, G2Affine};
use ark_ec::AffineRepr;

use super::{Ciphertext, ShieldAad, AAD_BYTES, MIN_CIPHERTEXT_BYTES};
use crate::shield::{params::MAX_SHIELD_PAYLOAD_BYTES, ShieldError};

// ── ShieldAad encoding ────────────────────────────────────────────────────────

#[test]
fn shield_aad_to_bytes_is_24_bytes() {
    let aad = ShieldAad {
        chain_id: 1,
        epoch: 42,
        submitter_nonce: 999,
    };
    assert_eq!(aad.to_bytes().len(), AAD_BYTES);
}

#[test]
fn shield_aad_roundtrip() {
    let aad = ShieldAad {
        chain_id: 0xDEAD_BEEF_1234_5678,
        epoch: 7,
        submitter_nonce: 0,
    };
    let bytes = aad.to_bytes();
    let decoded = ShieldAad::from_bytes(&bytes);
    assert_eq!(aad, decoded);
}

#[test]
fn shield_aad_zero_roundtrip() {
    let aad = ShieldAad {
        chain_id: 0,
        epoch: 0,
        submitter_nonce: 0,
    };
    assert_eq!(aad, ShieldAad::from_bytes(&aad.to_bytes()));
}

#[test]
fn shield_aad_max_roundtrip() {
    let aad = ShieldAad {
        chain_id: u64::MAX,
        epoch: u64::MAX,
        submitter_nonce: u64::MAX,
    };
    assert_eq!(aad, ShieldAad::from_bytes(&aad.to_bytes()));
}

#[test]
fn shield_aad_different_fields_produce_different_bytes() {
    let a = ShieldAad {
        chain_id: 1,
        epoch: 2,
        submitter_nonce: 3,
    };
    let b = ShieldAad {
        chain_id: 1,
        epoch: 2,
        submitter_nonce: 4,
    };
    let c = ShieldAad {
        chain_id: 1,
        epoch: 3,
        submitter_nonce: 3,
    };
    assert_ne!(a.to_bytes(), b.to_bytes());
    assert_ne!(a.to_bytes(), c.to_bytes());
}

#[test]
fn shield_aad_to_bytes_is_deterministic() {
    let aad = ShieldAad {
        chain_id: 42,
        epoch: 1,
        submitter_nonce: 7,
    };
    assert_eq!(aad.to_bytes(), aad.to_bytes());
}

// ── Ciphertext serialization roundtrip ───────────────────────────────────────

/// Build a minimal valid `Ciphertext` with generator points (pass validity).
fn valid_ciphertext(payload: Vec<u8>) -> Ciphertext {
    // Use curve generators — these form a valid ciphertext structure for
    // serialization tests (the pairing equation may not hold, but that's tpke::validate's concern).
    Ciphertext {
        u: G1Affine::generator(),
        w: G2Affine::generator(),
        aad: ShieldAad {
            chain_id: 1,
            epoch: 5,
            submitter_nonce: 0,
        },
        payload,
    }
}

#[test]
fn ciphertext_bytes_roundtrip_empty_payload() {
    let ct = valid_ciphertext(vec![]);
    let bytes = ct.to_bytes().unwrap();
    let decoded = Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(ct, decoded);
}

#[test]
fn ciphertext_bytes_roundtrip_nonempty_payload() {
    let payload = vec![0xAB; 64];
    let ct = valid_ciphertext(payload);
    let bytes = ct.to_bytes().unwrap();
    let decoded = Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(ct, decoded);
}

#[test]
fn ciphertext_bytes_roundtrip_max_payload() {
    let payload = vec![0xFF; MAX_SHIELD_PAYLOAD_BYTES];
    let ct = valid_ciphertext(payload);
    let bytes = ct.to_bytes().unwrap();
    let decoded = Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(ct, decoded);
}

#[test]
fn ciphertext_to_bytes_includes_expected_header_size() {
    let ct = valid_ciphertext(vec![1, 2, 3]);
    let bytes = ct.to_bytes().unwrap();
    assert_eq!(bytes.len(), MIN_CIPHERTEXT_BYTES + 3);
}

#[test]
fn ciphertext_to_bytes_is_deterministic() {
    let ct = valid_ciphertext(vec![0xAA; 16]);
    assert_eq!(ct.to_bytes().unwrap(), ct.to_bytes().unwrap());
}

// ── from_bytes error cases ────────────────────────────────────────────────────

#[test]
fn from_bytes_rejects_too_short() {
    let short = vec![0u8; MIN_CIPHERTEXT_BYTES - 1];
    assert!(
        matches!(
            Ciphertext::from_bytes(&short),
            Err(ShieldError::Serialization(_))
        ),
        "expected Serialization error for truncated input"
    );
}

#[test]
fn from_bytes_rejects_empty() {
    assert!(matches!(
        Ciphertext::from_bytes(&[]),
        Err(ShieldError::Serialization(_))
    ));
}

#[test]
fn from_bytes_rejects_payload_exceeding_max() {
    // Build a valid header but claim a huge payload.
    let ct = valid_ciphertext(vec![]);
    let mut bytes = ct.to_bytes().unwrap();
    // Overwrite the payload_len u32 field (last 4 bytes of the fixed header).
    let len_offset = bytes.len() - 4; // payload is empty so this is where len is
    let oversized = (MAX_SHIELD_PAYLOAD_BYTES + 1) as u32;
    bytes[len_offset..len_offset + 4].copy_from_slice(&oversized.to_be_bytes());

    assert!(matches!(
        Ciphertext::from_bytes(&bytes),
        Err(ShieldError::PayloadTooLarge { .. })
    ));
}

#[test]
fn from_bytes_rejects_truncated_payload() {
    // Claim payload of 10 bytes but provide 0.
    let mut bytes = valid_ciphertext(vec![]).to_bytes().unwrap();
    let len_offset = bytes.len() - 4;
    bytes[len_offset..len_offset + 4].copy_from_slice(&10u32.to_be_bytes());
    // No payload bytes follow — should error.
    assert!(matches!(
        Ciphertext::from_bytes(&bytes),
        Err(ShieldError::Serialization(_))
    ));
}

#[test]
fn from_bytes_accepts_zero_length_payload() {
    let ct = valid_ciphertext(vec![]);
    let bytes = ct.to_bytes().unwrap();
    assert!(Ciphertext::from_bytes(&bytes).is_ok());
}

// ── Fuzz-lite: from_bytes must not panic on arbitrary bytes ───────────────────

#[test]
fn from_bytes_does_not_panic_on_all_zeros() {
    let zeros = vec![0u8; 256];
    let _ = Ciphertext::from_bytes(&zeros); // must not panic, may return Err
}

#[test]
fn from_bytes_does_not_panic_on_all_ones() {
    let ones = vec![0xFF; 512];
    let _ = Ciphertext::from_bytes(&ones);
}

#[test]
fn from_bytes_does_not_panic_on_random_pattern() {
    // Deterministic "random" pattern via repeating byte sequence.
    let data: Vec<u8> = (0u8..=255).cycle().take(300).collect();
    let _ = Ciphertext::from_bytes(&data);
}
