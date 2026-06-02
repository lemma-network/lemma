//! Tests for `shield::share` (S3).
//!
//! Coverage:
//! - `decryption_share`: correctness of D_i, zero-key guard, proof round-trip
//! - `verify_share`: accepts valid share, rejects tampered D, proof, cm, ek
//! - DLEQ soundness: cross-witness forgery rejected
//! - `verify_share_batch`: valid batch, mixed-validator batch, bad-share detection,
//!   empty batch, singleton fallback

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{Field, UniformRand, Zero};

use super::{decryption_share, verify_share, verify_share_batch};
use crate::shield::{ciphertext::ShieldAad, tpke::encrypt, ShieldError};

// ── Test fixtures ─────────────────────────────────────────────────────────────

/// A consistent AAD used across tests.
fn test_aad() -> ShieldAad {
    ShieldAad {
        chain_id: 1,
        epoch: 7,
        submitter_nonce: 99,
    }
}

/// A different AAD for cross-aad tests.
fn test_aad2() -> ShieldAad {
    ShieldAad {
        chain_id: 1,
        epoch: 8,
        submitter_nonce: 0,
    }
}

/// A fixed nonzero epoch decryption scalar `dk_i`.
///
/// In production, this is sampled uniformly from 𝔽_r. Here we use Fr::from(42)
/// — small but nonzero, invertible, and deterministic across test runs.
fn test_dk() -> Fr {
    Fr::from(42u64)
}

/// The epoch public key corresponding to `test_dk()`:
/// `ek_i = [dk_i] H  ∈  𝔾₂`
fn test_ek() -> G2Affine {
    // G2Projective has no generator() in arkworks 0.4 — use G2Affine::generator().
    (G2Projective::from(G2Affine::generator()) * test_dk()).into_affine()
}

/// A second validator keypair (dk=7, ek=[7]H).
fn test_dk2() -> Fr {
    Fr::from(7u64)
}

fn test_ek2() -> G2Affine {
    (G2Projective::from(G2Affine::generator()) * test_dk2()).into_affine()
}

/// A threshold public key `Y` used for encryption.
///
/// In production `Y` is the PVSS aggregate. For S3 tests we encrypt to G1::generator()
/// — any nonzero point works, the DLEQ/pairing tests don't depend on Y's origin.
fn test_y() -> G1Affine {
    G1Affine::generator()
}

/// Produce a valid ciphertext for test purposes.
fn test_ct() -> crate::shield::ciphertext::Ciphertext {
    encrypt(&test_y(), test_aad(), b"hello shield").unwrap()
}

/// Produce a second ciphertext (for multi-entry batch tests).
fn test_ct2() -> crate::shield::ciphertext::Ciphertext {
    encrypt(&test_y(), test_aad2(), b"second tx").unwrap()
}

// ── decryption_share correctness ─────────────────────────────────────────────

#[test]
fn decryption_share_d_equals_dk_inv_times_u() {
    // D_i = [dk_i^{-1}] U — verify the scalar-mult is correct.
    let ct = test_ct();
    let dk = test_dk();
    let share = decryption_share(&dk, 0, &ct).unwrap();

    let dk_inv = dk.inverse().unwrap();
    let expected_d: G1Affine = (G1Projective::from(ct.u) * dk_inv).into_affine();
    assert_eq!(share.d, expected_d, "D_i must equal [dk_inv] U");
}

#[test]
fn decryption_share_cm_equals_dk_inv_times_g() {
    // cm_i = [dk_i^{-1}] G
    let ct = test_ct();
    let dk = test_dk();
    let share = decryption_share(&dk, 0, &ct).unwrap();

    let dk_inv = dk.inverse().unwrap();
    let expected_cm: G1Affine = (G1Projective::from(G1Affine::generator()) * dk_inv).into_affine();
    assert_eq!(share.cm, expected_cm, "cm_i must equal [dk_inv] G");
}

#[test]
fn decryption_share_rejects_zero_dk() {
    let ct = test_ct();
    let zero_dk = Fr::zero();
    assert_eq!(
        decryption_share(&zero_dk, 0, &ct).unwrap_err(),
        ShieldError::InvalidKey,
        "zero dk_i must be rejected with InvalidKey"
    );
}

#[test]
fn decryption_share_validator_index_preserved() {
    let ct = test_ct();
    let share = decryption_share(&test_dk(), 17, &ct).unwrap();
    assert_eq!(share.validator_index, 17);
}

#[test]
fn decryption_share_proof_response_is_consistent() {
    // The DLEQ invariant: both p_u and p_g yield the same response.
    // We verify this indirectly: verify_share passes (which checks both DLEQ legs).
    let ct = test_ct();
    let share = decryption_share(&test_dk(), 0, &ct).unwrap();
    // Construct pok_u and pok_g manually from the proof and verify both.
    // (The fact that verify_share passes confirms same response works for both bases.)
    verify_share(&test_ek(), &ct, &share).unwrap();
}

// ── verify_share: happy path ──────────────────────────────────────────────────

#[test]
fn verify_share_accepts_valid_share() {
    let ct = test_ct();
    let share = decryption_share(&test_dk(), 0, &ct).unwrap();
    verify_share(&test_ek(), &ct, &share).unwrap();
}

#[test]
fn verify_share_accepts_second_ciphertext() {
    // DLEQ is per-ciphertext: same dk, different U → different D_i, both valid.
    let ct2 = test_ct2();
    let share2 = decryption_share(&test_dk(), 0, &ct2).unwrap();
    verify_share(&test_ek(), &ct2, &share2).unwrap();
}

#[test]
fn verify_share_accepts_second_validator() {
    let ct = test_ct();
    let share = decryption_share(&test_dk2(), 1, &ct).unwrap();
    verify_share(&test_ek2(), &ct, &share).unwrap();
}

// ── verify_share: tamper rejection ───────────────────────────────────────────

#[test]
fn verify_share_rejects_tampered_d() {
    // Replace D_i with a different G1 point — DLEQ fails.
    let ct = test_ct();
    let mut share = decryption_share(&test_dk(), 0, &ct).unwrap();
    share.d = G1Affine::generator(); // wrong D_i
    assert_eq!(
        verify_share(&test_ek(), &ct, &share).unwrap_err(),
        ShieldError::InvalidProof,
        "tampered D_i must be detected by DLEQ"
    );
}

#[test]
fn verify_share_rejects_tampered_cm() {
    // Replace cm_i — DLEQ on G fails.
    let ct = test_ct();
    let mut share = decryption_share(&test_dk(), 0, &ct).unwrap();
    share.cm = G1Affine::generator(); // wrong cm_i (unless it happens to match — negligible)
    let err = verify_share(&test_ek(), &ct, &share).unwrap_err();
    assert!(
        err == ShieldError::InvalidProof || err == ShieldError::InvalidShare,
        "tampered cm_i must be rejected: got {err:?}"
    );
}

#[test]
fn verify_share_rejects_tampered_proof_response() {
    // Replace the Schnorr response with a random scalar — both DLEQ checks fail.
    let ct = test_ct();
    let mut share = decryption_share(&test_dk(), 0, &ct).unwrap();
    let mut rng = ark_std::rand::thread_rng();
    share.proof.response = Fr::rand(&mut rng);
    assert_eq!(
        verify_share(&test_ek(), &ct, &share).unwrap_err(),
        ShieldError::InvalidProof,
        "random response must be rejected by DLEQ"
    );
}

#[test]
fn verify_share_rejects_tampered_t_u() {
    // Replace t_U — challenge c changes ⟹ verify fails.
    let ct = test_ct();
    let mut share = decryption_share(&test_dk(), 0, &ct).unwrap();
    share.proof.t_u = G1Affine::generator();
    assert_eq!(
        verify_share(&test_ek(), &ct, &share).unwrap_err(),
        ShieldError::InvalidProof,
        "tampered t_U must be rejected"
    );
}

#[test]
fn verify_share_rejects_wrong_ek() {
    // Use a different validator's ek — pairing tie fails.
    let ct = test_ct();
    let share = decryption_share(&test_dk(), 0, &ct).unwrap();
    let wrong_ek = test_ek2(); // ek for dk=7, not dk=42
    assert_eq!(
        verify_share(&wrong_ek, &ct, &share).unwrap_err(),
        ShieldError::InvalidShare,
        "wrong ek_i must be detected by pairing tie"
    );
}

#[test]
fn verify_share_rejects_wrong_ciphertext() {
    // Verify a share for ct1 against ct2 — pairing correctness fails.
    let ct1 = test_ct();
    let ct2 = test_ct2();
    let share = decryption_share(&test_dk(), 0, &ct1).unwrap();
    // share.d = [dk_inv] ct1.u, but ct2.u is different → e(D_i, ek) ≠ e(ct2.u, H)
    let err = verify_share(&test_ek(), &ct2, &share).unwrap_err();
    assert!(
        err == ShieldError::InvalidProof || err == ShieldError::InvalidShare,
        "share for ct1 must be rejected when verified against ct2: got {err:?}"
    );
}

// ── DLEQ soundness ────────────────────────────────────────────────────────────

#[test]
fn dleq_soundness_cross_witness_forged_share_rejected() {
    // Attempt to forge: produce a valid D_i for dk=42, but embed it in a share
    // claiming validator_index=1 (which would use dk=7 with ek=[7]H).
    // The pairing tie e(cm_i, ek_2) == e(G, H) will fail because
    // cm_i = [42_inv]G but ek_2 = [7]H → e([42_inv]G, [7]H) ≠ e(G, H).
    let ct = test_ct();
    let share_42 = decryption_share(&test_dk(), 0, &ct).unwrap();

    // Try to verify share_42 (D = [42_inv]U) against ek_2 ([7]H) — must fail.
    assert_eq!(
        verify_share(&test_ek2(), &ct, &share_42).unwrap_err(),
        ShieldError::InvalidShare,
        "share for dk=42 must be rejected when verified against ek for dk=7"
    );
}

#[test]
fn dleq_soundness_zero_response_rejected() {
    // s=0 with t_U = D_i and t_G = cm_i would satisfy [0]U = t_U + [c]D_i only
    // if t_U = -[c]D_i — extremely unlikely to hold for a real c.
    // This test is a basic sanity check on the response guard.
    let ct = test_ct();
    let mut share = decryption_share(&test_dk(), 0, &ct).unwrap();
    share.proof.response = Fr::zero();
    assert_eq!(
        verify_share(&test_ek(), &ct, &share).unwrap_err(),
        ShieldError::InvalidProof,
        "zero response must be rejected"
    );
}

// ── verify_share_batch ────────────────────────────────────────────────────────

#[test]
fn verify_share_batch_empty_returns_ok() {
    assert!(
        verify_share_batch(&[]).is_ok(),
        "empty batch must return Ok"
    );
}

#[test]
fn verify_share_batch_singleton_delegates_to_verify_share() {
    let ct = test_ct();
    let share = decryption_share(&test_dk(), 0, &ct).unwrap();
    let ek = test_ek();
    verify_share_batch(&[(share, ct, ek)]).unwrap();
}

#[test]
fn verify_share_batch_accepts_two_valid_entries_same_validator() {
    // Same validator, two different ciphertexts.
    let ct1 = test_ct();
    let ct2 = test_ct2();
    let dk = test_dk();
    let ek = test_ek();
    let share1 = decryption_share(&dk, 0, &ct1).unwrap();
    let share2 = decryption_share(&dk, 0, &ct2).unwrap();
    verify_share_batch(&[(share1, ct1, ek), (share2, ct2, ek)]).unwrap();
}

#[test]
fn verify_share_batch_accepts_two_validators() {
    // Two validators, one ciphertext each.
    let ct1 = test_ct();
    let ct2 = test_ct2();
    let share1 = decryption_share(&test_dk(), 0, &ct1).unwrap();
    let share2 = decryption_share(&test_dk2(), 1, &ct2).unwrap();
    verify_share_batch(&[(share1, ct1, test_ek()), (share2, ct2, test_ek2())]).unwrap();
}

#[test]
fn verify_share_batch_rejects_one_bad_share_in_two() {
    // One valid share + one tampered share — batch must reject.
    let ct1 = test_ct();
    let ct2 = test_ct2();
    let good_share = decryption_share(&test_dk(), 0, &ct1).unwrap();
    let mut bad_share = decryption_share(&test_dk(), 0, &ct2).unwrap();
    // Tamper: replace D with an arbitrary point.
    bad_share.d = G1Affine::generator();

    // Note: batch pairing check only — does NOT check DLEQ proofs.
    // A tampered D_i with correct DLEQ proof is structurally inconsistent
    // (the proof would fail in verify_share). Here we test that the batch
    // pairing equation catches the bad share.
    let result = verify_share_batch(&[(good_share, ct1, test_ek()), (bad_share, ct2, test_ek())]);
    assert_eq!(
        result.unwrap_err(),
        ShieldError::InvalidShare,
        "batch must detect the tampered D_i via multi-pairing"
    );
}

#[test]
fn verify_share_batch_rejects_wrong_ek() {
    // Valid share but wrong ek passed in the batch entry.
    let ct = test_ct();
    let share = decryption_share(&test_dk(), 0, &ct).unwrap();
    let wrong_ek = test_ek2();
    assert_eq!(
        verify_share_batch(&[(share, ct, wrong_ek)]).unwrap_err(),
        ShieldError::InvalidShare,
        "batch must reject wrong ek"
    );
}
