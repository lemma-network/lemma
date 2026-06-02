//! Tests for `shield::tpke`.
//!
//! Covers: hash_to_g2 determinism, encrypt→validate roundtrip, validity
//! rejection on tampered ciphertexts, batch validity, HKDF determinism,
//! payload size bounds, and combine (S4: full encrypt→combine→plaintext roundtrip,
//! threshold enforcement, Lagrange subset determinism, error paths).

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};

use super::{combine, encrypt, hash_to_g2, validate, validate_batch, CombineShare};
use crate::shield::{
    ciphertext::ShieldAad, domain::ShieldDomain, params::MAX_SHIELD_PAYLOAD_BYTES, ShieldError,
};

// ── Test fixtures ─────────────────────────────────────────────────────────────

fn test_aad() -> ShieldAad {
    ShieldAad {
        chain_id: 1,
        epoch: 10,
        submitter_nonce: 42,
    }
}

fn test_aad2() -> ShieldAad {
    ShieldAad {
        chain_id: 2,
        epoch: 10,
        submitter_nonce: 0,
    }
}

fn test_y() -> G1Affine {
    G1Affine::generator()
}

// ── hash_to_g2 determinism ────────────────────────────────────────────────────

#[test]
fn hash_to_g2_is_deterministic_for_same_input() {
    let u = G1Affine::generator();
    let aad = test_aad();
    let p1 = hash_to_g2(&u, &aad).unwrap();
    let p2 = hash_to_g2(&u, &aad).unwrap();
    assert_eq!(p1, p2, "H_G2 must be deterministic for same (U, aad)");
}

#[test]
fn hash_to_g2_differs_for_different_u() {
    let aad = test_aad();
    let u1 = G1Affine::generator();
    let u2: G1Affine = (-G1Affine::generator().into_group()).into_affine();
    let p1 = hash_to_g2(&u1, &aad).unwrap();
    let p2 = hash_to_g2(&u2, &aad).unwrap();
    assert_ne!(p1, p2, "different U must produce different H_G2 points");
}

#[test]
fn hash_to_g2_differs_for_different_aad() {
    let u = G1Affine::generator();
    let p1 = hash_to_g2(&u, &test_aad()).unwrap();
    let p2 = hash_to_g2(&u, &test_aad2()).unwrap();
    assert_ne!(p1, p2, "different aad must produce different H_G2 points");
}

#[test]
fn hash_to_g2_output_is_in_correct_subgroup() {
    let p = hash_to_g2(&G1Affine::generator(), &test_aad()).unwrap();
    assert!(
        p.is_in_correct_subgroup_assuming_on_curve(),
        "hash_to_g2 output must be in G2 subgroup"
    );
}

// ── encrypt → validate roundtrip ─────────────────────────────────────────────

#[test]
fn encrypt_produces_valid_ciphertext_empty_msg() {
    let ct = encrypt(&test_y(), test_aad(), b"").unwrap();
    assert!(
        validate(&ct).is_ok(),
        "empty-message ciphertext must validate"
    );
}

#[test]
fn encrypt_produces_valid_ciphertext_hello() {
    let ct = encrypt(&test_y(), test_aad(), b"hello lemma shield").unwrap();
    assert!(validate(&ct).is_ok());
}

#[test]
fn encrypt_produces_valid_ciphertext_max_payload() {
    let msg = vec![0x42u8; MAX_SHIELD_PAYLOAD_BYTES];
    let ct = encrypt(&test_y(), test_aad(), &msg).unwrap();
    assert!(validate(&ct).is_ok());
}

#[test]
fn encrypt_two_calls_produce_different_ciphertexts() {
    let ct1 = encrypt(&test_y(), test_aad(), b"same message").unwrap();
    let ct2 = encrypt(&test_y(), test_aad(), b"same message").unwrap();
    assert_ne!(ct1.u, ct2.u, "distinct r values must produce distinct U");
}

// ── validate rejects tampered ciphertexts ────────────────────────────────────

#[test]
fn validate_rejects_tampered_u() {
    let mut ct = encrypt(&test_y(), test_aad(), b"test").unwrap();
    ct.u = (-G1Affine::generator().into_group()).into_affine();
    assert_eq!(
        validate(&ct).unwrap_err(),
        ShieldError::InvalidCiphertext,
        "tampered U must fail"
    );
}

#[test]
fn validate_rejects_tampered_w() {
    let mut ct = encrypt(&test_y(), test_aad(), b"test").unwrap();
    ct.w = G2Affine::generator();
    assert_eq!(
        validate(&ct).unwrap_err(),
        ShieldError::InvalidCiphertext,
        "tampered W must fail"
    );
}

#[test]
fn validate_rejects_tampered_aad() {
    let mut ct = encrypt(&test_y(), test_aad(), b"test").unwrap();
    ct.aad.epoch += 1;
    assert_eq!(
        validate(&ct).unwrap_err(),
        ShieldError::InvalidCiphertext,
        "tampered aad must fail"
    );
}

#[test]
fn validate_rejects_zero_points() {
    use crate::shield::ciphertext::Ciphertext;
    let ct = Ciphertext {
        u: G1Affine::zero(),
        w: G2Affine::zero(),
        aad: test_aad(),
        payload: vec![0u8; 32],
    };
    assert!(
        validate(&ct).is_err(),
        "ciphertext with zero points must fail"
    );
}

// ── Payload size guard ────────────────────────────────────────────────────────

#[test]
fn encrypt_rejects_oversized_payload() {
    let oversized = vec![0u8; MAX_SHIELD_PAYLOAD_BYTES + 1];
    assert_eq!(
        encrypt(&test_y(), test_aad(), &oversized).unwrap_err(),
        ShieldError::PayloadTooLarge {
            len: MAX_SHIELD_PAYLOAD_BYTES + 1,
            max: MAX_SHIELD_PAYLOAD_BYTES
        }
    );
}

#[test]
fn encrypt_accepts_exactly_max_payload() {
    let exactly_max = vec![0u8; MAX_SHIELD_PAYLOAD_BYTES];
    assert!(encrypt(&test_y(), test_aad(), &exactly_max).is_ok());
}

// ── validate_batch ────────────────────────────────────────────────────────────

#[test]
fn validate_batch_empty_slice_is_ok() {
    assert!(validate_batch(&[]).is_ok());
}

#[test]
fn validate_batch_single_valid_ciphertext() {
    let ct = encrypt(&test_y(), test_aad(), b"batch test").unwrap();
    assert!(validate_batch(&[ct]).is_ok());
}

#[test]
fn validate_batch_multiple_valid_ciphertexts() {
    let ct1 = encrypt(&test_y(), test_aad(), b"msg one").unwrap();
    let ct2 = encrypt(&test_y(), test_aad2(), b"msg two").unwrap();
    let ct3 = encrypt(
        &test_y(),
        ShieldAad {
            chain_id: 3,
            epoch: 1,
            submitter_nonce: 0,
        },
        b"three",
    )
    .unwrap();
    assert!(validate_batch(&[ct1, ct2, ct3]).is_ok());
}

#[test]
fn validate_batch_rejects_when_one_ciphertext_is_tampered() {
    let ct1 = encrypt(&test_y(), test_aad(), b"good one").unwrap();
    let mut ct2 = encrypt(&test_y(), test_aad2(), b"bad one").unwrap();
    ct2.w = G2Affine::generator();
    assert_eq!(
        validate_batch(&[ct1, ct2]).unwrap_err(),
        ShieldError::InvalidCiphertext,
        "batch must reject if any ciphertext is invalid"
    );
}

#[test]
fn validate_batch_matches_individual_validate_for_valid_set() {
    let cts: Vec<_> = (0..4)
        .map(|i| {
            let aad = ShieldAad {
                chain_id: 1,
                epoch: 1,
                submitter_nonce: i,
            };
            encrypt(&test_y(), aad, b"message").unwrap()
        })
        .collect();
    for ct in &cts {
        assert!(validate(ct).is_ok());
    }
    assert!(validate_batch(&cts).is_ok());
}

// ── Subgroup rejection ────────────────────────────────────────────────────────

#[test]
fn validate_rejects_zero_u() {
    use crate::shield::ciphertext::Ciphertext;
    let ct = Ciphertext {
        u: G1Affine::zero(),
        w: G2Affine::generator(),
        aad: test_aad(),
        payload: vec![0u8; 16],
    };
    assert_eq!(validate(&ct).unwrap_err(), ShieldError::InvalidCiphertext);
}

#[test]
fn validate_rejects_zero_w() {
    use crate::shield::ciphertext::Ciphertext;
    let ct = Ciphertext {
        u: G1Affine::generator(),
        w: G2Affine::zero(),
        aad: test_aad(),
        payload: vec![0u8; 16],
    };
    assert_eq!(validate(&ct).unwrap_err(), ShieldError::InvalidCiphertext);
}

#[test]
fn guard_chain_fires_on_degenerate_point() {
    // Tests the zero-point branch of the guard chain in `validate`.
    // The guard checks: is_zero() || !is_in_correct_subgroup_assuming_on_curve().
    // A zero 𝔾₂ point triggers is_zero(), so the guard fires before the subgroup check.
    //
    // Coverage note (S2-subgroup debt, living-notes.md):
    // A genuine off-subgroup 𝔾₂ vector (non-zero, on curve, wrong subgroup) cannot
    // be constructed through arkworks' safe public API — cofactor clearing happens
    // automatically on deserialization and in all standard constructors.
    // The subgroup branch (`!is_in_correct_subgroup_assuming_on_curve()`) therefore
    // requires a low-level unsafe construction or an externally-sourced raw byte vector.
    // TODO(shield): add a genuine off-subgroup 𝔾₂ byte vector test — issue #3.
    use crate::shield::ciphertext::Ciphertext;
    let ct = Ciphertext {
        u: G1Affine::generator(),
        w: G2Affine::zero(),
        aad: test_aad(),
        payload: vec![0u8; 16],
    };
    assert_eq!(
        validate(&ct).unwrap_err(),
        ShieldError::InvalidCiphertext,
        "guard chain must fire on zero 𝔾₂ point (degenerate ciphertext)"
    );
}

#[test]
fn validate_batch_rejects_element_with_zero_u() {
    use crate::shield::ciphertext::Ciphertext;
    let good = encrypt(&test_y(), test_aad(), b"good").unwrap();
    let bad = Ciphertext {
        u: G1Affine::zero(),
        w: G2Affine::generator(),
        aad: test_aad2(),
        payload: vec![0u8; 16],
    };
    assert_eq!(
        validate_batch(&[good, bad]).unwrap_err(),
        ShieldError::InvalidCiphertext,
        "batch must reject any element with a zero U"
    );
}

// ── Fiat-Shamir challenge determinism ─────────────────────────────────────────

#[test]
fn fiat_shamir_challenges_are_deterministic_for_same_ciphertexts() {
    use super::fiat_shamir_challenges;
    let ct1 = encrypt(&test_y(), test_aad(), b"alpha").unwrap();
    let ct2 = encrypt(&test_y(), test_aad2(), b"beta").unwrap();
    let cts = vec![ct1, ct2];
    let alphas1 = fiat_shamir_challenges(&cts).unwrap();
    let alphas2 = fiat_shamir_challenges(&cts).unwrap();
    assert_eq!(alphas1, alphas2, "FS challenges must be deterministic");
}

#[test]
fn fiat_shamir_challenges_differ_for_different_ciphertext_order() {
    use super::fiat_shamir_challenges;
    let ct1 = encrypt(&test_y(), test_aad(), b"first").unwrap();
    let ct2 = encrypt(&test_y(), test_aad2(), b"second").unwrap();
    let fwd = fiat_shamir_challenges(&[ct1.clone(), ct2.clone()]).unwrap();
    let rev = fiat_shamir_challenges(&[ct2, ct1]).unwrap();
    assert_ne!(
        fwd, rev,
        "different order must produce different challenges"
    );
}

// ── combine (S4) ──────────────────────────────────────────────────────────────
//
// Z_{i,ω} = [f(ω)]H synthesized directly — no PVSS needed (dk cancels, §4.5).
// f(x) = a₀ + a₁·x,  Y = [a₀]G,  Z_ω = [a₀ + a₁·ω]H ∈ 𝔾₂
//
// Minimum W=4 (ShieldParams::for_weight rejects W<4).
// W=4: t=0, p=2, p+1=3. Need ≥3 contributing shares.
// W=6: t=1, p=4, p+1=5. Need ≥5 contributing shares.

fn poly_eval(a0: Fr, a1: Fr, omega: u16) -> Fr {
    a0 + a1 * Fr::from(omega as u64)
}

fn z_share(a0: Fr, a1: Fr, omega: u16) -> G2Affine {
    (G2Projective::from(G2Affine::generator()) * poly_eval(a0, a1, omega)).into_affine()
}

fn threshold_y(a0: Fr) -> G1Affine {
    (G1Projective::from(G1Affine::generator()) * a0).into_affine()
}

fn make_domain(w: u64) -> ShieldDomain {
    ShieldDomain::new(w).unwrap()
}

/// ValidatorSet from (address_byte, share_count) pairs — mirrors committee/tests.rs.
fn vset_for_combine(epoch: u64, entries: &[(u8, u64)]) -> lemma_core::validator_set::ValidatorSet {
    use crate::shield::params::WEIGHT_GRANULARITY_DROP;
    use lemma_core::{
        amount::Amount,
        validator::{ConsensusKey, VotingPower},
        validator_set::{Member, ValidatorSet},
    };
    use std::collections::BTreeMap;
    let mut members = BTreeMap::new();
    let mut total_power = Amount::from_drop(0);
    for &(byte, shares) in entries {
        let drop_amt = u128::from(shares) * WEIGHT_GRANULARITY_DROP;
        let power = VotingPower(Amount::from_drop(drop_amt));
        total_power = total_power
            .checked_add(Amount::from_drop(drop_amt))
            .unwrap();
        members.insert(
            lemma_core::address::Address::from_public_key(&[byte; 32]),
            Member {
                consensus_pubkey: ConsensusKey::from_bytes(vec![byte; 32], vec![0u8; 1952]),
                power,
            },
        );
    }
    ValidatorSet {
        epoch,
        members,
        total_power,
    }
}

/// Single-validator roundtrip. Committee has `committee_w` total shares;
/// `contributing` is the subset actually provided to combine.
fn roundtrip_single(
    committee_w: u64,
    a0: Fr,
    a1: Fr,
    contributing: &[u16],
    msg: &[u8],
    aad: ShieldAad,
) -> Result<Vec<u8>, ShieldError> {
    use crate::shield::committee::ShieldCommittee;
    let domain = make_domain(committee_w);
    let y = threshold_y(a0);
    let ct = encrypt(&y, aad, msg).unwrap();
    let shares = vec![CombineShare {
        validator_index: 0,
        z_shares: contributing
            .iter()
            .map(|&id| (id, z_share(a0, a1, id)))
            .collect(),
    }];
    let vs = vset_for_combine(1, &[(1u8, committee_w)]);
    let committee = ShieldCommittee::from_validator_set(&vs)?;
    combine(&ct, &shares, &committee, &domain)
}

/// Two-validator roundtrip. V0 has ids0, V1 has ids1.
fn roundtrip_two(
    a0: Fr,
    a1: Fr,
    ids0: &[u16],
    ids1: &[u16],
    msg: &[u8],
    aad: ShieldAad,
) -> Result<Vec<u8>, ShieldError> {
    use crate::shield::committee::ShieldCommittee;
    let total_w = (ids0.len() + ids1.len()) as u64;
    let domain = make_domain(total_w);
    let y = threshold_y(a0);
    let ct = encrypt(&y, aad, msg).unwrap();
    let shares = vec![
        CombineShare {
            validator_index: 0,
            z_shares: ids0.iter().map(|&id| (id, z_share(a0, a1, id))).collect(),
        },
        CombineShare {
            validator_index: 1,
            z_shares: ids1.iter().map(|&id| (id, z_share(a0, a1, id))).collect(),
        },
    ];
    let vs = vset_for_combine(1, &[(1u8, ids0.len() as u64), (2u8, ids1.len() as u64)]);
    let committee = ShieldCommittee::from_validator_set(&vs)?;
    combine(&ct, &shares, &committee, &domain)
}

#[test]
fn combine_full_committee_recovers_plaintext() {
    // W=4 (minimum), f(x)=7 (constant). All 4 shares. 4 ≥ p+1=3.
    let msg = b"hello threshold";
    let res = roundtrip_single(
        4,
        Fr::from(7u64),
        Fr::from(0u64),
        &[1, 2, 3, 4],
        msg,
        test_aad(),
    )
    .unwrap();
    assert_eq!(res, msg);
}

#[test]
fn combine_linear_poly_recovers_plaintext() {
    // W=4, f(x) = 3 + 2x. All 4 shares.
    let msg = b"linear polynomial";
    let res = roundtrip_single(
        4,
        Fr::from(3u64),
        Fr::from(2u64),
        &[1, 2, 3, 4],
        msg,
        test_aad(),
    )
    .unwrap();
    assert_eq!(res, msg);
}

#[test]
fn combine_two_validators_split_shares() {
    // W=4: V0={1,2,3}, V1={4}. Total=4 ≥ p+1=3.
    let msg = b"split across validators";
    let res = roundtrip_two(
        Fr::from(11u64),
        Fr::from(5u64),
        &[1, 2, 3],
        &[4],
        msg,
        test_aad(),
    )
    .unwrap();
    assert_eq!(res, msg);
}

#[test]
fn combine_succeeds_at_exactly_p_plus_1_weight() {
    // W=6: t=1, p=4, p+1=5. Contribute exactly 5 shares (minimum threshold).
    let msg = b"exactly at threshold";
    let res = roundtrip_single(
        6,
        Fr::from(13u64),
        Fr::from(3u64),
        &[1, 2, 3, 4, 5],
        msg,
        test_aad(),
    )
    .unwrap();
    assert_eq!(res, msg);
}

#[test]
fn combine_fails_below_threshold() {
    // W=6: p+1=5. Contribute 4 shares → InsufficientShares{have:4,need:5}.
    use crate::shield::committee::ShieldCommittee;
    let a0 = Fr::from(13u64);
    let a1 = Fr::from(3u64);
    let domain = make_domain(6);
    let y = threshold_y(a0);
    let ct = encrypt(&y, test_aad(), b"secret").unwrap();
    let shares = vec![CombineShare {
        validator_index: 0,
        z_shares: (1u16..=4).map(|id| (id, z_share(a0, a1, id))).collect(),
    }];
    // Full committee = W=6; we only contribute 4
    let vs = vset_for_combine(1, &[(1u8, 6u64)]);
    let committee = ShieldCommittee::from_validator_set(&vs).unwrap();
    let err = combine(&ct, &shares, &committee, &domain).unwrap_err();
    assert!(
        matches!(err, ShieldError::InsufficientShares { have: 4, need: 5 }),
        "expected InsufficientShares{{have:4,need:5}}, got {err:?}"
    );
}

#[test]
fn combine_any_valid_subset_yields_identical_plaintext() {
    // W=6: subset A={1..5} (5 shares) vs subset B={1..6} (6 shares).
    // Both recover f(0)=a₀ → same S → same plaintext (§11 determinism).
    let a0 = Fr::from(17u64);
    let a1 = Fr::from(4u64);
    let msg = b"determinism across subsets";
    let res_a = roundtrip_single(6, a0, a1, &[1, 2, 3, 4, 5], msg, test_aad()).unwrap();
    let res_b = roundtrip_single(6, a0, a1, &[1, 2, 3, 4, 5, 6], msg, test_aad()).unwrap();
    assert_eq!(res_a, msg, "subset A (5 of 6) must recover plaintext");
    assert_eq!(res_b, msg, "subset B (all 6) must recover plaintext");
}

#[test]
fn combine_rejects_tampered_payload() {
    use crate::shield::committee::ShieldCommittee;
    let a0 = Fr::from(7u64);
    let a1 = Fr::from(0u64);
    let domain = make_domain(4);
    let y = threshold_y(a0);
    let mut ct = encrypt(&y, test_aad(), b"secret msg").unwrap();
    if let Some(b) = ct.payload.first_mut() {
        *b ^= 0xFF;
    }
    let shares = vec![CombineShare {
        validator_index: 0,
        z_shares: (1u16..=4).map(|id| (id, z_share(a0, a1, id))).collect(),
    }];
    let vs = vset_for_combine(1, &[(1u8, 4u64)]);
    let committee = ShieldCommittee::from_validator_set(&vs).unwrap();
    assert_eq!(
        combine(&ct, &shares, &committee, &domain).unwrap_err(),
        ShieldError::AeadFailure
    );
}

#[test]
fn combine_empty_message_roundtrip() {
    let res = roundtrip_single(
        4,
        Fr::from(5u64),
        Fr::from(0u64),
        &[1, 2, 3, 4],
        b"",
        test_aad(),
    )
    .unwrap();
    assert_eq!(res, b"");
}

// ── Lagrange subset validation (W1 closure, S4) ───────────────────────────────

#[test]
fn lagrange_coeffs_for_rejects_zero_id() {
    let domain = make_domain(4);
    assert!(matches!(
        domain.lagrange_coeffs_for(vec![0u16, 1, 2]).unwrap_err(),
        ShieldError::Lagrange(_)
    ));
}

#[test]
fn lagrange_coeffs_for_rejects_out_of_range_id() {
    let domain = make_domain(4); // W=4; ID 5 > W
    assert!(matches!(
        domain.lagrange_coeffs_for(vec![1, 2, 5]).unwrap_err(),
        ShieldError::Lagrange(_)
    ));
}

#[test]
fn lagrange_coeffs_for_rejects_duplicates() {
    let domain = make_domain(4);
    assert!(matches!(
        domain.lagrange_coeffs_for(vec![1, 2, 2]).unwrap_err(),
        ShieldError::Lagrange(_)
    ));
}
