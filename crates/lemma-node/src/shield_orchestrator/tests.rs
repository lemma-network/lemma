//! Tests for `shield_orchestrator`.
//!
//! | Test | Covers |
//! |------|--------|
//! | `run_epoch_shield_genesis_produces_active_outcome` | DKG path (prev_epoch_key=None) → Active |
//! | `run_epoch_shield_reshare_preserves_y_invariant` | Reshare path (prev_epoch_key=Some) → Active, Y unchanged |
//! | `run_epoch_shield_reshare_noshow_yields_withholders_and_slash` | Reshare with no-show dealer → withholder slashed end-to-end |
//! | `run_epoch_shield_quorum_not_reached_returns_transparent` | DkgQuorumNotReached → Transparent::QuorumNotReached |
//! | `run_epoch_shield_committee_too_small_returns_transparent` | CommitteeTooSmall → Transparent::CommitteeTooSmall |
//! | `run_epoch_shield_is_idempotent` | Same inputs → same outcome |
//! | `apply_withholding_slashes_slashes_and_jails_withholder` | Slash + jail applied to withholder |
//! | `apply_withholding_slashes_honest_but_unselected_not_slashed` | Non-withholder untouched |
//! | `apply_withholding_slashes_returns_total_burned` | total_burned = sum of per-validator burns |
//! | `apply_withholding_slashes_returns_error_for_missing_validator` | ValidatorNotFound on unknown address |

use std::collections::{BTreeMap, BTreeSet};

use ark_bls12_381::{Fr, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use rand::{rngs::StdRng, SeedableRng};

use super::{
    apply_withholding_slashes, run_epoch_shield, EpochShieldOutcome, ShieldOrchestratorError,
    TransparentReason,
};
use lemma_consensus::slashing::liveness::SHARE_WITHHOLDING_JAIL_DURATION_SECONDS;
use lemma_core::{
    address::Address,
    amount::Amount,
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus, VotingPower},
    validator_set::{Member, ValidatorSet},
};
use lemma_mempool::shield::{
    committee::ShieldCommittee,
    params::WEIGHT_GRANULARITY_DROP,
    pvss::{deal, PvssTranscript},
};

// ── Shared test helpers (DRY — AGENTS §2.6) ───────────────────────────────────

/// Deterministic RNG seeded from a `u64`.
fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

/// Epoch label bytes for a given epoch number.
fn test_tau(epoch: u64) -> Vec<u8> {
    format!("epoch:{epoch}:dkg").into_bytes()
}

/// Dummy consensus key (no crypto validation in lemma-core).
fn dummy_key() -> ConsensusKey {
    ConsensusKey::from_bytes(vec![0u8; 32], vec![0u8; 1952])
}

/// Derive an `Address` from a single distinguishing byte.
fn addr(byte: u8) -> Address {
    Address::from_public_key(&[byte; 32])
}

/// Build a `ValidatorSet` with `n` validators, each with `shares_per_validator`
/// shares (weight = shares_per_validator × WEIGHT_GRANULARITY_DROP).
///
/// Requires `n ≥ 2` and `shares_per_validator ≥ 2` so that W ≥ 4 (minimum
/// viable Shield committee). Uses deterministic addresses (byte = index + 1).
fn test_vset_n(n: usize) -> ValidatorSet {
    assert!(
        n >= 2,
        "test_vset_n: need at least 2 validators for a viable committee"
    );
    // 4 shares per validator → W = 4n ≥ 8 (well above the W=4 minimum).
    let shares_per_validator: u64 = 4;
    let power_drop = u128::from(shares_per_validator) * WEIGHT_GRANULARITY_DROP;
    let mut members = BTreeMap::new();
    let mut total_power = Amount::zero();
    for i in 0..n {
        let a = addr((i + 1) as u8);
        let power = VotingPower(Amount::from_drop(power_drop));
        total_power = total_power
            .checked_add(Amount::from_drop(power_drop))
            .unwrap();
        members.insert(
            a,
            Member {
                consensus_pubkey: dummy_key(),
                power,
            },
        );
    }
    ValidatorSet {
        epoch: 1,
        members,
        total_power,
    }
}

/// Build epoch public keys for a committee: `ek_i = dk_i × G2::generator()`.
///
/// Returns `(eks, dks)` where `eks` is the `BTreeMap<u16, G2Affine>` passed to
/// `run_dkg`/`reshare`, and `dks` are the corresponding decryption keys.
/// Pattern mirrors `facade/tests.rs::test_epoch_keys`.
fn test_eks(committee: &ShieldCommittee) -> (BTreeMap<u16, G2Affine>, Vec<Fr>) {
    let h = G2Affine::generator();
    let mut eks = BTreeMap::new();
    let mut dks = Vec::new();
    for (idx, _) in committee.iter().enumerate() {
        let dk = Fr::from((idx + 1) as u64);
        let ek: G2Affine = (G2Projective::from(h) * dk).into_affine();
        eks.insert(idx as u16, ek);
        dks.push(dk);
    }
    (eks, dks)
}

/// Build a `posted` map where all committee members post valid transcripts
/// (`sig_ok = true`).
fn test_posted_all_valid(
    committee: &ShieldCommittee,
    eks: &BTreeMap<u16, G2Affine>,
    tau: &[u8],
) -> BTreeMap<Address, (PvssTranscript, bool)> {
    committee
        .iter()
        .enumerate()
        .map(|(i, (a, _))| {
            let tr = deal(
                tau.to_vec(),
                committee,
                eks,
                &mut seeded_rng(100 + i as u64),
            )
            .unwrap();
            (*a, (tr, true))
        })
        .collect()
}

/// Build a minimal `Validator` with `active` stake set to `active_drop` Drop.
fn test_validator(address: Address, active_drop: u128) -> Validator {
    Validator {
        address,
        consensus_pubkey: dummy_key(),
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active: Amount::from_drop(active_drop),
            ..Stake::zero()
        },
        delegated: Amount::zero(),
        commission_bps: 0,
        jailed_until: None,
    }
}

// ── run_epoch_shield tests ────────────────────────────────────────────────────

#[test]
fn run_epoch_shield_genesis_produces_active_outcome() {
    // Genesis path: prev_epoch_key = None → run_dkg.
    let vset = test_vset_n(3);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_eks(&committee);
    let tau = test_tau(1);
    let posted = test_posted_all_valid(&committee, &eks, &tau);

    let outcome = run_epoch_shield(None, &vset, &posted, &eks, &tau);

    match outcome {
        EpochShieldOutcome::Active {
            epoch_key,
            withholders,
        } => {
            // Y must be a non-identity G1 point (DKG produced a real key).
            assert!(
                !epoch_key.is_zero(),
                "epoch_key must be non-identity after DKG"
            );
            // All dealers posted valid transcripts → no withholders.
            assert!(
                withholders.is_empty(),
                "no withholders when all dealers post valid"
            );
        }
        EpochShieldOutcome::Transparent { reason } => {
            panic!("expected Active, got Transparent({reason:?})");
        }
    }
}

#[test]
fn run_epoch_shield_reshare_preserves_y_invariant() {
    // Reshare path: prev_epoch_key = Some(Y) → reshare, Y must be preserved.
    let vset = test_vset_n(3);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_eks(&committee);
    let tau_dkg = test_tau(1);
    let tau_reshare = b"epoch:1:to:2:reshare".to_vec();
    let posted_dkg = test_posted_all_valid(&committee, &eks, &tau_dkg);

    // Step 1: genesis DKG to get Y.
    let genesis_outcome = run_epoch_shield(None, &vset, &posted_dkg, &eks, &tau_dkg);
    let prev_y = match genesis_outcome {
        EpochShieldOutcome::Active { epoch_key, .. } => epoch_key,
        other => panic!("genesis DKG failed: {other:?}"),
    };

    // Step 2: reshare with the same committee (same vset, epoch N→N+1).
    // Build reshare transcripts using deal_reshare.
    use lemma_mempool::shield::pss::deal_reshare;
    let reshare_posted: BTreeMap<Address, (PvssTranscript, bool)> = committee
        .iter()
        .enumerate()
        .map(|(i, (a, _))| {
            let tr = deal_reshare(
                tau_reshare.clone(),
                &committee,
                &eks,
                &mut seeded_rng(300 + i as u64),
            )
            .unwrap();
            (*a, (tr, true))
        })
        .collect();

    let reshare_outcome =
        run_epoch_shield(Some(prev_y), &vset, &reshare_posted, &eks, &tau_reshare);

    match reshare_outcome {
        EpochShieldOutcome::Active {
            epoch_key,
            withholders,
        } => {
            // Y invariant: reshare output's y = aggregate F_0 = 𝒪 (zero-secret).
            // The epoch_key returned is the aggregate's F_0 (identity for reshare).
            // This is correct per spec §5: the old Y is preserved; the reshare
            // output's y is the zero-aggregate constant term.
            assert!(
                epoch_key.is_zero(),
                "reshare aggregate F_0 must be 𝒪 (Y invariant — zero-secret reshare)"
            );
            assert!(
                withholders.is_empty(),
                "no withholders when all dealers post valid"
            );
        }
        EpochShieldOutcome::Transparent { reason } => {
            panic!("expected Active, got Transparent({reason:?})");
        }
    }
}

#[test]
fn run_epoch_shield_reshare_noshow_yields_withholders_and_slash() {
    // End-to-end: reshare where one validator (addr(3)) is a no-show dealer.
    // Expected: run_epoch_shield → Active { withholders = {addr(3)} }
    //           apply_withholding_slashes → addr(3) slashed 10% + jailed.
    //
    // Use 3 validators with 4 shares each (W = 12).
    // Quorum for reshare = ⌈2/3 · 12⌉ = 8. Two posting dealers have weight 8 → quorum met.
    let vset = test_vset_n(3); // W = 12
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_eks(&committee);

    // Genesis DKG to establish Y.
    let tau_dkg = test_tau(1);
    let posted_dkg = test_posted_all_valid(&committee, &eks, &tau_dkg);
    let genesis_outcome = run_epoch_shield(None, &vset, &posted_dkg, &eks, &tau_dkg);
    let prev_y = match genesis_outcome {
        EpochShieldOutcome::Active { epoch_key, .. } => epoch_key,
        other => panic!("genesis DKG failed: {other:?}"),
    };

    // Reshare: only 2 of 3 dealers post (addr(3) is a no-show).
    let tau_reshare = b"epoch:1:to:2:reshare".to_vec();
    let addrs: Vec<Address> = committee.iter().map(|(a, _)| *a).collect();
    let noshow_addr = addrs[2]; // third validator (addr(3)) withholds

    let mut reshare_posted: BTreeMap<Address, (PvssTranscript, bool)> = BTreeMap::new();
    for (i, addr_i) in addrs.iter().enumerate().take(2) {
        // Only the first two dealers post.
        use lemma_mempool::shield::pss::deal_reshare;
        let tr = deal_reshare(
            tau_reshare.clone(),
            &committee,
            &eks,
            &mut seeded_rng(300 + i as u64),
        )
        .unwrap();
        reshare_posted.insert(*addr_i, (tr, true));
    }

    let outcome = run_epoch_shield(Some(prev_y), &vset, &reshare_posted, &eks, &tau_reshare);

    let withholders = match outcome {
        EpochShieldOutcome::Active {
            epoch_key: _,
            withholders,
        } => {
            assert!(
                withholders.contains(&noshow_addr),
                "no-show dealer must appear in withholders"
            );
            assert_eq!(withholders.len(), 1, "only one withholder expected");
            withholders
        }
        EpochShieldOutcome::Transparent { reason } => {
            panic!("expected Active (quorum met by 2 dealers), got Transparent({reason:?})");
        }
    };

    // Apply slashes: the withholder must be slashed 10% and jailed.
    let active_drop: u128 = 4 * lemma_mempool::shield::params::WEIGHT_GRANULARITY_DROP;
    let mut validators = BTreeMap::from([(noshow_addr, test_validator(noshow_addr, active_drop))]);
    let powers = BTreeMap::from([(noshow_addr, Amount::from_drop(active_drop))]);
    let block_time = 2_000_000u64;

    let slash_result =
        apply_withholding_slashes(&mut validators, &withholders, &powers, 200, block_time);
    assert!(
        slash_result.is_ok(),
        "apply_withholding_slashes must succeed: {slash_result:?}"
    );

    let slash_outcome = slash_result.unwrap();
    assert_eq!(slash_outcome.slashed_count, 1, "one validator slashed");
    let expected_burn = active_drop / 10; // 10%
    assert_eq!(
        slash_outcome.total_burned.as_drop(),
        expected_burn,
        "withholder burned 10% of active stake"
    );

    let v = &validators[&noshow_addr];
    assert_eq!(
        v.self_stake.active.as_drop(),
        active_drop - expected_burn,
        "withholder active stake reduced by 10%"
    );
    assert_eq!(
        v.jailed_until,
        Some(block_time + SHARE_WITHHOLDING_JAIL_DURATION_SECONDS),
        "withholder jailed for SHARE_WITHHOLDING_JAIL_DURATION_SECONDS"
    );
    assert!(!v.tombstoned, "withholder must NOT be tombstoned");
}

#[test]
fn run_epoch_shield_quorum_not_reached_returns_transparent() {
    // Only 1 dealer posts (weight 4) → quorum ⌈2/3·W⌉ = ⌈2/3·12⌉ = 8 not reached.
    let vset = test_vset_n(3); // W = 3×4 = 12
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_eks(&committee);
    let tau = test_tau(1);

    // Post only the first dealer.
    let first_addr = *committee.iter().next().unwrap().0;
    let tr = deal(tau.clone(), &committee, &eks, &mut seeded_rng(100)).unwrap();
    let mut posted = BTreeMap::new();
    posted.insert(first_addr, (tr, true));

    let outcome = run_epoch_shield(None, &vset, &posted, &eks, &tau);

    match outcome {
        EpochShieldOutcome::Transparent {
            reason: TransparentReason::QuorumNotReached { have, need },
        } => {
            assert!(have < need, "have={have} must be < need={need}");
        }
        other => panic!("expected Transparent(QuorumNotReached), got {other:?}"),
    }
}

#[test]
fn run_epoch_shield_committee_too_small_returns_transparent() {
    // A ValidatorSet with 1 validator → W = 4 (minimum), but let's use 0 validators
    // to trigger CommitteeTooSmall. We build an empty ValidatorSet directly.
    let empty_vset = ValidatorSet {
        epoch: 1,
        members: BTreeMap::new(),
        total_power: Amount::zero(),
    };
    let tau = test_tau(1);
    let posted = BTreeMap::new();
    let eks = BTreeMap::new();

    let outcome = run_epoch_shield(None, &empty_vset, &posted, &eks, &tau);

    match outcome {
        EpochShieldOutcome::Transparent {
            reason: TransparentReason::CommitteeTooSmall { have },
        } => {
            assert_eq!(have, 0, "empty committee has W=0");
        }
        other => panic!("expected Transparent(CommitteeTooSmall), got {other:?}"),
    }
}

#[test]
fn run_epoch_shield_is_idempotent() {
    // Same inputs → same outcome (determinism check).
    let vset = test_vset_n(3);
    let committee = ShieldCommittee::from_validator_set(&vset).unwrap();
    let (eks, _) = test_eks(&committee);
    let tau = test_tau(1);
    let posted = test_posted_all_valid(&committee, &eks, &tau);

    let outcome_a = run_epoch_shield(None, &vset, &posted, &eks, &tau);
    let outcome_b = run_epoch_shield(None, &vset, &posted, &eks, &tau);

    assert_eq!(
        outcome_a, outcome_b,
        "run_epoch_shield must be deterministic"
    );
}

// ── apply_withholding_slashes tests ──────────────────────────────────────────

#[test]
fn apply_withholding_slashes_slashes_and_jails_withholder() {
    let a = addr(1);
    let active_drop: u128 = 1_000_000 * lemma_core::DROPS_PER_LEM; // 1M LEM
    let mut validators = BTreeMap::from([(a, test_validator(a, active_drop))]);
    let mut withholders = BTreeSet::new();
    withholders.insert(a);
    let powers = BTreeMap::from([(a, Amount::from_drop(active_drop))]);
    let infraction_height = 100u64;
    let block_time = 1_000_000u64;

    let result = apply_withholding_slashes(
        &mut validators,
        &withholders,
        &powers,
        infraction_height,
        block_time,
    );

    assert!(
        result.is_ok(),
        "apply_withholding_slashes must succeed: {result:?}"
    );
    let outcome = result.unwrap();
    assert_eq!(outcome.slashed_count, 1, "one validator slashed");

    let v = &validators[&a];

    // Slash: 10% of 1M LEM = 100K LEM burned.
    let expected_burned_drop: u128 = active_drop / 10; // 10% = 1000 bps / 10000
    assert_eq!(
        outcome.total_burned.as_drop(),
        expected_burned_drop,
        "total_burned must be 10% of active stake"
    );
    // Active stake reduced by 10%.
    assert_eq!(
        v.self_stake.active.as_drop(),
        active_drop - expected_burned_drop,
        "active stake must be reduced by 10%"
    );

    // Jail: jailed_until must be set to block_time + SHARE_WITHHOLDING_JAIL_DURATION_SECONDS.
    let expected_until = block_time + SHARE_WITHHOLDING_JAIL_DURATION_SECONDS;
    assert_eq!(
        v.jailed_until,
        Some(expected_until),
        "validator must be jailed until block_time + SHARE_WITHHOLDING_JAIL_DURATION_SECONDS"
    );

    // NOT tombstoned — share-withholding is a liveness fault, not a safety fault.
    assert!(
        !v.tombstoned,
        "withholder must NOT be tombstoned (finite jail only)"
    );
}

#[test]
fn apply_withholding_slashes_honest_but_unselected_not_slashed() {
    // An honest validator that is NOT in the withholders set must be untouched.
    let a = addr(1);
    let b = addr(2);
    let active_drop: u128 = 1_000_000 * lemma_core::DROPS_PER_LEM;
    let mut validators = BTreeMap::from([
        (a, test_validator(a, active_drop)),
        (b, test_validator(b, active_drop)),
    ]);
    // Only `a` is a withholder; `b` is honest.
    let mut withholders = BTreeSet::new();
    withholders.insert(a);
    let powers = BTreeMap::from([
        (a, Amount::from_drop(active_drop)),
        (b, Amount::from_drop(active_drop)),
    ]);

    let result = apply_withholding_slashes(&mut validators, &withholders, &powers, 100, 1_000_000);

    assert!(result.is_ok());
    let outcome = result.unwrap();
    assert_eq!(outcome.slashed_count, 1, "only the withholder is slashed");

    // `b` must be completely untouched.
    let vb = &validators[&b];
    assert_eq!(
        vb.self_stake.active.as_drop(),
        active_drop,
        "honest validator stake unchanged"
    );
    assert!(
        vb.jailed_until.is_none(),
        "honest validator must not be jailed"
    );
    assert!(!vb.tombstoned, "honest validator must not be tombstoned");
}

#[test]
fn apply_withholding_slashes_returns_total_burned() {
    // Two withholders with different stakes → total_burned = sum of both burns.
    let a = addr(1);
    let b = addr(2);
    let active_a: u128 = 2_000_000 * lemma_core::DROPS_PER_LEM; // 2M LEM
    let active_b: u128 = 4_000_000 * lemma_core::DROPS_PER_LEM; // 4M LEM
    let mut validators = BTreeMap::from([
        (a, test_validator(a, active_a)),
        (b, test_validator(b, active_b)),
    ]);
    let mut withholders = BTreeSet::new();
    withholders.insert(a);
    withholders.insert(b);
    let powers = BTreeMap::from([
        (a, Amount::from_drop(active_a)),
        (b, Amount::from_drop(active_b)),
    ]);

    let result = apply_withholding_slashes(&mut validators, &withholders, &powers, 100, 1_000_000);

    assert!(result.is_ok());
    let outcome = result.unwrap();
    assert_eq!(outcome.slashed_count, 2, "both withholders slashed");

    // 10% of 2M + 10% of 4M = 200K + 400K = 600K LEM.
    let expected_burned = active_a / 10 + active_b / 10;
    assert_eq!(
        outcome.total_burned.as_drop(),
        expected_burned,
        "total_burned must be sum of per-validator 10% burns"
    );
}

#[test]
fn apply_withholding_slashes_returns_error_for_missing_validator() {
    // A withholder address not in the validators map → ValidatorNotFound.
    let a = addr(1);
    let missing = addr(99); // not in validators
    let active_drop: u128 = 1_000_000 * lemma_core::DROPS_PER_LEM;
    let mut validators = BTreeMap::from([(a, test_validator(a, active_drop))]);
    let mut withholders = BTreeSet::new();
    withholders.insert(missing);
    let powers = BTreeMap::new();

    let result = apply_withholding_slashes(&mut validators, &withholders, &powers, 100, 1_000_000);

    match result {
        Err(ShieldOrchestratorError::ValidatorNotFound { address }) => {
            assert_eq!(address, missing, "error must name the missing address");
        }
        other => panic!("expected ValidatorNotFound, got {other:?}"),
    }
}
