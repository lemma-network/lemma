//! # `advance_epoch` — deterministic epoch-boundary settlement (spec §4)
//!
//! Implements the 9-step `advance_epoch` routine from
//! `docs/13-VALIDATOR_EPOCH_SPEC §4.1`. Private helpers keep each concern
//! focused and independently testable.
//!
//! ## Step ownership
//!
//! | Step | Implemented here | Notes |
//! |------|-----------------|-------|
//! | 1–2 (rewards) | ✅ `rewards::compute_epoch_inflation` + `distribute_rewards` | B2 done |
//! | 3a (expire unbonding) | ✅ `settle_expired_unbonding` | Aptos bug-class guard |
//! | 3b (activate) | ✅ `activate_pending_stake` | pending_active → active |
//! | 4 (seat/remove) | ✅ `update_validator_status` | eligibility + unjail |
//! | 5 (recompute set) | ✅ `build_next_validator_set` | BTreeMap, checked power |
//! | 6 (reputation) | ✅ `recompute_leader_schedule` | D9a/b/c/f from Step 9 |
//! | 7 (config changes) | no-op | Phase 3 governance |
//! | 8 (Shield DKG) | no-op | ferveo GPL-3.0 blocked (decisions-log) |
//! | 9 (write hash) | ✅ | returned in `EpochOutput` |

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    validator::{Validator, ValidatorStatus},
    validator_set::ValidatorSet,
    Epoch,
};

use crate::{
    commit::Commit,
    pulse::leader::LeaderSchedule,
    reputation::{LeaderSwapTable, ReputationScores},
    LEADER_OFFSET,
};

use super::{EpochError, EpochOutput};

/// Advance the chain from epoch N to epoch N+1.
///
/// Runs the deterministic `advance_epoch` settlement routine
/// (`docs/13-VALIDATOR_EPOCH_SPEC §4.1`). Must never panic (AGENTS §7.2 /
/// Sui-stall lesson). All fallible operations propagate via `Result`.
///
/// ## Determinism
///
/// Pure function of its inputs — no `SystemTime`, no `HashMap`, no floats.
/// Two nodes given identical inputs produce identical `ValidatorSet(N+1)`,
/// `next_validators_hash`, and `LeaderSchedule`. The boundary block's quorum
/// commit on `next_validators_hash` IS the epoch-change proof (spec §4.4).
///
/// ## Preconditions
///
/// - `current.number + 1` must not overflow `u64` (practically unreachable).
/// - `validators` reflects the state at the end of epoch N (after all mid-epoch
///   TX processing by `lemma-vm`, which is Phase 3).
/// - `block_time` is `BlockHeader.timestamp` (consensus seconds) of the
///   boundary block — never set from `SystemTime` (AGENTS §7.1).
///
/// ## Parameters
///
/// - `current`        — the epoch being closed (epoch N).
/// - `validators`     — full validator state map; mutated in-place.
/// - `commits`        — all commits produced in epoch N (for reputation scoring).
/// - `total_supply`   — tracked total supply at the start of epoch N's boundary
///   (Drop units). Used to compute inflation for epoch N. Caller updates supply
///   using `EpochOutput.minted` and `EpochOutput.burned_remainder`.
///   **T2 decision**: priority tips are credited per-block to the block proposer
///   during execution (`lemma-vm`, Phase 3) — NOT here at epoch boundary.
/// - `block_time`     — consensus `block.time` of the boundary block (seconds).
/// - `block_height`   — height of the boundary block.
/// - `min_stake`      — minimum self-stake for eligibility (governance parameter,
///   injectable — NOT a constant; changed via governance proposal + boundary
///   application, spec §4.1 step 7).
pub fn advance_epoch(
    current: &Epoch,
    validators: &mut BTreeMap<Address, Validator>,
    commits: &[Commit],
    total_supply: Amount,
    block_time: u64,
    block_height: u64,
    min_stake: Amount,
) -> Result<EpochOutput, EpochError> {
    let next_number = current
        .number
        .checked_add(1)
        .ok_or(EpochError::EpochNumberOverflow {
            current: current.number,
        })?;

    // ── Steps 1–2: Inflation mint + validator reward distribution ─────────
    //
    // Compute epoch inflation from total supply (DB-2 stepped schedule, spec §7).
    // Distribute proportionally by epoch N's voting power (`current.validators`)
    // to all Bonded validators. Credited to `self_stake.active` BEFORE stake
    // settlement so rewards auto-compound into epoch N+1 power (Cosmos model).
    //
    // T2: priority tips are per-block proposer credits in lemma-vm (Phase 3).
    // This step handles inflation only.
    let minted = crate::rewards::compute_epoch_inflation(total_supply, current.number)
        .map_err(EpochError::Reward)?;
    let reward_outcome =
        crate::rewards::distribute_rewards(validators, &current.validators, minted)
            .map_err(EpochError::Reward)?;

    // ── Step 3a: Expire pending_inactive BEFORE committee recompute ───────
    //
    // CRITICAL ORDER — Aptos bug class (spec §4.2):
    // "settle expired pending_inactive BEFORE step 3b/5 hashes the committee.
    //  If stale pending_inactive stake leaks into the voting-power computation,
    //  two nodes compute different next_validators_hash → consensus split."
    settle_expired_unbonding(validators, block_time)?;

    // ── Step 3b: pending_active → active ─────────────────────────────────
    activate_pending_stake(validators)?;

    // ── Step 4: Seat newly eligible / remove ineligible validators ────────
    update_validator_status(validators, min_stake, block_time);

    // ── Step 5: Recompute ValidatorSet(N+1) ──────────────────────────────
    let next_vset = build_next_validator_set(next_number, validators)?;
    let next_validators_hash = next_vset.hash();

    // ── Step 6: Recompute LeaderSwapTable from ReputationScores ──────────
    // D9a/b: score = committed-block count from epoch N's commits.
    // D9c/f: cross-pairing swap, equal-score guard, f = (n-1)/3.
    let leader_schedule = recompute_leader_schedule(&next_vset, commits)?;

    // ── Steps 7–8: No-ops ─────────────────────────────────────────────────
    // Step 7: Buffered protocol/config changes — Phase 3 governance.
    // Step 8: Shield DKG/resharing — driven at the `lemma-node` orchestration
    //   layer (DB-12, 15-SHIELD_SPEC §5.3). `lemma-consensus` is crypto-free and
    //   cannot depend on `lemma-mempool` (AGENTS §8). The node observes the epoch
    //   boundary, drives `Shield::run_dkg` (genesis) or `Shield::reshare` (N→N+1)
    //   using the post-settlement `ValidatorSet(N+1)` produced by step 5 above,
    //   and feeds the resulting withholding set back as injected slashing input.
    //   In-tree Shield (S1–S8) is fully built; ferveo (GPL-3.0) was rejected
    //   (decisions-log DB-11). Node-layer orchestrator: `lemma-node::shield_orchestrator`.

    // ── Step 9: Assemble new Epoch ────────────────────────────────────────
    let epoch = Epoch {
        number: next_number,
        start_height: block_height.saturating_add(1),
        start_timestamp: block_time,
        validators: next_vset,
    };

    Ok(EpochOutput {
        epoch,
        next_validators_hash,
        leader_schedule,
        minted,
        burned_remainder: reward_outcome.burned_remainder,
    })
}

// ── Step 3a ───────────────────────────────────────────────────────────────────

/// Expire `pending_inactive` entries whose `complete_time ≤ block_time`
/// and that are not frozen (`on_hold = false`).
///
/// Expired amounts move to `stake.inactive` (withdrawable).
/// Entries that are on-hold (slash-evasion freeze, spec §2.3) or not yet
/// matured remain in `pending_inactive`.
///
/// **Must run BEFORE `activate_pending_stake` and `build_next_validator_set`.**
/// This is the Aptos bug-class guard: stale unbonding must not leak into the
/// committee power hash (spec §4.2 note).
fn settle_expired_unbonding(
    validators: &mut BTreeMap<Address, Validator>,
    block_time: u64,
) -> Result<(), EpochError> {
    for (addr, v) in validators.iter_mut() {
        let (expired, remaining) = v
            .self_stake
            .pending_inactive
            .drain(..)
            .partition::<Vec<_>, _>(|e| !e.on_hold && e.complete_time <= block_time);

        let matured = expired
            .into_iter()
            .try_fold(Amount::zero(), |acc, e| acc.checked_add(e.initial_balance))
            .map_err(|e| EpochError::SettlementOverflow {
                address: *addr,
                source: e,
            })?;

        v.self_stake.inactive = v.self_stake.inactive.checked_add(matured).map_err(|e| {
            EpochError::SettlementOverflow {
                address: *addr,
                source: e,
            }
        })?;
        v.self_stake.pending_inactive = remaining;
    }
    Ok(())
}

// ── Step 3b ───────────────────────────────────────────────────────────────────

/// Move `pending_active` stake into `active` for every validator.
///
/// This is the only place where voting power increases (pending stake becomes
/// effective). Must run AFTER `settle_expired_unbonding` to avoid stale
/// pending_inactive entries affecting the settled-active amount.
fn activate_pending_stake(validators: &mut BTreeMap<Address, Validator>) -> Result<(), EpochError> {
    for (addr, v) in validators.iter_mut() {
        let new_active = v
            .self_stake
            .active
            .checked_add(v.self_stake.pending_active)
            .map_err(|e| EpochError::SettlementOverflow {
                address: *addr,
                source: e,
            })?;
        v.self_stake.active = new_active;
        v.self_stake.pending_active = Amount::zero();
    }
    Ok(())
}

// ── Step 4 ────────────────────────────────────────────────────────────────────

/// Update validator statuses based on settled stake and elapsed jail sentences.
///
/// Transitions applied (in order per validator):
/// 1. **Unjail** if `jailed_until ≤ block_time`.
/// 2. `Unbonded` + `active ≥ min_stake` + `!tombstoned` → `Bonded` (seat).
/// 3. `Bonded` + `active < min_stake` → `Unbonding` (drop from active set).
/// 4. `Unbonding` + `active == 0` + `pending_inactive` empty → `Unbonded`.
///
/// Note: `Bonded → Unbonded` directly is **impossible** by design — the path
/// is always `Bonded → Unbonding → Unbonded`. This enforces the slash-evasion
/// rule: stake stays slashable for the full unbonding window (spec §2.1).
fn update_validator_status(
    validators: &mut BTreeMap<Address, Validator>,
    min_stake: Amount,
    block_time: u64,
) {
    for v in validators.values_mut() {
        // Unjail if the sentence has elapsed.
        if v.jailed_until.is_some_and(|t| block_time >= t) {
            v.jailed_until = None;
        }

        if v.tombstoned {
            continue; // Tombstoned: permanent ban — no status transitions.
        }

        match v.status {
            ValidatorStatus::Unbonded => {
                // Seat if stake threshold is now met.
                if v.self_stake.active >= min_stake {
                    v.status = ValidatorStatus::Bonded;
                }
            }
            ValidatorStatus::Bonded => {
                // Drop from the active set if stake fell below minimum.
                if v.self_stake.active < min_stake {
                    v.status = ValidatorStatus::Unbonding;
                }
            }
            ValidatorStatus::Unbonding => {
                // Fully unwound once no active or pending-inactive stake remains.
                if v.self_stake.active.is_zero() && v.self_stake.pending_inactive.is_empty() {
                    v.status = ValidatorStatus::Unbonded;
                }
            }
        }
    }
}

// ── Step 5 ────────────────────────────────────────────────────────────────────

/// Build `ValidatorSet(N+1)` from all currently-active validators.
///
/// Active = `Bonded`, not tombstoned, not jailed (spec §2.1, `Validator::is_active`).
/// Voting power = `self_stake.active + delegated` (`Validator::voting_power`).
///
/// Returns `Err(EmptyNextCommittee)` if no eligible validators remain —
/// the chain cannot progress and the node must seek recovery (spec §6, B4).
fn build_next_validator_set(
    epoch_number: u64,
    validators: &BTreeMap<Address, Validator>,
) -> Result<ValidatorSet, EpochError> {
    use lemma_core::error::{CoreError, ValidatorError};
    // Delegate to the canonical constructor in lemma-core (AGENTS §2.4 / §2.2).
    // One implementation shared with genesis_boot; filter, overflow handling,
    // and total_power accumulation are identical on every call path.
    ValidatorSet::from_active_validators(epoch_number, validators).map_err(|e| match e {
        CoreError::Validator(ValidatorError::PowerOverflow { address, source }) => {
            EpochError::PowerOverflow { address, source }
        }
        CoreError::Validator(ValidatorError::EmptyValidatorSet { epoch }) => {
            EpochError::EmptyNextCommittee { next_epoch: epoch }
        }
        // S-2 fix: a future CoreError variant from from_active_validators must
        // not panic the settlement path (AGENTS §7.2 / §9.3 Sui-stall lesson).
        // Map to EpochError::Internal so the node can handle it gracefully.
        other => EpochError::Internal {
            reason: format!(
                "ValidatorSet::from_active_validators returned unexpected error: {other}"
            ),
        },
    })
}

// ── Step 6 ────────────────────────────────────────────────────────────────────

/// Recompute `LeaderSwapTable` from epoch N's commits and build the
/// `LeaderSchedule` for epoch N+1 (spec §4.3, closes 07 §6).
///
/// Uses all `commits` as the scoring window (D9b: caller-supplied window).
/// `f = (n−1)/3` swap candidates (D9c). Cross-pairing (D9f).
fn recompute_leader_schedule(
    vset: &ValidatorSet,
    commits: &[Commit],
) -> Result<LeaderSchedule, EpochError> {
    let scores = ReputationScores::from_commits(commits);
    let f = vset.len().saturating_sub(1) / 3;
    let table = LeaderSwapTable::from_scores(&scores, vset, f);
    LeaderSchedule::with_swap(vset, LEADER_OFFSET, table).map_err(EpochError::ScheduleError)
}
