//! # Pulse commit rule — spec §4
//!
//! Decides, for each leader slot, exactly one of `Commit`, `Skip`, or
//! `Undecided`. The commit rule is a **pure function of the DAG + validator
//! set** — every honest validator computes the identical result from the same
//! blocks (`docs/07-CONSENSUS_SPEC.md §4`, §7.1).
//!
//! ## Module layout
//!
//! - **`find_supported_block`/`is_vote`/`is_certificate`/`is_blame`** (§4.2): vote/cert/blame predicates
//! - **`try_direct_decide`** (§4.3): direct commit/skip via quorum of certs or blame
//! - **`try_indirect_decide`** (§4.4): indirect commit/skip via nearest committed anchor
//! - **`try_decide`** (§4.5): driver — gapless committed prefix
//!
//! ## Leader schedule injection (Decision 6a)
//!
//! [`try_decide`] accepts `leader_of: impl Fn(u64) -> Slot` rather than
//! calling `elect_leader` directly. The commit rule is a pure function of the
//! DAG; *who* leads a round is an input. The full `elect_leader` (round-robin +
//! reputation swap, spec §6) is implemented in `pulse::leader` (Step 7) and
//! injected by the node/surge driver. In tests, a simple round-robin closure
//! suffices.
//!
//! ## Single `LeaderStatus` enum (Decision 6b)
//!
//! The spec uses two near-identical enums (`LeaderStatus` / `DecidedLeader`).
//! We use one — [`LeaderStatus`] — with `is_decided()`. The gapless driver
//! emits `Vec<LeaderStatus>` containing only `Commit | Skip` entries
//! (stops at first `Undecided`). AGENTS §2 forbids near-duplicate types.
//!
//! ## Byzantine invariant breach (Decision 6c)
//!
//! If >1 certified leader is found at the same slot (BFT assumption violated),
//! the functions return `Err(ConsensusError::ByzantineInvariantBreach)` rather
//! than `panic!`. The caller (node binary) emits slashing evidence and halts
//! gracefully. This is the one exception to the "no panic" rule
//! (AGENTS §7.2), surfaced as `Result` instead.

use lemma_core::validator_set::ValidatorSet;

use crate::{
    dag::{
        block::{DagBlock, DagBlockRef, Slot},
        graph::Dag,
    },
    error::ConsensusError,
    stake::StakeAggregator,
    WAVE_LENGTH,
};

// ── LeaderStatus ──────────────────────────────────────────────────────────────

/// The commit-rule decision for a single leader slot.
///
/// Produced by [`try_direct_decide`], [`try_indirect_decide`], and collected
/// by the gapless-prefix driver [`try_decide`].
///
/// Single enum (not split into `LeaderStatus`/`DecidedLeader`) — Decision 6b.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaderStatus {
    /// The leader's block is committed: 2f+1 stake of certificates (direct)
    /// or a certificate in an already-committed anchor's causal history
    /// (indirect). Contains the leader's block reference for sub-DAG
    /// linearisation (Step 8).
    Commit(DagBlockRef),

    /// The leader slot is skipped: 2f+1 stake of blame (direct), or no
    /// certified link to the leader from the nearest committed anchor
    /// (indirect).
    Skip(Slot),

    /// Not enough information yet — the decision round has not filled with
    /// sufficient blocks. The driver stops at the first `Undecided` to
    /// preserve the gapless prefix guarantee.
    Undecided(Slot),
}

impl LeaderStatus {
    /// Returns `true` if the status is `Commit` or `Skip` (decided).
    #[must_use]
    pub fn is_decided(&self) -> bool {
        matches!(self, Self::Commit(_) | Self::Skip(_))
    }

    /// The wave-aligned round of this leader slot.
    #[must_use]
    pub fn round(&self) -> u64 {
        match self {
            Self::Commit(r) => r.round,
            Self::Skip(s) | Self::Undecided(s) => s.round,
        }
    }
}

// ── §4.1 Wave helpers (local aliases for readability) ─────────────────────────

/// Round `L+1` of the same wave — voting round.
fn voting_round(leader: u64) -> u64 {
    leader + 1
}

/// Round `L+2` of the same wave — decision round.
fn decision_round(leader: u64) -> u64 {
    leader + 2
}

// ── §4.2 Votes, certificates, blame ──────────────────────────────────────────

/// Find the unique block at `slot` in `voter`'s direct ancestor list.
///
/// Returns `None` if the voter references **two different blocks** at the same
/// slot (equivocation) — the voter supports NEITHER in that case. This is the
/// linchpin of vote safety: a voter supports at most one block per slot
/// (`docs/07-CONSENSUS_SPEC.md §4.2`, "Mysticeti `find_supported_block`").
///
/// Only scans `voter.ancestors` (direct parents), not the transitive closure —
/// consistent with the spec sketch.
pub(crate) fn find_supported_block(slot: Slot, voter: &DagBlock) -> Option<DagBlockRef> {
    let mut found: Option<DagBlockRef> = None;
    for a in voter.ancestors.iter() {
        if a.round == slot.round && a.author == slot.author {
            match found {
                None => found = Some(*a),
                // Two different digests at same slot = equivocation → support neither.
                Some(prev) if prev.digest != a.digest => return None,
                Some(_) => {} // same digest seen again — idempotent, no-op
            }
        }
    }
    found
}

/// Returns `true` if `voter` (a round-`L+1` block) votes for `leader_ref`.
///
/// A voter votes for a leader iff the leader's block is the unique supported
/// block at the leader slot in the voter's view (§4.2). Equivocation-safe via
/// `find_supported_block`.
pub(crate) fn is_vote(voter: &DagBlock, leader_slot: Slot, leader_ref: DagBlockRef) -> bool {
    find_supported_block(leader_slot, voter) == Some(leader_ref)
}

/// Returns `true` if `decision_block` (round-`L+2`) is a certificate for the
/// leader.
///
/// A certificate = the decision block's voting-round ancestors include a **2f+1
/// stake quorum** of distinct authors that vote for the leader (§4.2).
///
/// # Errors
/// `StakeOverflow` if stake accumulation overflows `u128`.
fn is_certificate(
    decision_block: &DagBlock,
    leader_slot: Slot,
    leader_ref: DagBlockRef,
    dag: &Dag,
    vset: &ValidatorSet,
) -> Result<bool, ConsensusError> {
    let v_round = voting_round(leader_slot.round);
    let mut q = StakeAggregator::quorum(vset.total_power);

    for ancestor_ref in decision_block.ancestors_at_round(v_round) {
        let Some(voter) = dag.block(ancestor_ref) else {
            continue; // ancestor not locally available — cannot count its vote
        };
        if is_vote(voter, leader_slot, leader_ref) {
            if let Some(member) = vset.members.get(&ancestor_ref.author) {
                if q.add(ancestor_ref.author, member.power)? {
                    return Ok(true); // 2f+1 stake quorum reached
                }
            }
        }
    }
    Ok(false)
}

/// Returns `true` if `voter` (a round-`L+1` block) places **blame** on the
/// leader slot.
///
/// Blame = the voter has NO direct ancestor at the full leader slot `(round,
/// author)`. We check the full slot (round AND author) — checking only the
/// author would allow a Byzantine weak-link to a different-round block by the
/// leader's address to falsely suppress blame (spec §4.2 W4 fix).
pub(crate) fn is_blame(voter: &DagBlock, leader_slot: Slot) -> bool {
    voter
        .ancestors
        .iter()
        .all(|a| !(a.round == leader_slot.round && a.author == leader_slot.author))
}

/// Accumulate blame stake at the voting round for `leader_slot`.
///
/// Returns the `StakeAggregator` after scanning all voting-round blocks so the
/// caller can check `agg.is_reached()` (quorum) without re-allocating.
///
/// # Errors
/// `StakeOverflow` if stake accumulation overflows.
fn blame_aggregator(
    leader_slot: Slot,
    dag: &Dag,
    vset: &ValidatorSet,
) -> Result<StakeAggregator, ConsensusError> {
    let v_round = voting_round(leader_slot.round);
    let mut agg = StakeAggregator::quorum(vset.total_power);
    for voter in dag.blocks_at_round(v_round) {
        if is_blame(voter, leader_slot) {
            if let Some(member) = vset.members.get(&voter.author) {
                agg.add(voter.author, member.power)?;
            }
        }
    }
    Ok(agg)
}

// ── §4.3 Direct decision ──────────────────────────────────────────────────────

/// Attempt a direct commit or skip for `leader_slot` (spec §4.3).
///
/// Returns:
/// - `Commit(ref)` — 2f+1 stake of certificates at decision round.
/// - `Skip(slot)` — 2f+1 stake of blame at voting round.
/// - `Undecided(slot)` — insufficient information yet.
///
/// Skip-check is performed **before** commit-check (spec §4.3 ordering):
/// blame is measured at voting round which fills before decision round, so we
/// can skip without waiting for L+2. Do not reorder these checks.
///
/// # Errors
/// `StakeOverflow` or `ByzantineInvariantBreach` (>1 certified leader found).
pub(crate) fn try_direct_decide(
    leader_slot: Slot,
    dag: &Dag,
    vset: &ValidatorSet,
) -> Result<LeaderStatus, ConsensusError> {
    let d_round = decision_round(leader_slot.round);

    // Leader block — if absent the leader produced no block; fall through to
    // blame/skip path.
    let leader_ref = match dag.block_at_slot(leader_slot) {
        Some(r) => r,
        None => {
            // No leader block: blame check still valid (voters may blame correctly).
            let blame = blame_aggregator(leader_slot, dag, vset)?;
            return Ok(if blame.is_reached() {
                LeaderStatus::Skip(leader_slot)
            } else {
                LeaderStatus::Undecided(leader_slot)
            });
        }
    };

    // SKIP-CHECK FIRST (spec §4.3): voting round fills before decision round.
    let blame = blame_aggregator(leader_slot, dag, vset)?;
    if blame.is_reached() {
        return Ok(LeaderStatus::Skip(leader_slot));
    }

    // COMMIT-CHECK: scan decision-round blocks for certificates.
    // Early exit: if total decision-round stake < quorum, no certificate
    // is possible — avoid scanning individual blocks.
    let decision_agg = dag.total_stake_at(d_round, vset)?;
    if !decision_agg.is_reached() {
        return Ok(LeaderStatus::Undecided(leader_slot));
    }

    // Scan decision-round blocks for certificates.
    let mut certified: Option<DagBlockRef> = None;
    for decision_block in dag.blocks_at_round(d_round) {
        if is_certificate(decision_block, leader_slot, leader_ref, dag, vset)? {
            match certified {
                None => certified = Some(leader_ref),
                Some(prev) if prev.digest != leader_ref.digest => {
                    // Two distinct certified leaders at the same slot.
                    // BFT assumption (Byzantine < S/3) is violated — halt.
                    return Err(ConsensusError::ByzantineInvariantBreach {
                        slot_round: leader_slot.round,
                        slot_author: leader_slot.author,
                        first: prev.digest,
                        second: leader_ref.digest,
                    });
                }
                Some(_) => {} // same ref certified by multiple blocks — fine
            }
        }
    }

    Ok(match certified {
        Some(r) => LeaderStatus::Commit(r),
        None => LeaderStatus::Undecided(leader_slot),
    })
}

// ── §4.4 Indirect decision (anchor rule) ──────────────────────────────────────

/// Attempt an indirect decision via a previously-decided higher leader (spec §4.4).
///
/// `decided_above` MUST be ordered **nearest-first** (lowest decided round
/// above `leader_slot` comes first). [`try_decide`] builds its list high→low
/// then reverses before passing here.
///
/// # Safety-critical invariant — do not weaken
///
/// The **nearest committed anchor** above `leader_slot` is decisive — it either
/// certify-links the leader (Commit) or it does not (Skip). No later/farther
/// anchor is ever consulted after a committed anchor is found. The inner
/// `return LeaderStatus::Skip` MUST stay inside the anchor loop — refactoring
/// it outside would allow a farther anchor to override the nearest one, breaking
/// safety (`docs/07-CONSENSUS_SPEC.md §4.4` correctness note).
///
/// # Errors
/// `StakeOverflow` or `ByzantineInvariantBreach`.
pub(crate) fn try_indirect_decide(
    leader_slot: Slot,
    decided_above: &[LeaderStatus],
    dag: &Dag,
    vset: &ValidatorSet,
) -> Result<LeaderStatus, ConsensusError> {
    // Spec §4.4: "Anchor candidates: decided leaders at round >= leader.round + WAVE_LENGTH."
    // Filter-then-nearest: walk `decided_above` (nearest-first) and stop at the first
    // anchor that is:
    //   - A Commit at round ≥ leader + WAVE_LENGTH  → decisive (either Commit or Skip)
    //   - An Undecided                              → stop (gapless prefix)
    //   - A Skip                                   → continue to next
    //   - A Commit below the WAVE_LENGTH threshold → stop (not a valid anchor)
    //
    // C1 fix: the WAVE_LENGTH guard is applied *inside the loop*, and once a valid
    // committed anchor is found the function returns immediately — guaranteeing the
    // *nearest* committed anchor is decisive (spec §4.4 correctness note). The
    // low-round Commit breaks the loop rather than silently skipping, so a farther
    // anchor cannot be consulted after the nearest committed-but-too-low one.
    for anchor_status in decided_above {
        match anchor_status {
            LeaderStatus::Commit(anchor_ref)
                if anchor_ref.round >= leader_slot.round + WAVE_LENGTH =>
            {
                // Nearest valid committed anchor found — this one is decisive.
                let Some(anchor_block) = dag.block(anchor_ref) else {
                    // Anchor block not locally present — data has not arrived yet.
                    // Return Undecided (recoverable, like MissingAncestor) rather than
                    // Skip (permanent). A node missing the anchor block must not
                    // permanently skip a leader that a synced node would commit (W3 fix).
                    return Ok(LeaderStatus::Undecided(leader_slot));
                };

                let d_round = decision_round(leader_slot.round);
                let leader_ref = dag.block_at_slot(leader_slot);
                // None ⇒ leader has no block ⇒ no cert possible ⇒ Skip immediately.

                if let Some(lref) = leader_ref {
                    // Scan anchor's direct decision-round ancestors for a cert.
                    // A cert must be an ANCESTOR of the anchor (spec §4.4 last para).
                    // Not merely "in the causal history" — direct ancestors only.
                    let mut certified: Option<DagBlockRef> = None;
                    for cert_ref in anchor_block.ancestors_at_round(d_round) {
                        let Some(cert_block) = dag.block(cert_ref) else {
                            continue; // cert block not locally present — skip
                        };
                        if is_certificate(cert_block, leader_slot, lref, dag, vset)? {
                            match certified {
                                None => certified = Some(lref),
                                Some(prev) if prev.digest != lref.digest => {
                                    // C2 fix: two distinct certified leaders at same slot
                                    // found in the anchor's ancestry — BFT assumption
                                    // (Byzantine < S/3) violated. Node must halt + slash.
                                    return Err(ConsensusError::ByzantineInvariantBreach {
                                        slot_round: leader_slot.round,
                                        slot_author: leader_slot.author,
                                        first: prev.digest,
                                        second: lref.digest,
                                    });
                                }
                                Some(_) => {} // same ref — idempotent
                            }
                        }
                    }

                    if certified.is_some() {
                        // NEAREST COMMITTED ANCHOR COMMITS THE LEADER.
                        // DO NOT continue the loop — no farther anchor can override
                        // the nearest one (safety invariant, spec §4.4).
                        return Ok(LeaderStatus::Commit(lref));
                    }
                }

                // Nearest committed anchor found NO certified link → Skip permanently.
                // DO NOT continue the loop — nearest anchor is decisive.
                return Ok(LeaderStatus::Skip(leader_slot));
            }

            // Skip anchor: no commit from this one, but keep looking for a committed
            // anchor above. Skip is NOT the nearest committed anchor.
            LeaderStatus::Skip(_) => continue,

            // Undecided anchor: gapless prefix broken — stop.
            LeaderStatus::Undecided(_) => break,

            // Commit anchor at round < leader + WAVE_LENGTH: not a valid anchor
            // per spec §4.4. Break (do not continue) — a farther anchor must not
            // be consulted after the nearest committed-but-invalid one (C1 fix).
            LeaderStatus::Commit(_) => break,
        }
    }
    Ok(LeaderStatus::Undecided(leader_slot))
}

// ── §4.5 Decision driver ──────────────────────────────────────────────────────

/// Decide all leader slots reachable from `last_decided` and return the
/// **longest gapless prefix** of decided leaders (spec §4.5).
///
/// # Arguments
/// - `last_decided` — the most recently committed leader slot (exclusive lower
///   bound for this call).
/// - `dag` — the current local DAG.
/// - `vset` — the current validator set.
/// - `leader_of` — injected leader schedule: `round → Slot`. In production
///   this is `pulse::leader::elect_leader`; in tests a simple round-robin
///   closure suffices. Injection decouples the commit rule from the reputation
///   system (Decision 6a).
///
/// # Returns
/// `Vec<LeaderStatus>` in ascending round order. All entries are `Commit` or
/// `Skip` — the driver stops at the first `Undecided` to preserve the gapless
/// prefix guarantee. Returns `Err` only on `StakeOverflow` or
/// `ByzantineInvariantBreach`.
///
/// # Determinism
/// The driver iterates rounds in a fixed descending order, then reverses once
/// for output — no hash maps, no floating point, no `SystemTime`. Every honest
/// node that has seen the same set of blocks produces the identical result.
///
/// # Errors
/// `ConsensusError::StakeOverflow` or `ConsensusError::ByzantineInvariantBreach`.
pub fn try_decide(
    last_decided: Slot,
    dag: &Dag,
    vset: &ValidatorSet,
    leader_of: impl Fn(u64) -> Slot,
) -> Result<Vec<LeaderStatus>, ConsensusError> {
    let highest = dag.highest_accepted_round();

    // Build HIGH → LOW to have "already-decided higher leaders" available
    // for try_indirect_decide's nearest-first scan (spec §4.5 comment).
    // Need round L+2 to direct-decide L ⇒ upper bound = highest - 2.
    let mut leaders: Vec<LeaderStatus> = Vec::new();

    let lower = last_decided.round + 1;
    // Upper bound = highest - 2 (spec §4.5 line 382: "upper bound highest-2").
    // A direct decision at leader round L requires blocks at L+2 (decision round).
    // With highest = L+2, the driver can attempt direct decision at L.
    // Leaders above highest-2 lack their decision round — they are Undecided and
    // would truncate the gapless prefix immediately. Excluding them avoids adding
    // useless Undecided entries that would stop the prefix at the first emitted entry.
    // Consequence: blame/skip-only leaders (decidable via L+1 alone) at rounds
    // > highest-2 are excluded. This matches the spec (same bound) — skip-by-blame
    // is detected at voting round L+1, but the driver needs L+2 in the DAG to be
    // sure the decision round has fully arrived. Confirmed intentional (spec §4.5).
    let upper = highest.saturating_sub(2);

    if lower > upper {
        return Ok(Vec::new());
    }

    for round in (lower..=upper).rev() {
        // v1 single-leader: only wave-aligned rounds carry a leader (§4.1).
        if round % WAVE_LENGTH != 0 {
            continue;
        }

        let slot = leader_of(round);

        let status = match try_direct_decide(slot, dag, vset)? {
            s if s.is_decided() => s,
            _ => {
                // Not directly decided — try indirect via nearest already-decided
                // higher leader. `leaders` is HIGH→LOW; reverse it to get
                // nearest-first for the anchor scan (spec §4.5, C2 fix).
                //
                // SAFETY: collect is necessary — `decided_above` is a
                // filtered/reversed slice, not a raw index into `leaders`.
                let decided_above: Vec<LeaderStatus> = leaders.iter().rev().cloned().collect();
                try_indirect_decide(slot, &decided_above, dag, vset)?
            }
        };

        leaders.push(status);
    }

    // `leaders` is HIGH→LOW — reverse to ascending round order.
    leaders.reverse();

    // Emit the longest gapless decided prefix (stop at first Undecided).
    let mut out = Vec::new();
    for s in leaders {
        match s {
            LeaderStatus::Commit(_) | LeaderStatus::Skip(_) => out.push(s),
            LeaderStatus::Undecided(_) => break, // gapless guarantee
        }
    }
    Ok(out)
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
