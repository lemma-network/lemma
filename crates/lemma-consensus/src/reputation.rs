//! # Reputation scores and leader swap table (spec §6, spec 13 §4.3)
//!
//! `ReputationScores` accumulates per-authority scores from committed sub-DAGs
//! (D9a: each block appearing in [`Commit::blocks`] earns its author one point).
//! `LeaderSwapTable` uses those scores to swap persistently-failing leaders out
//! for high-reputation alternates — improving liveness without affecting safety.
//!
//! ## Determinism (AGENTS.md §7.1)
//!
//! - Scores stored in `BTreeMap<Address, u64>` — canonically sorted by address.
//! - Sort key `(score ASC, Address ASC)` is a total order — identical on every node.
//! - Integer-only arithmetic — no floats, no `HashMap`.
//!
//! ## Liveness-only, never safety (spec 13 §4.3)
//!
//! The swap table changes ONLY who leads a round — never the 2f+1 quorum
//! threshold. Every swap target is a current committee member.
//!
//! ## Usage (Batch B `epoch::transition`)
//!
//! ```text
//! 1. ReputationScores::from_commits(epoch_commits)         — score the epoch.
//! 2. LeaderSwapTable::from_scores(&scores, &vset, f)       — build the swap table.
//! 3. LeaderSchedule::with_swap(vset, offset, table)        — wire into the schedule.
//! ```
//!
//! Steps 1 and 2 are called by the epoch-boundary orchestration in
//! `epoch::transition` (Batch B, spec 13 §4.3). This module owns the algorithm,
//! not the trigger.
//!
//! [`LeaderSchedule`]: crate::pulse::leader::LeaderSchedule

use std::collections::BTreeMap;

use lemma_core::{address::Address, validator_set::ValidatorSet};

use crate::commit::Commit;

// ── ReputationScores ─────────────────────────────────────────────────────────

/// Per-authority reputation scores accumulated from committed sub-DAGs.
///
/// **Scoring (D9a)**: each block in [`Commit::blocks`] earns its author one
/// point. A block that survived into a committed sub-DAG was voted and certified
/// by 2f+1 peers — a proxy for "this authority contributed positively".
/// Using only [`Commit`] data (not the full DAG) keeps scoring cheap and
/// verifiable with the same data handed to Flux.
///
/// **Window (D9b)**: `from_commits` accepts a caller-supplied slice — the
/// epoch-boundary orchestration decides the window (typically all commits in
/// the current epoch). No window is hard-coded in this module.
///
/// **Determinism**: scores in a `BTreeMap<Address, u64>`, canonically sorted
/// by address. No floats, no `HashMap`. See AGENTS.md §7.1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReputationScores {
    /// Per-authority score: number of committed blocks authored in the window.
    scores: BTreeMap<Address, u64>,
}

impl ReputationScores {
    /// Create an empty (zero) score set.
    ///
    /// Used for the first epoch (no prior commits) and as the neutral baseline
    /// when `from_commits` is called with an empty slice.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            scores: BTreeMap::new(),
        }
    }

    /// Compute reputation scores from a committed-sub-DAG window.
    ///
    /// For each block ref in `commit.blocks`, the block's author receives one
    /// point. The leader block is included in `blocks` (linearizer marks it
    /// first during DFS), so leaders are scored for their own contribution.
    ///
    /// `commits` is the caller-determined window (D9b). Pass all commits in the
    /// current epoch for epoch-boundary recompute, or any subset for testing.
    ///
    /// # Determinism
    ///
    /// Pure function: same input slice → same `BTreeMap` output on every node.
    ///
    /// Uses `saturating_add` to prevent theoretical overflow (u64::MAX ≈
    /// 1.8×10¹⁹ blocks — unreachable in practice; defence-in-depth against
    /// adversarial input per AGENTS §7.2, no panics in the consensus path).
    #[must_use]
    pub fn from_commits(commits: &[Commit]) -> Self {
        let mut scores: BTreeMap<Address, u64> = BTreeMap::new();
        for commit in commits {
            for block_ref in &commit.blocks {
                let entry = scores.entry(block_ref.author).or_insert(0);
                *entry = entry.saturating_add(1);
            }
        }
        Self { scores }
    }

    /// Return the reputation score for `author`, or 0 if not present.
    #[must_use]
    pub fn score(&self, author: &Address) -> u64 {
        self.scores.get(author).copied().unwrap_or(0)
    }

    /// Return `true` if no scores have been accumulated.
    ///
    /// True for the first epoch (genesis) before any commits exist, or when
    /// `from_commits` is called with an empty slice.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }
}

// ── LeaderSwapTable ──────────────────────────────────────────────────────────

/// Maps a base round-robin leader candidate to the actual leader for that round.
///
/// **Swap policy (D9c)**: bottom-`swap_count` members (by score ASC, tie-break
/// Address ASC) are swapped for top-`swap_count` members (score DESC, same
/// tie-break). `swap_count` is typically `f = (n−1) / 3`.
///
/// **Equal-score guard**: a pair is only swapped when the bad member's score is
/// strictly less than the good member's. Equal scores mean no evidence of
/// persistent failure (spec 13 §4.3) — no swap is inserted.
///
/// **No-self-swap invariant**: `swap_count` is capped at `n / 2`, keeping the
/// bad and good sets disjoint (proof: overlap requires 2·`actual` > n).
///
/// **Liveness-only, never safety** (spec 13 §4.3): changes only who proposes,
/// never the 2f+1 quorum. Every swap target is a committee member.
///
/// **Determinism**: `BTreeMap<Address, Address>` with sort key `(score, Address)`
/// — total order — identical result on every honest node for the same epoch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaderSwapTable {
    /// bad → good: authority with low reputation → its high-reputation replacement.
    ///
    /// Empty for the identity table (no swaps); see [`identity`].
    ///
    /// [`identity`]: LeaderSwapTable::identity
    swaps: BTreeMap<Address, Address>,
}

impl LeaderSwapTable {
    /// Create an identity swap table (no authority is swapped).
    ///
    /// Used for the first epoch (no commit data yet) and whenever
    /// `from_scores` finds no swaps warranted (e.g. all scores equal).
    #[must_use]
    pub fn identity() -> Self {
        Self {
            swaps: BTreeMap::new(),
        }
    }

    /// Build a swap table from reputation scores and the current committee.
    ///
    /// Sort key `(score ASC, Address ASC)` partitions the committee into:
    /// - **bad**  = bottom `swap_count` (lowest scores — candidates most
    ///   likely to exhibit persistent failure);
    /// - **good** = top `swap_count` (highest scores — preferred alternates).
    ///
    /// Only `(bad, good)` pairs where `bad.score < good.score` produce a swap
    /// entry — equal scores mean no information about failure; the pair is
    /// skipped (no swap). `swap_count` is capped at `n / 2` so bad and good
    /// sets are always disjoint.
    ///
    /// Returns [`identity`] when:
    /// - `swap_count == 0` or `committee.is_empty()`,
    /// - effective count after capping is 0 (single-member committee),
    /// - or all scores are equal (no evidence of persistent failure).
    ///
    /// # Determinism
    ///
    /// Pure function: same `scores` + `committee` + `swap_count`
    /// → same `BTreeMap` output on every node (AGENTS §7.1).
    ///
    /// [`identity`]: LeaderSwapTable::identity
    #[must_use]
    pub fn from_scores(
        scores: &ReputationScores,
        committee: &ValidatorSet,
        swap_count: usize,
    ) -> Self {
        if swap_count == 0 || committee.is_empty() {
            return Self::identity();
        }

        // Collect committee addresses (BTreeMap gives them Address-sorted, but we
        // re-sort below by (score, address) for the swap split).
        let mut members: Vec<Address> = committee.members.keys().copied().collect();
        let n = members.len();

        // Cap at n/2 — guarantees bad and good sets are disjoint (no self-swap).
        // Proof of disjoint: overlap would require index i s.t. i < actual AND
        // i ≥ n−actual, i.e. 2·actual > n — contradicts actual ≤ n/2.
        let actual = swap_count.min(n / 2);
        if actual == 0 {
            return Self::identity();
        }

        // Sort by (score ASC, Address ASC) — total order, deterministic across nodes.
        // Front = low reputation (bad candidates); Back = high reputation (good).
        members.sort_by_key(|addr| (scores.score(addr), *addr));

        // bad  = members[0 .. actual]          (lowest scores)
        // good = members[n−actual .. n]         (highest scores)
        let bad = &members[..actual];
        let good = &members[n - actual..];

        let mut swaps: BTreeMap<Address, Address> = BTreeMap::new();
        // Cross-pairing: worst bad → best good, second-worst → second-best, etc.
        // (D9f) This maximises liveness improvement: the least-reliable leader
        // is replaced by the most-reliable alternate. Mirrors Mysticeti's
        // LeaderSwapTable design (adapted in-tree, AGENTS §9.2).
        for (b, g) in bad.iter().zip(good.iter().rev()) {
            // Only insert a swap when there is evidence of persistent failure.
            // Equal scores → no information → no swap (spec 13 §4.3).
            if scores.score(b) < scores.score(g) {
                swaps.insert(*b, *g);
            }
        }

        Self { swaps }
    }

    /// Map `candidate` to the actual leader for `round`.
    ///
    /// Returns the high-reputation replacement when `candidate` is in the swap
    /// table, or `candidate` itself when it is not.
    ///
    /// `_round` is kept for forward-compatibility with per-round swap variants.
    /// The v1 policy is epoch-fixed: the same table applies to every round.
    #[must_use]
    pub fn swap(&self, candidate: Address, _round: u64) -> Address {
        self.swaps.get(&candidate).copied().unwrap_or(candidate)
    }

    /// Return `true` if this is the identity table (no authorities are swapped).
    #[must_use]
    pub fn is_identity(&self) -> bool {
        self.swaps.is_empty()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
