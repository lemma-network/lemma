//! # SurgeDriver — the Surge dissemination loop (spec §11, Architecture Y)
//!
//! `SurgeDriver` is the **per-epoch orchestrator** that wires together all the
//! previously-built pieces of the consensus crate into a single event-driven loop:
//!
//! ```text
//! on_block(block, sig_ok)
//!   → dag.insert                     (rule-check; may suspend/equivocate)
//!   → if Accepted → clock.add_block  (2f+1 round advancement)
//!   → if Some(new_round)             (signal: "time to propose at new_round")
//!   → try_decide(last_decided, …)    (gapless committed-leader prefix)
//!   → linearizer.commit_leaders(…)  (Commit records with chained digests)
//!   → return SurgeOutput             (new_round, commits, equivocations, …)
//! ```
//!
//! ## What lives here vs elsewhere
//!
//! | Concern | Lives in |
//! |---------|----------|
//! | DAG validity rules (§3) | `dag::graph::Dag::insert` |
//! | Round advancement (§2.3) | `dag::threshold_clock::ThresholdClock` |
//! | Commit rule + gapless prefix (§4) | `pulse::committer::try_decide` |
//! | Sub-DAG linearization (§5) | `pulse::linearizer::Linearizer` |
//! | Leader election (§6) | `pulse::leader::LeaderSchedule` |
//! | **Wiring all the above** | **`SurgeDriver`** (this file) |
//!
//! ## Network integration point (H1 / H2 debt closure)
//!
//! `on_block` is the single entry point for blocks arriving from peers.
//! The network layer (`lemma-network`) is responsible for:
//! - Verifying the hybrid Ed25519 + ML-DSA-65 signature and passing
//!   `sig_ok: bool` to `on_block` (decisions-log "Decision 4a").
//! - Gossipping `DagBlock`s via a `DagProposal(DagBlock)` message variant
//!   (debt H1, now unblocked: `DagBlock` ships in Step 3).
//! - The separate `DagVote` gossip message (debt H2) is **not needed**:
//!   Decision 3b piggybacks `CommitVote` inside `DagBlock.commit_votes`, so
//!   votes travel with their author's block — no standalone vote message.
//!
//! ## Block production trigger
//!
//! When `on_block` returns `SurgeOutput { new_round: Some(r), .. }`, the caller
//! (node binary or integration harness) should build and broadcast a new
//! `DagBlock` at round `r` referencing the 2f+1 quorum it just observed
//! (spec §2.3: "propose → observe 2f+1 → advance → propose").
//! `SurgeDriver` does **not** build blocks itself — that requires access to the
//! transaction mempool, validator keys, and network I/O, none of which belong
//! inside consensus.
//!
//! ## Epoch lifecycle
//!
//! Construct a fresh `SurgeDriver` for each epoch via [`SurgeDriver::new`].
//! On epoch transition, call [`SurgeDriver::advance_epoch`] which:
//! - Rebuilds `ThresholdClock` at the current DAG round.
//! - Rebuilds `LeaderSchedule` from the new `ValidatorSet`.
//! - Returns buffered next-epoch blocks for re-insertion via `on_block`.
//!
//! [`SurgeDriver::new`]: SurgeDriver::new
//! [`SurgeDriver::advance_epoch`]: SurgeDriver::advance_epoch

use lemma_core::validator_set::ValidatorSet;

use crate::{
    commit::Commit,
    dag::{
        block::{DagBlock, Slot},
        graph::{Dag, InsertOutcome},
        threshold_clock::ThresholdClock,
    },
    error::ConsensusError,
    pulse::{committer::try_decide, leader::LeaderSchedule, linearizer::Linearizer},
};

// ── SurgeOutput ───────────────────────────────────────────────────────────────

/// The result of processing one block through the Surge loop.
///
/// Returned by [`SurgeDriver::on_block`]. The caller inspects this to:
/// - **Propose** a new block if `new_round` is `Some(r)` (spec §2.3).
/// - **Submit to Flux** the commits in `commits` (passed to `lemma-vm`).
/// - **Emit slashing evidence** for each entry in `equivocations`
///   (`docs/13-VALIDATOR_EPOCH_SPEC.md §5.2`).
/// - **Handle `outcome`** for network-layer decisions (re-request suspended
///   ancestors, log drops, etc.).
#[derive(Debug, Clone)]
pub struct SurgeOutput {
    /// How the inserted block was handled by the DAG.
    ///
    /// Callers use this for network decisions:
    /// - `Accepted` → block is in the DAG; normal flow.
    /// - `Suspended` → one or more ancestors missing; trigger sync.
    /// - `NextEpochBuffered` → block buffered for the coming epoch.
    /// - `Dropped` → buffer full; caller may re-submit later.
    /// - `Equivocation { .. }` → slashing evidence required; also appears
    ///   in `equivocations`.
    pub outcome: InsertOutcome,

    /// Non-`None` when this block's insertion caused the threshold clock to
    /// advance to a new round.
    ///
    /// When `Some(r)`, the caller should build and broadcast a `DagBlock` at
    /// round `r`, referencing the 2f+1 quorum that triggered the advance
    /// (spec §2.3 Surge loop). `None` means the clock did not advance this
    /// call.
    pub new_round: Option<u64>,

    /// Commits produced by the Pulse commit pipeline after this insertion.
    ///
    /// An empty `Vec` is normal — most block insertions don't immediately
    /// decide a new leader. When non-empty, forward each `Commit` to Flux
    /// (`lemma-vm`) in order for execution and `BlockHeader` production.
    pub commits: Vec<Commit>,

    /// Equivocations detected during this insertion (including cascade
    /// unsuspend) that require slashing evidence.
    ///
    /// Each entry mirrors the `InsertOutcome::Equivocation { author, round,
    /// first, second }` shape. Callers MUST construct and broadcast
    /// `DoubleSignEvidence` for each (`docs/13-VALIDATOR_EPOCH_SPEC.md §5.2`).
    pub equivocations: Vec<InsertOutcome>,
}

// ── SurgeDriver ───────────────────────────────────────────────────────────────

/// Per-epoch consensus orchestrator: wires `Dag`, `ThresholdClock`,
/// `LeaderSchedule`, and `Linearizer` into the Surge dissemination loop.
///
/// ## Ownership
///
/// `SurgeDriver` owns all per-epoch consensus state:
/// - [`Dag`] — the local DAG for the current epoch.
/// - [`ThresholdClock`] — tracks 2f+1 round advancement.
/// - [`LeaderSchedule`] — deterministic leader election per round.
/// - [`Linearizer`] — stateful commit-chain producer.
/// - `last_decided` — the most recently committed leader slot (exclusive
///   lower bound for the next [`try_decide`] call).
///
/// ## Determinism
///
/// Given the same set of blocks in any insertion order, `SurgeDriver`
/// produces the **identical** `commits` output on all honest nodes
/// (spec §12, AGENTS.md §7.1). The commit pipeline (`try_decide` →
/// `commit_leaders`) is a pure function of the accumulated DAG state;
/// `SurgeDriver` only adds the stateful wiring.
///
/// [`Dag`]: crate::dag::graph::Dag
/// [`ThresholdClock`]: crate::dag::threshold_clock::ThresholdClock
/// [`LeaderSchedule`]: crate::pulse::leader::LeaderSchedule
/// [`Linearizer`]: crate::pulse::linearizer::Linearizer
#[derive(Debug)]
pub struct SurgeDriver {
    /// The local DAG for the current epoch (spec §2–3).
    dag: Dag,
    /// Threshold clock tracking 2f+1 round advancement (spec §2.3).
    clock: ThresholdClock,
    /// Deterministic leader schedule for the current epoch (spec §6).
    schedule: LeaderSchedule,
    /// Stateful commit-chain linearizer (spec §5).
    linearizer: Linearizer,
    /// The most recently committed leader slot. Used as the exclusive lower
    /// bound for each `try_decide` call. Starts at the sentinel genesis slot
    /// (round 0, author = genesis sentinel), which lies below all real leaders.
    last_decided: Slot,
    /// Current validator set (needed for clock, commit rule, linearizer).
    vset: ValidatorSet,
}

impl SurgeDriver {
    /// Create a fresh driver for the given epoch.
    ///
    /// Constructs a new empty `Dag`, a `ThresholdClock` starting at round 0,
    /// and a `LeaderSchedule` from `vset`.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::EmptyCommittee`] if `vset` has no members
    /// (protocol invariant: all valid epochs have ≥ 1 validator; Decision 6c).
    pub fn new(vset: ValidatorSet) -> Result<Self, ConsensusError> {
        let epoch = vset.epoch;
        let total_power = vset.total_power;
        let schedule = LeaderSchedule::new(&vset)?;
        Ok(Self {
            dag: Dag::new(epoch),
            clock: ThresholdClock::new(total_power),
            schedule,
            linearizer: Linearizer::new(),
            last_decided: genesis_sentinel(),
            vset,
        })
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// The local DAG (read-only access for tests and node diagnostics).
    #[must_use]
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    /// The current ThresholdClock round.
    #[must_use]
    pub fn clock_round(&self) -> u64 {
        self.clock.round()
    }

    /// The most recently committed leader slot.
    ///
    /// Starts at the genesis sentinel (round 0). Advances as commits are
    /// produced by the Pulse pipeline.
    #[must_use]
    pub fn last_decided(&self) -> Slot {
        self.last_decided
    }

    /// The index that will be assigned to the next commit.
    #[must_use]
    pub fn next_commit_index(&self) -> u64 {
        self.linearizer.next_index()
    }

    // ── Core event ────────────────────────────────────────────────────────────

    /// Process one incoming block through the full Surge loop (Architecture Y).
    ///
    /// Steps (spec §11):
    /// 1. `dag.insert(block, &vset, sig_ok)` — rule-check and accept/suspend/equivocate.
    /// 2. Drain any equivocations surfaced during the cascade unsuspend.
    /// 3. If `Accepted`: feed to `clock.add_block` → detect round advancement.
    /// 4. Run `try_decide(last_decided, …)` → gapless committed-leader prefix.
    /// 5. Run `linearizer.commit_leaders(…)` → `Vec<Commit>`.
    /// 6. Advance `last_decided` to the highest decided leader slot.
    /// 7. Return [`SurgeOutput`].
    ///
    /// # Design notes
    ///
    /// - The commit pipeline (steps 4–5) runs **on every `Accepted` block**,
    ///   not only when the clock advances. A lagging block may complete a
    ///   decision-round quorum without triggering a clock tick — the pipeline
    ///   must still run to catch newly decidable leaders.
    /// - Equivocations returned in `SurgeOutput::equivocations` include both
    ///   the inline `InsertOutcome::Equivocation` (direct insertion) and any
    ///   deferred ones from the cascade unsuspend (via `drain_equivocations`).
    ///   The caller is responsible for broadcasting slashing evidence for all
    ///   of them.
    /// - `StakeOverflow` and `ByzantineInvariantBreach` from the commit
    ///   pipeline propagate as `Err(ConsensusError)` — these are fatal and
    ///   the node should halt (AGENTS.md §7.2).
    ///
    /// # Errors
    ///
    /// - `ConsensusError::StakeOverflow` — checked-arithmetic overflow in
    ///   stake accumulation (AGENTS.md §7.4).
    /// - `ConsensusError::ByzantineInvariantBreach` — two certified leaders
    ///   at the same slot; BFT assumption violated. Node must halt + slash.
    /// - `ConsensusError::DecidedLeaderMissing` — internal invariant: a
    ///   decided leader's block vanished from the DAG. Node must halt.
    ///
    /// All other failure modes (epoch mismatch, unknown author, GC boundary,
    /// missing ancestors, equivocation) are returned as `Ok(SurgeOutput)` with
    /// the appropriate `outcome` field — they are per-block rejections, not
    /// driver-level failures.
    pub fn on_block(
        &mut self,
        block: DagBlock,
        sig_ok: bool,
    ) -> Result<SurgeOutput, ConsensusError> {
        // Step 1: Insert into the DAG (validity rules §3).
        let outcome = self.dag.insert(block.clone(), &self.vset, sig_ok)?;

        // Step 2: Drain cascade equivocations surfaced by try_unsuspend.
        let mut equivocations: Vec<InsertOutcome> = self.dag.drain_equivocations();

        // If the inline outcome is itself an equivocation, collect it too.
        if matches!(outcome, InsertOutcome::Equivocation { .. }) {
            equivocations.push(outcome.clone());
        }

        // Steps 3–6: only proceed with the commit pipeline if the block was
        // accepted (suspended / buffered / dropped blocks don't change DAG state
        // that could produce new commits; equivocated blocks are NOT inserted).
        if outcome != InsertOutcome::Accepted {
            return Ok(SurgeOutput {
                outcome,
                new_round: None,
                commits: Vec::new(),
                equivocations,
            });
        }

        // Step 3: Feed the accepted block to the threshold clock.
        // `add_block` is Ok(None) for round-mismatch; Ok(Some(r)) on advancement;
        // Err(StakeOverflow) on overflow — propagate as fatal.
        let new_round = self.clock.add_block(&block, &self.vset)?;

        // Steps 4–5: run the commit pipeline unconditionally on every accepted
        // block (not just on clock ticks — see design notes above).
        let leader_fn = self.schedule.leader_fn();
        let decided = try_decide(self.last_decided, &self.dag, &self.vset, leader_fn)?;
        let commits = self
            .linearizer
            .commit_leaders(&decided, &mut self.dag, &self.vset)?;

        // Step 6: Advance last_decided to the highest committed-or-skipped slot.
        // `decided` is in ascending round order (gapless prefix from try_decide).
        // We take the last entry regardless of Commit/Skip — both are "decided".
        if let Some(highest) = decided.last() {
            self.last_decided = Slot {
                round: highest.round(),
                author: self.schedule.elect_leader(highest.round()).author,
            };
        }

        Ok(SurgeOutput {
            outcome,
            new_round,
            commits,
            equivocations,
        })
    }

    // ── Epoch advance ─────────────────────────────────────────────────────────

    /// Advance to a new epoch, returning buffered next-epoch blocks for
    /// re-insertion by the caller.
    ///
    /// The caller should call `on_block(b, sig_ok)` for each returned block
    /// using the **new** validator set's signature verification result.
    /// Blocks that fail re-validation (author not in new committee, etc.)
    /// will be silently rejected by `on_block`.
    ///
    /// Resets:
    /// - `Dag` — replaced with a fresh empty DAG for the new epoch.
    ///   `Dag::advance_epoch` (which only drains the next-epoch buffer without
    ///   clearing accepted blocks) is NOT sufficient here: carrying stale
    ///   prior-epoch blocks would leave `highest_accepted_round()` at the old
    ///   epoch's final round, causing `ThresholdClock::at_round(stale_round, …)`
    ///   to silently drop every incoming new-epoch round-0 block (since
    ///   `b.round != clock.round`). Each epoch's DAG starts fresh at round 0.
    /// - `ThresholdClock` — reset to round 0 (new epoch starts at round 0).
    /// - `LeaderSchedule` — rebuilt from the new `ValidatorSet`.
    /// - `last_decided` — reset to genesis sentinel for the new epoch.
    /// - `Linearizer` — reset (new epoch starts a fresh commit chain).
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::EmptyCommittee`] if `new_vset` is empty.
    pub fn advance_epoch(
        &mut self,
        new_vset: ValidatorSet,
    ) -> Result<Vec<DagBlock>, ConsensusError> {
        let new_epoch = new_vset.epoch;
        let total_power = new_vset.total_power;
        let schedule = LeaderSchedule::new(&new_vset)?;

        // Drain buffered next-epoch blocks from the OLD DAG before replacing it.
        // `Dag::advance_epoch` returns them and updates the epoch counter; we
        // discard the old DAG immediately after because it contains stale
        // prior-epoch blocks (see doc above).
        let buffered = self.dag.advance_epoch(new_epoch);

        // Replace the DAG with a fresh one. New epoch starts at round 0.
        self.dag = Dag::new(new_epoch);
        // Clock at round 0 — matches the fresh DAG's starting state.
        self.clock = ThresholdClock::new(total_power);
        self.schedule = schedule;
        self.linearizer = Linearizer::new();
        self.last_decided = genesis_sentinel();
        self.vset = new_vset;

        Ok(buffered)
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Genesis sentinel slot: round 0, `Address::zero()` author.
///
/// Used as the initial `last_decided` so that `try_decide` starts scanning
/// from round `last_decided.round + 1 = 1` upward. The first wave-aligned
/// leader (`round % WAVE_LENGTH == 0`) in range is round 3 (wave 1);
/// the foundation wave (rounds 0–2) is required for strong-link ancestors
/// but its leader is never directly committed via this driver.
///
/// # Note — author field is a placeholder
///
/// `try_decide` reads **only** `last_decided.round` (committer.rs, the lower
/// bound of its iteration range). The author field is never compared.
/// `Address::zero()` is the canonical Lemma sentinel value
/// (e.g. genesis block proposer — `lemma_core::Address::zero()`).
fn genesis_sentinel() -> Slot {
    use lemma_core::address::Address;
    Slot {
        round: 0,
        author: Address::zero(),
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
