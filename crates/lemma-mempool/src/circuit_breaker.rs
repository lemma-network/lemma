//! Load-based circuit breaker for `lemma-mempool`.
//!
//! Implements graceful degradation tiers: as the mempool fills, the set of
//! admitted transaction types narrows. This keeps the chain alive under load
//! by shedding low-priority work before the pool saturates completely.
//!
//! # Tiers
//!
//! ```text
//! Normal   (< 70%)  — all transaction types accepted
//! Busy     (70–90%) — ContractDeploy rejected (heaviest; defer, don't drop)
//! Critical (90–100%)— only Transfer, Stake, Unstake, GovernanceVote
//! Emergency(≥ 100%) — only Stake, Unstake (validator-set preservation)
//! ```
//!
//! # Tier mapping vs WHITEPAPER (honest deviation notes)
//!
//! The WHITEPAPER (`01-WHITEPAPER.md §4`) describes tiers by a *fee axis*
//! (Busy = "only txs with priority fee above threshold") and by consensus-
//! message semantics (Emergency = "only validator consensus messages"). This
//! module is a *tx-type* circuit breaker; the two deviations are documented:
//!
//! - **Busy**: WHITEPAPER uses a fee threshold; here we reject `ContractDeploy`
//!   as the "heaviest" type. Fee-based Busy filtering is enforced elsewhere
//!   via `qos.rs` (stake-weighted priority) and `pool.rs` eviction. These two
//!   mechanisms together achieve the WHITEPAPER intent.
//!
//! - **Emergency**: WHITEPAPER says "validator consensus messages only; user
//!   transactions queued". Validator *consensus* messages (DagProposal,
//!   DagVote) travel via the `lemma-network` P2P layer — they are **not**
//!   mempool transactions. The Emergency tx-type equivalent is `Stake`/`Unstake`
//!   only: these are the user-initiated operations that directly maintain the
//!   validator set and keep the network alive under consensus instability.
//!
//! # Integer arithmetic (no f64)
//!
//! Load ratio is computed as `pending_count × 100 / capacity` (integer, percent).
//! No `f64` needed — thresholds are whole-percent integers. This is simpler and
//! avoids the precision/platform concerns of floating-point comparisons.
//!
//! `capacity == 0` is guarded by returning `Emergency` immediately (safest
//! degraded state, no division by zero).
//!
//! # Determinism note (spec §1.1)
//!
//! Tier assignment is local-only — it affects admission on this node, never
//! the committed transaction order. Mempool heuristics may diverge between
//! nodes without affecting consensus (AGENTS.md §7.1).
//!
//! # References
//!
//! - `docs/11-MEMPOOL_SHIELD_SPEC.md §1` line 32 — circuit breaker spec
//! - `docs/01-WHITEPAPER.md §4` — tiered degradation table
//! - Solana/Sui outage lessons: graceful degradation > total halt

use lemma_core::transaction::TxType;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Pool load percentage at which Normal transitions to Busy.
pub const BUSY_THRESHOLD_PCT: u64 = 70;

/// Pool load percentage at which Busy transitions to Critical.
pub const CRITICAL_THRESHOLD_PCT: u64 = 90;

/// Pool load percentage at which Critical transitions to Emergency.
/// At 100% (or over-capacity) the pool is Emergency.
pub const EMERGENCY_THRESHOLD_PCT: u64 = 100;

// ── NetworkTier ───────────────────────────────────────────────────────────────

/// Load-based degradation tier for mempool admission.
///
/// Ordered from least to most restrictive: `Normal < Busy < Critical < Emergency`.
/// The `Ord` implementation allows callers to compare severity with `>=`.
///
/// `#[non_exhaustive]` allows adding intermediate tiers in future without
/// breaking downstream `match` arms (AGENTS.md §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum NetworkTier {
    /// Load < [`BUSY_THRESHOLD_PCT`]% — all transaction types admitted.
    Normal,
    /// Load [`BUSY_THRESHOLD_PCT`]–[`CRITICAL_THRESHOLD_PCT`]% —
    /// `ContractDeploy` rejected; all other types admitted.
    Busy,
    /// Load [`CRITICAL_THRESHOLD_PCT`]–[`EMERGENCY_THRESHOLD_PCT`]% —
    /// only `Transfer`, `Stake`, `Unstake`, `GovernanceVote` admitted.
    Critical,
    /// Load ≥ [`EMERGENCY_THRESHOLD_PCT`]% (or `capacity == 0`) —
    /// only `Stake` and `Unstake` admitted.
    ///
    /// Validator-set operations are the minimum required to keep the network
    /// alive. Consensus messages travel via the P2P layer (not mempool) and
    /// are unaffected by this tier.
    Emergency,
}

impl NetworkTier {
    /// Determine the current tier from pool load.
    ///
    /// Load is computed as integer percent: `pending_count × 100 / capacity`.
    /// No `f64` used — thresholds are whole-percent integers.
    ///
    /// Returns `Emergency` when `capacity == 0` (safest default — no division
    /// by zero, no transactions admitted until capacity is known).
    ///
    /// # Threshold semantics
    ///
    /// | Condition | Tier |
    /// |---|---|
    /// | `capacity == 0` | Emergency |
    /// | `load_pct < 70` | Normal |
    /// | `load_pct < 90` | Busy |
    /// | `load_pct < 100` | Critical |
    /// | `load_pct >= 100` | Emergency |
    #[must_use]
    pub fn from_load(pending_count: usize, capacity: usize) -> Self {
        if capacity == 0 {
            return Self::Emergency;
        }
        // Integer percent: avoids f64. Saturating mul guards against usize overflow
        // on hypothetical 32-bit platforms with huge pending counts.
        let load_pct = (pending_count as u64)
            .saturating_mul(100)
            .saturating_div(capacity as u64);

        match load_pct {
            l if l < BUSY_THRESHOLD_PCT => Self::Normal,
            l if l < CRITICAL_THRESHOLD_PCT => Self::Busy,
            l if l < EMERGENCY_THRESHOLD_PCT => Self::Critical,
            _ => Self::Emergency,
        }
    }

    /// Returns `true` if `tx_type` is admitted at this tier.
    ///
    /// # Tier admission table
    ///
    /// | TxType | Normal | Busy | Critical | Emergency |
    /// |---|---|---|---|---|
    /// | Transfer | ✅ | ✅ | ✅ | ❌ |
    /// | ContractCall | ✅ | ✅ | ❌ | ❌ |
    /// | ContractDeploy | ✅ | ❌ | ❌ | ❌ |
    /// | Stake | ✅ | ✅ | ✅ | ✅ |
    /// | Unstake | ✅ | ✅ | ✅ | ✅ |
    /// | GovernanceVote | ✅ | ✅ | ✅ | ❌ |
    ///
    /// See module-level docs for WHITEPAPER deviation notes.
    #[must_use]
    pub fn admits(&self, tx_type: TxType) -> bool {
        match self {
            // All types admitted — normal operation.
            Self::Normal => true,

            // Shed the heaviest type first: ContractDeploy (bytecode upload,
            // storage writes, constructor execution). Use a positive allow-list
            // so future TxType variants (TxType is #[non_exhaustive]) default-deny
            // under Busy rather than being silently admitted.
            Self::Busy => matches!(
                tx_type,
                TxType::Transfer
                    | TxType::ContractCall
                    | TxType::Stake
                    | TxType::Unstake
                    | TxType::GovernanceVote
            ),

            // Keep value flow (Transfer), validator-set ops (Stake/Unstake),
            // and on-chain governance (GovernanceVote) — shed execution.
            Self::Critical => matches!(
                tx_type,
                TxType::Transfer | TxType::Stake | TxType::Unstake | TxType::GovernanceVote
            ),

            // Minimum viable: only validator-set operations.
            // Transfer, contract ops, and governance are queued externally.
            Self::Emergency => matches!(tx_type, TxType::Stake | TxType::Unstake),
        }
    }

    /// Human-readable rejection message for a circuit-breaker rejection.
    ///
    /// Only meaningful when `!self.admits(tx_type)`. Used by [`crate::pool`] to
    /// populate `MempoolError::CircuitBreakerRejected::reason`.
    ///
    /// `pub(crate)`: callers outside `lemma-mempool` do not need this message;
    /// they receive the structured `MempoolError` variant instead.
    #[must_use]
    pub(crate) fn rejection_reason(&self) -> &'static str {
        match self {
            Self::Normal => "Normal: all transaction types accepted",
            Self::Busy => "Busy: ContractDeploy deferred; resubmit when load normalises",
            Self::Critical => "Critical: only Transfer, Stake, Unstake, GovernanceVote accepted",
            Self::Emergency => "Emergency: only Stake and Unstake accepted",
        }
    }
}

// ── Convenience function ──────────────────────────────────────────────────────

/// Returns `true` if `tx_type` is admitted given the current pool load.
///
/// Combines [`NetworkTier::from_load`] and [`NetworkTier::admits`] in one call.
/// Use this at ingress; callers that need the tier for logging/metrics should
/// call the two methods separately.
#[must_use]
pub fn is_admitted(tx_type: TxType, pending_count: usize, capacity: usize) -> bool {
    NetworkTier::from_load(pending_count, capacity).admits(tx_type)
}

#[cfg(test)]
mod tests;
