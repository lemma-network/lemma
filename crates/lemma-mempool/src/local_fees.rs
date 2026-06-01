//! Per-contract local fee markets for `lemma-mempool`.
//!
//! When a single contract (e.g. a popular NFT mint) generates sustained demand,
//! its transactions pay a higher base fee. All other contracts and simple
//! transfers are unaffected. One hot dApp cannot raise fees chain-wide.
//!
//! # Algorithm
//!
//! Each contract's load is tracked as a **per-block EMA** (exponentially
//! weighted moving average). Counts are updated via [`LocalFeeMarket::record`];
//! the EMA advances exactly once per block via [`LocalFeeMarket::tick`].
//!
//! ```text
//! ema_new = (ema_old × DECAY_NUM + current_block_count) / DECAY_DEN
//! ```
//!
//! At steady state (constant tx rate `x` per block), `ema → x`. With
//! `DECAY_NUM=7, DECAY_DEN=8` (α = 1/8), the half-life is ~5 blocks — fast
//! enough to react to a hot mint within seconds, slow enough to ignore
//! single-block spikes.
//!
//! Once a contract's EMA exceeds [`HIGH_DEMAND_THRESHOLD`], a **continuous**
//! surcharge applies — no threshold cliff:
//!
//! ```text
//! excess     = max(0, ema_load − HIGH_DEMAND_THRESHOLD)
//! multiplier = (SCALE_FACTOR + excess) / SCALE_FACTOR        ← continuous
//! fee        = global_base × min(multiplier, MAX_SURCHARGE_MULTIPLIER)
//! ```
//!
//! At `ema = HIGH_DEMAND_THRESHOLD`, `excess = 0` → `multiplier = 1.0×` →
//! `fee = global_base` exactly (no jump). Above threshold, fee rises smoothly
//! by `global_base / SCALE_FACTOR` per additional tx/block of EMA load.
//!
//! # Design choice: continuous (Level 1), not demand-driven auction (Level 3)
//!
//! Three designs were evaluated (see `decisions-log.md` "Local fee market"):
//! - **Level 1 (this)** — continuous EMA formula, no cliff.
//! - **Level 2** — per-contract fee-observation ring buffer + percentile. No
//!   production precedent; lagging signal; added complexity for marginal gain.
//! - **Level 3** — per-resource real-time auction at the pool layer (Solana's
//!   actual model: no precomputed floor; clearing price emerges from bids in
//!   the scheduler). Solana is a *cautionary tale* in WHITEPAPER §4.3, not a
//!   model to copy wholesale. Level 3's scheduler complexity is the class of
//!   bug that caused both the Solana and Sui stalls; it also requires
//!   `pool.rs` to exist before it can be implemented.
//!
//! **Level 1 wins on every axis for Lemma:**
//! - *User*: predictable fees ("this contract is ~2×") — consistent with the
//!   EIP-1559 choice ("simpel buat user", FULL_CONVERSATION line 97).
//! - *Determinism*: integer formula, same result on every node — trivially
//!   satisfies AGENTS.md §7.1 with no scheduler state dependency.
//! - *Network resilience*: isolates hot contracts (the stated goal, WHITEPAPER
//!   §4.3) with minimal complexity.
//!
//! # Surcharge destination: burned (not to validator)
//!
//! The surcharge raises the **base fee**, which is **100% burned** per
//! TOKENOMICS §5 / WHITEPAPER §7.4. It is NOT routed to the block proposer.
//! This is deliberate: if the surcharge went to the validator, proposers would
//! gain a direct incentive to induce or tolerate congestion — contradicting
//! Lemma's anti-MEV thesis (Shield, 11-MEMPOOL_SHIELD_SPEC). Validators still
//! benefit indirectly: more burn → stronger deflation → higher value of staked
//! and minted LEM.
//!
//! # Arithmetic (saturating, not checked)
//!
//! The surcharge is a **local fee hint** for admission and gossip ordering —
//! never used for actual token deduction (that is the execution layer's job).
//! Like [`qos::Priority`], it is a local heuristic value (spec §1.1):
//!
//! - Surcharge arithmetic uses **saturating** operations, not `checked_*`.
//!   Overflow clamps to the cap — the correct degradation (maximally expensive
//!   → maximally deterrent). Documented exception to AGENTS.md §7.4.
//! - All intermediate computation uses `u128` to prevent overflow before
//!   clamping back to `u64`.
//!
//! # Block-tick design (no `Instant`)
//!
//! Unlike [`rate_limit::RateLimiter`] which uses wall-clock `Instant` for
//! continuous refill, the fee market operates on block ticks. The caller
//! (pool.rs / node tick loop) calls [`LocalFeeMarket::tick`] exactly once per
//! block. No `Instant::now()` is used — the EMA advances one step per block
//! regardless of wall time. Fee markets are logically per-block; tying them to
//! wall clock would couple the fee signal to validator hardware speed.
//!
//! # Upstream attribution
//!
//! Borrows the *goal* from Solana's post-outage local fee markets (isolate hot
//! contracts), not the mechanism (real-time scheduler auction). See
//! `docs/01-WHITEPAPER.md §4` line 232 and `decisions-log.md`.
//!
//! # References
//!
//! - `docs/01-WHITEPAPER.md §4` (line 232) — design intent
//! - `docs/11-MEMPOOL_SHIELD_SPEC.md §1` (line 33) — canonical 1-line spec
//! - `docs/04-BUILD_GUIDE.md §2.5` — algorithm sketch
//! - `decisions-log.md` — "Local fee market = continuous EMA (Level 1), surcharge burned"
//! - [`qos`] — parallel saturating-arithmetic precedent (same §1.1 exception)

use std::collections::BTreeMap;

use lemma_core::Address;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Numerator for the per-block EMA decay formula.
///
/// ```text
/// ema_new = (ema_old × DECAY_NUM + current_block_count) / DECAY_DEN
/// ```
///
/// With `DECAY_NUM=7, DECAY_DEN=8`, the EMA retains 7/8 of its previous value
/// each block (α = 1/8 weight on the new observation). At a constant tx rate
/// `x` per block, the EMA converges to `x` (steady state = actual rate).
/// Half-life ≈ 5 blocks: a hot contract's fee reacts within ~10 seconds at
/// 2-second block times.
pub const DECAY_NUM: u64 = 7;

/// Denominator for the per-block EMA decay. Must be > [`DECAY_NUM`] and > 0.
pub const DECAY_DEN: u64 = 8;

/// EMA load (txs/block) above which a contract is considered hot and triggers
/// a fee surcharge.
///
/// A contract must sustain > 800 txs/block (EMA, not instantaneous) before
/// its transactions are surcharged. Instantaneous spikes that decay within a
/// few blocks do not trigger a surcharge.
///
/// # Derivation (data-grounded interim value, Jun 2026)
///
/// Anchored to **Solana's** `MAX_WRITABLE_ACCOUNT_UNITS / MAX_BLOCK_UNITS`
/// = 12M / 60M = **20% of block capacity** per single account (Agave v3.1.8
/// cost-model — the production threshold that survived 7+ Solana outages).
/// Mapping that 20% ratio onto Lemma's conservative v1 target (10k TPS @ ~0.4s
/// block time ⇒ ~4,000 tx/block): `20% × 4,000 = 800 tx/block`. Ethereum's
/// base-fee model (`±12.5%/block`, target = 50% gas limit) is preserved
/// separately in `calculate_base_fee` (lemma-consensus).
///
/// # ⚠️ Still a placeholder (absolute value — superseded in Phase 2)
///
/// 800 is a *more educated* interim, not a final value: it assumes a block time
/// (~0.4s) and TPS (10k) that are not yet locked, and maps a compute-unit ratio
/// onto a tx-count domain (approximate, not 1:1). Real calibration needs testnet
/// traffic. Tracked in `living-notes.md`. Compare `qos::STAKE_UNIT`.
///
/// **Phase 2 refactor**: this should become *relative to block capacity*
/// (a percentage of the adaptive block size — exactly how Solana expresses it,
/// not an absolute), so it stays meaningful as block size flexes (WHITEPAPER
/// §4.3). Blocked on `block_capacity` (Phase 2 consensus). See the "Make
/// HIGH_DEMAND_THRESHOLD relative to block capacity" action item in
/// `living-notes.md`.
pub const HIGH_DEMAND_THRESHOLD: u64 = 800;

/// Divisor in the continuous surcharge: `multiplier = (SCALE_FACTOR + excess) / SCALE_FACTOR`,
/// where `excess = max(0, ema_load − HIGH_DEMAND_THRESHOLD)`.
///
/// At `ema_load = HIGH_DEMAND_THRESHOLD + SCALE_FACTOR` (excess = SCALE_FACTOR),
/// the multiplier is 2×. Each additional `SCALE_FACTOR` txs/block of *excess*
/// (load above the threshold) adds one more multiplier unit, up to
/// [`MAX_SURCHARGE_MULTIPLIER`].
///
/// Set to `HIGH_DEMAND_THRESHOLD / 2` (= 400): the fee doubles once a contract's
/// excess load reaches half its threshold, i.e. when a single contract uses
/// ~30% of block capacity (between Solana's strict 20% cliff and Sui's
/// tip-only congestion pricing). A moderate, predictable slope.
///
/// # ⚠️ Placeholder
///
/// Interim value derived from `HIGH_DEMAND_THRESHOLD` (Jun 2026 research).
/// Calibrate with real testnet load profiles. Tracked in `living-notes.md`.
pub const SCALE_FACTOR: u64 = 400;

/// Hard cap on the surcharge multiplier.
///
/// Prevents an astronomically hot contract from producing u64-overflowing fee
/// hints (which would be meaningless beyond a point) and provides a predictable
/// worst-case fee ceiling for users and wallets to reason about.
pub const MAX_SURCHARGE_MULTIPLIER: u64 = 10;

// ── ContractLoad ──────────────────────────────────────────────────────────────

/// Per-contract EMA load state.
///
/// Tracks the exponentially weighted moving average of transactions per block
/// (committed by each [`LocalFeeMarket::tick`]) and the raw count for the
/// current in-progress block (accumulated by [`LocalFeeMarket::record`]).
#[derive(Debug, Default, Clone)]
struct ContractLoad {
    /// Exponentially weighted moving average of transactions per block.
    /// Updated once per block by [`LocalFeeMarket::tick`].
    ema_load: u64,
    /// Transaction count targeting this contract in the current (unfinished) block.
    /// Reset to 0 on each [`LocalFeeMarket::tick`].
    current_block_count: u64,
}

// ── LocalFeeMarket ────────────────────────────────────────────────────────────

/// Per-contract local fee market state.
///
/// Caller workflow:
/// 1. At ingress, call [`record`] for each transaction targeting a contract.
/// 2. Once per block, call [`tick`] to advance the EMA.
/// 3. At admission time, call [`local_base_fee`] to get the surcharge-adjusted
///    minimum fee for a given contract address.
/// 4. Periodically call [`prune_idle`] (e.g. after [`tick`]) to bound memory.
///
/// [`record`]: LocalFeeMarket::record
/// [`tick`]: LocalFeeMarket::tick
/// [`local_base_fee`]: LocalFeeMarket::local_base_fee
/// [`prune_idle`]: LocalFeeMarket::prune_idle
#[derive(Debug, Default, Clone)]
pub struct LocalFeeMarket {
    // BTreeMap for deterministic iteration order (AGENTS §7.1). The map is
    // local-heuristic state (never serialized, never committed) so HashMap
    // would also be sound, but BTreeMap makes prune_idle iteration order
    // predictable and consistent across test runs.
    loads: BTreeMap<Address, ContractLoad>,
}

impl LocalFeeMarket {
    /// Create a new, empty fee market with no tracked contracts.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a transaction targeting `contract` in the current block.
    ///
    /// Increments the contract's in-progress `current_block_count`. This count
    /// is folded into the EMA on the next call to [`tick`].
    ///
    /// Creates the tracking entry eagerly: a contract recorded but not yet
    /// ticked has `ema_load == 0` but `current_block_count > 0`, so it counts
    /// toward [`tracked_contracts`] and survives [`prune_idle`] until it is
    /// either ticked or goes idle.
    ///
    /// Saturating increment: recording `u64::MAX` transactions in one block
    /// clamps to `u64::MAX` rather than wrapping to 0.
    ///
    /// [`tick`]: LocalFeeMarket::tick
    /// [`tracked_contracts`]: LocalFeeMarket::tracked_contracts
    /// [`prune_idle`]: LocalFeeMarket::prune_idle
    pub fn record(&mut self, contract: &Address) {
        let load = self.loads.entry(*contract).or_default();
        load.current_block_count = load.current_block_count.saturating_add(1);
    }

    /// Advance the EMA by one block step.
    ///
    /// Folds each contract's `current_block_count` into its EMA using the decay
    /// formula, then resets the count for the next block.
    ///
    /// Call this **exactly once per block** from the pool's block-tick loop.
    ///
    /// # EMA formula
    ///
    /// ```text
    /// ema_new = (ema_old × DECAY_NUM + current_block_count) / DECAY_DEN
    /// ```
    ///
    /// Intermediate computation uses `u128` to prevent overflow before clamping
    /// back to `u64`. See module-level docs for arithmetic rationale.
    pub fn tick(&mut self) {
        for load in self.loads.values_mut() {
            // u128 intermediate prevents (ema_old × DECAY_NUM + count) from overflowing
            // u64. Saturating operations guard against the u128 ceiling too (theoretical
            // only — real loads are many orders of magnitude below u128::MAX).
            let numerator = (load.ema_load as u128)
                .saturating_mul(DECAY_NUM as u128)
                .saturating_add(load.current_block_count as u128);
            // DECAY_DEN is a non-zero const — compile-time division, no runtime panic.
            let new_ema = numerator / DECAY_DEN as u128;
            // Clamp back to u64. Theoretical — a u64::MAX ema would require ~1.8×10¹⁹
            // txs/block sustained over many blocks.
            load.ema_load = new_ema.min(u64::MAX as u128) as u64;
            load.current_block_count = 0;
        }
    }

    /// Remove contracts whose EMA load and current block count are both zero.
    ///
    /// Call periodically (e.g. after each [`tick`]) to bound the size of the
    /// internal map. Contracts that have been idle for enough blocks decay to
    /// zero EMA and are reclaimed here.
    ///
    /// [`tick`]: LocalFeeMarket::tick
    pub fn prune_idle(&mut self) {
        self.loads
            .retain(|_, load| load.ema_load > 0 || load.current_block_count > 0);
    }

    /// Compute the surcharge-adjusted minimum base fee for a contract's transaction.
    ///
    /// Returns `global_base` unchanged for cold contracts (EMA ≤
    /// [`HIGH_DEMAND_THRESHOLD`]). Above the threshold the surcharge rises
    /// **continuously** — no step-function cliff:
    ///
    /// ```text
    /// excess     = max(0, ema_load − HIGH_DEMAND_THRESHOLD)
    /// multiplier = (SCALE_FACTOR + excess) / SCALE_FACTOR
    /// fee        = global_base × min(multiplier, MAX_SURCHARGE_MULTIPLIER)
    /// ```
    ///
    /// At `ema = HIGH_DEMAND_THRESHOLD`, `excess = 0` → `multiplier = 1.0×` →
    /// `fee = global_base` exactly. At `ema = HIGH_DEMAND_THRESHOLD + 1`,
    /// `fee ≈ global_base × 1.01` (smooth, not 2×). The "free zone" for normal
    /// contracts is preserved: contracts below threshold always pay `global_base`.
    ///
    /// For transactions that do not target a contract (e.g. `Transfer` to a
    /// regular EOA), pass any untracked address — it will have no load and the
    /// returned fee equals `global_base`.
    ///
    /// # Surcharge destination
    ///
    /// The surcharge raises the **base fee** which is **100% burned** per
    /// TOKENOMICS §5 / WHITEPAPER §7.4. See module-level docs.
    ///
    /// # Arithmetic
    ///
    /// `u128` intermediate prevents overflow; final value clamped to `u64`.
    /// Saturating, not `checked_*` — see module-level docs for rationale.
    #[must_use]
    pub fn local_base_fee(&self, contract: &Address, global_base: u64) -> u64 {
        let ema = self.contract_load(contract);
        // Cold contracts: excess = 0 → multiplier = 1.0× → returns global_base.
        // Hot contracts: excess > 0 → multiplier rises smoothly above 1.0×.
        let excess = ema.saturating_sub(HIGH_DEMAND_THRESHOLD);
        // numerator = SCALE_FACTOR + excess; capped at SCALE_FACTOR × MAX_MULT
        // so the multiplier never exceeds MAX_SURCHARGE_MULTIPLIER.
        // All u128 to prevent overflow before the final clamp.
        let numerator = (SCALE_FACTOR as u128).saturating_add(excess as u128);
        let cap = (SCALE_FACTOR as u128).saturating_mul(MAX_SURCHARGE_MULTIPLIER as u128);
        let capped = numerator.min(cap);
        // fee = global_base × capped / SCALE_FACTOR.
        // SCALE_FACTOR is a non-zero const — division is safe.
        let fee = (global_base as u128).saturating_mul(capped) / SCALE_FACTOR as u128;
        // Clamp back to u64. Theoretical only — real fees are far below u64::MAX.
        fee.min(u64::MAX as u128) as u64
    }

    /// Return the committed EMA load for a contract.
    ///
    /// Returns `0` for untracked contracts. Useful for metrics and diagnostics.
    ///
    /// Note: this reflects the EMA *after the last [`tick`]*, not the in-progress
    /// current-block count. Callers reading load for admission decisions should
    /// use [`local_base_fee`] instead.
    ///
    /// [`tick`]: LocalFeeMarket::tick
    /// [`local_base_fee`]: LocalFeeMarket::local_base_fee
    #[must_use]
    pub fn contract_load(&self, contract: &Address) -> u64 {
        self.loads.get(contract).map(|c| c.ema_load).unwrap_or(0)
    }

    /// Return the number of contracts currently tracked in the load map.
    ///
    /// Useful for metrics. Call [`prune_idle`] to reclaim memory for idle
    /// contracts whose EMA has decayed to zero.
    ///
    /// [`prune_idle`]: LocalFeeMarket::prune_idle
    #[must_use]
    pub fn tracked_contracts(&self) -> usize {
        self.loads.len()
    }
}

#[cfg(test)]
mod tests;
