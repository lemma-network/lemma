//! Core mempool — priority queue for pending transactions.
//!
//! [`Mempool`] is the orchestrator that ties together all prior mempool
//! modules: ingress validation, circuit-breaker admission, per-account rate
//! limiting, stake-weighted QoS priority, replace-by-fee policy, per-contract
//! local fee markets, and Express fast-path classification.
//!
//! # Data structures (determinism, AGENTS.md §7.1)
//!
//! All ordered collections use `BTreeMap`/`BTreeSet` so iteration order is
//! deterministic and consistent across nodes. The priority index uses
//! `(Priority, seq_id)` as a composite key — `Priority` first (higher =
//! better), `seq_id` as a monotonic tiebreaker (FIFO within equal-priority
//! entries).
//!
//! ```text
//! entries:        BTreeMap<Hash,            PoolEntry>   — primary store
//! priority_index: BTreeMap<(Priority, u64), Hash>        — ascending: first = evict candidate
//! by_sender:      BTreeMap<Address, BTreeMap<u64, Hash>> — per-account nonce ordering
//! ```
//!
//! # Admission pipeline
//!
//! Every `admit` call runs these checks in order (cheap → expensive, then policy):
//!
//! 1. Ingress validation (`validation.rs`) — signature, nonce, balance, size.
//! 2. Circuit breaker (`circuit_breaker.rs`) — shed by type under load.
//! 3. Per-account rate limiting (`rate_limit.rs`) — token bucket.
//! 4. Replace-by-fee (`MIN_REPLACE_BUMP_BPS`) — replacement must beat old price.
//! 5. Capacity eviction — incoming must beat the pool minimum to enter a full pool.
//! 6. Local fee recording (`local_fees.rs`) — track contract load.
//! 7. Express classification (`express.rs`) — stored for the consensus layer.
//! 8. Insert into all indexes.
//!
//! # Determinism note (spec §1.1)
//!
//! Priority and admission are **local policy** — they affect which transactions
//! this node gossips and proposes, never the committed order.  Consensus (07)
//! owns the final order and re-validates at execution time.  `Mempool` may
//! therefore use local state (nonces, balances, timestamps) without violating
//! the determinism requirement of AGENTS.md §7.1.
//!
//! # Level-3 scheduler / demand-based auction
//!
//! The Level-3 per-resource real-time auction (Solana-style) is **explicitly
//! deferred** to a post-testnet Phase 2 refactor.  Building it now carries a
//! determinism hazard (the Sui stall lesson) and requires real load data that
//! does not exist yet.  The current Level-1 `LocalFeeMarket` already provides
//! per-contract surcharges.  See decisions-log "Local fee constant calibration"
//! and the living-notes Phase 2 action item.
//!
//! # Module size note
//!
//! This module is intentionally larger than the 300-line guideline (AGENTS.md
//! §3.1) because it is the orchestration layer — all seven prior modules
//! converge here.  Future refactors may extract the eviction / replacement
//! logic into a focused submodule once consensus integration drives a natural
//! split boundary.
//!
//! # References
//!
//! - `docs/11-MEMPOOL_SHIELD_SPEC.md §1` — pool spec, RBF rule, admission order
//! - `docs/11-MEMPOOL_SHIELD_SPEC.md §1.1` — determinism carve-out
//! - `docs/07-CONSENSUS_SPEC.md §10` — Express eligibility consumed by consensus
//! - `decisions-log.md` — Level-3 deferral, RBF bump, capacity rationale

use std::collections::BTreeMap;
use std::time::Instant;

use lemma_core::{
    amount::Amount,
    hash::Hash,
    transaction::{Transaction, TxType},
    Address,
};
use lemma_crypto::PublicKey;
use lemma_storage::WorldState;

use crate::{
    circuit_breaker::NetworkTier,
    error::MempoolError,
    express::{classify, ExpressEligibility, ExpressHint},
    local_fees::LocalFeeMarket,
    qos::{priority_score, Priority},
    rate_limit::RateLimiter,
    validation::{validate_transaction, ValidationContext},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum gas-price bump (in basis points) required for a replace-by-fee.
///
/// A new transaction for `(sender, nonce)` is accepted only if its `gas_price`
/// exceeds the existing transaction's price by at least this many basis points.
/// 1000 bps = 10%: `new_price ≥ old_price × 1.10`.
///
/// 10% is the standard used by Ethereum's mempool (EIP-1559 node defaults) and
/// most major MEV relays. It discourages spam replacements (attacker must pay
/// ≥10% more each round) while still allowing timely replacement for legitimate
/// fee-bumps.
pub const MIN_REPLACE_BUMP_BPS: u32 = 1_000;

/// Default maximum number of pending transactions the pool will hold.
///
/// # ⚠️ Placeholder
///
/// 5 000 is a conservative interim value. Final value depends on node hardware
/// targets, block time, and TPS benchmarks.  Calibrate after testnet load
/// profiling — tracked in `living-notes.md`.
pub const DEFAULT_CAPACITY: usize = 5_000;

// ── AdmitContext ──────────────────────────────────────────────────────────────

/// Per-call node context for [`Mempool::admit`].
///
/// Groups the three values that come from the node's current state (not the
/// transaction itself) and do not vary within a single block processing loop.
/// Splitting them out keeps `admit` under the 7-argument clippy limit.
pub struct AdmitContext {
    /// Chain identifier — replay-protection check (must match `tx.chain_id`).
    pub chain_id: u64,
    /// Current global base fee in Drop/gas.
    pub base_fee: Amount,
    /// Current time — injected for testability (pass `Instant::now()` in production).
    pub now: Instant,
}

// ── PoolEntry ─────────────────────────────────────────────────────────────────

/// A pending transaction stored in the mempool, with its computed metadata.
#[derive(Debug)]
pub struct PoolEntry {
    /// The pending transaction.
    pub tx: Transaction,
    /// Computed local admission priority (`gas_component + stake_bonus`).
    ///
    /// Higher value = admitted and retained first under congestion.
    /// This is a **sort key only** — never serialized, never committed.
    pub priority: Priority,
    /// Monotonic insertion sequence number.
    ///
    /// Used as a tiebreaker within equal-priority entries.  Higher `seq` = inserted
    /// later = higher BTreeMap key = returned first by `pending_by_priority` (LIFO
    /// tiebreak within a priority band; see `priority_index` doc for rationale).
    pub seq: u64,
    /// Express fast-path classification for this transaction.
    ///
    /// Stored so the consensus layer can consume it without re-classifying.
    /// Ineligibility is not an error — the transaction routes to base Pulse.
    pub express: ExpressEligibility,
}

// ── AdmitOutcome ──────────────────────────────────────────────────────────────

/// The successful outcome of [`Mempool::admit`].
///
/// Provides the gossip layer with enough information to handle the admission:
/// a `Replaced` outcome means the previous transaction should be withdrawn from
/// the gossip graph.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum AdmitOutcome {
    /// Transaction was inserted as a new entry (no prior `(sender, nonce)` in pool).
    Inserted,
    /// Transaction replaced an existing entry via replace-by-fee.
    Replaced {
        /// Hash of the previous transaction for `(sender, nonce)` that was evicted.
        replaced_hash: Hash,
    },
}

// ── Mempool ───────────────────────────────────────────────────────────────────

/// The pending-transaction pool for the Lemma node.
///
/// Owns all mempool sub-modules and presents a single admission + retrieval
/// interface to the RPC and consensus layers.
///
/// # Ownership
///
/// `Mempool` owns the [`RateLimiter`] and [`LocalFeeMarket`] (stateful per-block
/// state).  All other sub-modules (`validation`, `circuit_breaker`, `qos`,
/// `express`) are pure functions — they are called inline with no ownership.
///
/// # Time and stake injection
///
/// `admit` and `on_new_block` take `now: Instant` explicitly so tests can drive
/// the rate limiter and block-tick state without `sleep()` or `Instant::now()`
/// calls inside the struct.  `admit` also takes `sender_stake: Amount` so the
/// pool does not need to reach into `WorldState` for staking data — the caller
/// (RPC ingress) provides it.
pub struct Mempool {
    /// Primary store: `tx_hash → entry`.
    entries: BTreeMap<Hash, PoolEntry>,
    /// Priority index: `(priority, seq_id) → tx_hash`.
    ///
    /// Ascending: `.iter().next()` = lowest-priority (eviction candidate).
    /// Reverse: `.iter().rev()` = highest-priority (retrieval order).
    ///
    /// **Equal-priority tiebreak is LIFO** (last-inserted = higher seq = higher key =
    /// comes first in `.rev()`). This favors fresher fee signals under congestion
    /// (a tx re-submitted at the same price is more likely to reflect current conditions).
    priority_index: BTreeMap<(Priority, u64), Hash>,
    /// Per-account nonce index: `sender → (nonce → tx_hash)`.
    ///
    /// Enables O(log n) lookup for replace-by-fee and per-account nonce ordering.
    by_sender: BTreeMap<Address, BTreeMap<u64, Hash>>,
    /// Monotonic insertion counter — incremented on every successful insert.
    next_seq: u64,
    /// Maximum number of entries this pool will hold.
    capacity: usize,
    /// Per-account rate limiter (token bucket).
    rate_limiter: RateLimiter,
    /// Per-contract local fee market (continuous EMA, Level 1).
    local_fees: LocalFeeMarket,
}

impl Mempool {
    /// Create a new `Mempool` with the given capacity and default sub-modules.
    ///
    /// Uses [`RateLimiter::with_defaults`] (capacity 20, refill 5 tx/s) and a
    /// fresh [`LocalFeeMarket`].
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self::with_rate_limiter(capacity, RateLimiter::with_defaults())
    }

    /// Create a `Mempool` with a caller-supplied `RateLimiter`.
    ///
    /// Useful in tests to control the rate-limit token capacity precisely without
    /// relying on the default 20-token bucket.
    #[must_use]
    pub fn with_rate_limiter(capacity: usize, rate_limiter: RateLimiter) -> Self {
        Self {
            entries: BTreeMap::new(),
            priority_index: BTreeMap::new(),
            by_sender: BTreeMap::new(),
            next_seq: 0,
            capacity,
            rate_limiter,
            local_fees: LocalFeeMarket::new(),
        }
    }

    // ── Admission ─────────────────────────────────────────────────────────────

    /// Attempt to admit `tx` into the pool.
    ///
    /// Runs the full 8-step admission pipeline (see module docs).  Returns
    /// [`AdmitOutcome`] on success, or a [`MempoolError`] that describes the
    /// first rejection reason encountered.
    ///
    /// # Arguments
    ///
    /// * `tx` — the transaction to admit.
    /// * `sender_pubkey` — Ed25519 + ML-DSA public key of `tx.sender`.
    ///   Cannot be derived from the address alone — must be supplied by the
    ///   caller (see `validation.rs` module docs).
    /// * `sender_stake` — active self-stake of the sender in Drop.
    ///   Pass `Amount::zero()` for non-staked accounts.
    /// * `hint` — compiler-provided state-access hint for Express classification.
    ///   Pass `None` if unavailable; this conservatively routes to base Pulse.
    /// * `state` — current world state (nonces, balances) for validation.
    /// * `ctx` — per-call node context (chain_id, base_fee, now).
    ///
    /// # Errors
    ///
    /// Returns the first [`MempoolError`] from the admission pipeline.
    /// On error, the pool state is **unchanged** (no partial mutations).
    pub fn admit(
        &mut self,
        tx: Transaction,
        sender_pubkey: &PublicKey,
        sender_stake: Amount,
        hint: Option<&ExpressHint>,
        state: &WorldState,
        ctx: &AdmitContext,
    ) -> Result<AdmitOutcome, MempoolError> {
        // ── Step 1: Ingress validation (cheap → expensive per validation.rs) ──
        let val_ctx = ValidationContext {
            chain_id: ctx.chain_id,
            base_fee: ctx.base_fee,
        };
        validate_transaction(&tx, sender_pubkey, state, &val_ctx)?;

        // ── Step 2: Circuit breaker — shed by tx type under load ──────────────
        let load = self.entries.len();
        let tier = NetworkTier::from_load(load, self.capacity);
        if !tier.admits(tx.tx_type) {
            return Err(MempoolError::CircuitBreakerRejected {
                tx_hash: tx.hash,
                reason: tier.rejection_reason(),
            });
        }

        // ── Step 3: Per-account rate limiting ─────────────────────────────────
        self.rate_limiter.try_acquire(&tx.sender, ctx.now)?;

        // ── Step 4: Compute priority (used in RBF bump check + capacity guard) ─
        let priority = priority_score(tx.gas_price, sender_stake);

        // ── Step 5a: Replace-by-fee ─────────────────────────────────────────
        // Check for an existing (sender, nonce) entry BEFORE any mutation.
        let existing = self
            .by_sender
            .get(&tx.sender)
            .and_then(|m| m.get(&tx.nonce))
            .copied(); // Option<Hash> — Copy, no borrow kept alive

        let replaced_hash: Option<Hash> = if let Some(old_hash) = existing {
            // Extract needed fields before mutating (ends the immutable borrow).
            let (old_priority, old_seq, old_gas_price) = {
                let e = self.entries.get(&old_hash).expect(
                    "pool invariant: by_sender points to a hash that must exist in entries",
                );
                (e.priority, e.seq, e.tx.gas_price)
            };
            // Require a minimum price bump — stops spam replacements.
            let min_price = rbf_min_price(old_gas_price, MIN_REPLACE_BUMP_BPS);
            if tx.gas_price < min_price {
                return Err(MempoolError::ReplacementUnderpriced {
                    sender: tx.sender,
                    nonce: tx.nonce,
                    old_price: old_gas_price.as_drop(),
                    new_price: tx.gas_price.as_drop(),
                    min_bump_bps: MIN_REPLACE_BUMP_BPS,
                });
            }
            // RBF accepted: remove old entry from all indexes.
            self.remove_internal(old_hash, old_priority, old_seq);
            Some(old_hash)
        } else {
            // ── Step 5b: Capacity — evict lowest-priority if pool is full ─────
            if self.entries.len() >= self.capacity {
                // The priority_index is ascending: first entry = lowest-priority candidate.
                let min_entry = self.priority_index.iter().next().map(|(&k, &v)| (k, v));
                match min_entry {
                    Some(((min_p, min_seq), evict_hash)) if priority > min_p => {
                        // Incoming beats the minimum — evict and make room.
                        self.remove_internal(evict_hash, min_p, min_seq);
                    }
                    _ => {
                        // Pool full and incoming does not beat the minimum.
                        return Err(MempoolError::PoolFull {
                            tx_hash: tx.hash,
                            capacity: self.capacity,
                        });
                    }
                }
            }
            None
        };

        // ── Step 6: Local fee recording ──────────────────────────────────────
        // Track contract load only for txs that target an existing contract.
        if let Some(contract_addr) = tx.to {
            if matches!(tx.tx_type, TxType::ContractCall | TxType::ContractDeploy) {
                self.local_fees.record(&contract_addr);
            }
        }

        // ── Step 7: Express classification ───────────────────────────────────
        let express = classify(tx.tx_type, hint);

        // ── Step 8: Insert into all indexes ──────────────────────────────────
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);

        let hash = tx.hash;
        let sender = tx.sender;
        let nonce = tx.nonce;

        self.entries.insert(
            hash,
            PoolEntry {
                tx,
                priority,
                seq,
                express,
            },
        );
        self.priority_index.insert((priority, seq), hash);
        self.by_sender
            .entry(sender)
            .or_default()
            .insert(nonce, hash);

        let outcome = match replaced_hash {
            Some(h) => AdmitOutcome::Replaced { replaced_hash: h },
            None => AdmitOutcome::Inserted,
        };
        Ok(outcome)
    }

    // ── Removal ───────────────────────────────────────────────────────────────

    /// Remove the transaction with `hash` from the pool.
    ///
    /// Returns the removed [`PoolEntry`] if present, or `None` if the hash was
    /// not in the pool.  Cleans up all three indexes atomically.
    pub fn remove(&mut self, hash: Hash) -> Option<PoolEntry> {
        // Copy the index key fields before the mutable remove (ends the borrow).
        let (priority, seq) = {
            let e = self.entries.get(&hash)?;
            (e.priority, e.seq)
        };
        self.remove_internal(hash, priority, seq)
    }

    // ── Query API ─────────────────────────────────────────────────────────────

    /// Return a reference to the pool entry for `hash`, or `None`.
    #[must_use]
    pub fn get(&self, hash: Hash) -> Option<&PoolEntry> {
        self.entries.get(&hash)
    }

    /// Returns `true` if `hash` is currently in the pool.
    #[must_use]
    pub fn contains(&self, hash: Hash) -> bool {
        self.entries.contains_key(&hash)
    }

    /// Current number of pending transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the pool holds no transactions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns `true` if the pool has reached its capacity limit.
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.capacity
    }

    /// The maximum number of pending transactions this pool will hold.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Return up to `limit` pending transactions, ordered by priority (highest first).
    ///
    /// Within equal-priority entries the tiebreak is **LIFO** — the most recently
    /// inserted entry comes first.  Higher `seq` = higher key = first in reverse
    /// iteration.  This favors fresher fee signals: a re-submitted tx at the same
    /// price likely reflects more current network conditions.
    ///
    /// # Nonce ordering note
    ///
    /// This method returns transactions in **priority order**, not per-account
    /// nonce order.  Nonce linearisation (ensuring a sender's nonce-N tx precedes
    /// nonce-N+1) is the consensus layer's responsibility (07-CONSENSUS_SPEC §1.1),
    /// not the pool's.  The pool exposes raw priority ordering; the block builder
    /// filters and sequences by sender.
    #[must_use]
    pub fn pending_by_priority(&self, limit: usize) -> Vec<&Transaction> {
        self.priority_index
            .iter()
            .rev() // highest (Priority, seq) first
            .take(limit)
            .filter_map(|(_key, hash)| self.entries.get(hash).map(|e| &e.tx))
            .collect()
    }

    // ── Per-block maintenance ──────────────────────────────────────────────────

    /// Drive all per-block maintenance: rate-limiter pruning and fee-market tick.
    ///
    /// Call once per new block arrival.  All three sub-module maintenance
    /// operations are routed through this single method (decisions-log:
    /// "all per-block maintenance through one block-tick method").
    ///
    /// * `now` — current time (injected; pass `Instant::now()` in production).
    pub fn on_new_block(&mut self, now: Instant) {
        self.rate_limiter.prune_full(now);
        self.local_fees.tick();
        self.local_fees.prune_idle();
    }

    // ── Fee market queries ────────────────────────────────────────────────────

    /// Compute the local base fee for a contract address.
    ///
    /// Delegates to the internal [`LocalFeeMarket`].  Returns `global_base`
    /// unmodified if the contract has no recorded load.
    ///
    /// See `local_fees.rs` for the continuous-EMA Level-1 formula.
    #[must_use]
    pub fn local_base_fee(&self, contract: &Address, global_base: u64) -> u64 {
        self.local_fees.local_base_fee(contract, global_base)
    }

    /// Number of contracts currently tracked in the local fee market.
    ///
    /// Primarily for tests and metrics.
    #[must_use]
    pub fn tracked_contracts(&self) -> usize {
        self.local_fees.tracked_contracts()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Remove `hash` from all three indexes.
    ///
    /// `priority` and `seq` are the key used in `priority_index`; they must
    /// match the entry's stored values (the caller is responsible for reading
    /// them before calling).
    ///
    /// Returns the removed [`PoolEntry`] if it existed, `None` otherwise.
    /// Always removes the `(priority, seq)` key from `priority_index` (defensive
    /// cleanup even if the primary entry was somehow absent).
    fn remove_internal(&mut self, hash: Hash, priority: Priority, seq: u64) -> Option<PoolEntry> {
        let entry = self.entries.remove(&hash);
        // Remove from priority index (defensive: runs even if entry was absent).
        self.priority_index.remove(&(priority, seq));
        if let Some(ref e) = entry {
            let sender = e.tx.sender;
            let nonce = e.tx.nonce;
            if let Some(nonces) = self.by_sender.get_mut(&sender) {
                nonces.remove(&nonce);
                if nonces.is_empty() {
                    self.by_sender.remove(&sender);
                }
            }
        }
        entry
    }
}

// ── Free helpers ──────────────────────────────────────────────────────────────

/// Compute the minimum gas price required to replace an existing transaction.
///
/// `min_price = old_price × (10_000 + bump_bps) / 10_000`
///
/// Uses `checked_mul` per AGENTS.md §7.4.  On overflow (physically impossible
/// for real token amounts — total LEM supply is ≪ `u128::MAX`) the function
/// returns `Amount::from_drop(u128::MAX)`, which is always greater than any real
/// gas price and therefore always rejects the replacement.  This is the correct
/// fail-safe: an "unreplaceable" sentinel, not a panic.
fn rbf_min_price(old_price: Amount, bump_bps: u32) -> Amount {
    let min_drop = old_price
        .as_drop()
        .checked_mul(10_000u128 + u128::from(bump_bps))
        .map(|v| v / 10_000)
        .unwrap_or(u128::MAX);
    Amount::from_drop(min_drop)
}

#[cfg(test)]
mod tests;
