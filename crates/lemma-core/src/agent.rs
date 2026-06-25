//! # Agent Layer types — bounded authority for autonomous AI agents
//!
//! Defines the core domain types for the Warden policy enforcement system
//! (14-AGENT_LAYER §2–§3). These types live in `lemma-core` because they are
//! shared by `lemma-vm` (enforcement), `lemma-lang` (analysis), and future
//! `lemma-rpc`/SDK (developer surface).
//!
//! ## Core types (P3·Step 13)
//!
//! | Type | Role |
//! |------|------|
//! | [`Action`] | Classifies what a transaction does (Transfer, ContractCall, …) |
//! | [`ActionMask`] | Bitmask of permitted actions |
//! | [`AllowList`] | Set of permitted target addresses |
//! | [`AgentPolicy`] | The full policy grant attached to a session key |
//! | [`PolicyViolation`] | Why a Warden check failed |
//! | [`WardenOutcome`] | Success outcome of a Warden check |
//!
//! ## Extension types (P3·Step 14)
//!
//! | Type | Role |
//! |------|------|
//! | [`CategoryBudget`] | Per-category cap + spent counter |
//! | [`CategoryCaps`] | Bounded map of named spending categories (max [`MAX_CATEGORIES`]) |
//!
//! ## Extension types (P3·Steps 15–17)
//!
//! | Type | Role |
//! |------|------|
//! | [`AnomalyConfig`] | Per-policy anomaly guard settings (opt-in, named thresholds) |
//! | [`AnomalyHistory`] | On-chain committed behavioral baseline for anomaly detection |
//! | [`AgentIdentity`] | Identity Registry record: owner, KYA tier, reputation score |
//! | [`MandateReceipt`] | AP2-aligned audit trail emitted on every applied agent tx (§11) |
//!
//! ## Extension fields
//!
//! | Field | Enforced in | Spec |
//! |-------|-------------|------|
//! | `refill_per_epoch` | P3·Step 14 ✅ | 14 §2.3.1 |
//! | `budget_ceiling` | P3·Step 14 ✅ | 14 §2.3.1 |
//! | `categories` | P3·Step 14 ✅ | 14 §2.3.2 |
//! | `active_window` | P3·Step 14 ✅ | 14 §2.3.3 |
//! | `cosign_threshold` | P3·Step 14 ✅ | 14 §2.3.4 |
//! | `auto_revoke` | P3·Step 14 ✅ | 14 §2.3.5 |
//! | `agents_paused` (owner-level) | P3·Step 15 ✅ | 14 §2.4 |
//! | `anomaly` + `history` | P3·Step 15 ✅ | 14 §9.1 |
//! | `required_kya_tier` | P3·Step 16 ✅ | 14 §8 |
//! | `min_counterparty_reputation` | P3·Step 16 ✅ | 14 §8 |
//! | `kya_tier` (own tier) | P3·Step 16 ✅ | 14 §7.2 |
//!
//! ## Determinism (AGENTS §7.1)
//!
//! All collections use `BTreeSet`/`BTreeMap` — never `HashSet`/`HashMap`.
//! All arithmetic is checked (AGENTS §7.4). No `SystemTime`, no `rand`.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{address::Address, amount::Amount, hash::Hash, transaction::Log};

// ── Action ───────────────────────────────────────────────────────────────────

/// Maximum reputation score (0–100 inclusive scale).
///
/// Agent reputation is recorded in the Identity Registry as a `u16` in
/// `[0, REPUTATION_SCORE_MAX]`. 0 = no track record / new agent; 100 = perfect
/// record. The Phase 4 reputation pipeline computes and writes the score;
/// Step 16 only reads and enforces it (AGENTS §3.3 — named constant).
pub const REPUTATION_SCORE_MAX: u16 = 100;

/// Classifies what a transaction does, for action-mask filtering.
///
/// Maps 1:1 from [`TxType`](crate::transaction::TxType) for the core types.
/// [`PayAgent`](Action::PayAgent) is detected via Identity Registry lookup
/// inside `warden_check` (not from TxType) — see 14 §8 + DB-A67.
///
/// See 14-AGENT_LAYER §3 `classify_action(tx)`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Native LEM transfer.
    Transfer,
    /// Call a deployed contract.
    ContractCall,
    /// Deploy new contract bytecode.
    ContractDeploy,
    /// Stake LEM with a validator.
    Stake,
    /// Withdraw staked LEM.
    Unstake,
    /// Cast a governance vote.
    GovernanceVote,
    /// Agent-to-Agent payment to a registered counterparty (14 §8, P3·Step 16 ✅).
    ///
    /// Detected inside `warden_check` via Identity Registry lookup: if `tx.to`
    /// is a registered agent, the action is reclassified as `PayAgent`. This
    /// adds **no new TxType or mempool path** (spec §8: "composes existing
    /// primitives"). The payer's `ActionMask` must explicitly permit `PayAgent`.
    PayAgent,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Transfer => "Transfer",
            Self::ContractCall => "ContractCall",
            Self::ContractDeploy => "ContractDeploy",
            Self::Stake => "Stake",
            Self::Unstake => "Unstake",
            Self::GovernanceVote => "GovernanceVote",
            Self::PayAgent => "PayAgent",
        };
        f.write_str(name)
    }
}

// ── ActionMask ───────────────────────────────────────────────────────────────

/// A set of permitted actions for an agent.
///
/// Uses `BTreeSet` for deterministic serialization and iteration (AGENTS §7.1).
///
/// # Examples
///
/// ```
/// use lemma_core::agent::{Action, ActionMask};
///
/// let mask = ActionMask::from_actions(&[Action::Transfer, Action::ContractCall]);
/// assert!(mask.permits(Action::Transfer));
/// assert!(!mask.permits(Action::Stake));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionMask {
    allowed: BTreeSet<Action>,
}

impl ActionMask {
    /// Create a mask permitting the given actions.
    pub fn from_actions(actions: &[Action]) -> Self {
        Self {
            allowed: actions.iter().copied().collect(),
        }
    }

    /// Create a mask permitting ALL actions (including [`Action::PayAgent`]).
    ///
    /// Existing policies using `all()` gain `PayAgent` automatically, which is
    /// correct: if an agent is allowed to do everything, it may also pay other
    /// agents. Policies that should NOT allow A2A must explicitly omit `PayAgent`
    /// from their mask or rely on `required_kya_tier` / `min_counterparty_reputation`
    /// to gate the quality of the counterparty (14 §8).
    pub fn all() -> Self {
        Self {
            allowed: [
                Action::Transfer,
                Action::ContractCall,
                Action::ContractDeploy,
                Action::Stake,
                Action::Unstake,
                Action::GovernanceVote,
                Action::PayAgent,
            ]
            .into_iter()
            .collect(),
        }
    }

    /// Create an empty mask (no actions permitted).
    pub fn none() -> Self {
        Self {
            allowed: BTreeSet::new(),
        }
    }

    /// Returns `true` if `action` is permitted.
    #[must_use]
    pub fn permits(&self, action: Action) -> bool {
        self.allowed.contains(&action)
    }
}

// ── AllowList ────────────────────────────────────────────────────────────────

/// Set of permitted target addresses (contracts/accounts) for an agent.
///
/// See 14-AGENT_LAYER §2.1 `allowed_targets`.
///
/// # Determinism
///
/// `Specific` uses `BTreeSet` — deterministic iteration order (AGENTS §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AllowList {
    /// Any target is permitted (wildcard).
    Any,
    /// Only these specific addresses are permitted.
    Specific { targets: BTreeSet<Address> },
}

impl AllowList {
    /// Create a wildcard allow-list.
    pub fn any() -> Self {
        Self::Any
    }

    /// Create a specific allow-list from the given addresses.
    pub fn from_targets(addrs: &[Address]) -> Self {
        Self::Specific {
            targets: addrs.iter().copied().collect(),
        }
    }

    /// Returns `true` if `addr` is permitted.
    #[must_use]
    pub fn contains(&self, addr: &Address) -> bool {
        match self {
            Self::Any => true,
            Self::Specific { targets } => targets.contains(addr),
        }
    }
}

// ── CategoryBudget + CategoryCaps ────────────────────────────────────────────

/// Hard maximum number of spending categories per policy (14 §2.3.2).
///
/// Bounded by design — prevents premature abstraction of `CategoryCaps`
/// into an unbounded DSL (AGENTS §17). Eight categories is more than
/// enough for practical agent budgeting (e.g. DATA, COMPUTE, TRADE,
/// GOVERNANCE, STAKE, BRIDGE, MINT, OTHER).
pub const MAX_CATEGORIES: usize = 8;

/// Per-category spending cap and current-epoch counter.
///
/// `cap` is the maximum total amount (in Drop) the agent may spend on
/// transactions that map to this category within a single epoch. `spent`
/// tracks the running total and is reset to zero at each epoch boundary
/// (alongside `spent_this_epoch` — see epoch-reset logic in `warden_check`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryBudget {
    /// Maximum amount spendable in this category per epoch (in Drop).
    pub cap: Amount,
    /// Accumulated spend in this category this epoch (mutable counter).
    pub spent: Amount,
    /// Actions that map to this category. An action maps to the first
    /// matching category in `BTreeMap` key order.
    pub actions: BTreeSet<Action>,
}

/// Bounded map of named per-category spending sub-budgets (14 §2.3.2).
///
/// Each entry is a named category (e.g. `"TRADE"`, `"DATA"`) with its own
/// cap and epoch-spent counter. An action maps to the first category whose
/// `actions` set contains it (BTreeMap key order = deterministic, AGENTS §7.1).
///
/// Bounded to [`MAX_CATEGORIES`] entries — adding more is rejected by
/// [`CategoryCaps::insert`]. This prevents the category system from
/// becoming an unbounded budget DSL.
///
/// # Determinism
///
/// Uses `BTreeMap` — iteration order is deterministic across all nodes.
/// Never use `HashMap` here (AGENTS §7.1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryCaps {
    /// Named category budgets. Max [`MAX_CATEGORIES`] entries.
    entries: BTreeMap<String, CategoryBudget>,
}

impl CategoryCaps {
    /// Create a new empty `CategoryCaps`.
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    /// Add a category budget. Returns `false` (no-op) if already at
    /// [`MAX_CATEGORIES`] entries — callers must check the return value
    /// when configuring a policy.
    pub fn insert(&mut self, name: impl Into<String>, budget: CategoryBudget) -> bool {
        if self.entries.len() >= MAX_CATEGORIES {
            return false;
        }
        self.entries.insert(name.into(), budget);
        true
    }

    /// Returns `true` if no categories are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find the first category whose `actions` set contains `action`.
    ///
    /// Returns the category name, or `None` if no category matches
    /// (uncategorized tx — category check is skipped).
    #[must_use]
    pub fn category_of(&self, action: Action) -> Option<&str> {
        self.entries
            .iter()
            .find(|(_, budget)| budget.actions.contains(&action))
            .map(|(name, _)| name.as_str())
    }

    /// Current spent amount for a category (0 if not found).
    #[must_use]
    pub fn spent(&self, category: &str) -> Amount {
        self.entries
            .get(category)
            .map(|b| b.spent)
            .unwrap_or(Amount::zero())
    }

    /// Cap for a category (0 if not found — acts as "no cap" sentinel;
    /// callers must ensure the category exists before calling).
    #[must_use]
    pub fn cap(&self, category: &str) -> Amount {
        self.entries
            .get(category)
            .map(|b| b.cap)
            .unwrap_or(Amount::zero())
    }

    /// Increment the spent counter for a category. No-op if not found.
    ///
    /// Uses checked arithmetic — silently saturates rather than panicking
    /// (AGENTS §7.4). In practice the budget check already guards against
    /// overflow before `add_spent` is called.
    pub fn add_spent(&mut self, category: &str, value: Amount) {
        if let Some(budget) = self.entries.get_mut(category) {
            // Saturate rather than wrap — the per-category check already
            // guards against exceeding the cap, so overflow here is a
            // defensive fallback only.
            budget.spent = budget
                .spent
                .checked_add(value)
                .unwrap_or(Amount::from_drop(u128::MAX));
        }
    }

    /// Reset all category spent counters to zero (called at epoch boundary).
    pub fn reset_epoch(&mut self) {
        for budget in self.entries.values_mut() {
            budget.spent = Amount::zero();
        }
    }
}

// ── EpochRange ───────────────────────────────────────────────────────────────

/// An epoch range for time-window restrictions (14 §2.3.3).
///
/// Enforced by `warden_check` (P3·Step 14): an agent may only act when
/// `policy.active_window.start_epoch <= epoch <= policy.active_window.end_epoch`.
/// Generalizes `expiry_epoch` — the window's hard upper bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRange {
    /// First epoch the agent may act in (inclusive).
    pub start_epoch: u64,
    /// Last epoch the agent may act in (inclusive).
    pub end_epoch: u64,
}

// ── AutoRevoke ───────────────────────────────────────────────────────────────

/// Dead-man's switch configuration (14 §2.3.5).
///
/// Enforced by `warden_check` caller in `executor.rs` (P3·Step 14): on every
/// `PolicyViolation`, `violations_this_epoch` is incremented. When it reaches
/// `max_violations_per_epoch` (if > 0), the policy is immediately revoked by
/// setting `expiry_epoch = current_epoch`. Resets to 0 at each epoch boundary
/// alongside `spent_this_epoch`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoRevoke {
    /// Revoke after this many PolicyViolations in a single epoch.
    /// 0 = disabled (no auto-revoke).
    #[serde(default)]
    pub max_violations_per_epoch: u32,
    /// Current violation count this epoch (mutable counter).
    /// Reset to 0 at epoch boundary.
    #[serde(default)]
    pub violations_this_epoch: u32,
    // DEFERRED(Step 15): anomaly trigger (14 §9.1).
    // When Step 15 lands, add: pub anomaly_triggered: bool,
}

// ── KyaTier ──────────────────────────────────────────────────────────────────

// ── Anomaly guard types (P3·Step 15) ─────────────────────────────────────────

/// Maximum number of target addresses tracked for the target-novelty anomaly signal.
///
/// Once the `seen_targets` set reaches this cap, target-novelty detection stops
/// updating AND stops firing — agents with many known targets have established
/// breadth and are not meaningfully "novel." Bounded to prevent unbounded state
/// growth (AGENTS §17 — premature abstraction of unbounded DSL).
pub const MAX_SEEN_TARGETS: usize = 16;

/// Default value spike threshold: 5.0× the historical average (in units of 100).
///
/// A tx whose value exceeds `avg_value_ema × ANOMALY_SPIKE_RATIO_DEFAULT / 100`
/// is flagged as a value spike. Named constant per AGENTS §3.3.
pub const ANOMALY_SPIKE_RATIO_DEFAULT: u16 = 500;

/// Default burst rate threshold: 3.0× the historical average tx count (in units of 100).
///
/// A tx that pushes the epoch count above `avg_tx_count_ema × ANOMALY_BURST_RATIO_DEFAULT / 100`
/// is flagged as a burst. Named constant per AGENTS §3.3.
pub const ANOMALY_BURST_RATIO_DEFAULT: u16 = 300;

/// Value threshold (as a percentage of per_tx_cap) for the novel-target signal.
///
/// A tx to a never-before-seen target is flagged only when `tx.value * 100 >=
/// policy.per_tx_cap * ANOMALY_NOVEL_TARGET_HIGH_VALUE_PCT` — i.e. ≥ 50% of the
/// per-tx cap. Below this threshold a novel-target tx is not suspicious (small
/// exploratory transfers are normal for new counterparties).
///
/// Named constant per AGENTS §3.3.
pub const ANOMALY_NOVEL_TARGET_HIGH_VALUE_PCT: u16 = 50;

/// Per-policy anomaly guard configuration (14 §9.1, P3·Step 15).
///
/// The anomaly guard is **opt-in** (`enabled: false` by default) and uses only
/// committed on-chain history — no wall-clock, no RNG, no off-chain data
/// (determinism preserved, AGENTS §7.1; SAFETY-019 enforced by the compiler
/// for Lem contracts; this type is the VM-layer equivalent).
///
/// Thresholds are expressed in units of 100 (100 = 1.0×, 500 = 5.0×)
/// to avoid floating-point (AGENTS §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnomalyConfig {
    /// Whether the anomaly guard is active for this policy.
    ///
    /// Default: `false` — anomaly detection is opt-in. The policy owner
    /// must explicitly enable it when granting a high-value session key.
    #[serde(default)]
    pub enabled: bool,

    /// Value spike threshold in units of 100.
    ///
    /// Flag if `tx.value > avg_value_ema × spike_ratio / 100`.
    /// Default: [`ANOMALY_SPIKE_RATIO_DEFAULT`] (5.0×).
    /// Owner-only to set (widening a policy requires owner key — SAFETY-015).
    #[serde(default = "AnomalyConfig::default_spike_ratio")]
    pub spike_ratio: u16,

    /// Burst rate threshold in units of 100.
    ///
    /// Flag if `tx_count_this_epoch > avg_tx_count_ema × burst_ratio / 100`.
    /// Default: [`ANOMALY_BURST_RATIO_DEFAULT`] (3.0×).
    #[serde(default = "AnomalyConfig::default_burst_ratio")]
    pub burst_ratio: u16,
}

impl AnomalyConfig {
    fn default_spike_ratio() -> u16 {
        ANOMALY_SPIKE_RATIO_DEFAULT
    }

    fn default_burst_ratio() -> u16 {
        ANOMALY_BURST_RATIO_DEFAULT
    }
}

impl Default for AnomalyConfig {
    /// Anomaly detection disabled by default; thresholds set to safe named defaults.
    fn default() -> Self {
        Self {
            enabled: false,
            spike_ratio: ANOMALY_SPIKE_RATIO_DEFAULT,
            burst_ratio: ANOMALY_BURST_RATIO_DEFAULT,
        }
    }
}

/// Committed on-chain behavioral baseline for the anomaly guard (14 §9.1, P3·Step 15).
///
/// All fields use integer-only arithmetic — no floating point — so every node
/// produces the same values for the same inputs (AGENTS §7.1, SAFETY-019).
///
/// ## EMA formula (1/8 alpha — TCP RTT-style)
///
/// ```text
/// new_ema = old_ema − (old_ema >> 3) + (value >> 3)
/// ```
///
/// This is `(7/8) × old_ema + (1/8) × value` without floating point.
/// Alpha = 1/8 gives a smooth window of roughly 8 data points.
///
/// ## Bootstrap guard
///
/// `has_history = false` on new policies. Anomaly detection is skipped until
/// `has_history` is set (after the first epoch with at least one successful tx).
/// This prevents false positives on fresh policies with no baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnomalyHistory {
    /// Exponential moving average of transaction value in Drop (1/8 alpha).
    ///
    /// Updated on each warden-applied tx via `update_history`.
    /// Zero = no committed value history yet.
    #[serde(default = "Amount::zero")]
    pub avg_value_ema: Amount,

    /// Number of warden-applied txs completed this epoch.
    ///
    /// Reset to 0 at each epoch boundary (inside `apply_epoch_reset`).
    /// Feeds `avg_tx_count_ema` at the boundary.
    #[serde(default)]
    pub tx_count_this_epoch: u16,

    /// EMA of txs-per-epoch (1/8 alpha, same formula as `avg_value_ema`).
    ///
    /// Updated at each epoch boundary with the completed epoch's `tx_count_this_epoch`.
    /// Zero = no completed epoch yet.
    #[serde(default)]
    pub avg_tx_count_ema: u16,

    /// Whether at least one epoch of history has been committed.
    ///
    /// Set to `true` after the first epoch boundary where `tx_count_this_epoch > 0`.
    /// Anomaly detection is skipped when `false` (no baseline to compare against).
    #[serde(default)]
    pub has_history: bool,

    /// Set of target addresses this agent has previously transacted with.
    ///
    /// Bounded to [`MAX_SEEN_TARGETS`] entries. When the set is at capacity,
    /// both target tracking and the target-novelty signal are disabled for this
    /// policy — agents with many known counterparties have established breadth
    /// and the signal loses discriminative power. Signal 3 only fires while the
    /// set is below capacity.
    ///
    /// Uses `BTreeSet` for deterministic iteration (AGENTS §7.1).
    #[serde(default)]
    pub seen_targets: BTreeSet<Address>,
}

impl Default for AnomalyHistory {
    /// All-zero baseline: `has_history = false` → anomaly detection skipped
    /// until the first epoch boundary with activity completes.
    fn default() -> Self {
        Self {
            avg_value_ema: Amount::zero(),
            tx_count_this_epoch: 0,
            avg_tx_count_ema: 0,
            has_history: false,
            seen_targets: BTreeSet::new(),
        }
    }
}

// ── AgentIdentity (Identity Registry record, §7.1) ───────────────────────────

/// On-chain Identity Registry record for an agent (14 §7.1, P3·Step 16 ✅).
///
/// Stored under the registry system contract (`Address::registry()`) keyed by
/// the agent's session-key address. Written when an agent registers via an
/// owner-authorized transaction; read by Warden during A2A counterparty checks.
///
/// ## Determinism (AGENTS §7.1)
///
/// All fields are plain scalar types — no wall-clock, no RNG, no `HashMap`.
/// Serialized as JSON (same as `AgentPolicy` — consistent with Warden storage).
///
/// ## Reputation score scale
///
/// `reputation_score` is in `[0, REPUTATION_SCORE_MAX]` (0–100). A score of
/// `0` means no track record (new or unscored agent); `100` means perfect.
/// The Phase 4 reputation pipeline computes and updates the score; Step 16
/// only reads and enforces it — a clean Phase 3/4 boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Owner address that registered this agent (bound to `session_key`).
    ///
    /// The owner key is required to create or update the registry entry
    /// (SAFETY-015: widening requires owner key).
    pub owner: Address,

    /// KYA tier at registration time (14 §7.2).
    ///
    /// `None` — anonymous (not registered). `Identified` — registered and
    /// owner-bound. `Verified` — identity attested + human-sponsorship link.
    pub kya_tier: KyaTier,

    /// Agent reputation score (0–[`REPUTATION_SCORE_MAX`]).
    ///
    /// Written by the Phase 4 reputation pipeline; read by Warden in Step 16.
    /// `0` = new / unscored; `REPUTATION_SCORE_MAX` = perfect record.
    pub reputation_score: u16,
}

// ── MandateReceipt (§11, P3·Step 17) ─────────────────────────────────────────

/// Canonical event signature for the `MandateReceipt` log topic[0].
///
/// Follows the Lemma event-signature convention (mirrors EVM `Event(types…)`):
/// `blake3(MANDATE_RECEIPT_EVENT_SIG)[0..32]` gives the deterministic topic hash.
/// Named constant per AGENTS §3.3.
///
/// ## Encoding note (JSON vs ABI)
///
/// `topic[0]` is derived from this ABI-style signature string for explorer/SDK
/// filtering compatibility. **`Log.data` is JSON-encoded** (not ABI-encoded) in
/// Phase 3 for human-readability and explorer friendliness. ABI-encoding of `data`
/// is deferred to Phase 4 (post-token LIP, §11.1 interop adapter).
/// SDK authors should decode `topic[0]` as a selector but parse `data` as JSON.
///
/// ## Field order (matches `MandateReceipt` struct definition)
///
/// `address`=owner, `bytes`=session_key, `bytes32`=policy_hash, `string`=action,
/// `address`=target, `uint128`=value, `uint128`=budget_remaining,
/// `uint64`=epoch, `string`=kya_tier, `bool`=cosigned.
pub const MANDATE_RECEIPT_EVENT_SIG: &[u8] =
    b"MandateReceipt(address,bytes,bytes32,string,address,uint128,uint128,uint64,string,bool)";

/// Structured AP2-aligned Mandate Receipt emitted on every applied agent tx (14 §11).
///
/// Maps onto Google AP2's Cart Mandate: the exact executed terms paired with
/// the Intent Mandate (`AgentPolicy`) to form a **non-repudiable audit trail**:
/// - **WHO** acted under **WHOSE** authority, under **WHICH** policy snapshot.
/// - **WHAT** was done (action, target, value).
/// - **Accountability** (budget remaining after the tx).
/// - **Verification** (KYA tier, human co-sign).
///
/// Serialized to JSON and stored in `Log.data` under `address = Address::warden()`
/// so the explorer and SDK can filter all agent activity by topic[0].
///
/// ## Determinism (AGENTS §7.1)
///
/// All fields are plain scalars or `#[serde]`-compatible types. No `SystemTime`,
/// no RNG, no `HashMap`. JSON serialization of these types is fully deterministic.
///
/// ## Privacy (14 §10, future)
///
/// Privacy-sensitive receipts can be emitted under Veil (shielded log) and
/// revealed via the owner's viewing key. This is a Phase 4 / post-Veil concern;
/// Step 17 emits plaintext receipts on the transparent settlement path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandateReceipt {
    /// Owner address under whose authority the agent acted.
    pub owner: Address,

    /// Session key public key bytes (identifies the specific agent).
    pub session_key: Vec<u8>,

    /// `blake3` hash of the serialized `AgentPolicy` at execution time.
    ///
    /// This is the "Intent Mandate" fingerprint — a deterministic snapshot of
    /// the policy the agent operated under. Computed from the post-commit policy
    /// (counters already updated), so it reflects the exact authority state after
    /// the tx was applied.
    pub policy_hash: Hash,

    /// Action class of the applied transaction (Transfer, ContractCall, PayAgent, …).
    pub action: Action,

    /// Recipient address, if any (`None` for `ContractDeploy`).
    pub target: Option<Address>,

    /// Value transferred in Drop (native LEM, for non-zero-value txs).
    pub value: Amount,

    /// Lifetime budget remaining after this tx (`budget_total - spent_total`).
    ///
    /// Provides accountability signal: how much authority the agent still holds.
    pub budget_remaining: Amount,

    /// Epoch at which the tx was applied.
    pub epoch: u64,

    /// KYA tier of the agent's session key at time of execution.
    pub kya_tier: KyaTier,

    /// Whether the tx carried a valid owner co-signature (`tx.has_owner_cosignature()`).
    ///
    /// Maps to AP2's "human-in-the-loop" field. `true` means a human explicitly
    /// approved this specific tx (co-sign step-up, 14 §2.3.4).
    pub cosigned: bool,
}

impl MandateReceipt {
    /// Encode this receipt as a `Log` for inclusion in the `TransactionReceipt`.
    ///
    /// - `address` = `Address::warden()` — protocol-level event, not contract-level.
    /// - `topics[0]` = `blake3(MANDATE_RECEIPT_EVENT_SIG)` — deterministic event selector.
    /// - `data` = JSON-serialized receipt bytes.
    ///
    /// ## Determinism (AGENTS §7.1)
    ///
    /// `blake3` of a fixed byte string is always the same. `serde_json::to_vec`
    /// on `MandateReceipt` is deterministic: field order is fixed by the struct
    /// definition, all inner types serialize to deterministic forms (BTreeSet,
    /// hex strings for `Address`/`Hash`, decimal strings for `Amount`).
    ///
    /// ## No-panic guarantee (AGENTS §7.2)
    ///
    /// `serde_json::to_vec` cannot fail for `MandateReceipt` (all fields are
    /// JSON-serializable). On the off-chance it does (future non-serializable
    /// field added), `data` is an empty byte slice — the log is still emitted,
    /// just without structured content.
    #[must_use]
    pub fn to_log(&self) -> Log {
        // Sanctioned direct `blake3::hash` — `lemma-core` cannot depend on
        // `lemma-crypto` (circular). See `lemma-crypto/src/hashing.rs` doc header.
        let sig_hash = blake3::hash(MANDATE_RECEIPT_EVENT_SIG);
        let topic = Hash::from_bytes(*sig_hash.as_bytes());
        let data = serde_json::to_vec(self).unwrap_or_default();
        Log::new(Address::warden(), vec![topic], data)
    }
}

/// Know Your Agent tier (14 §7.2).
///
/// DEFERRED(Step 16): Not enforced by `warden_check` until P3·Step 16
/// (A2A counterparty check requires KYA tier comparison).
///
/// See living-notes kya-tier-ordering-1: enum discriminant comparison
/// is handled here in Rust via `#[derive(PartialOrd, Ord)]` with explicit
/// discriminants. The Lem-language-level ordering (for contract code) is
/// a separate concern deferred to Step 16.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum KyaTier {
    /// Anonymous session key (still Warden-bounded).
    #[default]
    None = 0,
    /// Agent registered in the Identity Registry, bound to an owner.
    Identified = 1,
    /// Owner identity attested + human-sponsorship link.
    Verified = 2,
}

// ── AgentPolicy ──────────────────────────────────────────────────────────────

/// A bounded authority grant attached to a session key.
///
/// Stored on-chain under the owner account; checked by Warden each tx.
/// All amounts in Drop; all time in epoch terms (deterministic).
///
/// See 14-AGENT_LAYER §2.1.
///
/// ## Core fields (enforced by Step 13)
///
/// `session_key`, `expiry_epoch`, `budget_total`, `per_tx_cap`, `per_epoch_cap`,
/// `allowed_targets`, `allowed_actions`, `spent_total`, `spent_this_epoch`,
/// `last_epoch`.
///
/// ## Extension fields (placeholder — enforced by later steps)
///
/// See the module docs for the deferred-field table.
///
/// ## Invariant (load-bearing, 14 §2.2)
///
/// An agent transaction can only *narrow or consume* its policy, never widen it.
/// Any path that would increase an agent's authority must be authorized by the
/// **owner key**, not the session key. Enforced by SAFETY-015 (compile-time)
/// and Warden (runtime).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPolicy {
    // ── Core fields (Step 13) ────────────────────────────────────────────
    /// The public key bytes of the session key this policy is for.
    pub session_key: Vec<u8>,
    /// Hard expiry epoch — policy is inert at and after this epoch.
    pub expiry_epoch: u64,
    /// Lifetime spend ceiling for this grant (in Drop).
    pub budget_total: Amount,
    /// Max value per single transaction (in Drop).
    pub per_tx_cap: Amount,
    /// Max value per epoch — the deterministic "daily limit" (in Drop).
    pub per_epoch_cap: Amount,
    /// Contracts/addresses the agent may call.
    pub allowed_targets: AllowList,
    /// Actions the agent may perform.
    pub allowed_actions: ActionMask,
    /// Mutable counter: total spent lifetime (Warden updates on success).
    pub spent_total: Amount,
    /// Mutable counter: spent this epoch (resets at epoch boundary).
    pub spent_this_epoch: Amount,
    /// The epoch when `spent_this_epoch` was last valid. When the current
    /// epoch exceeds this, `spent_this_epoch` is lazily reset to 0.
    pub last_epoch: u64,

    // ── Extension fields (Step 14 — now enforced) ────────────────────────
    /// Streaming allowance: budget added each epoch (14 §2.3.1).
    ///
    /// At each epoch boundary (lazy reset in `warden_check`), `budget_total`
    /// is incremented by `refill_per_epoch` up to `budget_ceiling` (if set)
    /// via checked arithmetic. 0 = static (no refill). Owner-only to set.
    #[serde(default = "Amount::zero")]
    pub refill_per_epoch: Amount,

    /// Optional ceiling for `budget_total` when streaming refill is active.
    ///
    /// When `refill_per_epoch > 0`, `budget_total` grows each epoch but is
    /// capped at `budget_ceiling` (if `Some`). `None` = no ceiling (budget
    /// grows unboundedly, limited only by `u128::MAX`). Ignored when
    /// `refill_per_epoch == 0`. Owner-only to set.
    #[serde(default)]
    pub budget_ceiling: Option<Amount>,

    /// Named per-category spending sub-budgets (14 §2.3.2).
    ///
    /// If the action matches a category, the per-category cap is checked in
    /// addition to the per-epoch and budget caps. Category `spent` counters
    /// reset at each epoch boundary alongside `spent_this_epoch`. Max
    /// [`MAX_CATEGORIES`] entries. Empty = no category checks.
    #[serde(default)]
    pub categories: CategoryCaps,

    /// Active time-window: agent may only act within \[start, end\] epochs.
    ///
    /// Checked in `warden_check` after the expiry check. Generalizes
    /// `expiry_epoch` (the window's hard upper bound). `None` = no window
    /// restriction. See 14-AGENT_LAYER §2.3.3.
    #[serde(default)]
    pub active_window: Option<EpochRange>,

    /// Co-sign threshold: value ≥ threshold → tx pends for owner co-sign.
    ///
    /// If `tx.value >= cosign_threshold` and the tx lacks an owner
    /// co-signature, `warden_check` returns `Ok(PendingOwnerCosign)`.
    /// The executor produces a failed receipt without committing state.
    /// The owner resubmits after attaching their co-signature.
    /// `None` = co-sign step-up disabled. See 14-AGENT_LAYER §2.3.4.
    #[serde(default)]
    pub cosign_threshold: Option<Amount>,

    /// Dead-man's switch: auto-revoke after N violations per epoch.
    ///
    /// On each `PolicyViolation`, the executor increments
    /// `auto_revoke.violations_this_epoch`. When it reaches
    /// `max_violations_per_epoch` (if > 0), `expiry_epoch` is set to
    /// `current_epoch` — instant revocation. See 14-AGENT_LAYER §2.3.5.
    #[serde(default)]
    pub auto_revoke: AutoRevoke,

    // ── Extension fields (P3·Step 15 — now enforced) ─────────────────────
    /// Anomaly guard configuration (opt-in, 14 §9.1, P3·Step 15 ✅).
    ///
    /// When `anomaly.enabled = true` and `history.has_history = true`, the
    /// anomaly guard runs after the co-sign check and flags behavioral
    /// deviations (value spike, burst rate) as `AnomalyHold` violations.
    /// The dead-man's switch IS incremented for `AnomalyHold` (§9.1).
    ///
    /// Default: disabled. Owner-only to enable (SAFETY-015).
    #[serde(default)]
    pub anomaly: AnomalyConfig,

    /// Committed behavioral history for the anomaly guard (14 §9.1, P3·Step 15 ✅).
    ///
    /// Updated on each successful warden-applied tx (`update_history`) and at
    /// each epoch boundary (`apply_epoch_reset`). Always committed to state on
    /// full success; never speculatively modified on PendingOwnerCosign/errors.
    #[serde(default)]
    pub history: AnomalyHistory,

    // ── Extension fields (P3·Step 16 — now enforced) ─────────────────────
    /// Minimum KYA tier required of A2A counterparties (14 §8, P3·Step 16 ✅).
    ///
    /// When a `PAY_AGENT` tx is detected (recipient is a registered agent),
    /// `warden_check` reads the payee's `AgentIdentity` and rejects with
    /// `CounterpartyRejected` if `payee.kya_tier < required_kya_tier`.
    ///
    /// Default: `KyaTier::None` — no minimum tier required (gate disabled).
    /// Setting to `Identified` or `Verified` opts in to counterparty checking.
    /// Owner-only to set (SAFETY-015: widening requires owner key).
    ///
    /// Uses `KyaTier`'s `Ord` derive (`#[repr(u8)]` None=0 < Identified=1 <
    /// Verified=2) — VM-layer comparison is `<` on discriminants.
    #[serde(default)]
    pub required_kya_tier: KyaTier,

    /// Minimum reputation score required of A2A counterparties (14 §8, P3·Step 16 ✅).
    ///
    /// When `PAY_AGENT` is detected and `min_counterparty_reputation > 0`,
    /// `warden_check` rejects with `CounterpartyRejected` if the payee's
    /// `AgentIdentity.reputation_score < min_counterparty_reputation`.
    ///
    /// Default: `0` — no minimum reputation required (gate disabled).
    /// Scale: `[0, REPUTATION_SCORE_MAX]` (0–100). Owner-only to set.
    #[serde(default)]
    pub min_counterparty_reputation: u16,

    // ── Extension fields (this agent's own tier — Steps 13/16) ───────────
    /// KYA tier for **this agent** (not its counterparties — see `required_kya_tier`).
    ///
    /// Written into the Identity Registry at registration time. Read by
    /// counterparties' Warden checks when this agent is the payee in A2A txs.
    /// Default: `KyaTier::None` (unregistered agent).
    #[serde(default)]
    pub kya_tier: KyaTier,
    // ── Extension fields (Step 17 — deferred) ────────────────────────────
    // (no deferred policy fields for Step 17; Mandate Receipts are emitted
    // in warden.rs after counter commit, not stored in AgentPolicy)
}

// ── PolicyViolation ──────────────────────────────────────────────────────────

/// Why a Warden policy check failed.
///
/// Each variant corresponds to a specific check in `warden_check`
/// (14-AGENT_LAYER §3). The variant carries enough context for informative
/// error messages (AGENTS §12.2).
///
/// `#[non_exhaustive]` — Steps 14–17 will add new variants.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyViolation {
    /// No policy found for this (owner, session_key) pair.
    #[error("agent policy not found for session key")]
    PolicyNotFound,

    /// Session key has expired (epoch >= expiry_epoch).
    #[error("agent policy expired at epoch {expiry_epoch} (current: {current_epoch})")]
    Expired {
        expiry_epoch: u64,
        current_epoch: u64,
    },

    /// The action is not in the policy's allowed actions mask.
    #[error("action {action} denied by agent policy")]
    ActionDenied { action: Action },

    /// The target address is not in the policy's allowed targets list.
    #[error("target {target} denied by agent policy")]
    TargetDenied { target: Address },

    /// Transaction value exceeds the per-tx cap.
    #[error("per-tx cap exceeded: value {value} > cap {cap}")]
    PerTxExceeded { value: Amount, cap: Amount },

    /// Epoch spending would exceed the per-epoch cap.
    #[error("per-epoch cap exceeded: epoch total {epoch_total} > cap {cap}")]
    PerEpochExceeded { epoch_total: Amount, cap: Amount },

    /// Lifetime spending would exceed the budget total.
    #[error("budget exceeded: lifetime total {lifetime_total} > budget {budget}")]
    BudgetExceeded {
        lifetime_total: Amount,
        budget: Amount,
    },

    /// Checked arithmetic overflow during cap computation.
    #[error("arithmetic overflow in policy check")]
    Overflow,

    /// Transaction is outside the agent's allowed time window.
    ///
    /// Added P3·Step 14 (14 §2.3.3). The agent may only act when
    /// `start_epoch <= current_epoch <= end_epoch`.
    #[error(
        "agent inactive: current epoch {current_epoch} outside allowed window \
         [{start_epoch}, {end_epoch}]"
    )]
    OutsideWindow {
        current_epoch: u64,
        start_epoch: u64,
        end_epoch: u64,
    },

    /// Transaction would exceed a per-category spending sub-budget.
    ///
    /// Added P3·Step 14 (14 §2.3.2). `category` names the exceeded budget;
    /// `spent` is what the total would be; `cap` is the limit.
    #[error("category cap exceeded: {category} would be {spent}, cap is {cap}")]
    CategoryExceeded {
        /// Name of the spending category that was exceeded.
        category: String,
        /// Projected total (after this tx) in Drop.
        spent: Amount,
        /// Category cap in Drop.
        cap: Amount,
    },

    /// All agents under this owner are paused (14 §2.4, P3·Step 15 ✅).
    ///
    /// The owner called the kill switch (`write_owner_paused(true)`), freezing
    /// every session-key transaction instantly. Checked at Step 0 in
    /// `warden_check` — before the policy is read — so no dead-man's switch
    /// increment occurs. The executor skips `handle_violation` for this variant.
    ///
    /// Enforced at the compile-time layer by **SAFETY-017** (`09 §3-bis`).
    #[error("all agents paused by owner kill switch (14 §2.4)")]
    AgentsPaused,

    /// Transaction flagged by the anomaly guard (14 §9.1, P3·Step 15 ✅).
    ///
    /// `reason` describes which behavioral signal triggered the hold (value spike
    /// or burst rate). The dead-man's switch IS incremented for this variant
    /// (§9.1 explicit: "the dead-man's switch counter increments").
    ///
    /// The tx is held, not permanently rejected — the owner inspects the audit
    /// signal and may re-submit after reviewing/pausing.
    #[error("anomaly guard hold: {reason}")]
    AnomalyHold {
        /// Human-readable description of the triggering signal.
        reason: String,
    },
    /// A2A counterparty does not meet KYA/reputation requirements (14 §8, P3·Step 16 ✅).
    ///
    /// Fired when the payee is a registered agent but their `kya_tier` is
    /// below `policy.required_kya_tier`, or their `reputation_score` is below
    /// `policy.min_counterparty_reputation`. The dead-man's switch IS
    /// incremented — attempting to pay an unqualified counterparty is a
    /// policy misbehavior, not an expected condition.
    ///
    /// Carries both tier AND reputation context regardless of which gate fired,
    /// so the error message is always informative (AGENTS §12.2).
    #[error(
        "A2A counterparty rejected: {reason} \
         (required tier: {required_tier:?}, actual tier: {actual_tier:?}; \
          required reputation: {required_reputation}, actual reputation: {actual_reputation})"
    )]
    CounterpartyRejected {
        /// Human-readable reason (which check failed: tier or reputation).
        reason: &'static str,
        /// Minimum KYA tier the policy required.
        required_tier: KyaTier,
        /// Actual KYA tier of the counterparty.
        actual_tier: KyaTier,
        /// Minimum reputation score the policy required (0 if tier gate fired first).
        required_reputation: u16,
        /// Actual reputation score of the counterparty (0 if tier gate fired first).
        actual_reputation: u16,
    },

    /// Counterparty is required to be a registered agent but is not (14 §8, P3·Step 16 ✅).
    ///
    /// Fired when `policy.required_kya_tier > KyaTier::None` OR
    /// `policy.min_counterparty_reputation > 0`, meaning the policy opts in to
    /// A2A counterparty verification, but `tx.to` is not present in the Identity
    /// Registry — the payee's credentials cannot be verified, so the tx is
    /// rejected. The dead-man's switch IS incremented (same rationale as
    /// `CounterpartyRejected`).
    #[error("A2A counterparty required but {target} is not a registered agent")]
    MissingCounterparty {
        /// The unregistered recipient address.
        target: Address,
    },
    // DEFERRED(Step 17): no additional PolicyViolation variants needed for
    // Mandate Receipt emission (receipts are emitted after counter commit,
    // not a rejection path).
}

// ── WardenOutcome ────────────────────────────────────────────────────────────

/// Successful outcome of a Warden policy check.
///
/// Not every `Ok` outcome applies the transaction — `PendingOwnerCosign`
/// holds the tx for owner approval without committing state.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WardenOutcome {
    /// Transaction passed all policy checks; counters updated in state.
    Applied,

    /// Transaction value meets or exceeds `cosign_threshold` but the tx does
    /// not carry an owner co-signature (14 §2.3.4, P3·Step 14).
    ///
    /// The executor must discard scratch (state NOT committed) and produce a
    /// failed receipt. The owner re-submits the tx with
    /// `Transaction::owner_cosignature` set. This is NOT a `PolicyViolation`
    /// — the dead-man's switch is NOT incremented for this outcome.
    PendingOwnerCosign,
    // DEFERRED(Step 15/16/17): future outcomes here.
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
