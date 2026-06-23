//! # Warden — deterministic policy enforcement for agent transactions
//!
//! Implements the `warden_check` algorithm from 14-AGENT_LAYER §3.
//! Warden is a pre-application check on every transaction signed by a
//! session key. It runs inside the deterministic settlement boundary
//! (08-EXECUTION_SPEC §5 — returns `Result`, never panics).
//!
//! ## What Steps 13–16 enforce (full core + extensions + kill switch + A2A + anomaly)
//!
//! - **0. Owner kill switch** — `agents_paused` → `AgentsPaused`. (Step 15)
//! - **1. Expiry** — `epoch >= policy.expiry_epoch` → reject. (Step 13)
//! - **2. Active window** — `epoch` outside `active_window` → reject. (Step 14)
//! - **3. Action allow-list** — `classify_action(tx)` vs `ActionMask`. (Step 13)
//! - **4. Target allow-list** — `tx.to` vs `AllowList`. (Step 13)
//! - **3b. A2A counterparty check** — registered-agent recipient → `PayAgent`; KYA/rep gate. (Step 16)
//! - **5. Per-tx cap** — `tx.value > per_tx_cap` → reject. (Step 13)
//! - **6. Per-category sub-budget** — `tx` action vs `CategoryCaps`. (Step 14)
//! - **7. Epoch reset (lazy)** — reset counters + streaming refill on epoch advance. (Step 13/14)
//! - **8. Per-epoch cap** — `spent_this_epoch + value > per_epoch_cap` → reject. (Step 13)
//! - **9. Budget total** — `spent_total + value > budget_total` → reject. (Step 13)
//! - **10. Co-sign step-up** — large tx without owner co-sig → `PendingOwnerCosign`. (Step 14)
//! - **11. Anomaly guard** — behavioral deviation → `AnomalyHold` (opt-in). (Step 15)
//! - **12. Counter commit** — update spent + category + history counters. (Step 13/14/15)
//!
//! ## Dead-man's switch (Step 14)
//!
//! On `PolicyViolation`, the **executor caller** (not `warden_check` itself)
//! increments `auto_revoke.violations_this_epoch`. When this reaches
//! `max_violations_per_epoch` (if > 0), the policy is immediately expired.
//! Use [`handle_violation`] in the executor for this logic.
//!
//! ## What later steps add
//!
//! P3·Steps 13–17 are now complete. Step 17 mandate receipts are emitted by the
//! executor via [`build_mandate_receipt_log`] after every `WardenOutcome::Applied`.
//!
//! ## Determinism (AGENTS §7.1)
//!
//! - All inputs come from the transaction and committed state — no wall-clock,
//!   no RNG, no `HashMap`.
//! - All arithmetic is checked (AGENTS §7.4).
//! - Policy state is keyed by `(owner, session_key)` and participates in Flux
//!   MVCC — two agent txs touching the same policy are serialized by `txn_idx`.
//!
//! ## No-panic guarantee (AGENTS §7.2)
//!
//! Every function in this module returns `Result`. No `unwrap()`, no `panic!()`.

use lemma_core::{
    address::Address,
    agent::{
        Action, AgentPolicy, KyaTier, MandateReceipt, PolicyViolation, WardenOutcome,
        ANOMALY_NOVEL_TARGET_HIGH_VALUE_PCT, MAX_SEEN_TARGETS,
    },
    amount::Amount,
    transaction::{Log, Transaction, TxType},
};

use crate::state::ContractStateView;

// ── System address for Warden policy storage ─────────────────────────────────

/// Reserved system address for Warden agent policy storage.
///
/// `blake3(b"lemma:system:warden")[0..20]` — a deterministic reserved
/// address that will never collide with contract deploys
/// (`Address::from_deployer` uses `blake3(deployer ++ nonce)`).
///
/// Policies are stored as serialized bytes under this address's storage
/// namespace, keyed by `POLICY_KEY_PREFIX ++ owner ++ session_key`.
///
/// Mirrors the registry system contract pattern (DB-A54, `Address::registry()`).
///
/// Not `const`: `Address::warden()` calls `blake3::hash` which is not
/// const-evaluable. This is called on every agent tx — the cost of one
/// blake3 hash (20-byte truncation) is negligible vs the state read/write.
fn warden_system_addr() -> Address {
    Address::warden()
}

/// Key prefix for agent policy storage entries.
///
/// Full key layout (deterministic — AGENTS §7.1):
/// ```text
/// b"warden:policy:" ++ owner.as_bytes() (20) ++ session_key_bytes (variable)
/// ```
const POLICY_KEY_PREFIX: &[u8] = b"warden:policy:";

/// Key prefix for the owner-level pause flag (kill switch, 14 §2.4, P3·Step 15).
///
/// Full key layout:
/// ```text
/// b"warden:paused:" ++ owner.as_bytes() (20)
/// ```
///
/// Separate from policy keys — the kill switch is owner-level (one flag
/// freezes ALL agents for that owner) rather than per-session-key.
/// Existence of the key = paused; absent = not paused (no value bytes needed).
const OWNER_PAUSE_KEY_PREFIX: &[u8] = b"warden:paused:";

// ── Kill switch state helpers (§2.4) ─────────────────────────────────────────

/// Build the storage key for the owner-level pause flag.
///
/// Key = `OWNER_PAUSE_KEY_PREFIX ++ owner.as_bytes()` (34 bytes total).
fn owner_pause_key(owner: &Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(OWNER_PAUSE_KEY_PREFIX.len() + 20);
    key.extend_from_slice(OWNER_PAUSE_KEY_PREFIX);
    key.extend_from_slice(owner.as_bytes());
    key
}

/// Returns `true` if the owner has paused all their agents (kill switch active).
///
/// Uses `ContractStateView::exists` — a single existence check; no byte
/// allocation needed since the key presence is the flag.
fn read_owner_paused<S: ContractStateView>(state: &S, owner: &Address) -> bool {
    state.exists(&warden_system_addr(), &owner_pause_key(owner))
}

/// Write (or clear) the owner-level agent pause flag (14 §2.4 kill switch).
///
/// * `paused = true` — freeze ALL agents for this owner instantly.
/// * `paused = false` — unfreeze; agents resume normal policy checks.
///
/// Called by owner-authorized transactions (not by Warden itself — Warden
/// only reads this flag). The owner tx must carry the owner's private key,
/// not a session key (SAFETY-017).
///
/// ## Production caller (DEFERRED — kill-switch-write-gap)
///
/// The owner-tx handler that routes `TxType::PauseAgents` (or equivalent)
/// through the executor has not been built yet. This function is currently
/// `#[cfg(test)]` — it is verified by `warden/tests.rs` and records the
/// correct API contract. Remove `#[cfg(test)]` when the owner-tx handler
/// lands and wires this into the execution pipeline.
///
/// Technical debt: `kill-switch-write-gap` in living-notes.
///
/// ## No-panic guarantee (AGENTS §7.2)
///
/// `state.write` / `state.delete` are infallible per `ContractStateView` contract.
#[cfg(test)]
pub(crate) fn write_owner_paused<S: ContractStateView>(
    state: &mut S,
    owner: &Address,
    paused: bool,
) {
    let addr = warden_system_addr();
    let key = owner_pause_key(owner);
    if paused {
        // Store a single sentinel byte (value irrelevant; key existence = paused).
        state.write(&addr, &key, vec![0x01]);
    } else {
        state.delete(&addr, &key);
    }
}

// ── Policy state helpers ─────────────────────────────────────────────────────

/// Build the storage key for an agent policy.
///
/// Key = `POLICY_KEY_PREFIX ++ owner.as_bytes() ++ session_key_bytes`.
/// Deterministic for the same inputs (AGENTS §7.1).
fn policy_state_key(owner: &Address, session_key: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(POLICY_KEY_PREFIX.len() + 20 + session_key.len());
    key.extend_from_slice(POLICY_KEY_PREFIX);
    key.extend_from_slice(owner.as_bytes());
    key.extend_from_slice(session_key);
    key
}

/// Read an agent policy from state.
///
/// Returns `None` if no policy exists for this `(owner, session_key)` pair.
/// Returns `None` (with a warning log) if the stored bytes are corrupt.
///
/// ## No-panic guarantee (AGENTS §7.2)
///
/// Corrupt JSON → `None` (no policy found), not a panic.
pub(crate) fn read_policy<S: ContractStateView>(
    state: &S,
    owner: &Address,
    session_key: &[u8],
) -> Option<AgentPolicy> {
    let key = policy_state_key(owner, session_key);
    let addr = warden_system_addr();
    let bytes = state.read(&addr, &key)?;
    match serde_json::from_slice(&bytes) {
        Ok(policy) => Some(policy),
        Err(e) => {
            tracing::warn!(
                owner = %owner,
                error = %e,
                "warden: corrupt policy JSON — treating as no policy"
            );
            None
        }
    }
}

/// Write an agent policy to state.
///
/// Serializes the policy as JSON and stores it under the Warden system address.
/// Called after successful `warden_check` to persist updated counters, and by
/// `handle_violation` to persist the violation counter even on failed txs.
///
/// Returns `false` if serialization fails (should never happen for `AgentPolicy`,
/// but we log and skip rather than panic — AGENTS §7.2 no-panic guarantee).
pub(crate) fn write_policy<S: ContractStateView>(
    state: &mut S,
    owner: &Address,
    session_key: &[u8],
    policy: &AgentPolicy,
) -> bool {
    let key = policy_state_key(owner, session_key);
    match serde_json::to_vec(policy) {
        Ok(bytes) => {
            let addr = warden_system_addr();
            state.write(&addr, &key, bytes);
            true
        }
        Err(e) => {
            // This branch is unreachable for AgentPolicy (all fields are
            // JSON-serializable plain data). But: a future step adding a
            // non-trivially-serializable field could reach it. Log and skip
            // rather than panic — AGENTS §7.2 no-panic settlement path.
            tracing::warn!(
                owner = %owner,
                error = %e,
                "warden: policy serialization failed — counters NOT persisted"
            );
            false
        }
    }
}

// ── Action classification ────────────────────────────────────────────────────

/// Classify a transaction's action for policy checking.
///
/// Maps from [`TxType`] to [`Action`]. This is the `classify_action(tx)`
/// function from 14-AGENT_LAYER §3.
///
/// ## A2A detection (P3·Step 16)
///
/// `PayAgent` is NOT detected here — `classify_action` is purely TxType-driven
/// and therefore stateless. A2A detection requires a registry lookup (committed
/// state) which happens in step 3b of `warden_check` after the target allow-list.
/// See DB-A67 for the rationale (no new TxType / no new mempool path).
pub(crate) fn classify_action(tx: &Transaction) -> Action {
    match tx.tx_type {
        TxType::Transfer => Action::Transfer,
        TxType::ContractCall => Action::ContractCall,
        TxType::ContractDeploy => Action::ContractDeploy,
        TxType::Stake => Action::Stake,
        TxType::Unstake => Action::Unstake,
        TxType::GovernanceVote => Action::GovernanceVote,
        // #[non_exhaustive] catch-all: future TxType variants (Step 21
        // cross-contract, etc.) not yet mapped. GovernanceVote is an unlikely
        // mask entry → fail-closed; add an explicit arm when a new TxType lands.
        //
        // NOTE: `PayAgent` is NOT detected here. A2A payments use the same
        // existing TxTypes (Transfer/ContractCall); `PayAgent` is classified by
        // `warden_check` step 3b via Identity Registry lookup — no new TxType,
        // no new mempool path (DB-A67; spec §8 "composes existing primitives").
        _ => Action::GovernanceVote,
    }
}

// ── Anomaly guard (§9.1, P3·Step 15) ────────────────────────────────────────

/// Deterministic behavioral anomaly detection (14 §9.1, P3·Step 15).
///
/// A pure function of **committed on-chain state only** — no wall-clock,
/// no RNG, no `HashMap`, no off-chain data (AGENTS §7.1; SAFETY-019
/// enforced by the Lem compiler for contract code; this is the VM layer).
///
/// Returns `Some(&'static str)` naming the triggering signal if the tx
/// exhibits suspicious behavioral deviation, `None` if normal.
///
/// ## Signals
///
/// **Signal 1 — Value spike**: `tx.value > avg_value_ema × spike_ratio / 100`.
/// Catches sudden jumps in *native LEM* value above the established baseline.
///
/// **`tx.value` vs spec `value_out()`**: The spec pseudocode (§3 line 168) uses
/// `tx.value_out()` as a conceptual name for "value leaving the agent." In the
/// current B4/B5 type model, `tx.value` is the only value field; there is no
/// `value_out()` method. Token transfers via `ContractCall` carry economic value
/// in calldata and have `tx.value == 0`, so Signal 1 does **not** catch native-
/// value-zero token drains. Token outflow accounting (calldata parsing) is deferred
/// to Phase 4 when the contract ABI layer lands. Until then, token outflows are
/// bounded by per-tx and per-epoch *caps* but are invisible to the value-EMA
/// baseline. This is a known and documented limitation (CR-S15-1/S15-3).
///
/// **Signal 2 — Burst rate**: `tx_count_this_epoch > avg_tx_count_ema × burst_ratio / 100`.
/// Catches an agent suddenly submitting far more txs than its established cadence.
/// Note: a single-epoch smash-and-grab (all txs in one epoch, count starts at 0)
/// cannot exceed the burst threshold until count reaches `avg × ratio / 100`,
/// which means the first ~`avg × ratio / 100` txs of any epoch are unconditionally
/// allowed. The hard per-epoch cap still bounds total outflow.
///
/// **Signal 3 — Novel high-value target** (spec §9.1 third signal):
/// A tx to a target address never seen before AND `tx.value ≥ per_tx_cap × 50%`
/// is flagged. Bounded to the first [`MAX_SEEN_TARGETS`] known addresses —
/// once the set is full, this signal is disabled (established breadth = not novel).
///
/// ## Arithmetic (no division, no floating point)
///
/// Comparisons are rewritten to avoid integer division truncation:
/// `a > b × ratio / 100` → `a × 100 > b × ratio`. Uses `saturating_mul`
/// (no panics — AGENTS §7.2).
///
/// ## Caller precondition
///
/// Callers MUST guard with `policy.anomaly.enabled && policy.history.has_history`
/// before calling.
///
/// ## Honest limit (mirrors §9.1 note)
///
/// Catches *behavioral* deviation, not semantic intent. A tripwire that buys the
/// owner time + an audit signal, not a judgment oracle. Combined with hard caps.
fn anomaly_detected(policy: &AgentPolicy, tx: &Transaction) -> Option<&'static str> {
    // Signal 1: native-LEM value spike.
    // NOTE: tx.value is native LEM only; token-calldata value is not captured
    // here (see CR-S15-1/S15-3 doc above; deferred to Phase 4 ABI layer).
    if policy.history.avg_value_ema > Amount::zero() {
        let avg = policy.history.avg_value_ema.as_drop();
        let value = tx.value.as_drop();
        // value × 100 > avg × spike_ratio ⟺ value > avg × spike_ratio / 100
        if value.saturating_mul(100) > avg.saturating_mul(u128::from(policy.anomaly.spike_ratio)) {
            return Some("value spike: tx value exceeds spike_ratio x historical average");
        }
    }

    // Signal 2: burst rate.
    // NOTE: single-epoch drains are bounded by per-epoch cap, not this signal.
    if policy.history.avg_tx_count_ema > 0 {
        let avg = u32::from(policy.history.avg_tx_count_ema);
        let current = u32::from(policy.history.tx_count_this_epoch);
        // current × 100 > avg × burst_ratio
        if current.saturating_mul(100) > avg.saturating_mul(u32::from(policy.anomaly.burst_ratio)) {
            return Some("burst rate: tx count exceeds burst_ratio x historical average");
        }
    }

    // Signal 3: novel high-value target (§9.1 third signal).
    //
    // Only active while `seen_targets.len() < MAX_SEEN_TARGETS`. Once the set is
    // at capacity the signal is disabled (agents with many known counterparties
    // have established breadth — the signal loses discriminative power).
    //
    // High-value threshold: tx.value ≥ per_tx_cap × ANOMALY_NOVEL_TARGET_HIGH_VALUE_PCT / 100
    // Written as: tx.value × 100 ≥ per_tx_cap × PCT (avoids division, AGENTS §7.1).
    if let Some(target) = tx.to {
        if policy.history.seen_targets.len() < MAX_SEEN_TARGETS
            && !policy.history.seen_targets.contains(&target)
        {
            // Novel target — check if value is high enough to flag.
            let cap = policy.per_tx_cap.as_drop();
            let value = tx.value.as_drop();
            // value × 100 >= cap × PCT
            if value.saturating_mul(100)
                >= cap.saturating_mul(u128::from(ANOMALY_NOVEL_TARGET_HIGH_VALUE_PCT))
            {
                return Some(
                    "novel high-value target: never-before-seen target at >= 50% of per-tx cap",
                );
            }
        }
    }

    None
}

/// Update the behavioral history after a successfully warden-applied tx (14 §9.1).
///
/// Updates the value EMA and increments `tx_count_this_epoch`. Called from
/// the counter-commit step in `warden_check` when `policy.anomaly.enabled`.
///
/// ## EMA formula (1/8 alpha — TCP RTT-style, AGENTS §7.1)
///
/// ```text
/// new_ema = old_ema − (old_ema >> 3) + (value >> 3)
///         = (7/8) × old_ema + (1/8) × value
/// ```
///
/// Integer-only; no floating point. Uses `saturating_sub` / `saturating_add`
/// for safety (AGENTS §7.2 no-panic guarantee).
fn update_history(policy: &mut AgentPolicy, tx: &Transaction, value: Amount) {
    // Value EMA update (1/8 alpha).
    let old = policy.history.avg_value_ema.as_drop();
    let v = value.as_drop();
    let new_ema = old.saturating_sub(old >> 3).saturating_add(v >> 3);
    policy.history.avg_value_ema = Amount::from_drop(new_ema);

    // Increment this-epoch tx counter.
    policy.history.tx_count_this_epoch = policy.history.tx_count_this_epoch.saturating_add(1);

    // Record the target address for Signal 3 (novel high-value target).
    // Stop recording once the set reaches MAX_SEEN_TARGETS — after that the
    // signal is disabled (too many known counterparties to be meaningful).
    if let Some(target) = tx.to {
        if policy.history.seen_targets.len() < MAX_SEEN_TARGETS {
            policy.history.seen_targets.insert(target);
        }
    }
}

// ── Epoch reset helper ───────────────────────────────────────────────────────

/// Apply the deterministic epoch-boundary reset + streaming refill to a policy.
///
/// Called lazily inside `warden_check` and `handle_violation` on the first
/// Warden touch in a new epoch. Resets ALL per-epoch counters (spend, category
/// spent, violation counter) and applies streaming refill (§2.3.1).
///
/// Extracted as a canonical helper to prevent divergence between
/// `warden_check` and `handle_violation` (AGENTS §2 DRY, CodeReviewer M1).
///
/// ## Idempotency
///
/// Guarded by `epoch > policy.last_epoch` at the call site — only runs
/// once per epoch per policy regardless of how many txs touch it.
fn apply_epoch_reset(policy: &mut AgentPolicy, epoch: u64) {
    policy.spent_this_epoch = Amount::zero();
    policy.categories.reset_epoch();
    policy.auto_revoke.violations_this_epoch = 0;
    policy.last_epoch = epoch;

    // Streaming refill (§2.3.1): add refill_per_epoch to budget_total,
    // capped at budget_ceiling if set. checked_add overflow → keep current.
    if policy.refill_per_epoch > Amount::zero() {
        let refilled = policy
            .budget_total
            .checked_add(policy.refill_per_epoch)
            .unwrap_or(policy.budget_total);
        policy.budget_total = match policy.budget_ceiling {
            Some(ceiling) if refilled > ceiling => ceiling,
            _ => refilled,
        };
    }

    // Anomaly history: slide the tx-count EMA at epoch boundary (14 §9.1).
    // The completed epoch's `tx_count_this_epoch` feeds into `avg_tx_count_ema`
    // using the same 1/8-alpha EMA formula as the value EMA.
    // Reset `tx_count_this_epoch` to 0 for the new epoch.
    //
    // Bootstrap: set `has_history = true` after the first epoch boundary where
    // at least one tx was committed — gives the anomaly guard a baseline.
    let completed = policy.history.tx_count_this_epoch;
    let old_avg = policy.history.avg_tx_count_ema;
    policy.history.avg_tx_count_ema = old_avg
        .saturating_sub(old_avg >> 3)
        .saturating_add(completed >> 3);
    policy.history.tx_count_this_epoch = 0;
    if !policy.history.has_history && completed > 0 {
        policy.history.has_history = true;
    }
}

// ── Core enforcement algorithm ───────────────────────────────────────────────

/// Warden pre-application policy check (14-AGENT_LAYER §3, P3·Steps 13+14).
///
/// Runs on every transaction whose `session_key` is `Some`. Validates the
/// transaction against the agent's on-chain policy and updates spending
/// counters on success.
///
/// ## Arguments
///
/// * `tx` — the transaction to check. `tx.sender` is the owner address.
/// * `session_key` — the session key public key bytes (from `tx.session_key`).
/// * `epoch` — current epoch (from `BlockContext.epoch`).
/// * `state` — mutable scratch overlay; policy reads/writes land here and
///   are committed/discarded atomically with the transaction.
///
/// ## Returns
///
/// * `Ok(WardenOutcome::Applied)` — all checks passed, counters updated.
/// * `Ok(WardenOutcome::PendingOwnerCosign)` — co-sign threshold met but no
///   owner co-signature present; executor must discard scratch + fail receipt.
/// * `Err(PolicyViolation)` — check failed; call [`handle_violation`] to run
///   the dead-man's switch logic before discarding scratch.
///
/// ## Deferred (Step 15+)
///
/// - **Step 15**: Owner kill switch (`agents_paused`), anomaly guard (§2.4, §9).
///   Insert at TOP of this function (kill switch) and after co-sign (anomaly).
///   Add `AgentsPaused` and `AnomalyHold` variants to `PolicyViolation`.
///
/// - **Step 16**: A2A `PAY_AGENT` + counterparty KYA/reputation gate (§7–§8).
///   Insert after target allow-list check. Add `Action::PayAgent`,
///   `CounterpartyRejected`, `MissingCounterparty` variants.
///
/// - **Step 17** ✅: Mandate Receipt emission (§11) — emitted by the executor
///   via [`build_mandate_receipt_log`] after this function returns `Applied`.
pub(crate) fn warden_check<S: ContractStateView>(
    tx: &Transaction,
    session_key: &[u8],
    epoch: u64,
    state: &mut S,
) -> Result<WardenOutcome, PolicyViolation> {
    // ── 0. Owner kill switch (§2.4, P3·Step 15) ─────────────────────────
    //
    // Checked BEFORE reading the policy — one owner tx freezes ALL agents
    // instantly without revoking individual policies. Returns AgentsPaused
    // without reading or modifying policy state.
    //
    // The executor MUST NOT call `handle_violation` for this error: the kill
    // switch is an owner-initiated emergency freeze, not a per-policy
    // misbehavior. Penalizing the dead-man's switch would make it harder for
    // the owner to unpause and resume (see executor.rs).
    //
    // SAFETY-017: every @agentCallable entry must be dominated by this gate
    // (enforced by the Lem compiler; this is the VM-layer runtime enforcement).
    if read_owner_paused(state, &tx.sender) {
        return Err(PolicyViolation::AgentsPaused);
    }

    // ── Read policy from state ───────────────────────────────────────────

    let mut policy =
        read_policy(state, &tx.sender, session_key).ok_or(PolicyViolation::PolicyNotFound)?;

    // ── 1. Expiry check ──────────────────────────────────────────────────

    if epoch >= policy.expiry_epoch {
        return Err(PolicyViolation::Expired {
            expiry_epoch: policy.expiry_epoch,
            current_epoch: epoch,
        });
    }

    // ── 1b. Active window (§2.3.3, Step 14) ─────────────────────────────

    if let Some(ref w) = policy.active_window {
        if epoch < w.start_epoch || epoch > w.end_epoch {
            return Err(PolicyViolation::OutsideWindow {
                current_epoch: epoch,
                start_epoch: w.start_epoch,
                end_epoch: w.end_epoch,
            });
        }
    }

    // ── 2. Action allow-list ─────────────────────────────────────────────

    let action = classify_action(tx);
    if !policy.allowed_actions.permits(action) {
        return Err(PolicyViolation::ActionDenied { action });
    }

    // ── 3. Target allow-list ─────────────────────────────────────────────

    if let Some(target) = tx.to {
        if !policy.allowed_targets.contains(&target) {
            return Err(PolicyViolation::TargetDenied { target });
        }
    }

    // ── 3b. A2A counterparty check (§8, P3·Step 16) ─────────────────────
    //
    // If `tx.to` is a registered agent (present in Identity Registry), this
    // payment is classified as `PAY_AGENT` — no new TxType, no mempool path
    // (spec §8: "composes existing primitives", DB-A67). Three sub-checks:
    //
    // (i)  Action mask: payer's policy must permit `PayAgent`.
    // (ii) KYA tier: payee.kya_tier >= policy.required_kya_tier (if > None).
    // (iii) Reputation: payee.reputation_score >= policy.min_counterparty_reputation
    //       (if min > 0).
    //
    // `MissingCounterparty` fires when the policy opts in to A2A requirements
    // (required_kya_tier > None ∨ min_counterparty_reputation > 0) but the
    // recipient is NOT a registered agent — credentials cannot be verified.
    // Both variants trip the dead-man's switch via `handle_violation` (same
    // path as all other `PolicyViolation`s).
    //
    // DETERMINISM (AGENTS §7.1): reads only committed state via `read_agent_identity`.
    // No wall-clock, no RNG, no `HashMap`.
    if let Some(target) = tx.to {
        let a2a_required =
            policy.required_kya_tier > KyaTier::None || policy.min_counterparty_reputation > 0;
        let payee_identity = crate::agent_registry::read_agent_identity(state, &target);

        if let Some(identity) = payee_identity {
            // Recipient IS a registered agent → PAY_AGENT action class.
            // (i) Action mask check — payer must have PayAgent permission.
            if !policy.allowed_actions.permits(Action::PayAgent) {
                return Err(PolicyViolation::ActionDenied {
                    action: Action::PayAgent,
                });
            }

            // (ii) KYA tier gate (opt-in: only enforced when required_kya_tier > None).
            if policy.required_kya_tier > KyaTier::None
                && identity.kya_tier < policy.required_kya_tier
            {
                return Err(PolicyViolation::CounterpartyRejected {
                    reason: "counterparty KYA tier below required minimum",
                    required_tier: policy.required_kya_tier,
                    actual_tier: identity.kya_tier,
                    // Reputation values included for full context (AGENTS §12.2).
                    required_reputation: policy.min_counterparty_reputation,
                    actual_reputation: identity.reputation_score,
                });
            }

            // (iii) Reputation gate (opt-in: only enforced when min > 0).
            if policy.min_counterparty_reputation > 0
                && identity.reputation_score < policy.min_counterparty_reputation
            {
                return Err(PolicyViolation::CounterpartyRejected {
                    reason: "counterparty reputation score below required minimum",
                    required_tier: policy.required_kya_tier,
                    actual_tier: identity.kya_tier,
                    required_reputation: policy.min_counterparty_reputation,
                    actual_reputation: identity.reputation_score,
                });
            }
        } else if a2a_required {
            // Recipient is NOT registered but the policy requires verified counterparties.
            return Err(PolicyViolation::MissingCounterparty { target });
        }
        // Else: non-agent recipient, no A2A requirements → normal pass-through.
    }

    // ── 4. Value bounds (checked arithmetic — AGENTS §7.4) ───────────────

    let value = tx.value;

    // 4a. Per-tx cap
    if value > policy.per_tx_cap {
        return Err(PolicyViolation::PerTxExceeded {
            value,
            cap: policy.per_tx_cap,
        });
    }

    // ── Epoch reset (lazy) ───────────────────────────────────────────────
    //
    // If the epoch has advanced, reset all per-epoch counters and apply
    // streaming refill. Must happen BEFORE category check and per-epoch cap
    // so the newly-started epoch begins with clean counters and fresh budget.
    //
    // Uses the canonical `apply_epoch_reset` helper — same function called by
    // `handle_violation` — ensuring both code paths stay in sync (AGENTS §2).

    if epoch > policy.last_epoch {
        apply_epoch_reset(&mut policy, epoch);
    }

    // ── 4b. Per-category sub-budget (§2.3.2, Step 14) ───────────────────
    //
    // Check after epoch reset — counters are fresh for a new epoch.

    let matched_category = policy.categories.category_of(action).map(str::to_owned);

    if let Some(ref cat) = matched_category {
        let cat_after = policy
            .categories
            .spent(cat)
            .checked_add(value)
            .map_err(|_| PolicyViolation::Overflow)?;
        let cat_cap = policy.categories.cap(cat);
        if cat_after > cat_cap {
            return Err(PolicyViolation::CategoryExceeded {
                category: cat.clone(),
                spent: cat_after,
                cap: cat_cap,
            });
        }
    }

    // 4c. Per-epoch cap
    let epoch_after = policy
        .spent_this_epoch
        .checked_add(value)
        .map_err(|_| PolicyViolation::Overflow)?;
    if epoch_after > policy.per_epoch_cap {
        return Err(PolicyViolation::PerEpochExceeded {
            epoch_total: epoch_after,
            cap: policy.per_epoch_cap,
        });
    }

    // 4d. Budget total (lifetime)
    let total_after = policy
        .spent_total
        .checked_add(value)
        .map_err(|_| PolicyViolation::Overflow)?;
    if total_after > policy.budget_total {
        return Err(PolicyViolation::BudgetExceeded {
            lifetime_total: total_after,
            budget: policy.budget_total,
        });
    }

    // ── 4e. Co-sign step-up (§2.3.4, Step 14) ───────────────────────────
    //
    // If the tx value meets or exceeds the co-sign threshold and the tx
    // does NOT carry an owner co-signature, return PendingOwnerCosign.
    // This is NOT a violation — the dead-man's switch is NOT incremented.
    // The executor produces a failed receipt; the owner re-submits with
    // `Transaction::owner_cosignature` set.

    if let Some(threshold) = policy.cosign_threshold {
        if value >= threshold && !tx.has_owner_cosignature() {
            // Co-sign required. Return PendingOwnerCosign WITHOUT writing state.
            //
            // The epoch-reset applied above (if any) is intentionally NOT
            // persisted here — the executor will discard the entire scratch
            // overlay. On resubmit (same epoch), `epoch > policy.last_epoch`
            // will still be true (last_epoch never advanced), so the reset
            // runs exactly once when the tx finally commits. This is correct:
            // epoch reset + refill are idempotent side effects that must be
            // committed atomically with a successful tx, never speculatively.
            // NOT calling write_policy here prevents double-refill on resubmit.
            return Ok(WardenOutcome::PendingOwnerCosign);
        }
    }

    // ── 4e. Anomaly guard (§9.1, P3·Step 15) ────────────────────────────
    //
    // Pure function of committed on-chain history — no wall-clock, no RNG
    // (AGENTS §7.1, SAFETY-019). Skipped when disabled or no baseline yet.
    //
    // The dead-man's switch IS incremented for AnomalyHold (§9.1 explicit:
    // "the dead-man's switch counter increments") — the executor's existing
    // Err(violation) → handle_violation path handles this correctly since
    // AnomalyHold is a PolicyViolation (not a WardenOutcome hold).
    if policy.anomaly.enabled && policy.history.has_history {
        if let Some(reason) = anomaly_detected(&policy, tx) {
            return Err(PolicyViolation::AnomalyHold {
                reason: reason.to_owned(),
            });
        }
    }

    // ── 5. Commit counters ───────────────────────────────────────────────────────
    //
    // Only reached on full success. Counter writes land in the scratch overlay
    // and are committed/discarded atomically with the transaction.

    policy.spent_this_epoch = epoch_after;
    policy.spent_total = total_after;
    if let Some(ref cat) = matched_category {
        policy.categories.add_spent(cat, value);
    }
    // Update behavioral history for the anomaly guard (§9.1, P3·Step 15).
    // History is only tracked when anomaly detection is enabled — saves state
    // write bytes for the common case (opt-in feature).
    if policy.anomaly.enabled {
        update_history(&mut policy, tx, value);
    }
    write_policy(state, &tx.sender, session_key, &policy);

    // P3·Step 17: Mandate Receipt emission ✅ — handled by the executor immediately
    // after this function returns `Ok(Applied)`, via `build_mandate_receipt_log`
    // (defined below). Cannot be done inside this function because `WardenOutcome`
    // derives `Copy` and cannot carry a `Vec<Log>`. Observationally equivalent to
    // spec §3 line 207 placement (same deterministic tx execution context).

    Ok(WardenOutcome::Applied)
}

// ── Mandate Receipt emission (§11, P3·Step 17) ───────────────────────────────

/// Build the AP2-aligned Mandate Receipt `Log` for an applied agent transaction.
///
/// Called by the **executor** immediately after `warden_check` returns
/// `Ok(WardenOutcome::Applied)`. The log is prepended to the contract's event
/// logs before building the `TransactionReceipt`.
///
/// ## Why here, not inside `warden_check`
///
/// `WardenOutcome` derives `Copy` (needed for the executor's match arms), so it
/// cannot carry a `Vec<Log>`. Returning a separate value avoids changing the
/// `warden_check` signature and touching 88+ existing tests. The log is built
/// from the same data `warden_check` committed, re-read from the scratch overlay
/// (one extra state read, well within the 7 500-gas `warden_check` budget).
///
/// ## Determinism (AGENTS §7.1)
///
/// - `read_policy` reads committed scratch state — same state `warden_check` wrote.
/// - `blake3(policy_bytes)` of the serialized post-commit policy is deterministic.
/// - `MandateReceipt::to_log()` uses `serde_json::to_vec` — deterministic field order.
/// - No wall-clock, no RNG.
///
/// ## No-panic guarantee (AGENTS §7.2)
///
/// `read_policy` returns `None` if the policy is corrupt or absent; in that case
/// the log is silently skipped (the tx already applied — not emitting the audit log
/// is better than halting the settlement path). `MandateReceipt::to_log()` never
/// panics (`serde_json` fallback to empty `data`).
///
/// ## Spec position (14 §3 line 207)
///
/// The spec pseudocode calls `emit_mandate_receipt` after `policy.spent_total =
/// total_after` and before `Ok(WardenOutcome::Applied)`. The executor calling
/// this function right after `Applied` is returned is observationally equivalent:
/// both happen within the same deterministic tx execution before `scratch.commit`.
pub(crate) fn build_mandate_receipt_log<S: ContractStateView>(
    tx: &Transaction,
    session_key: &[u8],
    epoch: u64,
    action: Action,
    state: &S,
) -> Option<Log> {
    let policy = read_policy(state, &tx.sender, session_key)?;

    // `policy_hash` = blake3 of the serialized post-commit policy.
    // This is the Intent Mandate fingerprint: the exact policy state the agent
    // operated under, after counters were updated (§11: "executed terms").
    let policy_bytes = serde_json::to_vec(&policy).unwrap_or_default();
    let hash_bytes = *blake3::hash(&policy_bytes).as_bytes();
    let policy_hash = lemma_core::hash::Hash::from_bytes(hash_bytes);

    // `spent_total` was set to `total_after ≤ budget_total` by counter commit, so
    // this subtraction should never underflow. If it somehow does (future refactor
    // breaks ordering), log a warning and emit `0` rather than panicking (AGENTS §7.2).
    let budget_remaining = policy
        .budget_total
        .checked_sub(policy.spent_total)
        .unwrap_or_else(|_| {
            tracing::warn!(
                owner = %tx.sender,
                "mandate receipt: spent_total > budget_total — invariant break (emitting 0)"
            );
            lemma_core::amount::Amount::zero()
        });

    let receipt = MandateReceipt {
        owner: tx.sender,
        session_key: session_key.to_vec(),
        policy_hash,
        action,
        target: tx.to,
        value: tx.value,
        budget_remaining,
        epoch,
        kya_tier: policy.kya_tier,
        // `has_owner_cosignature()` is a pure function of `tx` — re-reading it here
        // is safe and consistent with the co-sign gate in `warden_check` (Step 14).
        // If a future step makes co-sign state-dependent, thread the result from
        // `warden_check` instead of re-deriving it here.
        cosigned: tx.has_owner_cosignature(),
    };

    Some(receipt.to_log())
}

// ── Dead-man's switch helper ─────────────────────────────────────────────────

/// Record a `PolicyViolation` for the dead-man's switch (14 §2.3.5, Step 14).
///
/// Called by the **executor** after receiving `Err(PolicyViolation)` from
/// `warden_check`. Increments `auto_revoke.violations_this_epoch` and, if the
/// threshold is met, immediately expires the policy (`expiry_epoch = epoch`).
///
/// Writes the updated policy back to state even on a violation — the violation
/// counter must persist regardless of whether the tx was applied.
///
/// ## Why a separate function (not inside `warden_check`)
///
/// `warden_check` bails out on the first violation without committing any
/// state. The dead-man's switch must read-modify-write the policy *after*
/// the violation decision, so it lives in the caller. This also lets the
/// executor choose not to call it for `PendingOwnerCosign` (which is not
/// a violation and should not count toward the switch).
///
/// ## No-op conditions
///
/// - `auto_revoke.max_violations_per_epoch == 0` → switch disabled, no-op.
/// - Policy not found in state → no-op (policy already gone).
pub(crate) fn handle_violation<S: ContractStateView>(
    tx: &Transaction,
    session_key: &[u8],
    epoch: u64,
    state: &mut S,
) {
    // Re-read the policy. If missing (e.g. already revoked), nothing to do.
    let Some(mut policy) = read_policy(state, &tx.sender, session_key) else {
        return;
    };

    // Disabled — exit early to avoid unnecessary state write.
    if policy.auto_revoke.max_violations_per_epoch == 0 {
        return;
    }

    // Apply the canonical epoch reset if the epoch has advanced. This uses
    // the same `apply_epoch_reset` as `warden_check` — ensuring spend counters,
    // category counters, violation counter, and streaming refill are all handled
    // consistently (AGENTS §2 DRY; fixes CodeReviewer M1 divergence).
    if epoch > policy.last_epoch {
        apply_epoch_reset(&mut policy, epoch);
    }

    policy.auto_revoke.violations_this_epoch =
        policy.auto_revoke.violations_this_epoch.saturating_add(1);

    // Trip the switch: immediately expire the policy.
    if policy.auto_revoke.violations_this_epoch >= policy.auto_revoke.max_violations_per_epoch {
        policy.expiry_epoch = epoch; // expired as of this epoch
        tracing::warn!(
            owner = %tx.sender,
            epoch,
            violations = policy.auto_revoke.violations_this_epoch,
            "warden: dead-man's switch tripped — policy expired immediately"
        );
    }

    write_policy(state, &tx.sender, session_key, &policy);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
