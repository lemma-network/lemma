//! Tests for `lemma_vm::warden` — Warden policy enforcement (P3·Steps 13–17).

use std::collections::BTreeSet;

use lemma_core::{
    address::Address,
    agent::{
        Action, ActionMask, AgentIdentity, AgentPolicy, AllowList, AnomalyConfig, AnomalyHistory,
        AutoRevoke, CategoryBudget, CategoryCaps, EpochRange, KyaTier, MandateReceipt,
        PolicyViolation, WardenOutcome, MANDATE_RECEIPT_EVENT_SIG,
    },
    amount::Amount,
    hash::Hash,
    signature::Signature,
    transaction::{Transaction, TxType},
};

use super::*;
use crate::state::InMemoryStateView;

// ── Test helpers ─────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = n;
    Address::from_raw_bytes(bytes)
}

fn session_key() -> Vec<u8> {
    vec![0xAA, 0xBB, 0xCC, 0xDD]
}

/// Create a basic agent policy with generous limits.
fn base_policy() -> AgentPolicy {
    AgentPolicy {
        session_key: session_key(),
        expiry_epoch: 100,
        budget_total: Amount::from_drop(1_000_000),
        per_tx_cap: Amount::from_drop(10_000),
        per_epoch_cap: Amount::from_drop(100_000),
        allowed_targets: AllowList::any(),
        allowed_actions: ActionMask::all(),
        spent_total: Amount::zero(),
        spent_this_epoch: Amount::zero(),
        last_epoch: 0,
        refill_per_epoch: Amount::zero(),
        budget_ceiling: None,
        categories: CategoryCaps::new(),
        active_window: None,
        cosign_threshold: None,
        auto_revoke: AutoRevoke::default(),
        kya_tier: KyaTier::None,
        anomaly: AnomalyConfig::default(),
        history: AnomalyHistory::default(),
        required_kya_tier: KyaTier::None,
        min_counterparty_reputation: 0,
    }
}

/// Register an agent identity in state (test helper).
fn register_agent(
    state: &mut crate::state::InMemoryStateView,
    agent: Address,
    identity: AgentIdentity,
) {
    crate::agent_registry::write_agent_identity(state, &agent, &identity);
}

/// Build an `AgentIdentity` for use in tests.
fn agent_identity(kya_tier: KyaTier, reputation_score: u16) -> AgentIdentity {
    AgentIdentity {
        owner: addr(1), // payer is owner (arbitrary for tests)
        kya_tier,
        reputation_score,
    }
}

/// Build a policy with anomaly detection enabled where ONLY Signal 3
/// (novel high-value target) can fire. Signals 1 and 2 are disabled by zeroing
/// their baselines. Useful for isolating target-novelty tests.
fn signal3_only_policy() -> AgentPolicy {
    let mut policy = base_policy();
    policy.anomaly = AnomalyConfig {
        enabled: true,
        spike_ratio: 500,
        burst_ratio: 300,
    };
    policy.history = AnomalyHistory {
        avg_value_ema: Amount::zero(), // Signal 1 baseline = 0 → skipped
        tx_count_this_epoch: 0,
        avg_tx_count_ema: 0, // Signal 2 baseline = 0 → skipped
        has_history: true,
        seen_targets: std::collections::BTreeSet::new(),
    };
    policy
}

/// Build a policy with anomaly detection enabled and a committed baseline.
///
/// `avg_value` = EMA baseline for value (in Drop).
/// `avg_count` = EMA baseline for tx-per-epoch count.
fn anomaly_policy(avg_value: u128, avg_count: u16) -> AgentPolicy {
    let mut policy = base_policy();
    policy.anomaly = AnomalyConfig {
        enabled: true,
        spike_ratio: 500, // 5.0× default
        burst_ratio: 300, // 3.0× default
    };
    policy.history = AnomalyHistory {
        avg_value_ema: Amount::from_drop(avg_value),
        tx_count_this_epoch: 0,
        avg_tx_count_ema: avg_count,
        has_history: true, // baseline committed
        seen_targets: std::collections::BTreeSet::new(),
    };
    policy
}

/// Build a CategoryCaps with a TRADE category mapping to Transfer actions.
fn trade_caps(cap: u128) -> CategoryCaps {
    let mut caps = CategoryCaps::new();
    let mut actions = BTreeSet::new();
    actions.insert(Action::Transfer);
    caps.insert(
        "TRADE",
        CategoryBudget {
            cap: Amount::from_drop(cap),
            spent: Amount::zero(),
            actions,
        },
    );
    caps
}

/// Create a transfer tx from owner `addr(1)` to `addr(2)` with the given value.
fn transfer_tx(value: u128) -> Transaction {
    let mut tx = Transaction::new(
        Hash::zero(),
        addr(1), // owner/sender
        Some(addr(2)),
        0,
        1,
        Amount::from_drop(value),
        100_000,
        Amount::from_drop(1),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("valid tx");
    tx.session_key = Some(session_key());
    tx
}

/// Create a contract call tx from owner `addr(1)` to target.
fn call_tx(target: Address, value: u128) -> Transaction {
    let mut tx = Transaction::new(
        Hash::zero(),
        addr(1),
        Some(target),
        0,
        1,
        Amount::from_drop(value),
        100_000,
        Amount::from_drop(1),
        TxType::ContractCall,
        vec![0x01], // minimal calldata
        Signature::Unsigned,
    )
    .expect("valid tx");
    tx.session_key = Some(session_key());
    tx
}

/// Store a policy in state and return the state view.
fn state_with_policy(policy: &AgentPolicy) -> InMemoryStateView {
    let mut state = InMemoryStateView::new();
    write_policy(&mut state, &addr(1), &session_key(), policy);
    state
}

// ── Core flow tests ──────────────────────────────────────────────────────────

#[test]
fn warden_check_passes_valid_transfer() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(1_000);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    // Verify counters were updated.
    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy exists");
    assert_eq!(updated.spent_total, Amount::from_drop(1_000));
    assert_eq!(updated.spent_this_epoch, Amount::from_drop(1_000));
    assert_eq!(updated.last_epoch, 5);
}

#[test]
fn warden_check_skipped_when_no_session_key() {
    // This tests the executor integration point — warden_check itself
    // requires a session key. The executor only calls warden_check when
    // tx.session_key.is_some(). This test verifies the warden module's
    // behavior when called with a tx that has no policy.
    let mut state = InMemoryStateView::new(); // no policy stored
    let tx = transfer_tx(1_000);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Err(PolicyViolation::PolicyNotFound));
}

// ── Expiry tests ─────────────────────────────────────────────────────────────

#[test]
fn warden_rejects_expired_policy() {
    let policy = base_policy(); // expiry_epoch = 100
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    // Epoch == expiry → expired
    let result = warden_check(&tx, &session_key(), 100, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::Expired {
            expiry_epoch: 100,
            current_epoch: 100,
        })
    );
}

#[test]
fn warden_rejects_past_expiry() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 200, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::Expired {
            expiry_epoch: 100,
            current_epoch: 200,
        })
    );
}

#[test]
fn warden_accepts_before_expiry() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 99, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

// ── Action allow-list tests ──────────────────────────────────────────────────

#[test]
fn warden_rejects_denied_action() {
    let mut policy = base_policy();
    // Only allow ContractCall, deny Transfer.
    policy.allowed_actions = ActionMask::from_actions(&[Action::ContractCall]);
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100); // TxType::Transfer → Action::Transfer

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::ActionDenied {
            action: Action::Transfer
        })
    );
}

#[test]
fn warden_accepts_permitted_action() {
    let mut policy = base_policy();
    policy.allowed_actions = ActionMask::from_actions(&[Action::Transfer]);
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

// ── Target allow-list tests ──────────────────────────────────────────────────

#[test]
fn warden_rejects_denied_target() {
    let mut policy = base_policy();
    // Only allow addr(3), deny addr(2).
    policy.allowed_targets = AllowList::from_targets(&[addr(3)]);
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100); // target is addr(2)

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::TargetDenied { target: addr(2) })
    );
}

#[test]
fn warden_accepts_permitted_target() {
    let mut policy = base_policy();
    policy.allowed_targets = AllowList::from_targets(&[addr(2)]);
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

#[test]
fn warden_accepts_wildcard_target() {
    let policy = base_policy(); // allowed_targets = Any
    let mut state = state_with_policy(&policy);
    let tx = call_tx(addr(99), 100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

// ── Per-tx cap tests ─────────────────────────────────────────────────────────

#[test]
fn warden_rejects_per_tx_exceeded() {
    let policy = base_policy(); // per_tx_cap = 10_000
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(10_001);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::PerTxExceeded {
            value: Amount::from_drop(10_001),
            cap: Amount::from_drop(10_000),
        })
    );
}

#[test]
fn warden_accepts_exactly_at_per_tx_cap() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(10_000);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

// ── Per-epoch cap tests ──────────────────────────────────────────────────────

#[test]
fn warden_rejects_per_epoch_exceeded() {
    let mut policy = base_policy(); // per_epoch_cap = 100_000
    policy.spent_this_epoch = Amount::from_drop(95_000);
    policy.last_epoch = 5;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(5_001); // 95_000 + 5_001 = 100_001 > 100_000

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::PerEpochExceeded {
            epoch_total: Amount::from_drop(100_001),
            cap: Amount::from_drop(100_000),
        })
    );
}

#[test]
fn warden_accepts_exactly_at_per_epoch_cap() {
    let mut policy = base_policy();
    policy.spent_this_epoch = Amount::from_drop(90_000);
    policy.last_epoch = 5;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(10_000); // 90_000 + 10_000 = 100_000 == cap

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

// ── Budget total tests ───────────────────────────────────────────────────────

#[test]
fn warden_rejects_budget_exceeded() {
    let mut policy = base_policy(); // budget_total = 1_000_000
    policy.spent_total = Amount::from_drop(995_000);
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(5_001); // 995_000 + 5_001 = 1_000_001 > 1_000_000

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::BudgetExceeded {
            lifetime_total: Amount::from_drop(1_000_001),
            budget: Amount::from_drop(1_000_000),
        })
    );
}

#[test]
fn warden_accepts_exactly_at_budget() {
    let mut policy = base_policy();
    policy.spent_total = Amount::from_drop(990_000);
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(10_000); // 990_000 + 10_000 = 1_000_000 == budget

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

// ── Epoch reset tests ────────────────────────────────────────────────────────

#[test]
fn warden_resets_epoch_counter_on_epoch_advance() {
    let mut policy = base_policy();
    policy.spent_this_epoch = Amount::from_drop(90_000); // almost at cap
    policy.last_epoch = 5;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(5_000);

    // Epoch 6 — should reset spent_this_epoch to 0 first.
    let result = warden_check(&tx, &session_key(), 6, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.spent_this_epoch, Amount::from_drop(5_000));
    assert_eq!(updated.last_epoch, 6);
}

#[test]
fn warden_does_not_reset_within_same_epoch() {
    let mut policy = base_policy();
    policy.spent_this_epoch = Amount::from_drop(50_000);
    policy.last_epoch = 5;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(5_000);

    // Same epoch 5 — spent_this_epoch accumulates.
    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.spent_this_epoch, Amount::from_drop(55_000));
    assert_eq!(updated.last_epoch, 5);
}

// ── Counter accumulation tests ───────────────────────────────────────────────

#[test]
fn warden_accumulates_spent_total_across_txs() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);

    // First tx: spend 3_000.
    let tx1 = transfer_tx(3_000);
    let r1 = warden_check(&tx1, &session_key(), 5, &mut state);
    assert_eq!(r1, Ok(WardenOutcome::Applied));

    // Second tx: spend 4_000 — total = 7_000.
    let tx2 = transfer_tx(4_000);
    let r2 = warden_check(&tx2, &session_key(), 5, &mut state);
    assert_eq!(r2, Ok(WardenOutcome::Applied));

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.spent_total, Amount::from_drop(7_000));
    assert_eq!(updated.spent_this_epoch, Amount::from_drop(7_000));
}

// ── classify_action tests ────────────────────────────────────────────────────

#[test]
fn classify_action_maps_all_tx_types() {
    let base = transfer_tx(0);

    // Transfer
    assert_eq!(classify_action(&base), Action::Transfer);

    // ContractCall (need a contract call tx)
    let call = call_tx(addr(5), 0);
    assert_eq!(classify_action(&call), Action::ContractCall);
}

// ── Policy read/write roundtrip ──────────────────────────────────────────────

#[test]
fn policy_read_write_roundtrip() {
    let policy = base_policy();
    let mut state = InMemoryStateView::new();

    // Write
    write_policy(&mut state, &addr(1), &session_key(), &policy);

    // Read
    let read_back = read_policy(&state, &addr(1), &session_key());
    assert_eq!(read_back, Some(policy));
}

#[test]
fn policy_read_missing_returns_none() {
    let state = InMemoryStateView::new();
    let result = read_policy(&state, &addr(1), &session_key());
    assert_eq!(result, None);
}

#[test]
fn policy_read_corrupt_json_returns_none() {
    let mut state = InMemoryStateView::new();
    let key = policy_state_key(&addr(1), &session_key());
    state.write(&warden_system_addr(), &key, b"not json".to_vec());

    let result = read_policy(&state, &addr(1), &session_key());
    assert_eq!(result, None);
}

// ── Zero-value transfer passes all caps ──────────────────────────────────────

#[test]
fn warden_accepts_zero_value_transfer() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(0);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.spent_total, Amount::zero());
    assert_eq!(updated.spent_this_epoch, Amount::zero());
}

// ── Active window tests (Step 14, §2.3.3) ────────────────────────────────────

#[test]
fn warden_rejects_before_active_window() {
    let mut policy = base_policy();
    policy.active_window = Some(EpochRange {
        start_epoch: 10,
        end_epoch: 20,
    });
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::OutsideWindow {
            current_epoch: 5,
            start_epoch: 10,
            end_epoch: 20,
        })
    );
}

#[test]
fn warden_rejects_after_active_window() {
    let mut policy = base_policy();
    policy.active_window = Some(EpochRange {
        start_epoch: 10,
        end_epoch: 20,
    });
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 25, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::OutsideWindow {
            current_epoch: 25,
            start_epoch: 10,
            end_epoch: 20,
        })
    );
}

#[test]
fn warden_accepts_at_window_start_epoch() {
    let mut policy = base_policy();
    policy.active_window = Some(EpochRange {
        start_epoch: 10,
        end_epoch: 20,
    });
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);
    assert_eq!(
        warden_check(&tx, &session_key(), 10, &mut state),
        Ok(WardenOutcome::Applied)
    );
}

#[test]
fn warden_accepts_at_window_end_epoch() {
    let mut policy = base_policy();
    policy.active_window = Some(EpochRange {
        start_epoch: 10,
        end_epoch: 20,
    });
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);
    assert_eq!(
        warden_check(&tx, &session_key(), 20, &mut state),
        Ok(WardenOutcome::Applied)
    );
}

#[test]
fn warden_accepts_no_active_window_restriction() {
    let policy = base_policy(); // active_window = None
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);
    assert_eq!(
        warden_check(&tx, &session_key(), 50, &mut state),
        Ok(WardenOutcome::Applied)
    );
}

// ── Per-category sub-budget tests (Step 14, §2.3.2) ──────────────────────────

#[test]
fn warden_rejects_category_exceeded() {
    let mut policy = base_policy();
    policy.categories = trade_caps(5_000); // TRADE cap = 5_000
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(5_001); // Transfer → TRADE, 5_001 > 5_000

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(matches!(
        result,
        Err(PolicyViolation::CategoryExceeded { ref category, .. }) if category == "TRADE"
    ));
}

#[test]
fn warden_accepts_within_category_cap() {
    let mut policy = base_policy();
    policy.categories = trade_caps(10_000);
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(5_000);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    // Category counter updated.
    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.categories.spent("TRADE"), Amount::from_drop(5_000));
}

#[test]
fn warden_skips_category_when_no_match() {
    let mut policy = base_policy();
    // TRADE only covers Transfer; ContractCall is uncategorized.
    policy.categories = trade_caps(1_000);
    let mut state = state_with_policy(&policy);
    let tx = call_tx(addr(5), 5_000); // ContractCall — no category match

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

#[test]
fn warden_category_counters_reset_on_epoch_advance() {
    let mut policy = base_policy();
    policy.categories = trade_caps(8_000);
    // Pre-fill to near cap.
    policy
        .categories
        .add_spent("TRADE", Amount::from_drop(7_500));
    policy.last_epoch = 5;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(5_000); // Would exceed if counters not reset

    // Epoch 6 — category counter resets to 0 first.
    let result = warden_check(&tx, &session_key(), 6, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(
        updated.categories.spent("TRADE"),
        Amount::from_drop(5_000) // only this epoch's spend
    );
}

// ── Streaming refill tests (Step 14, §2.3.1) ─────────────────────────────────

#[test]
fn warden_refills_budget_on_epoch_advance() {
    let mut policy = base_policy();
    policy.budget_total = Amount::from_drop(500_000);
    policy.refill_per_epoch = Amount::from_drop(100_000);
    policy.last_epoch = 5;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(1); // Minimal tx just to trigger a check

    let result = warden_check(&tx, &session_key(), 6, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    // budget was 500_000, refill adds 100_000 → 600_000.
    assert_eq!(updated.budget_total, Amount::from_drop(600_000));
}

#[test]
fn warden_refill_capped_at_ceiling() {
    let mut policy = base_policy();
    policy.budget_total = Amount::from_drop(950_000);
    policy.refill_per_epoch = Amount::from_drop(100_000);
    policy.budget_ceiling = Some(Amount::from_drop(1_000_000)); // can't exceed 1M
    policy.last_epoch = 5;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(1);

    let result = warden_check(&tx, &session_key(), 6, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    // 950_000 + 100_000 = 1_050_000 but ceiling is 1_000_000.
    assert_eq!(updated.budget_total, Amount::from_drop(1_000_000));
}

#[test]
fn warden_no_refill_when_zero() {
    let mut policy = base_policy();
    policy.budget_total = Amount::from_drop(500_000);
    policy.refill_per_epoch = Amount::zero(); // disabled
    policy.last_epoch = 5;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(1);

    warden_check(&tx, &session_key(), 6, &mut state).unwrap();

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.budget_total, Amount::from_drop(500_000)); // unchanged
}

// ── Co-sign threshold tests (Step 14, §2.3.4) ────────────────────────────────

#[test]
fn warden_returns_pending_cosign_above_threshold() {
    let mut policy = base_policy();
    policy.cosign_threshold = Some(Amount::from_drop(8_000));
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(8_000); // >= threshold, no co-sig

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::PendingOwnerCosign));

    // State NOT modified (counters not updated for pending tx).
    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.spent_total, Amount::zero());
}

#[test]
fn warden_accepts_with_owner_cosignature() {
    let mut policy = base_policy();
    policy.cosign_threshold = Some(Amount::from_drop(8_000));
    let mut state = state_with_policy(&policy);
    let mut tx = transfer_tx(8_000);
    tx.owner_cosignature = Some(vec![0xDE, 0xAD, 0xBE, 0xEF]); // co-sig present

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

#[test]
fn warden_accepts_below_cosign_threshold() {
    let mut policy = base_policy();
    policy.cosign_threshold = Some(Amount::from_drop(8_000));
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(7_999); // below threshold → no co-sig needed

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

// ── Dead-man's switch tests (Step 14, §2.3.5) ────────────────────────────────

#[test]
fn handle_violation_increments_violation_counter() {
    let mut policy = base_policy();
    policy.auto_revoke.max_violations_per_epoch = 5;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    handle_violation(&tx, &session_key(), 5, &mut state);

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.auto_revoke.violations_this_epoch, 1);
    // Policy NOT expired yet.
    assert_eq!(updated.expiry_epoch, 100);
}

#[test]
fn handle_violation_trips_switch_after_n_violations() {
    let mut policy = base_policy();
    policy.auto_revoke.max_violations_per_epoch = 3;
    policy.auto_revoke.violations_this_epoch = 2; // 2 already this epoch
    policy.last_epoch = 5; // same epoch as the call below — no reset
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    // Third violation trips the switch.
    handle_violation(&tx, &session_key(), 5, &mut state);

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.auto_revoke.violations_this_epoch, 3);
    // Immediately expired: expiry_epoch set to current epoch.
    assert_eq!(updated.expiry_epoch, 5);
}

#[test]
fn handle_violation_noop_when_switch_disabled() {
    let mut policy = base_policy();
    policy.auto_revoke.max_violations_per_epoch = 0; // disabled
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    handle_violation(&tx, &session_key(), 5, &mut state);

    // Policy unchanged — no write happened (switch is disabled).
    // The policy expiry must remain 100.
    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(updated.expiry_epoch, 100);
}

#[test]
fn handle_violation_resets_counter_on_epoch_advance() {
    let mut policy = base_policy();
    policy.auto_revoke.max_violations_per_epoch = 3;
    policy.auto_revoke.violations_this_epoch = 2; // 2 from epoch 4
    policy.last_epoch = 4;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    // Epoch 5 — counter resets before incrementing.
    handle_violation(&tx, &session_key(), 5, &mut state);

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    // Counter reset to 0, then incremented once → 1. Switch NOT tripped.
    assert_eq!(updated.auto_revoke.violations_this_epoch, 1);
    assert_eq!(updated.expiry_epoch, 100); // not expired
}

// ── C1: PendingOwnerCosign resubmit idempotency ───────────────────────────────
//
// Verifies that epoch-reset + streaming refill are NOT applied speculatively
// on PendingOwnerCosign — they run exactly once when the tx finally commits.

#[test]
fn cosign_pending_does_not_persist_epoch_reset_allowing_idempotent_resubmit() {
    let mut policy = base_policy();
    policy.refill_per_epoch = Amount::from_drop(50_000);
    policy.cosign_threshold = Some(Amount::from_drop(8_000));
    policy.last_epoch = 4; // epoch 5 will be a new epoch
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(8_000); // >= threshold, no co-sig

    // First attempt: PendingOwnerCosign (epoch-reset NOT committed).
    let result1 = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result1, Ok(WardenOutcome::PendingOwnerCosign));

    // Policy state unchanged: last_epoch still 4, budget_total still 1_000_000.
    // (The epoch-reset + refill were discarded with the scratch overlay.)
    let after_pending = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(
        after_pending.last_epoch, 4,
        "last_epoch must not advance on pending"
    );
    assert_eq!(
        after_pending.budget_total,
        Amount::from_drop(1_000_000),
        "budget_total must not refill on pending"
    );

    // Second attempt (resubmit with co-sig, same epoch 5).
    // Epoch-reset + refill run exactly ONCE here.
    let mut tx2 = transfer_tx(8_000);
    tx2.owner_cosignature = Some(vec![0xAB, 0xCD]);
    let result2 = warden_check(&tx2, &session_key(), 5, &mut state);
    assert_eq!(result2, Ok(WardenOutcome::Applied));

    let after_commit = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(
        after_commit.last_epoch, 5,
        "last_epoch advances exactly once on commit"
    );
    // Refill applied once: 1_000_000 + 50_000 = 1_050_000.
    assert_eq!(
        after_commit.budget_total,
        Amount::from_drop(1_050_000),
        "refill applied exactly once on successful commit"
    );
}

// ── M1: handle_violation epoch-reset uses canonical apply_epoch_reset ─────────
//
// Verifies that handle_violation resets spend + category counters (not just
// violations), so a violating tx as the first tx of a new epoch doesn't
// leave stale spend state for the next successful tx.

#[test]
fn handle_violation_as_first_tx_of_epoch_resets_all_counters() {
    let mut policy = base_policy();
    policy.auto_revoke.max_violations_per_epoch = 5;
    policy.spent_this_epoch = Amount::from_drop(80_000); // stale from epoch 4
    policy.categories = trade_caps(10_000);
    policy
        .categories
        .add_spent("TRADE", Amount::from_drop(9_000)); // stale
    policy.refill_per_epoch = Amount::from_drop(10_000);
    policy.last_epoch = 4;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    // Violating tx is the first touch in epoch 5.
    handle_violation(&tx, &session_key(), 5, &mut state);

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    // Spend counters reset (epoch 5 is fresh).
    assert_eq!(
        updated.spent_this_epoch,
        Amount::zero(),
        "spent_this_epoch must reset on epoch advance in handle_violation"
    );
    // Category counters reset.
    assert_eq!(
        updated.categories.spent("TRADE"),
        Amount::zero(),
        "category spent must reset on epoch advance in handle_violation"
    );
    // Refill applied (same apply_epoch_reset used by warden_check).
    assert_eq!(
        updated.budget_total,
        Amount::from_drop(1_010_000), // 1_000_000 + 10_000
        "streaming refill must apply in handle_violation's epoch reset"
    );
    // Violation counter: reset to 0 then incremented to 1.
    assert_eq!(updated.auto_revoke.violations_this_epoch, 1);
    assert_eq!(updated.last_epoch, 5);
}

// ── Kill switch (P3·Step 15, 14 §2.4) ────────────────────────────────────────

#[test]
fn kill_switch_rejects_all_agents_when_paused() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    // Pause the owner (addr(1)).
    write_owner_paused(&mut state, &addr(1), true);
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Err(PolicyViolation::AgentsPaused));
}

#[test]
fn kill_switch_fires_before_policy_read() {
    // Owner paused, NO policy in state (PolicyNotFound would fire without kill switch).
    let mut state = InMemoryStateView::new();
    write_owner_paused(&mut state, &addr(1), true);
    let tx = transfer_tx(100);

    // Must return AgentsPaused, NOT PolicyNotFound — kill switch is Step 0.
    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Err(PolicyViolation::AgentsPaused),
        "kill switch must fire before policy read (Step 0)"
    );
}

#[test]
fn kill_switch_unpaused_allows_normal_flow() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    // Pause then immediately unpause.
    write_owner_paused(&mut state, &addr(1), true);
    write_owner_paused(&mut state, &addr(1), false);
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

#[test]
fn kill_switch_pause_roundtrip_via_state() {
    let mut state = InMemoryStateView::new();
    assert!(!read_owner_paused(&state, &addr(1)), "initially not paused");
    write_owner_paused(&mut state, &addr(1), true);
    assert!(
        read_owner_paused(&state, &addr(1)),
        "should be paused after write"
    );
    write_owner_paused(&mut state, &addr(1), false);
    assert!(
        !read_owner_paused(&state, &addr(1)),
        "should not be paused after clear"
    );
}

#[test]
fn kill_switch_does_not_affect_other_owners() {
    // Pause owner addr(1); addr(2) has its own policy and is not paused.
    let policy = base_policy();
    let mut state = InMemoryStateView::new();
    write_policy(&mut state, &addr(1), &session_key(), &policy);

    // Separate policy for addr(2).
    let mut policy2 = base_policy();
    policy2.session_key = session_key();
    write_policy(&mut state, &addr(2), &session_key(), &policy2);

    // Pause owner 1.
    write_owner_paused(&mut state, &addr(1), true);

    // addr(1)'s agent → paused.
    let tx1 = transfer_tx(100); // sender = addr(1)
    assert_eq!(
        warden_check(&tx1, &session_key(), 5, &mut state),
        Err(PolicyViolation::AgentsPaused)
    );

    // addr(2)'s agent → not paused, normal check.
    let mut tx2 = transfer_tx(100);
    tx2.sender = addr(2);
    let result2 = warden_check(&tx2, &session_key(), 5, &mut state);
    assert_eq!(
        result2,
        Ok(WardenOutcome::Applied),
        "addr(2) must not be affected by addr(1) pause"
    );
}

// ── Anomaly guard: bootstrap + disabled cases ─────────────────────────────────

#[test]
fn anomaly_guard_skipped_without_history() {
    // Even if enabled, anomaly detection is skipped when has_history = false.
    let mut policy = base_policy();
    policy.anomaly = AnomalyConfig {
        enabled: true,
        spike_ratio: 100,
        burst_ratio: 100,
    };
    policy.history.has_history = false;
    let mut state = state_with_policy(&policy);
    // tx.value massively exceeds any "average" — but no baseline yet.
    let tx = transfer_tx(9_999); // just under per_tx_cap

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Ok(WardenOutcome::Applied),
        "anomaly guard must be silent when has_history=false"
    );
}

#[test]
fn anomaly_guard_skipped_when_disabled() {
    // Anomaly explicitly enabled=false: guard never runs.
    let policy = anomaly_policy(100, 5); // has baseline
    let mut p2 = policy.clone();
    p2.anomaly.enabled = false;
    let mut state = state_with_policy(&p2);
    // Send a "spike" tx — 100x the average.
    let tx = transfer_tx(10_000);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Ok(WardenOutcome::Applied),
        "anomaly guard must be silent when disabled"
    );
}

// ── Anomaly guard: Signal 1 — value spike ────────────────────────────────────

#[test]
fn anomaly_guard_detects_value_spike() {
    // avg_value_ema = 100 Drop; spike_ratio = 500 (5.0×); threshold = 500 Drop.
    // tx.value = 501 → 501 × 100 = 50100 > 100 × 500 = 50000 → spike.
    let policy = anomaly_policy(100, 5);
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(501);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(result, Err(PolicyViolation::AnomalyHold { .. })),
        "value 501 against avg 100 (5× spike) must trigger AnomalyHold: {result:?}"
    );
}

#[test]
fn anomaly_guard_passes_value_at_spike_boundary() {
    // tx.value = 500 → 500 × 100 = 50000, NOT > 100 × 500 = 50000 → no spike.
    let policy = anomaly_policy(100, 5);
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(500);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Ok(WardenOutcome::Applied),
        "value exactly at spike threshold must pass (strict >)"
    );
}

#[test]
fn anomaly_guard_passes_zero_avg_value_ema() {
    // avg_value_ema = 0: no baseline for value spike → skip signal 1.
    // Value is kept below 50% of per_tx_cap (10_000 Drop) so Signal 3 also
    // cannot fire — isolates Signal 1's zero-baseline guard.
    let mut policy = anomaly_policy(0, 5);
    policy.history.avg_value_ema = Amount::zero();
    let mut state = state_with_policy(&policy);
    // Use value 100 Drop (well below Signal 3 threshold of 5_000 Drop).
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    // Should not AnomalyHold on value signal (avg=0 → skip).
    assert!(
        !matches!(result, Err(PolicyViolation::AnomalyHold { .. })),
        "zero avg_value_ema must skip value spike signal"
    );
}

// ── Anomaly guard: Signal 2 — burst rate ─────────────────────────────────────

#[test]
fn anomaly_guard_detects_burst_rate() {
    // avg_tx_count_ema = 4; burst_ratio = 300 (3.0×); threshold = 12 txs/epoch.
    // tx_count_this_epoch = 13: 13 × 100 = 1300 > 4 × 300 = 1200 → burst.
    // last_epoch == test epoch: no epoch reset (count is preserved as-is).
    let mut policy = anomaly_policy(100, 4);
    policy.history.tx_count_this_epoch = 13; // already past 3× avg(4)=12
    policy.last_epoch = 5; // same epoch as test → no reset
    let mut state = state_with_policy(&policy);
    // Use a small value to avoid triggering value spike signal.
    let tx = transfer_tx(50);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(result, Err(PolicyViolation::AnomalyHold { .. })),
        "tx_count 13 against avg 4 (3× burst) must trigger AnomalyHold: {result:?}"
    );
}

#[test]
fn anomaly_guard_passes_normal_burst_rate() {
    // avg_tx_count_ema = 4; burst_ratio = 300 (3.0×); threshold = 12.
    // tx_count_this_epoch = 11: 11 × 100 = 1100, NOT > 4 × 300 = 1200 → pass.
    // last_epoch == test epoch: no reset (count preserved).
    let mut policy = anomaly_policy(100, 4);
    policy.history.tx_count_this_epoch = 11;
    policy.last_epoch = 5; // same epoch as test → no reset
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(50);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Ok(WardenOutcome::Applied),
        "tx_count 11 against avg 4 (3× burst=12) must pass"
    );
}

#[test]
fn anomaly_guard_passes_zero_avg_tx_count() {
    // avg_tx_count_ema = 0: no baseline for burst → skip signal 2.
    // last_epoch == test epoch: no reset (count preserved).
    let mut policy = anomaly_policy(100, 0);
    policy.history.tx_count_this_epoch = 1000;
    policy.last_epoch = 5; // same epoch → no reset
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(50);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        !matches!(result, Err(PolicyViolation::AnomalyHold { .. })),
        "zero avg_tx_count_ema must skip burst signal"
    );
}

// ── Anomaly guard: history update on success ──────────────────────────────────

#[test]
fn anomaly_guard_updates_history_on_successful_tx() {
    // avg_value_ema = 0 initially (has_history=true but no prior value).
    // After one successful tx of value 80, EMA = 0 + 80>>3 = 10.
    let mut policy = anomaly_policy(0, 0);
    policy.history.avg_value_ema = Amount::zero();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(80);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    // new_ema = 0 - (0>>3) + (80>>3) = 0 + 10 = 10
    assert_eq!(
        updated.history.avg_value_ema,
        Amount::from_drop(10),
        "EMA must be updated: 0 + (80>>3)=10"
    );
    // tx_count incremented.
    assert_eq!(updated.history.tx_count_this_epoch, 1);
}

#[test]
fn anomaly_guard_history_not_updated_on_violation() {
    // On AnomalyHold, the history must NOT be updated (warden_check returns
    // Err before reaching the commit step).
    let policy = anomaly_policy(100, 4);
    let initial_count = policy.history.tx_count_this_epoch;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(9_001); // > 5× avg(100)=500 → spike

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(matches!(result, Err(PolicyViolation::AnomalyHold { .. })));

    // Policy may be updated by handle_violation, but history EMA must not change.
    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(
        updated.history.tx_count_this_epoch, initial_count,
        "tx_count must not increment on AnomalyHold"
    );
}

// ── Anomaly guard: epoch reset slides tx-count EMA ───────────────────────────

#[test]
fn epoch_reset_slides_tx_count_ema_and_resets_counter() {
    // Setup: avg_tx_count_ema = 8; completed 10 txs last epoch.
    let mut policy = base_policy();
    policy.anomaly = AnomalyConfig {
        enabled: true,
        spike_ratio: 500,
        burst_ratio: 300,
    };
    policy.history = AnomalyHistory {
        avg_value_ema: Amount::zero(),
        tx_count_this_epoch: 10, // completed epoch's count
        avg_tx_count_ema: 8,
        has_history: true,
        seen_targets: std::collections::BTreeSet::new(),
    };
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(50);

    // Trigger epoch advance (epoch 5 > last_epoch 0).
    let _ = warden_check(&tx, &session_key(), 5, &mut state);

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    // EMA: 8 - (8>>3) + (10>>3) = 8 - 1 + 1 = 8
    assert_eq!(
        updated.history.avg_tx_count_ema, 8,
        "EMA of tx count must be updated at epoch boundary"
    );
    // Counter reset to 0 then incremented to 1 by the successful tx.
    assert_eq!(
        updated.history.tx_count_this_epoch, 1,
        "counter must reset+increment on epoch advance"
    );
}

#[test]
fn epoch_reset_sets_has_history_after_first_epoch_with_activity() {
    // Start with has_history=false, one successful tx this epoch.
    let mut policy = base_policy();
    policy.anomaly = AnomalyConfig {
        enabled: true,
        spike_ratio: 500,
        burst_ratio: 300,
    };
    policy.history = AnomalyHistory {
        avg_value_ema: Amount::zero(),
        tx_count_this_epoch: 1, // one tx completed last epoch
        avg_tx_count_ema: 0,
        has_history: false,
        seen_targets: std::collections::BTreeSet::new(),
    };
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(50);

    // Epoch advance triggers apply_epoch_reset which slides the EMA.
    let _ = warden_check(&tx, &session_key(), 5, &mut state);

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert!(
        updated.history.has_history,
        "has_history must be set true after first epoch with activity"
    );
}

#[test]
fn epoch_reset_keeps_has_history_false_if_no_activity() {
    // Start with has_history=false, zero txs completed last epoch.
    let mut policy = base_policy();
    policy.anomaly = AnomalyConfig {
        enabled: true,
        spike_ratio: 500,
        burst_ratio: 300,
    };
    policy.history = AnomalyHistory {
        avg_value_ema: Amount::zero(),
        tx_count_this_epoch: 0, // no txs completed
        avg_tx_count_ema: 0,
        has_history: false,
        seen_targets: std::collections::BTreeSet::new(),
    };
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(50);

    let _ = warden_check(&tx, &session_key(), 5, &mut state);

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert!(
        !updated.history.has_history,
        "has_history must stay false when no txs completed in the prior epoch"
    );
}

// ── Anomaly guard: Signal 3 — novel high-value target ────────────────────────

#[test]
fn anomaly_guard_detects_novel_high_value_target() {
    // per_tx_cap = 10_000. Novel target at value >= 5_000 (50% of cap) → flag.
    // Uses signal3_only_policy so Signal 1+2 baselines are zero and don't interfere.
    let policy = signal3_only_policy();
    assert!(
        !policy.history.seen_targets.contains(&addr(5)),
        "addr(5) must not be in seen_targets"
    );
    let mut state = state_with_policy(&policy);

    // Build a tx to addr(5) with value = 5_000 (exactly 50% of per_tx_cap=10_000).
    let tx = call_tx(addr(5), 5_000);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(result, Err(PolicyViolation::AnomalyHold { .. })),
        "novel target at 50% per_tx_cap must trigger AnomalyHold: {result:?}"
    );
}

#[test]
fn anomaly_guard_passes_novel_target_below_high_value_threshold() {
    // Signal 3: novel target addr(5) at value 4_999 < 50% of per_tx_cap(10_000)=5_000 → no flag.
    // Uses signal3_only_policy to isolate Signal 3 (Signals 1+2 disabled via zero baselines).
    let policy = signal3_only_policy();
    let mut state = state_with_policy(&policy);
    // 4_999 × 100 = 499_900 < 10_000 × 50 = 500_000 → no flag.
    let tx = call_tx(addr(5), 4_999);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        !matches!(result, Err(PolicyViolation::AnomalyHold { .. })),
        "novel target below high-value threshold must NOT flag: {result:?}"
    );
}

#[test]
fn anomaly_guard_passes_known_target_at_high_value() {
    // addr(2) is already in seen_targets → not novel → no Signal 3 flag.
    // Uses signal3_only_policy to isolate Signal 3.
    let mut policy = signal3_only_policy();
    policy.history.seen_targets.insert(addr(2));
    let mut state = state_with_policy(&policy);
    let tx = call_tx(addr(2), 9_000); // high value but known target

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        !matches!(result, Err(PolicyViolation::AnomalyHold { .. })),
        "known target at high value must NOT trigger novel-target signal: {result:?}"
    );
}

#[test]
fn anomaly_guard_signal3_disabled_when_seen_targets_at_capacity() {
    use lemma_core::agent::MAX_SEEN_TARGETS;
    // Fill seen_targets to capacity with addresses addr(10..10+MAX).
    // Uses signal3_only_policy so only Signal 3 can fire.
    let mut policy = signal3_only_policy();
    for i in 10u8..10 + MAX_SEEN_TARGETS as u8 {
        policy.history.seen_targets.insert(addr(i));
    }
    assert_eq!(
        policy.history.seen_targets.len(),
        MAX_SEEN_TARGETS,
        "seen_targets must be at capacity"
    );
    let mut state = state_with_policy(&policy);
    // Novel target (not in set) at high value — signal should be disabled at capacity.
    let tx = call_tx(addr(5), 9_000);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        !matches!(result, Err(PolicyViolation::AnomalyHold { .. })),
        "signal 3 must be disabled when seen_targets is at capacity: {result:?}"
    );
}

#[test]
fn anomaly_guard_records_target_in_seen_targets_on_success() {
    // After a successful tx to addr(5), addr(5) must appear in seen_targets.
    let policy = anomaly_policy(100, 4);
    let mut state = state_with_policy(&policy);
    let tx = call_tx(addr(5), 100); // low value → no signal 3 flag

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert!(
        updated.history.seen_targets.contains(&addr(5)),
        "addr(5) must be recorded in seen_targets after successful tx"
    );
}

// ── AnomalyHold + dead-man's switch interaction ───────────────────────────────

#[test]
fn anomaly_hold_increments_dead_mans_switch() {
    let mut policy = anomaly_policy(100, 4);
    policy.auto_revoke.max_violations_per_epoch = 3;
    policy.auto_revoke.violations_this_epoch = 0;
    let mut state = state_with_policy(&policy);
    // Spike tx.
    let tx = transfer_tx(9_001); // > 5× avg(100)=500

    warden_check(&tx, &session_key(), 5, &mut state).expect_err("must be AnomalyHold");
    // Simulate executor calling handle_violation.
    handle_violation(&tx, &session_key(), 5, &mut state);

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(
        updated.auto_revoke.violations_this_epoch, 1,
        "AnomalyHold must increment dead-man's switch counter via handle_violation"
    );
}

// ── A2A counterparty check (P3·Step 16, 14 §8) ───────────────────────────────
//
// Legend for addr roles: addr(1) = payer/sender, addr(5) = payee/counterparty.

// ── Non-agent recipient — ungated pass-through ────────────────────────────────

#[test]
fn a2a_non_agent_recipient_passes_without_requirements() {
    // No A2A requirements on policy; addr(5) not registered → plain Transfer.
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    // addr(5) not registered → not in Identity Registry.
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

#[test]
fn a2a_non_agent_recipient_with_requirements_fires_missing_counterparty() {
    // Policy requires Identified tier; addr(2) (transfer target) NOT registered → reject.
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Identified;
    let mut state = state_with_policy(&policy);
    // transfer_tx sends to addr(2); addr(2) not in registry.
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(result, Err(PolicyViolation::MissingCounterparty { target }) if target == addr(2)),
        "registered-agent requirement with unregistered payee must fire MissingCounterparty: {result:?}"
    );
}

#[test]
fn a2a_reputation_requirement_alone_fires_missing_counterparty_for_unregistered() {
    // Policy has reputation requirement but no tier; unregistered payee → reject.
    let mut policy = base_policy();
    policy.min_counterparty_reputation = 50;
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(result, Err(PolicyViolation::MissingCounterparty { .. })),
        "reputation requirement with unregistered payee must fire MissingCounterparty: {result:?}"
    );
}

// ── Registered payee, no requirements — action-mask check only ───────────────

#[test]
fn a2a_registered_payee_no_requirements_passes_when_pay_agent_in_mask() {
    // addr(2) is Identified; policy has no tier/rep requirements; mask includes PayAgent.
    let policy = base_policy(); // ActionMask::all() includes PayAgent
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Identified, 50));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(
        result,
        Ok(WardenOutcome::Applied),
        "registered payee with no requirements must pass"
    );
}

#[test]
fn a2a_registered_payee_denied_when_pay_agent_not_in_mask() {
    // addr(2) is registered; policy mask lacks PayAgent → ActionDenied(PayAgent).
    let mut policy = base_policy();
    policy.allowed_actions = ActionMask::from_actions(&[Action::Transfer, Action::ContractCall]);
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Identified, 50));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(
            result,
            Err(PolicyViolation::ActionDenied {
                action: Action::PayAgent
            })
        ),
        "PayAgent not in mask must fire ActionDenied(PayAgent): {result:?}"
    );
}

// ── KYA tier gate ─────────────────────────────────────────────────────────────

#[test]
fn a2a_tier_gate_passes_when_payee_meets_required_tier() {
    // Required: Identified; payee: Identified → pass.
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Identified;
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Identified, 50));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

#[test]
fn a2a_tier_gate_passes_when_payee_exceeds_required_tier() {
    // Required: Identified; payee: Verified → pass (Verified > Identified).
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Identified;
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Verified, 90));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

#[test]
fn a2a_tier_gate_rejects_when_payee_below_required_tier() {
    // Required: Verified; payee: Identified → CounterpartyRejected.
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Verified;
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Identified, 90));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(
            result,
            Err(PolicyViolation::CounterpartyRejected {
                required_tier: KyaTier::Verified,
                actual_tier: KyaTier::Identified,
                ..
            })
        ),
        "Identified payee with Verified requirement must fire CounterpartyRejected: {result:?}"
    );
}

#[test]
fn a2a_tier_gate_rejects_none_tier_when_identified_required() {
    // Required: Identified; payee: None → reject.
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Identified;
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::None, 50));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(result, Err(PolicyViolation::CounterpartyRejected { .. })),
        "None tier against Identified requirement must fire CounterpartyRejected: {result:?}"
    );
}

// ── Reputation gate ───────────────────────────────────────────────────────────

#[test]
fn a2a_reputation_gate_passes_when_payee_meets_minimum() {
    // Min: 50; payee score: 50 → pass (>=).
    let mut policy = base_policy();
    policy.min_counterparty_reputation = 50;
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Identified, 50));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

#[test]
fn a2a_reputation_gate_rejects_below_minimum() {
    // Min: 80; payee score: 49 → CounterpartyRejected.
    let mut policy = base_policy();
    policy.min_counterparty_reputation = 80;
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Verified, 49));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(result, Err(PolicyViolation::CounterpartyRejected { .. })),
        "score 49 against min 80 must fire CounterpartyRejected: {result:?}"
    );
}

#[test]
fn a2a_reputation_gate_zero_minimum_is_always_satisfied() {
    // Default min=0: any score passes (0 = gate disabled).
    let policy = base_policy(); // min_counterparty_reputation = 0
    let mut state = state_with_policy(&policy);
    // Score = 0 (new/unscored agent) → still passes.
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Identified, 0));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

// ── Both gates together ───────────────────────────────────────────────────────

#[test]
fn a2a_both_gates_pass_when_payee_meets_both() {
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Identified;
    policy.min_counterparty_reputation = 60;
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Verified, 80));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::Applied));
}

#[test]
fn a2a_tier_check_fails_first_when_both_gates_active_and_tier_low() {
    // Tier check comes before reputation check in warden_check.
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Verified;
    policy.min_counterparty_reputation = 60;
    let mut state = state_with_policy(&policy);
    // Tier: Identified (below Verified), score: 80 (meets rep gate).
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Identified, 80));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(
            result,
            Err(PolicyViolation::CounterpartyRejected {
                actual_tier: KyaTier::Identified,
                ..
            })
        ),
        "tier check must fire first: {result:?}"
    );
}

// ── dead-man's switch interaction ─────────────────────────────────────────────

#[test]
fn a2a_counterparty_rejected_increments_dead_mans_switch() {
    // CounterpartyRejected is a violation → dead-man's switch increments.
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Verified;
    policy.auto_revoke.max_violations_per_epoch = 5;
    let mut state = state_with_policy(&policy);
    register_agent(&mut state, addr(2), agent_identity(KyaTier::None, 0));
    let tx = transfer_tx(100);

    warden_check(&tx, &session_key(), 5, &mut state).expect_err("must be CounterpartyRejected");
    handle_violation(&tx, &session_key(), 5, &mut state);

    let updated = read_policy(&state, &addr(1), &session_key()).expect("policy");
    assert_eq!(
        updated.auto_revoke.violations_this_epoch, 1,
        "CounterpartyRejected must increment dead-man's switch"
    );
}

// ── CR-S16-2: token-registry entry is NOT treated as an agent ─────────────────
//
// The token registry (executor.rs try_write_registry_entry) writes a 40-byte
// raw key under Address::registry(). The agent identity key is a 35-byte key
// with b"agent:identity:" prefix. They cannot collide — different lengths and
// different byte content. This test pins that namespace invariant:
// a tx.to that exists in the token registry (but NOT the agent registry)
// must be treated as a non-agent, so MissingCounterparty fires when A2A is
// required (not a silent pass-through).

#[test]
fn a2a_token_registry_entry_is_not_treated_as_agent_identity() {
    // Write a fake token-registry entry for addr(2) using the 40-byte raw key
    // scheme from try_write_registry_entry (executor.rs:1090-1092):
    //   key = registry_addr.as_bytes() (20) ++ contract_addr.as_bytes() (20)
    let registry = lemma_core::address::Address::registry();
    let mut raw_key = [0u8; 40];
    raw_key[..20].copy_from_slice(registry.as_bytes());
    raw_key[20..].copy_from_slice(addr(2).as_bytes());

    let mut state = InMemoryStateView::new();
    // Write the token entry directly to state.
    state.write(
        &registry,
        &raw_key,
        br#"{"address":"0000000000000000000000000000000000000002","is_token":true}"#.to_vec(),
    );

    // The agent identity key for addr(2) would be b"agent:identity:" ++ addr(2).as_bytes()
    // — a different 35-byte key. read_agent_identity should return None.
    let identity = crate::agent_registry::read_agent_identity(&state, &addr(2));
    assert!(
        identity.is_none(),
        "token-registry entry must NOT be read as an AgentIdentity (namespace isolation)"
    );

    // Set A2A requirement on the policy → MissingCounterparty must fire (not pass).
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Identified;
    write_policy(&mut state, &addr(1), &session_key(), &policy);
    let tx = transfer_tx(100); // to addr(2)
    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert!(
        matches!(result, Err(PolicyViolation::MissingCounterparty { target }) if target == addr(2)),
        "token-registry addr must be MissingCounterparty when A2A required: {result:?}"
    );
}

// ── CR-S16-3: tx.to == None (ContractDeploy) with A2A fields set ──────────────
//
// When tx.to is None, the entire A2A block is skipped (the `if let Some(target)`
// guard fails). MissingCounterparty must NOT fire even if A2A requirements are set.

#[test]
fn a2a_deploy_tx_with_a2a_requirements_skips_a2a_block() {
    // ContractDeploy has no `to` → tx.to == None.
    let mut policy = base_policy();
    policy.required_kya_tier = KyaTier::Verified;
    policy.min_counterparty_reputation = 80;
    let mut state = state_with_policy(&policy);

    // Build a ContractDeploy tx (tx.to = None).
    let deploy_tx = {
        let mut tx = Transaction::new(
            Hash::zero(),
            addr(1), // sender
            None,    // no `to` for deploy
            0,
            1,
            Amount::zero(),
            100_000,
            Amount::from_drop(1),
            TxType::ContractDeploy,
            vec![0x00, 0x61, 0x73, 0x6d], // minimal WASM magic bytes
            Signature::Unsigned,
        )
        .expect("valid deploy tx");
        tx.session_key = Some(session_key());
        tx
    };

    let result = warden_check(&deploy_tx, &session_key(), 5, &mut state);
    // Must NOT be MissingCounterparty — the A2A block is entirely skipped.
    // (May fail on other checks: ContractDeploy may be denied by ActionMask,
    // since base_policy allows ContractDeploy in ActionMask::all(). Either
    // Applied or a non-A2A error is acceptable; MissingCounterparty is not.)
    assert!(
        !matches!(result, Err(PolicyViolation::MissingCounterparty { .. })),
        "ContractDeploy (tx.to=None) must NEVER fire MissingCounterparty: {result:?}"
    );
}

// ── CR-S16-4: CounterpartyRejected carries reputation context on rep failure ──

#[test]
fn a2a_counterparty_rejected_reputation_failure_carries_reputation_values() {
    // Reputation failure must carry required_reputation + actual_reputation
    // in the error (AGENTS §12.2 — informative errors).
    let mut policy = base_policy();
    policy.min_counterparty_reputation = 80;
    let mut state = state_with_policy(&policy);
    // Register payee with score 49 (below 80).
    register_agent(&mut state, addr(2), agent_identity(KyaTier::Identified, 49));
    let tx = transfer_tx(100);

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    match result {
        Err(PolicyViolation::CounterpartyRejected {
            required_reputation,
            actual_reputation,
            reason,
            ..
        }) => {
            assert_eq!(required_reputation, 80, "must carry required_reputation=80");
            assert_eq!(actual_reputation, 49, "must carry actual_reputation=49");
            assert!(
                reason.contains("reputation"),
                "reason must mention reputation for reputation failure: {reason}"
            );
        }
        other => panic!("reputation failure must produce CounterpartyRejected, got: {other:?}"),
    }
}

// ── Mandate Receipt emission (P3·Step 17, 14 §11) ────────────────────────────

/// Helper: build mandate log from committed state after a warden_check that returned Applied.
fn mandate_log_for(
    tx: &Transaction,
    state: &InMemoryStateView,
    epoch: u64,
) -> Option<lemma_core::transaction::Log> {
    let sk = session_key();
    let action = classify_action(tx);
    build_mandate_receipt_log(tx, &sk, epoch, action, state)
}

#[test]
fn build_mandate_receipt_log_emits_log_on_applied_tx() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    warden_check(&tx, &session_key(), 5, &mut state).expect("must apply");
    let log = mandate_log_for(&tx, &state, 5);
    assert!(
        log.is_some(),
        "mandate receipt log must be emitted after Applied"
    );
}

#[test]
fn mandate_receipt_log_address_is_warden_system() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    warden_check(&tx, &session_key(), 5, &mut state).expect("must apply");
    let log = mandate_log_for(&tx, &state, 5).expect("log must be present");
    assert_eq!(
        log.address,
        lemma_core::address::Address::warden(),
        "mandate receipt log address must be Address::warden() (protocol-level event)"
    );
}

#[test]
fn mandate_receipt_log_topic0_is_event_sig_hash() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    warden_check(&tx, &session_key(), 5, &mut state).expect("must apply");
    let log = mandate_log_for(&tx, &state, 5).expect("log must be present");

    assert_eq!(log.topics.len(), 1, "must have exactly one topic");
    let expected_topic = {
        let h = blake3::hash(MANDATE_RECEIPT_EVENT_SIG);
        Hash::from_bytes(*h.as_bytes())
    };
    assert_eq!(
        log.topics[0], expected_topic,
        "topic[0] must be blake3(MANDATE_RECEIPT_EVENT_SIG)"
    );
}

#[test]
fn mandate_receipt_log_data_deserializes_to_mandate_receipt() {
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    warden_check(&tx, &session_key(), 5, &mut state).expect("must apply");
    let log = mandate_log_for(&tx, &state, 5).expect("log must be present");

    let receipt: MandateReceipt =
        serde_json::from_slice(&log.data).expect("data must deserialize to MandateReceipt");
    assert_eq!(receipt.owner, addr(1), "owner must match tx sender");
    assert_eq!(receipt.epoch, 5, "epoch must match");
    assert_eq!(
        receipt.value,
        Amount::from_drop(100),
        "value must match tx value"
    );
    assert_eq!(receipt.action, Action::Transfer, "action must be Transfer");
}

#[test]
fn mandate_receipt_log_budget_remaining_reflects_post_commit_state() {
    // budget_total = 1_000_000; after spending 100 Drop → remaining = 999_900.
    let policy = base_policy(); // budget_total = 1_000_000, spent_total = 0
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    warden_check(&tx, &session_key(), 5, &mut state).expect("must apply");
    let log = mandate_log_for(&tx, &state, 5).expect("log must be present");
    let receipt: MandateReceipt = serde_json::from_slice(&log.data).unwrap();

    assert_eq!(
        receipt.budget_remaining,
        Amount::from_drop(999_900),
        "budget_remaining must reflect post-commit state (budget_total - spent_total)"
    );
}

#[test]
fn build_mandate_receipt_log_returns_none_for_missing_policy() {
    // Policy not in state → None (no panic, no halt — AGENTS §7.2).
    let state = InMemoryStateView::new();
    let tx = transfer_tx(100);
    let log = build_mandate_receipt_log(&tx, &session_key(), 5, Action::Transfer, &state);
    assert!(
        log.is_none(),
        "missing policy must return None without panicking"
    );
}

#[test]
fn mandate_receipt_not_emitted_for_pending_cosign() {
    // PendingOwnerCosign: no counters committed, so policy re-read gives pre-check state.
    // No mandate receipt should be emitted (tx not applied).
    let mut policy = base_policy();
    policy.cosign_threshold = Some(Amount::from_drop(50)); // small threshold
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100); // > threshold, no cosig

    let result = warden_check(&tx, &session_key(), 5, &mut state);
    assert_eq!(result, Ok(WardenOutcome::PendingOwnerCosign));
    // Executor does NOT call build_mandate_receipt_log for PendingOwnerCosign.
    // (This test confirms that PendingOwnerCosign is NOT Applied, by construction.)
}

#[test]
fn mandate_receipt_is_deterministic_for_same_inputs() {
    // Two identical calls to build_mandate_receipt_log must produce identical logs.
    let policy = base_policy();
    let mut state = state_with_policy(&policy);
    let tx = transfer_tx(100);

    warden_check(&tx, &session_key(), 5, &mut state).expect("must apply");
    let log_a = mandate_log_for(&tx, &state, 5).expect("log must be present");
    let log_b = mandate_log_for(&tx, &state, 5).expect("log must be present");
    assert_eq!(
        log_a, log_b,
        "mandate receipt log must be deterministic (AGENTS §7.1)"
    );
}
