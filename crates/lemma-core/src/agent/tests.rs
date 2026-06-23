//! Tests for `lemma_core::agent` — Warden policy types (P3·Steps 13–17).

use super::*;
use crate::address::Address;
use crate::amount::Amount;

// ── Test helpers ─────────────────────────────────────────────────────────────

fn test_address(n: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = n;
    Address::from_raw_bytes(bytes)
}

fn test_policy() -> AgentPolicy {
    AgentPolicy {
        session_key: vec![1, 2, 3, 4],
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

/// Build a CategoryCaps with one TRADE category covering Transfer actions.
fn trade_caps(cap: u128) -> CategoryCaps {
    let mut caps = CategoryCaps::new();
    let mut actions = std::collections::BTreeSet::new();
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

// ── Action ───────────────────────────────────────────────────────────────────

#[test]
fn action_display_matches_variant_name() {
    assert_eq!(Action::Transfer.to_string(), "Transfer");
    assert_eq!(Action::ContractCall.to_string(), "ContractCall");
    assert_eq!(Action::ContractDeploy.to_string(), "ContractDeploy");
    assert_eq!(Action::Stake.to_string(), "Stake");
    assert_eq!(Action::Unstake.to_string(), "Unstake");
    assert_eq!(Action::GovernanceVote.to_string(), "GovernanceVote");
}

#[test]
fn action_serde_roundtrip() {
    let action = Action::ContractCall;
    let json = serde_json::to_string(&action).expect("serialize");
    let back: Action = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(action, back);
}

// ── ActionMask ───────────────────────────────────────────────────────────────

#[test]
fn action_mask_permits_specified_actions() {
    let mask = ActionMask::from_actions(&[Action::Transfer, Action::ContractCall]);
    assert!(mask.permits(Action::Transfer));
    assert!(mask.permits(Action::ContractCall));
    assert!(!mask.permits(Action::Stake));
    assert!(!mask.permits(Action::Unstake));
    assert!(!mask.permits(Action::ContractDeploy));
    assert!(!mask.permits(Action::GovernanceVote));
}

#[test]
fn action_mask_all_permits_everything() {
    let mask = ActionMask::all();
    assert!(mask.permits(Action::Transfer));
    assert!(mask.permits(Action::ContractCall));
    assert!(mask.permits(Action::ContractDeploy));
    assert!(mask.permits(Action::Stake));
    assert!(mask.permits(Action::Unstake));
    assert!(mask.permits(Action::GovernanceVote));
}

#[test]
fn action_mask_none_permits_nothing() {
    let mask = ActionMask::none();
    assert!(!mask.permits(Action::Transfer));
    assert!(!mask.permits(Action::ContractCall));
}

#[test]
fn action_mask_serde_roundtrip() {
    let mask = ActionMask::from_actions(&[Action::Transfer, Action::Stake]);
    let json = serde_json::to_string(&mask).expect("serialize");
    let back: ActionMask = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(mask, back);
}

// ── AllowList ────────────────────────────────────────────────────────────────

#[test]
fn allow_list_any_contains_everything() {
    let list = AllowList::any();
    assert!(list.contains(&test_address(1)));
    assert!(list.contains(&test_address(255)));
    assert!(list.contains(&Address::zero()));
}

#[test]
fn allow_list_specific_contains_only_listed() {
    let addr1 = test_address(1);
    let addr2 = test_address(2);
    let addr3 = test_address(3);
    let list = AllowList::from_targets(&[addr1, addr2]);
    assert!(list.contains(&addr1));
    assert!(list.contains(&addr2));
    assert!(!list.contains(&addr3));
}

#[test]
fn allow_list_serde_roundtrip_any() {
    let list = AllowList::any();
    let json = serde_json::to_string(&list).expect("serialize");
    let back: AllowList = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(list, back);
}

#[test]
fn allow_list_serde_roundtrip_specific() {
    let list = AllowList::from_targets(&[test_address(1), test_address(2)]);
    let json = serde_json::to_string(&list).expect("serialize");
    let back: AllowList = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(list, back);
}

// ── KyaTier ──────────────────────────────────────────────────────────────────

#[test]
fn kya_tier_ordering_matches_discriminants() {
    assert!(KyaTier::None < KyaTier::Identified);
    assert!(KyaTier::Identified < KyaTier::Verified);
    assert!(KyaTier::None < KyaTier::Verified);
}

#[test]
fn kya_tier_default_is_none() {
    assert_eq!(KyaTier::default(), KyaTier::None);
}

// ── AgentPolicy ──────────────────────────────────────────────────────────────

#[test]
fn agent_policy_serde_roundtrip() {
    let policy = test_policy();
    let json = serde_json::to_string(&policy).expect("serialize");
    let back: AgentPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, back);
}

#[test]
fn agent_policy_serde_with_extensions() {
    let mut policy = test_policy();
    policy.refill_per_epoch = Amount::from_drop(5_000);
    policy.active_window = Some(EpochRange {
        start_epoch: 10,
        end_epoch: 50,
    });
    policy.cosign_threshold = Some(Amount::from_drop(50_000));
    policy.auto_revoke = AutoRevoke {
        max_violations_per_epoch: 3,
        violations_this_epoch: 0,
    };
    policy.kya_tier = KyaTier::Verified;

    let json = serde_json::to_string(&policy).expect("serialize");
    let back: AgentPolicy = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(policy, back);
}

#[test]
fn agent_policy_backward_compat_missing_extensions() {
    // Simulate a policy serialized without extension fields (pre-Step 14).
    // serde(default) should fill them with defaults.
    let json = r#"{
        "session_key": [1,2,3],
        "expiry_epoch": 50,
        "budget_total": "100000",
        "per_tx_cap": "1000",
        "per_epoch_cap": "10000",
        "allowed_targets": {"type": "any"},
        "allowed_actions": {"allowed": ["transfer"]},
        "spent_total": "0",
        "spent_this_epoch": "0",
        "last_epoch": 0
    }"#;
    let policy: AgentPolicy = serde_json::from_str(json).expect("deserialize");
    assert_eq!(policy.refill_per_epoch, Amount::zero());
    assert_eq!(policy.budget_ceiling, None);
    assert_eq!(policy.categories, CategoryCaps::new());
    assert_eq!(policy.active_window, None);
    assert_eq!(policy.cosign_threshold, None);
    assert_eq!(policy.auto_revoke, AutoRevoke::default());
    assert_eq!(policy.kya_tier, KyaTier::None);
}

// ── PolicyViolation ──────────────────────────────────────────────────────────

#[test]
fn policy_violation_display_is_informative() {
    let v = PolicyViolation::Expired {
        expiry_epoch: 50,
        current_epoch: 60,
    };
    let msg = v.to_string();
    assert!(msg.contains("expired"));
    assert!(msg.contains("50"));
    assert!(msg.contains("60"));
}

#[test]
fn policy_violation_per_tx_exceeded_display() {
    let v = PolicyViolation::PerTxExceeded {
        value: Amount::from_drop(20_000),
        cap: Amount::from_drop(10_000),
    };
    let msg = v.to_string();
    assert!(msg.contains("per-tx cap exceeded"));
}

#[test]
fn policy_violation_action_denied_display() {
    let v = PolicyViolation::ActionDenied {
        action: Action::Stake,
    };
    let msg = v.to_string();
    assert!(msg.contains("Stake"));
    assert!(msg.contains("denied"));
}

// ── AutoRevoke ───────────────────────────────────────────────────────────────

#[test]
fn auto_revoke_default_is_disabled() {
    let ar = AutoRevoke::default();
    assert_eq!(ar.max_violations_per_epoch, 0);
    assert_eq!(ar.violations_this_epoch, 0);
}

// ── CategoryBudget + CategoryCaps (P3·Step 14) ───────────────────────────────

#[test]
fn category_caps_new_is_empty() {
    let caps = CategoryCaps::new();
    assert!(caps.is_empty());
    assert_eq!(caps.category_of(Action::Transfer), None);
}

#[test]
fn category_caps_insert_and_lookup() {
    let caps = trade_caps(50_000);
    assert!(!caps.is_empty());
    assert_eq!(caps.category_of(Action::Transfer), Some("TRADE"));
    assert_eq!(caps.category_of(Action::ContractCall), None);
}

#[test]
fn category_caps_spent_and_cap() {
    let caps = trade_caps(50_000);
    assert_eq!(caps.cap("TRADE"), Amount::from_drop(50_000));
    assert_eq!(caps.spent("TRADE"), Amount::zero());
}

#[test]
fn category_caps_add_spent_accumulates() {
    let mut caps = trade_caps(50_000);
    caps.add_spent("TRADE", Amount::from_drop(10_000));
    caps.add_spent("TRADE", Amount::from_drop(5_000));
    assert_eq!(caps.spent("TRADE"), Amount::from_drop(15_000));
}

#[test]
fn category_caps_reset_epoch_clears_spent() {
    let mut caps = trade_caps(50_000);
    caps.add_spent("TRADE", Amount::from_drop(40_000));
    assert_eq!(caps.spent("TRADE"), Amount::from_drop(40_000));
    caps.reset_epoch();
    assert_eq!(caps.spent("TRADE"), Amount::zero());
}

#[test]
fn category_caps_insert_enforces_max_categories() {
    let mut caps = CategoryCaps::new();
    let actions_set: std::collections::BTreeSet<Action> = [Action::Transfer].into_iter().collect();
    for i in 0..MAX_CATEGORIES {
        let inserted = caps.insert(
            format!("CAT_{i}"),
            CategoryBudget {
                cap: Amount::from_drop(1_000),
                spent: Amount::zero(),
                actions: actions_set.clone(),
            },
        );
        assert!(inserted, "should insert category {i}");
    }
    // One more should fail.
    let rejected = caps.insert(
        "TOO_MANY",
        CategoryBudget {
            cap: Amount::from_drop(1_000),
            spent: Amount::zero(),
            actions: actions_set,
        },
    );
    assert!(!rejected, "should reject at max categories");
}

#[test]
fn category_caps_serde_roundtrip() {
    let caps = trade_caps(50_000);
    let json = serde_json::to_string(&caps).expect("serialize");
    let back: CategoryCaps = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(caps, back);
}

// ── PolicyViolation: Step 14 variants ────────────────────────────────────────

#[test]
fn policy_violation_outside_window_display() {
    let v = PolicyViolation::OutsideWindow {
        current_epoch: 5,
        start_epoch: 10,
        end_epoch: 20,
    };
    let msg = v.to_string();
    assert!(msg.contains("outside") || msg.contains("window") || msg.contains("5"));
}

#[test]
fn policy_violation_category_exceeded_display() {
    let v = PolicyViolation::CategoryExceeded {
        category: "TRADE".to_string(),
        spent: Amount::from_drop(55_000),
        cap: Amount::from_drop(50_000),
    };
    let msg = v.to_string();
    assert!(msg.contains("TRADE"));
    assert!(msg.contains("cap"));
}

// ── WardenOutcome: Step 14 variant ───────────────────────────────────────────

#[test]
fn warden_outcome_pending_cosign_is_not_applied() {
    assert_ne!(WardenOutcome::PendingOwnerCosign, WardenOutcome::Applied);
}

// ── AnomalyConfig + AnomalyHistory (P3·Step 15) ──────────────────────────────

#[test]
fn anomaly_config_defaults_to_disabled() {
    let cfg = AnomalyConfig::default();
    assert!(
        !cfg.enabled,
        "anomaly detection must be opt-in (disabled by default)"
    );
}

#[test]
fn anomaly_config_default_spike_ratio_is_named_constant() {
    let cfg = AnomalyConfig::default();
    assert_eq!(
        cfg.spike_ratio, ANOMALY_SPIKE_RATIO_DEFAULT,
        "default spike_ratio must equal ANOMALY_SPIKE_RATIO_DEFAULT"
    );
}

#[test]
fn anomaly_config_default_burst_ratio_is_named_constant() {
    let cfg = AnomalyConfig::default();
    assert_eq!(
        cfg.burst_ratio, ANOMALY_BURST_RATIO_DEFAULT,
        "default burst_ratio must equal ANOMALY_BURST_RATIO_DEFAULT"
    );
}

#[test]
fn anomaly_history_defaults_to_no_baseline() {
    let h = AnomalyHistory::default();
    assert!(
        !h.has_history,
        "new history must have has_history=false (bootstrap guard)"
    );
    assert_eq!(h.avg_value_ema, Amount::zero());
    assert_eq!(h.tx_count_this_epoch, 0);
    assert_eq!(h.avg_tx_count_ema, 0);
}

#[test]
fn policy_violation_agents_paused_displays_correctly() {
    let v = PolicyViolation::AgentsPaused;
    let msg = format!("{v}");
    assert!(
        msg.contains("paused"),
        "AgentsPaused display must mention 'paused': {msg}"
    );
}

#[test]
fn policy_violation_anomaly_hold_carries_reason() {
    let v = PolicyViolation::AnomalyHold {
        reason: "value spike: 10x average".to_owned(),
    };
    let msg = format!("{v}");
    assert!(
        msg.contains("10x"),
        "AnomalyHold display must include the reason: {msg}"
    );
}

#[test]
fn anomaly_config_serde_roundtrip_preserves_enabled_flag() {
    let cfg = AnomalyConfig {
        enabled: true,
        spike_ratio: 250,
        ..AnomalyConfig::default()
    };
    let json = serde_json::to_string(&cfg).unwrap();
    let back: AnomalyConfig = serde_json::from_str(&json).unwrap();
    assert!(back.enabled);
    assert_eq!(back.spike_ratio, 250);
}

#[test]
fn anomaly_history_serde_roundtrip_preserves_ema() {
    let mut seen = std::collections::BTreeSet::new();
    seen.insert(test_address(7));
    let h = AnomalyHistory {
        avg_value_ema: Amount::from_drop(5_000),
        tx_count_this_epoch: 3,
        avg_tx_count_ema: 2,
        has_history: true,
        seen_targets: seen,
    };
    let json = serde_json::to_string(&h).unwrap();
    let back: AnomalyHistory = serde_json::from_str(&json).unwrap();
    assert_eq!(back, h);
}

// ── Action::PayAgent + AgentIdentity + Step 16 fields (P3·Step 16) ───────────

#[test]
fn action_pay_agent_is_distinct_from_transfer() {
    assert_ne!(Action::PayAgent, Action::Transfer);
}

#[test]
fn action_pay_agent_display_is_pay_agent() {
    assert_eq!(format!("{}", Action::PayAgent), "PayAgent");
}

#[test]
fn action_mask_all_includes_pay_agent() {
    let mask = ActionMask::all();
    assert!(
        mask.permits(Action::PayAgent),
        "ActionMask::all() must include PayAgent (agents with all permissions may pay agents)"
    );
}

#[test]
fn action_mask_none_excludes_pay_agent() {
    let mask = ActionMask::none();
    assert!(!mask.permits(Action::PayAgent));
}

#[test]
fn agent_identity_serde_roundtrip() {
    let id = AgentIdentity {
        owner: test_address(1),
        kya_tier: KyaTier::Verified,
        reputation_score: 85,
    };
    let json = serde_json::to_string(&id).unwrap();
    let back: AgentIdentity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, id);
}

#[test]
fn agent_identity_kya_tier_ord_verified_gt_identified_gt_none() {
    assert!(KyaTier::Verified > KyaTier::Identified);
    assert!(KyaTier::Identified > KyaTier::None);
    assert!(KyaTier::Verified > KyaTier::None);
}

#[test]
fn policy_violation_counterparty_rejected_displays_tier_and_reputation_info() {
    let v = PolicyViolation::CounterpartyRejected {
        reason: "KYA tier below minimum",
        required_tier: KyaTier::Verified,
        actual_tier: KyaTier::None,
        required_reputation: 80,
        actual_reputation: 30,
    };
    let msg = format!("{v}");
    assert!(
        msg.contains("Verified"),
        "display must include required tier: {msg}"
    );
    assert!(
        msg.contains("None"),
        "display must include actual tier: {msg}"
    );
    assert!(
        msg.contains("80"),
        "display must include required reputation: {msg}"
    );
    assert!(
        msg.contains("30"),
        "display must include actual reputation: {msg}"
    );
}

#[test]
fn policy_violation_missing_counterparty_displays_target() {
    let target = test_address(42);
    let v = PolicyViolation::MissingCounterparty { target };
    let msg = format!("{v}");
    assert!(
        msg.contains("not a registered agent"),
        "display must mention unregistered: {msg}"
    );
}

#[test]
fn policy_required_kya_tier_defaults_to_none() {
    let p = test_policy();
    assert_eq!(
        p.required_kya_tier,
        KyaTier::None,
        "required_kya_tier must default to None (A2A gating opt-in)"
    );
}

#[test]
fn policy_min_counterparty_reputation_defaults_to_zero() {
    let p = test_policy();
    assert_eq!(
        p.min_counterparty_reputation, 0,
        "min_counterparty_reputation must default to 0 (A2A reputation gate opt-in)"
    );
}

#[test]
fn reputation_score_max_constant_is_100() {
    assert_eq!(REPUTATION_SCORE_MAX, 100, "scale must be 0–100 per spec §6");
}

// ── MandateReceipt (P3·Step 17) ───────────────────────────────────────────────

fn mandate_receipt_fixture() -> MandateReceipt {
    MandateReceipt {
        owner: test_address(1),
        session_key: vec![0xAA, 0xBB],
        policy_hash: crate::hash::Hash::zero(),
        action: Action::Transfer,
        target: Some(test_address(2)),
        value: Amount::from_drop(1_000),
        budget_remaining: Amount::from_drop(999_000),
        epoch: 5,
        kya_tier: KyaTier::Identified,
        cosigned: false,
    }
}

#[test]
fn mandate_receipt_serde_roundtrip() {
    let r = mandate_receipt_fixture();
    let json = serde_json::to_string(&r).unwrap();
    let back: MandateReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn mandate_receipt_to_log_uses_warden_address() {
    let log = mandate_receipt_fixture().to_log();
    assert_eq!(
        log.address,
        crate::address::Address::warden(),
        "mandate receipt log must use Address::warden() as the emitter"
    );
}

#[test]
fn mandate_receipt_to_log_has_event_sig_as_topic0() {
    let log = mandate_receipt_fixture().to_log();
    assert_eq!(
        log.topics.len(),
        1,
        "must have exactly one topic (event sig)"
    );
    // topic[0] must be blake3(MANDATE_RECEIPT_EVENT_SIG) — deterministic.
    let expected = {
        let hash = blake3::hash(MANDATE_RECEIPT_EVENT_SIG);
        crate::hash::Hash::from_bytes(*hash.as_bytes())
    };
    assert_eq!(
        log.topics[0], expected,
        "topic[0] must be the event signature hash"
    );
}

#[test]
fn mandate_receipt_to_log_data_is_json_containing_fields() {
    let r = mandate_receipt_fixture();
    let log = r.to_log();
    let json_str = std::str::from_utf8(&log.data).expect("data must be valid UTF-8");
    assert!(
        json_str.contains("epoch"),
        "data must contain epoch field: {json_str}"
    );
    // Action is serialized as snake_case ("transfer") per #[serde(rename_all = "snake_case")].
    assert!(
        json_str.contains("transfer"),
        "data must contain action: {json_str}"
    );
}

#[test]
fn mandate_receipt_event_sig_constant_is_non_empty() {
    assert!(!MANDATE_RECEIPT_EVENT_SIG.is_empty());
}

#[test]
fn mandate_receipt_to_log_is_deterministic_for_same_input() {
    let r = mandate_receipt_fixture();
    assert_eq!(
        r.to_log(),
        r.to_log(),
        "to_log() must be deterministic (AGENTS §7.1)"
    );
}
