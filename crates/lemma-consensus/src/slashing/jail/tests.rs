//! Tests for `lemma_consensus::slashing::jail` — tombstone + jail (B3b, spec §5.2/§5.5).

use lemma_core::{
    address::Address,
    amount::Amount,
    validator::{ConsensusKey, Stake, Validator, ValidatorStatus},
};

use crate::slashing::jail::{jail, tombstone};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn addr(n: u8) -> Address {
    Address::from_public_key(&[n; 32])
}

fn make_validator() -> Validator {
    Validator {
        address: addr(1),
        consensus_pubkey: ConsensusKey::from_bytes(vec![1; 32], vec![1; 32]),
        status: ValidatorStatus::Bonded,
        tombstoned: false,
        self_stake: Stake {
            active: Amount::from_drop(20_000_000),
            pending_active: Amount::zero(),
            pending_inactive: Vec::new(),
            inactive: Amount::zero(),
        },
        delegated: Amount::zero(),
        commission_bps: 0,
        jailed_until: None,
    }
}

// ── tombstone ─────────────────────────────────────────────────────────────────

#[test]
fn tombstone_sets_tombstoned_flag() {
    let mut v = make_validator();
    tombstone(&mut v);
    assert!(v.tombstoned, "tombstone must set tombstoned = true");
}

#[test]
fn tombstone_is_idempotent() {
    let mut v = make_validator();
    tombstone(&mut v);
    tombstone(&mut v); // second call — must not panic or change other fields
    assert!(v.tombstoned);
    assert_eq!(
        v.status,
        ValidatorStatus::Bonded,
        "status unchanged by tombstone"
    );
}

#[test]
fn tombstone_does_not_change_status() {
    // Tombstone is a ban flag, not a status change — status stays for audit.
    let mut v = make_validator();
    tombstone(&mut v);
    assert_eq!(
        v.status,
        ValidatorStatus::Bonded,
        "tombstone does not change ValidatorStatus — retained for audit"
    );
}

#[test]
fn tombstone_does_not_touch_stake() {
    let mut v = make_validator();
    let initial_active = v.self_stake.active;
    tombstone(&mut v);
    assert_eq!(
        v.self_stake.active, initial_active,
        "tombstone must not touch stake"
    );
}

// ── jail ──────────────────────────────────────────────────────────────────────

#[test]
fn jail_sets_jailed_until() {
    let mut v = make_validator();
    jail(&mut v, 1_000_000);
    assert_eq!(
        v.jailed_until,
        Some(1_000_000),
        "jail must set jailed_until"
    );
}

#[test]
fn jail_extends_sentence_when_new_is_longer() {
    let mut v = make_validator();
    jail(&mut v, 1_000_000);
    jail(&mut v, 2_000_000); // second offense — longer sentence
    assert_eq!(
        v.jailed_until,
        Some(2_000_000),
        "jail must extend to the longer sentence"
    );
}

#[test]
fn jail_keeps_existing_when_new_is_shorter() {
    let mut v = make_validator();
    jail(&mut v, 2_000_000);
    jail(&mut v, 500_000); // lighter offense — must not reduce existing sentence
    assert_eq!(
        v.jailed_until,
        Some(2_000_000),
        "jail must not shorten an existing sentence (max semantics)"
    );
}

#[test]
fn jail_is_idempotent_same_time() {
    let mut v = make_validator();
    jail(&mut v, 1_000_000);
    jail(&mut v, 1_000_000); // same time — no change
    assert_eq!(v.jailed_until, Some(1_000_000));
}

#[test]
fn jail_does_not_tombstone() {
    let mut v = make_validator();
    jail(&mut v, 1_000_000);
    assert!(
        !v.tombstoned,
        "jail must not set tombstoned (finite sentence, not permanent)"
    );
}

#[test]
fn jail_does_not_change_status() {
    let mut v = make_validator();
    jail(&mut v, 1_000_000);
    assert_eq!(
        v.status,
        ValidatorStatus::Bonded,
        "jail does not change ValidatorStatus — epoch boundary handles exclusion"
    );
}

#[test]
fn jail_does_not_touch_stake() {
    let mut v = make_validator();
    let initial_active = v.self_stake.active;
    jail(&mut v, 1_000_000);
    assert_eq!(
        v.self_stake.active, initial_active,
        "jail must not touch stake"
    );
}

// ── Combined ──────────────────────────────────────────────────────────────────

#[test]
fn tombstone_then_jail_both_take_effect() {
    // A tombstoned validator could also be jailed (belt-and-suspenders).
    let mut v = make_validator();
    tombstone(&mut v);
    jail(&mut v, 9_999_999);
    assert!(v.tombstoned);
    assert_eq!(v.jailed_until, Some(9_999_999));
}
