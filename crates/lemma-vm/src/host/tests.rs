//! Tests for [`CallContext`], [`HostState`], and [`HostFunctions`].
//!
//! Coverage: all 16 host functions in the HostFunctions trait + CallContext enter/exit + OOG safety.

use std::collections::BTreeMap;

use lemma_core::{address::Address, amount::Amount, hash::Hash};
use lemma_crypto::KeyPair;

use crate::{
    gas::{FuelMeter, Gas, GasMeter, GasSchedule},
    host::{BlockContext, CallContext, HostFunctions, HostState},
    runtime::{LemmaEngine, MAX_CALL_DEPTH},
    state::{ContractStateView, InMemoryStateView},
    VmError,
};

// ── Test helpers ──────────────────────────────────────────────────────────────

fn test_address(seed: u8) -> Address {
    Address::from_public_key(&[seed; 32])
}

fn test_amount(drops: u128) -> Amount {
    Amount::from_drop(drops)
}

fn test_block(sender: Address) -> BlockContext {
    BlockContext {
        height: 100,
        timestamp: 1_700_000_000,
        msg_sender: sender,
        msg_value: Amount::zero(),
        tx_origin: sender,
        // In host tests, contract == sender (single-frame, no cross-contract calls).
        // M3: storage ops use block.contract, not block.msg_sender.
        contract: sender,
    }
}

/// Build a `HostState` with a given gas budget and optional pre-seeded balances.
fn make_host(budget: u64, balances: BTreeMap<Address, Amount>) -> HostState<InMemoryStateView> {
    let sender = test_address(1);
    let meter = FuelMeter::new(Gas::new(budget));
    let engine = LemmaEngine::new().expect("test engine must initialise");
    let schedule = GasSchedule::devnet();
    let call_ctx = CallContext::new();
    let block = test_block(sender);
    let state = InMemoryStateView::with_balances(balances);
    // Pass empty calldata — host tests don't exercise the input() host function.
    HostState::new(meter, engine, schedule, call_ctx, block, state, vec![])
}

/// Build a `HostState` with no pre-seeded balances.
fn make_host_empty(budget: u64) -> HostState<InMemoryStateView> {
    make_host(budget, BTreeMap::new())
}

// ── CallContext tests ─────────────────────────────────────────────────────────

#[test]
fn call_context_new_has_zero_depth_and_empty_active() {
    let ctx = CallContext::new();
    assert_eq!(ctx.depth(), 0);
}

#[test]
fn enter_call_increments_depth_and_inserts_address() {
    let mut ctx = CallContext::new();
    let addr = test_address(10);
    ctx.enter_call(addr).expect("first enter should succeed");
    assert_eq!(ctx.depth(), 1);
}

#[test]
fn enter_call_rejects_at_max_depth() {
    let mut ctx = CallContext::new();
    // Fill up to MAX_CALL_DEPTH using distinct addresses.
    for i in 0..MAX_CALL_DEPTH {
        let addr = Address::from_public_key(&[i as u8; 32]);
        ctx.enter_call(addr)
            .expect("should succeed below max depth");
    }
    // One more should fail.
    let extra = test_address(200);
    let err = ctx.enter_call(extra).expect_err("should fail at max depth");
    assert!(matches!(err, VmError::CallDepthExceeded));
}

#[test]
fn enter_call_rejects_reentrant_address() {
    let mut ctx = CallContext::new();
    let addr = test_address(5);
    ctx.enter_call(addr).expect("first enter should succeed");
    let err = ctx
        .enter_call(addr)
        .expect_err("reentrant enter should fail");
    assert!(matches!(err, VmError::Reentrancy { addr: a } if a == addr));
}

#[test]
fn exit_call_decrements_depth_and_removes_address() {
    let mut ctx = CallContext::new();
    let addr = test_address(7);
    ctx.enter_call(addr).expect("enter should succeed");
    assert_eq!(ctx.depth(), 1);
    ctx.exit_call(&addr);
    assert_eq!(ctx.depth(), 0);
    // After exit, the same address can be entered again.
    ctx.enter_call(addr)
        .expect("re-enter after exit should succeed");
}

// ── Storage tests ─────────────────────────────────────────────────────────────

#[test]
fn storage_read_cold_charges_cold_cost() {
    let schedule = GasSchedule::devnet();
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    let before = host.meter.remaining();
    host.storage_read(b"key").expect("read should succeed");
    let after = host.meter.remaining();

    let charged = before.as_u64() - after.as_u64();
    assert_eq!(charged, schedule.storage_read_cold.as_u64());
}

#[test]
fn storage_read_warm_charges_warm_cost_on_second_access() {
    let schedule = GasSchedule::devnet();
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    // First access — cold.
    host.storage_read(b"key")
        .expect("first read should succeed");

    let before_warm = host.meter.remaining();
    // Second access — warm.
    host.storage_read(b"key")
        .expect("second read should succeed");
    let after_warm = host.meter.remaining();

    let charged = before_warm.as_u64() - after_warm.as_u64();
    assert_eq!(charged, schedule.storage_read_warm.as_u64());
}

#[test]
fn storage_write_create_charges_create_cost() {
    let schedule = GasSchedule::devnet();
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    let before = host.meter.remaining();
    host.storage_write(b"new_key", b"value")
        .expect("write should succeed");
    let after = host.meter.remaining();

    let charged = before.as_u64() - after.as_u64();
    assert_eq!(charged, schedule.storage_write_create.as_u64());
}

#[test]
fn storage_write_update_charges_update_cost_when_key_exists() {
    let schedule = GasSchedule::devnet();
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    // Create the key first.
    host.storage_write(b"key", b"v1")
        .expect("create should succeed");

    let before = host.meter.remaining();
    // Update the existing key.
    host.storage_write(b"key", b"v2")
        .expect("update should succeed");
    let after = host.meter.remaining();

    let charged = before.as_u64() - after.as_u64();
    assert_eq!(charged, schedule.storage_write_update.as_u64());
}

#[test]
fn storage_delete_charges_delete_cost_and_issues_refund() {
    let schedule = GasSchedule::devnet();
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    // Write a key first.
    host.storage_write(b"key", b"value")
        .expect("write should succeed");

    let before = host.meter.remaining();
    let refund_before = host.meter.accumulated_refund();
    host.storage_delete(b"key").expect("delete should succeed");
    let after = host.meter.remaining();
    let refund_after = host.meter.accumulated_refund();

    let charged = before.as_u64() - after.as_u64();
    assert_eq!(charged, schedule.storage_delete.as_u64());
    assert_eq!(
        refund_after.as_u64() - refund_before.as_u64(),
        schedule.storage_delete_refund.as_u64()
    );
}

// ── Transfer tests ────────────────────────────────────────────────────────────

#[test]
fn transfer_debits_sender_and_credits_recipient() {
    let sender = test_address(1);
    let recipient = test_address(2);
    let initial_balance = test_amount(1_000_000_000_000_000_000); // 1 LEM

    let mut balances = BTreeMap::new();
    balances.insert(sender, initial_balance);
    let mut host = make_host(10_000_000, balances);

    let transfer_amount = test_amount(500_000_000_000_000_000); // 0.5 LEM
    host.transfer(recipient, transfer_amount)
        .expect("transfer should succeed");

    let sender_balance = host.state.balance(&sender);
    let recipient_balance = host.state.balance(&recipient);

    assert_eq!(
        sender_balance,
        initial_balance.checked_sub(transfer_amount).unwrap()
    );
    assert_eq!(recipient_balance, transfer_amount);
}

#[test]
fn transfer_fails_insufficient_funds_without_panic() {
    let sender = test_address(1);
    let recipient = test_address(2);

    // Sender has 100 drops, tries to send 200.
    let mut balances = BTreeMap::new();
    balances.insert(sender, test_amount(100));
    let mut host = make_host(10_000_000, balances);

    let err = host
        .transfer(recipient, test_amount(200))
        .expect_err("should fail with insufficient funds");

    assert!(matches!(
        err,
        VmError::InsufficientFunds {
            required,
            available
        } if required == test_amount(200) && available == test_amount(100)
    ));
}

#[test]
fn transfer_applies_balance_immediately_cei_contract() {
    // Verify that after a successful transfer, the sender's balance is
    // immediately reduced (CEI — effect applied before any further call).
    let sender = test_address(1);
    let recipient = test_address(2);
    let initial = test_amount(1_000);

    let mut balances = BTreeMap::new();
    balances.insert(sender, initial);
    let mut host = make_host(10_000_000, balances);

    host.transfer(recipient, test_amount(300))
        .expect("transfer should succeed");

    // Sender balance is immediately reduced — no deferred application.
    assert_eq!(host.state.balance(&sender), test_amount(700));
    assert_eq!(host.state.balance(&recipient), test_amount(300));
}

// ── Crypto tests ──────────────────────────────────────────────────────────────

#[test]
fn hash_blake3_charges_per_byte() {
    let schedule = GasSchedule::devnet();
    let data = b"hello lemma";
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    let before = host.meter.remaining();
    host.hash_blake3(data).expect("hash should succeed");
    let after = host.meter.remaining();

    let expected_cost = schedule.hash_blake3_base.as_u64()
        + schedule.hash_blake3_per_byte.as_u64() * data.len() as u64;
    let charged = before.as_u64() - after.as_u64();
    assert_eq!(charged, expected_cost);
}

#[test]
fn hash_keccak256_charges_per_byte() {
    let schedule = GasSchedule::devnet();
    let data = b"hello lemma";
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    let before = host.meter.remaining();
    host.hash_keccak256(data).expect("hash should succeed");
    let after = host.meter.remaining();

    let expected_cost = schedule.hash_keccak256_base.as_u64()
        + schedule.hash_keccak256_per_byte.as_u64() * data.len() as u64;
    let charged = before.as_u64() - after.as_u64();
    assert_eq!(charged, expected_cost);
}

#[test]
fn verify_signature_charges_verify_cost() {
    let schedule = GasSchedule::devnet();
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    let kp = KeyPair::generate().expect("key generation should succeed");
    let pk = kp.public_key();
    let msg = b"test message";
    let sig = kp.sign(msg);

    let pk_bytes = bincode::serialize(&pk).expect("serialize pk");
    let sig_bytes = bincode::serialize(&sig).expect("serialize sig");

    let before = host.meter.remaining();
    let result = host
        .verify_signature(&pk_bytes, msg, &sig_bytes)
        .expect("verify should not error");
    let after = host.meter.remaining();

    assert!(result, "valid signature should verify as true");
    // Hybrid verify runs BOTH Ed25519 AND ML-DSA-65 — charge must reflect both
    // (verify_mldsa65 ≈ 10× verify_ed25519; under-charging is a DoS vector).
    let expected_cost = schedule.verify_ed25519.as_u64() + schedule.verify_mldsa65.as_u64();
    let charged = before.as_u64() - after.as_u64();
    assert_eq!(charged, expected_cost);
}

#[test]
fn verify_signature_returns_false_for_invalid_sig() {
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    let kp = KeyPair::generate().expect("key generation should succeed");
    let pk = kp.public_key();
    let msg = b"test message";
    let sig = kp.sign(msg);

    let pk_bytes = bincode::serialize(&pk).expect("serialize pk");
    let sig_bytes = bincode::serialize(&sig).expect("serialize sig");

    // Tamper with the message — signature should not verify.
    let result = host
        .verify_signature(&pk_bytes, b"tampered message", &sig_bytes)
        .expect("verify should not error on invalid sig");

    assert!(!result, "invalid signature should return false, not error");
}

// ── Event tests ───────────────────────────────────────────────────────────────

#[test]
fn emit_event_charges_per_byte_and_stores_log() {
    let schedule = GasSchedule::devnet();
    let data = b"event data payload";
    let topics = vec![Hash::zero()];
    let budget = 1_000_000;
    let mut host = make_host_empty(budget);

    let before = host.meter.remaining();
    host.emit_event(&topics, data).expect("emit should succeed");
    let after = host.meter.remaining();

    let expected_cost = schedule.emit_event_base.as_u64()
        + schedule.emit_event_per_byte.as_u64() * data.len() as u64;
    let charged = before.as_u64() - after.as_u64();
    assert_eq!(charged, expected_cost);

    assert_eq!(host.events.len(), 1);
    assert_eq!(host.events[0].data, data);
    assert_eq!(host.events[0].topics, topics);
}

// M3 regression: emit_event must attribute to block.contract, not block.msg_sender.
// In single-frame tests contract==sender hides this; this test uses distinct addresses.
#[test]
fn emit_event_log_address_is_executing_contract_not_caller() {
    let sender = Address::from_public_key(&[0xAA; 32]);
    let contract = Address::from_public_key(&[0xBB; 32]); // distinct from sender
    let mut block = test_block(sender);
    block.contract = contract;
    let mut host = HostState::new(
        FuelMeter::new(Gas::new(1_000_000)),
        LemmaEngine::new().expect("test engine must initialise"),
        GasSchedule::devnet(),
        CallContext::new(),
        block,
        InMemoryStateView::with_balances(BTreeMap::new()),
        vec![],
    );
    host.emit_event(&[Hash::zero()], b"data")
        .expect("emit should succeed");
    assert_eq!(
        host.events[0].address, contract,
        "event.address must be the executing contract (block.contract), not msg_sender"
    );
    assert_ne!(
        host.events[0].address, sender,
        "event.address must NOT be msg_sender"
    );
}

// ── Gas remaining test ────────────────────────────────────────────────────────

#[test]
fn gas_remaining_returns_remaining_gas() {
    let budget = 50_000;
    let mut host = make_host_empty(budget);

    let remaining = host.gas_remaining().expect("gas_remaining should succeed");
    assert_eq!(remaining, Gas::new(budget));

    // Charge some gas and verify remaining decreases.
    host.meter
        .charge(Gas::new(1_000))
        .expect("charge should succeed");
    let remaining2 = host.gas_remaining().expect("gas_remaining should succeed");
    assert_eq!(remaining2, Gas::new(budget - 1_000));
}

// ── call_contract tests ───────────────────────────────────────────────────────

#[test]
fn call_contract_oog_during_call_base_charge_restores_call_context() {
    // Budget (2_099) is just below call_base (2_100), so enter_call succeeds
    // but charge(call_base) OOGs. Verify exit_call is called and depth returns
    // to 0 — the invariant "depth == active.len()" must hold after any failure.
    let call_base_cost = GasSchedule::devnet().call_base.as_u64();
    let budget = call_base_cost - 1; // just below call_base → OOG on charge
    let mut host = make_host_empty(budget);
    let callee = test_address(42);

    let err = host
        .call_contract(callee, b"", Gas::new(1_000))
        .expect_err("should fail OOG during call_base charge");
    assert!(matches!(err, VmError::OutOfGas));

    // CallContext must be fully unwound — no phantom reentrancy lock.
    assert_eq!(
        host.call_ctx.depth(),
        0,
        "depth must be 0 after OOG in call_contract"
    );
    // Verify address is no longer locked — same address can be entered again.
    host.call_ctx
        .enter_call(callee)
        .expect("callee should not be locked after OOG unwind");
}

// ── OOG safety test ───────────────────────────────────────────────────────────

#[test]
fn oog_before_side_effect_storage_write() {
    // Budget is exactly 0 — any write should fail with OutOfGas.
    let mut host = make_host_empty(0);

    let err = host
        .storage_write(b"key", b"value")
        .expect_err("should fail with OOG");
    assert!(matches!(err, VmError::OutOfGas));

    // State must be unchanged — no side effect on OOG.
    // M3: storage is namespaced by block.contract, not block.msg_sender.
    assert!(
        host.state.read(&host.block.contract, b"key").is_none(),
        "state must be unchanged after OOG"
    );
}
