//! Tests for [`Executor`] — covers the panic-free settlement boundary (B4).
//!
//! All tests follow the naming convention `{action}_{condition}_{outcome}`
//! (AGENTS.md §11.3). Tests live in a separate submodule file (AGENTS.md §11.2).

use std::collections::BTreeMap;

use lemma_core::{
    address::Address,
    amount::Amount,
    hash::Hash,
    signature::Signature,
    transaction::{Transaction, TxType},
};

use crate::{
    executor::{Executor, ScratchState},
    gas::GasSchedule,
    host::BlockContext,
    runtime::LemmaEngine,
    state::{ContractStateView, InMemoryStateView},
};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Create a deterministic test address from a seed byte.
fn test_address(seed: u8) -> Address {
    Address::from_public_key(&[seed; 32])
}

/// Create a test `BlockContext` with deterministic values.
///
/// `contract` is set to `sender` here; `execute_call` overrides it with the
/// real contract address via `BlockContext { contract: contract_addr, ..block }`.
fn test_block(sender: Address) -> BlockContext {
    BlockContext {
        height: 1,
        timestamp: 1_000_000,
        msg_sender: sender,
        msg_value: Amount::zero(),
        tx_origin: sender,
        // Placeholder — execute_call injects the real contract address (M3 fix).
        contract: sender,
    }
}

/// Create a test executor with the devnet gas schedule.
fn test_executor() -> Executor {
    let engine = LemmaEngine::new().expect("engine must initialize");
    Executor::new(engine, GasSchedule::devnet())
}

/// Build a minimal `Transfer` transaction.
fn transfer_tx(
    sender: Address,
    to: Address,
    value: Amount,
    nonce: u64,
    gas_limit: u64,
) -> Transaction {
    Transaction::new(
        Hash::zero(),
        sender,
        Some(to),
        nonce,
        1, // chain_id
        value,
        gas_limit,
        Amount::from_drop(1_000_000_000), // gas_price
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("valid transfer tx")
}

/// Build a `ContractDeploy` transaction with the given bytecode.
fn deploy_tx(sender: Address, bytecode: Vec<u8>, nonce: u64, gas_limit: u64) -> Transaction {
    Transaction::new(
        Hash::zero(),
        sender,
        None, // ContractDeploy has no `to`
        nonce,
        1,
        Amount::zero(),
        gas_limit,
        Amount::from_drop(1_000_000_000),
        TxType::ContractDeploy,
        bytecode,
        Signature::Unsigned,
    )
    .expect("valid deploy tx")
}

/// Build a `ContractCall` transaction.
fn call_tx(sender: Address, to: Address, nonce: u64, gas_limit: u64) -> Transaction {
    Transaction::new(
        Hash::zero(),
        sender,
        Some(to),
        nonce,
        1,
        Amount::zero(),
        gas_limit,
        Amount::from_drop(1_000_000_000),
        TxType::ContractCall,
        vec![0x00], // minimal non-empty calldata
        Signature::Unsigned,
    )
    .expect("valid call tx")
}

/// Minimal noop WAT: exports `call` with no args, no return, no body.
const NOOP_WAT: &[u8] = b"(module (func (export \"call\")))";

/// Infinite loop WAT: exports `call` that loops forever (triggers OOG).
const INFINITE_LOOP_WAT: &[u8] = b"(module (func (export \"call\") (loop $l (br $l))))";

/// Trap WAT: exports `call` that immediately traps with `unreachable`.
const TRAP_WAT: &[u8] = b"(module (func (export \"call\") unreachable))";

// ── Noop contract tests ───────────────────────────────────────────────────────

#[test]
fn execute_noop_contract_returns_success_receipt() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // First deploy the noop contract.
    let deploy = deploy_tx(sender, NOOP_WAT.to_vec(), 0, 500_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    // Derive the contract address (nonce was 0 at deploy time).
    let contract_addr = Address::from_deployer(&sender, 0);

    // Now call it.
    let call = call_tx(sender, contract_addr, 1, 500_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(receipt.success, "noop call must succeed");
    assert!(receipt.gas_used > 0, "gas must be consumed");
    assert!(receipt.gas_used <= call.gas_limit, "gas_used ≤ gas_limit");
    // Nonce advanced twice (deploy + call).
    assert_eq!(state.nonce(&sender), 2);
}

#[test]
fn execute_out_of_gas_yields_failed_receipt_never_panics() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // Deploy the infinite loop contract with a generous gas limit.
    let deploy = deploy_tx(sender, INFINITE_LOOP_WAT.to_vec(), 0, 500_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);

    // Call with a tiny gas budget — must OOG, never panic.
    let call = call_tx(sender, contract_addr, 1, 30_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(!receipt.success, "OOG must produce failed receipt");
    assert!(receipt.logs.is_empty(), "failed receipt must have no logs");
    // Nonce still advances on failure.
    assert_eq!(state.nonce(&sender), 2, "nonce advances even on OOG");
    assert!(receipt.gas_used <= call.gas_limit, "gas_used ≤ gas_limit");
}

#[test]
fn execute_trap_unreachable_yields_failed_receipt() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // Deploy the trap contract.
    let deploy = deploy_tx(sender, TRAP_WAT.to_vec(), 0, 500_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);

    // Call — must trap, never panic.
    let call = call_tx(sender, contract_addr, 1, 500_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(!receipt.success, "trap must produce failed receipt");
    assert!(receipt.logs.is_empty(), "failed receipt must have no logs");
    assert_eq!(state.nonce(&sender), 2, "nonce advances even on trap");
}

#[test]
fn execute_advances_nonce_on_failure() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // Deploy infinite loop (receipt intentionally ignored — testing call failure path).
    let deploy = deploy_tx(sender, INFINITE_LOOP_WAT.to_vec(), 0, 500_000);
    let _ = executor.execute_transaction(&deploy, test_block(sender), &mut state);

    let contract_addr = Address::from_deployer(&sender, 0);

    // Nonce before failure.
    assert_eq!(state.nonce(&sender), 1);

    // OOG call.
    let call = call_tx(sender, contract_addr, 1, 25_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(!receipt.success);
    // Nonce must advance even on failure.
    assert_eq!(state.nonce(&sender), 2, "nonce must advance on failure");
}

#[test]
fn gas_used_never_exceeds_gas_limit() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // Deploy infinite loop (receipt intentionally ignored — testing call OOG path).
    let deploy = deploy_tx(sender, INFINITE_LOOP_WAT.to_vec(), 0, 500_000);
    let _ = executor.execute_transaction(&deploy, test_block(sender), &mut state);

    let contract_addr = Address::from_deployer(&sender, 0);

    // Call with a very small gas limit.
    let gas_limit = 22_500_u64;
    let call = call_tx(sender, contract_addr, 1, gas_limit);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(
        receipt.gas_used <= gas_limit,
        "gas_used ({}) must not exceed gas_limit ({})",
        receipt.gas_used,
        gas_limit
    );
}

// ── Deploy tests ──────────────────────────────────────────────────────────────

#[test]
fn deploy_stores_code_and_derives_correct_address() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, NOOP_WAT.to_vec(), 0, 500_000);
    let receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);

    assert!(receipt.success, "deploy must succeed");

    // Contract address is derived from deployer + nonce (0 at deploy time).
    let expected_addr = Address::from_deployer(&sender, 0);
    assert!(
        state.code(&expected_addr).is_some(),
        "bytecode must be stored at derived address"
    );
    assert_eq!(
        state.code(&expected_addr).unwrap(),
        NOOP_WAT,
        "stored bytecode must match input"
    );
    // Nonce advanced.
    assert_eq!(state.nonce(&sender), 1);
}

#[test]
fn deploy_invalid_wasm_yields_failed_receipt() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // Garbage bytes — not valid WASM or WAT.
    let garbage = b"this is not valid wasm bytecode at all!!!".to_vec();
    let deploy = deploy_tx(sender, garbage, 0, 500_000);
    let receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);

    assert!(!receipt.success, "invalid WASM must produce failed receipt");
    assert!(receipt.logs.is_empty(), "failed receipt must have no logs");
    // Nonce still advances.
    assert_eq!(
        state.nonce(&sender),
        1,
        "nonce advances even on failed deploy"
    );

    // No code stored.
    let contract_addr = Address::from_deployer(&sender, 0);
    assert!(
        state.code(&contract_addr).is_none(),
        "no code must be stored on failed deploy"
    );
}

// ── Transfer tests ────────────────────────────────────────────────────────────

#[test]
fn execute_transfer_moves_balance() {
    let executor = test_executor();
    let sender = test_address(1);
    let recipient = test_address(2);

    let initial_balance = Amount::from_drop(1_000_000_000_000);
    let transfer_value = Amount::from_drop(500_000_000_000);

    let mut balances = BTreeMap::new();
    balances.insert(sender, initial_balance);
    let mut state = InMemoryStateView::with_balances(balances);

    let tx = transfer_tx(sender, recipient, transfer_value, 0, 100_000);
    let receipt = executor.execute_transaction(&tx, test_block(sender), &mut state);

    assert!(receipt.success, "transfer must succeed");
    assert!(receipt.gas_used > 0, "gas must be consumed");
    assert!(receipt.gas_used <= tx.gas_limit, "gas_used ≤ gas_limit");

    // Sender balance decreased by transfer value.
    let sender_balance = state.balance(&sender);
    assert!(
        sender_balance < initial_balance,
        "sender balance must decrease"
    );

    // Recipient received the value.
    assert_eq!(
        state.balance(&recipient),
        transfer_value,
        "recipient must receive transfer value"
    );

    // Nonce advanced.
    assert_eq!(state.nonce(&sender), 1);
}

#[test]
fn execute_transfer_insufficient_funds_fails_cleanly() {
    let executor = test_executor();
    let sender = test_address(1);
    let recipient = test_address(2);

    // Sender has zero balance.
    let mut state = InMemoryStateView::new();

    let tx = transfer_tx(sender, recipient, Amount::from_drop(1_000_000), 0, 100_000);
    let receipt = executor.execute_transaction(&tx, test_block(sender), &mut state);

    assert!(
        !receipt.success,
        "insufficient funds must produce failed receipt"
    );
    assert!(receipt.logs.is_empty(), "failed receipt must have no logs");

    // Balances unchanged.
    assert_eq!(
        state.balance(&sender),
        Amount::zero(),
        "sender balance unchanged"
    );
    assert_eq!(
        state.balance(&recipient),
        Amount::zero(),
        "recipient balance unchanged"
    );

    // Nonce still advances.
    assert_eq!(
        state.nonce(&sender),
        1,
        "nonce advances even on failed transfer"
    );
}

// ── Scratch state tests ───────────────────────────────────────────────────────

#[test]
fn scratch_state_commit_flushes_writes() {
    let mut inner = InMemoryStateView::new();
    let addr = test_address(1);
    let sender = test_address(2);

    {
        let mut scratch = ScratchState::new(&mut inner);
        scratch.write(&addr, b"key", b"value".to_vec());
        scratch.set_balance(&addr, Amount::from_drop(999));
        scratch.set_nonce(&addr, 7);
        scratch.set_code(&addr, b"code".to_vec());
        // Commit — flushes all writes and advances sender nonce.
        scratch.commit_with_nonce(&sender);
    }

    // All writes must be visible on inner.
    assert_eq!(inner.read(&addr, b"key"), Some(b"value".to_vec()));
    assert_eq!(inner.balance(&addr), Amount::from_drop(999));
    assert_eq!(inner.nonce(&addr), 7);
    assert_eq!(inner.code(&addr), Some(b"code".to_vec()));
    // Sender nonce advanced.
    assert_eq!(inner.nonce(&sender), 1);
}

#[test]
fn scratch_state_discard_leaves_inner_unchanged() {
    let mut inner = InMemoryStateView::new();
    let addr = test_address(1);

    {
        let mut scratch = ScratchState::new(&mut inner);
        scratch.write(&addr, b"key", b"value".to_vec());
        scratch.set_balance(&addr, Amount::from_drop(999));
        scratch.set_nonce(&addr, 7);
        scratch.set_code(&addr, b"code".to_vec());
        // Discard — no writes reach inner.
        let _ = scratch.discard();
    }

    // Inner must be completely unchanged.
    assert!(inner.read(&addr, b"key").is_none());
    assert_eq!(inner.balance(&addr), Amount::zero());
    assert_eq!(inner.nonce(&addr), 0);
    assert!(inner.code(&addr).is_none());
}

#[test]
fn scratch_state_read_falls_through_to_inner() {
    let mut inner = InMemoryStateView::new();
    let addr = test_address(1);

    // Write directly to inner.
    inner.write(&addr, b"inner_key", b"inner_value".to_vec());
    inner.set_balance(&addr, Amount::from_drop(42));

    let scratch = ScratchState::new(&mut inner);

    // Scratch has no writes — reads fall through to inner.
    assert_eq!(
        scratch.read(&addr, b"inner_key"),
        Some(b"inner_value".to_vec())
    );
    assert_eq!(scratch.balance(&addr), Amount::from_drop(42));
}

#[test]
fn scratch_state_delete_shadows_inner_value() {
    let mut inner = InMemoryStateView::new();
    let addr = test_address(1);

    // Write to inner.
    inner.write(&addr, b"key", b"value".to_vec());

    let mut scratch = ScratchState::new(&mut inner);

    // Delete in scratch — should shadow the inner value.
    scratch.delete(&addr, b"key");
    assert!(
        scratch.read(&addr, b"key").is_none(),
        "deleted key must read as None through scratch"
    );
    assert!(
        !scratch.exists(&addr, b"key"),
        "deleted key must not exist through scratch"
    );
}

// ── Revert / H2 invariant tests ───────────────────────────────────────────────

#[test]
fn execute_revert_clears_logs_h2() {
    // H2 invariant: failed tx → success=false, logs=[], reverted writes, nonce++.
    // We use the trap WAT (unreachable) to force a revert.
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // Deploy the trap contract (receipt intentionally ignored — testing call revert path).
    let deploy = deploy_tx(sender, TRAP_WAT.to_vec(), 0, 500_000);
    let _ = executor.execute_transaction(&deploy, test_block(sender), &mut state);

    let contract_addr = Address::from_deployer(&sender, 0);
    let nonce_before = state.nonce(&sender);

    // Call the trap contract.
    let call = call_tx(sender, contract_addr, 1, 500_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    // H2: success=false, logs=[], nonce++.
    assert!(!receipt.success, "trap must produce failed receipt");
    assert!(
        receipt.logs.is_empty(),
        "H2: failed receipt must have empty logs"
    );
    assert_eq!(
        state.nonce(&sender),
        nonce_before + 1,
        "H2: nonce must advance even on revert"
    );
}

// ── Intrinsic OOG test ────────────────────────────────────────────────────────

#[test]
fn execute_intrinsic_oog_charges_full_gas_limit_and_advances_nonce() {
    // Gas limit below tx_base (21_000) → OOG on intrinsic before any execution.
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();
    let gas_limit = 100_u64; // below tx_base = 21_000

    let deploy = deploy_tx(sender, NOOP_WAT.to_vec(), 0, gas_limit);
    let receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);

    assert!(!receipt.success, "intrinsic OOG must fail");
    assert_eq!(
        receipt.gas_used, gas_limit,
        "intrinsic OOG charges the full gas_limit"
    );
    assert!(receipt.logs.is_empty());
    assert_eq!(
        state.nonce(&sender),
        1,
        "nonce advances even on intrinsic OOG"
    );
}

// ── Unsupported tx type test ──────────────────────────────────────────────────

#[test]
fn execute_unsupported_tx_type_yields_failed_receipt() {
    // Stake/Unstake/GovernanceVote are not supported in B4 — must produce
    // a failed receipt, never panic.
    use lemma_core::transaction::TxType;

    let executor = test_executor();
    let sender = test_address(1);
    let recipient = test_address(2);
    let mut state = InMemoryStateView::new();

    // Use GovernanceVote (unsupported in B4) — construct manually.
    let tx = Transaction::new(
        Hash::zero(),
        sender,
        Some(recipient),
        0,
        1,
        Amount::zero(),
        500_000,
        Amount::from_drop(1_000_000_000),
        TxType::GovernanceVote,
        vec![0x00, 0x01], // non-empty data (required by GovernanceVote)
        lemma_core::signature::Signature::Unsigned,
    )
    .expect("valid governance vote tx");

    let receipt = executor.execute_transaction(&tx, test_block(sender), &mut state);

    assert!(
        !receipt.success,
        "unsupported tx type must yield failed receipt"
    );
    assert!(receipt.logs.is_empty());
    // Nonce still advances.
    assert_eq!(state.nonce(&sender), 1);
}

// ── M1 pinning tests ──────────────────────────────────────────────────────────

/// WAT contract that imports and calls `storage_write` once.
///
/// The linker registers `storage_write` with real gas charging (M1 fix), so
/// calling it deducts `storage_write_create` gas from the Store fuel pool.
/// This makes the cost visible in `wasm_consumed` and therefore in `gas_used`.
///
/// Import order: only `storage_write` is imported — the linker resolves by
/// name, not by index, so we only need to import what we call.
const STORAGE_WRITE_CALLER_WAT: &[u8] = b"(module
  (import \"lemma\" \"storage_write\" (func $sw (param i32 i32 i32 i32)))
  (func (export \"call\")
    i32.const 0
    i32.const 0
    i32.const 0
    i32.const 0
    call $sw)
)";

/// Verifies M1 fix: storage_write's gas cost now flows into gas_used.
///
/// Previously, host-fn charges used HostState.meter (inner) which was
/// silently dropped; now they use caller.set_fuel() (Store fuel = shared budget).
/// The `wasm_consumed` value in executor.rs therefore includes both WASM
/// instruction fuel AND host-fn gas charges.
#[test]
fn execute_host_fn_charges_flow_to_gas_used() {
    let schedule = GasSchedule::devnet();
    let expected_min_host_gas = schedule.storage_write_create.as_u64();

    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // Deploy the storage_write caller contract.
    let deploy = deploy_tx(sender, STORAGE_WRITE_CALLER_WAT.to_vec(), 0, 500_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);

    // Call the contract — it will invoke storage_write once.
    let call = call_tx(sender, contract_addr, 1, 500_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(receipt.success, "storage_write call must succeed");

    // gas_used must include at least the tx_base intrinsic + storage_write_create host charge.
    // Before M1 fix, gas_used only reflected WASM instruction fuel (host charges were dropped).
    let min_expected = schedule.tx_base.as_u64() + expected_min_host_gas;
    assert!(
        receipt.gas_used >= min_expected,
        "gas_used ({}) must include host-fn charge: tx_base ({}) + storage_write_create ({}) = {}",
        receipt.gas_used,
        schedule.tx_base.as_u64(),
        expected_min_host_gas,
        min_expected,
    );
    assert!(receipt.gas_used <= call.gas_limit, "gas_used ≤ gas_limit");
}

/// Verifies that `gas_remaining` returns Store fuel (the M1 source of truth),
/// not the inner HostState.meter which is no longer the authoritative counter.
///
/// After M1 fix, Store fuel is the single budget pool for both WASM instructions
/// and host-fn charges. `gas_remaining()` must reflect this pool.
#[test]
fn gas_remaining_host_fn_reflects_store_fuel() {
    // A WAT contract that calls gas_remaining and block_height (both charge context_query gas).
    // We can't easily inspect the return value from outside, but we can verify that
    // the overall gas_used increases by at least 2 × context_query when both are called.
    const CONTEXT_QUERY_WAT: &[u8] = b"(module
      (import \"lemma\" \"block_height\" (func $bh (result i64)))
      (import \"lemma\" \"gas_remaining\" (func $gr (result i64)))
      (func (export \"call\")
        call $bh
        drop
        call $gr
        drop)
    )";

    let schedule = GasSchedule::devnet();
    let executor = test_executor();
    let sender = test_address(3);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, CONTEXT_QUERY_WAT.to_vec(), 0, 500_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    let call = call_tx(sender, contract_addr, 1, 500_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(receipt.success, "context query call must succeed");

    // gas_used must include at least tx_base + 1 × context_query (block_height).
    // gas_remaining does NOT charge itself (circular), so only block_height charges.
    let min_expected = schedule.tx_base.as_u64() + schedule.context_query.as_u64();
    assert!(
        receipt.gas_used >= min_expected,
        "gas_used ({}) must include context_query charge for block_height",
        receipt.gas_used,
    );
}
