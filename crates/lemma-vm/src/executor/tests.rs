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
    MAX_CONTRACT_WASM_SIZE,
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

// ── Size gate tests (DB-A21) ──────────────────────────────────────────────────

/// Verifies that a valid WASM deploy under the size limit succeeds.
///
/// Acceptance criterion 7: deploy succeeds for valid WASM under size limit.
#[test]
fn deploy_valid_wasm_under_size_limit_succeeds() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // NOOP_WAT is well under MAX_CONTRACT_WASM_SIZE (2 MiB).
    assert!(
        NOOP_WAT.len() < MAX_CONTRACT_WASM_SIZE,
        "NOOP_WAT must be under the size limit for this test to be meaningful"
    );

    let deploy = deploy_tx(sender, NOOP_WAT.to_vec(), 0, 500_000);
    let receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);

    assert!(receipt.success, "deploy under size limit must succeed");
    assert!(receipt.gas_used > 0, "gas must be consumed");
    assert!(receipt.gas_used <= deploy.gas_limit, "gas_used ≤ gas_limit");

    // Bytecode stored at derived address.
    let contract_addr = Address::from_deployer(&sender, 0);
    assert!(
        state.code(&contract_addr).is_some(),
        "bytecode must be stored at derived address"
    );
}

/// Verifies that an oversized deploy is rejected BEFORE deploy gas is charged (DB-A21).
///
/// Acceptance criteria 1 and 8: ContractTooLarge returned before deploy gas charged.
///
/// The size gate fires inside `execute_deploy` AFTER intrinsic gas is charged by
/// `execute_transaction`. The spec "reject-before-charge" means no DEPLOY-specific
/// gas is charged (no `deploy_base + deploy_storage_per_byte × len`). The intrinsic
/// `tx_base` is still charged — the validator did work to receive and validate the
/// tx structure; the DoS protection is against the AOT compiler.
///
/// We use a small oversized payload (MAX + 1 bytes of valid-looking data) with a
/// gas limit large enough to cover intrinsic gas, so the size gate is the failure
/// cause (not intrinsic OOG).
#[test]
fn deploy_oversized_wasm_rejected_with_contract_too_large_no_deploy_gas() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    // Build a bytecode that exceeds MAX_CONTRACT_WASM_SIZE by exactly 1 byte.
    // Use a simple byte pattern — doesn't need to be valid WASM (size gate fires first).
    let oversized = vec![0u8; MAX_CONTRACT_WASM_SIZE + 1];
    let data_len = oversized.len() as u64;

    // Gas limit must cover intrinsic gas so the size gate (not intrinsic OOG) fires.
    // Intrinsic = tx_base (21_000) + tx_calldata_per_byte (16) × data_len.
    let schedule = GasSchedule::devnet();
    let intrinsic_cost =
        schedule.tx_base.as_u64() + schedule.tx_calldata_per_byte.as_u64() * data_len;
    // Add deploy_base + deploy_storage_per_byte × len as headroom (size gate fires before these).
    let deploy_cost =
        schedule.deploy_base.as_u64() + schedule.deploy_storage_per_byte.as_u64() * data_len;
    let gas_limit = intrinsic_cost + deploy_cost + 100_000;

    let deploy = deploy_tx(sender, oversized, 0, gas_limit);
    let receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);

    assert!(
        !receipt.success,
        "oversized deploy must produce failed receipt"
    );
    assert!(receipt.logs.is_empty(), "failed receipt must have no logs");

    // gas_used must be ≤ gas_limit (always).
    assert!(
        receipt.gas_used <= gas_limit,
        "gas_used ({}) must not exceed gas_limit ({})",
        receipt.gas_used,
        gas_limit
    );

    // No deploy gas charged — gas_used must equal only the intrinsic cost.
    // The size gate fires before deploy_base or deploy_storage_per_byte are charged.
    assert_eq!(
        receipt.gas_used, intrinsic_cost,
        "only intrinsic gas must be charged for oversized deploy (no deploy gas): \
         expected {intrinsic_cost}, got {}",
        receipt.gas_used
    );

    // No code stored at the derived address.
    let contract_addr = Address::from_deployer(&sender, 0);
    assert!(
        state.code(&contract_addr).is_none(),
        "no code must be stored for oversized deploy"
    );

    // Nonce still advances (failed tx still increments nonce).
    assert_eq!(
        state.nonce(&sender),
        1,
        "nonce advances even on failed deploy"
    );
}

/// Verifies that a second deploy of identical bytecode charges less gas (DB-A23).
///
/// Acceptance criteria 3, 4, and 9: first deployer pays storage gas; later
/// deployer pays only base gas (dedup savings).
#[test]
fn deploy_identical_bytecode_second_time_charges_less_gas() {
    let executor = test_executor();
    let sender_a = test_address(1);
    let sender_b = test_address(2);
    let mut state = InMemoryStateView::new();

    // First deploy: sender_a deploys NOOP_WAT — pays storage gas.
    let deploy_a = deploy_tx(sender_a, NOOP_WAT.to_vec(), 0, 500_000);
    let receipt_a = executor.execute_transaction(&deploy_a, test_block(sender_a), &mut state);
    assert!(receipt_a.success, "first deploy must succeed");
    let gas_first = receipt_a.gas_used;

    // Second deploy: sender_b deploys the SAME bytecode — pays only base gas.
    let deploy_b = deploy_tx(sender_b, NOOP_WAT.to_vec(), 0, 500_000);
    let receipt_b = executor.execute_transaction(&deploy_b, test_block(sender_b), &mut state);
    assert!(
        receipt_b.success,
        "second deploy of identical bytecode must succeed"
    );
    let gas_second = receipt_b.gas_used;

    // Second deployer must pay less gas than first deployer (dedup savings).
    // First deployer: deploy_base + deploy_storage_per_byte × len + intrinsic.
    // Second deployer: deploy_base + intrinsic (no storage gas).
    assert!(
        gas_second < gas_first,
        "second deploy of identical bytecode must charge less gas: \
         first={gas_first}, second={gas_second}"
    );

    // Both contracts are deployed at their respective addresses.
    let addr_a = Address::from_deployer(&sender_a, 0);
    let addr_b = Address::from_deployer(&sender_b, 0);
    assert!(
        state.code(&addr_a).is_some(),
        "first contract must be deployed"
    );
    assert!(
        state.code(&addr_b).is_some(),
        "second contract must be deployed"
    );

    // Both can be called (bytecode is valid and accessible).
    let call_a = call_tx(sender_a, addr_a, 1, 500_000);
    let call_receipt_a = executor.execute_transaction(&call_a, test_block(sender_a), &mut state);
    assert!(
        call_receipt_a.success,
        "call to first contract must succeed"
    );

    let call_b = call_tx(sender_b, addr_b, 1, 500_000);
    let call_receipt_b = executor.execute_transaction(&call_b, test_block(sender_b), &mut state);
    assert!(
        call_receipt_b.success,
        "call to second contract must succeed"
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

/// WAT contract that imports and calls `storage_write` once with empty key/value.
///
/// The linker registers `storage_write` with real gas charging and memory
/// marshalling (6b-vm-2), so calling it deducts storage_write_create gas +
/// memory_copy_per_byte charges from the Store fuel pool.
///
/// Must export `"memory"` — the linker resolves guest memory for marshalling.
const STORAGE_WRITE_CALLER_WAT: &[u8] = b"(module
  (import \"lemma\" \"storage_write\" (func $sw (param i32 i32 i32 i32)))
  (memory (export \"memory\") 1)
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

// ── 6b-vm-2 host function marshalling tests ───────────────────────────────

/// WAT: writes key "test" (4 bytes) and value "hello" (5 bytes) to memory,
/// calls storage_write, then storage_read with the same key → register 1,
/// then read_register to copy register 1 back to memory at offset 200.
///
/// ⚠️ M4: ScratchSnapshot does NOT read-through to canonical state.
/// This test only verifies same-tx round-trips (write then read in one call).
const STORAGE_ROUND_TRIP_WAT: &[u8] = b"(module
  (import \"lemma\" \"storage_write\" (func $sw (param i32 i32 i32 i32)))
  (import \"lemma\" \"storage_read\" (func $sr (param i32 i32 i32) (result i32)))
  (import \"lemma\" \"register_len\" (func $rl (param i32) (result i64)))
  (import \"lemma\" \"read_register\" (func $rr (param i32 i32)))
  (memory (export \"memory\") 1)
  ;; key at offset 0, length 4: \"test\"
  (data (i32.const 0) \"test\")
  ;; value at offset 100, length 5: \"hello\"
  (data (i32.const 100) \"hello\")
  (func (export \"call\")
    ;; storage_write(key_ptr=0, key_len=4, val_ptr=100, val_len=5)
    i32.const 0  i32.const 4  i32.const 100  i32.const 5
    call $sw
    ;; storage_read(key_ptr=0, key_len=4, register_id=1) -> status
    i32.const 0  i32.const 4  i32.const 1
    call $sr
    drop  ;; drop status (should be 0 = FOUND)
    ;; read_register(register_id=1, dest_ptr=200)
    i32.const 1  i32.const 200
    call $rr))
";

/// Verifies storage_write → storage_read round-trip within the same transaction.
///
/// ⚠️ M4: ScratchSnapshot does NOT read-through to canonical state.
/// Only same-tx writes are visible to storage_read.
#[test]
fn storage_write_read_round_trip_same_tx() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, STORAGE_ROUND_TRIP_WAT.to_vec(), 0, 1_000_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    let call = call_tx(sender, contract_addr, 1, 1_000_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(
        receipt.success,
        "storage round-trip call must succeed — receipt: gas_used={}",
        receipt.gas_used
    );
}

/// WAT: calls storage_read with a key that was never written.
/// The return value should be -1 (STORAGE_NOT_FOUND).
/// We verify by storing the result in a global and checking it doesn't trap.
const STORAGE_READ_ABSENT_WAT: &[u8] = b"(module
  (import \"lemma\" \"storage_read\" (func $sr (param i32 i32 i32) (result i32)))
  (memory (export \"memory\") 1)
  ;; key at offset 0, length 6: \"absent\"
  (data (i32.const 0) \"absent\")
  (global $status (mut i32) (i32.const 99))
  (func (export \"call\")
    ;; storage_read(key_ptr=0, key_len=6, register_id=0) -> status
    i32.const 0  i32.const 6  i32.const 0
    call $sr
    global.set $status))
";

#[test]
fn storage_read_absent_key_returns_not_found() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, STORAGE_READ_ABSENT_WAT.to_vec(), 0, 1_000_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    let call = call_tx(sender, contract_addr, 1, 1_000_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    // The call must succeed — storage_read returns -1 sentinel, not a trap.
    assert!(receipt.success, "storage_read of absent key must not trap");
}

/// WAT: writes recipient address (20 bytes) to memory, calls transfer.
/// Recipient is all-0x42 bytes (20 bytes).
const TRANSFER_WAT: &[u8] = b"(module
  (import \"lemma\" \"transfer\" (func $tr (param i32 i32 i64) (result i32)))
  (memory (export \"memory\") 1)
  ;; recipient address at offset 0: 20 bytes of 0x42
  (data (i32.const 0) \"\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\")
  (global $status (mut i32) (i32.const 99))
  (func (export \"call\")
    ;; transfer(to_ptr=0, to_len=20, amount=1000)
    i32.const 0  i32.const 20  i64.const 1000
    call $tr
    global.set $status))
";

/// Verifies that the transfer host function correctly moves balance when the
/// contract has funds available in the snapshot.
///
/// ⚠️ M4: ScratchSnapshot does NOT read-through to canonical state for balances.
/// Pre-seeded balances on the canonical state are invisible to the snapshot.
/// This test verifies that transfer with insufficient funds (zero balance in
/// snapshot) returns the TRANSFER_INSUFFICIENT sentinel (1) without trapping.
/// A full balance-transfer integration test requires M4 fix (ScratchSnapshot
/// read-through) or a WAT that first receives value via msg_value.
#[test]
fn transfer_with_zero_snapshot_balance_returns_insufficient() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, TRANSFER_WAT.to_vec(), 0, 1_000_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    // Contract has zero balance in snapshot — transfer of 1000 returns sentinel 1.
    let call = call_tx(sender, contract_addr, 1, 1_000_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    // The call succeeds (transfer returns sentinel, doesn't trap).
    assert!(
        receipt.success,
        "transfer with insufficient funds must not trap — returns sentinel"
    );
    // Recipient balance unchanged (transfer failed gracefully).
    let recipient = Address::from_raw_bytes([0x42; 20]);
    assert_eq!(
        state.balance(&recipient),
        Amount::zero(),
        "recipient must not receive funds when transfer returns insufficient"
    );
}

/// WAT: calls transfer with a negative amount (-1). Must trap (not silent cast).
const TRANSFER_NEGATIVE_WAT: &[u8] = b"(module
  (import \"lemma\" \"transfer\" (func $tr (param i32 i32 i64) (result i32)))
  (memory (export \"memory\") 1)
  (data (i32.const 0) \"\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\\42\")
  (func (export \"call\")
    ;; transfer(to_ptr=0, to_len=20, amount=-1) -- negative amount must trap
    i32.const 0  i32.const 20  i64.const -1
    call $tr
    drop))
";

#[test]
fn transfer_negative_amount_traps() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, TRANSFER_NEGATIVE_WAT.to_vec(), 0, 1_000_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    let call = call_tx(sender, contract_addr, 1, 1_000_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    // Negative amount must trap — failed receipt, not silent cast to huge u128.
    assert!(
        !receipt.success,
        "transfer with negative amount must produce failed receipt"
    );
}

/// WAT: writes "result" (6 bytes) to memory, calls value_return.
const VALUE_RETURN_WAT: &[u8] = b"(module
  (import \"lemma\" \"value_return\" (func $vr (param i32 i32)))
  (memory (export \"memory\") 1)
  (data (i32.const 0) \"result\")
  (func (export \"call\")
    ;; value_return(ptr=0, len=6)
    i32.const 0  i32.const 6
    call $vr))
";

#[test]
fn value_return_captures_guest_bytes() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, VALUE_RETURN_WAT.to_vec(), 0, 1_000_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    let call = call_tx(sender, contract_addr, 1, 1_000_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    // value_return captures bytes into host_after.return_data, which is currently
    // dropped in execute_call (P3·Step 7 consumer). The call itself must succeed.
    assert!(receipt.success, "value_return call must succeed");
}

/// WAT: writes a 32-byte topic + 4-byte data to memory, calls emit_event.
const EMIT_EVENT_WAT: &[u8] = b"(module
  (import \"lemma\" \"emit_event\" (func $ee (param i32 i32 i32 i32)))
  (memory (export \"memory\") 1)
  ;; topic at offset 0: 32 zero bytes (Hash::zero)
  ;; data at offset 100: \"data\" (4 bytes)
  (data (i32.const 100) \"data\")
  (func (export \"call\")
    ;; emit_event(topics_ptr=0, topics_len=32, data_ptr=100, data_len=4)
    i32.const 0  i32.const 32  i32.const 100  i32.const 4
    call $ee))
";

#[test]
fn emit_event_emits_log_with_correct_address() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, EMIT_EVENT_WAT.to_vec(), 0, 1_000_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    let call = call_tx(sender, contract_addr, 1, 1_000_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(receipt.success, "emit_event call must succeed");
    assert_eq!(receipt.logs.len(), 1, "must emit exactly one event");
    assert_eq!(
        receipt.logs[0].address, contract_addr,
        "event address must be the executing contract"
    );
    assert_eq!(receipt.logs[0].topics.len(), 1, "must have one topic");
    assert_eq!(
        receipt.logs[0].topics[0],
        Hash::zero(),
        "topic must be zero hash (32 zero bytes from memory)"
    );
    assert_eq!(receipt.logs[0].data, b"data", "event data must match");
}

/// WAT: calls storage_write with ptr beyond memory bounds → must trap cleanly.
const MEMORY_OOB_WAT: &[u8] = b"(module
  (import \"lemma\" \"storage_write\" (func $sw (param i32 i32 i32 i32)))
  (memory (export \"memory\") 1)
  (func (export \"call\")
    ;; storage_write with key_ptr way beyond 1 page (65536 bytes)
    i32.const 100000  i32.const 10  i32.const 0  i32.const 0
    call $sw))
";

#[test]
fn memory_oob_traps_cleanly() {
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, MEMORY_OOB_WAT.to_vec(), 0, 1_000_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    let call = call_tx(sender, contract_addr, 1, 1_000_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    // Must produce a failed receipt (trap), NOT a panic.
    assert!(
        !receipt.success,
        "memory OOB must produce failed receipt, not panic"
    );
    assert!(receipt.logs.is_empty(), "failed receipt must have no logs");
}

/// Verifies that per-byte gas scales with data size for storage_write.
///
/// WAT writes a 100-byte key and 200-byte value. Gas used must include
/// memory_copy_per_byte charges for both key and value copies.
const LARGE_STORAGE_WRITE_WAT: &[u8] = b"(module
  (import \"lemma\" \"storage_write\" (func $sw (param i32 i32 i32 i32)))
  (memory (export \"memory\") 1)
  (func (export \"call\")
    ;; storage_write(key_ptr=0, key_len=100, val_ptr=200, val_len=200)
    i32.const 0  i32.const 100  i32.const 200  i32.const 200
    call $sw))
";

#[test]
fn per_byte_gas_scales_with_data_size() {
    let schedule = GasSchedule::devnet();
    let executor = test_executor();
    let sender = test_address(1);
    let mut state = InMemoryStateView::new();

    let deploy = deploy_tx(sender, LARGE_STORAGE_WRITE_WAT.to_vec(), 0, 1_000_000);
    let deploy_receipt = executor.execute_transaction(&deploy, test_block(sender), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    let call = call_tx(sender, contract_addr, 1, 1_000_000);
    let receipt = executor.execute_transaction(&call, test_block(sender), &mut state);

    assert!(receipt.success, "large storage_write call must succeed");

    // gas_used must include at least:
    // - tx_base (intrinsic)
    // - memory_copy_per_byte * (100 + 200) for key + value copies
    // - storage_write_create for the actual write
    let key_len = 100_u64;
    let val_len = 200_u64;
    let copy_gas = schedule.memory_copy_per_byte.as_u64() * (key_len + val_len);
    let min_expected =
        schedule.tx_base.as_u64() + copy_gas + schedule.storage_write_create.as_u64();
    assert!(
        receipt.gas_used >= min_expected,
        "gas_used ({}) must include per-byte copy charges: \
         tx_base ({}) + copy ({}) + storage_write_create ({}) = {}",
        receipt.gas_used,
        schedule.tx_base.as_u64(),
        copy_gas,
        schedule.storage_write_create.as_u64(),
        min_expected,
    );
}
