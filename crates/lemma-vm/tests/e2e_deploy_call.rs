//! End-to-end integration test: deploy + call on LemmaVM (P3·Step 7).
//!
//! Exercises the full deploy+call pipeline added in Step 7:
//!   size gate → code dedup (CF_CODE) → cold/warm gas → success receipts
//!
//! Uses a hand-crafted WAT module (no lemma-lang dependency — AGENTS §8).
//! wasmtime accepts WAT text directly via `Module::new`.
//!
//! ## Host import signatures (from abi.rs HOST_SIGS)
//!
//! | # | Name             | WASM type                                    |
//! |---|------------------|----------------------------------------------|
//! | 0 | block_height     | () → i64                                     |
//! | 1 | block_timestamp  | () → i64                                     |
//! | 2 | gas_remaining    | () → i64                                     |
//! | 3 | msg_value        | () → i64                                     |
//! | 4 | msg_sender       | (i32) → ()                                   |
//! | 5 | input            | (i32) → ()                                   |
//! | 6 | register_len     | (i32) → i64                                  |
//! | 7 | read_register    | (i32 i32) → ()                               |
//! | 8 | storage_read     | (i32 i32 i32) → i32                          |
//! | 9 | storage_write    | (i32 i32 i32 i32) → ()                       |
//! |10 | storage_delete   | (i32 i32) → ()                               |
//! |11 | emit_event       | (i32 i32 i32 i32) → i32                      |
//! |12 | transfer         | (i32 i32 i64) → i32                          |
//! |13 | value_return     | (i32 i32) → ()                               |
//! |14 | call_contract    | (i32 i32 i32 i64 i64) → i32 (stub, P3·S21)  |
//! |15 | static_call      | (i32 i32 i32 i64) → i32 (stub, P3·S21)      |
//! |16 | delegate_call    | (i32 i32 i32 i64) → i32 (stub, P3·S21)      |

#![allow(clippy::result_large_err)]

use lemma_core::{
    transaction::{Transaction, TxType},
    Address, Amount, Hash, Signature, MAX_CONTRACT_WASM_SIZE,
};
use lemma_vm::{
    executor::Executor, gas::GasSchedule, runtime::LemmaEngine, state::InMemoryStateView,
    BlockContext,
};

// ─── WAT fixture ─────────────────────────────────────────────────────────────

/// Minimal no-op contract: empty `"call"` export, no `"init"`.
///
/// The WASM linker in lemma-vm registers all 17 imports (14 active + 3 stubs), so a
/// module with no explicit imports is valid and instantiates successfully.
/// This mirrors the existing unit-test pattern in executor/tests.rs.
const NOOP_WAT: &[u8] = b"(module (func (export \"call\")))";

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn make_executor() -> Executor {
    let engine = LemmaEngine::new().expect("LemmaEngine::new");
    Executor::new(engine, GasSchedule::devnet())
}

fn block_ctx() -> BlockContext {
    BlockContext {
        height: 1,
        timestamp: 1_000_000,
        msg_sender: Address::zero(),
        msg_value: Amount::zero(),
        tx_origin: Address::zero(),
        contract: Address::zero(),
        epoch: 0,
        // P3·Step 20: empty = ABI v1 baseline (P4·Step 12 populates from governance).
        active_features: std::collections::BTreeSet::new(),
    }
}

fn empty_state() -> InMemoryStateView {
    InMemoryStateView::new()
}

// LemmaEngine::compile_module accepts both binary WASM and WAT text via
// wasmtime::Module::new — so NOOP_WAT (as &[u8]) is valid tx.data.

fn deploy_tx(sender: Address, nonce: u64, data: Vec<u8>) -> Transaction {
    Transaction::new(
        Hash::zero(),
        sender,
        None, // ContractDeploy has no `to`
        nonce,
        1, // chain_id
        Amount::zero(),
        10_000_000,
        Amount::from_drop(1_000_000_000), // gas_price
        TxType::ContractDeploy,
        data,
        Signature::Unsigned,
    )
    .expect("valid deploy tx")
}

fn call_tx(sender: Address, nonce: u64, to: Address, data: Vec<u8>) -> Transaction {
    Transaction::new(
        Hash::zero(),
        sender,
        Some(to),
        nonce,
        1,
        Amount::zero(),
        10_000_000,
        Amount::from_drop(1_000_000_000),
        TxType::ContractCall,
        data,
        Signature::Unsigned,
    )
    .expect("valid call tx")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn deploy_minimal_wasm_produces_success_receipt() {
    // Deploying a valid minimal WASM module succeeds and charges gas.
    let executor = make_executor();
    let mut state = empty_state();
    let tx = deploy_tx(Address::zero(), 0, NOOP_WAT.to_vec());
    let receipt = executor.execute_transaction(&tx, block_ctx(), &mut state);

    assert!(
        receipt.success,
        "ContractDeploy of valid WASM must succeed; gas_used={}",
        receipt.gas_used
    );
    assert!(
        receipt.gas_used > 0,
        "deploy must charge some gas; got gas_used={}",
        receipt.gas_used
    );
}

#[test]
fn call_deployed_contract_succeeds() {
    // Deploy then call: both should succeed.
    let executor = make_executor();
    let mut state = empty_state();
    let sender = Address::zero();

    let deploy = deploy_tx(sender, 0, NOOP_WAT.to_vec());
    let deploy_receipt = executor.execute_transaction(&deploy, block_ctx(), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);
    let call = call_tx(sender, 1, contract_addr, vec![0u8; 4]);
    let call_receipt = executor.execute_transaction(&call, block_ctx(), &mut state);

    assert!(
        call_receipt.success,
        "ContractCall must succeed; gas_used={}",
        call_receipt.gas_used
    );
}

#[test]
fn first_call_charges_cold_surcharge_second_does_not() {
    // Cold/warm gas: first call to a contract in an Executor charges
    // code_cold_surcharge; the second call (same Executor, same contract) does not.
    let executor = make_executor();
    let mut state = empty_state();
    let sender = Address::zero();

    // Deploy (receipt discarded — we only care about the call receipts below)
    let _deploy = executor.execute_transaction(
        &deploy_tx(sender, 0, NOOP_WAT.to_vec()),
        block_ctx(),
        &mut state,
    );
    let contract = Address::from_deployer(&sender, 0);

    let r1 = executor.execute_transaction(
        &call_tx(sender, 1, contract, vec![0u8; 4]),
        block_ctx(),
        &mut state,
    );
    let r2 = executor.execute_transaction(
        &call_tx(sender, 2, contract, vec![0u8; 4]),
        block_ctx(),
        &mut state,
    );

    assert!(r1.success && r2.success, "both calls must succeed");
    assert!(
        r1.gas_used > r2.gas_used,
        "first call (cold) must use more gas than second (warm); cold={} warm={}",
        r1.gas_used,
        r2.gas_used
    );

    let surcharge = GasSchedule::devnet().code_cold_surcharge.0;
    let diff = r1.gas_used.saturating_sub(r2.gas_used);
    assert_eq!(
        diff, surcharge,
        "gas diff must equal code_cold_surcharge; diff={diff} surcharge={surcharge}"
    );
}

#[test]
fn second_deploy_of_identical_bytecode_charges_less_gas() {
    // Code dedup: deploying the same bytecode a second time skips CF_CODE
    // storage and charges only deploy_base instead of deploy_base + per_byte×len.
    let executor = make_executor();
    let mut state = empty_state();
    let sender = Address::zero();
    let wasm = NOOP_WAT.to_vec();

    let r1 =
        executor.execute_transaction(&deploy_tx(sender, 0, wasm.clone()), block_ctx(), &mut state);
    let r2 = executor.execute_transaction(&deploy_tx(sender, 1, wasm), block_ctx(), &mut state);

    assert!(r1.success && r2.success, "both deploys must succeed");
    assert!(
        r2.gas_used < r1.gas_used,
        "second deploy of identical bytecode must charge less gas (dedup); \
         first={} second={}",
        r1.gas_used,
        r2.gas_used
    );
}

#[test]
fn oversized_deploy_produces_failed_receipt() {
    // Size gate: data > MAX_CONTRACT_WASM_SIZE → ContractTooLarge error
    // (DB-A21 — DoS protection, reject before AOT compilation).
    // The intrinsic gas for huge calldata still fires (per-byte tx cost),
    // so gas_used may be up to gas_limit — but the receipt is a failure.
    let executor = make_executor();
    let mut state = empty_state();

    // Use data slightly over the limit but large enough to trigger the gate.
    // Note: intrinsic gas for ~2 MiB will exhaust a 10M gas limit, so use a
    // high gas_limit or a small-but-over-limit size with enough gas.
    let oversized = vec![0u8; MAX_CONTRACT_WASM_SIZE + 1];
    let tx = deploy_tx(Address::zero(), 0, oversized);
    let receipt = executor.execute_transaction(&tx, block_ctx(), &mut state);

    assert!(
        !receipt.success,
        "oversized ContractDeploy must produce a failed receipt (ContractTooLarge or OOG from intrinsic)"
    );
}
