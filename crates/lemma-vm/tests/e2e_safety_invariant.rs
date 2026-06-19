//! End-to-end integration tests: deploy + call + safety-invariant enforcement.
//!
//! Exercises the full deploy→call→settle→invariant-check pipeline added in
//! P3·Step 18 (DB-A51 part 2). Each test:
//!
//! 1. Builds a WASM module with `wasm_encoder` that imports `storage_write`
//!    from `"lemma"` and writes specific key/value pairs when called.
//! 2. Embeds a `"lemma.meta"` custom section with safety constraints.
//! 3. Deploys the contract, optionally pre-populates canonical state.
//! 4. Calls the contract and asserts the receipt outcome (success or failure).
//!
//! ## WASM module structure
//!
//! Each test module:
//! - Imports `("lemma", "storage_write", func (param i32 i32 i32 i32))`.
//! - Exports a 1-page linear memory.
//! - Embeds key and value bytes as data segments at known offsets.
//! - Exports a `"call"` function that invokes `storage_write` with the
//!   embedded key/value data.
//! - Contains a `"lemma.meta"` custom section with the safety manifest JSON.
//!
//! The linker in `executor/linker.rs` matches imports by name (not index),
//! so importing only `storage_write` is sufficient — the other 13 host
//! functions are registered but not imported by the test module.

#![allow(clippy::result_large_err)]

use lemma_core::{
    transaction::{Transaction, TxType},
    Address, Amount, Hash, Signature,
};
use lemma_vm::{
    executor::Executor,
    gas::GasSchedule,
    runtime::LemmaEngine,
    state::{ContractStateView, InMemoryStateView},
    BlockContext,
};

// ─── WASM builder ────────────────────────────────────────────────────────────

/// Build a WASM module that writes `storage_value` to `storage_key` when
/// its `"call"` export is invoked, and includes a `"lemma.meta"` custom
/// section with the given `manifest_json`.
///
/// ## Memory layout (offsets in linear memory page 0)
///
/// ```text
/// 0x0000 .. 0x0000+key_len   : storage key bytes
/// 0x0100 .. 0x0100+val_len   : storage value bytes
/// ```
///
/// ## WASM structure
///
/// - Type section: one function type `(i32, i32, i32, i32) -> ()` for the
///   imported `storage_write`, and one `() -> ()` for the `"call"` export.
/// - Import section: `("lemma", "storage_write")` with the 4×i32 signature.
/// - Function section: one local function (the `"call"` export).
/// - Memory section: one memory (1 page min, 1 page max), exported as `"memory"`.
/// - Export section: `"call"` (function) and `"memory"` (memory).
/// - Data section: active data segments placing key and value bytes at offsets.
/// - Code section: `"call"` body calls `storage_write(0, key_len, 256, val_len)`.
/// - Custom section: `"lemma.meta"` with the manifest JSON.
fn build_wasm_with_manifest_and_write(
    manifest_json: &str,
    storage_key: &[u8],
    storage_value: &[u8],
) -> Vec<u8> {
    use std::borrow::Cow;
    use wasm_encoder::{
        CodeSection, ConstExpr, CustomSection, DataSection, EntityType, ExportKind, ExportSection,
        Function, FunctionSection, ImportSection, Instruction, MemorySection, MemoryType, Module,
        TypeSection, ValType,
    };

    let key_offset: i32 = 0;
    let val_offset: i32 = 256;

    let mut module = Module::new();

    // ── Type section ─────────────────────────────────────────────────────
    // Type 0: (i32, i32, i32, i32) -> () — storage_write signature
    // Type 1: () -> ()                   — call export signature
    let mut types = TypeSection::new();
    types.ty().function(
        vec![ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        vec![],
    );
    types.ty().function(vec![], vec![]);
    module.section(&types);

    // ── Import section ───────────────────────────────────────────────────
    // Import storage_write from "lemma" module, type index 0.
    let mut imports = ImportSection::new();
    imports.import("lemma", "storage_write", EntityType::Function(0));
    module.section(&imports);

    // ── Function section ─────────────────────────────────────────────────
    // One local function (the "call" export), type index 1.
    let mut functions = FunctionSection::new();
    functions.function(1); // type index 1: () -> ()
    module.section(&functions);

    // ── Memory section ───────────────────────────────────────────────────
    // One memory: 1 page min, 1 page max (64 KiB — plenty for test data).
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: 1,
        maximum: Some(1),
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    // ── Export section ───────────────────────────────────────────────────
    // Export "call" (function index 1 — index 0 is the imported storage_write).
    // Export "memory" (memory index 0).
    let mut exports = ExportSection::new();
    exports.export("call", ExportKind::Func, 1); // func idx 1 = local fn
    exports.export("memory", ExportKind::Memory, 0);
    module.section(&exports);

    // ── Code section ─────────────────────────────────────────────────────
    // "call" body: invoke storage_write(key_offset, key_len, val_offset, val_len)
    let mut code = CodeSection::new();
    let mut func = Function::new(vec![]); // no locals
    func.instruction(&Instruction::I32Const(key_offset));
    func.instruction(&Instruction::I32Const(storage_key.len() as i32));
    func.instruction(&Instruction::I32Const(val_offset));
    func.instruction(&Instruction::I32Const(storage_value.len() as i32));
    func.instruction(&Instruction::Call(0)); // call imported storage_write (func idx 0)
    func.instruction(&Instruction::End);
    code.function(&func);
    module.section(&code);

    // ── Data section ─────────────────────────────────────────────────────
    // Active data segments: place key at offset 0, value at offset 256.
    let key_const = ConstExpr::i32_const(key_offset);
    let val_const = ConstExpr::i32_const(val_offset);
    let mut data = DataSection::new();
    data.active(0, &key_const, storage_key.iter().copied());
    data.active(0, &val_const, storage_value.iter().copied());
    module.section(&data);

    // ── Custom section: "lemma.meta" ─────────────────────────────────────
    module.section(&CustomSection {
        name: Cow::Borrowed("lemma.meta"),
        data: Cow::Borrowed(manifest_json.as_bytes()),
    });

    module.finish()
}

/// Build a WASM module that writes multiple key/value pairs when called.
///
/// Each `(key, value)` pair is written via a separate `storage_write` call.
/// Memory layout: keys and values are packed sequentially starting at
/// offset 0, with each segment at a unique offset.
fn build_wasm_with_manifest_and_multi_write(
    manifest_json: &str,
    writes: &[(&[u8], &[u8])],
) -> Vec<u8> {
    use std::borrow::Cow;
    use wasm_encoder::{
        CodeSection, ConstExpr, CustomSection, DataSection, EntityType, ExportKind, ExportSection,
        Function, FunctionSection, ImportSection, Instruction, MemorySection, MemoryType, Module,
        TypeSection, ValType,
    };

    let mut module = Module::new();

    // ── Type section ─────────────────────────────────────────────────────
    let mut types = TypeSection::new();
    types.ty().function(
        vec![ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        vec![],
    );
    types.ty().function(vec![], vec![]);
    module.section(&types);

    // ── Import section ───────────────────────────────────────────────────
    let mut imports = ImportSection::new();
    imports.import("lemma", "storage_write", EntityType::Function(0));
    module.section(&imports);

    // ── Function section ─────────────────────────────────────────────────
    let mut functions = FunctionSection::new();
    functions.function(1);
    module.section(&functions);

    // ── Memory section ───────────────────────────────────────────────────
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: 1,
        maximum: Some(1),
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    // ── Export section ───────────────────────────────────────────────────
    let mut exports = ExportSection::new();
    exports.export("call", ExportKind::Func, 1);
    exports.export("memory", ExportKind::Memory, 0);
    module.section(&exports);

    // ── Compute memory layout ────────────────────────────────────────────
    // Pack all keys and values sequentially with 16-byte alignment.
    struct Segment {
        key_off: i32,
        key_len: i32,
        val_off: i32,
        val_len: i32,
    }
    let mut segments: Vec<Segment> = Vec::new();
    let mut offset: u32 = 0;
    for (key, value) in writes {
        let key_off = offset;
        let key_len = key.len() as u32;
        offset += key_len;
        // Align to next 16-byte boundary for readability (not required).
        offset = (offset + 15) & !15;
        let val_off = offset;
        let val_len = value.len() as u32;
        offset += val_len;
        offset = (offset + 15) & !15;
        segments.push(Segment {
            key_off: key_off as i32,
            key_len: key_len as i32,
            val_off: val_off as i32,
            val_len: val_len as i32,
        });
    }

    // ── Code section ─────────────────────────────────────────────────────
    // Build the "call" body: one storage_write call per (key, value) pair.
    let mut code = CodeSection::new();
    let mut func = Function::new(vec![]);
    for seg in &segments {
        func.instruction(&Instruction::I32Const(seg.key_off));
        func.instruction(&Instruction::I32Const(seg.key_len));
        func.instruction(&Instruction::I32Const(seg.val_off));
        func.instruction(&Instruction::I32Const(seg.val_len));
        func.instruction(&Instruction::Call(0));
    }
    func.instruction(&Instruction::End);
    code.function(&func);
    module.section(&code);

    // ── Data section ─────────────────────────────────────────────────────
    // Build ConstExpr offsets and data segments. We need to collect the
    // ConstExpr values first so they live long enough for the borrows.
    let mut data = DataSection::new();
    let mut data_offset: u32 = 0;
    for (key, value) in writes {
        // Key segment
        let key_const = ConstExpr::i32_const(data_offset as i32);
        data.active(0, &key_const, key.iter().copied());
        data_offset += key.len() as u32;
        data_offset = (data_offset + 15) & !15;
        // Value segment
        let val_const = ConstExpr::i32_const(data_offset as i32);
        data.active(0, &val_const, value.iter().copied());
        data_offset += value.len() as u32;
        data_offset = (data_offset + 15) & !15;
    }
    module.section(&data);

    // ── Custom section: "lemma.meta" ─────────────────────────────────────
    module.section(&CustomSection {
        name: Cow::Borrowed("lemma.meta"),
        data: Cow::Borrowed(manifest_json.as_bytes()),
    });

    module.finish()
}

/// Build a WASM module that writes `storage_value` to `storage_key` when
/// called, but has NO `"lemma.meta"` custom section (backward compat test).
fn build_wasm_without_manifest_with_write(storage_key: &[u8], storage_value: &[u8]) -> Vec<u8> {
    use wasm_encoder::{
        CodeSection, ConstExpr, DataSection, EntityType, ExportKind, ExportSection, Function,
        FunctionSection, ImportSection, Instruction, MemorySection, MemoryType, Module,
        TypeSection, ValType,
    };

    let key_offset: i32 = 0;
    let val_offset: i32 = 256;

    let mut module = Module::new();

    let mut types = TypeSection::new();
    types.ty().function(
        vec![ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        vec![],
    );
    types.ty().function(vec![], vec![]);
    module.section(&types);

    let mut imports = ImportSection::new();
    imports.import("lemma", "storage_write", EntityType::Function(0));
    module.section(&imports);

    let mut functions = FunctionSection::new();
    functions.function(1);
    module.section(&functions);

    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: 1,
        maximum: Some(1),
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    let mut exports = ExportSection::new();
    exports.export("call", ExportKind::Func, 1);
    exports.export("memory", ExportKind::Memory, 0);
    module.section(&exports);

    let mut code = CodeSection::new();
    let mut func = Function::new(vec![]);
    func.instruction(&Instruction::I32Const(key_offset));
    func.instruction(&Instruction::I32Const(storage_key.len() as i32));
    func.instruction(&Instruction::I32Const(val_offset));
    func.instruction(&Instruction::I32Const(storage_value.len() as i32));
    func.instruction(&Instruction::Call(0));
    func.instruction(&Instruction::End);
    code.function(&func);
    module.section(&code);

    let key_const = ConstExpr::i32_const(key_offset);
    let val_const = ConstExpr::i32_const(val_offset);
    let mut data = DataSection::new();
    data.active(0, &key_const, storage_key.iter().copied());
    data.active(0, &val_const, storage_value.iter().copied());
    module.section(&data);

    // No "lemma.meta" custom section — backward compatibility.
    module.finish()
}

// ─── Manifest JSON builders ──────────────────────────────────────────────────

/// Build a `"lemma.meta"` JSON string with a single `ratchet_off` constraint.
fn manifest_ratchet_off(key: &[u8]) -> String {
    let key_json = serde_json::to_string(&key).expect("serialize key");
    format!(
        r#"{{"contract":"TestToken","compiler":"lemma-lang/0.1.0","functions":[],"safety_constraints":[{{"type":"ratchet_off","key":{key_json}}}]}}"#
    )
}

/// Build a `"lemma.meta"` JSON string with a single `fee_cap` constraint.
fn manifest_fee_cap(fee_keys: &[&[u8]], max_sum_bps: u16) -> String {
    let keys_json: Vec<String> = fee_keys
        .iter()
        .map(|k| serde_json::to_string(k).expect("serialize fee key"))
        .collect();
    let keys_array = keys_json.join(",");
    format!(
        r#"{{"contract":"TestToken","compiler":"lemma-lang/0.1.0","functions":[],"safety_constraints":[{{"type":"fee_cap","fee_keys":[{keys_array}],"max_sum_bps":{max_sum_bps}}}]}}"#
    )
}

// ─── Shared helpers (mirrors e2e_deploy_call.rs — DRY within test crate) ─────

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
    }
}

fn deploy_tx(sender: Address, nonce: u64, data: Vec<u8>) -> Transaction {
    Transaction::new(
        Hash::zero(),
        sender,
        None,
        nonce,
        1,
        Amount::zero(),
        50_000_000, // generous gas limit for WASM with storage_write
        Amount::from_drop(1_000_000_000),
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
        50_000_000,
        Amount::from_drop(1_000_000_000),
        TxType::ContractCall,
        data,
        Signature::Unsigned,
    )
    .expect("valid call tx")
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn deploy_with_manifest_then_safe_call_succeeds() {
    // Deploy a contract with a RatchetOff constraint on key "mintable".
    // Call the contract — it writes mintable=[1] (already enabled in canonical).
    // No state change (was [1], still [1]) → no violation → success receipt.
    let executor = make_executor();
    let mut state = InMemoryStateView::new();
    let sender = Address::zero();

    let manifest = manifest_ratchet_off(b"mintable");
    let wasm = build_wasm_with_manifest_and_write(&manifest, b"mintable", &[1]);

    // Deploy the contract.
    let deploy = deploy_tx(sender, 0, wasm);
    let deploy_receipt = executor.execute_transaction(&deploy, block_ctx(), &mut state);
    assert!(
        deploy_receipt.success,
        "deploy must succeed; gas_used={}",
        deploy_receipt.gas_used
    );

    let contract_addr = Address::from_deployer(&sender, 0);

    // Pre-populate canonical state: mintable=[1] (already enabled).
    // This must be done AFTER deploy commits (deploy advances nonce and writes
    // code to state). We write directly to the state view.
    state.write(&contract_addr, b"mintable", vec![1]);

    // Call the contract — writes mintable=[1] (same value, no state change).
    let call = call_tx(sender, 1, contract_addr, vec![0u8; 4]);
    let call_receipt = executor.execute_transaction(&call, block_ctx(), &mut state);

    assert!(
        call_receipt.success,
        "call writing same value (no state change) must succeed; gas_used={}",
        call_receipt.gas_used
    );
}

#[test]
fn deploy_with_manifest_then_honeypot_call_reverts() {
    // Deploy a contract with a RatchetOff constraint on key "mintable".
    // Pre-set canonical state: mintable=[0] (disabled).
    // Call the contract — it writes mintable=[1] (re-enabling).
    // RatchetOff violation: off→on is blocked → failed receipt.
    let executor = make_executor();
    let mut state = InMemoryStateView::new();
    let sender = Address::zero();

    let manifest = manifest_ratchet_off(b"mintable");
    let wasm = build_wasm_with_manifest_and_write(&manifest, b"mintable", &[1]);

    // Deploy.
    let deploy = deploy_tx(sender, 0, wasm);
    let deploy_receipt = executor.execute_transaction(&deploy, block_ctx(), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);

    // Pre-populate canonical state: mintable=[0] (disabled — the "off" state).
    state.write(&contract_addr, b"mintable", vec![0]);

    // Call the contract — writes mintable=[1] (re-enabling: off→on).
    // This violates the ratchet_off constraint.
    let call = call_tx(sender, 1, contract_addr, vec![0u8; 4]);
    let call_receipt = executor.execute_transaction(&call, block_ctx(), &mut state);

    assert!(
        !call_receipt.success,
        "call re-enabling a ratchet_off flag must produce a FAILED receipt \
         (honeypot invariant violation); gas_used={}",
        call_receipt.gas_used
    );
    // Gas must still be charged (spec §5: reverted tx charges gas).
    assert!(
        call_receipt.gas_used > 0,
        "reverted tx must still charge gas; got gas_used=0"
    );
}

#[test]
fn deploy_with_fee_cap_then_exceeded_reverts() {
    // Deploy with FeeCap constraint: fee_keys=[b"fees.burn", b"fees.holders"],
    // max_sum_bps=1000.
    // Call — writes fees.burn=1000 (LE u64) and fees.holders=1 (LE u64).
    // Sum = 1001 > 1000 → violation → failed receipt.
    let executor = make_executor();
    let mut state = InMemoryStateView::new();
    let sender = Address::zero();

    let manifest = manifest_fee_cap(&[b"fees.burn", b"fees.holders"], 1000);
    let wasm = build_wasm_with_manifest_and_multi_write(
        &manifest,
        &[
            (b"fees.burn" as &[u8], &1000u64.to_le_bytes() as &[u8]),
            (b"fees.holders" as &[u8], &1u64.to_le_bytes() as &[u8]),
        ],
    );

    // Deploy.
    let deploy = deploy_tx(sender, 0, wasm);
    let deploy_receipt = executor.execute_transaction(&deploy, block_ctx(), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);

    // Call — writes fees.burn=1000 and fees.holders=1. Sum=1001 > cap=1000.
    let call = call_tx(sender, 1, contract_addr, vec![0u8; 4]);
    let call_receipt = executor.execute_transaction(&call, block_ctx(), &mut state);

    assert!(
        !call_receipt.success,
        "call exceeding fee cap must produce a FAILED receipt; gas_used={}",
        call_receipt.gas_used
    );
    assert!(
        call_receipt.gas_used > 0,
        "reverted tx must still charge gas"
    );
}

#[test]
fn deploy_with_fee_cap_within_limit_succeeds() {
    // Deploy with FeeCap constraint: max_sum_bps=1000.
    // Call — writes fees.burn=500 and fees.holders=500. Sum=1000 = cap → OK.
    let executor = make_executor();
    let mut state = InMemoryStateView::new();
    let sender = Address::zero();

    let manifest = manifest_fee_cap(&[b"fees.burn", b"fees.holders"], 1000);
    let wasm = build_wasm_with_manifest_and_multi_write(
        &manifest,
        &[
            (b"fees.burn" as &[u8], &500u64.to_le_bytes() as &[u8]),
            (b"fees.holders" as &[u8], &500u64.to_le_bytes() as &[u8]),
        ],
    );

    // Deploy.
    let deploy = deploy_tx(sender, 0, wasm);
    let deploy_receipt = executor.execute_transaction(&deploy, block_ctx(), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);

    // Call — writes fees.burn=500 and fees.holders=500. Sum=1000 ≤ 1000 → OK.
    let call = call_tx(sender, 1, contract_addr, vec![0u8; 4]);
    let call_receipt = executor.execute_transaction(&call, block_ctx(), &mut state);

    assert!(
        call_receipt.success,
        "call within fee cap must succeed; gas_used={}",
        call_receipt.gas_used
    );
}

#[test]
fn deploy_without_manifest_allows_any_write() {
    // Deploy a contract with NO safety constraints (no "lemma.meta" section).
    // Call — writes arbitrary data. No invariant check → success.
    // This verifies backward compatibility: pre-Step-18 contracts are unaffected.
    let executor = make_executor();
    let mut state = InMemoryStateView::new();
    let sender = Address::zero();

    // Build WASM without a "lemma.meta" section — the module writes
    // mintable=[1] but has no manifest, so no constraints are enforced.
    let no_manifest_wasm = build_wasm_without_manifest_with_write(b"mintable", &[1]);

    // Deploy.
    let deploy = deploy_tx(sender, 0, no_manifest_wasm);
    let deploy_receipt = executor.execute_transaction(&deploy, block_ctx(), &mut state);
    assert!(deploy_receipt.success, "deploy must succeed");

    let contract_addr = Address::from_deployer(&sender, 0);

    // Pre-populate: mintable=[0] (disabled). Without a manifest, re-enabling
    // is allowed — no ratchet_off constraint exists.
    state.write(&contract_addr, b"mintable", vec![0]);

    // Call — writes mintable=[1]. No manifest → no invariant check → success.
    let call = call_tx(sender, 1, contract_addr, vec![0u8; 4]);
    let call_receipt = executor.execute_transaction(&call, block_ctx(), &mut state);

    assert!(
        call_receipt.success,
        "contract without manifest must allow any write (backward compat); gas_used={}",
        call_receipt.gas_used
    );
}
