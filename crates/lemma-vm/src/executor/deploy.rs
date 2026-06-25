//! Deploy execution path for [`Executor`].
//!
//! Contains `execute_deploy` and the registry auto-population helper
//! (`try_write_registry_entry`). Split from `executor.rs` for file-size
//! compliance (AGENTS §3.1 < 300 lines, V-5 audit fix).

use lemma_core::{address::Address, hash::Hash, transaction::Transaction, MAX_CONTRACT_WASM_SIZE};

use crate::{
    error::VmError,
    gas::{FuelMeter, GasMeter},
    host::{BlockContext, CallContext, HostState},
    safety_manifest::parse_safety_manifest,
    state::ContractStateView,
};

use super::{ExecResult, Executor, ScratchState, INIT_ENTRY_POINT};

// ── IToken detection (DB-A48/DB-A54) ─────────────────────────────────────────

/// IToken interface export names used for token detection (DB-A54 decision 2).
///
/// A deployed WASM is classified as a token if it exports ANY of these names.
/// This matches the IToken interface defined in `03-LANGUAGE_SPEC §24`.
const ITOKEN_EXPORTS: &[&str] = &["transfer", "transferFrom", "balanceOf", "approve"];

impl Executor {
    /// Execute a `ContractDeploy` transaction.
    ///
    /// Implements the full deploy design contract (08-EXECUTION_SPEC §3.4(a)(b)(c)):
    ///
    /// 1. **Size gate** (DB-A21): reject oversized bytecode BEFORE charging gas.
    ///    A validator must never let an oversized module occupy its AOT compiler.
    /// 2. **Content-addressed dedup** (DB-A23): bytecode is stored in CF_CODE keyed
    ///    by `blake3(bytecode)`. First deployer pays storage gas; later deployers of
    ///    identical bytecode pay only the base pointer-write cost.
    /// 3. **Thin pointer** (DB-A22): `Account.code_hash = blake3(bytecode)` — the
    ///    account record holds only the 32-byte hash, not the full bytecode.
    /// 4. **Init constructor** (P3·Step 7): if the module exports `"init"`, invoke
    ///    it once after the thin pointer is set. Init gas is charged from the same
    ///    meter. If init traps, the entire deploy fails — no contract is registered.
    ///
    /// # Errors
    ///
    /// - [`VmError::ContractTooLarge`] — bytecode exceeds `MAX_CONTRACT_WASM_SIZE`
    ///   (returned BEFORE gas is charged — DoS protection).
    /// - [`VmError::CompilationFailed`] — bytecode is not valid WASM/WAT.
    /// - [`VmError::InvalidParameter`] — address already has code deployed.
    /// - Any [`VmError`] from init execution — deploy fails, no contract registered.
    pub(crate) fn execute_deploy<S: ContractStateView + Clone + 'static>(
        &self,
        tx: &Transaction,
        block: BlockContext,
        scratch: &mut ScratchState<'_, S>,
        meter: &mut FuelMeter,
    ) -> ExecResult {
        // 1. SIZE GATE — reject-before-charge (DB-A21, 08-EXECUTION_SPEC §3.4(a)).
        //    No gas is charged for an oversized module: the validator did no meaningful
        //    work beyond the size check, and charging gas would reward DoS attempts.
        if tx.data.len() > MAX_CONTRACT_WASM_SIZE {
            return (
                Err(VmError::ContractTooLarge {
                    size: tx.data.len(),
                    limit: MAX_CONTRACT_WASM_SIZE,
                }),
                None,
            );
        }

        // 2. COMPUTE code_hash = blake3(bytecode).
        //    lemma_crypto::hash_bytes is the canonical Blake3 primitive (AGENTS §2.2).
        let code_hash: Hash = lemma_crypto::hash_bytes(&tx.data);

        // 3. DERIVE contract address from deployer + current nonce.
        let current_nonce = scratch.nonce(&tx.sender);
        let contract_addr = Address::from_deployer(&tx.sender, current_nonce);

        // 4. GUARD: address must not already have code (no re-deploy).
        //    scratch.code() checks: thin-pointer map (this tx) → legacy code_writes
        //    (this tx) → inner.code() (prior committed txs). Covers all cases.
        if scratch.code(&contract_addr).is_some() {
            return (
                Err(VmError::InvalidParameter {
                    reason: format!("contract already deployed at {contract_addr}"),
                }),
                None,
            );
        }

        // 5. COMPILE bytecode — fail fast before storing anything.
        //    (compile_module accepts both binary WASM and WAT text)
        //    The compiled module is reused for init invocation below (step 8).
        let module = match self.engine.compile_module(&tx.data) {
            Ok(m) => m,
            Err(e) => return (Err(e), None),
        };

        // 5b. HOST-ABI VERSION GATE (P3·Step 20, DB-A58 L2).
        //
        //     Extract and validate the host-ABI version from "lemma.meta".
        //     Reject BEFORE any state writes or gas charges for storage:
        //     the node cannot provide correct host-function semantics for a
        //     contract compiled against an unsupported ABI version.
        //
        //     Placement: after compile (step 5) so the WASM is valid enough to
        //     parse, but before content-addressed dedup (step 6) so no storage
        //     gas is charged. Follows the reject-before-charge pattern used by
        //     ContractTooLarge (step 1, line ~459).
        let host_abi = crate::safety_manifest::parse_host_abi(&tx.data);
        if host_abi > crate::MAX_SUPPORTED_HOST_ABI {
            return (
                Err(VmError::UnsupportedHostAbi {
                    deployed_abi: host_abi,
                    max_supported: crate::MAX_SUPPORTED_HOST_ABI,
                }),
                None,
            );
        }

        // 6. CONTENT-ADDRESSED DEDUP (DB-A23, 08-EXECUTION_SPEC §3.4(b/c)).
        //    Check whether this code_hash is already in the content store.
        //    First deployer: store bytecode + charge storage gas.
        //    Later deployer: skip storage gas, charge only base (pointer write).
        //
        //    has_code_hash() checks both scratch (this tx) and inner (prior txs),
        //    enabling cross-transaction dedup savings.
        //
        //    NOTE: We always store bytecode in code_store_writes (even for later
        //    deployers) so that commit_with_nonce can resolve bytecode for
        //    inner.set_code(). The dedup savings are in GAS, not in scratch storage
        //    (scratch is per-transaction and discarded after commit).
        let is_first_deployer = !scratch.has_code_hash(&code_hash);

        if is_first_deployer {
            // First deployer pays storage cost: base + per_byte × len (AGENTS §2.1 DRY).
            if let Err(e) = meter.charge_per_byte(
                self.schedule.deploy_base,
                self.schedule.deploy_storage_per_byte,
                tx.data.len(),
            ) {
                return (Err(e), None);
            }
        } else {
            // Later deployer: only the account pointer write — base cost only.
            if let Err(e) = meter.charge(self.schedule.deploy_base) {
                return (Err(e), None);
            }
        }

        // Always store bytecode in the content-addressed scratch store so that
        // commit_with_nonce can resolve it for inner.set_code(). For later deployers,
        // this is a no-op if the hash is already present (BTreeMap::insert overwrites
        // with the same value — idempotent and correct).
        scratch.put_code_content(code_hash, tx.data.clone());

        // 7. SET thin pointer: Account.code_hash = blake3(bytecode).
        //    Always set regardless of first/later deployer — the account record
        //    must point to the code_hash so execute_call can resolve bytecode.
        scratch.set_code_hash_ptr(&contract_addr, code_hash);

        // 8. INIT CONSTRUCTOR INVOCATION (P3·Step 7, 08-EXECUTION_SPEC §4.5).
        //
        //    If the compiled module exports "init", invoke it once now.
        //    Init runs with:
        //      - msg.sender = tx.sender (the deployer)
        //      - contract   = contract_addr (the newly derived address)
        //      - calldata   = empty (constructor args are not yet defined in B4)
        //
        //    State writes from init are accumulated in the same scratch overlay
        //    and committed together with the deploy on success. If init traps or
        //    runs out of gas, the entire deploy fails — no contract is registered
        //    and scratch is discarded by settle() (AGENTS §7.2 — no panics).
        //
        //    Modules without an "init" export deploy successfully without a
        //    constructor (defaults-only deploy).
        //
        //    Gas: init execution is charged from the same meter as the deploy.
        //    The snapshot/merge pattern (same as execute_call) satisfies the
        //    'static bound on the linker's func_wrap closures without requiring
        //    ScratchState to be 'static (Phase 3 will replace with multi-frame stack).
        let init_block_ctx = BlockContext {
            contract: contract_addr,
            msg_sender: tx.sender,
            ..block
        };

        let snapshot = scratch.snapshot();
        let init_host = HostState::new(
            FuelMeter::new(meter.remaining()),
            self.engine.clone(), // engine for cross-contract calls (LemmaEngine = Arc<wasmtime::Engine> newtype)
            self.schedule,
            CallContext::new(),
            init_block_ctx,
            snapshot,
            vec![], // init calldata: empty (B4 — constructor args deferred to Phase 3)
        );

        let (init_consumed, init_host_after) =
            match self.run_wasm_with_entry(host_abi, &module, init_host, INIT_ENTRY_POINT) {
                Ok(r) => r,
                Err(e) => return (Err(e), None),
            };

        // Merge init's state writes back into the deploy's scratch overlay.
        // On success, these writes are committed together with the deploy.
        scratch.merge_snapshot(init_host_after.state);

        // Charge init gas from the outer meter.
        // run_wasm_with_entry already returned Ok, so init_consumed ≤ meter.remaining().
        // The match above ensures we only reach here on success.
        let _ = meter.charge(init_consumed);

        // 9. REGISTRY AUTO-POPULATION (DB-A48/DB-A54, P3·Step 7 subtask_09).
        //
        //    If the deployed WASM exports any IToken interface function
        //    ("transfer", "transferFrom", "balanceOf", "approve"), write a
        //    metadata entry into the registry system contract's storage namespace.
        //
        //    Key layout (40 bytes, deterministic — AGENTS §7.1):
        //      registry_addr.as_bytes() (20) ++ contract_addr.as_bytes() (20)
        //
        //    Value: minimal JSON metadata `{"address":"<hex>","is_token":true}`.
        //
        //    This is a best-effort, append-only write. If detection or the write
        //    fails for any reason, we log a warning and continue — the deploy
        //    MUST NOT be failed by registry issues (DB-A54 decision 2, AGENTS §7.2).
        try_write_registry_entry(&module, &contract_addr, scratch);

        // 10. PARSE SAFETY MANIFEST from the deploy bytecode (P3·Step 18, DB-A51).
        //
        //     tx.data is the WASM bytecode — parse the manifest from it now so
        //     settle() (and later, the invariant enforcer) has access to it.
        //     Also cache it for subsequent calls to this contract in the same block.
        let manifest = parse_safety_manifest(&tx.data);

        // C1 fix: charge invariant-check gas if manifest has constraints (DB-A51).
        // Charge BEFORE the check runs (charge-before-execute, AGENTS §7.5).
        if !manifest.constraints.is_empty() {
            if let Err(e) = meter.charge(self.schedule.invariant_check) {
                return (Err(e), Some((contract_addr, manifest)));
            }
        }

        {
            // W1 fix: recover from poisoned mutex instead of panicking.
            let mut cache = self
                .safety_manifests
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            cache.insert(contract_addr, manifest.clone());
        }

        // C2 fix: pass contract_addr alongside manifest so settle() uses the
        // correct storage namespace (not tx.sender which is the deployer EOA).
        (Ok(vec![]), Some((contract_addr, manifest)))
    }
}

// ── Registry auto-population (DB-A48/DB-A54) ─────────────────────────────────

/// Attempt to write a registry entry for a newly deployed token contract.
///
/// Called after successful init invocation in `execute_deploy`. Inspects the
/// compiled module's exports to detect IToken interface compliance, then writes
/// a metadata entry into the registry system contract's storage namespace.
///
/// ## Key layout (40 bytes, deterministic — AGENTS §7.1)
///
/// ```text
/// key = registry_addr.as_bytes() (20) ++ contract_addr.as_bytes() (20)
/// ```
///
/// The key is stored under the registry system contract's storage namespace
/// (first argument to `scratch.write`), so the full storage address is:
/// `(registry_addr, key)` where `key` is the 40-byte concatenation above.
///
/// ## Best-effort semantics (DB-A54 decision 2, AGENTS §7.2)
///
/// This function NEVER propagates errors. Any failure (export inspection,
/// JSON formatting, storage write) is logged as a warning and silently
/// ignored. The deploy MUST NOT fail due to registry issues.
fn try_write_registry_entry<S: ContractStateView>(
    module: &wasmtime::Module,
    contract_addr: &Address,
    scratch: &mut ScratchState<'_, S>,
) {
    // Detect IToken interface: check if the module exports any IToken function.
    // wasmtime::Module::get_export(name) returns Some(ExternType) if the export
    // exists, None otherwise. We check ExternType::Func to ensure it is a function
    // (not a memory or global with the same name). O(1) per lookup.
    // This is a pure inspection — no instantiation, no gas, no side effects.
    let is_token = ITOKEN_EXPORTS
        .iter()
        .any(|&name| matches!(module.get_export(name), Some(wasmtime::ExternType::Func(_))));

    if !is_token {
        // Non-token contract — no registry entry needed.
        return;
    }

    // Build the 40-byte registry key:
    //   registry_addr.as_bytes() (20) ++ contract_addr.as_bytes() (20)
    // This is deterministic: same inputs → same key on every node (AGENTS §7.1).
    let registry_addr = Address::registry();
    let mut key = [0u8; 40];
    key[..20].copy_from_slice(registry_addr.as_bytes());
    key[20..].copy_from_slice(contract_addr.as_bytes());

    // Build minimal JSON metadata value.
    // Format: {"address":"<hex>","is_token":true}
    // Hex-encode the 20-byte address for human-readable JSON.
    let addr_hex: String = contract_addr
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let metadata = format!(r#"{{"address":"{addr_hex}","is_token":true}}"#);

    // Write to the registry system contract's storage namespace.
    // Key = 40-byte concatenation; value = UTF-8 JSON bytes.
    // On any failure, warn and continue — never fail the deploy.
    scratch.write(&registry_addr, &key, metadata.into_bytes());

    tracing::debug!(
        contract = %contract_addr,
        "registry: token contract auto-registered (DB-A54)"
    );
}
