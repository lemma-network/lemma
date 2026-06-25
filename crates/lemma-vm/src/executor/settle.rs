//! Settlement logic for [`Executor`].
//!
//! Contains `settle()` — the final step that applies execution results to
//! canonical state and builds the [`TransactionReceipt`]. Split from
//! `executor.rs` for file-size compliance (AGENTS §3.1 < 300 lines, V-5 audit fix).

use lemma_core::{
    address::Address,
    transaction::{Log, Transaction, TransactionReceipt},
};
use tracing::warn;

use crate::{
    error::VmError,
    gas::{gas_used, FuelMeter, Gas, GasMeter},
    safety_manifest::{validate_safety_invariants, SafetyManifest},
    state::ContractStateView,
};

use super::{Executor, ScratchState};

impl Executor {
    /// Apply the execution result to canonical state and build the receipt.
    ///
    /// ## Settlement logic
    ///
    /// 1. On success: flush scratch writes to state, record logs.
    /// 2. On failure: discard scratch (writes reverted), clear logs.
    /// 3. Either way: advance nonce, charge gas (clamped to gas_limit).
    /// 4. Build and return the receipt — never panic.
    ///
    /// ## Safety manifest (P3·Step 18, DB-A51)
    ///
    /// `manifest` is `Some((contract_addr, manifest))` for contract calls and
    /// deploys (parsed from the contract's `"lemma.meta"` WASM custom section).
    /// `None` for plain transfers (no contract, no manifest).
    ///
    /// The `contract_addr` is the address of the executing contract — NOT
    /// `tx.sender` (which is the caller/deployer EOA). This ensures the
    /// invariant check inspects the correct storage namespace (C2 fix).
    pub(crate) fn settle<S: ContractStateView>(
        &self,
        tx: &Transaction,
        result: Result<Vec<Log>, VmError>,
        manifest: Option<(Address, SafetyManifest)>,
        mandate_log: Option<Log>,
        scratch: ScratchState<'_, S>,
        meter: FuelMeter,
    ) -> TransactionReceipt {
        // Compute gas used — clamp to gas_limit (spec invariant: gas_used ≤ gas_limit).
        let initial = Gas::new(tx.gas_limit);
        let used_gas = gas_used(initial, meter.remaining()).unwrap_or_else(|| {
            // remaining > initial indicates a meter bug — log and use 0.
            warn!(
                tx_hash = %tx.hash,
                "gas meter remaining exceeded initial budget — clamping gas_used to 0"
            );
            Gas::ZERO
        });
        // Clamp: gas_used ≤ gas_limit (defensive — should already hold).
        let gas_used_clamped = used_gas.0.min(tx.gas_limit);

        match result {
            Ok(logs) => {
                // P3·Step 18-05 (DB-A51): post-execution safety-invariant check.
                //
                // If the manifest has constraints, verify the state diff before
                // committing. A violation converts success → failure (scratch
                // discarded, failed receipt produced). This is the runtime pair
                // of compile-time SAFETY-001/002/005/009.
                //
                // C2 fix: `contract_addr` is plumbed from execute_call/execute_deploy
                // so settle() uses the correct storage namespace. Previously used
                // `tx.to.unwrap_or(tx.sender)` which was WRONG for deploys (tx.to
                // is None, fell back to tx.sender = deployer EOA, not the contract).
                if let Some((contract_addr, ref m)) = manifest {
                    if !m.constraints.is_empty() {
                        if let Err(violation) = validate_safety_invariants(
                            m,
                            &contract_addr,
                            scratch.storage_writes_ref(),
                            scratch.inner_ref(),
                        ) {
                            // Invariant violated: convert success → failure.
                            // Discard scratch (no partial writes reach canonical state).
                            let inner = scratch.discard();
                            let current_nonce = inner.nonce(&tx.sender);
                            // saturating_add: nonce at u64::MAX stays there rather than wrapping.
                            inner.set_nonce(&tx.sender, current_nonce.saturating_add(1));

                            warn!(
                                tx_hash = %tx.hash,
                                error = %violation,
                                "honeypot invariant violated — reverting transaction"
                            );

                            return TransactionReceipt::new(
                                tx.hash,
                                false,
                                gas_used_clamped,
                                vec![],
                            );
                        }
                    }
                }

                // No violation — commit scratch writes to canonical state and advance nonce.
                scratch.commit_with_nonce(&tx.sender);

                // Prepend the Mandate Receipt log (§11, Step 17) before contract logs.
                // Mandate receipt is first so it is always at index 0 in the logs vec,
                // making it reliably filterable by the explorer/SDK.
                // Absent for non-agent txs (mandate_log = None).
                let mut all_logs = Vec::with_capacity(logs.len() + 1);
                if let Some(ml) = mandate_log {
                    all_logs.push(ml);
                }
                all_logs.extend(logs);

                TransactionReceipt::new(tx.hash, true, gas_used_clamped, all_logs)
            }
            Err(err) => {
                // Failure: discard scratch (no partial writes reach canonical state).
                // Advance nonce on the canonical state directly.
                let inner = scratch.discard();
                let current_nonce = inner.nonce(&tx.sender);
                // saturating_add: nonce at u64::MAX stays there rather than wrapping.
                inner.set_nonce(&tx.sender, current_nonce.saturating_add(1));

                // Log the failure for observability (not a panic — just a warn).
                warn!(
                    tx_hash = %tx.hash,
                    error = %err,
                    gas_used = gas_used_clamped,
                    "transaction failed — producing failed receipt"
                );

                // Failed receipt: success=false, logs=[] (spec §5 H2 invariant).
                TransactionReceipt::new(tx.hash, false, gas_used_clamped, vec![])
            }
        }
    }
}
