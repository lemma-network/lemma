//! # Gas primitives — shared across VM, RPC, and mempool.
//!
//! [`Gas`] and [`GasSchedule`] live here so that `lemma-rpc` (fee estimation)
//! and `lemma-mempool` (base-fee checks) can import them without depending on
//! `lemma-vm` (AGENTS §2.4 — shared utilities live in `lemma-core`).
//!
//! The metering machinery ([`GasMeter`] trait, [`FuelMeter`] impl, [`gas_used`])
//! remains in `lemma-vm` because it depends on [`VmError`].
//!
//! ## Key rules (08-EXECUTION_SPEC §3.1)
//!
//! 1. **Charge BEFORE execute** — meter up front; OOG traps before side effects.
//! 2. **No free host functions** — every host call has a cost (else DoS).
//! 3. **Checked arithmetic** — all gas math uses `checked_*` (AGENTS §7.4).

// ── Gas ───────────────────────────────────────────────────────────────────────

/// Dimensionless execution cost unit (08-EXECUTION_SPEC §3.3).
///
/// One `Gas` unit ≈ one wasmtime fuel unit for raw compute.
/// Not to be confused with `Amount`/`Drop`/`Drip` — those are fee *values*.
/// Conversion: fee = `gas_used × gas_price` (where gas_price is an `Amount`).
///
/// All arithmetic is checked (AGENTS §7.4) — panicking ops are not exposed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Gas(pub u64);

impl Gas {
    /// Zero gas cost — the additive identity.
    pub const ZERO: Gas = Gas(0);

    /// Construct from a raw `u64`.
    #[inline]
    pub fn new(n: u64) -> Self {
        Gas(n)
    }

    /// Return the inner `u64` value.
    #[inline]
    pub fn as_u64(self) -> u64 {
        self.0
    }

    /// Checked addition. Returns `None` on overflow.
    #[inline]
    pub fn checked_add(self, rhs: Gas) -> Option<Gas> {
        self.0.checked_add(rhs.0).map(Gas)
    }

    /// Checked subtraction. Returns `None` on underflow.
    #[inline]
    pub fn checked_sub(self, rhs: Gas) -> Option<Gas> {
        self.0.checked_sub(rhs.0).map(Gas)
    }

    /// Saturating subtraction — clamps to zero on underflow (never panics).
    #[inline]
    pub fn saturating_sub(self, rhs: Gas) -> Gas {
        Gas(self.0.saturating_sub(rhs.0))
    }

    /// Gas forwardable to a sub-call: `self − self/64` (63/64 rule, EIP-150).
    ///
    /// Integer division rounds down. Cannot underflow: `self/64 ≤ self`.
    /// Guarantees the caller always retains at least `1/64` of its remaining
    /// gas for cleanup / return handling after the callee returns.
    #[inline]
    pub fn forwardable(self) -> Gas {
        // self.0 / 64 ≤ self.0 always, so subtraction cannot underflow.
        Gas(self.0 - self.0 / 64)
    }
}

impl std::fmt::Display for Gas {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── GasSchedule ───────────────────────────────────────────────────────────────

/// Named gas cost constants for all LemmaVM operation categories.
///
/// Placeholder values grounded in EIP-2929/EIP-150 ratios — final values
/// require post-testnet benchmarking (08-EXECUTION_SPEC §3.2 principle 1:
/// "cost ∝ resource consumed").
///
/// Lives in `lemma-core` so that `lemma-rpc` (fee estimation) and
/// `lemma-mempool` (base-fee checks) share ONE schedule (AGENTS §2.4).
#[derive(Debug, Clone, Copy)]
pub struct GasSchedule {
    // ── Tx intrinsic (charged before any execution begins) ──────────────────
    /// Flat baseline cost per transaction (EIP-2930: 21 000 gas floor).
    pub tx_base: Gas,
    /// Per-byte cost of calldata (EIP-2028: 16 gas/non-zero byte; simplified).
    pub tx_calldata_per_byte: Gas,

    // ── Storage (dominant cost — every full node stores it forever) ──────────
    /// First touch of a storage slot in a tx: trie/disk lookup (EIP-2929: 2 100).
    pub storage_read_cold: Gas,
    /// Subsequent touches of a slot already loaded: cached (EIP-2929: 100).
    pub storage_read_warm: Gas,
    /// Creating a new storage slot (trie node allocation; EIP-2929 SSTORE create).
    pub storage_write_create: Gas,
    /// Updating an existing slot (EIP-2929 SSTORE update).
    pub storage_write_update: Gas,
    /// Clearing a storage slot (delete).
    pub storage_delete: Gas,
    /// Refund earned on storage deletion (EIP-3529 reduced refund).
    pub storage_delete_refund: Gas,

    // ── Contract calls ────────────────────────────────────────────────────────
    /// Base cost for a cross-contract call (EIP-2929: 2 100 cold call base).
    ///
    /// Applies to all 3 cross-contract host functions:
    /// `call_contract` (host fn index 14), `static_call` (15), `delegate_call` (16).
    /// Charged BEFORE execution per AGENTS §7.5. See 08-EXECUTION_SPEC §3.2.
    pub call_base: Gas,
    /// Additional surcharge when the call transfers value > 0 (EVM: 9 000).
    pub call_value_transfer: Gas,

    // ── Hashing (per-byte pricing, bandwidth + CPU) ───────────────────────────
    /// Blake3 hash: base cost.
    pub hash_blake3_base: Gas,
    /// Blake3 hash: per-byte cost.
    pub hash_blake3_per_byte: Gas,
    /// Keccak-256 hash: base cost (EVM: SHA3 base = 30).
    pub hash_keccak256_base: Gas,
    /// Keccak-256 hash: per-byte cost (EVM: SHA3 data = 6 gas/byte approx).
    pub hash_keccak256_per_byte: Gas,

    // ── Cryptographic verification (per-op, expensive) ────────────────────────
    /// Ed25519 signature verification (EVM ecrecover analogue ≈ 3 000).
    pub verify_ed25519: Gas,
    /// ML-DSA-65 (post-quantum) verification — ~10× heavier than Ed25519.
    pub verify_mldsa65: Gas,

    // ── Events / logs (bandwidth + indexer cost) ──────────────────────────────
    /// Base cost per emitted event (EVM: LOG0 = 375).
    pub emit_event_base: Gas,
    /// Per-byte cost of event data (EVM: LOG data = 8 gas/byte).
    pub emit_event_per_byte: Gas,

    // ── Contract deployment ───────────────────────────────────────────────────
    /// Base cost to deploy a contract (EVM: CREATE = 32 000).
    pub deploy_base: Gas,
    /// Phase-2 placeholder — superseded by `deploy_storage_per_byte` for the
    /// storage-cost component and `code_cold_surcharge` for the AOT-compile
    /// component (DB-A22). Retained for backward compatibility until callers
    /// are migrated in subtask_05.
    pub deploy_per_byte: Gas,
    /// Per-byte gas for storing bytecode in CF_CODE on ContractDeploy.
    ///
    /// Charged only when the `code_hash` is NEW (first deployer pays storage);
    /// later deployers of identical bytecode pay only `deploy_base` (the account
    /// pointer write). Supersedes the Phase-2 `deploy_per_byte` semantic for the
    /// storage-cost component. See DB-A22/DB-A23 and 08-EXECUTION_SPEC §3.4(b/c).
    pub deploy_storage_per_byte: Gas,
    /// Flat gas surcharge charged on the FIRST call to a contract
    /// (code-cold = not yet in the wasmtime engine's compiled-module cache).
    ///
    /// Covers the one-time AOT compilation cost. Subsequent calls to the same
    /// contract in the same block are code-warm and pay only execution fuel.
    /// Flat per module — NOT per-instruction instrumentation
    /// (see DB-A22 and 08-EXECUTION_SPEC §3.4(c)).
    pub code_cold_surcharge: Gas,

    // ── Memory ────────────────────────────────────────────────────────────────
    /// Cost per 64 KiB WASM linear-memory page grown (super-linear to bound blowup).
    pub memory_grow_per_page: Gas,

    // ── Context queries ───────────────────────────────────────────────────────
    /// Base gas for a context-query host function call (block_height, block_timestamp,
    /// gas_remaining, msg_value). Covers the host↔guest boundary overhead.
    /// No free host functions (spec §3.1 rule 2 — else DoS vector).
    pub context_query: Gas,

    // ── Memory marshalling ────────────────────────────────────────────────────
    /// Per-byte gas for host↔guest memory copies (read_bytes / write_bytes in linker).
    /// Covers: calldata, register reads, storage key/value marshalling, event data, value_return.
    /// DoS protection: bounds the cost of moving N bytes across the WASM boundary.
    pub memory_copy_per_byte: Gas,

    // ── Safety invariant checks ───────────────────────────────────────────────
    /// Flat cost for the post-execution safety-invariant check (DB-A51).
    ///
    /// Charged once per `ContractCall` that targets a contract with a non-empty
    /// safety manifest. Covers the state-diff scan against the manifest.
    /// Devnet placeholder — benchmark-tune before mainnet.
    pub invariant_check: Gas,

    // ── Warden policy enforcement (P3·Step 13) ───────────────────────────────
    /// Flat cost for the Warden pre-application policy check on session-key
    /// transactions (14-AGENT_LAYER §3).
    ///
    /// Charged once per agent transaction, BEFORE `warden_check` runs
    /// (charge-before-execute, AGENTS §7.5). Covers the full Warden pipeline:
    /// - Steps 13–16: policy state read, all checks, counter write, A2A registry read.
    /// - Step 17: `build_mandate_receipt_log` (1 policy re-read, 1 blake3, 2 serde_json
    ///   serializes). This post-check work is absorbed into the same 7_500 envelope.
    ///
    /// **Devnet placeholder — benchmark-tune before mainnet.** The 7_500 figure covers
    /// the observed work in testing but has not been formally profiled. Steps 13–17
    /// are the current maximum scope; the value must be revisited when A2A reputation
    /// lookup (Phase 4) or Veil shielded receipts (§10) are added.
    pub warden_check: Gas,
}

impl GasSchedule {
    /// Phase-2 devnet placeholder schedule.
    ///
    /// Values grounded in EIP-2929/EIP-150 ratios — NOT final.
    /// Final values require post-testnet benchmarking (spec §3.2).
    pub fn devnet() -> Self {
        Self {
            // Tx intrinsic
            tx_base: Gas(21_000),          // EIP-2930: 21 K tx floor
            tx_calldata_per_byte: Gas(16), // EIP-2028: 16 gas/non-zero byte

            // Storage
            storage_read_cold: Gas(2_100), // EIP-2929: COLD_SLOAD_COST
            storage_read_warm: Gas(100),   // EIP-2929: WARM_STORAGE_READ_COST
            storage_write_create: Gas(22_100), // EIP-2929: SSTORE create (20K + cold)
            storage_write_update: Gas(5_000), // EIP-2929: SSTORE update
            storage_delete: Gas(5_000),    // SSTORE clear (same as update)
            storage_delete_refund: Gas(4_800), // EIP-3529: reduced refund (< 5K)

            // Calls
            call_base: Gas(2_100),           // EIP-2929: cold call base
            call_value_transfer: Gas(9_000), // EVM: value-transfer surcharge

            // Hashing
            hash_blake3_base: Gas(30),
            hash_blake3_per_byte: Gas(6),
            hash_keccak256_base: Gas(30),    // EVM: SHA3 base = 30
            hash_keccak256_per_byte: Gas(6), // EVM: SHA3 ÷ 32-byte word ≈ 6/byte

            // Crypto
            verify_ed25519: Gas(3_000),  // EVM: ecrecover ≈ 3 000
            verify_mldsa65: Gas(30_000), // post-quantum: ~10× ed25519

            // Events
            emit_event_base: Gas(375),   // EVM: LOG0 = 375
            emit_event_per_byte: Gas(8), // EVM: LOG data = 8/byte

            // Deploy
            deploy_base: Gas(32_000),  // EVM: CREATE = 32 000
            deploy_per_byte: Gas(200), // Phase-2 placeholder (see field doc)
            // Per-byte storage cost for new bytecode in CF_CODE (DB-A22/DB-A23).
            // Same value as Phase-2 placeholder for now; benchmarked post-testnet.
            deploy_storage_per_byte: Gas(200),
            // Flat AOT-compile surcharge on first call to a cold module (DB-A22).
            // Placeholder — final value requires post-validator-hardware benchmarking.
            code_cold_surcharge: Gas(100_000),

            // Memory
            memory_grow_per_page: Gas(3), // per 64 KiB page

            // Context queries
            // EVM COINBASE/NUMBER context opcode ≈ 2–5 gas; 3 is conservative.
            context_query: Gas(3),

            // Memory marshalling
            // Per-byte cost for host↔guest memory copies; similar to EVM CALLDATACOPY ≈ 3/word.
            memory_copy_per_byte: Gas(3),

            // Safety invariant checks
            // Flat cost for post-execution honeypot invariant scan (DB-A51).
            // Cheap — small state-diff scan, not execution. Benchmark-tune before mainnet.
            invariant_check: Gas(5_000),

            // Warden policy enforcement (P3·Step 13)
            // Covers: 1 state read (policy), validation logic, 1 state write (counters).
            // Similar to storage_read_cold + storage_write_update ≈ 7 100.
            // Rounded to 7 500 for buffer. Benchmark-tune before mainnet.
            warden_check: Gas(7_500),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
