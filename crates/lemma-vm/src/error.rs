//! # VmError — all LemmaVM failure paths
//!
//! Every failure mode the VM can produce is represented here.
//! Callers match on variants to decide whether to charge full gas (OOG, trap)
//! or return a structured error receipt (invalid module, reentrancy, etc.).
//!
//! ## Settlement contract (Sui-stall lesson)
//!
//! No variant here should ever cause a node halt. Every failure produces a
//! failed [`TransactionReceipt`] — never a panic (08-EXECUTION_SPEC §5,
//! AGENTS.md §9.3 "no panics in the settlement path").

use lemma_core::{address::Address, amount::Amount};

/// All failure modes of the LemmaVM execution engine.
///
/// `#[non_exhaustive]` — future spec revisions may add new failure modes
/// without breaking existing match arms in downstream crates.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    /// WASM module failed to compile (invalid bytecode, unsupported feature).
    ///
    /// The module bytes are rejected before any execution begins.
    /// Charge the full gas limit to the sender (failed validation = wasted work).
    #[error("WASM compilation failed: {reason}")]
    CompilationFailed { reason: String },

    /// WASM module compiled but failed to instantiate (missing imports, start trap).
    ///
    /// Charge the full gas limit — instantiation is part of execution cost.
    #[error("WASM instantiation failed: {reason}")]
    InstantiationFailed { reason: String },

    /// The transaction exhausted its gas budget (wasmtime `Trap::OutOfFuel`).
    ///
    /// Charge the full gas limit. State changes are reverted.
    #[error("transaction ran out of gas")]
    OutOfGas,

    /// The WASM native stack was exhausted (`Config::max_wasm_stack` exceeded).
    ///
    /// Corresponds to `Trap::StackOverflow`. Charge the full gas limit.
    #[error("WASM stack overflow")]
    StackOverflow,

    /// Cross-contract call depth exceeded `MAX_CALL_DEPTH` (08-EXECUTION_SPEC §2.3).
    ///
    /// The VM-level depth cap trips before any native-stack overflow on all
    /// target platforms (verified by determinism tests in §6).
    #[error("call depth limit exceeded")]
    CallDepthExceeded,

    /// Reentrancy detected: a contract attempted to re-enter itself while a
    /// live frame is already on the call stack (08-EXECUTION_SPEC §2.3).
    ///
    /// This is a VM-level, always-on guard — no contract can opt out.
    /// Charge the full gas limit. State changes are reverted.
    #[error("reentrancy into contract {addr}")]
    Reentrancy {
        /// The address of the contract that was re-entered.
        addr: Address,
    },

    /// The WASM module is structurally invalid (bad magic, unsupported section).
    ///
    /// Distinct from `CompilationFailed` — this is a pre-compilation structural
    /// check (e.g. module exceeds size limits, uses a banned proposal).
    #[error("invalid WASM module: {reason}")]
    InvalidModule { reason: String },

    /// The `ContractDeploy` bytecode exceeds `MAX_CONTRACT_WASM_SIZE`.
    ///
    /// Rejected **before** gas is charged and **before** AOT compilation is
    /// attempted — a validator must never let an oversized module occupy its
    /// compiler and stall block production (DoS gate, 08-EXECUTION_SPEC §3.4(a),
    /// DB-A21).
    ///
    /// The caller should return a failed [`TransactionReceipt`] with zero gas
    /// charged (the node did no meaningful work beyond the size check).
    #[error("contract bytecode {size} bytes exceeds maximum allowed size {limit} bytes")]
    ContractTooLarge {
        /// Actual bytecode length in bytes.
        size: usize,
        /// The limit that was exceeded (`lemma_core::MAX_CONTRACT_WASM_SIZE`).
        limit: usize,
    },

    /// A post-execution state diff violated a safety constraint embedded in the
    /// contract's `"lemma.meta"` safety manifest (DB-A51 runtime honeypot invariant).
    ///
    /// The transaction is reverted — scratch writes are discarded. This is the
    /// runtime pair of compile-time SAFETY-001/002/005/009: the compiler rejects
    /// code that *has* a honeypot lever; the runtime invariant rejects *pressing*
    /// the lever into a honeypot state.
    #[error("honeypot invariant violation: {reason}")]
    HoneypotInvariantViolation { reason: String },

    /// A WASM trap occurred that does not map to a specific known variant.
    ///
    /// `Trap` is `#[non_exhaustive]` in wasmtime — new trap variants may appear
    /// in minor releases. This catch-all preserves the trap message for receipts.
    #[error("WASM trap: {message}")]
    TrapUnknown { message: String },

    /// The sender has insufficient funds to cover the value transfer.
    ///
    /// Charge the base gas cost (validation work was done). State unchanged.
    #[error("insufficient funds: required {required}, available {available}")]
    InsufficientFunds {
        /// The amount required for the transfer.
        required: Amount,
        /// The amount actually available in the sender's account.
        available: Amount,
    },

    /// A Warden policy check failed — the agent transaction violates its
    /// on-chain policy (14-AGENT_LAYER §3, P3·Step 13).
    ///
    /// The transaction is reverted — scratch writes are discarded, nonce is
    /// advanced, gas is charged. The `violation` field carries the specific
    /// reason (from [`lemma_core::PolicyViolation`]).
    #[error("agent policy violation: {violation}")]
    PolicyViolation { violation: String },

    /// A parameter passed to a host function or the executor is invalid.
    ///
    /// Examples: zero gas limit, entry-point name too long, calldata exceeds limit.
    #[error("invalid parameter: {reason}")]
    InvalidParameter { reason: String },

    /// The wasmtime `Engine` could not be created with the deterministic config.
    ///
    /// This is a node-startup failure — the node cannot execute contracts until
    /// the engine is healthy. Returned only by [`crate::runtime::LemmaEngine::new`].
    #[error("VM engine setup failed: {reason}")]
    EngineSetupFailed { reason: String },
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
