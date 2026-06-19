//! # Protocol limits
//!
//! Hard-coded upper bounds that guard the chain against DoS via resource
//! exhaustion. These constants are the **single source of truth** — every
//! crate that needs a limit imports from here; no magic numbers elsewhere.
//!
//! Limits are governance-adjustable via LIP (Lemma Improvement Proposal).
//! Until a LIP changes them, the values here are canonical.
//!
//! See `docs/08-EXECUTION_SPEC.md §3.4(a)` and `docs/04-BUILD_GUIDE.md §3.1`.

// ─── WASM contract limits ─────────────────────────────────────────────────────

/// Hard size limit for deployed WASM bytecode (in bytes).
///
/// A `ContractDeploy` transaction whose `tx.data.len()` exceeds this value is
/// rejected **before** gas is charged and **before** AOT compilation is
/// attempted. This prevents DoS via super-linear AOT compile time: a validator
/// must never let an oversized module occupy its compiler and stall block
/// production.
///
/// # Value
///
/// `2 MiB` (2 × 1024 × 1024 = 2 097 152 bytes). This is an interim value —
/// well above CosmWasm's ~800 KiB norm and below Near's 4 MiB ceiling. The
/// final value will be calibrated by a validator-hardware AOT benchmark
/// targeting worst-case compile time ≤ `block_time / 4` (whitepaper §4.3).
///
/// # Governance
///
/// Adjustable via LIP without a hard fork (stored in genesis config for future
/// on-chain governance). Until then, this constant is the authoritative limit.
///
/// See DB-A21 and `docs/08-EXECUTION_SPEC.md §3.4(a)`.
pub const MAX_CONTRACT_WASM_SIZE: usize = 2 * 1024 * 1024; // 2 MiB = 2_097_152

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
