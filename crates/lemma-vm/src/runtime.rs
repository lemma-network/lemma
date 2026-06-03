//! # LemmaVM Runtime — deterministic wasmtime Engine + Config
//!
//! This module provides the shared [`LemmaEngine`] and the
//! [`deterministic_config`] function that every validator MUST use identically.
//!
//! ## Determinism contract (08-EXECUTION_SPEC §2.1)
//!
//! **Allow-list posture** — every WASM proposal is explicitly pinned ON or OFF
//! in [`deterministic_config`]. Do not rely on wasmtime defaults: a minor-version
//! default-flip silently changes consensus behaviour across a mixed validator fleet.
//! Re-audit the full table on every wasmtime upgrade (AGENTS.md §9.3).
//!
//! | Setting | Value | Reason |
//! |---------|-------|--------|
//! | `consume_fuel` | `true` | Gas metering — every instruction decrements fuel |
//! | `cranelift_nan_canonicalization` | `true` | Canonical NaN bits across all CPUs |
//! | `wasm_threads` | **OFF** | Shared-memory nondeterminism |
//! | `wasm_simd` | **OFF** | SIMD results differ across x86_64 / AArch64 |
//! | `wasm_relaxed_simd` | **OFF** | Explicitly nondeterministic by spec |
//! | `wasm_bulk_memory` | **ON** | `memory.copy/fill` — deterministic, needed |
//! | `wasm_multi_value` | **ON** | Multiple return values — deterministic, needed |
//! | `wasm_reference_types` | **OFF** | Externref/funcref GC roots — banned Phase 2 |
//! | `wasm_tail_call` | **OFF** | Tail-call; not needed by Lem contracts |
//! | `wasm_extended_const` | **OFF** | Extended const expressions — not needed |
//! | `wasm_function_references` | **OFF** | Typed func refs (GC precursor) — banned |
//! | `wasm_gc` | **OFF** | GC proposal — banned; Lem is arena-managed |
//! | `wasm_multi_memory` | **OFF** | Multiple memories — not needed |
//! | `wasm_wide_arithmetic` | **OFF** | 128-bit arithmetic proposal — not needed |
//! | `wasm_custom_page_sizes` | **OFF** | Non-standard page sizes — banned |
//! | `wasm_memory64` | **OFF** | 64-bit memory — not needed Phase 2 |
//! | `wasm_exceptions` | **OFF** | Exception-handling proposal — banned |
//! | `wasm_stack_switching` | **OFF** | Async/coroutine proposal — banned |
//! | `wasm_component_model` | **OFF** | Component model — not used |
//! | `max_wasm_stack` | `MAX_WASM_STACK` | Bounded native stack → `StackOverflow` trap |
//!
//! Any divergence in version or config between validators = consensus fork.
//!
//! ## Usage
//!
//! ```no_run
//! use lemma_vm::runtime::LemmaEngine;
//!
//! // Create once at node startup — clone cheaply across transactions.
//! let engine = LemmaEngine::new().expect("engine setup must succeed at startup");
//! let module = engine.compile_module(b"(module)").expect("valid WASM");
//! ```

use std::sync::Arc;

use crate::error::VmError;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum native WASM stack depth in bytes.
///
/// Identical on all validators — any divergence = consensus fork.
/// 512 KiB = 524_288 bytes.
///
/// **Role**: backstop native-stack trap. The primary depth guard is
/// `MAX_CALL_DEPTH` (enforced by `CallContext::enter_call` in B3) — it MUST
/// trip before this native limit on every target platform. The chosen values
/// (64 frames × conservative 8 KiB/frame = 512 KiB = `MAX_WASM_STACK`) provide
/// this margin; the 8 KiB estimate is conservative (wasmtime frames are
/// typically ≤ 1–2 KiB for simple call stacks). Cross-platform frame-size
/// verification is deferred to B4 executor integration tests (08-EXEC §6)
/// — intentional deferred debt, not an oversight.
pub const MAX_WASM_STACK: usize = 524_288; // 512 KiB

/// Maximum cross-contract call nesting depth.
///
/// The VM-level reentrancy lock (08-EXECUTION_SPEC §2.3) provides stronger
/// protection; this cap is the deterministic depth backstop.
///
/// **Safety invariant (backstop)**: `MAX_CALL_DEPTH` is chosen so the VM-level
/// depth trap fires before any native-stack overflow on every target platform.
/// `64 × 8_192 = 524_288 = MAX_WASM_STACK` — using a conservative 8 KiB/frame
/// bound (typical wasmtime frames are ≤ 1–2 KiB). Cross-platform frame-size
/// confirmation is deferred to B4 executor integration tests (08-EXEC §6).
///
/// B3 (host functions) imports this constant to enforce the limit inside
/// `CallContext::enter_call`.
pub const MAX_CALL_DEPTH: u32 = 64;

// ── deterministic_config ──────────────────────────────────────────────────────

/// Build the deterministic wasmtime [`Config`] for LemmaVM (08-EXECUTION_SPEC §2.1).
///
/// Every validator MUST create its [`LemmaEngine`] with this exact config.
/// Any divergence in settings between validators = consensus fork.
///
/// ## Allow-list posture
///
/// **Every** WASM proposal is pinned explicitly — ON or OFF. Never rely on
/// wasmtime defaults: a minor-version default-flip silently changes consensus
/// behaviour across a mixed validator fleet (AGENTS.md §9.3).
/// See the module-level table for the full posture and rationale.
///
/// Re-audit this function and the module table on every wasmtime upgrade.
pub fn deterministic_config() -> wasmtime::Config {
    let mut c = wasmtime::Config::new();

    // ── Gas metering ─────────────────────────────────────────────────────────
    // Instruments every WASM instruction to decrement fuel.
    // Callers MUST call store.set_fuel(budget) before execution.
    // On exhaustion: Trap::OutOfFuel → VmError::OutOfGas.
    c.consume_fuel(true);

    // ── Float determinism ─────────────────────────────────────────────────────
    // Without this, different CPUs produce different NaN payloads for the same
    // float operation → divergent state roots → consensus fork.
    c.cranelift_nan_canonicalization(true);

    // ── Proposals: explicit allow-list (OFF unless needed) ────────────────────

    // BANNED — nondeterministic across platforms:
    c.wasm_threads(false); // shared-memory atomics — nondeterministic
    c.wasm_simd(false); // 128-bit SIMD — results differ x86_64/AArch64
    c.wasm_relaxed_simd(false); // explicitly nondeterministic by spec

    // ENABLED — deterministic and required by Lem compiled output:
    c.wasm_bulk_memory(true); // memory.copy/fill — deterministic, needed
    c.wasm_multi_value(true); // multiple return values — deterministic, needed

    // BANNED — not needed, or GC/async/stack semantics incompatible with Lem:
    c.wasm_reference_types(false); // externref/funcref GC roots — banned Phase 2
    c.wasm_tail_call(false); // tail-call; Lem contracts don't need it
    c.wasm_extended_const(false); // extended const-exprs — not needed
    c.wasm_function_references(false); // typed func refs (GC precursor) — banned
    c.wasm_gc(false); // GC proposal — Lem is arena-managed
    c.wasm_multi_memory(false); // multiple memories — not needed
    c.wasm_wide_arithmetic(false); // 128-bit arithmetic proposal — not needed
    c.wasm_custom_page_sizes(false); // non-standard page sizes — banned
    c.wasm_memory64(false); // 64-bit memory — not needed Phase 2
    c.wasm_exceptions(false); // exception-handling — banned
    c.wasm_stack_switching(false); // async/coroutine proposal — banned
    c.wasm_component_model(false); // component model — not used

    // ── Stack bound ───────────────────────────────────────────────────────────
    // Raises Trap::StackOverflow when the native stack exceeds MAX_WASM_STACK.
    // MAX_CALL_DEPTH (64 frames) is the primary depth guard (B3 CallContext).
    // wasmtime 45.x: max_wasm_stack is infallible (&mut Config builder).
    c.max_wasm_stack(MAX_WASM_STACK);

    c
}

// ── LemmaEngine ───────────────────────────────────────────────────────────────

/// Shared wasmtime Engine — created once at node startup, cloned cheaply
/// across transactions.
///
/// Wraps `Arc<wasmtime::Engine>` so cloning is O(1) (reference count bump).
/// All validators MUST use identical [`deterministic_config`] settings
/// (08-EXECUTION_SPEC §2.1) — any divergence = consensus fork.
///
/// # Usage
///
/// ```no_run
/// use lemma_vm::runtime::LemmaEngine;
///
/// let engine = LemmaEngine::new().expect("engine setup must succeed at startup");
/// // Clone cheaply for each worker thread / transaction executor:
/// let engine2 = engine.clone();
/// ```
#[derive(Clone)]
pub struct LemmaEngine(Arc<wasmtime::Engine>);

impl LemmaEngine {
    /// Create a new [`LemmaEngine`] with the deterministic config.
    ///
    /// Call **once** at node startup. The returned engine is cheaply cloneable
    /// via [`Clone`] — share it across all transaction executors.
    ///
    /// # Errors
    ///
    /// Returns [`VmError::EngineSetupFailed`] if wasmtime's `Engine::new` fails
    /// (extremely unlikely with a statically-correct config, but surfaced as a
    /// `Result` so startup failures are visible rather than silent panics).
    pub fn new() -> Result<Self, VmError> {
        let config = deterministic_config();
        let engine = wasmtime::Engine::new(&config).map_err(|e| VmError::EngineSetupFailed {
            reason: e.to_string(),
        })?;
        Ok(Self(Arc::new(engine)))
    }

    /// Borrow the inner wasmtime [`Engine`] reference.
    ///
    /// Use this to create [`wasmtime::Store`], [`wasmtime::Module`], and
    /// [`wasmtime::Linker`] instances.
    pub fn inner(&self) -> &wasmtime::Engine {
        &self.0
    }

    /// Compile a WASM module from bytes.
    ///
    /// Validates and compiles the module against the deterministic feature set
    /// (no threads, no SIMD). This is the expensive step — **cache the returned
    /// [`wasmtime::Module`] per contract address** to avoid recompilation on
    /// every transaction.
    ///
    /// Accepts both binary WASM (magic bytes `\0asm`) and WAT text format
    /// (bytes starting with `(`). wasmtime auto-detects the format.
    ///
    /// # Errors
    ///
    /// Returns [`VmError::CompilationFailed`] if the bytes are not valid WASM
    /// or WAT, or if the module uses a proposal disabled by [`deterministic_config`]
    /// (e.g. threads, SIMD — wasmtime rejects banned proposals at compile time
    /// for proposals that require explicit config; see behavioral tests).
    pub fn compile_module(&self, wasm_bytes: &[u8]) -> Result<wasmtime::Module, VmError> {
        wasmtime::Module::new(self.inner(), wasm_bytes).map_err(|e| VmError::CompilationFailed {
            reason: e.to_string(),
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
