use super::*;
use crate::error::VmError;

// ── deterministic_config tests ────────────────────────────────────────────────

#[test]
fn deterministic_config_creates_successfully() {
    // The config must be constructible without panic.
    let _c = deterministic_config();
}

#[test]
fn deterministic_config_has_fuel_enabled() {
    // `consume_fuel` has no config getter, but a Store will reject set_fuel
    // with an error if fuel is NOT enabled. This is the behavioral proof.
    let engine = LemmaEngine::new().unwrap();
    let mut store = wasmtime::Store::new(engine.inner(), ());
    store
        .set_fuel(1_000)
        .expect("set_fuel must succeed when consume_fuel(true) — FAIL means fuel not enabled");
}

#[test]
fn compile_module_rejects_simd_instructions() {
    // Behavioral proof that wasm_simd(false) is in effect.
    // v128 type requires the SIMD proposal — banned in our config.
    let engine = LemmaEngine::new().unwrap();
    let simd_wat = b"(module (func (export \"f\") (result v128) v128.const i32x4 0 0 0 0))";
    match engine.compile_module(simd_wat) {
        Err(VmError::CompilationFailed { .. }) => {} // expected: SIMD rejected
        Ok(_) => panic!(
            "SIMD instructions must be rejected (wasm_simd=false) \
             — FAIL means SIMD is accidentally enabled"
        ),
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn compile_module_rejects_shared_memory() {
    // Behavioral proof that wasm_threads(false) is in effect.
    // Shared memory requires the threads proposal — banned in our config.
    let engine = LemmaEngine::new().unwrap();
    let shared_wat = b"(module (memory (import \"\" \"m\") 1 2 shared))";
    match engine.compile_module(shared_wat) {
        Err(VmError::CompilationFailed { .. }) => {} // expected: threads rejected
        Ok(_) => panic!(
            "Shared memory must be rejected (wasm_threads=false) \
             — FAIL means thread/shared-memory is accidentally enabled"
        ),
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

// ── LemmaEngine tests ─────────────────────────────────────────────────────────

#[test]
fn lemma_engine_creates_successfully() {
    assert!(LemmaEngine::new().is_ok());
}

#[test]
fn lemma_engine_is_cloneable() {
    let e1 = LemmaEngine::new().unwrap();
    // Clone must not panic and the clone must be usable.
    let e2 = e1.clone();
    let _ = e2.inner();
}

#[test]
fn lemma_engine_inner_returns_usable_engine_reference() {
    let engine = LemmaEngine::new().unwrap();
    // inner() must return a valid Engine reference (used for Store::new etc.).
    // Verified by constructing a Store — this will fail if the reference is bad.
    let _store = wasmtime::Store::new(engine.inner(), ());
}

// ── compile_module tests ──────────────────────────────────────────────────────

#[test]
fn compile_module_accepts_empty_wasm() {
    let engine = LemmaEngine::new().unwrap();
    // An empty module is the minimal valid WASM program.
    let result = engine.compile_module(b"(module)");
    assert!(result.is_ok(), "empty WASM module must compile: {result:?}");
}

#[test]
fn compile_module_accepts_module_with_export() {
    let engine = LemmaEngine::new().unwrap();
    let wat = b"(module (func (export \"noop\")))";
    assert!(engine.compile_module(wat).is_ok());
}

#[test]
fn compile_module_accepts_module_with_memory() {
    let engine = LemmaEngine::new().unwrap();
    let wat = b"(module (memory 1) (export \"memory\" (memory 0)))";
    assert!(engine.compile_module(wat).is_ok());
}

#[test]
fn compile_module_accepts_valid_wasm() {
    let engine = LemmaEngine::new().unwrap();
    // A module with a function that returns a constant.
    let wat = b"(module (func (export \"f\") (result i32) i32.const 42))";
    assert!(engine.compile_module(wat).is_ok());
}

#[test]
fn compile_module_rejects_invalid_bytes() {
    let engine = LemmaEngine::new().unwrap();
    let result = engine.compile_module(b"not valid wasm");
    match result {
        Err(VmError::CompilationFailed { .. }) => {} // expected
        other => panic!("expected CompilationFailed, got {other:?}"),
    }
}

#[test]
fn compile_module_rejects_empty_bytes() {
    let engine = LemmaEngine::new().unwrap();
    let result = engine.compile_module(b"");
    assert!(result.is_err(), "empty bytes must fail compilation");
}

#[test]
fn two_engines_with_identical_config_both_compile_same_wat() {
    // Both engines use identical deterministic_config — both must compile the
    // same WAT successfully. Result-equivalence (byte-identical execution output)
    // is deferred to B4 executor integration tests (08-EXECUTION_SPEC §6):
    // intentional deferred debt, not an oversight.
    let e1 = LemmaEngine::new().unwrap();
    let e2 = LemmaEngine::new().unwrap();
    let wat = b"(module (func (export \"f\") (result i32) i32.const 42))";
    assert!(e1.compile_module(wat).is_ok());
    assert!(e2.compile_module(wat).is_ok());
}

// ── Constants tests ───────────────────────────────────────────────────────────

#[test]
fn max_wasm_stack_is_512_kib() {
    // 512 KiB = 524_288 bytes — must match spec (08-EXECUTION_SPEC §2.1).
    assert_eq!(MAX_WASM_STACK, 512 * 1024);
}

#[test]
fn max_call_depth_is_64() {
    assert_eq!(MAX_CALL_DEPTH, 64);
}

#[test]
fn max_call_depth_fits_within_max_wasm_stack() {
    // Backstop invariant: MAX_CALL_DEPTH × conservative_frame_size ≤ MAX_WASM_STACK.
    // 8 KiB/frame is conservative (typical wasmtime frames are ≤ 1–2 KiB).
    // Cross-platform frame-size confirmation deferred to B4 executor tests (§6).
    const CONSERVATIVE_FRAME_BYTES: usize = 8_192; // 8 KiB
    let max_depth_stack = MAX_CALL_DEPTH as usize * CONSERVATIVE_FRAME_BYTES;
    assert!(
        max_depth_stack <= MAX_WASM_STACK,
        "MAX_CALL_DEPTH ({}) × frame_size ({} B) = {} B > MAX_WASM_STACK ({} B): \
         depth cap may not trip before native overflow",
        MAX_CALL_DEPTH,
        CONSERVATIVE_FRAME_BYTES,
        max_depth_stack,
        MAX_WASM_STACK,
    );
}
