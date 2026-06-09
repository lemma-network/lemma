//! Fuzz target for the Lem well-formedness pass (WF-001…015).
//!
//! # Purpose
//!
//! Ensures the wellformed pass NEVER PANICS on arbitrary input, regardless of
//! what the tokenizer and parser produce.  Per AGENTS §7.6 (fuzz testing for
//! security-critical code), the lexer, parser, and compiler must not panic on
//! any input.
//!
//! # Strategy
//!
//! Fuzz at the **tokenize → parse → check pipeline level**.  If the input is
//! valid enough to survive tokenize + parse + type-check, `wellformed::check`
//! will run on it.  If tokenize/parse/type-check returns `Err(_)`, that is
//! fine — only panics are failures.
//!
//! This is the correct approach because:
//! 1. `TypedAst` has no `Arbitrary` impl (complex internal structure).
//! 2. The real attack surface is the full pipeline — a panic anywhere in
//!    tokenize/parse/check is a bug.
//! 3. The fuzzer will naturally discover inputs that reach the wellformed pass
//!    by finding inputs that survive the earlier stages.
//!
//! # Running
//!
//! ```bash
//! # Build only (no run) — confirms no compile errors:
//! cd lemma/crates/lemma-lang && cargo fuzz build fuzz_wellformed
//!
//! # Run with a time limit (always use a timeout — never run unbounded):
//! cd lemma/crates/lemma-lang && timeout 60 cargo fuzz run fuzz_wellformed -- -max_total_time=55
//! ```
//!
//! # Crash handling
//!
//! If the fuzzer finds a crash, it writes the input to
//! `fuzz/artifacts/fuzz_wellformed/crash-*`.  Report the crash input to the
//! team — do NOT auto-fix without understanding the root cause.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only process valid UTF-8 — the Lem lexer operates on `&str`.
    // Non-UTF-8 bytes are silently skipped (not a panic, not a bug).
    let Ok(src) = std::str::from_utf8(data) else {
        return;
    };

    // Stage 1: tokenize.
    // A tokenize error is fine — the fuzzer will find inputs that pass.
    let Ok(tokens) = lemma_lang::tokenize(src) else {
        return;
    };

    // Stage 2: parse.
    // A parse error is fine.
    let Ok(ast) = lemma_lang::parse(tokens) else {
        return;
    };

    // Stage 3: type-check (which internally runs wellformed::check).
    // An Err(_) is fine — only a panic is a failure.
    // The `let _ =` suppresses the unused-result lint without swallowing panics.
    let _ = lemma_lang::check(ast);
});
