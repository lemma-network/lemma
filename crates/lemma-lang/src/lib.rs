// `LangError` is the intentional top-level pipeline error type for this crate.
// It wraps large variants (TypeError, SafetyError, WellFormed) by design — the
// compiler pipeline is not a hot path and the ergonomics of a flat enum outweigh
// the stack-size concern.  Boxing every variant would change the public API and
// add allocations on every error path.  Suppressed crate-wide because the lint
// fires on every function returning `Result<_, LangError>` across the codebase.
#![allow(clippy::result_large_err)]

//! # lemma-lang
//!
//! The Lem language compiler pipeline: lexer, parser, type checker,
//! safety analyzer (SAFETY-001…025), and WASM codegen.
//!
//! ## Current status
//!
//! - **P3·Step 1 (Lexer)** ✅ — `tokenize()` is the public entry point.
//! - **P3·Step 2 (Parser)** ✅ — `parse()` produces the full AST.
//! - **P3·Step 3 (Type checker)** ✅ — `check()` complete (3a–3h).
//! - **P3·Step 4 (Safety analyzer)** ✅ — SAFETY-001…025 complete. Wired into `check()`.
//! - **P3·Step 5 (State-access analyzer)** ✅ — `analyze_state_access()` extracts per-function
//!   read/write [`AccessKey`] sets (Field/SenderSlot/ParamSlot/DynamicSlot), Express eligibility,
//!   and a placeholder gas estimate for Flux/Express. Producer-only (hint, not a pipeline gate).
//! - **P3·Step 6 (Codegen)** ✅ — `compile()` produces a valid WASM binary. The full pipeline
//!   is now wired: tokenize → parse → check → compile → `Vec<u8>`. ABI + metadata custom
//!   sections embedded (B5-3 part-a). See docs/04-BUILD_GUIDE.md for sub-steps 6a–6j.
//! - **P3·Step 7–8**: VM end-to-end, std library. See docs/04-BUILD_GUIDE.md.
//!
//! ## Usage
//!
//! ```ignore
//! use lemma_lang::{tokenize, parse, check, compile};
//!
//! let tokens = tokenize("contract Foo {}")?;
//! let ast = parse(tokens)?;
//! let typed = check(ast)?;
//! for contract in typed.contracts() {
//!     let wasm_bytes: Vec<u8> = compile(&contract)?;
//!     // deploy wasm_bytes to LemmaVM
//! }
//! ```

pub mod analyzer;
pub mod codegen;
pub mod error;
pub mod lexer;
pub mod parser;
pub mod type_checker;
pub(crate) mod visit;

// Re-export the primary entry points at the crate root for ergonomics.
// Full pipeline: tokenize → parse → check → compile
pub use analyzer::{analyze_safety, analyze_state_access, AccessKey, StateAccessInfo};
pub use codegen::compile;
pub use lexer::tokenize;
pub use parser::parse;
pub use type_checker::check;
