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
//! safety analyzer (SAFETY-001…013), and WASM codegen.
//!
//! ## Current status
//!
//! - **P3·Step 1 (Lexer)** ✅ — `tokenize()` is the public entry point.
//! - **P3·Step 2 (Parser)** ✅ — `parse()` produces the full AST.
//! - **P3·Step 3 (Type checker)** ✅ — `check()` complete (3a–3h).
//! - **P3·Step 4 (Safety analyzer)** 🔨 — `analyze_safety()` in progress (4a stub).
//! - Codegen: Step 6.
//!
//! ## Usage
//!
//! ```ignore
//! use lemma_lang::{tokenize, parse, check, analyze_safety};
//! use lemma_lang::lexer::token::Token;
//!
//! let tokens = tokenize("contract Foo {}")?;
//! let ast = parse(tokens)?;
//! let typed = check(ast)?;
//! for contract in typed.contracts() {
//!     analyze_safety(&contract)?;
//! }
//! ```

pub mod analyzer;
pub mod error;
pub mod lexer;
pub mod parser;
pub mod type_checker;

// Re-export the primary entry points at the crate root for ergonomics.
pub use analyzer::analyze_safety;
pub use lexer::tokenize;
pub use parser::parse;
pub use type_checker::check;
