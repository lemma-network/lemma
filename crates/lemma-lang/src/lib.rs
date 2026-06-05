//! # lemma-lang
//!
//! The Lem language compiler pipeline: lexer, parser, type checker,
//! safety analyzer (12 rules), and WASM codegen.
//!
//! ## Current status
//!
//! - **P3·Step 1 (Lexer)**: complete — `tokenize()` is the public entry point.
//! - Parser, type checker, safety analyzer, codegen: planned for later steps.
//!
//! ## Usage
//!
//! ```ignore
//! use lemma_lang::tokenize;
//! use lemma_lang::lexer::token::Token;
//!
//! let tokens = tokenize("contract Foo {}")?;
//! assert!(tokens.iter().any(|(t, _)| matches!(t, Token::Contract)));
//! ```

pub mod error;
pub mod lexer;

// Re-export the primary entry point at the crate root for ergonomics.
pub use lexer::tokenize;
