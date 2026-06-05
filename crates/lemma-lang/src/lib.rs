//! # lemma-lang
//!
//! The Lem language compiler pipeline: lexer, parser, type checker,
//! safety analyzer (12 rules), and WASM codegen.
//!
//! ## Current status
//!
//! - **P3·Step 1 (Lexer)**: complete — `tokenize()` is the public entry point.
//! - **P3·Step 2a (Parser skeleton + AST + type parser)**: complete — `parse()` is the entry point.
//! - Type checker, safety analyzer, codegen: planned for later steps.
//!
//! ## Usage
//!
//! ```ignore
//! use lemma_lang::{tokenize, parse};
//! use lemma_lang::lexer::token::Token;
//!
//! let tokens = tokenize("contract Foo {}")?;
//! assert!(tokens.iter().any(|(t, _)| matches!(t, Token::Contract)));
//!
//! let ast = parse(tokens)?;
//! ```

pub mod error;
pub mod lexer;
pub mod parser;

// Re-export the primary entry points at the crate root for ergonomics.
pub use lexer::tokenize;
pub use parser::parse;
