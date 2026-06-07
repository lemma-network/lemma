//! # lemma-lang
//!
//! The Lem language compiler pipeline: lexer, parser, type checker,
//! safety analyzer (12 rules), and WASM codegen.
//!
//! ## Current status
//!
//! - **P3·Step 1 (Lexer)** ✅ — `tokenize()` is the public entry point.
//! - **P3·Step 2 (Parser)** ✅ — `parse()` produces the full AST.
//! - **P3·Step 3 (Type checker)** 🔨 — `check()` in progress (3a: foundation).
//! - Safety analyzer, codegen: Steps 4+.
//!
//! ## Usage
//!
//! ```ignore
//! use lemma_lang::{tokenize, parse, check};
//! use lemma_lang::lexer::token::Token;
//!
//! let tokens = tokenize("contract Foo {}")?;
//! assert!(tokens.iter().any(|(t, _)| matches!(t, Token::Contract)));
//!
//! let ast = parse(tokens)?;
//! let typed = check(ast)?;
//! assert_eq!(typed.ast.items.len(), 1);
//! ```

pub mod error;
pub mod lexer;
pub mod parser;
pub mod type_checker;

// Re-export the primary entry points at the crate root for ergonomics.
pub use lexer::tokenize;
pub use parser::parse;
pub use type_checker::check;
