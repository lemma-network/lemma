//! `lemma compile` — Lem contract compiler dispatch (P3·Step 10).
//!
//! ## Pipeline
//!
//! ```text
//! source (.lem)
//!   → tokenize   (lexer)
//!   → parse      (AST)
//!   → check      (type inference + WF-001…015 + SAFETY-001…025)
//!   → compile    (WASM codegen, embeds "lemma.abi" + "lemma.meta" custom sections)
//! ```
//!
//! Per contract in the source file, three output files are written:
//!
//! | File             | Contents |
//! |------------------|----------|
//! | `{name}.wasm`    | Compiled WASM binary — deploy this to LemmaVM |
//! | `{name}.abi.json`  | JSON array of public function descriptors (ABI) |
//! | `{name}.meta.json` | JSON contract metadata: name, compiler version, safety
//! |                  | ruleset, per-function state-access hints, runtime constraints |
//!
//! ## Custom section extraction
//!
//! The two JSON files are embedded by the compiler as WASM custom sections
//! (`"lemma.abi"`, `"lemma.meta"`). `extract_custom_section` reads them back
//! from the emitted WASM bytes using `wasmparser` (pinned `=0.251.0`, workspace
//! dep — same technique as `lemma-vm/parallel/hints.rs`).

use std::path::{Path, PathBuf};

use wasmparser::{Parser, Payload};

use lemma_lang::type_checker::typed_contract::TypedContract;
use lemma_lang::type_checker::TypedAst;

use crate::error::LemmaCliError;

// ── Public types ──────────────────────────────────────────────────────────────

/// Output artifact paths produced for a single compiled contract.
#[derive(Debug)]
pub struct CompileOutput {
    /// Compiled WASM binary — deploy this to LemmaVM.
    pub wasm: PathBuf,
    /// ABI descriptor JSON — function selectors and types for SDK callers.
    pub abi_json: PathBuf,
    /// Contract metadata JSON — compiler version, safety ruleset version,
    /// per-function state-access hints, and runtime safety constraints.
    pub meta_json: PathBuf,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Compile a `.lem` source file and write output artifacts to `output_dir`.
///
/// Runs the full Lem compiler pipeline for every contract in `source_path`.
/// Three output files are written per contract (see module docs).
///
/// Returns one [`CompileOutput`] per compiled contract. An empty vec means
/// the source contained no contracts (only struct/enum/library definitions).
///
/// # Errors
///
/// - [`LemmaCliError::CompileIo`]     — source read or artifact write failure.
/// - [`LemmaCliError::CompileFailed`] — any compiler stage returned an error.
pub fn compile_contract(
    source_path: &Path,
    output_dir: &Path,
) -> Result<Vec<CompileOutput>, LemmaCliError> {
    let source = read_source(source_path)?;
    let typed = run_pipeline(&source)?;

    // Create the output directory once before iterating over contracts.
    std::fs::create_dir_all(output_dir).map_err(|e| LemmaCliError::CompileIo {
        path: output_dir.to_owned(),
        source: e,
    })?;

    let contracts = typed.contracts();
    contracts
        .iter()
        .map(|contract| compile_one(contract, output_dir))
        .collect()
}

// ── Internals ─────────────────────────────────────────────────────────────────

/// Read a `.lem` source file into a UTF-8 string.
fn read_source(path: &Path) -> Result<String, LemmaCliError> {
    std::fs::read_to_string(path).map_err(|e| LemmaCliError::CompileIo {
        path: path.to_owned(),
        source: e,
    })
}

/// Tokenize, parse, and type-check `source`, returning a [`TypedAst`].
///
/// `lemma_lang::check` runs the complete pipeline:
///   name resolution → type inference → WF-001…015 → SAFETY-001…025.
/// Any violation returns early as `LemmaCliError::CompileFailed`.
fn run_pipeline(source: &str) -> Result<TypedAst, LemmaCliError> {
    let tokens = lemma_lang::tokenize(source)?;
    let ast = lemma_lang::parse(tokens)?;
    Ok(lemma_lang::check(ast)?)
}

/// Codegen one contract and write its three output artifacts.
fn compile_one(
    contract: &TypedContract<'_>,
    output_dir: &Path,
) -> Result<CompileOutput, LemmaCliError> {
    // Emit WASM — includes "lemma.abi" and "lemma.meta" as custom sections.
    let wasm = lemma_lang::compile(contract)?;
    let name = contract.name().to_owned();

    // Extract JSON payloads from the embedded WASM custom sections.
    // Fall back to empty JSON if a section is absent — both sections are always
    // emitted by the compiler, so absence would indicate a format change.
    let abi_bytes = extract_custom_section(&wasm, "lemma.abi").unwrap_or_else(|| b"[]".to_vec());
    let meta_bytes = extract_custom_section(&wasm, "lemma.meta").unwrap_or_else(|| b"{}".to_vec());

    let wasm_path = output_dir.join(format!("{name}.wasm"));
    let abi_path = output_dir.join(format!("{name}.abi.json"));
    let meta_path = output_dir.join(format!("{name}.meta.json"));

    write_artifact(&wasm_path, &wasm)?;
    write_artifact(&abi_path, &abi_bytes)?;
    write_artifact(&meta_path, &meta_bytes)?;

    Ok(CompileOutput {
        wasm: wasm_path,
        abi_json: abi_path,
        meta_json: meta_path,
    })
}

/// Write raw bytes to `path`, mapping I/O errors to [`LemmaCliError::CompileIo`].
fn write_artifact(path: &Path, contents: &[u8]) -> Result<(), LemmaCliError> {
    std::fs::write(path, contents).map_err(|e| LemmaCliError::CompileIo {
        path: path.to_owned(),
        source: e,
    })
}

/// Extract a WASM custom section's payload bytes by name.
///
/// Uses `wasmparser` (workspace dep, `=0.251.0`) to scan the WASM binary for a
/// custom section matching `section_name`. Returns `None` if absent or malformed.
///
/// Same scanning pattern as `lemma-vm/parallel/hints.rs::find_lemma_meta_section`.
fn extract_custom_section(wasm: &[u8], section_name: &str) -> Option<Vec<u8>> {
    for payload in Parser::new(0).parse_all(wasm) {
        match payload {
            Ok(Payload::CustomSection(reader)) if reader.name() == section_name => {
                return Some(reader.data().to_vec());
            }
            Ok(_) => {}
            Err(_) => return None,
        }
    }
    None
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
