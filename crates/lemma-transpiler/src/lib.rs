//! # lemma-transpiler
//!
//! Source-to-source transpiler: Solidity → Lem.
//!
//! Converts Solidity smart contracts (ERC-20 and compatible) into equivalent
//! Lem source code compilable by `lemma compile`.
//!
//! ## Pipeline
//!
//! ```text
//! Solidity text
//!   → sol_parser  (wraps solang-parser 0.3.5)
//!   → mapper      (Solidity AST → Lem IR)    [Batches 2-3]
//!   → codegen     (Lem IR → Lem source text) [Batch 4]
//!   → Lem text + TranspileWarning list
//! ```

pub mod lem_ir;
mod mapper;
mod sol_parser;
pub mod warnings;

pub use warnings::{TranspileWarning, WarningCode};

/// Result of a successful transpilation.
#[derive(Debug, Clone)]
pub struct TranspileResult {
    /// Generated Lem source. Valid input to `lemma compile`.
    pub lem_source: String,
    /// Warnings for Solidity features that could not be fully mapped.
    /// Warnings do not abort transpilation — the problematic node is skipped
    /// and a comment is inserted in its place.
    pub warnings: Vec<TranspileWarning>,
    /// Name of the primary contract found in the Solidity source.
    pub contract_name: String,
}

/// Errors that prevent transpilation from completing.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TranspileError {
    /// The Solidity source could not be parsed.
    #[error("solidity parse error in {file} near byte offset {offset}: {message}")]
    ParseError {
        file: String,
        /// Byte offset in the source string (from `pt::Loc::File(_, start, _)`).
        offset: usize,
        message: String,
    },
    /// No `contract` definition was found in the source.
    #[error("no contract definition found in solidity source")]
    NoContractFound,
}

/// Transpile a Solidity source string into Lem source.
///
/// On success returns a [`TranspileResult`] with the Lem source and any
/// [`TranspileWarning`]s for unmappable features (W001 inline assembly,
/// W002 function overloading). Warnings don't prevent successful transpilation.
///
/// # Errors
///
/// - [`TranspileError::ParseError`] — invalid Solidity syntax.
/// - [`TranspileError::NoContractFound`] — no contract definition in source.
pub fn transpile(sol_source: &str) -> Result<TranspileResult, TranspileError> {
    let source_unit = sol_parser::parse_solidity(sol_source)?;
    let contract_name = sol_parser::extract_primary_contract_name(&source_unit)
        .ok_or(TranspileError::NoContractFound)?;

    // Find the primary contract definition to pass to the mapper.
    let contract_def = source_unit
        .0
        .iter()
        .find_map(|part| {
            if let solang_parser::pt::SourceUnitPart::ContractDefinition(def) = part {
                if def.name.as_ref().map(|n| n.name.as_str()) == Some(contract_name.as_str()) {
                    return Some(def.as_ref());
                }
            }
            None
        })
        .ok_or(TranspileError::NoContractFound)?;

    let mut warnings_col = warnings::WarningCollector::new();
    // Batch 2: map Solidity AST → Lem IR (declarations only; bodies empty).
    let _ir = mapper::map_contract(contract_def, &mut warnings_col);
    let warnings = warnings_col.finish();

    // Codegen (Batch 4) will replace this placeholder with real Lem source.
    let lem_source =
        format!("// Transpiled from Solidity by lemma-transpiler\n// Contract: {contract_name}\n");

    Ok(TranspileResult {
        lem_source,
        warnings,
        contract_name,
    })
}

#[cfg(test)]
mod tests;
