//! Thin wrapper around `solang-parser` (0.3.5).
//!
//! This is the ONLY module that imports `solang_parser` directly.
//! All other modules receive `solang_parser::pt` types from here, keeping
//! the external crate boundary minimal and replaceable.

use solang_parser::{diagnostics::Diagnostic, pt};

use crate::TranspileError;

/// Parse a Solidity source string into a [`pt::SourceUnit`].
///
/// Uses `solang_parser::parse` (file id = 0).
///
/// `solang_parser::parse` returns:
/// - `Ok((SourceUnit, Vec<Comment>))` — successful parse; comments are discarded here.
/// - `Err(Vec<Diagnostic>)` — hard parse failure; we convert the first diagnostic to
///   [`TranspileError::ParseError`].
///
/// # Errors
///
/// Returns [`TranspileError::ParseError`] if the parser reports a hard failure.
pub(crate) fn parse_solidity(source: &str) -> Result<pt::SourceUnit, TranspileError> {
    // The Ok branch carries Vec<Comment> (not diagnostics); hard errors are Err(Vec<Diagnostic>).
    let (source_unit, _comments) =
        solang_parser::parse(source, 0).map_err(|diags| first_parse_error(&diags))?;

    Ok(source_unit)
}

/// Extract the name of the first `contract` (not `interface` or `library`)
/// found in the parse tree.
///
/// Returns `None` if no contract definition exists.
pub(crate) fn extract_primary_contract_name(unit: &pt::SourceUnit) -> Option<String> {
    unit.0.iter().find_map(|part| match part {
        pt::SourceUnitPart::ContractDefinition(def)
            if matches!(def.ty, pt::ContractTy::Contract(_)) =>
        {
            def.name.as_ref().map(|id| id.name.clone())
        }
        _ => None,
    })
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn first_parse_error(diags: &[Diagnostic]) -> TranspileError {
    diags
        .first()
        .map(diagnostic_to_error)
        .unwrap_or_else(|| TranspileError::ParseError {
            file: "<input>".to_owned(),
            offset: 0,
            message: "unknown parse error".to_owned(),
        })
}

fn diagnostic_to_error(d: &Diagnostic) -> TranspileError {
    // pt::Loc::File(_, start, _) carries a byte offset, not a line number.
    let offset = match d.loc {
        pt::Loc::File(_, start, _) => start,
        _ => 0,
    };
    TranspileError::ParseError {
        file: "<input>".to_owned(),
        offset,
        message: d.message.clone(),
    }
}

#[cfg(test)]
mod tests;
