//! Transpilation warning types.
//!
//! Warnings represent Solidity features that could not be fully mapped to Lem.
//! They are attached to [`crate::TranspileResult`] and never abort transpilation:
//! the unmappable construct is skipped and a comment is emitted in its place.
//!
//! ## Warning codes
//!
//! | Code | Feature | Reason |
//! |------|---------|--------|
//! | W001 | Inline assembly (Yul) | Lem restricts arbitrary EVM opcodes by design; safe intrinsics cover the common cases |
//! | W002 | Function overloading | Lem enforces one-name-one-fn for sound safety analysis; overloads are auto-renamed |
//! | W003 | Unchecked arithmetic block | Lem always uses checked arithmetic (§7.4); `unchecked {}` is treated as normal block |

use solang_parser::pt::Loc;

/// Codes for specific Solidity features that cannot be fully mapped to Lem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WarningCode {
    /// W001 — Inline assembly (Yul) block. Skipped; safe intrinsics can replace common uses.
    InlineAssembly,
    /// W002 — Function overloading. Overloaded functions are auto-renamed (`foo` / `foo_2`).
    FunctionOverloading,
    /// W003 — `unchecked { }` arithmetic block. Treated as a normal block (Lem always checks).
    UncheckedBlock,
}

impl std::fmt::Display for WarningCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WarningCode::InlineAssembly => write!(f, "W001"),
            WarningCode::FunctionOverloading => write!(f, "W002"),
            WarningCode::UncheckedBlock => write!(f, "W003"),
        }
    }
}

/// A single transpilation warning.
#[derive(Debug, Clone)]
pub struct TranspileWarning {
    /// Machine-readable warning code.
    pub code: WarningCode,
    /// Human-readable description of what was skipped or transformed.
    pub message: String,
    /// Byte offset in the original Solidity source (from solang-parser [`Loc`]).
    pub offset: usize,
}

// These constructors are called by mapper.rs and codegen.rs (Batches 2-4).
// They are intentionally forward-declared here so the warning API is complete
// before the mapper is written. Suppress dead-code lint until Batch 2 lands.
#[allow(dead_code)]
impl TranspileWarning {
    /// Create a W001 warning for an inline assembly block.
    pub(crate) fn inline_assembly(loc: &Loc) -> Self {
        Self {
            code: WarningCode::InlineAssembly,
            message: "inline assembly (Yul) is not supported in Lem — block skipped. \
                      Use safe intrinsics for equivalent operations."
                .to_owned(),
            offset: loc_start(loc),
        }
    }

    /// Create a W002 warning for an overloaded function.
    ///
    /// `original_name` is the Solidity name; `renamed_to` is the Lem name chosen.
    pub(crate) fn function_overloading(loc: &Loc, original_name: &str, renamed_to: &str) -> Self {
        Self {
            code: WarningCode::FunctionOverloading,
            message: format!(
                "function `{original_name}` is overloaded — Lem does not support overloading \
                 (one name = one fn for sound safety analysis). Renamed to `{renamed_to}`."
            ),
            offset: loc_start(loc),
        }
    }

    /// Create a W003 warning for an `unchecked` block.
    pub(crate) fn unchecked_block(loc: &Loc) -> Self {
        Self {
            code: WarningCode::UncheckedBlock,
            message: "unchecked arithmetic block treated as normal block — \
                      Lem always uses checked arithmetic (AGENTS §7.4)."
                .to_owned(),
            offset: loc_start(loc),
        }
    }
}

impl std::fmt::Display for TranspileWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} at offset {}: {}",
            self.code, self.offset, self.message
        )
    }
}

/// Collects warnings during a single transpilation pass.
///
/// Passed by mutable reference through mapper → codegen; drained at the end
/// into [`crate::TranspileResult::warnings`].
// Used by mapper.rs and codegen.rs (Batches 2-4). Forward-declared here.
#[allow(dead_code)]
#[derive(Debug, Default)]
pub(crate) struct WarningCollector {
    warnings: Vec<TranspileWarning>,
}

#[allow(dead_code)]
impl WarningCollector {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, w: TranspileWarning) {
        self.warnings.push(w);
    }

    /// Consume the collector, returning all accumulated warnings.
    pub(crate) fn finish(self) -> Vec<TranspileWarning> {
        self.warnings
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

// Called by the `#[allow(dead_code)]` constructors above; suppress lint here too.
#[allow(dead_code)]
fn loc_start(loc: &Loc) -> usize {
    match loc {
        Loc::File(_, start, _) => *start,
        _ => 0,
    }
}

#[cfg(test)]
mod tests;
