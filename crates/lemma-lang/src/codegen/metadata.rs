//! Metadata / custom-section stub.
//!
//! Metadata/custom-section stub — full implementation in P3·Step 6i.
//!
//! In P3·Step 6i this module will build the `"lemma.meta"` WASM custom
//! section payload, which embeds:
//! - Contract name and version
//! - State-access hints from P3·Step 5 `StateAccessInfo` (B5-3 part-a)
//!   for Express eligibility and Flux parallel-execution scheduling
//! - Compiler version and build metadata
//!
//! The custom section is appended last in the WASM binary (after Code/Data),
//! per the canonical section order (wasm spec §5.5.2). It is ignored by WASM
//! validation/execution but readable by the VM host and tooling.

/// Build the metadata custom-section payload.
///
/// Returns the serialized metadata as raw bytes, suitable for embedding in a
/// `"lemma.meta"` WASM custom section.
///
/// # Phase note
///
/// Stub in P3·Step 6a — returns an empty `Vec<u8>`. Full implementation
/// (state-access hints, compiler version, contract metadata) lands in
/// P3·Step 6i.
// consumer: codegen/wasm.rs metadata custom-section embed (P3·Step 6i)
#[allow(dead_code)]
pub(crate) fn build_metadata() -> Vec<u8> {
    vec![]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
