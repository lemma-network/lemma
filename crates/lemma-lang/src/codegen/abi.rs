//! ABI emission stub.
//!
//! ABI emission stub — full implementation in P3·Step 6i.
//!
//! In P3·Step 6i this module will emit the contract ABI descriptor
//! (function signatures, parameter types, return types) as a serialized
//! byte payload, embedded in the WASM binary as a `"lemma.abi"` custom
//! section (wasm-encoder `CustomSection`).
//!
//! The ABI byte contract (calldata/return marshalling via ptr/len in linear
//! memory) is defined in P3·Step 6b and documented in 08-EXECUTION_SPEC.

use crate::type_checker::typed_contract::TypedContract;

/// Build the ABI descriptor for a contract.
///
/// Returns the serialized ABI as raw bytes, suitable for embedding in a
/// `"lemma.abi"` WASM custom section.
///
/// # Phase note
///
/// Stub in P3·Step 6a — returns an empty `Vec<u8>`. Full implementation
/// (function signatures, parameter/return type encoding) lands in P3·Step 6i.
// consumer: codegen/wasm.rs ABI custom-section embed (P3·Step 6i)
#[allow(dead_code)]
pub(crate) fn build_abi(_contract: &TypedContract<'_>) -> Vec<u8> {
    vec![]
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
