use super::*;

#[test]
fn max_contract_wasm_size_is_two_mib() {
    // 2 MiB = 2 * 1024 * 1024 — verify the constant matches the spec value
    // exactly (08-EXECUTION_SPEC §3.4(a), DB-A21).
    assert_eq!(MAX_CONTRACT_WASM_SIZE, 2_097_152);
}

#[test]
fn max_contract_wasm_size_equals_two_times_1024_squared() {
    // Verify the derivation is correct: 2 * 1024 * 1024 = 2_097_152.
    // This guards against accidental off-by-one if the constant expression
    // is ever edited.
    assert_eq!(MAX_CONTRACT_WASM_SIZE, 2 * 1024 * 1024);
}
