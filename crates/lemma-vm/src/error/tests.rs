use super::*;

#[test]
fn unsupported_host_abi_displays_versions() {
    // Verify the Display output contains both the deployed and max-supported versions
    // so operators can diagnose rejected deploys from receipts alone (DB-A58 L2).
    let e = VmError::UnsupportedHostAbi {
        deployed_abi: 99,
        max_supported: 1,
    };
    let msg = e.to_string();
    assert!(
        msg.contains("99"),
        "error message must contain the deployed ABI version (99); got: {msg}"
    );
    assert!(
        msg.contains("1"),
        "error message must contain the max supported version (1); got: {msg}"
    );
    assert!(
        msg.contains("unsupported host-ABI"),
        "error message must contain 'unsupported host-ABI'; got: {msg}"
    );
}

#[test]
fn compilation_failed_displays_reason() {
    let e = VmError::CompilationFailed {
        reason: "bad magic".to_string(),
    };
    assert!(e.to_string().contains("bad magic"));
}

#[test]
fn out_of_gas_displays_message() {
    let e = VmError::OutOfGas;
    assert!(e.to_string().contains("gas"));
}

#[test]
fn call_depth_exceeded_displays_message() {
    let e = VmError::CallDepthExceeded;
    assert!(e.to_string().contains("depth"));
}

#[test]
fn instantiation_failed_displays_reason() {
    let e = VmError::InstantiationFailed {
        reason: "missing import".to_string(),
    };
    assert!(e.to_string().contains("missing import"));
}

#[test]
fn stack_overflow_displays_message() {
    let e = VmError::StackOverflow;
    assert!(e.to_string().contains("overflow"));
}

#[test]
fn reentrancy_displays_address() {
    let addr = Address::zero();
    let e = VmError::Reentrancy { addr };
    // Address implements Display (bech32m rendering) — message must include it.
    let msg = e.to_string();
    assert!(
        msg.contains(&addr.to_string()),
        "reentrancy message must contain the rendered address; got: {msg}"
    );
}

#[test]
fn invalid_module_displays_reason() {
    let e = VmError::InvalidModule {
        reason: "unsupported section".to_string(),
    };
    assert!(e.to_string().contains("unsupported section"));
}

#[test]
fn trap_unknown_displays_message() {
    let e = VmError::TrapUnknown {
        message: "IntegerDivisionByZero".to_string(),
    };
    assert!(e.to_string().contains("IntegerDivisionByZero"));
}

#[test]
fn insufficient_funds_displays_amounts() {
    let required = Amount::from_drop(1_000_000);
    let available = Amount::from_drop(500_000);
    let e = VmError::InsufficientFunds {
        required,
        available,
    };
    let msg = e.to_string();
    assert!(msg.contains("insufficient funds"));
}

#[test]
fn invalid_parameter_displays_reason() {
    let e = VmError::InvalidParameter {
        reason: "zero gas limit".to_string(),
    };
    assert!(e.to_string().contains("zero gas limit"));
}

#[test]
fn engine_setup_failed_displays_reason() {
    let e = VmError::EngineSetupFailed {
        reason: "config conflict".to_string(),
    };
    assert!(e.to_string().contains("config conflict"));
}

#[test]
fn honeypot_invariant_violation_displays_reason() {
    let e = VmError::HoneypotInvariantViolation {
        reason: "owner changed to attacker".to_string(),
    };
    let msg = e.to_string();
    assert!(
        msg.contains("honeypot invariant violation"),
        "message must contain 'honeypot invariant violation'; got: {msg}"
    );
    assert!(
        msg.contains("owner changed to attacker"),
        "message must contain the reason; got: {msg}"
    );
}

#[test]
fn contract_too_large_displays_size_and_limit() {
    // Verify the Display output contains both the actual size and the limit so
    // that operators can diagnose oversized deploys from receipts alone
    // (08-EXECUTION_SPEC §3.4(a), DB-A21).
    //
    // We use the canonical constant value directly (2 MiB = 2_097_152) so this
    // test also acts as a regression guard: if MAX_CONTRACT_WASM_SIZE ever
    // changes, the caller site in lemma-vm must be updated too.
    let size = 3_000_000_usize;
    let limit = lemma_core::MAX_CONTRACT_WASM_SIZE;
    let e = VmError::ContractTooLarge { size, limit };
    let msg = e.to_string();
    assert!(
        msg.contains(&size.to_string()),
        "error message must contain the actual size ({size}); got: {msg}"
    );
    assert!(
        msg.contains(&limit.to_string()),
        "error message must contain the limit ({limit}); got: {msg}"
    );
}
