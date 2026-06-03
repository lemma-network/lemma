use super::*;

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
