use super::*;

// ── RpcError::code ────────────────────────────────────────────────────────────

#[test]
fn parse_error_maps_to_minus_32700() {
    let e = RpcError::ParseError {
        reason: "bad json".into(),
    };
    assert_eq!(e.code(), CODE_PARSE_ERROR);
}

#[test]
fn invalid_request_maps_to_minus_32600() {
    let e = RpcError::InvalidRequest {
        reason: "missing jsonrpc".into(),
    };
    assert_eq!(e.code(), CODE_INVALID_REQUEST);
}

#[test]
fn method_not_found_maps_to_minus_32601() {
    let e = RpcError::MethodNotFound {
        method: "eth_blockNumber".into(),
    };
    assert_eq!(e.code(), CODE_METHOD_NOT_FOUND);
}

#[test]
fn invalid_params_maps_to_minus_32602() {
    let e = RpcError::InvalidParams {
        reason: "missing address".into(),
    };
    assert_eq!(e.code(), CODE_INVALID_PARAMS);
}

#[test]
fn storage_error_maps_to_minus_32603() {
    let e = RpcError::StorageError {
        reason: "rocksdb io error".into(),
    };
    assert_eq!(e.code(), CODE_INTERNAL_ERROR);
}

#[test]
fn transaction_rejected_maps_to_minus_32603() {
    let e = RpcError::TransactionRejected {
        reason: "nonce too low".into(),
    };
    assert_eq!(e.code(), CODE_INTERNAL_ERROR);
}

#[test]
fn internal_error_maps_to_minus_32603() {
    let e = RpcError::Internal {
        reason: "unexpected state".into(),
    };
    assert_eq!(e.code(), CODE_INTERNAL_ERROR);
}

// ── RpcError::Unsupported ─────────────────────────────────────────────────────

#[test]
fn unsupported_maps_to_method_not_found_code() {
    // Unsupported maps to -32601 (MethodNotFound) so callers can detect
    // deferred stubs without treating them as internal errors.
    let e = RpcError::Unsupported {
        method: "lem_call".into(),
        reason: "VM simulation not yet implemented".into(),
    };
    assert_eq!(e.code(), CODE_METHOD_NOT_FOUND);
}

#[test]
fn unsupported_displays_method_and_reason() {
    let e = RpcError::Unsupported {
        method: "lem_call".into(),
        reason: "tracked as lem_call-stub-1".into(),
    };
    let s = e.to_string();
    assert!(s.contains("lem_call"), "display must include method name");
    assert!(s.contains("lem_call-stub-1"), "display must include reason");
}

// ── Display ───────────────────────────────────────────────────────────────────

#[test]
fn parse_error_displays_reason() {
    let e = RpcError::ParseError {
        reason: "unexpected eof".into(),
    };
    assert!(e.to_string().contains("unexpected eof"));
}

#[test]
fn method_not_found_displays_method_name() {
    let e = RpcError::MethodNotFound {
        method: "lem_unknown".into(),
    };
    assert!(e.to_string().contains("lem_unknown"));
}

#[test]
fn invalid_params_displays_reason() {
    let e = RpcError::InvalidParams {
        reason: "expected hex string".into(),
    };
    assert!(e.to_string().contains("expected hex string"));
}
