use super::*;
use serde_json::json;

// ── JsonRpcRequest deserialization ────────────────────────────────────────────

#[test]
fn request_deserializes_valid_envelope() {
    let raw = r#"{"jsonrpc":"2.0","method":"lem_blockNumber","params":[],"id":1}"#;
    let req: JsonRpcRequest = serde_json::from_str(raw).expect("must deserialize");
    assert_eq!(req.jsonrpc, "2.0");
    assert_eq!(req.method, "lem_blockNumber");
    assert_eq!(req.id, json!(1));
}

#[test]
fn request_deserializes_null_params() {
    let raw = r#"{"jsonrpc":"2.0","method":"lem_gasPrice","id":"abc"}"#;
    let req: JsonRpcRequest = serde_json::from_str(raw).expect("must deserialize");
    assert_eq!(req.params, serde_json::Value::Null);
    assert_eq!(req.id, json!("abc"));
}

#[test]
fn request_deserializes_string_id() {
    let raw = r#"{"jsonrpc":"2.0","method":"lem_blockNumber","id":"req-1"}"#;
    let req: JsonRpcRequest = serde_json::from_str(raw).expect("must deserialize");
    assert_eq!(req.id, json!("req-1"));
}

// ── JsonRpcRequest::validate_version ─────────────────────────────────────────

#[test]
fn validate_version_accepts_2_0() {
    let req = JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "lem_blockNumber".into(),
        params: json!(null),
        id: json!(1),
    };
    assert!(req.validate_version().is_ok());
}

#[test]
fn validate_version_rejects_wrong_version() {
    let req = JsonRpcRequest {
        jsonrpc: "1.0".into(),
        method: "lem_blockNumber".into(),
        params: json!(null),
        id: json!(1),
    };
    let err = req.validate_version().unwrap_err();
    assert!(matches!(err, RpcError::InvalidRequest { .. }));
}

// ── JsonRpcResponse::success ──────────────────────────────────────────────────

#[test]
fn success_response_serializes_correctly() {
    let resp = JsonRpcResponse::success(json!(1), json!("0x1a"));
    let serialized = serde_json::to_value(&resp).expect("must serialize");
    assert_eq!(serialized["jsonrpc"], "2.0");
    assert_eq!(serialized["result"], "0x1a");
    assert_eq!(serialized["id"], 1);
    // error field must be absent
    assert!(serialized.get("error").is_none());
}

#[test]
fn success_response_omits_error_field() {
    let resp = JsonRpcResponse::success(json!(42), json!(null));
    let s = serde_json::to_string(&resp).expect("must serialize");
    assert!(!s.contains("\"error\""));
}

// ── JsonRpcResponse::error ────────────────────────────────────────────────────

#[test]
fn error_response_serializes_correctly() {
    let resp = JsonRpcResponse::error(
        json!(1),
        RpcError::MethodNotFound {
            method: "eth_blockNumber".into(),
        },
    );
    let serialized = serde_json::to_value(&resp).expect("must serialize");
    assert_eq!(serialized["jsonrpc"], "2.0");
    assert_eq!(serialized["error"]["code"], -32601_i64);
    assert!(serialized["error"]["message"]
        .as_str()
        .unwrap()
        .contains("eth_blockNumber"));
    // result field must be absent
    assert!(serialized.get("result").is_none());
}

#[test]
fn error_response_omits_result_field() {
    let resp = JsonRpcResponse::error(
        json!(null),
        RpcError::Internal {
            reason: "oops".into(),
        },
    );
    let s = serde_json::to_string(&resp).expect("must serialize");
    assert!(!s.contains("\"result\""));
}

// ── Round-trip ────────────────────────────────────────────────────────────────

#[test]
fn success_response_round_trips_through_json() {
    let resp = JsonRpcResponse::success(json!("id-1"), json!({"height": 42}));
    let s = serde_json::to_string(&resp).expect("serialize");
    let v: serde_json::Value = serde_json::from_str(&s).expect("deserialize");
    assert_eq!(v["result"]["height"], 42);
    assert_eq!(v["id"], "id-1");
}
