use lemma_core::{
    address::Address, amount::Amount, block::Block, hash::Hash, header::BlockHeader,
    transaction::Transaction,
};

use super::{MAX_GOSSIP_DECODE_BYTES, *};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Minimal valid `Block` for use in message tests.
///
/// Returns a structurally valid block at the given height with no transactions.
/// Does NOT represent a real consensus-produced block — genesis-style zeros
/// for all hashes.
fn test_block(height: u64) -> Block {
    let header = BlockHeader::new(
        height,
        1_700_000_000,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,            // epoch
        0,            // dag_round
        Hash::zero(), // dag_anchor
        Hash::zero(), // validators_hash
        Hash::zero(), // next_validators_hash
        1_000_000,    // gas_limit
        0,            // gas_used
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("test block header is always valid");
    Block::new(header, vec![], vec![], None).expect("test block is always valid")
}

/// A minimal `Transaction` for gossip tests (unsigned, Transfer type).
///
/// Transfer type requires a `to` recipient — uses `Address::burn()` as a
/// convenient stand-in that satisfies the structural constraint.
fn test_tx() -> Transaction {
    use lemma_core::signature::Signature;
    use lemma_core::transaction::TxType;
    Transaction::new(
        Hash::zero(),                     // hash
        Address::zero(),                  // sender
        Some(Address::burn()),            // to — Transfer requires recipient
        0,                                // nonce
        1,                                // chain_id
        Amount::from_drop(0),             // value
        21_000,                           // gas_limit (must be > 0)
        Amount::from_drop(1_000_000_000), // gas_price
        TxType::Transfer,
        vec![], // data (Transfer allows empty)
        Signature::Unsigned,
    )
    .expect("test transaction is always valid")
}

// ── MessageError — display ────────────────────────────────────────────────────

#[test]
fn message_error_inverted_range_display_contains_heights() {
    let err = MessageError::InvertedRange { from: 100, to: 50 };
    let msg = err.to_string();
    assert!(
        msg.contains("100"),
        "expected from_height in display, got: {msg}"
    );
    assert!(
        msg.contains("50"),
        "expected to_height in display, got: {msg}"
    );
}

#[test]
fn message_error_range_too_wide_display_contains_got_and_max() {
    let err = MessageError::RangeTooWide {
        got: 1000,
        max: 256,
    };
    let msg = err.to_string();
    assert!(msg.contains("1000"), "expected got in display, got: {msg}");
    assert!(msg.contains("256"), "expected max in display, got: {msg}");
}

#[test]
fn message_error_encoding_display_contains_reason() {
    let err = MessageError::Encoding {
        reason: "unexpected io".to_string(),
    };
    assert!(err.to_string().contains("unexpected io"));
}

#[test]
fn message_error_decoding_display_contains_reason() {
    let err = MessageError::Decoding {
        reason: "bad magic".to_string(),
    };
    assert!(err.to_string().contains("bad magic"));
}

// ── RangeRequest — construction ───────────────────────────────────────────────

#[test]
fn range_request_new_stores_heights() {
    let req = RangeRequest::new(100, 200);
    assert_eq!(req.from_height, 100);
    assert_eq!(req.to_height, 200);
}

#[test]
fn range_request_width_returns_difference() {
    let req = RangeRequest::new(100, 200);
    assert_eq!(req.width(), Some(100));
}

#[test]
fn range_request_width_returns_zero_for_same_height() {
    // from == to → single-block request → width 0 (valid, not inverted).
    let req = RangeRequest::new(50, 50);
    assert_eq!(req.width(), Some(0));
}

#[test]
fn range_request_width_returns_none_for_inverted_range() {
    let req = RangeRequest::new(200, 100);
    assert_eq!(req.width(), None);
}

// ── RangeRequest — validate ───────────────────────────────────────────────────

#[test]
fn range_request_validate_accepts_within_max() {
    let req = RangeRequest::new(0, 100);
    assert!(req.validate(256).is_ok());
}

#[test]
fn range_request_validate_accepts_exactly_at_max() {
    // width == max_range is the boundary — must be accepted.
    let req = RangeRequest::new(0, 256);
    assert!(req.validate(256).is_ok());
}

#[test]
fn range_request_validate_accepts_single_block() {
    // width 0: from == to — request for one block at a height.
    let req = RangeRequest::new(100, 100);
    assert!(req.validate(256).is_ok());
}

#[test]
fn range_request_validate_accepts_genesis_to_first() {
    let req = RangeRequest::new(0, 1);
    assert!(req.validate(256).is_ok());
}

#[test]
fn range_request_validate_rejects_inverted_range() {
    let req = RangeRequest::new(200, 100);
    assert_eq!(
        req.validate(256),
        Err(MessageError::InvertedRange { from: 200, to: 100 })
    );
}

#[test]
fn range_request_validate_rejects_one_over_max() {
    // width == max_range + 1 is the first rejection point.
    let req = RangeRequest::new(0, 257);
    assert_eq!(
        req.validate(256),
        Err(MessageError::RangeTooWide { got: 257, max: 256 })
    );
}

#[test]
fn range_request_validate_rejects_far_beyond_max() {
    let req = RangeRequest::new(0, 10_000);
    assert_eq!(
        req.validate(256),
        Err(MessageError::RangeTooWide {
            got: 10_000,
            max: 256
        })
    );
}

#[test]
fn range_request_validate_rejects_max_u64_range() {
    // Edge case: from=0, to=u64::MAX.
    let req = RangeRequest::new(0, u64::MAX);
    let result = req.validate(256);
    assert!(
        matches!(result, Err(MessageError::RangeTooWide { .. })),
        "u64::MAX range must be rejected, got: {result:?}"
    );
}

#[test]
fn range_request_validate_uses_caller_max_not_hardcoded() {
    // Verify the limit comes from the parameter, not a hardcoded constant.
    let req = RangeRequest::new(0, 16);
    assert!(req.validate(16).is_ok()); // exactly at smaller limit
    assert!(req.validate(256).is_ok()); // same request, larger limit
    assert!(req.validate(15).is_err()); // same request, smaller limit
}

// ── RangeRequest — serde roundtrip ───────────────────────────────────────────

#[test]
fn range_request_serde_json_roundtrip() {
    let original = RangeRequest::new(42, 99);
    let json = serde_json::to_string(&original).expect("serialize to JSON");
    let decoded: RangeRequest = serde_json::from_str(&json).expect("deserialize from JSON");
    assert_eq!(decoded, original);
}

#[test]
fn range_request_bincode_roundtrip() {
    let original = RangeRequest::new(1_000_000, 1_000_256);
    let bytes = bincode::serialize(&original).expect("serialize to bincode");
    let decoded: RangeRequest = bincode::deserialize(&bytes).expect("deserialize from bincode");
    assert_eq!(decoded, original);
}

// ── RangeResponse — construction ─────────────────────────────────────────────

#[test]
fn range_response_new_is_empty_for_no_blocks() {
    let resp = RangeResponse::new(vec![]);
    assert!(resp.is_empty());
    assert_eq!(resp.block_count(), 0);
}

#[test]
fn range_response_block_count_matches_input_length() {
    let blocks = vec![test_block(0), test_block(1), test_block(2)];
    let resp = RangeResponse::new(blocks);
    assert_eq!(resp.block_count(), 3);
    assert!(!resp.is_empty());
}

// ── RangeResponse — validate_size ────────────────────────────────────────────

#[test]
fn range_response_validate_size_accepts_empty_response() {
    let resp = RangeResponse::new(vec![]);
    assert!(resp.validate_size(8 * 1024 * 1024).is_ok());
}

#[test]
fn range_response_validate_size_accepts_small_response() {
    let resp = RangeResponse::new(vec![test_block(0)]);
    assert!(resp.validate_size(8 * 1024 * 1024).is_ok());
}

#[test]
fn range_response_validate_size_rejects_when_over_limit() {
    // Use a tiny limit (1 byte) to force rejection.
    let resp = RangeResponse::new(vec![test_block(0)]);
    let result = resp.validate_size(1);
    assert!(
        matches!(result, Err(NetworkError::ResponseTooLarge { .. })),
        "must reject when response exceeds limit, got: {result:?}"
    );
}

#[test]
fn range_response_validate_size_error_contains_got_and_max() {
    let resp = RangeResponse::new(vec![test_block(0)]);
    match resp.validate_size(1) {
        Err(NetworkError::ResponseTooLarge { got, max }) => {
            assert!(got > 0, "got must be > 0");
            assert_eq!(max, 1, "max must match the configured limit");
        }
        other => panic!("expected ResponseTooLarge, got: {other:?}"),
    }
}

// ── RangeResponse — serde roundtrip ──────────────────────────────────────────

#[test]
fn range_response_empty_bincode_roundtrip() {
    let original = RangeResponse::new(vec![]);
    let bytes = bincode::serialize(&original).expect("serialize");
    let decoded: RangeResponse = bincode::deserialize(&bytes).expect("deserialize");
    assert_eq!(decoded, original);
}

#[test]
fn range_response_with_blocks_bincode_roundtrip() {
    let blocks = vec![test_block(0), test_block(1)];
    let original = RangeResponse::new(blocks);
    let bytes = bincode::serialize(&original).expect("serialize");
    let decoded: RangeResponse = bincode::deserialize(&bytes).expect("deserialize");
    assert_eq!(decoded, original);
}

// ── GossipMessage — topic routing ────────────────────────────────────────────

#[test]
fn gossip_new_block_routes_to_blocks_topic() {
    let msg = GossipMessage::NewBlock(Box::new(test_block(0)));
    assert_eq!(msg.topic(), config::TOPIC_BLOCKS);
}

#[test]
fn gossip_new_transaction_routes_to_tx_topic() {
    let msg = GossipMessage::NewTransaction(test_tx());
    assert_eq!(msg.topic(), config::TOPIC_TX);
}

#[test]
fn gossip_message_topic_is_versioned() {
    // Each topic must carry a version suffix for forward-compat.
    assert!(GossipMessage::NewBlock(Box::new(test_block(0)))
        .topic()
        .ends_with("/1"));
    assert!(GossipMessage::NewTransaction(test_tx())
        .topic()
        .ends_with("/1"));
}

// ── GossipMessage — encode / decode roundtrip ─────────────────────────────────

#[test]
fn gossip_new_block_encode_decode_roundtrip() {
    let original = GossipMessage::NewBlock(Box::new(test_block(42)));
    let bytes = original.encode().expect("encode must succeed");
    let decoded = GossipMessage::decode(&bytes).expect("decode must succeed");
    assert_eq!(decoded, original);
}

#[test]
fn gossip_new_transaction_encode_decode_roundtrip() {
    let original = GossipMessage::NewTransaction(test_tx());
    let bytes = original.encode().expect("encode must succeed");
    let decoded = GossipMessage::decode(&bytes).expect("decode must succeed");
    assert_eq!(decoded, original);
}

#[test]
fn gossip_decode_returns_error_on_empty_bytes() {
    // Never panics — returns Decoding error.
    let result = GossipMessage::decode(&[]);
    assert!(
        matches!(result, Err(MessageError::Decoding { .. })),
        "empty bytes must yield Decoding error, got: {result:?}"
    );
}

#[test]
fn gossip_decode_returns_error_on_garbage_bytes() {
    // Never panics — returns Decoding error for arbitrary malformed input.
    let garbage = b"not a valid gossip message at all !!!";
    let result = GossipMessage::decode(garbage);
    assert!(
        matches!(result, Err(MessageError::Decoding { .. })),
        "garbage bytes must yield Decoding error, got: {result:?}"
    );
}

#[test]
fn gossip_decode_returns_error_on_truncated_bytes() {
    // A prefix of valid bytes is not valid — decode must fail gracefully.
    let valid = GossipMessage::NewBlock(Box::new(test_block(1)))
        .encode()
        .expect("encode");
    let truncated = &valid[..valid.len() / 2];
    let result = GossipMessage::decode(truncated);
    assert!(
        matches!(result, Err(MessageError::Decoding { .. })),
        "truncated bytes must yield Decoding error, got: {result:?}"
    );
}

// ── GossipMessage — Debug ─────────────────────────────────────────────────────

#[test]
fn gossip_new_block_debug_contains_variant_name() {
    let msg = GossipMessage::NewBlock(Box::new(test_block(0)));
    assert!(format!("{msg:?}").contains("NewBlock"));
}

#[test]
fn gossip_new_transaction_debug_contains_variant_name() {
    let msg = GossipMessage::NewTransaction(test_tx());
    assert!(format!("{msg:?}").contains("NewTransaction"));
}

// ── GossipMessage — size guard in decode (SEC-2) ──────────────────────────────

#[test]
fn gossip_decode_rejects_oversized_input() {
    // A byte slice larger than MAX_GOSSIP_DECODE_BYTES must be rejected before
    // JSON parsing begins — defense-in-depth against memory exhaustion.
    let oversized = vec![b'{'; MAX_GOSSIP_DECODE_BYTES + 1];
    let result = GossipMessage::decode(&oversized);
    assert!(
        matches!(result, Err(MessageError::Decoding { .. })),
        "oversized input must be rejected, got: {result:?}"
    );
}

#[test]
fn gossip_decode_decoding_error_for_oversized_mentions_size() {
    let oversized = vec![0u8; MAX_GOSSIP_DECODE_BYTES + 1];
    let Err(MessageError::Decoding { reason }) = GossipMessage::decode(&oversized) else {
        panic!("expected Decoding error");
    };
    assert!(
        reason.contains("too large"),
        "reason should mention 'too large', got: {reason}"
    );
}

// ── RangeRequest — u64::MAX boundary (TST-3) ─────────────────────────────────

#[test]
fn range_request_validate_accepts_max_u64_single_block() {
    // from == to == u64::MAX: single block at maximum possible height.
    // checked_sub must return Some(0) — not overflow.
    let req = RangeRequest::new(u64::MAX, u64::MAX);
    assert!(req.validate(256).is_ok());
    assert_eq!(req.width(), Some(0));
}

#[test]
fn range_request_validate_rejects_inverted_at_max_height() {
    // to == u64::MAX - 1 < from == u64::MAX: inverted at the boundary.
    // checked_sub must return None — not wrap to a large positive number.
    let req = RangeRequest::new(u64::MAX, u64::MAX - 1);
    assert_eq!(
        req.validate(256),
        Err(MessageError::InvertedRange {
            from: u64::MAX,
            to: u64::MAX - 1
        })
    );
}

// ── RangeResponse — validate_size at-exactly-max (TST-5) ─────────────────────

#[test]
fn range_response_validate_size_accepts_exactly_at_limit() {
    let resp = RangeResponse::new(vec![]);
    let size =
        usize::try_from(bincode::serialized_size(&resp).expect("size")).expect("size fits usize");
    // At exactly the limit → accept.
    assert!(
        resp.validate_size(size).is_ok(),
        "at exactly the limit must be accepted"
    );
}

#[test]
fn range_response_validate_size_rejects_one_byte_under_actual_size() {
    let resp = RangeResponse::new(vec![]);
    let size =
        usize::try_from(bincode::serialized_size(&resp).expect("size")).expect("size fits usize");
    // Assert the precondition rather than silently skipping the check.
    // An empty RangeResponse always has at least a Vec length prefix (8 bytes
    // in bincode v1), so size == 0 would indicate a broken bincode assumption.
    assert!(
        size > 0,
        "empty RangeResponse must have non-zero serialized size"
    );
    assert!(
        resp.validate_size(size - 1).is_err(),
        "one byte below actual size must be rejected"
    );
}

// ── Topic constants are versioned (TST-9 strengthened) ───────────────────────

#[test]
fn all_gossip_topic_constants_are_versioned() {
    // The topic strings themselves carry the version — not just the messages.
    // This test pins the constants directly so a rename would be caught here.
    assert!(
        config::TOPIC_BLOCKS.ends_with("/1"),
        "TOPIC_BLOCKS must be versioned"
    );
    assert!(
        config::TOPIC_TX.ends_with("/1"),
        "TOPIC_TX must be versioned"
    );
    assert!(
        config::TOPIC_DAG.ends_with("/1"),
        "TOPIC_DAG must be versioned"
    );
}
