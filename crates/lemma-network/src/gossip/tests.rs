use libp2p::{gossipsub, identity, PeerId};

use lemma_core::{
    address::Address,
    amount::Amount,
    block::Block,
    hash::Hash,
    header::BlockHeader,
    signature::Signature,
    transaction::{Transaction, TxType},
};

use crate::{config, error::NetworkError, messages::GossipMessage};

use super::*;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// A standalone `gossipsub::Behaviour` for unit tests.
///
/// Does NOT need a tokio runtime — gossipsub only spawns tasks when driven
/// by a Swarm event loop, not at construction time.
fn test_gossipsub() -> gossipsub::Behaviour {
    let key = identity::Keypair::generate_ed25519();
    let config = gossipsub::ConfigBuilder::default()
        .build()
        .expect("default gossipsub config is always valid");
    gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(key), config)
        .expect("gossipsub Behaviour must build from valid config and keypair")
}

/// Deterministic test PeerId from a fixed zero seed.
fn test_peer() -> PeerId {
    let mut seed = [0u8; 32];
    let secret = identity::ed25519::SecretKey::try_from_bytes(&mut seed)
        .expect("fixed seed is always valid");
    identity::Keypair::from(identity::ed25519::Keypair::from(secret))
        .public()
        .to_peer_id()
}

/// Minimal valid `Block` for gossip tests.
fn test_block() -> Block {
    let header = BlockHeader::new(
        0,
        1_700_000_000,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        0,
        0,
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        1_000_000,
        0,
        Amount::from_drop(1_000_000_000),
        vec![],
    )
    .expect("test block header is always valid");
    Block::new(header, vec![], vec![], None).expect("test block is always valid")
}

/// Minimal valid `Transaction` for gossip tests.
fn test_tx() -> Transaction {
    Transaction::new(
        Hash::zero(),
        Address::zero(),
        Some(Address::burn()),
        0,
        1,
        Amount::from_drop(0),
        21_000,
        Amount::from_drop(1_000_000_000),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .expect("test transaction is always valid")
}

// ── GossipTopics — construction ───────────────────────────────────────────────

#[test]
fn gossip_topics_blocks_hash_matches_config_constant() {
    let topics = GossipTopics::new();
    let expected = gossipsub::IdentTopic::new(config::TOPIC_BLOCKS).hash();
    assert_eq!(
        topics.blocks.hash(),
        expected,
        "blocks topic hash must match TOPIC_BLOCKS constant"
    );
}

#[test]
fn gossip_topics_dag_hash_matches_config_constant() {
    let topics = GossipTopics::new();
    let expected = gossipsub::IdentTopic::new(config::TOPIC_DAG).hash();
    assert_eq!(topics.dag.hash(), expected);
}

#[test]
fn gossip_topics_tx_hash_matches_config_constant() {
    let topics = GossipTopics::new();
    let expected = gossipsub::IdentTopic::new(config::TOPIC_TX).hash();
    assert_eq!(topics.tx.hash(), expected);
}

#[test]
fn gossip_topics_all_three_are_distinct() {
    let topics = GossipTopics::new();
    assert_ne!(
        topics.blocks.hash(),
        topics.dag.hash(),
        "blocks and dag topics must be distinct"
    );
    assert_ne!(
        topics.blocks.hash(),
        topics.tx.hash(),
        "blocks and tx topics must be distinct"
    );
    assert_ne!(
        topics.dag.hash(),
        topics.tx.hash(),
        "dag and tx topics must be distinct"
    );
}

#[test]
fn gossip_topics_default_equals_new() {
    // Default must produce the same topics as new().
    let a = GossipTopics::new();
    let b = GossipTopics::default();
    assert_eq!(a.blocks.hash(), b.blocks.hash());
    assert_eq!(a.dag.hash(), b.dag.hash());
    assert_eq!(a.tx.hash(), b.tx.hash());
}

// ── GossipTopics::for_message — routing ───────────────────────────────────────

#[test]
fn for_message_routes_new_block_to_blocks_topic() {
    let topics = GossipTopics::new();
    let msg = GossipMessage::NewBlock(Box::new(test_block()));

    let routed = topics.for_message(&msg);
    assert_eq!(
        routed.hash(),
        topics.blocks.hash(),
        "NewBlock must route to the blocks topic"
    );
}

#[test]
fn for_message_routes_new_transaction_to_tx_topic() {
    let topics = GossipTopics::new();
    let msg = GossipMessage::NewTransaction(test_tx());

    let routed = topics.for_message(&msg);
    assert_eq!(
        routed.hash(),
        topics.tx.hash(),
        "NewTransaction must route to the tx topic"
    );
}

#[test]
fn for_message_routing_is_consistent_with_gossip_message_topic_string() {
    // The topic string from GossipMessage::topic() must map to the same
    // IdentTopic hash as for_message returns. This pins the contract between
    // messages.rs and gossip.rs.
    let topics = GossipTopics::new();

    let block_msg = GossipMessage::NewBlock(Box::new(test_block()));
    let block_topic_str = block_msg.topic();
    let expected_block_hash = gossipsub::IdentTopic::new(block_topic_str).hash();
    assert_eq!(topics.for_message(&block_msg).hash(), expected_block_hash);

    let tx_msg = GossipMessage::NewTransaction(test_tx());
    let tx_topic_str = tx_msg.topic();
    let expected_tx_hash = gossipsub::IdentTopic::new(tx_topic_str).hash();
    assert_eq!(topics.for_message(&tx_msg).hash(), expected_tx_hash);
}

// ── subscribe_all ─────────────────────────────────────────────────────────────

#[test]
fn subscribe_all_succeeds_on_fresh_behaviour() {
    let mut gs = test_gossipsub();
    let topics = GossipTopics::new();

    let result = subscribe_all(&mut gs, &topics);
    assert!(
        result.is_ok(),
        "subscribe_all must succeed on a fresh gossipsub behaviour: {:?}",
        result.err()
    );
}

#[test]
fn subscribe_all_is_idempotent() {
    let mut gs = test_gossipsub();
    let topics = GossipTopics::new();

    // First subscription.
    subscribe_all(&mut gs, &topics).expect("first subscribe_all must succeed");
    // Second call — already subscribed → Ok(false) for each, must not error.
    let result = subscribe_all(&mut gs, &topics);
    assert!(
        result.is_ok(),
        "subscribe_all must be idempotent: {:?}",
        result.err()
    );
}

#[test]
fn subscribe_all_subscribes_to_all_three_topics() {
    let mut gs = test_gossipsub();
    let topics = GossipTopics::new();

    subscribe_all(&mut gs, &topics).expect("subscribe_all must succeed");

    // gossipsub::Behaviour::topics() yields subscribed TopicHash values.
    let subscribed: Vec<_> = gs.topics().collect();
    assert!(
        subscribed.contains(&&topics.blocks.hash()),
        "must be subscribed to blocks topic"
    );
    assert!(
        subscribed.contains(&&topics.dag.hash()),
        "must be subscribed to dag topic"
    );
    assert!(
        subscribed.contains(&&topics.tx.hash()),
        "must be subscribed to tx topic"
    );
}

// ── publish ───────────────────────────────────────────────────────────────────

#[test]
fn publish_returns_publish_error_when_no_peers_subscribed() {
    let mut gs = test_gossipsub();
    let topics = GossipTopics::new();

    subscribe_all(&mut gs, &topics).expect("subscribe must succeed");

    let msg = GossipMessage::NewBlock(Box::new(test_block()));
    let result = publish(&mut gs, &topics, &msg);

    // With no peers in the mesh, gossipsub returns NoPeersSubscribedToTopic.
    // publish() maps this to NetworkError::Publish.
    assert!(
        matches!(result, Err(NetworkError::Publish { .. })),
        "publish with no mesh peers must return NetworkError::Publish, got: {result:?}"
    );
}

#[test]
fn publish_error_contains_topic_name() {
    let mut gs = test_gossipsub();
    let topics = GossipTopics::new();
    subscribe_all(&mut gs, &topics).expect("subscribe must succeed");

    let msg = GossipMessage::NewBlock(Box::new(test_block()));
    let Err(NetworkError::Publish { topic, .. }) = publish(&mut gs, &topics, &msg) else {
        panic!("expected Publish error");
    };

    assert_eq!(
        topic,
        config::TOPIC_BLOCKS,
        "error topic must name the blocks topic"
    );
}

#[test]
fn publish_transaction_error_contains_tx_topic_name() {
    let mut gs = test_gossipsub();
    let topics = GossipTopics::new();
    subscribe_all(&mut gs, &topics).expect("subscribe must succeed");

    let msg = GossipMessage::NewTransaction(test_tx());
    let Err(NetworkError::Publish { topic, .. }) = publish(&mut gs, &topics, &msg) else {
        panic!("expected Publish error");
    };

    assert_eq!(topic, config::TOPIC_TX);
}

// ── decode_incoming ───────────────────────────────────────────────────────────

#[test]
fn decode_incoming_valid_block_bytes_returns_correct_message() {
    let original = GossipMessage::NewBlock(Box::new(test_block()));
    let bytes = original.encode().expect("encode must succeed");
    let peer = test_peer();

    let decoded = decode_incoming(&peer, &bytes).expect("decode must succeed for valid bytes");
    assert_eq!(decoded, original, "decoded message must equal the original");
}

#[test]
fn decode_incoming_valid_tx_bytes_returns_correct_message() {
    let original = GossipMessage::NewTransaction(test_tx());
    let bytes = original.encode().expect("encode must succeed");
    let peer = test_peer();

    let decoded = decode_incoming(&peer, &bytes).expect("decode must succeed for valid bytes");
    assert_eq!(decoded, original);
}

#[test]
fn decode_incoming_garbage_bytes_returns_invalid_message_error() {
    let peer = test_peer();
    let result = decode_incoming(&peer, b"not valid json");

    assert!(
        matches!(result, Err(NetworkError::InvalidMessage { .. })),
        "garbage bytes must yield InvalidMessage error, got: {result:?}"
    );
}

#[test]
fn decode_incoming_empty_bytes_returns_invalid_message_error() {
    let peer = test_peer();
    let result = decode_incoming(&peer, &[]);

    assert!(
        matches!(result, Err(NetworkError::InvalidMessage { .. })),
        "empty bytes must yield InvalidMessage error"
    );
}

#[test]
fn decode_incoming_error_contains_sending_peer_id() {
    let peer = test_peer();
    let Err(NetworkError::InvalidMessage { peer: err_peer, .. }) =
        decode_incoming(&peer, b"garbage")
    else {
        panic!("expected InvalidMessage error");
    };

    assert_eq!(err_peer, peer, "error must carry the peer_id of the sender");
}

#[test]
fn decode_incoming_oversized_input_returns_invalid_message_error() {
    use crate::messages::MAX_GOSSIP_DECODE_BYTES;

    let peer = test_peer();
    let oversized = vec![b'{'; MAX_GOSSIP_DECODE_BYTES + 1];
    let result = decode_incoming(&peer, &oversized);

    assert!(
        matches!(result, Err(NetworkError::InvalidMessage { .. })),
        "oversized input must be rejected before JSON parsing"
    );
}

#[test]
fn decode_incoming_does_not_panic_on_any_byte_sequence() {
    // Fuzz-style: a few edge-case byte patterns must not panic.
    let peer = test_peer();
    let patterns: &[&[u8]] = &[
        b"",
        b"\x00",
        b"\xff\xfe\xfd",
        b"{}",
        b"[]",
        b"null",
        b"{\"type\":\"unknown\"}",
        &[0xDE, 0xAD, 0xBE, 0xEF],
    ];
    for pattern in patterns {
        // Any result (Ok or Err) is acceptable — just must not panic.
        let _ = decode_incoming(&peer, pattern);
    }
}

// ── Encode → publish path integration (encode only, no swarm needed) ──────────

#[test]
fn gossip_message_encodes_and_decodes_through_gossip_layer() {
    // Verifies the full encode → decode round-trip that publish + receive does.
    let peer = test_peer();
    let original = GossipMessage::NewBlock(Box::new(test_block()));

    let encoded = original.encode().expect("encode must succeed");
    let decoded = decode_incoming(&peer, &encoded)
        .expect("decode_incoming must succeed for freshly encoded bytes");

    assert_eq!(decoded, original);
}
