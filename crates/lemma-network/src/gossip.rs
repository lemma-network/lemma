//! Gossip dissemination — topic management, publish, and incoming message decode.
//!
//! This module is the typed API layer over the raw `gossipsub::Behaviour` from
//! `behaviour.rs`. It knows about Lemma's three gossip topics and the
//! `GossipMessage` wire type from `messages.rs`.
//!
//! ## Design
//!
//! Functions take `&mut gossipsub::Behaviour` (not `&mut LemmaBehaviour`)
//! to remain narrow and independently testable. The service layer passes
//! `behaviour.gossipsub` directly.
//!
//! ## Topics (12-NETWORK_SYNC_SPEC §2.1)
//!
//! | Topic | Carries | Published by |
//! |-------|---------|--------------|
//! | `lemma/blocks/1` | Finalized blocks | Block proposer |
//! | `lemma/tx/1` | Pending transactions | Any node or client |
//! | `lemma/dag/1` | DAG consensus msgs | Validators |
//! | `lemma/batch/1` | Surge tx batches | Validators (C·Step 14) |
//!
//! ## "Gossip is a hint, the QC is the proof" (§2.1)
//!
//! Receiving a gossiped block does NOT mean trusting it. The service layer
//! verifies the block's quorum certificate before extending the chain.
//! This module only handles encode/decode and topic routing — verification
//! is the service layer's responsibility.
//!
//! ## No panics on wire input (§1.2)
//!
//! [`decode_incoming`] maps any decode failure to
//! [`NetworkError::InvalidMessage`] with the sending peer's identity. The
//! caller demotes the peer via the [`PeerTable`](crate::peer::PeerTable)
//! and continues — no panic on a crafted payload.

use libp2p::{gossipsub, PeerId};

use crate::{config, error::NetworkError, messages::GossipMessage};

// ── GossipTopics ──────────────────────────────────────────────────────────────

/// Pre-built `IdentTopic` handles for all three Lemma gossip topics.
///
/// Construct once at startup via [`GossipTopics::new`] and pass by reference
/// to [`subscribe_all`] and [`publish`]. Topics are lightweight but building
/// them on every publish call would repeat the string→hash conversion.
///
/// # Topic routing
///
/// [`GossipTopics::for_message`] maps a [`GossipMessage`] variant to the
/// correct topic using [`GossipMessage::topic`] (the single source of truth
/// for variant→topic-string mapping, defined in `messages.rs`).
#[derive(Debug)]
pub struct GossipTopics {
    /// gossipsub topic for finalized blocks — `lemma/blocks/1`.
    pub blocks: gossipsub::IdentTopic,

    /// gossipsub topic for DAG consensus messages — `lemma/dag/1`.
    pub dag: gossipsub::IdentTopic,

    /// gossipsub topic for pending transactions — `lemma/tx/1`.
    pub tx: gossipsub::IdentTopic,

    /// gossipsub topic for Surge transaction batches — `lemma/batch/1` (C·Step 14).
    ///
    /// Validators broadcast serialized batches here before proposing a `DagBlock`
    /// that references them. Peers pin received batches so `TxBatchRef → txs`
    /// resolution succeeds at commit time.
    pub batch: gossipsub::IdentTopic,
}

impl GossipTopics {
    /// Construct `GossipTopics` from the canonical topic strings in `config`.
    pub fn new() -> Self {
        GossipTopics {
            blocks: gossipsub::IdentTopic::new(config::TOPIC_BLOCKS),
            dag: gossipsub::IdentTopic::new(config::TOPIC_DAG),
            tx: gossipsub::IdentTopic::new(config::TOPIC_TX),
            batch: gossipsub::IdentTopic::new(config::TOPIC_BATCH),
        }
    }

    /// Return the pre-built `IdentTopic` for the given message.
    ///
    /// Routing is driven by [`GossipMessage::topic`] → topic-string constant
    /// comparison. If a new `GossipMessage` variant is added, updating its
    /// `topic()` impl in `messages.rs` is sufficient — this method picks it
    /// up automatically.
    ///
    /// Unknown topic strings fall back to `dag` (the natural home for future
    /// consensus-layer extensions) and emit a `tracing::warn!`.
    pub fn for_message(&self, msg: &GossipMessage) -> &gossipsub::IdentTopic {
        match msg.topic() {
            t if t == config::TOPIC_BLOCKS => &self.blocks,
            t if t == config::TOPIC_TX => &self.tx,
            t if t == config::TOPIC_DAG => &self.dag,
            t if t == config::TOPIC_BATCH => &self.batch,
            other => {
                tracing::warn!(
                    topic = other,
                    "GossipTopics::for_message: unknown topic string — routing to dag \
                     (update for_message when a new GossipMessage variant lands)"
                );
                &self.dag
            }
        }
    }
}

impl Default for GossipTopics {
    fn default() -> Self {
        Self::new()
    }
}

// ── subscribe_all ─────────────────────────────────────────────────────────────

/// Subscribe this node to all three Lemma gossip topics.
///
/// Must be called once after the swarm starts. Both `Ok(true)` (newly
/// subscribed) and `Ok(false)` (already subscribed — idempotent) are
/// treated as success.
///
/// # Errors
///
/// Returns [`NetworkError::Subscribe`] if gossipsub rejects the subscription
/// (e.g. subscription filter blocks it). In practice this should never fail
/// with the default gossipsub config.
pub fn subscribe_all(
    gs: &mut gossipsub::Behaviour,
    topics: &GossipTopics,
) -> Result<(), NetworkError> {
    let to_subscribe = [
        (&topics.blocks, config::TOPIC_BLOCKS),
        (&topics.dag, config::TOPIC_DAG),
        (&topics.tx, config::TOPIC_TX),
        (&topics.batch, config::TOPIC_BATCH),
    ];

    for (topic, name) in to_subscribe {
        // Ok(true) = newly subscribed, Ok(false) = already subscribed — both fine.
        gs.subscribe(topic).map_err(|_| NetworkError::Subscribe {
            topic: name.to_string(),
        })?;
    }

    Ok(())
}

// ── publish ───────────────────────────────────────────────────────────────────

/// Encode a [`GossipMessage`] and publish it to its gossipsub topic.
///
/// 1. `msg.encode()` serialises the message to JSON bytes (see `messages.rs`
///    encoding note — JSON is used because `lemma-core` types use custom serde).
/// 2. [`GossipTopics::for_message`] resolves the correct `IdentTopic`.
/// 3. `gs.publish()` broadcasts to all mesh peers and returns the [`MessageId`].
///
/// The returned `MessageId` is the Blake3 content-addressed ID from
/// `behaviour.rs::compute_message_id` — callers can use it for dedup tracking.
///
/// # Errors
///
/// - [`NetworkError::Publish`] with `reason` describing the publish failure:
///   - `NoPeersSubscribedToTopic` — no mesh peers yet (expected during startup).
///   - `Duplicate` — message was already sent (Blake3 dedup triggered).
///   - Other gossipsub publish errors.
/// - [`NetworkError::Publish`] if JSON encoding fails (programming error — the
///   message types should always be serializable).
pub fn publish(
    gs: &mut gossipsub::Behaviour,
    topics: &GossipTopics,
    msg: &GossipMessage,
) -> Result<gossipsub::MessageId, NetworkError> {
    let topic_str = msg.topic().to_string();

    // Encode to JSON bytes (encoding note: bincode rejected for lemma-core types).
    let bytes = msg.encode().map_err(|e| NetworkError::Publish {
        topic: topic_str.clone(),
        reason: format!("encoding failed: {e}"),
    })?;

    let topic = topics.for_message(msg);

    gs.publish(topic.hash(), bytes)
        .map_err(|e| NetworkError::Publish {
            topic: topic_str,
            reason: format!("{e}"),
        })
}

// ── decode_incoming ───────────────────────────────────────────────────────────

/// Decode raw gossipsub wire bytes into a typed [`GossipMessage`].
///
/// The `peer` argument is the `propagation_source` from the gossipsub
/// [`Event::Message`](gossipsub::Event) — it identifies who sent the bytes,
/// and is embedded in any error so the service layer can demote the peer.
///
/// # Never panics
///
/// Any decode failure returns [`NetworkError::InvalidMessage`] — it never
/// panics (12-NETWORK_SYNC_SPEC §1.2, AGENTS.md §7.2). A gossip peer sending
/// a crafted oversized or malformed payload is a crash-attempt — it must be
/// dropped and the peer demoted, not kill the process.
///
/// The 1 MiB size guard from [`GossipMessage::decode`] fires before JSON
/// parsing begins (defence-in-depth against memory exhaustion).
pub fn decode_incoming(peer: &PeerId, data: &[u8]) -> Result<GossipMessage, NetworkError> {
    GossipMessage::decode(data).map_err(|e| NetworkError::InvalidMessage {
        peer: *peer,
        reason: format!("{e}"),
    })
}

#[cfg(test)]
mod tests;
