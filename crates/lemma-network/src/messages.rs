//! Wire message types for the `lemma-network` P2P stack.
//!
//! Two categories of messages carry data between peers:
//!
//! ## Request-response (CBOR, `/lemma/sync/1`)
//!
//! Targeted pull requests for missing block ranges. The CBOR codec is handled
//! automatically by `libp2p::request_response::cbor::Behaviour` — these types
//! only need `Serialize + Deserialize`.
//!
//! | Type | Direction | Protocol |
//! |------|-----------|----------|
//! | [`RangeRequest`] | requester → responder | `/lemma/sync/1` |
//! | [`RangeResponse`] | responder → requester | `/lemma/sync/1` |
//!
//! ## Gossipsub (bincode, `lemma/blocks/1` · `lemma/tx/1` · `lemma/dag/1`)
//!
//! Broadcast payloads pushed to all subscribed peers via the gossip mesh.
//! The [`GossipMessage`] enum wraps the payload and knows its own topic.
//!
//! ## Safety contract
//!
//! Both categories enforce bounds **at the message layer**:
//! - [`RangeRequest::validate`] — rejects inverted or too-wide ranges before dispatch.
//! - [`RangeResponse::validate_size`] — rejects over-size responses after receipt.
//! - [`GossipMessage::decode`] — never panics on malformed bytes; returns
//!   [`MessageError::Decoding`] so callers can demote the peer.
//!
//! See `12-NETWORK_SYNC_SPEC.md §2.2` for the spec-level bounds rationale.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use lemma_core::{block::Block, transaction::Transaction};

use crate::{config, error::NetworkError};

// ── Gossip decode size limit ──────────────────────────────────────────────────

/// Maximum byte length of gossip message input accepted before JSON parsing.
///
/// Defense-in-depth: the gossipsub layer enforces `max_transmit_size` at the
/// transport level, but `GossipMessage::decode` must not trust that the caller
/// has already bounded the input. An unbounded `serde_json::from_slice` on a
/// crafted multi-gigabyte payload forces the decoder to allocate before the
/// error path fires — a memory-exhaustion attack vector (AGENTS.md §15.1,
/// 12-NETWORK_SYNC_SPEC §2.2 "Bounded everywhere").
///
/// 1 MiB is generous for a single block + signatures + transactions; blocks
/// that genuinely exceed this are already pathological under gas limits.
///
/// TODO(network): move to `NetworkConfig::max_gossip_message_bytes` so callers
/// can tune it per deployment without recompiling.
pub(crate) const MAX_GOSSIP_DECODE_BYTES: usize = 1024 * 1024; // 1 MiB

// ── Encoding note ─────────────────────────────────────────────────────────────
// GossipMessage uses JSON (serde_json) for wire encoding, not bincode.
//
// Reason: lemma-core types (Amount, Hash) use custom serde implementations
// that call `deserialize_any` / `deserialize_str` internally. Bincode v1 does
// not support `deserialize_any` and returns an error on these types. JSON is a
// self-describing format that handles all custom serde impls correctly.
//
// RangeRequest / RangeResponse use bincode only for serialized-size estimation
// in `validate_size`. The actual transport encoding is CBOR, handled by
// `libp2p::request_response::cbor::Behaviour`. Bincode produces smaller output
// than CBOR for Lemma block types (dominated by fixed-size byte arrays: hashes,
// signatures, amounts), so a bincode size that exceeds `max_response_bytes` also
// exceeds the CBOR size — making it a conservative lower-bound estimate. The
// libp2p CBOR codec enforces its own transport-level limit as the authoritative
// check; `validate_size` is a defence-in-depth application-layer guard.
//
// Forward-compat note: if lemma-core types are ever updated to use
// bincode-compatible serde impls (i.e. no `deserialize_any`), the gossip
// encoding should be revisited — bincode would be more compact and faster.

// ── MessageError ──────────────────────────────────────────────────────────────

/// Typed errors for message-layer validation and serialization.
///
/// Distinct from [`NetworkError`] (which carries peer identity for transport
/// and consensus errors). `MessageError` covers structural validation and
/// bincode serialization failures that occur before or after the peer identity
/// is known — the caller converts to [`NetworkError::InvalidMessage`] or
/// [`NetworkError::RangeTooWide`] as appropriate once the peer context exists.
///
/// `#[non_exhaustive]` allows adding new variants without breaking downstream
/// `match` arms (AGENTS.md §4.3).
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum MessageError {
    /// `to_height` is less than `from_height` — the range is inverted.
    ///
    /// This is peer misbehaviour: a well-formed request always has
    /// `to_height >= from_height`. The caller should wrap this in
    /// [`NetworkError::InvalidMessage`] and demote the peer.
    #[error("inverted range: to_height ({to}) < from_height ({from})")]
    InvertedRange { from: u64, to: u64 },

    /// The range width `to_height - from_height` exceeds the configured
    /// [`max_range`](crate::config::NetworkConfig::max_range) limit.
    ///
    /// This is either peer misbehaviour or a local programming error. Map to
    /// [`NetworkError::RangeTooWide`] for transport-layer reporting.
    #[error("range width {got} exceeds maximum {max} blocks")]
    RangeTooWide { got: u64, max: u64 },

    /// [`GossipMessage::encode`] failed to serialize the message.
    ///
    /// This is a local (non-peer) error — bincode should never fail to
    /// serialize well-formed Rust types, so this indicates a programming error.
    #[error("gossip message encoding failed: {reason}")]
    Encoding { reason: String },

    /// [`GossipMessage::decode`] failed to deserialize peer-supplied bytes.
    ///
    /// This is peer misbehaviour — the bytes don't form a valid `GossipMessage`.
    /// The caller should wrap this in [`NetworkError::InvalidMessage`] and
    /// demote the peer. This variant exists to prevent `unwrap()` / `panic!()`
    /// on crafted wire input (12-NETWORK_SYNC_SPEC §1.2, AGENTS.md §7.2).
    #[error("gossip message decoding failed: {reason}")]
    Decoding { reason: String },
}

// ── RangeRequest ──────────────────────────────────────────────────────────────

/// A request to a peer for a bounded range of finalized blocks.
///
/// Sent over the `/lemma/sync/1` request-response protocol (CBOR codec).
/// The responding peer returns a [`RangeResponse`] containing blocks from
/// `from_height` (inclusive) through `to_height` (inclusive).
///
/// # DoS contract
///
/// Always call [`RangeRequest::validate`] before dispatching. An unchecked
/// range can force O(n) allocation on the responder and is a
/// memory-exhaustion attack vector (12-NETWORK_SYNC_SPEC §2.2).
///
/// # Examples
///
/// ```
/// use lemma_network::messages::RangeRequest;
///
/// let req = RangeRequest::new(100, 200);
/// assert!(req.validate(256).is_ok());
/// assert_eq!(req.width(), Some(100));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeRequest {
    /// Height of the first block to include (inclusive).
    pub from_height: u64,
    /// Height of the last block to include (inclusive).
    pub to_height: u64,
}

impl RangeRequest {
    /// Create a new range request.
    ///
    /// Does **not** validate the range — call [`Self::validate`] before
    /// dispatching. Deserialization from peer input via serde bypasses
    /// constructors, so validation must be a separate step.
    pub fn new(from_height: u64, to_height: u64) -> Self {
        RangeRequest {
            from_height,
            to_height,
        }
    }

    /// Validate the range against the configured maximum width.
    ///
    /// The range is valid when `to_height - from_height <= max_range`
    /// (inclusive upper bound — a width exactly equal to `max_range` is
    /// accepted).
    ///
    /// # Errors
    ///
    /// - [`MessageError::InvertedRange`] — `to_height < from_height`.
    /// - [`MessageError::RangeTooWide`] — `to_height - from_height > max_range`.
    ///
    /// # Note on `max_range`
    ///
    /// Pass [`NetworkConfig::max_range`](crate::config::NetworkConfig::max_range)
    /// directly. Do not hardcode — the limit must be configurable so test
    /// environments can use smaller values.
    pub fn validate(&self, max_range: u64) -> Result<(), MessageError> {
        // checked_sub catches the inverted-range case without arithmetic overflow.
        let width =
            self.to_height
                .checked_sub(self.from_height)
                .ok_or(MessageError::InvertedRange {
                    from: self.from_height,
                    to: self.to_height,
                })?;
        if width > max_range {
            return Err(MessageError::RangeTooWide {
                got: width,
                max: max_range,
            });
        }
        Ok(())
    }

    /// Returns the width (number of blocks) of this range, or `None` if the
    /// range is inverted (`to_height < from_height`).
    ///
    /// Width of 0 means `from_height == to_height` — a request for a single
    /// block by height.
    pub fn width(&self) -> Option<u64> {
        self.to_height.checked_sub(self.from_height)
    }
}

// ── RangeResponse ─────────────────────────────────────────────────────────────

/// A response to a [`RangeRequest`] carrying a bounded list of finalized blocks.
///
/// Received over the `/lemma/sync/1` request-response protocol (CBOR codec).
/// The receiver MUST call [`RangeResponse::validate_size`] and then verify
/// each block's `parent_hash` continuity and quorum certificate before
/// applying the blocks to the local chain (12-NETWORK_SYNC_SPEC §2.2).
///
/// # DoS contract
///
/// Always call [`RangeResponse::validate_size`] immediately after receipt.
/// A malicious peer can pad a response with junk to exhaust receiver memory
/// (12-NETWORK_SYNC_SPEC §2.2, AGENTS.md §15.2).
///
/// # Examples
///
/// ```
/// use lemma_network::messages::RangeResponse;
///
/// let resp = RangeResponse::new(vec![]);
/// assert!(resp.is_empty());
/// assert_eq!(resp.block_count(), 0);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeResponse {
    /// The returned blocks, ordered by ascending height.
    ///
    /// The receiver MUST verify `parent_hash` continuity — that each block's
    /// `parent_hash` matches the previous block's hash — before applying.
    pub blocks: Vec<Block>,
}

impl RangeResponse {
    /// Wrap a list of blocks in a range response.
    pub fn new(blocks: Vec<Block>) -> Self {
        RangeResponse { blocks }
    }

    /// Returns the number of blocks in this response.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Returns `true` if this response contains no blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Validates the serialized response size against the configured limit.
    ///
    /// Uses bincode as a conservative size proxy — see the module-level
    /// encoding note for why bincode is smaller than CBOR for Lemma types,
    /// making this a safe lower-bound estimate.
    ///
    /// Returns [`NetworkError::ResponseTooLarge`] (not `MessageError`) because
    /// a response that exceeds the size limit always has peer context by the
    /// time it is received — callers always know which peer served it. This
    /// asymmetry with [`RangeRequest::validate`] is intentional: request
    /// validation may happen locally before dispatch, response validation
    /// always happens after receipt.
    ///
    /// Call this immediately after receiving the response, before processing
    /// any blocks (12-NETWORK_SYNC_SPEC §2.2).
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::ResponseTooLarge`] if the estimated serialized
    /// size exceeds `max_bytes`. Pass
    /// [`NetworkConfig::max_response_bytes`](crate::config::NetworkConfig::max_response_bytes).
    pub fn validate_size(&self, max_bytes: usize) -> Result<(), NetworkError> {
        // bincode::serialized_size is cheap (no allocation) and sufficient as
        // a pre-processing guard. If size computation fails, saturate to
        // usize::MAX (reject) — safer than accepting a potentially unbounded
        // response. The try_into().unwrap_or avoids the silent truncation that
        // `as usize` would produce if the u64 value exceeded usize::MAX on a
        // 32-bit target.
        let size: usize = bincode::serialized_size(self)
            .map(|s| usize::try_from(s).unwrap_or(usize::MAX))
            .unwrap_or(usize::MAX);
        if size > max_bytes {
            return Err(NetworkError::ResponseTooLarge {
                got: size,
                max: max_bytes,
            });
        }
        Ok(())
    }
}

// ── GossipMessage ─────────────────────────────────────────────────────────────

/// A gossipsub message envelope carrying one of the Lemma broadcast payload types.
///
/// Serialized to `Vec<u8>` via JSON ([`serde_json`]) for gossipsub wire
/// transmission. JSON is used (not bincode) because `lemma-core` types use
/// custom serde implementations that bincode v1 cannot handle — see the
/// module-level encoding note for the full rationale.
///
/// The [`GossipMessage::topic`] method returns the gossipsub topic string this
/// message should be published to — determined by variant, not caller choice.
///
/// # DAG consensus messages
///
/// [`GossipMessage::DagProposal`] carries a [`DagBlock`] produced by a
/// validator during the Surge dissemination round. Published on
/// [`TOPIC_DAG`] — every validator broadcasts one DagBlock per DAG round.
/// Receivers feed it into `SurgeDriver::on_block` after verifying the
/// hybrid signature (`sig_ok: bool` injected per DB-12 / decisions-log).
///
/// `DagVote` is **not needed** — commit votes piggyback inside
/// `DagBlock.commit_votes` (Decision 3b, `07-CONSENSUS_SPEC §2.1`).
///
/// # Examples
///
/// ```
/// use lemma_network::messages::GossipMessage;
/// use lemma_core::transaction::Transaction;
///
/// // Encode → transmit → decode
/// // let msg = GossipMessage::NewBlock(block);
/// // let bytes = msg.encode().unwrap();
/// // let decoded = GossipMessage::decode(&bytes).unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum GossipMessage {
    /// A newly finalized chain block, broadcast on [`TOPIC_BLOCKS`].
    ///
    /// Published by the block proposer immediately after the block is
    /// committed to the chain store (`12-NETWORK_SYNC_SPEC §2.1`).
    /// Receivers verify the block's structural integrity before extending
    /// their chain — gossip is a *hint*, structural + QC verification is
    /// the *proof*.
    NewBlock(Block),

    /// A pending transaction, broadcast on [`TOPIC_TX`].
    ///
    /// Published by the submitting client or relaying node. Encrypted
    /// (Shield) transactions appear here in ciphertext form and are
    /// decrypted only after ordering (`11-MEMPOOL_SHIELD_SPEC`).
    NewTransaction(Transaction),

    /// A DAG block proposal from a validator, broadcast on [`TOPIC_DAG`].
    ///
    /// The payload is a **JSON-serialized `DagBlock`** (opaque `Vec<u8>` at
    /// the network layer). `lemma-consensus::DagBlock` is defined in build
    /// layer 6 (consensus), while `lemma-network` is layer 4 — the network
    /// crate cannot import the typed struct without a build-order violation
    /// (AGENTS §8). The node layer (`lemma-node`) handles encode/decode:
    /// `serde_json::to_vec(&dag_block)` before publish, `from_slice` on receive.
    ///
    /// Published by every validator once per DAG round, after observing a
    /// 2f+1 quorum of blocks from the previous round (`07-CONSENSUS_SPEC §2.3`
    /// Surge loop). Receivers verify the hybrid Ed25519+ML-DSA-65 signature
    /// (`sig_ok: bool` injected at node layer per DB-12) and feed the block
    /// into `SurgeDriver::on_block`.
    ///
    /// `CommitVote`s piggyback inside `DagBlock.commit_votes` (Decision 3b,
    /// `07-CONSENSUS_SPEC §2.1`) — no separate `DagVote` gossip is needed.
    DagProposal(Vec<u8>),
}

impl GossipMessage {
    /// Returns the gossipsub topic this message should be published to.
    ///
    /// Topic is determined by variant — callers do not choose the topic
    /// independently. This prevents publishing a block to the tx topic
    /// or vice versa.
    pub fn topic(&self) -> &str {
        match self {
            GossipMessage::NewBlock(_) => config::TOPIC_BLOCKS,
            GossipMessage::NewTransaction(_) => config::TOPIC_TX,
            GossipMessage::DagProposal(_) => config::TOPIC_DAG,
        }
    }

    /// Serialize this message to JSON bytes for gossipsub wire transmission.
    ///
    /// JSON is used (not bincode) because `lemma-core` types (`Amount`, `Hash`)
    /// use custom serde implementations that bincode v1 cannot handle —
    /// see the encoding note at the top of this module.
    ///
    /// # Errors
    ///
    /// Returns [`MessageError::Encoding`] if JSON serialization fails.
    /// In practice this should never fail for well-formed Rust types, so an
    /// error here indicates a programming error, not peer misbehaviour.
    pub fn encode(&self) -> Result<Vec<u8>, MessageError> {
        serde_json::to_vec(self).map_err(|e| MessageError::Encoding {
            reason: e.to_string(),
        })
    }

    /// Deserialize a `GossipMessage` from peer-supplied JSON bytes.
    ///
    /// **Never panics.** Malformed bytes from a peer return
    /// [`MessageError::Decoding`], which the caller should convert to
    /// [`NetworkError::InvalidMessage`] and use to demote the peer
    /// (12-NETWORK_SYNC_SPEC §1.2, AGENTS.md §7.2).
    ///
    /// A size guard (`MAX_GOSSIP_DECODE_BYTES`) rejects oversized input
    /// before JSON parsing begins — defense-in-depth against memory-exhaustion
    /// attacks even if the gossipsub transport-level `max_transmit_size` is
    /// bypassed or misconfigured (AGENTS.md §15.1).
    ///
    /// # Errors
    ///
    /// - [`MessageError::Decoding`] — bytes exceed [`MAX_GOSSIP_DECODE_BYTES`],
    ///   or the bytes are not valid JSON for a `GossipMessage`.
    pub fn decode(bytes: &[u8]) -> Result<Self, MessageError> {
        // Reject before parsing — an unbounded serde_json::from_slice on a
        // crafted multi-GiB blob forces allocation before the error path fires.
        if bytes.len() > MAX_GOSSIP_DECODE_BYTES {
            return Err(MessageError::Decoding {
                reason: format!(
                    "message too large: {} > {} bytes (MAX_GOSSIP_DECODE_BYTES)",
                    bytes.len(),
                    MAX_GOSSIP_DECODE_BYTES,
                ),
            });
        }
        serde_json::from_slice(bytes).map_err(|e| MessageError::Decoding {
            reason: e.to_string(),
        })
    }
}

#[cfg(test)]
mod tests;
