//! Merkle proof generation and verification for the Lemma MPT.
//!
//! A [`MerkleProof`] is a cryptographic witness that a given key maps to a
//! given value (inclusion proof) or that a key is absent (non-inclusion proof)
//! in a trie with a known root hash. It lets a verifier check membership
//! without replaying the full trie — only the path from root to the relevant
//! leaf is needed.
//!
//! ## How it works
//!
//! Generation ([`MerklePatriciaTrie::generate_proof`]) walks the trie from root
//! to the target key, collecting every node along the path into a
//! [`Vec<ProofNode>`]. The proof also records the key and (if found) the value.
//!
//! Verification ([`MerkleProof::verify`]) is self-contained — no DB access:
//!
//! 1. Walk `nodes` from last (deepest) to first (root's child), re-hashing
//!    each with the same bincode → Blake3 pipeline used by [`TrieNode::hash`].
//! 2. Check that each hash matches the parent's child reference at the correct
//!    nibble position.
//! 3. Check that the first node's hash equals `expected_root`.
//! 4. For inclusion: confirm the leaf value matches `proof.value`.
//! 5. For non-inclusion: confirm the path terminates without finding the key.
//!
//! ## Relationship to `RangeProof`
//!
//! The spec (`12-NETWORK_SYNC_SPEC.md §4.2`) defines `RangeProof` for
//! per-chunk state-sync. `RangeProof` will build on `MerkleProof` but belongs
//! to the state-sync layer (`lemma-network`). Only single-key proofs are
//! implemented here.
//!
//! [`TrieNode::hash`]: crate::trie::node::TrieNode::hash
//! [`MerklePatriciaTrie::generate_proof`]: crate::trie::MerklePatriciaTrie::generate_proof

use lemma_core::Hash;
use serde::{Deserialize, Serialize};

use crate::{
    trie::node::{NibblePath, TrieNode},
    StorageError,
};

// ─── ProofNode ────────────────────────────────────────────────────────────────

/// A single node along the trie path from root to the target key.
///
/// `ProofNode` mirrors [`TrieNode`] structurally so the verifier can
/// re-hash each node using the exact same bincode → Blake3 pipeline —
/// no separate proof encoding, no extra complexity.
///
/// [`TrieNode`]: crate::trie::node::TrieNode
// Same `large_enum_variant` justification as `TrieNode`: Branch holds
// [Option<Hash>; 16] (552 bytes) by design. Boxing changes the bincode layout
// and would break `ProofNode::hash()` parity with `TrieNode::hash()`.
// `#[non_exhaustive]` allows adding proof variants (e.g. Compact) without a
// semver break. Internal exhaustive matching still works within this crate.
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofNode {
    /// A 16-way branch node.
    ///
    /// `children[i]` is the hash of the child at nibble `i`, or `None` if
    /// that slot is empty. The verifier needs all 16 slots to recompute the
    /// branch hash.
    Branch {
        /// Child hashes, one per nibble (0–15). `None` = empty slot.
        children: [Option<Hash>; 16],
        /// Optional value stored directly at this branch (key path exhausted).
        value: Option<Vec<u8>>,
    },
    /// A path-compressed extension node.
    Extension {
        /// The shared nibble prefix compressed by this node.
        prefix: NibblePath,
        /// Hash of the single child at the end of the prefix.
        child: Hash,
    },
    /// A terminal leaf node.
    Leaf {
        /// The remaining nibble path for this leaf (from this node's depth
        /// to the key end — NOT the full path from the root).
        path: NibblePath,
        /// The value stored at this leaf.
        value: Vec<u8>,
    },
}

impl ProofNode {
    /// Compute the Blake3 hash of this proof node.
    ///
    /// Uses the same bincode → Blake3 pipeline as [`TrieNode::hash`] so a
    /// `ProofNode` hashes identically to its corresponding `TrieNode`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::SerializationFailed`] if bincode serialization
    /// fails (should never happen for well-formed nodes).
    ///
    /// [`TrieNode::hash`]: crate::trie::node::TrieNode::hash
    pub fn hash(&self) -> Result<Hash, StorageError> {
        // Convert to TrieNode and hash — guarantees identical serialization.
        // This is the canonical approach: one hash function, one representation.
        let trie_node = self.as_trie_node();
        trie_node.hash()
    }

    /// Convert this `ProofNode` to the equivalent [`TrieNode`].
    ///
    /// Used by [`hash`] to reuse `TrieNode`'s serialization path exactly.
    ///
    /// [`TrieNode`]: crate::trie::node::TrieNode
    /// [`hash`]: ProofNode::hash
    fn as_trie_node(&self) -> TrieNode {
        match self {
            ProofNode::Branch { children, value } => TrieNode::Branch {
                children: *children,
                value: value.clone(),
            },
            ProofNode::Extension { prefix, child } => TrieNode::extension(prefix.clone(), *child),
            ProofNode::Leaf { path, value } => TrieNode::leaf(path.clone(), value.clone()),
        }
    }
}

// ─── MerkleProof ──────────────────────────────────────────────────────────────

/// A Merkle proof for a key in the Lemma MPT.
///
/// A proof is either:
///
/// - **Inclusion** (`value = Some(v)`): proves key → v exists in the trie.
/// - **Non-inclusion** (`value = None`): proves the key is absent.
///
/// Call [`verify`] to check the proof against a known root hash.
///
/// ## Serialization
///
/// `MerkleProof` is `Serialize + Deserialize` so it can be sent over RPC
/// and P2P. The bincode layout is pinned by the field order of `ProofNode`
/// variants — do not reorder fields without a migration.
///
/// [`verify`]: MerkleProof::verify
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The key this proof is for (raw bytes, not nibble-encoded).
    pub key: Vec<u8>,
    /// `Some(value)` for inclusion, `None` for non-inclusion.
    pub value: Option<Vec<u8>>,
    /// Nodes from root (index 0) down to the terminal node (last index).
    pub nodes: Vec<ProofNode>,
}

impl MerkleProof {
    /// Verify this proof against `expected_root`.
    ///
    /// A proof is valid when:
    ///
    /// 1. All node hashes chain correctly (each parent references the next
    ///    node's hash at the right nibble position).
    /// 2. The first node's hash equals `expected_root`.
    /// 3. For inclusion (`value = Some`): the terminal leaf path and value
    ///    match the proof's key and value.
    /// 4. For non-inclusion (`value = None`): the path terminates without
    ///    finding the key (diverging nibble or empty branch slot).
    ///
    /// Verification is **self-contained** — no DB access required.
    ///
    /// # Errors
    ///
    /// - [`StorageError::InvalidProof`] — nodes don't hash-chain correctly,
    ///   or inclusion/non-inclusion claim doesn't match the terminal node.
    /// - [`StorageError::TrieRootMismatch`] — the computed root doesn't match
    ///   `expected_root`.
    /// - [`StorageError::SerializationFailed`] — bincode failure re-hashing a
    ///   node (indicates corrupt proof data).
    pub fn verify(&self, expected_root: Hash) -> Result<(), StorageError> {
        let key_hex = hex::encode(&self.key);

        // An empty proof list is always invalid — a real trie has at least
        // one node (the root).
        if self.nodes.is_empty() {
            return Err(StorageError::InvalidProof { key: key_hex });
        }

        // Forward pass: compute the depth (nibbles consumed by ancestors) of
        // each node and its Blake3 hash.  Depths are needed to look up the
        // correct branch slot when a Branch is a parent node.
        let full_path = NibblePath::from_bytes(&self.key);
        let (depths, hashes) = self.compute_depths_and_hashes()?;

        // Verify that each parent node's child reference equals the hash of
        // the next node at the correct depth/slot.
        for i in 0..self.nodes.len().saturating_sub(1) {
            self.verify_child_linkage(
                &self.nodes[i],
                hashes[i + 1],
                &full_path,
                depths[i],
                &key_hex,
            )?;
        }

        // The root is the hash of the first node.
        let root_hash = hashes[0];
        if root_hash != expected_root {
            return Err(StorageError::TrieRootMismatch {
                expected: expected_root.to_string(),
                got: root_hash.to_string(),
            });
        }

        // Verify the terminal node (last in the list) matches the
        // inclusion/non-inclusion claim.
        let terminal_depth = *depths.last().expect("depths non-empty: checked above");
        self.verify_terminal_node(&full_path, terminal_depth, &key_hex)
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Compute per-node depths and hashes in a single forward pass.
    ///
    /// `depths[i]` = number of nibbles of the key path consumed by
    /// `nodes[0..i]` (i.e., the depth of `nodes[i]` in the forward trie walk).
    ///
    /// `hashes[i]` = `nodes[i].hash()`.
    fn compute_depths_and_hashes(&self) -> Result<(Vec<usize>, Vec<Hash>), StorageError> {
        let mut depths = Vec::with_capacity(self.nodes.len());
        let mut hashes = Vec::with_capacity(self.nodes.len());
        let mut d = 0usize;

        for node in &self.nodes {
            depths.push(d);
            hashes.push(node.hash()?);
            d += match node {
                // Branch routes on one nibble — depth advances by 1.
                ProofNode::Branch { .. } => 1,
                // Extension compresses prefix.len() nibbles — depth advances accordingly.
                ProofNode::Extension { prefix, .. } => prefix.len(),
                // Leaf is always terminal; no next node uses its depth.
                ProofNode::Leaf { .. } => 0,
            };
        }

        Ok((depths, hashes))
    }

    /// Verify that `parent` at `depth` references `expected_child_hash`
    /// at the correct slot/child pointer.
    ///
    /// For Branch: `depth` is the nibble index in the key path that the
    /// Branch routes on.  `children[path[depth]]` must equal
    /// `expected_child_hash`.
    /// For Extension: the single `child` field must equal
    /// `expected_child_hash`.
    /// For Leaf: structurally impossible — Leaf has no children.
    fn verify_child_linkage(
        &self,
        parent: &ProofNode,
        expected_child_hash: Hash,
        path: &NibblePath,
        depth: usize,
        key_hex: &str,
    ) -> Result<(), StorageError> {
        match parent {
            ProofNode::Branch { children, .. } => {
                // `depth` is the nibble position this Branch routes on.
                let nibble = path.get(depth).ok_or_else(|| StorageError::InvalidProof {
                    key: key_hex.to_string(),
                })? as usize;
                let actual = children[nibble].ok_or_else(|| StorageError::InvalidProof {
                    key: key_hex.to_string(),
                })?;
                if actual != expected_child_hash {
                    return Err(StorageError::InvalidProof {
                        key: key_hex.to_string(),
                    });
                }
            }
            ProofNode::Extension { child, .. } => {
                if *child != expected_child_hash {
                    return Err(StorageError::InvalidProof {
                        key: key_hex.to_string(),
                    });
                }
            }
            ProofNode::Leaf { .. } => {
                // A Leaf can never parent another node.
                return Err(StorageError::InvalidProof {
                    key: key_hex.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Verify the terminal node (last in `nodes`) matches the proof claim.
    ///
    /// `terminal_depth` = nibbles consumed by all nodes before the terminal.
    /// The terminal node's expected remaining path is `full_path.skip(terminal_depth)`.
    ///
    /// ## Inclusion cases
    /// - `Leaf` terminal: leaf's stored path must equal the remaining key path,
    ///   and leaf's value must match the claimed value.
    /// - `Branch` terminal with path exhausted at the branch: `branch.value`
    ///   must match the claimed value (key ends exactly at this branch point).
    ///
    /// ## Non-inclusion cases
    /// - `Leaf` terminal with diverging path: key is absent because the only
    ///   candidate leaf leads to a different key.
    /// - `Branch` terminal: either the child slot was empty (key diverges here)
    ///   or the path was exhausted and the branch holds no value.  The hash
    ///   chain already verified the Branch's content — we just confirm the
    ///   claimed value is `None`.
    /// - `Extension` terminal with non-matching prefix: key diverges mid-prefix.
    fn verify_terminal_node(
        &self,
        full_path: &NibblePath,
        terminal_depth: usize,
        key_hex: &str,
    ) -> Result<(), StorageError> {
        let last = self
            .nodes
            .last()
            .ok_or_else(|| StorageError::InvalidProof {
                key: key_hex.to_string(),
            })?;

        // The remaining key path at the terminal node's depth.
        let remaining = full_path.skip(terminal_depth);

        match (last, &self.value) {
            // Inclusion via Leaf: stored path must equal the remaining key
            // path at this depth; value must match.
            (
                ProofNode::Leaf {
                    path: leaf_path,
                    value: leaf_val,
                },
                Some(claimed),
            ) => {
                if leaf_path != &remaining || leaf_val != claimed {
                    return Err(StorageError::InvalidProof {
                        key: key_hex.to_string(),
                    });
                }
            }
            // Inclusion via Branch value: path was exhausted at the branch.
            // CORR-2 / SEC-2: Also verify the path is actually exhausted here.
            // If remaining is non-empty, the Branch is not the correct terminal
            // for inclusion — the proof is forged or truncated.
            (
                ProofNode::Branch {
                    value: Some(branch_val),
                    ..
                },
                Some(claimed),
            ) => {
                if !remaining.is_empty() {
                    // Path not exhausted — Branch value inclusion is invalid here.
                    return Err(StorageError::InvalidProof {
                        key: key_hex.to_string(),
                    });
                }
                if branch_val != claimed {
                    return Err(StorageError::InvalidProof {
                        key: key_hex.to_string(),
                    });
                }
            }
            // Non-inclusion via Leaf: the leaf's path diverges from ours —
            // the key is absent.  If they were equal, it would be inclusion.
            (
                ProofNode::Leaf {
                    path: leaf_path, ..
                },
                None,
            ) => {
                if leaf_path == &remaining {
                    // Leaf path matches but value claimed None → contradiction.
                    return Err(StorageError::InvalidProof {
                        key: key_hex.to_string(),
                    });
                }
            }
            // Non-inclusion via Branch: either the path is exhausted with no
            // value stored here, or the child slot at the key's next nibble is
            // empty.  SEC-2: Verify the specific sub-case explicitly — the hash
            // chain confirms the Branch content; we verify the claim is coherent.
            (
                ProofNode::Branch {
                    value: branch_val,
                    children,
                },
                None,
            ) => {
                if remaining.is_empty() {
                    // Path exhausted — valid only if no value is stored here.
                    if branch_val.is_some() {
                        return Err(StorageError::InvalidProof {
                            key: key_hex.to_string(),
                        });
                    }
                } else {
                    // Path not exhausted — valid only if the child slot is empty.
                    let nibble = remaining.get(0).ok_or_else(|| StorageError::InvalidProof {
                        key: key_hex.to_string(),
                    })? as usize;
                    if children[nibble].is_some() {
                        // Child exists but was omitted — truncated/forged proof.
                        return Err(StorageError::InvalidProof {
                            key: key_hex.to_string(),
                        });
                    }
                }
            }
            // Non-inclusion via Extension: key's path didn't match the
            // extension prefix — divergence at this point.
            // SEC-1: Verify the key's remaining path does NOT start with the
            // extension prefix. If it does, the key could exist deeper — the
            // proof is truncated/forged.
            (ProofNode::Extension { prefix, .. }, None) => {
                if remaining.starts_with(prefix) {
                    return Err(StorageError::InvalidProof {
                        key: key_hex.to_string(),
                    });
                }
            }
            // All other combos are structurally invalid.
            _ => {
                return Err(StorageError::InvalidProof {
                    key: key_hex.to_string(),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
