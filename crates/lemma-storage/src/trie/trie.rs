//! Merkle Patricia Trie — insert, get, and root hash computation.
//!
//! [`MerklePatriciaTrie`] is a content-addressed key-value store where every
//! node is keyed by its Blake3 hash. Insertions build or restructure the trie
//! path from root to leaf, writing all new nodes atomically to the
//! `trie_nodes` RocksDB column family.
//!
//! ## Algorithm
//!
//! Keys are decomposed into 64-nibble paths (for 32-byte keys). The trie has
//! three node types (see [`trie::node`]):
//!
//! - **Branch**: 16-way fork keyed by the next nibble.
//! - **Extension**: path compression for shared prefixes.
//! - **Leaf**: terminal node storing the value.
//!
//! Insertions may create Branch nodes (when two paths diverge), Extension
//! nodes (when they share a prefix), or simply update a Leaf in place.
//!
//! ## Recursion depth
//!
//! A 32-byte key produces 64 nibbles — maximum recursion depth is 64.
//! No stack overflow risk.
//!
//! ## Batch writes
//!
//! Each [`insert`] creates an internal `WriteBatch` covering all nodes
//! written during that call, then commits it atomically. WorldState (Step 7)
//! will layer block-level batching on top via [`LemmaDb::write_batch`].
//!
//! [`insert`]: MerklePatriciaTrie::insert
//! [`trie::node`]: crate::trie::node

use lemma_core::Hash;
use rocksdb::WriteBatch;

use crate::{
    db::{LemmaDb, CF_TRIE_NODES},
    trie::{
        node::{NibblePath, TrieNode},
        proof::{MerkleProof, ProofNode},
    },
    StorageError,
};

// ─── MerklePatriciaTrie ───────────────────────────────────────────────────────

/// A content-addressed Merkle Patricia Trie backed by RocksDB.
///
/// Nodes are stored in the `trie_nodes` column family, keyed by their
/// Blake3 hash. The trie's current state is summarised by [`root`] — a
/// single [`Hash`] that commits to all inserted key-value pairs.
///
/// Tied to a `&'db LemmaDb` lifetime: the trie does not own the database.
/// `WorldState` (Step 7) owns the `LemmaDb` and passes references to tries.
///
/// ## Not yet implemented
///
/// - `delete(key)` — Step 6 or later. [`TrieNode::child_count`] is already
///   implemented to support branch collapsing on delete.
/// - `contains(key)` — can be implemented as `get(key).map(|v| v.is_some())`.
///
/// [`root`]: MerklePatriciaTrie::root
/// [`TrieNode::child_count`]: crate::trie::node::TrieNode::child_count
pub struct MerklePatriciaTrie<'db> {
    db: &'db LemmaDb,
    root: Option<Hash>,
}

impl<'db> MerklePatriciaTrie<'db> {
    /// Create a new empty trie backed by `db`.
    pub fn new(db: &'db LemmaDb) -> Self {
        Self { db, root: None }
    }

    /// Create a trie rooted at an existing `root` hash.
    ///
    /// Used when resuming a trie from a persisted state root (e.g. from
    /// [`BlockHeader::state_root`]).
    ///
    /// # Error behavior
    ///
    /// This constructor does **not** validate that `root` exists in `db`.
    /// The first call to [`get`] or [`insert`] will return
    /// [`StorageError::TrieNodeNotFound`] if `root` is not present in the
    /// `trie_nodes` column family (e.g. DB corruption or wrong hash).
    ///
    /// [`BlockHeader::state_root`]: lemma_core::BlockHeader::state_root
    /// [`get`]: MerklePatriciaTrie::get
    /// [`insert`]: MerklePatriciaTrie::insert
    pub fn with_root(db: &'db LemmaDb, root: Hash) -> Self {
        Self {
            db,
            root: Some(root),
        }
    }

    /// The current root hash, or `None` if the trie is empty.
    ///
    /// This hash is the cryptographic commitment to all key-value pairs in
    /// the trie. It is stored as [`BlockHeader::state_root`] at block boundary.
    ///
    /// [`BlockHeader::state_root`]: lemma_core::BlockHeader::state_root
    pub fn root(&self) -> Option<Hash> {
        self.root
    }

    /// Insert or update `key` → `value` in the trie.
    ///
    /// All new and modified nodes are written atomically to the `trie_nodes`
    /// column family. The root hash is updated on success.
    ///
    /// # Errors
    ///
    /// - [`StorageError::TrieNodeNotFound`] — a referenced node is missing
    ///   from storage (indicates DB corruption).
    /// - [`StorageError::SerializationFailed`] — bincode encode/decode failed.
    /// - [`StorageError::BatchFailed`] — RocksDB batch commit failed.
    pub fn insert(&mut self, key: &[u8], value: Vec<u8>) -> Result<(), StorageError> {
        let path = NibblePath::from_bytes(key);
        let mut batch = self.db.new_batch();
        let new_root = self.insert_recursive(&mut batch, self.root, path, value)?;
        self.db.write_batch(batch)?;
        self.root = Some(new_root);
        Ok(())
    }

    /// Look up `key` in the trie.
    ///
    /// Returns `Ok(Some(value))` if the key exists, `Ok(None)` if not.
    ///
    /// # Errors
    ///
    /// - [`StorageError::TrieNodeNotFound`] — a referenced node is missing.
    /// - [`StorageError::SerializationFailed`] — bincode decode failed.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let path = NibblePath::from_bytes(key);
        self.get_recursive(self.root, path)
    }

    /// Generate a Merkle proof for `key` against the current trie state.
    ///
    /// Returns an **inclusion proof** (`value = Some(v)`) if the key exists,
    /// or a **non-inclusion proof** (`value = None`) if the key is absent.
    ///
    /// The proof can be verified offline against the root hash via
    /// [`MerkleProof::verify`].
    ///
    /// # Errors
    ///
    /// - [`StorageError::InvalidProof`] — trie is empty (no root to prove against).
    /// - [`StorageError::TrieNodeNotFound`] — a referenced node is missing from
    ///   storage (DB corruption).
    /// - [`StorageError::SerializationFailed`] — bincode decode failed.
    pub fn generate_proof(&self, key: &[u8]) -> Result<MerkleProof, StorageError> {
        let key_hex = hex::encode(key);
        let root = self
            .root
            .ok_or(StorageError::InvalidProof { key: key_hex })?;
        let path = NibblePath::from_bytes(key);
        let mut proof_nodes = Vec::new();
        let value = self.collect_proof(root, path, &mut proof_nodes)?;
        Ok(MerkleProof {
            key: key.to_vec(),
            value,
            nodes: proof_nodes,
        })
    }

    // ── Node I/O ──────────────────────────────────────────────────────────────

    /// Load a node from the `trie_nodes` CF by its hash.
    fn load_node(&self, hash: Hash) -> Result<TrieNode, StorageError> {
        let bytes = self
            .db
            .get(CF_TRIE_NODES, hash.as_bytes())?
            .ok_or_else(|| StorageError::TrieNodeNotFound {
                hash: hash.to_string(),
            })?;
        bincode::deserialize(&bytes).map_err(StorageError::from)
    }

    /// Serialize `node`, add it to `batch` keyed by its hash, return that hash.
    fn store_node(&self, batch: &mut WriteBatch, node: &TrieNode) -> Result<Hash, StorageError> {
        let hash = node.hash()?;
        let encoded = bincode::serialize(node)?;
        self.db
            .batch_put(batch, CF_TRIE_NODES, hash.as_bytes(), &encoded)?;
        Ok(hash)
    }

    // ── Get (recursive) ───────────────────────────────────────────────────────

    fn get_recursive(
        &self,
        node_hash: Option<Hash>,
        path: NibblePath,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let hash = match node_hash {
            None => return Ok(None),
            Some(h) => h,
        };
        match self.load_node(hash)? {
            TrieNode::Leaf { path: lp, value } => Ok(if lp == path { Some(value) } else { None }),
            TrieNode::Extension { prefix, child } => {
                if path.starts_with(&prefix) {
                    self.get_recursive(Some(child), path.skip(prefix.len()))
                } else {
                    Ok(None)
                }
            }
            TrieNode::Branch {
                children,
                value: bv,
            } => {
                if path.is_empty() {
                    Ok(bv)
                } else {
                    // path is non-empty: guarded by is_empty() check above.
                    let nibble = path
                        .get(0)
                        .expect("path non-empty: guarded by is_empty() check")
                        as usize;
                    self.get_recursive(children[nibble], path.skip(1))
                }
            }
        }
    }

    // ── Proof collection (recursive) ─────────────────────────────────────────

    /// Walk the trie from `node_hash` toward `path`, appending each visited
    /// node to `out` as a [`ProofNode`].
    ///
    /// Returns `Some(value)` if the key is found (inclusion), `None` if not
    /// (non-inclusion). Either way, `out` holds the complete proof path.
    fn collect_proof(
        &self,
        node_hash: Hash,
        path: NibblePath,
        out: &mut Vec<ProofNode>,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        let node = self.load_node(node_hash)?;
        match node {
            TrieNode::Leaf {
                path: leaf_path,
                value: leaf_val,
            } => {
                out.push(ProofNode::Leaf {
                    path: leaf_path.clone(),
                    value: leaf_val.clone(),
                });
                Ok(if leaf_path == path {
                    Some(leaf_val)
                } else {
                    None
                })
            }
            TrieNode::Extension { prefix, child } => {
                let prefix_len = prefix.len();
                let starts = path.starts_with(&prefix);
                out.push(ProofNode::Extension { prefix, child });
                if starts {
                    self.collect_proof(child, path.skip(prefix_len), out)
                } else {
                    // Key diverges at this extension — non-inclusion.
                    Ok(None)
                }
            }
            TrieNode::Branch {
                children,
                value: branch_val,
            } => {
                out.push(ProofNode::Branch {
                    children,
                    value: branch_val.clone(),
                });
                if path.is_empty() {
                    // Path exhausted at this branch — value stored here.
                    Ok(branch_val)
                } else {
                    // path is non-empty: guarded by is_empty() check above.
                    let nibble = path
                        .get(0)
                        .expect("path non-empty: guarded by is_empty() check")
                        as usize;
                    match children[nibble] {
                        Some(child_hash) => self.collect_proof(child_hash, path.skip(1), out),
                        None => {
                            // Empty child slot — key is absent.
                            Ok(None)
                        }
                    }
                }
            }
        }
    }

    // ── Insert (recursive, dispatch) ──────────────────────────────────────────

    fn insert_recursive(
        &self,
        batch: &mut WriteBatch,
        node_hash: Option<Hash>,
        path: NibblePath,
        value: Vec<u8>,
    ) -> Result<Hash, StorageError> {
        match node_hash {
            // Empty slot: create a leaf directly.
            None => self.store_node(batch, &TrieNode::leaf(path, value)),
            Some(h) => match self.load_node(h)? {
                TrieNode::Leaf {
                    path: lp,
                    value: lv,
                } => self.insert_at_leaf(batch, lp, lv, path, value),
                TrieNode::Extension { prefix, child } => {
                    self.insert_at_extension(batch, prefix, child, path, value)
                }
                TrieNode::Branch {
                    children,
                    value: bv,
                } => self.insert_at_branch(batch, children, bv, path, value),
            },
        }
    }

    // ── Insert at Branch ──────────────────────────────────────────────────────

    fn insert_at_branch(
        &self,
        batch: &mut WriteBatch,
        mut children: [Option<Hash>; 16],
        branch_value: Option<Vec<u8>>,
        path: NibblePath,
        value: Vec<u8>,
    ) -> Result<Hash, StorageError> {
        if path.is_empty() {
            // Key terminates at this branch — update the branch value.
            return self.store_node(
                batch,
                &TrieNode::Branch {
                    children,
                    value: Some(value),
                },
            );
        }
        // path is non-empty: guarded by is_empty() check above.
        let nibble = path
            .get(0)
            .expect("path non-empty: guarded by is_empty() check") as usize;
        let new_child = self.insert_recursive(batch, children[nibble], path.skip(1), value)?;
        children[nibble] = Some(new_child);
        self.store_node(
            batch,
            &TrieNode::Branch {
                children,
                value: branch_value,
            },
        )
    }

    // ── Insert at Extension ───────────────────────────────────────────────────

    fn insert_at_extension(
        &self,
        batch: &mut WriteBatch,
        prefix: NibblePath,
        child: Hash,
        path: NibblePath,
        new_value: Vec<u8>,
    ) -> Result<Hash, StorageError> {
        let common = path.common_prefix_len(&prefix);
        if common == prefix.len() {
            // The entire extension prefix is consumed by `path`. Recurse into the
            // child with the remaining path, then re-wrap with the same Extension
            // prefix — the Extension node is structurally unchanged; only its
            // child hash may point to a new/updated subtree.
            let nc = self.insert_recursive(batch, Some(child), path.skip(common), new_value)?;
            return self.store_node(batch, &TrieNode::extension(prefix, nc));
        }
        // Path diverges inside the prefix — split the extension at `common`.
        let branch_hash = self.split_extension(batch, &prefix, child, &path, new_value, common)?;
        if common > 0 {
            // Use the existing prefix for the new Extension — not `path`.
            // Both share the same first `common` nibbles by definition of
            // `common_prefix_len`, but using `prefix` is semantically correct:
            // the Extension encodes the existing trie structure, not the new key.
            let ext = TrieNode::extension(prefix.take(common), branch_hash);
            self.store_node(batch, &ext)
        } else {
            Ok(branch_hash)
        }
    }

    /// Split an Extension at `common` nibbles when `path` diverges.
    fn split_extension(
        &self,
        batch: &mut WriteBatch,
        prefix: &NibblePath,
        child: Hash,
        path: &NibblePath,
        new_value: Vec<u8>,
        common: usize,
    ) -> Result<Hash, StorageError> {
        let mut branch = TrieNode::empty_branch();
        // Precondition: `common < prefix.len()` is guaranteed by the caller
        // (`insert_at_extension` returns early when `common == prefix.len()`).
        let ext_nibble = prefix
            .get(common)
            .expect("split_extension: common < prefix.len() guaranteed by caller")
            as usize;
        // Remaining extension tail (if the prefix was longer than 1 nibble past `common`).
        if common + 1 < prefix.len() {
            let sub = TrieNode::extension(prefix.skip(common + 1), child);
            let sub_hash = self.store_node(batch, &sub)?;
            branch.set_child(ext_nibble, sub_hash);
        } else {
            branch.set_child(ext_nibble, child);
        }
        // Place the new value into the branch.
        if path.len() == common {
            if let TrieNode::Branch { ref mut value, .. } = branch {
                *value = Some(new_value);
            }
        } else {
            // path.len() != common is guaranteed by the outer if-else.
            let n = path
                .get(common)
                .expect("split_extension: path.len() > common guaranteed by if-else")
                as usize;
            let leaf = TrieNode::leaf(path.skip(common + 1), new_value);
            let lh = self.store_node(batch, &leaf)?;
            branch.set_child(n, lh);
        }
        self.store_node(batch, &branch)
    }

    // ── Insert at Leaf ────────────────────────────────────────────────────────

    fn insert_at_leaf(
        &self,
        batch: &mut WriteBatch,
        leaf_path: NibblePath,
        leaf_value: Vec<u8>,
        new_path: NibblePath,
        new_value: Vec<u8>,
    ) -> Result<Hash, StorageError> {
        let common = leaf_path.common_prefix_len(&new_path);
        if common == leaf_path.len() && common == new_path.len() {
            // Exact key match — update value in place.
            return self.store_node(batch, &TrieNode::leaf(leaf_path, new_value));
        }
        // Paths diverge — build a branch (wrapped in an extension if common > 0).
        // Capture the shared prefix BEFORE moving leaf_path into build_diverging_branch.
        // Use leaf_path (the existing path) for the Extension — not new_path. Both share
        // the same first `common` nibbles by definition, but the existing path is canonical.
        let shared_prefix = leaf_path.take(common);
        let bh = self
            .build_diverging_branch(batch, leaf_path, leaf_value, &new_path, new_value, common)?;
        if common > 0 {
            let ext = TrieNode::extension(shared_prefix, bh);
            self.store_node(batch, &ext)
        } else {
            Ok(bh)
        }
    }

    /// Build the Branch node at the point where `leaf_path` and `new_path` diverge.
    fn build_diverging_branch(
        &self,
        batch: &mut WriteBatch,
        leaf_path: NibblePath,
        leaf_value: Vec<u8>,
        new_path: &NibblePath,
        new_value: Vec<u8>,
        common: usize,
    ) -> Result<Hash, StorageError> {
        let mut branch = TrieNode::empty_branch();
        // Place existing leaf (or make it the branch value if its key ends here).
        if leaf_path.len() == common {
            if let TrieNode::Branch { ref mut value, .. } = branch {
                *value = Some(leaf_value);
            }
        } else {
            // leaf_path.len() != common guaranteed by the outer if-else.
            let n = leaf_path
                .get(common)
                .expect("build_diverging_branch: leaf_path.len() > common guaranteed")
                as usize;
            let leaf = TrieNode::leaf(leaf_path.skip(common + 1), leaf_value);
            branch.set_child(n, self.store_node(batch, &leaf)?);
        }
        // Place new value (or new leaf if the new key extends beyond `common`).
        if new_path.len() == common {
            if let TrieNode::Branch { ref mut value, .. } = branch {
                *value = Some(new_value);
            }
        } else {
            // new_path.len() != common guaranteed by the outer if-else.
            let n = new_path
                .get(common)
                .expect("build_diverging_branch: new_path.len() > common guaranteed")
                as usize;
            let leaf = TrieNode::leaf(new_path.skip(common + 1), new_value);
            branch.set_child(n, self.store_node(batch, &leaf)?);
        }
        self.store_node(batch, &branch)
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
