//! # lemma-storage
//!
//! Persistent storage for the Lemma blockchain.
//!
//! Provides a RocksDB-backed store with column families for accounts, blocks,
//! transactions, receipts, and contract storage, plus a Blake3 Merkle Patricia
//! Trie for world-state proofs and state snapshot management.
//!
//! ## Crate structure
//!
//! | Module | Responsibility |
//! |--------|---------------|
//! | `error` | [`StorageError`] — single error type for all storage ops |
//! | `db` | RocksDB wrapper, column families, batch writes |
//! | `account` | [`Account`] struct |
//! | `trie` | Blake3 Merkle Patricia Trie + proofs |
//! | `state` | [`WorldState`] — typed account + contract storage access |
//! | `snapshot` | State snapshots for crash recovery |
//! | `chain` | [`ChainStore`] — typed block read/write/tip/range-sync access |

pub mod account;
pub mod chain;
pub mod db;
pub mod error;
pub mod snapshot;
pub mod state;
pub mod trie;

pub use account::Account;
pub use chain::ChainStore;
// Column family name constants (CF_STATE, CF_STORAGE, CF_TRIE_NODES, etc.)
// are implementation details of the RocksDB layer — not re-exported here.
// Access them via `lemma_storage::db::CF_*` if needed by integration code.
pub use db::LemmaDb;
pub use error::StorageError;
pub use snapshot::{SnapshotManager, SnapshotMetadata};
pub use state::WorldState;
pub use trie::{MerklePatriciaTrie, MerkleProof, NibblePath, ProofNode, TrieNode};
