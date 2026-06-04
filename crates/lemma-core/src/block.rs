//! Block — a finalized unit of state change in the Lemma chain.
//!
//! A [`Block`] pairs a [`BlockHeader`] with its transaction list and receipt
//! list. The header's root hashes (`transactions_root`, `receipts_root`,
//! `state_root`) commit to these lists; `lemma-storage` is responsible for
//! computing and verifying those roots.
//!
//! `lemma-core` enforces only **structural** invariants (receipt count matches
//! transaction count, gas accounting is consistent). Cryptographic verification
//! of root hashes and signatures is performed by `lemma-crypto`.
//!
//! See `docs/04-BUILD_GUIDE.md` Section 2.1 and AGENTS.md §7.

use serde::{Deserialize, Serialize};

use crate::{
    cert::QuorumCert,
    error::BlockError,
    header::BlockHeader,
    transaction::{Transaction, TransactionReceipt},
};

// ─── Block ───────────────────────────────────────────────────────────────────

/// A finalized Lemma block: header metadata + transaction list + receipt list.
///
/// The following structural invariants are enforced by [`Block::validate`]:
/// - `transactions.len() == receipts.len()` — one receipt per transaction.
/// - `header.gas_used == sum(receipt.gas_used)` — gas accounting consistency.
///
/// # Quorum certificate
///
/// `quorum_cert` carries the 2f+1 Pulse consensus certificate for this block.
/// It is `None` for the genesis block and for any block not yet certified
/// (Phase 1 range-sync). All blocks produced by the DAG consensus driver after
/// D·15a carry `Some(qc)`. Verification is performed by `CertifiedVerifier`
/// (D·15c) — **not** by `Block::validate`, which checks only structural
/// invariants.
///
/// # Serde
///
/// Serialized as a flat JSON object. The `header` is a nested object; both
/// lists are JSON arrays. `quorum_cert` serializes as `null` when `None`.
///
/// # Examples
///
/// ```no_run
/// use lemma_core::{block::Block, header::BlockHeader, Address, Amount, Hash};
///
/// let header = BlockHeader::new(
///     0, 1_700_000_000, Hash::zero(), Hash::zero(),
///     Hash::zero(), Hash::zero(), Address::zero(),
///     0, 0, Hash::zero(), Hash::zero(), Hash::zero(),
///     30_000_000, 0, Amount::from_drop(1_000_000_000), vec![],
/// ).unwrap();
/// let block = Block::new(header, vec![], vec![], None).unwrap();
/// assert!(block.is_empty());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// Metadata commitment — hashes, gas accounting, proposer, timestamp.
    pub header: BlockHeader,
    /// Ordered list of transactions included in this block.
    pub transactions: Vec<Transaction>,
    /// Execution outcomes — one receipt per transaction, in the same order.
    pub receipts: Vec<TransactionReceipt>,
    /// 2f+1 quorum certificate produced by Pulse consensus for this block.
    ///
    /// `None` for the genesis block and any block not yet certified
    /// (Phase 1 range-sync). `Some(qc)` for every block produced by the DAG
    /// consensus driver after D·15a. Verification is performed by
    /// `CertifiedVerifier` (D·15c) — NOT here.
    pub quorum_cert: Option<QuorumCert>,
}

impl Block {
    /// Create and validate a new `Block`.
    ///
    /// # Parameters
    ///
    /// - `quorum_cert` — the 2f+1 Pulse consensus certificate for this block,
    ///   or `None` for the genesis block / uncertified range-sync blocks.
    ///   QC verification is NOT performed here — use `CertifiedVerifier` (D·15c).
    ///
    /// # Errors
    ///
    /// - [`BlockError::ReceiptCountMismatch`] — `receipts.len() != transactions.len()`.
    /// - [`BlockError::GasAccountingMismatch`] — `header.gas_used` ≠ sum of receipt `gas_used`.
    /// - [`BlockError::GasLimitZero`] — propagated from [`BlockHeader::validate`].
    /// - [`BlockError::GasExceeded`] — propagated from [`BlockHeader::validate`].
    pub fn new(
        header: BlockHeader,
        transactions: Vec<Transaction>,
        receipts: Vec<TransactionReceipt>,
        quorum_cert: Option<QuorumCert>,
    ) -> Result<Self, BlockError> {
        let block = Self {
            header,
            transactions,
            receipts,
            quorum_cert,
        };
        block.validate()?;
        Ok(block)
    }

    /// Validate structural invariants.
    ///
    /// Called automatically by [`Block::new`]. Exposed publicly so that
    /// deserialized blocks can be re-validated after round-tripping.
    ///
    /// Checks run in order:
    /// 1. `receipts.len() == transactions.len()`
    /// 2. Header structural invariants (via [`BlockHeader::validate`])
    /// 3. `header.gas_used == sum(receipt.gas_used)` — gas accounting consistency
    ///
    /// # Errors
    ///
    /// - [`BlockError::ReceiptCountMismatch`] — list length mismatch.
    /// - [`BlockError::GasLimitZero`] — re-raised from [`BlockHeader::validate`].
    /// - [`BlockError::GasExceeded`] — re-raised from [`BlockHeader::validate`].
    /// - [`BlockError::GasAccountingMismatch`] — header `gas_used` ≠ sum of receipt `gas_used`.
    pub fn validate(&self) -> Result<(), BlockError> {
        if self.receipts.len() != self.transactions.len() {
            return Err(BlockError::ReceiptCountMismatch {
                transactions: self.transactions.len(),
                receipts: self.receipts.len(),
            });
        }
        // Delegate header structural checks (gas_limit > 0, gas_used <= gas_limit).
        self.header.validate()?;

        // Verify header.gas_used equals the sum of per-receipt gas consumption.
        // A block cannot claim different gas than its receipts actually consumed —
        // this catches tampered headers and incorrectly assembled blocks.
        let receipts_gas: u64 = self.receipts.iter().map(|r| r.gas_used).sum();
        if self.header.gas_used != receipts_gas {
            return Err(BlockError::GasAccountingMismatch {
                header_gas_used: self.header.gas_used,
                receipts_gas_used: receipts_gas,
            });
        }
        Ok(())
    }

    // ── Predicates ────────────────────────────────────────────────────────────

    /// Returns `true` if the block contains no transactions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Returns `true` if this is the genesis block (height 0).
    #[must_use]
    pub fn is_genesis(&self) -> bool {
        self.header.is_genesis()
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Returns the number of transactions in the block.
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Returns the block height from the header.
    #[must_use]
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Returns the block timestamp (Unix seconds) from the header.
    #[must_use]
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
