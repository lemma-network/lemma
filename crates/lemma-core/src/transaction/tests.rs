//! Tests for `lemma_core::transaction`.
//!
//! Covers `TxType`, `Log`, `Transaction`, and `TransactionReceipt`:
//! predicates, validation rules, serde round-trips, and derived traits.
//! 100% public API coverage per AGENTS.md §11.1.

use super::*;
use crate::{address::Address, amount::Amount, hash::Hash, signature::Signature};

// ── Shared fixtures ───────────────────────────────────────────────────────────

fn sender() -> Address {
    Address::zero()
}

fn recipient() -> Address {
    Address::burn()
}

fn tx_hash() -> Hash {
    Hash::zero()
}

fn gas_price() -> Amount {
    Amount::from_drop(1_000_000_000) // 1 Drip
}

fn sig_classical() -> Signature {
    Signature::Classical {
        bytes: vec![0xC1u8; 64],
    }
}

fn sig_post_quantum() -> Signature {
    Signature::PostQuantum {
        bytes: vec![0xD1u8; 32],
    }
}

fn sig_hybrid() -> Signature {
    Signature::Hybrid {
        classical: vec![0xC1u8; 64],
        quantum: vec![0xD1u8; 32],
    }
}

fn test_log() -> Log {
    Log::new(recipient(), vec![tx_hash()], vec![0xDE, 0xAD])
}

/// Minimal valid Transfer transaction.
fn transfer_tx() -> Transaction {
    Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        0,
        1,
        Amount::zero(),
        21_000,
        gas_price(),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .unwrap()
}

/// Minimal valid ContractDeploy transaction (non-empty calldata).
fn deploy_tx() -> Transaction {
    Transaction::new(
        tx_hash(),
        sender(),
        None,
        0,
        1,
        Amount::zero(),
        100_000,
        gas_price(),
        TxType::ContractDeploy,
        vec![0x60, 0x80], // mock bytecode prefix
        Signature::Unsigned,
    )
    .unwrap()
}

/// Minimal valid ContractCall transaction (non-empty calldata, has `to`).
fn call_tx() -> Transaction {
    Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        1,
        1,
        Amount::zero(),
        50_000,
        gas_price(),
        TxType::ContractCall,
        vec![0xA9, 0x05, 0x9C, 0xBB], // mock 4-byte selector
        sig_classical(),
    )
    .unwrap()
}

/// Minimal valid Stake transaction.
fn stake_tx() -> Transaction {
    Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        0,
        1,
        Amount::from_drop(100_000),
        21_000,
        gas_price(),
        TxType::Stake,
        vec![],
        Signature::Unsigned,
    )
    .unwrap()
}

/// Minimal valid Unstake transaction.
fn unstake_tx() -> Transaction {
    Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        1,
        1,
        Amount::from_drop(50_000),
        21_000,
        gas_price(),
        TxType::Unstake,
        vec![],
        Signature::Unsigned,
    )
    .unwrap()
}

/// Minimal valid GovernanceVote transaction.
///
/// `data` carries a minimal non-empty payload standing in for a real
/// `(proposal_id, choice)` ABI encoding — exact encoding is a Phase 3
/// concern (governance system contract + Lem ABI). Any non-empty `data`
/// satisfies the `requires_calldata` constraint.
fn governance_vote_tx() -> Transaction {
    Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()), // governance system-contract address (placeholder)
        2,
        1,
        Amount::zero(), // votes carry no LEM value
        21_000,
        gas_price(),
        TxType::GovernanceVote,
        vec![0x00, 0x00, 0x00, 0x01, 0x01], // stub: proposal_id=1, choice=1
        Signature::Unsigned,
    )
    .unwrap()
}

// ── TxType — is_contract_deploy ───────────────────────────────────────────────

#[test]
fn tx_type_is_contract_deploy_true_for_contract_deploy() {
    assert!(TxType::ContractDeploy.is_contract_deploy());
}

#[test]
fn tx_type_is_contract_deploy_false_for_transfer() {
    assert!(!TxType::Transfer.is_contract_deploy());
}

#[test]
fn tx_type_is_contract_deploy_false_for_contract_call() {
    assert!(!TxType::ContractCall.is_contract_deploy());
}

#[test]
fn tx_type_is_contract_deploy_false_for_stake() {
    assert!(!TxType::Stake.is_contract_deploy());
}

#[test]
fn tx_type_is_contract_deploy_false_for_unstake() {
    assert!(!TxType::Unstake.is_contract_deploy());
}

#[test]
fn tx_type_is_contract_deploy_false_for_governance_vote() {
    assert!(!TxType::GovernanceVote.is_contract_deploy());
}

// ── TxType — requires_recipient ───────────────────────────────────────────────

#[test]
fn tx_type_requires_recipient_true_for_transfer() {
    assert!(TxType::Transfer.requires_recipient());
}

#[test]
fn tx_type_requires_recipient_true_for_contract_call() {
    assert!(TxType::ContractCall.requires_recipient());
}

#[test]
fn tx_type_requires_recipient_false_for_contract_deploy() {
    assert!(!TxType::ContractDeploy.requires_recipient());
}

#[test]
fn tx_type_requires_recipient_true_for_stake() {
    assert!(TxType::Stake.requires_recipient());
}

#[test]
fn tx_type_requires_recipient_true_for_unstake() {
    assert!(TxType::Unstake.requires_recipient());
}

#[test]
fn tx_type_requires_recipient_true_for_governance_vote() {
    // GovernanceVote is sent to the governance system-contract address.
    assert!(TxType::GovernanceVote.requires_recipient());
}

// ── TxType — requires_calldata ────────────────────────────────────────────────

#[test]
fn tx_type_requires_calldata_false_for_transfer() {
    assert!(!TxType::Transfer.requires_calldata());
}

#[test]
fn tx_type_requires_calldata_true_for_contract_call() {
    assert!(TxType::ContractCall.requires_calldata());
}

#[test]
fn tx_type_requires_calldata_true_for_contract_deploy() {
    assert!(TxType::ContractDeploy.requires_calldata());
}

#[test]
fn tx_type_requires_calldata_false_for_stake() {
    assert!(!TxType::Stake.requires_calldata());
}

#[test]
fn tx_type_requires_calldata_false_for_unstake() {
    assert!(!TxType::Unstake.requires_calldata());
}

#[test]
fn tx_type_requires_calldata_true_for_governance_vote() {
    // GovernanceVote carries (proposal_id: u64, choice: u8) in data — required.
    assert!(TxType::GovernanceVote.requires_calldata());
}

// ── TxType — Display ──────────────────────────────────────────────────────────

#[test]
fn tx_type_display_transfer() {
    assert_eq!(TxType::Transfer.to_string(), "Transfer");
}

#[test]
fn tx_type_display_contract_call() {
    assert_eq!(TxType::ContractCall.to_string(), "ContractCall");
}

#[test]
fn tx_type_display_contract_deploy() {
    assert_eq!(TxType::ContractDeploy.to_string(), "ContractDeploy");
}

#[test]
fn tx_type_display_stake() {
    assert_eq!(TxType::Stake.to_string(), "Stake");
}

#[test]
fn tx_type_display_unstake() {
    assert_eq!(TxType::Unstake.to_string(), "Unstake");
}

#[test]
fn tx_type_display_governance_vote() {
    assert_eq!(TxType::GovernanceVote.to_string(), "GovernanceVote");
}

// ── TxType — Serde ────────────────────────────────────────────────────────────

#[test]
fn tx_type_transfer_roundtrips_through_json() {
    let json = serde_json::to_string(&TxType::Transfer).unwrap();
    let decoded: TxType = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, TxType::Transfer);
}

#[test]
fn tx_type_contract_call_roundtrips_through_json() {
    let json = serde_json::to_string(&TxType::ContractCall).unwrap();
    let decoded: TxType = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, TxType::ContractCall);
}

#[test]
fn tx_type_contract_deploy_roundtrips_through_json() {
    let json = serde_json::to_string(&TxType::ContractDeploy).unwrap();
    let decoded: TxType = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, TxType::ContractDeploy);
}

#[test]
fn tx_type_stake_roundtrips_through_json() {
    let json = serde_json::to_string(&TxType::Stake).unwrap();
    let decoded: TxType = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, TxType::Stake);
}

#[test]
fn tx_type_unstake_roundtrips_through_json() {
    let json = serde_json::to_string(&TxType::Unstake).unwrap();
    let decoded: TxType = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, TxType::Unstake);
}

#[test]
fn tx_type_governance_vote_roundtrips_through_json() {
    let json = serde_json::to_string(&TxType::GovernanceVote).unwrap();
    let decoded: TxType = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, TxType::GovernanceVote);
}

#[test]
fn tx_type_serializes_to_snake_case() {
    assert_eq!(
        serde_json::to_string(&TxType::Transfer).unwrap(),
        "\"transfer\""
    );
    assert_eq!(
        serde_json::to_string(&TxType::ContractCall).unwrap(),
        "\"contract_call\""
    );
    assert_eq!(
        serde_json::to_string(&TxType::ContractDeploy).unwrap(),
        "\"contract_deploy\""
    );
    assert_eq!(serde_json::to_string(&TxType::Stake).unwrap(), "\"stake\"");
    assert_eq!(
        serde_json::to_string(&TxType::Unstake).unwrap(),
        "\"unstake\""
    );
    assert_eq!(
        serde_json::to_string(&TxType::GovernanceVote).unwrap(),
        "\"governance_vote\""
    );
}

// ── TxType — Clone / Copy / PartialEq / Hash ─────────────────────────────────

#[test]
fn tx_type_clone_equals_original() {
    assert_eq!(TxType::Transfer.clone(), TxType::Transfer);
}

#[test]
fn tx_type_copy_semantics() {
    let t = TxType::Stake;
    let u = t; // Copy, not move
    assert_eq!(t, u);
}

#[test]
fn tx_type_different_variants_are_not_equal() {
    assert_ne!(TxType::Transfer, TxType::ContractCall);
    assert_ne!(TxType::ContractDeploy, TxType::Stake);
}

// ── Log ───────────────────────────────────────────────────────────────────────

#[test]
fn log_new_stores_address_topics_and_data() {
    let log = Log::new(recipient(), vec![tx_hash()], vec![0x01, 0x02]);
    assert_eq!(log.address, recipient());
    assert_eq!(log.topics.len(), 1);
    assert_eq!(log.data, vec![0x01, 0x02]);
}

#[test]
fn log_topic_returns_some_at_valid_index() {
    let log = test_log();
    assert_eq!(log.topic(0), Some(&tx_hash()));
}

#[test]
fn log_topic_returns_none_at_out_of_bounds_index() {
    let log = test_log(); // has 1 topic
    assert!(log.topic(1).is_none());
    assert!(log.topic(100).is_none());
}

#[test]
fn log_with_empty_topics_topic_returns_none() {
    let log = Log::new(sender(), vec![], vec![]);
    assert!(log.topic(0).is_none());
}

#[test]
fn log_roundtrips_through_json() {
    let original = test_log();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Log = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn log_clone_equals_original() {
    let log = test_log();
    assert_eq!(log.clone(), log);
}

// ── Transaction — valid construction ─────────────────────────────────────────

#[test]
fn transaction_new_transfer_with_valid_fields_succeeds() {
    let tx = transfer_tx();
    assert_eq!(tx.tx_type, TxType::Transfer);
    assert_eq!(tx.gas_limit, 21_000);
}

#[test]
fn transaction_new_contract_deploy_with_valid_fields_succeeds() {
    let tx = deploy_tx();
    assert_eq!(tx.tx_type, TxType::ContractDeploy);
    assert!(tx.to.is_none());
    assert!(!tx.data.is_empty());
}

#[test]
fn transaction_new_contract_call_with_valid_fields_succeeds() {
    let tx = call_tx();
    assert_eq!(tx.tx_type, TxType::ContractCall);
    assert!(tx.to.is_some());
    assert!(!tx.data.is_empty());
}

#[test]
fn transaction_new_stake_with_valid_fields_succeeds() {
    assert_eq!(stake_tx().tx_type, TxType::Stake);
}

#[test]
fn transaction_new_unstake_with_valid_fields_succeeds() {
    assert_eq!(unstake_tx().tx_type, TxType::Unstake);
}

#[test]
fn transaction_new_governance_vote_with_valid_fields_succeeds() {
    assert_eq!(governance_vote_tx().tx_type, TxType::GovernanceVote);
}

// ── Transaction — validation failures ─────────────────────────────────────────

#[test]
fn transaction_new_rejects_zero_gas_limit() {
    let result = Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        0,
        1,
        Amount::zero(),
        0, // invalid
        gas_price(),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    );
    assert_eq!(result.unwrap_err(), TransactionError::ZeroGasLimit);
}

#[test]
fn transaction_new_transfer_without_to_returns_missing_recipient() {
    let result = Transaction::new(
        tx_hash(),
        sender(),
        None, // Transfer requires to
        0,
        1,
        Amount::zero(),
        21_000,
        gas_price(),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    );
    assert!(matches!(
        result.unwrap_err(),
        TransactionError::MissingRecipient { tx_type } if tx_type == "Transfer"
    ));
}

#[test]
fn transaction_new_contract_call_without_to_returns_missing_recipient() {
    let result = Transaction::new(
        tx_hash(),
        sender(),
        None,
        0,
        1,
        Amount::zero(),
        50_000,
        gas_price(),
        TxType::ContractCall,
        vec![0xA9, 0x05, 0x9C, 0xBB],
        Signature::Unsigned,
    );
    assert!(matches!(
        result.unwrap_err(),
        TransactionError::MissingRecipient { tx_type } if tx_type == "ContractCall"
    ));
}

#[test]
fn transaction_new_contract_deploy_with_to_returns_unexpected_recipient() {
    let result = Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()), // ContractDeploy must have no `to`
        0,
        1,
        Amount::zero(),
        100_000,
        gas_price(),
        TxType::ContractDeploy,
        vec![0x60, 0x80],
        Signature::Unsigned,
    );
    assert_eq!(result.unwrap_err(), TransactionError::UnexpectedRecipient);
}

#[test]
fn transaction_new_contract_call_without_data_returns_missing_calldata() {
    let result = Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        0,
        1,
        Amount::zero(),
        50_000,
        gas_price(),
        TxType::ContractCall,
        vec![], // calldata required
        Signature::Unsigned,
    );
    assert!(matches!(
        result.unwrap_err(),
        TransactionError::MissingCalldata { tx_type } if tx_type == "ContractCall"
    ));
}

#[test]
fn transaction_new_contract_deploy_without_data_returns_missing_calldata() {
    let result = Transaction::new(
        tx_hash(),
        sender(),
        None,
        0,
        1,
        Amount::zero(),
        100_000,
        gas_price(),
        TxType::ContractDeploy,
        vec![], // bytecode required
        Signature::Unsigned,
    );
    assert!(matches!(
        result.unwrap_err(),
        TransactionError::MissingCalldata { tx_type } if tx_type == "ContractDeploy"
    ));
}

// ── Transaction — validate negative paths ─────────────────────────────────────

#[test]
fn transaction_validate_rejects_zero_gas_limit_on_deserialized_transaction() {
    // Construct directly (bypassing new()) to simulate a tampered deserialized tx —
    // this is exactly the scenario validate() is designed to catch post-deserialization.
    let tx = Transaction {
        hash: tx_hash(),
        sender: sender(),
        to: Some(recipient()),
        nonce: 0,
        chain_id: 1,
        value: Amount::zero(),
        gas_limit: 0, // tampered field
        gas_price: gas_price(),
        tx_type: TxType::Transfer,
        data: vec![],
        signature: Signature::Unsigned,
        session_key: None,
        owner_cosignature: None,
    };
    assert_eq!(tx.validate().unwrap_err(), TransactionError::ZeroGasLimit);
}

#[test]
fn transaction_validate_rejects_missing_recipient_on_deserialized_transaction() {
    let tx = Transaction {
        hash: tx_hash(),
        sender: sender(),
        to: None, // tampered: Transfer requires a recipient
        nonce: 0,
        chain_id: 1,
        value: Amount::zero(),
        gas_limit: 21_000,
        gas_price: gas_price(),
        tx_type: TxType::Transfer,
        data: vec![],
        signature: Signature::Unsigned,
        session_key: None,
        owner_cosignature: None,
    };
    assert!(matches!(
        tx.validate().unwrap_err(),
        TransactionError::MissingRecipient { .. }
    ));
}

#[test]
fn transaction_validate_rejects_unexpected_recipient_on_deserialized_transaction() {
    let tx = Transaction {
        hash: tx_hash(),
        sender: sender(),
        to: Some(recipient()), // tampered: ContractDeploy must not have `to`
        nonce: 0,
        chain_id: 1,
        value: Amount::zero(),
        gas_limit: 100_000,
        gas_price: gas_price(),
        tx_type: TxType::ContractDeploy,
        data: vec![0x60, 0x80],
        signature: Signature::Unsigned,
        session_key: None,
        owner_cosignature: None,
    };
    assert_eq!(
        tx.validate().unwrap_err(),
        TransactionError::UnexpectedRecipient
    );
}

// ── Transaction — predicates ──────────────────────────────────────────────────

#[test]
fn transaction_is_signed_false_for_unsigned_signature() {
    assert!(!transfer_tx().is_signed());
}

#[test]
fn transaction_is_signed_true_for_classical_signature() {
    assert!(call_tx().is_signed());
}

#[test]
fn transaction_is_signed_true_for_post_quantum_signature() {
    let tx = Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        0,
        1,
        Amount::zero(),
        21_000,
        gas_price(),
        TxType::Transfer,
        vec![],
        sig_post_quantum(),
    )
    .unwrap();
    assert!(tx.is_signed());
}

#[test]
fn transaction_is_signed_true_for_hybrid_signature() {
    let tx = Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        0,
        1,
        Amount::zero(),
        21_000,
        gas_price(),
        TxType::Transfer,
        vec![],
        sig_hybrid(),
    )
    .unwrap();
    assert!(tx.is_signed());
}

#[test]
fn transaction_is_contract_deploy_true_for_deploy_type() {
    assert!(deploy_tx().is_contract_deploy());
}

#[test]
fn transaction_is_contract_deploy_false_for_transfer_type() {
    assert!(!transfer_tx().is_contract_deploy());
}

#[test]
fn transaction_is_contract_deploy_false_for_contract_call_type() {
    assert!(!call_tx().is_contract_deploy());
}

#[test]
fn transaction_is_contract_deploy_false_for_stake_type() {
    assert!(!stake_tx().is_contract_deploy());
}

#[test]
fn transaction_is_contract_deploy_false_for_unstake_type() {
    assert!(!unstake_tx().is_contract_deploy());
}

#[test]
fn transaction_is_contract_deploy_false_for_governance_vote_type() {
    assert!(!governance_vote_tx().is_contract_deploy());
}

// ── Transaction — validate happy path ────────────────────────────────────────

#[test]
fn transaction_validate_on_constructed_transaction_returns_ok() {
    assert!(transfer_tx().validate().is_ok());
    assert!(deploy_tx().validate().is_ok());
    assert!(call_tx().validate().is_ok());
    assert!(stake_tx().validate().is_ok());
    assert!(unstake_tx().validate().is_ok());
    assert!(governance_vote_tx().validate().is_ok());
}

// ── Transaction — Serde ───────────────────────────────────────────────────────

#[test]
fn transaction_transfer_roundtrips_through_json() {
    let original = transfer_tx();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Transaction = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn transaction_deploy_roundtrips_through_json() {
    let original = deploy_tx();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Transaction = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn transaction_call_roundtrips_through_json() {
    let original = call_tx();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Transaction = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

// ── Transaction — chain_id ───────────────────────────────────────────────────

#[test]
fn transaction_new_stores_chain_id() {
    let tx = Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        0,
        42, // chain_id under test
        Amount::zero(),
        21_000,
        gas_price(),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .unwrap();
    assert_eq!(tx.chain_id, 42);
}

#[test]
fn transaction_chain_id_survives_json_roundtrip() {
    let original = Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        0,
        7, // distinctive chain_id
        Amount::zero(),
        21_000,
        gas_price(),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .unwrap();
    let json = serde_json::to_string(&original).unwrap();
    let decoded: Transaction = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
    assert_eq!(decoded.chain_id, 7);
}

#[test]
fn transactions_with_different_chain_ids_are_not_equal() {
    let mainnet = transfer_tx(); // chain_id 1
    let testnet = Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        0,
        2, // different chain_id
        Amount::zero(),
        21_000,
        gas_price(),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .unwrap();
    assert_ne!(mainnet, testnet);
}

// ── Transaction — Clone / PartialEq ──────────────────────────────────────────

#[test]
fn transaction_clone_equals_original() {
    let tx = transfer_tx();
    assert_eq!(tx.clone(), tx);
}

#[test]
fn transactions_with_different_nonces_are_not_equal() {
    let tx1 = transfer_tx(); // nonce 0
    let tx2 = Transaction::new(
        tx_hash(),
        sender(),
        Some(recipient()),
        99, // different nonce
        1,
        Amount::zero(),
        21_000,
        gas_price(),
        TxType::Transfer,
        vec![],
        Signature::Unsigned,
    )
    .unwrap();
    assert_ne!(tx1, tx2);
}

// ── TransactionReceipt ────────────────────────────────────────────────────────

#[test]
fn receipt_new_stores_all_fields() {
    let logs = vec![test_log()];
    let receipt = TransactionReceipt::new(tx_hash(), true, 21_000, logs.clone());
    assert_eq!(receipt.tx_hash, tx_hash());
    assert!(receipt.success);
    assert_eq!(receipt.gas_used, 21_000);
    assert_eq!(receipt.logs, logs);
}

#[test]
fn receipt_is_success_returns_true_for_successful_execution() {
    let receipt = TransactionReceipt::new(tx_hash(), true, 21_000, vec![]);
    assert!(receipt.is_success());
}

#[test]
fn receipt_is_success_returns_false_for_failed_execution() {
    let receipt = TransactionReceipt::new(tx_hash(), false, 21_000, vec![]);
    assert!(!receipt.is_success());
}

#[test]
fn receipt_log_count_returns_zero_when_no_logs() {
    let receipt = TransactionReceipt::new(tx_hash(), true, 21_000, vec![]);
    assert_eq!(receipt.log_count(), 0);
}

#[test]
fn receipt_log_count_returns_correct_count_with_multiple_logs() {
    let logs = vec![test_log(), test_log(), test_log()];
    let receipt = TransactionReceipt::new(tx_hash(), true, 60_000, logs);
    assert_eq!(receipt.log_count(), 3);
}

#[test]
fn receipt_roundtrips_through_json() {
    let original = TransactionReceipt::new(tx_hash(), true, 21_000, vec![test_log()]);
    let json = serde_json::to_string(&original).unwrap();
    let decoded: TransactionReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn receipt_clone_equals_original() {
    let receipt = TransactionReceipt::new(tx_hash(), false, 5_000, vec![]);
    assert_eq!(receipt.clone(), receipt);
}

#[test]
fn receipts_with_different_gas_used_are_not_equal() {
    let a = TransactionReceipt::new(tx_hash(), true, 21_000, vec![]);
    let b = TransactionReceipt::new(tx_hash(), true, 22_000, vec![]);
    assert_ne!(a, b);
}
