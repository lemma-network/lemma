//! Unit tests for the mutex-guarded scheduler state.

use super::*;
use lemma_core::hash::Hash;
use lemma_core::transaction::TransactionReceipt;

/// A trivial successful receipt for state bookkeeping tests.
fn receipt() -> TransactionReceipt {
    TransactionReceipt::new(Hash::zero(), true, 0, vec![])
}

#[test]
fn empty_block_is_done_immediately() {
    let st = SchedulerState::new(0);
    assert!(st.is_done());
}

#[test]
fn next_task_dispatches_executions_in_order_then_idle() {
    let mut st = SchedulerState::new(2);
    assert_eq!(
        st.next_task(),
        Task::Execute {
            txn_idx: 0,
            incarnation: 0
        }
    );
    assert_eq!(
        st.next_task(),
        Task::Execute {
            txn_idx: 1,
            incarnation: 0
        }
    );
    assert_eq!(st.next_task(), Task::Idle);
}

#[test]
fn commit_advances_cursor_until_done() {
    let mut st = SchedulerState::new(2);
    assert!(!st.is_done());
    st.commit(0);
    assert!(!st.is_done());
    st.commit(1);
    assert!(st.is_done());
}

#[test]
fn abort_bumps_incarnation_and_clears_executed() {
    let mut st = SchedulerState::new(1);
    st.record_execution(0, vec![], CapturedReads::new(), receipt());
    // An executed txn can be claimed for commit.
    assert_eq!(st.claim_commit(), Some(0));
    assert_eq!(st.incarnation(0), 0);
    // Restore (commit clears the claim) then abort.
    st.commit(0);
    let mut st = SchedulerState::new(1);
    st.record_execution(0, vec![], CapturedReads::new(), receipt());
    let _ = st.abort(0);
    // After abort the txn is no longer executed → cannot be claimed.
    assert_eq!(st.claim_commit(), None);
    assert_eq!(st.incarnation(0), 1);
}

#[test]
fn claim_commit_is_exclusive_until_commit() {
    let mut st = SchedulerState::new(1);
    st.record_execution(0, vec![], CapturedReads::new(), receipt());
    assert_eq!(st.claim_commit(), Some(0));
    // Second claim is blocked while one is in flight.
    assert_eq!(st.claim_commit(), None);
    st.commit(0);
    assert!(st.is_done());
}
