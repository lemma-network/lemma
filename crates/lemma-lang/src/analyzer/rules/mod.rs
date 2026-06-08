//! SAFETY rule modules — batch 1 (4d): rules 004, 012, 008, 011.
//! Batch 2 (4e): 002, 003, 006, 013.
//! Batch 3 (4f): 005, 009, 001, 007, 010.

// Batch 2 (4e): config-driven + structural rules.
pub(crate) mod approvals;
pub(crate) mod constants;
pub(crate) mod fee_cap;
pub(crate) mod supply_cap;
pub(crate) mod ticker;

// Batch 1 (4d): CFG/structural rules.
pub(crate) mod delegate;
pub(crate) mod hooks;
pub(crate) mod integer;
pub(crate) mod reentrancy;
