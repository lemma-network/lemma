//! SAFETY rule modules — batch 1 (4d): rules 004, 012, 008, 011.
//! Batch 2 (4e): 002, 003, 006.
//! Batch 3 (4f): 005, 009, 001, 007, 010.
//! Batch 3 (4f-tax): 020, 021, 022 (TaxToken fee-model rules) + SAFETY-002 rework.
//! Batch 3 (4f-launch): 023, 024 (launch/holding-control rules) + P3-own-3 (a)(c).
//! Note: SAFETY-013 (ticker registration) retired per decision DB-A48 —
//! registration is auto-injected by codegen.

// Batch 2 (4e): config-driven + structural rules.
pub(crate) mod approvals;
pub(crate) mod constants;
pub(crate) mod fee_cap;
pub(crate) mod supply_cap;

// Batch 1 (4d): CFG/structural rules.
pub(crate) mod delegate;
pub(crate) mod hooks;
pub(crate) mod integer;
pub(crate) mod reentrancy;

// Batch 3 (4f): authority/declaration rules.
pub(crate) mod blacklist;
pub(crate) mod declared;
pub(crate) mod honeypot;
pub(crate) mod one_way_gate;
pub(crate) mod upgrade;

// Batch 3 (4f-tax): TaxToken fee-model rules (SAFETY-020/021/022).
pub(crate) mod tax;

// Batch 3 (4f-launch): launch/holding-control rules (SAFETY-023/024 + P3-own-3 a/c).
pub(crate) mod launch;
