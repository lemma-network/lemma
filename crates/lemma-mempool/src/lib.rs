//! # lemma-mempool
//!
//! Transaction mempool for the Lemma blockchain.
//!
//! Provides the base mempool machinery (spec §1 of `11-MEMPOOL_SHIELD_SPEC`):
//! priority queue, ingress validation, per-account rate limiting, stake-weighted
//! QoS, circuit-breaker load tiers, per-contract local fee markets, and Express
//! fast-path detection.
//!
//! The `shield` module adds threshold-encrypted mempool support (decrypt-after-order
//! MEV protection). See `docs/15-SHIELD_SPEC.md` for the cryptographic specification.

pub mod circuit_breaker;
pub mod error;
pub mod express;
pub mod local_fees;
pub mod pool;
pub mod qos;
pub mod rate_limit;
pub mod shield;
pub mod validation;

#[cfg(test)]
mod tests;
