//! Named constants for the SAFETY rule modules (AGENTS §3.3 — no magic numbers).

/// Protocol ceiling on transfer fees — 25.00% expressed in basis points.
/// `maxFeePercent` in `config {}` must not exceed this value.
/// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-002`.
pub(crate) const PROTOCOL_MAX_FEE_BPS: u16 = 2500;

/// Denominator for the canonical fee form `amount * rate / FEE_DENOM`.
/// Basis-point arithmetic: `rate = 500` means 5.00% (500 / 10_000).
pub(crate) const FEE_DENOM: u128 = 10_000;
