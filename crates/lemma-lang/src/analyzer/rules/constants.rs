//! Named constants for the SAFETY rule modules (AGENTS §3.3 — no magic numbers).

/// Protocol ceiling on transfer fees — 25.00% expressed in basis points.
/// `maxFeePercent` in `config {}` must not exceed this value.
/// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-002`.
pub(crate) const PROTOCOL_MAX_FEE_BPS: u16 = 2500;

/// Minimum block delay before a TaxToken fee *increase* takes effect.
///
/// A fee setter that raises `fees` must write a pending change with
/// `effectiveBlock ≥ block.height + FEE_INCREASE_DELAY`.  This is a
/// **protocol constant** — it is NOT token-settable (a token-settable delay
/// could be set to 0 and defeat the rule).
///
/// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-022`.
pub(crate) const FEE_INCREASE_DELAY: u64 = 7200; // ≈ 24 h at 12 s/block

// MAX_ANTISNIPE_TAX removed — SAFETY-024 retired per decision DB-A57.
