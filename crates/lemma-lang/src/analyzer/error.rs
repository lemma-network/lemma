//! Safety-analyzer error types.
//!
//! [`SafetyError`] is the error produced by [`super::analyze_safety`] when a
//! contract violates one of the active SAFETY compile-time rules.
//!
//! `analyze_safety` collects **all** violations before returning, so a single
//! compilation attempt surfaces every problem at once.
//!
//! Note: SAFETY-013 (MissingTickerRegistration) retired per decision DB-A48 —
//! registration is auto-injected by codegen.

use crate::lexer::token::Span;

// ─── SafetyError ──────────────────────────────────────────────────────────────

/// A compile-time safety violation detected by the Lem safety analyzer.
///
/// Produced by [`super::analyze_safety`].  Each variant corresponds to one
/// active SAFETY rule from `docs/09-SAFETY_ANALYZER_SPEC.md §3`.
///
/// The enum is `#[non_exhaustive]` so that adding new SAFETY rules (e.g. the
/// Phase 3 agent rules SAFETY-014…019) is not a breaking change for consumers.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SafetyError {
    // ── SAFETY-001 — Anti-Honeypot Symmetry ──────────────────────────────────
    /// A token with `antiHoneypot: true` has no sell path symmetric to its
    /// buy path, or the sell path is guarded more strictly than the buy path.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-001`.
    #[error(
        "SAFETY-001 honeypot: {reason} \
         (a symmetric disposal path is required for every acquisition path)"
    )]
    Honeypot {
        /// Human-readable description of the asymmetry found.
        reason: String,
    },

    // ── SAFETY-002 — Fee Cap ──────────────────────────────────────────────────
    /// A transfer fee provably exceeds the `maxFeePercent` declared in
    /// `config {}`, or exceeds the protocol hard ceiling (2500 bps = 25%).
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-002`.
    #[error(
        "SAFETY-002 fee cap: fee {found} bps exceeds declared maximum {declared} bps \
         (protocol ceiling: 2500 bps)"
    )]
    FeeTooHigh {
        /// The `maxFeePercent` declared in `config {}` (basis points).
        declared: u16,
        /// The provable supremum of the fee found in the transfer hook.
        found: u16,
    },

    // ── SAFETY-003 — Supply Cap ───────────────────────────────────────────────
    /// A `totalSupply`-increasing path exists when `mintable: false`, or a
    /// mint is not dominated by a `totalSupply + delta <= maxSupply` guard.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-003`.
    #[error("SAFETY-003 supply cap: {reason}")]
    SupplyCapViolation {
        /// Human-readable description of the violation.
        reason: String,
    },

    // ── SAFETY-004 — State-Before-Call (Reentrancy) ───────────────────────────
    /// A state write occurs after an external call on some control-flow path
    /// through the function (checks-effects-interactions violation).
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-004`.
    #[error(
        "SAFETY-004 reentrancy: state written after external call in `{func}` \
         (effects must precede interactions)"
    )]
    StateAfterCall {
        /// The function where the violation occurs.
        func: String,
        /// Source location of the offending call site.
        call_site: Span,
    },

    // ── SAFETY-005 — Blacklist Governance ─────────────────────────────────────
    /// A function that can block a specific address's transfers is gated by
    /// `@onlyOwner` rather than the `GOVERNANCE` role.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-005`.
    #[error(
        "SAFETY-005 blacklist governance: `{func}` can freeze an address \
         but is only guarded by @onlyOwner — use @onlyRole(\"GOVERNANCE\")"
    )]
    UngovernedBlacklist {
        /// The function that writes the restriction field.
        func: String,
    },

    // ── SAFETY-006 — Approval Bounds ──────────────────────────────────────────
    /// An approval can be created with an unbounded amount or no expiry,
    /// breaking the infinite-approval protection.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-006`.
    #[error("SAFETY-006 approval bounds: {reason}")]
    UnboundedApproval {
        /// Human-readable description of the unbounded approval found.
        reason: String,
    },

    // ── SAFETY-007 — Upgrade Safety ───────────────────────────────────────────
    /// An upgradeable contract's upgrade path lacks governance auth or a
    /// declared timelock, or the new storage layout is incompatible.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-007`.
    #[error("SAFETY-007 upgrade safety: {reason}")]
    UnsafeUpgrade {
        /// Human-readable description of the upgrade-safety violation.
        reason: String,
    },

    // ── SAFETY-008 — Hook Sandboxing ──────────────────────────────────────────
    /// A `#[onTransfer]` hook writes state outside the declaring contract or
    /// makes an external call that is not a statically-known `@std` view.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-008`.
    #[error(
        "SAFETY-008 hook escape: hook `{hook}` accesses unauthorized key `{key}` \
         or makes a disallowed external call"
    )]
    HookEscape {
        /// The hook function name (e.g. `"onTransfer"`).
        hook: String,
        /// The unauthorized state key or external call target.
        key: String,
    },

    // ── SAFETY-009 — One-Way Gates ────────────────────────────────────────────
    /// A boolean flag that gates disposal/transfer can be set to the blocking
    /// value by a non-governance actor (reversible trading halt).
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-009`.
    #[error(
        "SAFETY-009 one-way gate: `{func}` can block transfers via a flag \
         that a non-governance actor can re-assert"
    )]
    OneWayGate {
        /// The function that writes the blocking value.
        func: String,
    },

    // ── SAFETY-010 — Declared Restrictions ────────────────────────────────────
    /// A revert source on the transfer path is not declared in `config {}`,
    /// making the restriction hidden from wallets and the runtime score.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-010`.
    #[error(
        "SAFETY-010 undeclared restriction: `{func}` can revert a transfer \
         via an undeclared condition — declare it in config {{}}"
    )]
    UndeclaredRestriction {
        /// The function containing the undeclared revert source.
        func: String,
    },

    // ── SAFETY-011 — Delegate Restriction ────────────────────────────────────
    /// A dynamic or mutable-target delegate call would execute arbitrary code
    /// in `self`'s storage context.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-011`.
    #[error(
        "SAFETY-011 unsafe delegate: dynamic delegate call at this site \
         would execute arbitrary external code in the contract's storage context"
    )]
    UnsafeDelegate {
        /// Source location of the offending delegate call.
        call_site: Span,
    },

    // ── SAFETY-012 — Integer Safety ───────────────────────────────────────────
    /// Unchecked arithmetic inside an `unchecked {}` block flows into a
    /// value-bearing quantity (balance, totalSupply, or a value transfer).
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-012`.
    #[error(
        "SAFETY-012 integer safety: unchecked `{op}` flows into a value path \
         — remove `unchecked {{}}` or ensure the operation cannot overflow"
    )]
    UncheckedArithmetic {
        /// The operator (e.g. `"+"`, `"-"`, `"*"`).
        op: String,
        /// Source location of the unchecked operation.
        span: Span,
    },

    // ── Inconclusive ──────────────────────────────────────────────────────────
    /// Analysis is inconclusive for a sound rule: the contract cannot be
    /// *proven* safe, so it is **rejected** (soundness over completeness).
    ///
    /// Example: a non-canonical fee expression that the fee-sup analysis
    /// cannot bound → `Inconclusive { rule: "SAFETY-002", … }`.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §5.1`.
    #[error(
        "SAFETY inconclusive ({rule}): {reason} — rewrite to the canonical \
         analyzable form to pass the safety analyzer"
    )]
    Inconclusive {
        /// The rule that could not be decided (e.g. `"SAFETY-002"`).
        rule: &'static str,
        /// Human-readable explanation of why analysis is inconclusive.
        reason: String,
        /// Source location of the unanalyzable construct.
        span: Span,
    },
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
