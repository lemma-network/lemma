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
    // ── SAFETY-001 — Anti-Honeypot (disposal-path existence) ────────────────
    /// A token contract has no disposal path (missing `transfer`) or the
    /// disposal path is access-restricted.  Fires unconditionally for all
    /// token contracts — anti-honeypot is a protocol invariant (DB-A57).
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

    // ── SAFETY-011b — Ungated delegateCall built-in ───────────────────────────
    /// An explicit `Address::delegateCall(calldata)` built-in call occurs in a
    /// function that is NOT annotated `#[allowDelegate]`.  `delegateCall`
    /// executes the callee's code in the *caller's* storage context (arbitrary
    /// code in your storage) — spec §16 requires the enclosing function to opt
    /// in via `#[allowDelegate]`.
    ///
    /// Distinct from [`SafetyError::UnsafeDelegate`] (the `self.<field>.<method>()`
    /// runtime-chosen proxy pattern): this variant covers the explicit built-in
    /// `addr.delegateCall(data)` where `addr` is a local/param, not a state field.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-011` and `03-LANGUAGE_SPEC §16`.
    #[error(
        "SAFETY-011 ungated delegateCall: `delegateCall` at this site runs arbitrary \
         code in the contract's storage context but `{func}` is not annotated \
         #[allowDelegate] — add #[allowDelegate] to opt in"
    )]
    UngatedDelegateCall {
        /// The enclosing function that lacks the `#[allowDelegate]` annotation.
        func: String,
        /// Source location of the offending `delegateCall` site.
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

    // ── SAFETY-020 — distributeTaxes separation + budget bound ───────────────
    /// A call-graph path exists from the transfer path (`transfer` /
    /// `transferFrom` / `#[onTransfer]` and their transitive callees) to
    /// `distributeTaxes`.  Fee distribution must run *outside* the transfer
    /// path to prevent it being used as a hidden honeypot or reentrancy vector.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-020`.
    #[error(
        "SAFETY-020 tax-distribute on transfer path: `{func}` is on the transfer path \
         and calls `distributeTaxes` (directly or transitively) — \
         fee distribution must not be reachable from the transfer path"
    )]
    TaxDistributeOnTransferPath {
        /// The transfer-path function (or its callee) that reaches `distributeTaxes`.
        func: String,
    },

    /// `distributeTaxes` reads or moves value from `self.balances` or
    /// `self.totalSupply` as an outflow source.  Only `self.taxPool` (via a
    /// local snapshot) is the permitted value source for fee distribution.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-020`.
    #[error(
        "SAFETY-020 tax-distribute unbounded: `distributeTaxes` uses an unauthorized \
         value source — {reason} \
         (only `self.taxPool` via a local snapshot is permitted)"
    )]
    TaxDistributeUnbounded {
        /// Human-readable description of the unauthorized value source found.
        reason: String,
    },

    /// `distributeTaxes` does not zero `self.taxPool` before every external
    /// call, or an external call reads `self.taxPool` after the zero-write.
    /// The canonical drain shape requires: snapshot → zero → distribute snapshot.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-020`.
    #[error(
        "SAFETY-020 tax-pool not zeroed first: `{func}` makes an external call \
         before zeroing `self.taxPool`, or reads `self.taxPool` after zeroing it — \
         zero the pool before any external interaction"
    )]
    TaxPoolNotZeroedFirst {
        /// The function where the zero-before-interaction violation occurs.
        func: String,
    },

    // ── SAFETY-021 — isTaxable determinism + purity ───────────────────────────
    /// `isTaxable` writes state or reads a non-deterministic input (clock,
    /// RNG, external call, block-randomness).  The taxable predicate must be
    /// a deterministic, side-effect-free decision.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-021`.
    #[error(
        "SAFETY-021 taxable predicate impure: `isTaxable` is not view-pure — {reason} \
         (the taxable predicate must be deterministic and side-effect-free)"
    )]
    TaxablePredicateImpure {
        /// Human-readable description of the impurity found.
        reason: String,
    },

    // ── SAFETY-022 — Fee-change asymmetric timelock ───────────────────────────
    /// A function that writes the `fees` state field can raise the effective
    /// fee without the required `FEE_INCREASE_DELAY`-block timelock.  Fee
    /// decreases may apply immediately; increases must be delayed.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3 SAFETY-022`.
    #[error(
        "SAFETY-022 fee raise no timelock: `{func}` can raise `fees` without the \
         required `FEE_INCREASE_DELAY`-block pending period — \
         fee increases must use a pending change with effectiveBlock ≥ block.height + FEE_INCREASE_DELAY"
    )]
    FeeRaiseNoTimelock {
        /// The function that can raise fees without the required timelock.
        func: String,
    },

    // ── SAFETY-023 — maxWallet Exempt Interface ───────────────────────────────
    /// A contract with `maxWallet` enabled does not consult the wallet-exempt
    /// interface on the enforcement path.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3-quater SAFETY-023`.
    #[error(
        "SAFETY-023 maxWallet exempt: `{func}` enforces maxWallet but does not \
         consult isWalletExempt / walletExempt — exempt interface unreachable"
    )]
    MaxWalletNoExempt {
        /// The function that enforces maxWallet without consulting the exempt interface.
        func: String,
    },

    // ── SAFETY-024 — RETIRED (DB-A57) ──────────────────────────────────────
    // AntiSnipeIsBlock and LaunchControlNotExpiring removed.
    // Number 024 is retired and not reused (same pattern as SAFETY-013).

    // ── P3-own-3 — Missing Required Trait ────────────────────────────────────
    /// A function uses an annotation that requires a trait the contract does not declare.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §2.1 P3-own-3`.
    #[error(
        "P3-own-3 missing trait: `{func}` uses `{annotation}` but contract does not \
         have state field `owner` — add `owner: Address` state field or use the \
         appropriate standard"
    )]
    MissingRequiredTrait {
        /// The function that uses the annotation.
        func: String,
        /// The annotation that requires the missing trait (e.g. `"onlyOwner"`).
        annotation: String,
    },

    // ── SAFETY-025 — Sell-Path External Veto ─────────────────────────────────
    /// An external call on the sell/transfer path is not try-wrapped — the called
    /// contract can revert and block the sell (revert-veto over sells).
    ///
    /// Fix: wrap the external call in `try { … } catch { … }`.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3-quinquies SAFETY-025`.
    #[error(
        "SAFETY-025 sell-path external veto: `{func}` makes an unwrapped external call \
         that can revert and block sells — wrap in try/catch or remove from sell path"
    )]
    SellPathExternalVeto {
        /// The transfer-path function containing the unguarded external call.
        func: String,
    },

    // ── SAFETY-014 — Agent-callable bounded effects ───────────────────────────
    /// An `@agentCallable` function has value outflow the analyzer cannot prove
    /// is bounded by the declared `maxValueOut` cap, or the annotation is missing
    /// the required `maxValueOut` argument.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-014`.
    #[error(
        "SAFETY-014 agent outflow unbounded: `{func}` is @agentCallable but value \
         outflow cannot be proven ≤ declared cap — {reason}"
    )]
    AgentOutflowUnbounded {
        /// The @agentCallable function with unprovable outflow.
        func: String,
        /// Human-readable reason (e.g. "unbounded transfer loop", "missing maxValueOut").
        reason: String,
    },

    // ── SAFETY-015 — Policy-mutation owner-gating ─────────────────────────────
    /// A function that creates or widens an `AgentPolicy` is not gated by
    /// `@onlyOwner`, meaning a session key could reach it.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-015`.
    #[error(
        "SAFETY-015 agent policy self-escalation: `{func}` modifies agent policy \
         but is not @onlyOwner — session keys must not widen their own authority"
    )]
    AgentPolicySelfEscalation {
        /// The policy-mutation function that lacks owner gating.
        func: String,
    },

    // ── SAFETY-016 — No agent re-grant ────────────────────────────────────────
    /// A session-key-reachable path (from an `@agentCallable` function) calls
    /// `grantAgent` — authority laundering through nested agents.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-016`.
    #[error(
        "SAFETY-016 agent re-grant: `{caller}` is @agentCallable and calls `{callee}` \
         — session keys cannot grant session keys (no delegation chains)"
    )]
    AgentReGrant {
        /// The @agentCallable function that makes the grant call.
        caller: String,
        /// The grant function being called.
        callee: String,
    },

    // ── SAFETY-017 — Kill-switch honored ──────────────────────────────────────
    /// An agent-entry function bypasses the Warden gate — not all `@agentCallable`
    /// paths are dominated by the kill-switch (`agents_paused`) check.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-017`.
    #[error(
        "SAFETY-017 agent gate bypassed: `{func}` is reachable by agents but does \
         not carry the @agentCallable annotation — hand-rolled agent entries are rejected"
    )]
    AgentGateBypassed {
        /// The function that is agent-accessible without the required annotation.
        func: String,
    },

    // ── SAFETY-018 — Co-sign threshold integrity ──────────────────────────────
    /// A co-sign-gated action can be satisfied by a session key or agent-controlled
    /// key rather than the owner key, defeating the human-in-the-loop step-up.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-018`.
    #[error(
        "SAFETY-018 agent cosign forgeable: `{func}` performs a co-signed action \
         but the co-signer is not verified to be the owner key — \
         co-sign must verify against the owner, not a session key"
    )]
    AgentCosignForgeable {
        /// The function with a forgeable co-sign.
        func: String,
    },

    // ── SAFETY-019 — Deterministic anomaly inputs ─────────────────────────────
    /// An anomaly or auto-revoke predicate reads a non-deterministic input
    /// (external call, system time, RNG, off-chain data) — would fork consensus.
    ///
    /// See `09-SAFETY_ANALYZER_SPEC §3-bis SAFETY-019`.
    #[error(
        "SAFETY-019 agent anomaly non-deterministic: `{func}` is an anomaly/auto-revoke \
         predicate but reads non-deterministic input `{input}` — \
         predicates must use committed on-chain state only"
    )]
    AgentAnomalyNonDeterministic {
        /// The anomaly-predicate function with a non-deterministic input.
        func: String,
        /// Description of the non-deterministic input found.
        ///
        /// Named `input` (not `source`) to avoid conflict with `thiserror`'s
        /// reserved `source` field name used for error chaining.
        input: String,
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
