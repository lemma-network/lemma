//! SAFETY-020/021/022 — TaxToken fee-model rules.
//!
//! These three rules are the compile-time safety layer for the `TaxToken`
//! standard (spec §24, DB-A41).  They apply **only** to `TaxToken` contracts;
//! plain `Token` and plain `contract` declarations trigger zero violations.
//!
//! ## Rule summary
//!
//! - **SAFETY-020** (`check_safety_020`): `distributeTaxes` separation + budget
//!   bound + zero-before-interaction.  Prevents fee distribution from being used
//!   as a hidden honeypot or reentrancy/drain vector.
//!
//! - **SAFETY-021** (`check_safety_021`): `isTaxable` determinism + purity.
//!   Prevents the taxable predicate from mutating state or reading non-deterministic
//!   inputs (clock, RNG, external call, block-randomness).
//!
//! - **SAFETY-022** (`check_safety_022`): Fee-change asymmetric timelock.
//!   Prevents an owner from silently raising fees on holders without the required
//!   `FEE_INCREASE_DELAY`-block pending period.
//!
//! ## Reject-on-doubt policy (spec §5.1)
//!
//! All three rules use **reject-on-doubt**: if the contract cannot be *proven*
//! safe, it is rejected with `Inconclusive`.  Non-canonical shapes, helper
//! function indirection, and non-literal values all trigger `Inconclusive`.
//!
//! ## Deferred enforcement (P3·Step 7)
//!
//! Several sub-checks currently use reject-on-doubt for shapes that are safe
//! but not yet analyzable.  Full enforcement is deferred to P3·Step 7:
//! - D1: SAFETY-020 zero-before: branch-aware CFG dominance
//! - D2: SAFETY-020 budget-bound: transitive callee tracking
//! - D3: SAFETY-022 timelock: full asymmetric enforcement
//! - D4: SAFETY-021 isTaxable: type-driven external call detection
//!
//! See `09-SAFETY_ANALYZER_SPEC §3-ter` and `living-notes.md deferred-D1…D4`.

use std::collections::BTreeSet;

use crate::analyzer::cfg::{self, build_call_graph, CfgNode};
use crate::analyzer::error::SafetyError;
use crate::analyzer::util::is_self;
use crate::lexer::token::Span;
use crate::parser::{CallArg, Expr, Literal, Stmt};
use crate::type_checker::typed_contract::TypedContract;
use crate::visit::{walk_expr, walk_stmt, Visitor};

use super::constants::FEE_INCREASE_DELAY;

// ─── Public entry point ───────────────────────────────────────────────────────

/// Check a contract for SAFETY-020, SAFETY-021, and SAFETY-022 violations.
///
/// Returns an empty `Vec` immediately for non-TaxToken contracts.
/// For TaxToken contracts, runs all three sub-checks and collects every
/// violation before returning (fail-all, not fail-fast).
#[must_use]
pub(crate) fn check(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    // All three rules apply only to TaxToken — guard at the top.
    if contract.base_standard() != Some("TaxToken") {
        return Vec::new();
    }

    let mut violations = Vec::new();
    violations.extend(check_safety_020(contract));
    violations.extend(check_safety_021(contract));
    violations.extend(check_safety_022(contract));
    violations
}

// ─── SAFETY-020 ───────────────────────────────────────────────────────────────

/// SAFETY-020: `distributeTaxes` separation + budget bound + zero-before-interaction.
///
/// Three sub-checks, all only when `distributeTaxes` exists:
/// 1. **Separation**: no call-graph path from the transfer path to `distributeTaxes`.
/// 2. **Budget bound**: `distributeTaxes` must not read `self.balances` or
///    `self.totalSupply` as an outflow source.
/// 3. **Zero-before-interaction**: canonical drain shape required.
fn check_safety_020(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    // Only applies when `distributeTaxes` is declared.
    let Some(distribute_fn) = contract
        .functions()
        .into_iter()
        .find(|f| f.name == "distributeTaxes")
    else {
        return violations;
    };

    // Sub-check 1: separation — no transfer-path function may reach `distributeTaxes`.
    violations.extend(check_020_separation(contract));

    // Sub-check 2: budget bound — `distributeTaxes` must not use balances/totalSupply.
    violations.extend(check_020_budget_bound(contract, &distribute_fn));

    // Sub-check 3: zero-before-interaction — canonical drain shape required.
    violations.extend(check_020_zero_before_interaction(contract, &distribute_fn));

    violations
}

/// Sub-check 1: no call-graph path from the transfer path to `distributeTaxes`.
///
/// Transfer path = `transfer`, `transferFrom`, any `#[onTransfer]`-annotated fn,
/// plus their transitive callees (via the call graph).
///
/// **Reject-on-doubt (C5)**: if the contract is a TaxToken with `distributeTaxes`
/// but has NO transfer-path entry points visible to the analyzer, we cannot
/// verify separation — return `Inconclusive`.
fn check_020_separation(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let call_graph = build_call_graph(contract);

    // Seed: direct transfer-path entry functions.
    let transfer_entries: BTreeSet<String> = contract
        .functions()
        .into_iter()
        .filter(|f| is_transfer_path_entry(f.name, f.annotations))
        .map(|f| f.name.to_owned())
        .collect();

    // C5: TaxToken with distributeTaxes but no transfer-path entries → Inconclusive.
    // We cannot verify separation without seeing the transfer path.
    // TODO(4f-tax/step7): full enforcement deferred — see living-notes deferred-D1/D2/D3/D4.
    // Currently: reject-on-doubt (Inconclusive). Step 7 will add branch-aware CFG
    // + block.height built-in that makes full enforcement possible.
    if transfer_entries.is_empty() {
        return vec![SafetyError::Inconclusive {
            rule: "SAFETY-020",
            reason: "TaxToken has no transfer-path entry points visible to the analyzer \
                     — cannot verify distributeTaxes separation \
                     (add `transfer`, `transferFrom`, or `#[onTransfer]` functions)"
                .to_owned(),
            span: Span::at(0, 0, 0),
        }];
    }

    // Expand to all transitive callees of the transfer path.
    let transfer_reachable = transitive_callees(&transfer_entries, &call_graph);

    // Violation: any transfer-path function (direct or transitive) calls `distributeTaxes`.
    let mut violations = Vec::new();
    for func_name in &transfer_reachable {
        if let Some(callees) = call_graph.get(func_name) {
            if callees.contains("distributeTaxes") {
                violations.push(SafetyError::TaxDistributeOnTransferPath {
                    func: func_name.clone(),
                });
                // One violation per offending function is sufficient.
            }
        }
    }
    violations
}

/// Sub-check 2: `distributeTaxes` must not read `self.balances` or
/// `self.totalSupply` as an outflow source.
///
/// Over-approximation: any read of `self.balances` or `self.totalSupply`
/// anywhere in the function body is flagged (reject on doubt — spec §5.1).
///
/// **C2 — transitive callee rejection**: if `distributeTaxes` calls any
/// internal helper function, we cannot trace into it safely → `Inconclusive`.
/// TODO(4f-tax/step7): full enforcement deferred — see living-notes deferred-D1/D2/D3/D4.
/// Currently: reject-on-doubt (Inconclusive). Step 7 will add branch-aware CFG
/// + block.height built-in that makes full enforcement possible.
fn check_020_budget_bound(
    contract: &TypedContract<'_>,
    distribute_fn: &crate::type_checker::typed_contract::ContractFunction<'_>,
) -> Vec<SafetyError> {
    let Some(body) = distribute_fn.body else {
        return Vec::new();
    };

    // C2: if distributeTaxes calls any internal helper, reject-on-doubt.
    let call_graph = build_call_graph(contract);
    if let Some(callees) = call_graph.get("distributeTaxes") {
        // Filter out self-recursive calls — only flag calls to OTHER functions.
        let has_helper_call = callees.iter().any(|c| c != "distributeTaxes");
        if has_helper_call {
            return vec![SafetyError::Inconclusive {
                rule: "SAFETY-020",
                reason: "`distributeTaxes` calls an internal helper function — \
                         cannot verify budget-bound without transitive callee analysis \
                         (inline all logic into `distributeTaxes` for static verification)"
                    .to_owned(),
                span: Span::at(0, 0, 0),
            }];
        }
    }

    let mut scanner = ForbiddenFieldReadScanner {
        forbidden: &["balances", "totalSupply"],
        found: None,
    };
    scanner.visit_stmts(body);

    if let Some(field) = scanner.found {
        vec![SafetyError::TaxDistributeUnbounded {
            reason: format!(
                "`distributeTaxes` reads `self.{field}` as a value source — \
                 only `self.taxPool` (via a local snapshot) is permitted"
            ),
        }]
    } else {
        Vec::new()
    }
}

/// Sub-check 3: canonical drain shape required.
///
/// The **only** accepted shape is:
/// ```lem
/// let pool = self.taxPool          // snapshot
/// self.taxPool = 0                 // literal-zero write
/// ... external_call(pool) ...      // uses snapshot, NOT self.taxPool
/// ```
///
/// Any deviation → `Inconclusive` (reject-on-doubt).
///
/// Specifically:
/// - No external call → clean (nothing to check).
/// - External call present → require exactly the canonical drain pattern.
/// - Non-literal-zero write to taxPool → `Inconclusive`.
/// - External call arg reads `self.taxPool` after zero-write → `Inconclusive`.
/// - Zero-write in a branch but external call outside → `Inconclusive`.
/// - Internal helper calls → `Inconclusive` (C2 applies here too).
///
/// TODO(4f-tax/step7): full enforcement deferred — see living-notes deferred-D1/D2/D3/D4.
/// Currently: reject-on-doubt (Inconclusive). Step 7 will add branch-aware CFG
/// + block.height built-in that makes full enforcement possible.
fn check_020_zero_before_interaction(
    contract: &TypedContract<'_>,
    distribute_fn: &crate::type_checker::typed_contract::ContractFunction<'_>,
) -> Vec<SafetyError> {
    let nodes = cfg::cfg_nodes(distribute_fn);

    // If there are no external calls, zero-before-interaction does not apply.
    let has_ext_call = nodes
        .iter()
        .any(|n| matches!(n, CfgNode::ExternalCall { .. }));
    if !has_ext_call {
        return Vec::new();
    }

    // C2: if distributeTaxes calls any internal helper, reject-on-doubt.
    let call_graph = build_call_graph(contract);
    if let Some(callees) = call_graph.get("distributeTaxes") {
        let has_helper_call = callees.iter().any(|c| c != "distributeTaxes");
        if has_helper_call {
            return vec![SafetyError::Inconclusive {
                rule: "SAFETY-020",
                reason: "`distributeTaxes` calls an internal helper function — \
                         cannot verify zero-before-interaction without transitive callee analysis \
                         (inline all logic into `distributeTaxes` for static verification)"
                    .to_owned(),
                span: Span::at(0, 0, 0),
            }];
        }
    }

    // Require the canonical drain pattern:
    // 1. A local variable snapshot of self.taxPool exists.
    // 2. self.taxPool is written with a literal 0 (not a non-zero or computed value).
    // 3. Every external call uses the snapshot variable, NOT self.taxPool.
    //
    // We check this via the linearised CFG nodes:
    // - Track whether we have seen a literal-zero write to taxPool.
    // - If an ExternalCall appears before a literal-zero taxPool write → Inconclusive.
    // - If a taxPool write is NOT a literal zero → Inconclusive.
    //
    // For the arg-reads-taxPool check, we use a separate AST scan.

    let Some(body) = distribute_fn.body else {
        return Vec::new();
    };

    // Check 1: scan for non-literal-zero writes to taxPool.
    let mut zero_write_scanner = TaxPoolZeroWriteScanner {
        result: TaxPoolWriteResult::None,
    };
    zero_write_scanner.visit_stmts(body);

    match zero_write_scanner.result {
        TaxPoolWriteResult::None => {
            // No write to taxPool at all, but there IS an external call.
            // Cannot verify the drain pattern → Inconclusive.
            return vec![SafetyError::Inconclusive {
                rule: "SAFETY-020",
                reason: "`distributeTaxes` has an external call but no `self.taxPool = 0` \
                         write — the canonical drain pattern requires zeroing taxPool \
                         before any external interaction"
                    .to_owned(),
                span: Span::at(0, 0, 0),
            }];
        }
        TaxPoolWriteResult::NonLiteralZero => {
            // Write to taxPool exists but is not a literal 0 (e.g. taxPool = taxPool - 1).
            return vec![SafetyError::Inconclusive {
                rule: "SAFETY-020",
                reason: "`distributeTaxes` writes `self.taxPool` with a non-literal-zero \
                         value — the canonical drain pattern requires `self.taxPool = 0` \
                         (literal integer 0) before any external interaction"
                    .to_owned(),
                span: Span::at(0, 0, 0),
            }];
        }
        TaxPoolWriteResult::LiteralZero => {
            // Good — there is a literal-zero write. Continue to ordering check.
        }
    }

    // Check 2: ordering — literal-zero write must precede every external call
    // in the linearised CFG (over-approximation: all branches merged).
    let mut taxpool_zeroed = false;
    for node in &nodes {
        match node {
            CfgNode::StateWrite { key, .. } if key == "taxPool" => {
                // We already verified above that the write is a literal zero.
                taxpool_zeroed = true;
            }
            CfgNode::StateWrite { .. } => {
                // Write to a different state field — does not affect ordering.
            }
            CfgNode::ExternalCall { .. } => {
                if !taxpool_zeroed {
                    // External call before taxPool was zeroed — Inconclusive.
                    return vec![SafetyError::Inconclusive {
                        rule: "SAFETY-020",
                        reason: "`distributeTaxes` makes an external call before \
                                 `self.taxPool = 0` — the canonical drain pattern \
                                 requires zeroing taxPool before any external interaction"
                            .to_owned(),
                        span: Span::at(0, 0, 0),
                    }];
                }
            }
            CfgNode::InternalCall { .. } => {
                // Internal calls already rejected above if any exist.
            }
        }
    }

    // Check 3: no external call arg may read self.taxPool after the zero-write.
    // We scan the body for external calls whose arguments contain self.taxPool reads.
    let mut arg_scanner = ExtCallArgTaxPoolScanner { found: false };
    arg_scanner.visit_stmts(body);
    if arg_scanner.found {
        return vec![SafetyError::Inconclusive {
            rule: "SAFETY-020",
            reason: "`distributeTaxes` passes `self.taxPool` as an argument to an \
                     external call — the canonical drain pattern requires using a \
                     local snapshot variable (not `self.taxPool` directly)"
                .to_owned(),
            span: Span::at(0, 0, 0),
        }];
    }

    Vec::new()
}

// ─── SAFETY-021 ───────────────────────────────────────────────────────────────

/// SAFETY-021: `isTaxable` must be view-pure (no state writes, no non-deterministic reads).
///
/// Only applies when `isTaxable` is declared.
fn check_safety_021(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let Some(taxable_fn) = contract
        .functions()
        .into_iter()
        .find(|f| f.name == "isTaxable")
    else {
        return Vec::new();
    };

    let Some(body) = taxable_fn.body else {
        return Vec::new();
    };

    let mut scanner = ImpurityScanner { reason: None };
    scanner.visit_stmts(body);

    if let Some(reason) = scanner.reason {
        vec![SafetyError::TaxablePredicateImpure { reason }]
    } else {
        Vec::new()
    }
}

// ─── SAFETY-022 ───────────────────────────────────────────────────────────────

/// SAFETY-022: Any function that writes `self.fees` directly is rejected as
/// `Inconclusive` — the canonical pattern requires using `pendingFees` +
/// `effectiveBlock` for increases.
///
/// ## Reject-on-doubt (C4)
///
/// A direct write to `self.fees` (or any component `self.fees.burn` /
/// `self.fees.holders` / `self.fees.others`) cannot be verified safe without
/// full branch-aware data-flow analysis.  Any such direct write → `Inconclusive`.
///
/// The canonical setter shape that will be accepted at P3·Step 7 is:
/// ```lem
/// if newTotal > currentTotal {
///     self.pendingFees = { ... }
///     self.feeEffectiveBlock = block.height + FEE_INCREASE_DELAY
/// } else {
///     self.fees = { ... }  // immediate decrease
/// }
/// emit FeeChanged(...)
/// ```
///
/// TODO(4f-tax/step7): full enforcement deferred — see living-notes deferred-D1/D2/D3/D4.
/// Currently: reject-on-doubt (Inconclusive). Step 7 will add branch-aware CFG
/// + block.height built-in that makes full enforcement possible.
///
/// `FEE_INCREASE_DELAY` = 7200 blocks (~24h at 12s/block).
/// See `rules/constants.rs` for the protocol constant definition.
fn check_safety_022(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        let Some(body) = func.body else {
            continue;
        };

        // Check whether this function writes `self.fees` directly (any component).
        let mut fees_write_scanner = DirectFeesWriteScanner { found: false };
        fees_write_scanner.visit_stmts(body);

        if !fees_write_scanner.found {
            continue; // Not a fees setter — skip.
        }

        // Direct `self.fees` write present → Inconclusive (reject-on-doubt).
        // We cannot verify the increase path uses the canonical pendingFees pattern
        // without branch-aware data-flow analysis (deferred to P3·Step 7).
        // FEE_INCREASE_DELAY = 7200 blocks (~24h at 12s/block) is the required
        // pending period for fee increases (protocol constant, not token-settable).
        violations.push(SafetyError::Inconclusive {
            rule: "SAFETY-022",
            reason: format!(
                "`{}` writes `self.fees` directly — fees setter must use the \
                 `pendingFees + effectiveBlock` canonical pattern for increases \
                 (FEE_INCREASE_DELAY = {} blocks); \
                 direct writes cannot be verified safe without branch-aware CFG analysis \
                 (deferred to P3·Step 7)",
                func.name, FEE_INCREASE_DELAY,
            ),
            span: Span::at(0, 0, 0),
        });
    }

    violations
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

/// Returns `true` if `name` / `annotations` identify a transfer-path entry.
fn is_transfer_path_entry(name: &str, annotations: &[crate::parser::Annotation]) -> bool {
    name == "transfer"
        || name == "transferFrom"
        || annotations.iter().any(|a| a.name == "onTransfer")
}

/// Compute the transitive closure of `seed` over forward call edges.
///
/// Returns the set of all functions reachable from any seed function
/// (including the seeds themselves).
fn transitive_callees(
    seed: &BTreeSet<String>,
    call_graph: &std::collections::BTreeMap<String, BTreeSet<String>>,
) -> BTreeSet<String> {
    let mut reachable = seed.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for (caller, callees) in call_graph {
            if reachable.contains(caller) {
                for callee in callees {
                    if reachable.insert(callee.clone()) {
                        changed = true;
                    }
                }
            }
        }
    }
    reachable
}

/// Returns `true` if `expr` is a literal integer 0.
///
/// Used by the zero-before-interaction check to distinguish `self.taxPool = 0`
/// (canonical drain) from `self.taxPool = self.taxPool - 1` (non-canonical).
fn is_literal_zero(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Literal(Literal::Int(0), _) | Expr::Literal(Literal::IntTyped { value: 0, .. }, _)
    )
}

/// Returns `true` if `expr` is `self.<field>` (a member access on `self`).
///
/// Used to distinguish own-state collection reads (`self.exemptList.get(…)`)
/// from external contract calls (`self.checker.isBlocked(…)`) in the
/// `ImpurityScanner`.  Note: this is a structural check — it cannot distinguish
/// a `Map<Address, bool>` field from an `Address` field without type info.
fn is_self_field_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Member(obj, _, _) if is_self(obj))
}

/// Returns `true` if `target` is a write to any `self.<field>`.
fn is_self_field_write(target: &Expr) -> bool {
    matches!(target, Expr::Member(obj, _, _) if is_self(obj))
        || matches!(target, Expr::Index(base, _, _)
            if matches!(base.as_ref(), Expr::Member(obj, _, _) if is_self(obj)))
}

/// Returns `true` if `method` is a Lem collection **read** method.
///
/// Collection read methods do not write state and do not leave the contract —
/// they are safe to call in `isTaxable`.  Mutating methods (`set`, `add`,
/// `remove`, `delete`, `push`, `pop`, etc.) are excluded.
///
/// The canonical list is defined here (single source of truth — AGENTS §2.4).
/// `cfg.rs::is_collection_mutator` is the complementary mutator list.
fn is_collection_read_method(method: &str) -> bool {
    matches!(
        method,
        "get"
            | "getOr"
            | "has"
            | "contains"
            | "keys"
            | "values"
            | "entries"
            | "len"
            | "isEmpty"
            | "indexOf"
            | "slice"
            | "concat"
            | "map"
            | "filter"
            | "find"
            | "some"
            | "every"
            | "reduce"
    )
}

/// Returns `true` if `target` is a write to a `self.fees.<component>` field
/// (`self.fees.burn`, `self.fees.holders`, or `self.fees.others`).
///
/// Shape: `Member(Member(self, "fees"), component)`.
fn is_self_fees_component_write(target: &Expr) -> bool {
    if let Expr::Member(inner, component, _) = target {
        if matches!(component.as_str(), "burn" | "holders" | "others") {
            if let Expr::Member(obj, field, _) = inner.as_ref() {
                return is_self(obj) && field == "fees";
            }
        }
    }
    false
}

/// Returns `true` if `target` is a write to `self.<name>`.
fn is_self_field(target: &Expr, name: &str) -> bool {
    matches!(target, Expr::Member(obj, field, _) if is_self(obj) && field == name)
}

/// Returns `true` if `expr` is the identifier `block`.
fn is_block_ident(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "block")
}

// ─── Visitors ─────────────────────────────────────────────────────────────────

/// Visitor that detects reads of forbidden `self.<field>` names.
///
/// Used by SAFETY-020 budget-bound check to detect `self.balances` /
/// `self.totalSupply` reads in `distributeTaxes`.
struct ForbiddenFieldReadScanner<'a> {
    forbidden: &'a [&'a str],
    /// The first forbidden field name found, or `None`.
    found: Option<String>,
}

impl Visitor for ForbiddenFieldReadScanner<'_> {
    fn visit_expr(&mut self, expr: &Expr) {
        if self.found.is_some() {
            return; // Already found one — stop scanning.
        }
        if let Expr::Member(obj, field, _) = expr {
            if is_self(obj) && self.forbidden.contains(&field.as_str()) {
                self.found = Some(field.clone());
                return;
            }
        }
        walk_expr(self, expr);
    }
}

/// Result of scanning for `self.taxPool` writes.
enum TaxPoolWriteResult {
    /// No write to `self.taxPool` found.
    None,
    /// A write to `self.taxPool` with a literal integer 0 was found.
    LiteralZero,
    /// A write to `self.taxPool` with a non-literal-zero value was found.
    NonLiteralZero,
}

/// Visitor that scans for writes to `self.taxPool` and classifies them.
///
/// Used by SAFETY-020 zero-before-interaction to verify the canonical drain
/// pattern requires `self.taxPool = 0` (literal zero, not a computed value).
struct TaxPoolZeroWriteScanner {
    result: TaxPoolWriteResult,
}

impl Visitor for TaxPoolZeroWriteScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if matches!(self.result, TaxPoolWriteResult::NonLiteralZero) {
            return; // Already found a non-literal-zero write — stop.
        }
        if let Stmt::Assign { target, value, .. } = stmt {
            if is_self_field(target, "taxPool") {
                if is_literal_zero(value) {
                    self.result = TaxPoolWriteResult::LiteralZero;
                } else {
                    // Non-literal-zero write (e.g. taxPool = taxPool - 1) → reject.
                    self.result = TaxPoolWriteResult::NonLiteralZero;
                }
                return;
            }
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        if matches!(self.result, TaxPoolWriteResult::NonLiteralZero) {
            return;
        }
        if let Expr::Assign_(target, _, value, _) = expr {
            if is_self_field(target, "taxPool") {
                if is_literal_zero(value) {
                    self.result = TaxPoolWriteResult::LiteralZero;
                } else {
                    self.result = TaxPoolWriteResult::NonLiteralZero;
                }
                return;
            }
        }
        walk_expr(self, expr);
    }
}

/// Visitor that detects external calls whose arguments read `self.taxPool`.
///
/// Used by SAFETY-020 zero-before-interaction (C1.3): after zeroing taxPool,
/// an external call must NOT pass `self.taxPool` as an argument (it would
/// pass 0, but the pattern is still non-canonical and could be a mistake).
struct ExtCallArgTaxPoolScanner {
    found: bool,
}

impl Visitor for ExtCallArgTaxPoolScanner {
    fn visit_expr(&mut self, expr: &Expr) {
        if self.found {
            return;
        }
        if let Expr::Call { callee, args, .. } = expr {
            // Only flag external calls (non-self receiver).
            let is_external = match callee.as_ref() {
                Expr::Member(obj, _, _) => !is_self(obj),
                _ => false,
            };
            if is_external {
                // Check if any argument reads self.taxPool.
                for arg in args {
                    let arg_expr = match arg {
                        CallArg::Positional(e) => e,
                        CallArg::Named(_, e) => e,
                    };
                    let mut arg_scanner = SelfFieldReadScanner {
                        field: "taxPool",
                        found: false,
                    };
                    arg_scanner.visit_expr(arg_expr);
                    if arg_scanner.found {
                        self.found = true;
                        return;
                    }
                }
            }
        }
        walk_expr(self, expr);
    }
}

/// Visitor that detects reads of `self.<field>` in an expression.
///
/// Used by `ExtCallArgTaxPoolScanner` to check if external call args read
/// `self.taxPool`.
struct SelfFieldReadScanner<'a> {
    field: &'a str,
    found: bool,
}

impl Visitor for SelfFieldReadScanner<'_> {
    fn visit_expr(&mut self, expr: &Expr) {
        if self.found {
            return;
        }
        if let Expr::Member(obj, name, _) = expr {
            if is_self(obj) && name == self.field {
                self.found = true;
                return;
            }
        }
        walk_expr(self, expr);
    }
}

/// Visitor that detects impurities in `isTaxable`:
/// - Any state write (`self.field = …`).
/// - Calls to `SystemTime`, `block.random`, RNG, or external contracts.
///
/// Over-approximation: any external call is flagged (reject on doubt).
///
/// ## C3 — SystemTime::now() detection
///
/// In Lem, `SystemTime::now()` is parsed as:
/// `Call { callee: Member(Ident("SystemTime"), "now") }`
/// This form is now caught in addition to the bare `Ident("SystemTime")` form.
struct ImpurityScanner {
    /// The first impurity reason found, or `None`.
    reason: Option<String>,
}

impl Visitor for ImpurityScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if self.reason.is_some() {
            return;
        }
        // State write: `self.field = …`
        if let Stmt::Assign { target, .. } = stmt {
            if is_self_field_write(target) {
                self.reason =
                    Some("writes to a state field (isTaxable must be view-pure)".to_owned());
                return;
            }
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        if self.reason.is_some() {
            return;
        }
        match expr {
            // Expression-form state write: `self.field = …`
            Expr::Assign_(target, _, _, _) => {
                if is_self_field_write(target) {
                    self.reason =
                        Some("writes to a state field (isTaxable must be view-pure)".to_owned());
                    return;
                }
            }
            // External call: any method call on a receiver that is NOT `self`
            // and NOT `self.<field>` (a collection method on own state).
            //
            // Allowed (own-state collection reads):
            //   `self.exemptList.get(addr)` — receiver is `self.exemptList`
            //   `self.pairs.has(addr)`      — receiver is `self.pairs`
            //
            // Flagged (external contract calls):
            //   `self.checker.isBlocked(addr)` — receiver is `self.checker` (Address)
            //   `ext.method(…)`                — receiver is a non-self ident
            //   `SystemTime::now()`            — receiver is `SystemTime` ident
            //
            // Soundness boundary (D4): we cannot statically distinguish a collection
            // field from an Address field without type information.  We use the
            // method name as a heuristic: collection read methods (`get`, `has`,
            // `contains`, `keys`, `values`, `getOr`) are allowed; all other
            // methods on a `self.<field>` receiver are flagged as external calls.
            // TODO(4f-tax/step7): full enforcement deferred — see living-notes deferred-D1/D2/D3/D4.
            // Currently: reject-on-doubt (Inconclusive). Step 7 will add branch-aware CFG
            // + block.height built-in that makes full enforcement possible.
            Expr::Call { callee, .. } => {
                if let Expr::Member(obj, method, _) = callee.as_ref() {
                    // `block.random` / `block.randao` reads via method call.
                    if is_block_ident(obj)
                        && matches!(method.as_str(), "random" | "randao" | "prevrandao")
                    {
                        self.reason = Some(format!(
                            "reads `block.{method}` (non-deterministic — \
                             isTaxable must not read block randomness)"
                        ));
                        return;
                    }
                    // C3: `SystemTime::now()` — callee is Member(Ident("SystemTime"), "now").
                    // In Lem, `SystemTime::now()` is parsed as a method call on the
                    // `SystemTime` identifier (path-style call).
                    if matches!(obj.as_ref(), Expr::Ident(name, _) if name == "SystemTime") {
                        self.reason = Some(format!(
                            "calls `SystemTime.{method}` (non-deterministic — \
                             isTaxable must not read clocks or RNG)"
                        ));
                        return;
                    }
                    // `self.method(…)` — internal call, always allowed.
                    if is_self(obj) {
                        // fall through to walk_expr
                    } else if is_self_field_expr(obj) {
                        // `self.<field>.<method>(…)` — allowed only for
                        // collection read methods (not external contract calls).
                        if !is_collection_read_method(method) {
                            self.reason = Some(format!(
                                "makes an external call to `{method}` on a state field \
                                 (isTaxable must not call external contracts)"
                            ));
                            return;
                        }
                    } else {
                        // Non-self receiver — external call.
                        self.reason = Some(format!(
                            "makes an external call to `{method}` \
                             (isTaxable must not call external contracts)"
                        ));
                        return;
                    }
                }
                // `SystemTime::now()` or similar free-function RNG calls
                // where the callee is a bare identifier.
                if let Expr::Ident(name, _) = callee.as_ref() {
                    if matches!(name.as_str(), "SystemTime" | "random" | "rand") {
                        self.reason = Some(format!(
                            "calls `{name}` (non-deterministic — \
                             isTaxable must not read clocks or RNG)"
                        ));
                        return;
                    }
                }
            }
            // `new Contract(…)` — deployment leaves the contract.
            Expr::New { .. } => {
                self.reason = Some(
                    "deploys a new contract (isTaxable must not make external calls)".to_owned(),
                );
                return;
            }
            // `block.random` / `block.timestamp` as a member access (not a call).
            Expr::Member(obj, field, _) if is_block_ident(obj) => {
                if matches!(field.as_str(), "random" | "randao" | "prevrandao") {
                    self.reason = Some(format!(
                        "reads `block.{field}` (non-deterministic — \
                         isTaxable must not read block randomness)"
                    ));
                    return;
                }
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

/// Visitor that detects writes to any `self.fees.<component>` field
/// (`self.fees.burn`, `self.fees.holders`, `self.fees.others`).
///
/// Used by SAFETY-022 to identify fees-setter functions.  In Lem, the `fees`
/// block in `state {}` is written via individual component assignments
/// (`self.fees.burn = N`) rather than a full struct literal.
struct DirectFeesWriteScanner {
    found: bool,
}

impl Visitor for DirectFeesWriteScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if self.found {
            return;
        }
        if let Stmt::Assign { target, .. } = stmt {
            if is_self_fees_component_write(target) {
                self.found = true;
                return;
            }
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        if self.found {
            return;
        }
        if let Expr::Assign_(target, _, _, _) = expr {
            if is_self_fees_component_write(target) {
                self.found = true;
                return;
            }
        }
        walk_expr(self, expr);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
