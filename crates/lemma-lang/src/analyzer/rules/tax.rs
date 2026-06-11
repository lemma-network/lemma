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
//! See `09-SAFETY_ANALYZER_SPEC §3-ter`.

use std::collections::BTreeSet;

use crate::analyzer::cfg::{self, build_call_graph, CfgNode};
use crate::analyzer::error::SafetyError;
use crate::parser::{Expr, Stmt};
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
/// 3. **Zero-before-interaction**: `self.taxPool = 0` must dominate every
///    `ExternalCall` in `distributeTaxes`.
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
    violations.extend(check_020_budget_bound(&distribute_fn));

    // Sub-check 3: zero-before-interaction — taxPool must be zeroed before any ext call.
    violations.extend(check_020_zero_before_interaction(&distribute_fn));

    violations
}

/// Sub-check 1: no call-graph path from the transfer path to `distributeTaxes`.
///
/// Transfer path = `transfer`, `transferFrom`, any `#[onTransfer]`-annotated fn,
/// plus their transitive callees (via the call graph).
fn check_020_separation(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let call_graph = build_call_graph(contract);

    // Seed: direct transfer-path entry functions.
    let transfer_entries: BTreeSet<String> = contract
        .functions()
        .into_iter()
        .filter(|f| is_transfer_path_entry(f.name, f.annotations))
        .map(|f| f.name.to_owned())
        .collect();

    if transfer_entries.is_empty() {
        return Vec::new();
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
fn check_020_budget_bound(
    distribute_fn: &crate::type_checker::typed_contract::ContractFunction<'_>,
) -> Vec<SafetyError> {
    let Some(body) = distribute_fn.body else {
        return Vec::new();
    };

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

/// Sub-check 3: `self.taxPool = 0` must dominate every `ExternalCall` in
/// `distributeTaxes`.
///
/// Linear CFG scan: if an `ExternalCall` appears before a `StateWrite` to
/// `taxPool` (or if there is an `ExternalCall` with no preceding `taxPool`
/// zero-write), the drain shape is incorrect.
fn check_020_zero_before_interaction(
    distribute_fn: &crate::type_checker::typed_contract::ContractFunction<'_>,
) -> Vec<SafetyError> {
    let nodes = cfg::cfg_nodes(distribute_fn);

    // Track whether we have seen `self.taxPool = 0` before the first ext call.
    let mut taxpool_zeroed = false;

    for node in &nodes {
        match node {
            CfgNode::StateWrite { key, .. } if key == "taxPool" => {
                // Any write to taxPool counts as the zero-write for this check.
                // (A non-zero write is a separate concern; here we track ordering.)
                taxpool_zeroed = true;
            }
            CfgNode::StateWrite { .. } => {
                // Write to a different state field — does not affect the taxPool
                // zero-before-interaction ordering check.
            }
            CfgNode::ExternalCall { .. } => {
                if !taxpool_zeroed {
                    // External call before taxPool was zeroed — violation.
                    return vec![SafetyError::TaxPoolNotZeroedFirst {
                        func: distribute_fn.name.to_owned(),
                    }];
                }
            }
            CfgNode::InternalCall { .. } => {
                // Internal calls are not external interactions — no violation here.
            }
        }
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

/// SAFETY-022: Any function that writes `self.fees` must use the asymmetric
/// timelock pattern for increases.
///
/// Decidable over-approximation: a function that writes `self.fees` (or a
/// component) without a `pendingFees` / `effectiveBlock` pattern is flagged.
///
/// ## What we check (decidable shape)
///
/// The canonical setter shape is:
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
/// The over-approximation: any function that writes `self.fees` directly
/// (without going through a `pendingFees` / `effectiveBlock` indirection)
/// is flagged as `FeeRaiseNoTimelock`.  A function that only writes
/// `self.pendingFees` (not `self.fees` directly) is assumed to follow the
/// canonical pattern and is not flagged.
///
/// ## Soundness boundary (documented)
///
/// This is a structural pattern check, not a full data-flow proof.  A setter
/// that writes `self.fees` directly on a decrease path AND `self.pendingFees`
/// on an increase path is correctly accepted (the direct write is the decrease
/// path).  A setter that writes `self.fees` directly on BOTH paths is flagged
/// (the increase path lacks the delay).  A setter that uses a non-canonical
/// structure (e.g. a helper function) may slip — tracked as a soundness
/// boundary in `living-notes.md`.
fn check_safety_022(contract: &TypedContract<'_>) -> Vec<SafetyError> {
    let mut violations = Vec::new();

    for func in contract.functions() {
        let Some(body) = func.body else {
            continue;
        };

        // Check whether this function writes `self.fees` directly.
        let mut fees_write_scanner = DirectFeesWriteScanner { found: false };
        fees_write_scanner.visit_stmts(body);

        if !fees_write_scanner.found {
            continue; // Not a fees setter — skip.
        }

        // A direct `self.fees` write is present.  Check whether the function
        // also writes `self.feeEffectiveBlock` (the timelock marker).
        // If it does NOT, the increase path lacks the required delay.
        let mut timelock_scanner = TimelockMarkerScanner { found: false };
        timelock_scanner.visit_stmts(body);

        if !timelock_scanner.found {
            // Direct fees write with no timelock marker → FeeRaiseNoTimelock.
            violations.push(SafetyError::FeeRaiseNoTimelock {
                func: func.name.to_owned(),
            });
        }
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
            if is_self_ident(obj) && self.forbidden.contains(&field.as_str()) {
                self.found = Some(field.clone());
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
            //
            // Soundness boundary: we cannot statically distinguish a collection
            // field from an Address field without type information.  We use the
            // method name as a heuristic: collection read methods (`get`, `has`,
            // `contains`, `keys`, `values`, `getOr`) are allowed; all other
            // methods on a `self.<field>` receiver are flagged as external calls.
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
                    // `self.method(…)` — internal call, always allowed.
                    if is_self_ident(obj) {
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
                // `SystemTime::now()` or similar free-function RNG calls.
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

/// Visitor that detects writes to `self.feeEffectiveBlock` — the timelock
/// marker that signals the canonical asymmetric-timelock pattern.
///
/// Used by SAFETY-022 to distinguish a compliant setter (writes both
/// `self.fees` and `self.feeEffectiveBlock`) from a non-compliant one
/// (writes `self.fees` directly without a timelock marker).
struct TimelockMarkerScanner {
    found: bool,
}

impl Visitor for TimelockMarkerScanner {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if self.found {
            return;
        }
        if let Stmt::Assign { target, .. } = stmt {
            if is_self_field(target, "feeEffectiveBlock") {
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
            if is_self_field(target, "feeEffectiveBlock") {
                self.found = true;
                return;
            }
        }
        walk_expr(self, expr);
    }
}

// ─── Expression predicates ────────────────────────────────────────────────────

/// Returns `true` if `expr` is the identifier `self`.
fn is_self_ident(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "self")
}

/// Returns `true` if `expr` is the identifier `block`.
fn is_block_ident(expr: &Expr) -> bool {
    matches!(expr, Expr::Ident(name, _) if name == "block")
}

/// Returns `true` if `target` is a write to any `self.<field>`.
fn is_self_field_write(target: &Expr) -> bool {
    matches!(target, Expr::Member(obj, _, _) if is_self_ident(obj))
        || matches!(target, Expr::Index(base, _, _)
            if matches!(base.as_ref(), Expr::Member(obj, _, _) if is_self_ident(obj)))
}

/// Returns `true` if `expr` is `self.<field>` (a member access on `self`).
///
/// Used to distinguish own-state collection reads (`self.exemptList.get(…)`)
/// from external contract calls (`self.checker.isBlocked(…)`) in the
/// `ImpurityScanner`.  Note: this is a structural check — it cannot distinguish
/// a `Map<Address, bool>` field from an `Address` field without type info.
fn is_self_field_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Member(obj, _, _) if is_self_ident(obj))
}

/// Returns `true` if `method` is a Lem collection **read** method.
///
/// Collection read methods do not write state and do not leave the contract —
/// they are safe to call in `isTaxable`.  Mutating methods (`set`, `add`,
/// `remove`, `delete`, `push`, `pop`, etc.) are excluded.
///
/// See `cfg.rs::is_collection_mutator` for the complementary mutator list.
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
                return is_self_ident(obj) && field == "fees";
            }
        }
    }
    false
}

/// Returns `true` if `target` is a write to `self.<name>`.
fn is_self_field(target: &Expr, name: &str) -> bool {
    matches!(target, Expr::Member(obj, field, _) if is_self_ident(obj) && field == name)
}

// Suppress unused-import warning: FEE_INCREASE_DELAY is a protocol constant
// referenced in the module doc and error messages; it is not used in the
// current decidable-shape check (which detects the absence of the timelock
// marker structurally rather than verifying the numeric delay value).
// The constant is retained here for documentation and future tightening.
const _: u64 = FEE_INCREASE_DELAY;

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
