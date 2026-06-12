//! State-access analyzer (P3·Step 5) — per-function read/write sets.
//!
//! ## Purpose
//!
//! Extracts, for every contract function, the set of state slots it **reads**
//! and **writes**, plus two derived hints:
//! - `is_express_eligible` — the function only writes the caller's own slots
//!   (Express mempool fast-path proof, 08-EXECUTION_SPEC §1.7).
//! - `estimated_gas` — a coarse pre-codegen cost estimate (refined at Step 6).
//!
//! These feed **Flux** (parallel execution conflict detection) and **Express**
//! (mempool fast-path).  Both consume the sets at Step 7, mapping [`AccessKey`]
//! onto `lemma-vm`'s runtime `StateKey` once addresses + slot hashes are known.
//!
//! ## Soundness direction (08 §1.7) — hint, never correctness input
//!
//! Read/write sets are an **optimization hint**.  Flux's MVCC re-validates every
//! transaction, so a wrong hint only costs a re-execution, never wrong state.
//! Therefore the analyzer **over-approximates on doubt**: an unprovable keying
//! becomes [`AccessKey::DynamicSlot`] (whole-field conflict), never a silently
//! dropped access.  Under-approximation (missing a real write) is the only
//! danger and is deliberately avoided — dynamic keys widen the set.
//!
//! External calls disqualify Express eligibility and are re-validated by Flux
//! (08 §1.7 — hints are optimization-only; MVCC re-validates).
//! The read/write SET is **NOT** widened for external calls — only the
//! `has_external_call` flag is set, which prevents Express scheduling.
//!
//! ## Per-slot keying (why not a bare field name)
//!
//! Flux conflict detection is **per slot**: `balances[alice]` and
//! `balances[bob]` are distinct slots that can execute in parallel.  A bare
//! field name (`"balances"`) would force Flux to serialize *all* transfers,
//! defeating the feature.  [`AccessKey`] therefore captures both the field and
//! *how* it is keyed.  See the type docs for the variant → consumer mapping.
//!
//! ## Dependency direction (AGENTS §8)
//!
//! [`AccessKey`] is **lemma-lang-native** — this crate must not depend on
//! `lemma-vm`.  The VM maps `AccessKey` to its own `StateKey` at Step 7.
//!
//! ## Pipeline position
//!
//! Producer-only: [`analyze_state_access`] is **not** wired into the compile
//! pipeline (it gates nothing).  Codegen (Step 6) and the VM (Step 7) consume
//! the hint.

use std::collections::{BTreeMap, BTreeSet};

use crate::parser::{Expr, Param, Stmt};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::visit::{walk_expr, walk_stmt, Visitor};

use super::cfg::{build_call_graph, is_collection_mutator, walk_function, CfgNode};
use super::util::is_self;

// ─── AccessKey ─────────────────────────────────────────────────────────────────

/// A state-access key extracted by the compiler for Flux/Express scheduling hints.
///
/// Captures not just WHICH field is touched but HOW it is keyed — the keying
/// distinguishes per-slot disjointness (`balances[alice]` vs `balances[bob]`),
/// which is the whole point of the hint (Flux schedules disjoint slots in
/// parallel).
///
/// This is a lemma-lang-NATIVE type.  `lemma-vm` maps it to its own `StateKey`
/// at consumption time (Step 7) when runtime addresses + slot hashes are
/// available — lemma-lang must not depend on lemma-vm (AGENTS §8).
///
/// `Ord` is derived for deterministic `BTreeSet` iteration (AGENTS §7.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum AccessKey {
    /// Whole field, no keying.  e.g. `self.totalSupply`, `self.paused`.
    Field(String),
    /// Field indexed by `msg.sender`.  e.g. `self.balances[msg.sender]`.
    ///
    /// This is what proves [`StateAccessInfo::is_express_eligible`] (sender-owned
    /// slot) and per-sender disjointness for Flux.
    SenderSlot(String),
    /// Field indexed by a function parameter or other named value.
    /// e.g. `self.balances[to]` → `ParamSlot { field: "balances", key: "to" }`.
    ///
    /// Flux derives slot-disjointness when two txns supply distinct param values.
    ParamSlot {
        /// The indexed field name (e.g. `"balances"`).
        field: String,
        /// The parameter name used as the key (e.g. `"to"`).
        key: String,
    },
    /// Field indexed by a dynamic / unprovable expression.
    /// e.g. `self.balances[hash(x)]`.
    ///
    /// CONSERVATIVE: treated as touching the whole field (assume conflict).
    DynamicSlot(String),
}

// ─── StateAccessInfo ───────────────────────────────────────────────────────────

/// Per-function state-access summary produced by [`analyze_state_access`].
///
/// `reads`/`writes` use [`BTreeSet`] for deterministic iteration (AGENTS §7.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StateAccessInfo {
    /// Slots read by the function (direct body + transitive callees + modifiers).
    pub reads: BTreeSet<AccessKey>,
    /// Slots written by the function (direct body + transitive callees + modifiers).
    pub writes: BTreeSet<AccessKey>,
    /// `true` only if every write is an [`AccessKey::SenderSlot`] and the function
    /// makes no external call — the Express mempool fast-path proof.
    pub is_express_eligible: bool,
    /// Coarse pre-codegen gas estimate (placeholder, refined at Step 6).
    pub estimated_gas: u64,
}

// ─── Constants ─────────────────────────────────────────────────────────────────

/// Placeholder per-statement gas cost used by [`StateAccessInfo::estimated_gas`].
///
/// **Placeholder only**: a flat per-statement charge gives a monotonic,
/// over-approximate estimate sufficient for early scheduling heuristics.  Step 6
/// (codegen) replaces this with per-opcode metering once the IR exists.  Named
/// per AGENTS §3.3 (no magic numbers).
const GAS_PER_STMT_ESTIMATE: u64 = 200;

// ─── Public entry point ─────────────────────────────────────────────────────────

/// Compute the [`StateAccessInfo`] for `func` within its `contract`.
///
/// The `contract` argument is required for the transitive closure (internal
/// callee read/write sets) and modifier folding — a function's effective access
/// set includes everything its internal callees and applied modifiers touch.
///
/// ## Algorithm
///
/// 1. **Direct extraction** — walk every function + modifier body, classifying
///    each `self.<field>` access into an [`AccessKey`] and bucketing it into a
///    read or write set (a write is an assignment LHS or a collection mutator;
///    everything else is a read).
/// 2. **Transitive closure** — union each internal callee's sets into the
///    caller via a worklist fixpoint over the call graph (terminates on cycles;
///    sets grow monotonically over a finite universe).
/// 3. **Modifier folding** (P3-own-3 b) — union the sets of every modifier
///    applied to `func` via an `@name` annotation.
/// 4. **Derived hints** — `is_express_eligible` and `estimated_gas`.
#[must_use]
pub fn analyze_state_access(
    contract: &TypedContract<'_>,
    func: &ContractFunction<'_>,
) -> StateAccessInfo {
    let call_graph = build_call_graph(contract);

    // Direct (intra-body) sets for every function, keyed by name.
    let mut direct: BTreeMap<String, FnAccess> = contract
        .functions()
        .into_iter()
        .map(|f| (f.name.to_owned(), direct_access(&f)))
        .collect();

    // Modifier sets, keyed by modifier name (for folding in step 3).
    let modifier_access: BTreeMap<String, FnAccess> = contract
        .modifiers()
        .into_iter()
        .map(|m| (m.name.clone(), direct_modifier_access(m)))
        .collect();

    // 2. Transitive closure over internal call edges.
    close_transitively(&mut direct, &call_graph);

    // Effective set for `func` = its closed direct set …
    let mut effective = direct.remove(func.name).unwrap_or_default();

    // … plus 3. modifier folding (union — order-independent for a SET).
    fold_modifiers(func, &modifier_access, &mut effective);

    // 4. Derived hints.
    let is_express_eligible = compute_express_eligible(&effective);
    let estimated_gas = estimate_gas(func);

    StateAccessInfo {
        reads: effective.reads,
        writes: effective.writes,
        is_express_eligible,
        estimated_gas,
    }
}

// ─── FnAccess — per-function read/write/ext accumulator ─────────────────────────

/// Direct (intra-body) access of a single function or modifier body.
///
/// `has_external_call` is tracked separately because an external call may touch
/// arbitrary unknown state: it both disqualifies the Express fast-path and is
/// recorded conservatively (the caller assumes whole-field conflicts).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct FnAccess {
    reads: BTreeSet<AccessKey>,
    writes: BTreeSet<AccessKey>,
    /// `true` if the body contains a call that leaves the contract boundary.
    has_external_call: bool,
}

impl FnAccess {
    /// Union `other` into `self` (used by closure + modifier folding).
    fn union(&mut self, other: &FnAccess) {
        self.reads.extend(other.reads.iter().cloned());
        self.writes.extend(other.writes.iter().cloned());
        self.has_external_call |= other.has_external_call;
    }
}

// ─── Step 1: direct extraction ───────────────────────────────────────────────────

/// Extract the direct read/write/ext access of `func`'s own body.
fn direct_access(func: &ContractFunction<'_>) -> FnAccess {
    let Some(body) = func.body else {
        return FnAccess::default();
    };
    let mut acc = FnAccess {
        has_external_call: !walk_function(func).ext_calls.is_empty(),
        ..FnAccess::default()
    };
    let mut walker = AccessWalker::new(func.params, &mut acc);
    walker.visit_stmts(body);
    acc
}

/// Extract the direct read/write/ext access of a modifier body (P3-own-3 b).
fn direct_modifier_access(modifier: &crate::parser::ModifierDef) -> FnAccess {
    let mut acc = FnAccess {
        has_external_call: body_has_external_call(&modifier.body),
        ..FnAccess::default()
    };
    let mut walker = AccessWalker::new(&modifier.params, &mut acc);
    walker.visit_stmts(&modifier.body);
    acc
}

/// Returns `true` if a statement slice contains any contract-boundary-leaving
/// call.  Mirrors the external-call detection in [`super::cfg`] (a method call
/// on a non-`self`, non-collection-field receiver, or a `new` deployment) by
/// reusing the canonical CFG walk on a synthetic statement slice.
fn body_has_external_call(stmts: &[Stmt]) -> bool {
    super::cfg::walk_stmts_fn_walk(stmts)
        .cfg_nodes
        .iter()
        .any(|n| matches!(n, CfgNode::ExternalCall { .. }))
}

/// Visitor that buckets each `self.<field>` access into a read or write key.
///
/// ## Read/write context detection (documented approach)
///
/// The visitor tracks whether it is currently descending the **LHS of an
/// assignment** (`in_write_lhs`).  A `self.<field>` reached on the LHS is a
/// write; any other `self.<field>` is a read.  Collection mutators
/// (`self.field.set(…)`) are writes detected at the `Call` node (reusing
/// [`super::cfg`]'s mutator classification via [`is_collection_mutator`]).
///
/// This complements [`super::cfg::FnWalk`]: that walk produces bare-field write
/// keys for the CFG; this one produces per-slot [`AccessKey`]s for both reads
/// and writes.  The two are kept separate because their key precision and
/// consumers differ (DRY does not merge them — different output types).
struct AccessWalker<'a> {
    params: &'a [Param],
    acc: &'a mut FnAccess,
}

impl<'a> AccessWalker<'a> {
    fn new(params: &'a [Param], acc: &'a mut FnAccess) -> Self {
        Self { params, acc }
    }

    /// Record `target` (an assignment LHS) as a write, then descend its index
    /// expression as a read (the key sub-expression is evaluated, not written).
    fn record_assign_target(&mut self, target: &Expr) {
        if let Some(key) = classify_access_key(target, self.params) {
            self.acc.writes.insert(key);
        }
        // The index/key sub-expression of `self.map[k] = …` is *read*.
        if let Expr::Index(_, idx, _) = target {
            self.visit_expr(idx);
        }
    }

    /// Record `target` as a READ (mirror of `record_assign_target` for the
    /// read set).  Used by compound assignments (`+=`, `-=`, `*=`, `/=`, `%=`)
    /// which **read** the target before writing it — the read is implicit in
    /// the operator but real: `self.count += 1` reads `count` then writes it.
    ///
    /// Only the slot key itself is inserted; the index sub-expression is
    /// already visited by `record_assign_target` (called first for the write).
    fn record_target_read(&mut self, target: &Expr) {
        if let Some(key) = classify_access_key(target, self.params) {
            self.acc.reads.insert(key);
        }
    }
}

impl Visitor for AccessWalker<'_> {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        if let Stmt::Assign {
            target, op, value, ..
        } = stmt
        {
            self.record_assign_target(target);
            // Compound assignment (+=, -=, *=, /=, %=) also READS the target
            // first — `self.count += 1` is "read count, add 1, write count".
            // Pure `=` is a write-only; all other operators are read-then-write.
            if !matches!(op, crate::parser::AssignOp::Assign) {
                self.record_target_read(target);
            }
            self.visit_expr(value);
            return;
        }
        walk_stmt(self, stmt);
    }

    fn visit_expr(&mut self, expr: &Expr) {
        match expr {
            // Expression-form assignment: `self.field = …` — LHS is a write.
            // Compound form (`+=` etc.) also reads the target first.
            Expr::Assign_(target, op, value, _) => {
                self.record_assign_target(target);
                if !matches!(op, crate::parser::AssignOp::Assign) {
                    self.record_target_read(target);
                }
                self.visit_expr(value);
                return;
            }
            // Collection mutator on own state: `self.field.set(k, v)` — a write.
            // Continue walking (args are reads) via `walk_expr` below.
            // TODO(step5/step7): set(msg.sender, v) could refine to SenderSlot
            // instead of whole-Field — deferred behind msg.sender resolution
            // (P3-checker-14, Step 7). Tracked: living-notes Technical Debt
            // (collection-mutator-sender-slot).
            Expr::Call { callee, .. } => {
                if let Expr::Member(recv, method, _) = callee.as_ref() {
                    if is_collection_mutator(method) {
                        if let Some(key) = classify_access_key(recv, self.params) {
                            self.acc.writes.insert(key);
                        }
                    }
                }
            }
            // `self.<field>[idx]` read.  Classify the whole slot, then descend
            // ONLY into the index sub-expression — descending into the `base`
            // (`self.<field>`) would double-count it as a bare `Field` read,
            // shadowing the precise per-slot key.  Short-circuit via `return`.
            Expr::Index(base, idx, _) if self_field_name(base).is_some() => {
                if let Some(key) = classify_access_key(expr, self.params) {
                    self.acc.reads.insert(key);
                }
                self.visit_expr(idx);
                return;
            }
            // `self.<field>` whole-field read.  Assignment LHS is handled (and
            // short-circuited) above, so a `self.field` reaching here is a
            // genuine read (RHS, condition, argument, …).
            Expr::Member(_, _, _) => {
                if let Some(key) = classify_access_key(expr, self.params) {
                    self.acc.reads.insert(key);
                }
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

// ─── Key classification ───────────────────────────────────────────────────────

/// Classify a `self.<field>` / `self.<field>[idx]` access expression into an
/// [`AccessKey`], or `None` if `expr` is not a `self` state access.
///
/// Conservative: a self-indexed access whose key is neither `msg.sender` nor a
/// known parameter is [`AccessKey::DynamicSlot`] (never dropped — 08 §1.7).
fn classify_access_key(expr: &Expr, params: &[Param]) -> Option<AccessKey> {
    match expr {
        // self.field — whole field.
        Expr::Member(obj, field, _) if is_self(obj) => Some(AccessKey::Field(field.clone())),
        // self.field[idx] — keyed slot; classify the index.
        Expr::Index(base, idx, _) => {
            let field = self_field_name(base)?;
            Some(classify_indexed(field, idx, params))
        }
        _ => None,
    }
}

/// Classify the index expression of `self.<field>[idx]`.
fn classify_indexed(field: String, idx: &Expr, params: &[Param]) -> AccessKey {
    // `self.field[msg.sender]` — sender-owned slot.
    if is_msg_sender(idx) {
        return AccessKey::SenderSlot(field);
    }
    // `self.field[param]` — parameter-keyed slot (Flux slot-disjointness).
    if let Expr::Ident(name, _) = idx {
        if params.iter().any(|p| &p.name == name) {
            return AccessKey::ParamSlot {
                field,
                key: name.clone(),
            };
        }
    }
    // Anything else (computed key, literal, nested) — conservative whole-field.
    AccessKey::DynamicSlot(field)
}

/// If `expr` is `self.<field>`, return the field name; otherwise `None`.
fn self_field_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Member(obj, field, _) if is_self(obj) => Some(field.clone()),
        _ => None,
    }
}

/// Returns `true` if `expr` is exactly `msg.sender`.
fn is_msg_sender(expr: &Expr) -> bool {
    matches!(expr, Expr::Member(obj, field, _)
        if field == "sender" && matches!(obj.as_ref(), Expr::Ident(n, _) if n == "msg"))
}

// ─── Step 2: transitive closure ──────────────────────────────────────────────────

/// Close every function's access set over internal call edges via a worklist
/// fixpoint (mirrors `dataflow::transitive_writes`).
///
/// Terminates on cyclic call graphs (recursion): sets grow monotonically over a
/// finite slot universe, so the `changed` flag eventually stays `false`.
fn close_transitively(direct: &mut BTreeMap<String, FnAccess>, call_graph: &super::cfg::CallGraph) {
    let mut changed = true;
    while changed {
        changed = false;
        for (caller, callees) in call_graph {
            for callee in callees {
                // Self-recursion contributes nothing new — skip.
                if callee == caller {
                    continue;
                }
                let Some(callee_access) = direct.get(callee).cloned() else {
                    continue;
                };
                let entry = direct.entry(caller.clone()).or_default();
                let before = (
                    entry.reads.len(),
                    entry.writes.len(),
                    entry.has_external_call,
                );
                entry.union(&callee_access);
                let after = (
                    entry.reads.len(),
                    entry.writes.len(),
                    entry.has_external_call,
                );
                if after != before {
                    changed = true;
                }
            }
        }
    }
}

// ─── Step 3: modifier folding (P3-own-3 b) ──────────────────────────────────────

/// Fold the access set of every modifier applied to `func` into `effective`.
///
/// A function decorated `@name` carries an annotation whose `name` matches the
/// `modifier name` definition; the modifier body runs around `_`, so both its
/// pre- and post-placeholder access contribute.  For the read/write **SET**,
/// union is sufficient and **order-independent** — modifier-application order
/// only affects the CFG (a separate Step 7 concern), not the set membership.
fn fold_modifiers(
    func: &ContractFunction<'_>,
    modifier_access: &BTreeMap<String, FnAccess>,
    effective: &mut FnAccess,
) {
    for ann in func.annotations {
        if let Some(mod_access) = modifier_access.get(&ann.name) {
            effective.union(mod_access);
        }
    }
}

// ─── Step 4: derived hints ───────────────────────────────────────────────────────

/// `true` only if every write is an [`AccessKey::SenderSlot`] and there is no
/// external call.  Any other write kind (`Field`, `ParamSlot`, `DynamicSlot`)
/// or any external call disqualifies the Express fast-path (conservative).
///
/// A function with **no** writes is trivially eligible (read-only sender path).
fn compute_express_eligible(access: &FnAccess) -> bool {
    if access.has_external_call {
        return false;
    }
    access
        .writes
        .iter()
        .all(|k| matches!(k, AccessKey::SenderSlot(_)))
}

/// Coarse gas estimate: flat per-statement charge over the function body.
///
/// **Placeholder** (Step 6 replaces with per-opcode metering).  Counts every
/// statement in the body — including nested ones — via a lightweight visitor so
/// the estimate is monotonic in body size.
fn estimate_gas(func: &ContractFunction<'_>) -> u64 {
    let Some(body) = func.body else {
        return 0;
    };
    let mut counter = StmtCounter { count: 0 };
    counter.visit_stmts(body);
    counter.count.saturating_mul(GAS_PER_STMT_ESTIMATE)
}

/// Counts every statement reached by the canonical walk (placeholder gas model).
struct StmtCounter {
    count: u64,
}

impl Visitor for StmtCounter {
    fn visit_stmt(&mut self, stmt: &Stmt) {
        self.count = self.count.saturating_add(1);
        walk_stmt(self, stmt);
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
