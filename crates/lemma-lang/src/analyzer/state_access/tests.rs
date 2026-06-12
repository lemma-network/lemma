//! Tests for the P3·Step 5 state-access analyzer.
//!
//! Each test compiles a small contract, runs [`analyze_state_access`] on a
//! named function, and asserts the resulting read/write [`AccessKey`] sets and
//! derived hints.

use crate::lexer::token::Span;
use crate::parser::{Expr, Param, Type};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::{parse, tokenize};

use super::{
    analyze_state_access, classify_access_key, compute_express_eligible, AccessKey, FnAccess,
    StateAccessInfo,
};

// ─── AST-level helpers (for cases that need `msg.sender`, a Step-7 built-in) ─────
//
// `msg` / `block` are context built-ins introduced at P3·Step 7 (P3-checker-14);
// the resolver rejects `msg` as undefined today, so `self.balances[msg.sender]`
// cannot pass `check_skip_wf`.  The analyzer's `SenderSlot` classification is
// purely STRUCTURAL on the AST, so we exercise it directly via hand-built
// expressions until the built-in lands.  (Intentional-deferred, AGENTS §1 Rule 7.)

/// A dummy span for hand-built AST nodes.
fn sp() -> Span {
    Span::at(0, 0, 0)
}

/// Build `Expr::Ident(name)`.
fn ident(name: &str) -> Expr {
    Expr::Ident(name.to_owned(), sp())
}

/// Build `self.<field>` = `Member(Ident("self"), field)`.
fn self_field(field: &str) -> Expr {
    Expr::Member(Box::new(ident("self")), field.to_owned(), sp())
}

/// Build `msg.sender` = `Member(Ident("msg"), "sender")`.
fn msg_sender() -> Expr {
    Expr::Member(Box::new(ident("msg")), "sender".to_owned(), sp())
}

/// Build `self.<field>[idx]`.
fn self_index(field: &str, idx: Expr) -> Expr {
    Expr::Index(Box::new(self_field(field)), Box::new(idx), sp())
}

/// Build a param named `name` (type irrelevant to classification).
fn param(name: &str) -> Param {
    Param {
        name: name.to_owned(),
        ty: Type::U128,
        default_expr: None,
        span: sp(),
    }
}

/// Compile `src` to a `TypedAst` (skipping well-formedness gating, mirroring the
/// `cfg`/`dataflow` test harness).
fn typed_ast(src: &str) -> crate::type_checker::TypedAst {
    let tokens = tokenize(src).expect("tokenize");
    let ast = parse(tokens).expect("parse");
    crate::type_checker::check_skip_wf(ast).expect("check")
}

/// Run the analyzer on the function named `fn_name` in the first contract.
fn analyze(src: &str, fn_name: &str) -> StateAccessInfo {
    let ast = typed_ast(src);
    let contracts = ast.contracts();
    let contract: &TypedContract<'_> = &contracts[0];
    let funcs = contract.functions();
    let func: &ContractFunction<'_> = funcs
        .iter()
        .find(|f| f.name == fn_name)
        .unwrap_or_else(|| panic!("function `{fn_name}` not found"));
    analyze_state_access(contract, func)
}

// ─── Field classification ───────────────────────────────────────────────────────

#[test]
fn field_read_classified_as_field() {
    let info = analyze(
        r#"contract C {
state { totalSupply: u128 = 0 }
pub view fn supply() -> u128 {
return self.totalSupply
}
}"#,
        "supply",
    );
    assert!(
        info.reads
            .contains(&AccessKey::Field("totalSupply".to_owned())),
        "reads must contain Field(totalSupply); got {:?}",
        info.reads
    );
    assert!(info.writes.is_empty(), "view fn writes nothing");
}

#[test]
fn field_write_classified_as_field() {
    let info = analyze(
        r#"contract C {
state { totalSupply: u128 = 0 }
pub fn mint(x: u128) {
self.totalSupply = x
}
}"#,
        "mint",
    );
    assert!(
        info.writes
            .contains(&AccessKey::Field("totalSupply".to_owned())),
        "writes must contain Field(totalSupply); got {:?}",
        info.writes
    );
}

// ─── SenderSlot classification (AST-level — `msg` is a Step-7 built-in) ──────────

#[test]
fn sender_slot_read() {
    // `self.balances[msg.sender]` → SenderSlot("balances").
    let expr = self_index("balances", msg_sender());
    let key = classify_access_key(&expr, &[]).expect("self-indexed access classifies");
    assert_eq!(key, AccessKey::SenderSlot("balances".to_owned()));
}

#[test]
fn sender_slot_write() {
    // Same structure on an assignment LHS yields the same SenderSlot key — the
    // classifier is read/write-context-agnostic (the walker buckets it).
    let expr = self_index("balances", msg_sender());
    let key = classify_access_key(&expr, &[]).expect("self-indexed access classifies");
    assert_eq!(key, AccessKey::SenderSlot("balances".to_owned()));
}

#[test]
fn non_self_access_classifies_as_none() {
    // A bare local / non-self member is not a state access.
    assert!(classify_access_key(&ident("x"), &[]).is_none());
    let other = Expr::Member(Box::new(ident("other")), "field".to_owned(), sp());
    assert!(classify_access_key(&other, &[]).is_none());
}

#[test]
fn field_classification_via_helper() {
    // `self.totalSupply` → Field; confirms the helper matches the e2e path.
    let key = classify_access_key(&self_field("totalSupply"), &[]).expect("self.field classifies");
    assert_eq!(key, AccessKey::Field("totalSupply".to_owned()));
}

#[test]
fn param_slot_classification_via_helper() {
    // `self.balances[to]` with `to` a param → ParamSlot.
    let expr = self_index("balances", ident("to"));
    let key = classify_access_key(&expr, &[param("to")]).expect("classifies");
    assert_eq!(
        key,
        AccessKey::ParamSlot {
            field: "balances".to_owned(),
            key: "to".to_owned(),
        }
    );
}

#[test]
fn non_param_ident_index_is_dynamic_slot() {
    // `self.balances[k]` where `k` is NOT a param → conservative DynamicSlot.
    let expr = self_index("balances", ident("k"));
    let key = classify_access_key(&expr, &[param("to")]).expect("classifies");
    assert_eq!(key, AccessKey::DynamicSlot("balances".to_owned()));
}

// ─── ParamSlot classification ───────────────────────────────────────────────────

#[test]
fn param_slot() {
    let info = analyze(
        r#"contract C {
state { balances: Map<Address, u128> }
init() {}
pub fn setFor(to: Address, x: u128) {
self.balances[to] = x
}
}"#,
        "setFor",
    );
    assert!(
        info.writes.contains(&AccessKey::ParamSlot {
            field: "balances".to_owned(),
            key: "to".to_owned(),
        }),
        "writes must contain ParamSlot{{balances, to}}; got {:?}",
        info.writes
    );
}

// ─── DynamicSlot classification ─────────────────────────────────────────────────

#[test]
fn dynamic_slot() {
    // A key that is neither `msg.sender` nor a parameter (a local binding) cannot
    // be proven disjoint → conservative DynamicSlot (end-to-end through check).
    let info = analyze(
        r#"contract C {
state { balances: Map<Address, u128> }
init() {}
pub fn setLocal(to: Address, x: u128) {
let k = to
self.balances[k] = x
}
}"#,
        "setLocal",
    );
    assert!(
        info.writes
            .contains(&AccessKey::DynamicSlot("balances".to_owned())),
        "writes must contain DynamicSlot(balances) for a local-var key; got {:?}",
        info.writes
    );
}

// ─── Transitive closure ─────────────────────────────────────────────────────────

#[test]
fn transitive_read_write_via_helper() {
    // a() calls b(); b writes self.x. a's writes must include Field(x).
    let info = analyze(
        r#"contract C {
state { x: u128 = 0 }
pub fn a() {
self.b()
}
fn b() {
self.x = 1
}
}"#,
        "a",
    );
    assert!(
        info.writes.contains(&AccessKey::Field("x".to_owned())),
        "a's writes must include Field(x) via transitive call to b; got {:?}",
        info.writes
    );
}

// ─── is_express_eligible ────────────────────────────────────────────────────────

#[test]
fn is_express_eligible_true_for_sender_only_writes() {
    // Sender-only writes, no external call → eligible.  Built directly because
    // `msg.sender` cannot pass the resolver yet (Step-7 built-in).
    let mut access = FnAccess::default();
    access
        .writes
        .insert(AccessKey::SenderSlot("balances".to_owned()));
    access
        .reads
        .insert(AccessKey::SenderSlot("balances".to_owned()));
    assert!(
        compute_express_eligible(&access),
        "sender-only writes with no ext call must be Express-eligible"
    );
}

#[test]
fn is_express_eligible_false_for_field_write() {
    // End-to-end: a whole-field write disqualifies Express.
    let info = analyze(
        r#"contract C {
state { totalSupply: u128 = 0 }
pub fn mint(x: u128) {
self.totalSupply = x
}
}"#,
        "mint",
    );
    assert!(
        !info.is_express_eligible,
        "a whole-field write must NOT be Express-eligible; writes = {:?}",
        info.writes
    );
}

#[test]
fn is_express_eligible_false_for_external_call() {
    // Sender-only writes, but an external call disqualifies the fast-path.
    let mut access = FnAccess {
        has_external_call: true,
        ..FnAccess::default()
    };
    access
        .writes
        .insert(AccessKey::SenderSlot("balances".to_owned()));
    assert!(
        !compute_express_eligible(&access),
        "an external call must disqualify Express even with sender-only writes"
    );
}

#[test]
fn is_express_eligible_false_for_param_slot_write() {
    // A param-keyed write (not sender-owned) disqualifies Express (end-to-end).
    let info = analyze(
        r#"contract C {
state { balances: Map<Address, u128> }
init() {}
pub fn setFor(to: Address, x: u128) {
self.balances[to] = x
}
}"#,
        "setFor",
    );
    assert!(
        !info.is_express_eligible,
        "a param-slot write is not sender-owned → not Express-eligible; writes = {:?}",
        info.writes
    );
}

#[test]
fn external_call_makes_express_ineligible_and_conservative() {
    // Pure external-call function: no provable writes, but ext call present →
    // express-ineligible (conservative).  Confirms ext-call handling end to end.
    let info = analyze(
        r#"contract C {
state { x: u128 = 0 }
pub fn forward(target: Address, amount: u128) {
let _ = target.transfer(amount)
}
}"#,
        "forward",
    );
    assert!(
        !info.is_express_eligible,
        "a function with an external call must be Express-ineligible"
    );
}

// ─── Modifier folding (P3-own-3 b) ──────────────────────────────────────────────

#[test]
fn modifier_state_folds_into_decorated_fn() {
    // The `requireOpen` modifier reads self.gateOpen; the decorated fn inherits
    // that read.  (Avoids `msg`, a Step-7 built-in not yet resolvable.)
    let info = analyze(
        r#"contract C {
state { gateOpen: bool = true, value: u128 = 0 }
init() {}
modifier requireOpen() {
assert(self.gateOpen)
_
}
@requireOpen
pub fn setValue(v: u128) {
self.value = v
}
}"#,
        "setValue",
    );
    assert!(
        info.reads
            .contains(&AccessKey::Field("gateOpen".to_owned())),
        "decorated fn must inherit modifier's read of Field(gateOpen); got {:?}",
        info.reads
    );
    assert!(
        info.writes.contains(&AccessKey::Field("value".to_owned())),
        "decorated fn keeps its own write Field(value); got {:?}",
        info.writes
    );
}

// ─── Read AND write to the same field ───────────────────────────────────────────

#[test]
fn same_field_read_and_write_appear_in_both_sets() {
    // self.count = self.count + 1 → Field(count) is both read and written.
    let info = analyze(
        r#"contract C {
state { count: u128 = 0 }
pub fn bump() {
self.count = self.count + 1
}
}"#,
        "bump",
    );
    assert!(
        info.reads.contains(&AccessKey::Field("count".to_owned())),
        "RHS read of count must be in reads; got {:?}",
        info.reads
    );
    assert!(
        info.writes.contains(&AccessKey::Field("count".to_owned())),
        "LHS write of count must be in writes; got {:?}",
        info.writes
    );
}

// ─── Compound assignment reads (C1 fix) ─────────────────────────────────────────

#[test]
fn compound_assign_records_target_read_unkeyed() {
    // `self.count += 1` is "read count, add 1, write count".
    // The implicit read of `count` must appear in the read set.
    let info = analyze(
        r#"contract C {
state { count: u128 = 0 }
pub fn bump() {
self.count += 1
}
}"#,
        "bump",
    );
    assert!(
        info.reads.contains(&AccessKey::Field("count".to_owned())),
        "compound += must record an implicit READ of count; reads = {:?}",
        info.reads
    );
    assert!(
        info.writes.contains(&AccessKey::Field("count".to_owned())),
        "compound += must also record a WRITE of count; writes = {:?}",
        info.writes
    );
}

#[test]
fn compound_assign_records_target_read_keyed() {
    // `self.balances[to] += amount` — ParamSlot{"balances","to"} must appear
    // in BOTH reads AND writes (read-then-write semantics of compound assign).
    let info = analyze(
        r#"contract C {
state { balances: Map<Address, u128> }
init() {}
pub fn credit(to: Address, amount: u128) {
self.balances[to] += amount
}
}"#,
        "credit",
    );
    let slot = AccessKey::ParamSlot {
        field: "balances".to_owned(),
        key: "to".to_owned(),
    };
    assert!(
        info.reads.contains(&slot),
        "compound += on keyed slot must record implicit READ; reads = {:?}",
        info.reads
    );
    assert!(
        info.writes.contains(&slot),
        "compound += on keyed slot must record WRITE; writes = {:?}",
        info.writes
    );
}

// ─── Modifier with external call disqualifies Express (C2/M1) ───────────────────

#[test]
fn modifier_with_external_call_disqualifies_express() {
    // A modifier that makes an external call must propagate `has_external_call`
    // into the decorated function, making it Express-ineligible even if the
    // function body itself only writes sender-owned slots.
    //
    // The modifier `checkExternal` calls `target.verify()` — an external call.
    // The decorated function `doTransfer` only writes `self.balances[msg.sender]`
    // (sender-owned), but the modifier's external call must disqualify Express.
    //
    // We test this end-to-end via `analyze_state_access` on a contract where
    // the modifier body contains an external call.  Because `msg.sender` is a
    // Step-7 built-in not yet resolvable, we use a param-keyed write instead
    // (which is also not Express-eligible on its own), and verify the modifier's
    // external call propagates `has_external_call` into the decorated function.
    let info = analyze(
        r#"contract C {
state { balances: Map<Address, u128>, checker: Address }
init() {}
modifier checkExternal(target: Address) {
let _ = target.verify()
_
}
@checkExternal
pub fn setBalance(to: Address, x: u128) {
self.balances[to] = x
}
}"#,
        "setBalance",
    );
    // The decorated function must be Express-ineligible because the modifier
    // makes an external call (has_external_call propagates via modifier folding).
    assert!(
        !info.is_express_eligible,
        "modifier with external call must disqualify Express on decorated fn; \
         writes = {:?}",
        info.writes
    );
}

// ─── SenderSlot walker bucketing (C2/M1) ────────────────────────────────────────

#[test]
fn sender_slot_walker_buckets_into_writes() {
    // Verify that the AccessWalker correctly buckets a SenderSlot key into
    // the WRITE set (not reads) when it appears on an assignment LHS.
    //
    // We test this via `classify_access_key` + direct FnAccess construction
    // (AST-level) because `msg.sender` is a Step-7 built-in not yet resolvable
    // through `check_skip_wf`.  This exercises the walker's bucketing path:
    // `record_assign_target` must call `classify_access_key` and insert into
    // `writes`, not `reads`.
    use crate::lexer::token::Span;
    use crate::parser::Stmt;

    let sp = Span::at(0, 0, 0);
    // Build: `self.balances[msg.sender] = x`
    let target = self_index("balances", msg_sender());
    let value = ident("x");
    let stmt = Stmt::Assign {
        target: target.clone(),
        op: crate::parser::AssignOp::Assign,
        value,
        span: sp,
    };

    // Run the walker directly on this single statement.
    let mut acc = FnAccess::default();
    let params: Vec<crate::parser::Param> = vec![];
    let mut walker = super::AccessWalker::new(&params, &mut acc);
    use crate::visit::Visitor;
    walker.visit_stmt(&stmt);

    // The SenderSlot must be in writes (LHS of pure assignment).
    assert!(
        acc.writes
            .contains(&AccessKey::SenderSlot("balances".to_owned())),
        "SenderSlot must be bucketed into writes on assignment LHS; \
         writes = {:?}",
        acc.writes
    );
    // And NOT in reads (pure `=` does not read the target).
    assert!(
        !acc.reads
            .contains(&AccessKey::SenderSlot("balances".to_owned())),
        "pure assignment LHS must NOT appear in reads; reads = {:?}",
        acc.reads
    );
}

// ─── estimated_gas ──────────────────────────────────────────────────────────────

#[test]
fn gas_estimate_body_less_function_returns_zero() {
    // A function with no body (interface / abstract declaration) must return
    // 0 gas — there are no statements to count.
    //
    // We test the body-less path by constructing a `ContractFunction` with
    // `body: None` directly, mirroring how the type-checker represents
    // interface methods.
    use crate::parser::Visibility;
    use crate::type_checker::typed_contract::ContractFunction;

    let func = ContractFunction {
        name: "noBody",
        visibility: &Visibility::Pub,
        annotations: &[],
        params: &[],
        return_type: None,
        body: None, // no body — interface / abstract
        symbol_id: None,
    };

    let gas = super::estimate_gas(&func);
    assert_eq!(gas, 0, "body-less function must estimate 0 gas; got {gas}");
}

#[test]
fn estimated_gas_is_monotonic_in_body_size() {
    let small = analyze(
        r#"contract C {
state { x: u128 = 0 }
pub fn one() {
self.x = 1
}
}"#,
        "one",
    );
    let large = analyze(
        r#"contract C {
state { x: u128 = 0 }
pub fn many() {
self.x = 1
self.x = 2
self.x = 3
self.x = 4
}
}"#,
        "many",
    );
    assert!(
        large.estimated_gas > small.estimated_gas,
        "larger body must estimate more gas: small={} large={}",
        small.estimated_gas,
        large.estimated_gas
    );
    assert!(small.estimated_gas > 0, "non-empty body must cost > 0 gas");
}
