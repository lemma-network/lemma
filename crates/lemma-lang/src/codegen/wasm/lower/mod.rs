//! WASM lowering context and shared helpers.
//!
//! This module defines [`LowerCtx`] — the codegen context for lowering a single
//! function body — and the free helper functions used across the lowering
//! submodules (selectors, storage keys, modifier inlining, etc.).
//!
//! ## Submodule layout (split from the original `wasm.rs` god-module)
//!
//! - [`expr`] — expression lowering (`emit_expr`, `emit_literal`, `emit_ident`,
//!   `emit_binary`, `emit_unary`, address constants/predicates)
//! - [`stmt`] — statement + control-flow lowering (`emit_stmt`, `emit_block`,
//!   `emit_assign`, `emit_with_modifiers`)
//! - [`storage`] — storage read/write lowering (`emit_storage_read`,
//!   `emit_storage_write`)
//! - [`arithmetic`] — checked arithmetic + u128 comparison helpers
//! - [`xcall`] — cross-contract call lowering (`rawCall`, `staticCall`,
//!   `delegateCall`)
//! - [`dispatch`] — dispatch prologue, bump allocator, contract function body
//!   emission

pub(crate) mod arithmetic;
pub(crate) mod dispatch;
pub(crate) mod expr;
pub(crate) mod stmt;
pub(crate) mod storage;
pub(crate) mod xcall;

use std::collections::BTreeMap;

use lemma_core::{DROPS_PER_DRIP, DROPS_PER_LEM};
use wasm_encoder::{Function, ValType};

use crate::error::LangError;
use crate::lexer::token::Span;
use crate::parser::{expr_span, CallArg, Expr, ModifierDef, Stmt, UnitKind};
use crate::type_checker::typed_contract::{ContractFunction, TypedContract};
use crate::type_checker::types::{ResolvedType, SymbolSig};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Initial linear memory size in pages (1 page = 64 KiB).
///
/// Two pages: page 0 for static data, page 1+ for the bump heap.
/// The bump allocator starts at HEAP_BASE_ADDR (page 1 start = 65536).
pub(crate) const INITIAL_MEMORY_PAGES: u64 = 2;

/// Bump-heap base address — first byte past the static data segment.
///
/// Set to page 1 start (65536 = 64 KiB). The guest bump allocator starts
/// here and grows upward. See 08-EXECUTION_SPEC §4.5.
pub(crate) const HEAP_BASE_ADDR: i32 = 65536;

// ─── Address constant data-segment offsets (P3·Step 6g) ──────────────────────
//
// Three 20-byte Address constants are placed in page 0 at fixed offsets.
// These are compile-time constants mirroring lemma-core::Address (AGENTS §2 DRY).
// Layout (page 0, starting at offset 0):
//   offset 0..20:  Address::zero   (20 zero bytes)
//   offset 20..40: Address::burn   (BURN_BYTES from lemma-core)
//   offset 40..60: Address::native_lem (NATIVE_LEM_BYTES from lemma-core)
//
// All offsets are well below the heap base (65536), so they never conflict
// with the bump allocator.

/// Byte offset in page 0 for the `Address::zero` constant (20 zero bytes).
pub(crate) const ADDR_ZERO_OFFSET: u32 = 0;

/// Byte offset in page 0 for the `Address::burn` constant (BURN_BYTES).
pub(crate) const ADDR_BURN_OFFSET: u32 = 20;

/// Byte offset in page 0 for the `Address::native_lem` constant (NATIVE_LEM_BYTES).
pub(crate) const ADDR_NATIVE_OFFSET: u32 = 40;

/// Number of active data segments emitted for Address constants.
pub(crate) const ADDR_DATA_SEGMENT_COUNT: u32 = 3;

/// Byte length of a Lemma `Address` value in guest linear memory.
///
/// All cross-contract call host functions receive the callee address as a
/// (ptr: i32, len: i32) pair where `len` is always this constant.
/// Named constant — no magic numbers (AGENTS §3.3).
pub(crate) const ADDRESS_BYTE_LEN: u32 = 20;

// ─── Unit-literal multipliers (P3·Step 6h) ───────────────────────────────────
//
// Time units lower to **seconds**; value units lower to **Drop** (Lemma's base
// denomination). All multipliers are named constants — no magic numbers (AGENTS
// §3.3). Value-unit constants re-use `lemma_core::amount` exports (AGENTS §2.4
// DRY — single definition, imported here). Time constants are codegen-local
// (no other crate consumes them today).
//
// Conversion table (03-LANGUAGE_SPEC §2):
//   .seconds × 1             → seconds
//   .minutes × 60            → seconds
//   .hours   × 3_600         → seconds
//   .days    × 86_400        → seconds
//   .ether   × DROPS_PER_LEM  (1e18) → Drop
//   .gwei    × DROPS_PER_DRIP (1e9)  → Drop  (1 Drip = DROPS_PER_DRIP Drops)

/// `.seconds` × 1 — explicit constant for a readable, exhaustive `unit_multiplier` match.
const SECONDS_PER_SECOND: u128 = 1;
/// `.minutes` → 60 seconds.
const SECONDS_PER_MINUTE: u128 = 60;
/// `.hours` → 3 600 seconds.
const SECONDS_PER_HOUR: u128 = 3_600;
/// `.days` → 86 400 seconds.
const SECONDS_PER_DAY: u128 = 86_400;

/// Return the fold multiplier for a [`UnitKind`] (named constants — no magic numbers).
///
/// Time units scale to **seconds**; value units scale to **Drop**.
/// `.ether`/`.gwei` multipliers are re-exported from `lemma_core::amount`
/// (AGENTS §2.4 — single source of truth). Time multipliers are defined above.
///
/// # Panics
///
/// Never panics — exhaustive match, no wildcard arm.
pub(super) fn unit_multiplier(kind: &UnitKind) -> u128 {
    match kind {
        UnitKind::Seconds => SECONDS_PER_SECOND,
        UnitKind::Minutes => SECONDS_PER_MINUTE,
        UnitKind::Hours => SECONDS_PER_HOUR,
        UnitKind::Days => SECONDS_PER_DAY,
        UnitKind::Ether => DROPS_PER_LEM,
        UnitKind::Gwei => DROPS_PER_DRIP,
    }
}

// ─── Host function type signatures ───────────────────────────────────────────

/// WASM type signatures for each host function, in `IMPORT_ORDER` order.
///
/// Each entry is `(params, results)`. The type index in the TypeSection
/// matches the position in this array.
///
/// `pub(crate)` so execution tests can build a wasmtime stub linker matching
/// these signatures (M3 — CR finding).
pub(crate) const HOST_SIGS: &[(&[ValType], &[ValType])] = &[
    // 0: block_height() -> i64
    (&[], &[ValType::I64]),
    // 1: block_timestamp() -> i64
    (&[], &[ValType::I64]),
    // 2: gas_remaining() -> i64
    (&[], &[ValType::I64]),
    // 3: msg_value() -> i64
    (&[], &[ValType::I64]),
    // 4: msg_sender(register_id: i32)
    (&[ValType::I32], &[]),
    // 5: input(register_id: i32)
    (&[ValType::I32], &[]),
    // 6: register_len(register_id: i32) -> i64
    (&[ValType::I32], &[ValType::I64]),
    // 7: read_register(register_id: i32, ptr: i32)
    (&[ValType::I32, ValType::I32], &[]),
    // 8: storage_read(key_ptr: i32, key_len: i32, register_id: i32) -> i32
    (&[ValType::I32, ValType::I32, ValType::I32], &[ValType::I32]),
    // 9: storage_write(key_ptr: i32, key_len: i32, val_ptr: i32, val_len: i32)
    (
        &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        &[],
    ),
    // 10: storage_delete(key_ptr: i32, key_len: i32)
    (&[ValType::I32, ValType::I32], &[]),
    // 11: emit_event(topics_ptr: i32, topics_len: i32, data_ptr: i32, data_len: i32)
    (
        &[ValType::I32, ValType::I32, ValType::I32, ValType::I32],
        &[],
    ),
    // 12: transfer(to_ptr: i32, to_len: i32, amount: i64) -> i32
    (&[ValType::I32, ValType::I32, ValType::I64], &[ValType::I32]),
    // 13: value_return(ptr: i32, len: i32)
    (&[ValType::I32, ValType::I32], &[]),
    // 14: call_contract(addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64, value: i64) -> i32
    (
        &[
            ValType::I32,
            ValType::I32,
            ValType::I32,
            ValType::I64,
            ValType::I64,
        ],
        &[ValType::I32],
    ),
    // 15: static_call(addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64) -> i32
    (
        &[ValType::I32, ValType::I32, ValType::I32, ValType::I64],
        &[ValType::I32],
    ),
    // 16: delegate_call(addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64) -> i32
    (
        &[ValType::I32, ValType::I32, ValType::I32, ValType::I64],
        &[ValType::I32],
    ),
];

// ─── Function selector + storage key computation ─────────────────────────────

/// Compute the 4-byte function selector for dispatch.
///
/// Selector = first 4 bytes of `blake3(fn_name + "(" + param_types + ")")`,
/// interpreted as a **little-endian** u32 (matching WASM `i32.load` native
/// endianness — AGENTS §7.1 determinism).
///
/// Example: `transfer(Address,u128)` → blake3("transfer(Address,u128)")[0..4] as LE u32.
///
/// This is Lemma-native (blake3, not keccak like Solidity). Deterministic.
pub(crate) fn compute_selector(
    func: &ContractFunction<'_>,
    contract: &TypedContract<'_>,
) -> Result<u32, LangError> {
    let mut sig = func.name.to_string();
    sig.push('(');

    // Use resolved param types from the function signature for canonical names.
    // The FnSig has (name, ResolvedType, has_default) tuples.
    // If we can't get canonical param types from the type checker, this is
    // an internal invariant violation — codegen must not emit a selector
    // from Debug output (ABI-fragile).
    let param_types: Vec<String> = if let Some(sym_id) = func.symbol_id {
        if let Some(SymbolSig::Function(fn_sig)) = contract.sig(sym_id) {
            fn_sig
                .params
                .iter()
                .map(|(_, ty, _)| type_canonical_name(ty))
                .collect()
        } else {
            return Err(LangError::Codegen {
                message: format!(
                    "cannot compute selector for function '{}': no resolved type signature",
                    func.name
                ),
            });
        }
    } else {
        return Err(LangError::Codegen {
            message: format!(
                "cannot compute selector for function '{}': no resolved type signature",
                func.name
            ),
        });
    };

    sig.push_str(&param_types.join(","));
    sig.push(')');

    let hash = blake3::hash(sig.as_bytes());
    let bytes = hash.as_bytes();
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Detect 4-byte function-selector collisions within a single contract (L-2).
///
/// Two dispatchable functions whose [`compute_selector`] outputs are equal would
/// make the second one (in declaration order) silently unreachable on a deployed,
/// immutable contract — the dispatch if/else chain and the ABI descriptor both
/// route the selector to whichever function appears first. On an immutable
/// contract this is irreversible and silent (the Solidity selector-clash class),
/// so it is rejected at **compile time** rather than allowed to ship.
///
/// `selectors` is `(function_name, selector)` in dispatch/declaration order. The
/// caller derives each selector via [`compute_selector`] (the single canonical
/// derivation — AGENTS §2 DRY); this helper only checks for duplicates.
///
/// # Determinism (AGENTS §7.1)
///
/// Uses a `BTreeMap` (not `HashMap`) and reports the collision against the
/// first-seen function in declaration order, so the same input always yields the
/// same error message across validators.
///
/// # Errors
///
/// Returns [`LangError::Codegen`] naming both colliding functions and the shared
/// selector (as `0x........`) the first time two selectors are found equal.
pub(crate) fn detect_selector_collisions(selectors: &[(&str, u32)]) -> Result<(), LangError> {
    // BTreeMap<selector, first-seen function name> — deterministic iteration and
    // deterministic first-seen reporting (declaration order is the input order).
    let mut seen: BTreeMap<u32, &str> = BTreeMap::new();
    for &(name, selector) in selectors {
        if let Some(&first) = seen.get(&selector) {
            return Err(LangError::Codegen {
                message: format!(
                    "selector collision between {first}() and {name}() (selector {selector:#010x})"
                ),
            });
        }
        seen.insert(selector, name);
    }
    Ok(())
}

/// Canonical type name for selector signature computation and ABI descriptors.
///
/// Maps `ResolvedType` to a stable string used in the blake3 hash input
/// (selector) and in the `"lemma.abi"` custom-section JSON (P3·Step 6i).
/// Must be deterministic and consistent across validators (AGENTS §7.1).
pub(crate) fn type_canonical_name(ty: &ResolvedType) -> String {
    match ty {
        ResolvedType::Bool => "bool".into(),
        ResolvedType::U8 => "u8".into(),
        ResolvedType::U16 => "u16".into(),
        ResolvedType::U32 => "u32".into(),
        ResolvedType::U64 => "u64".into(),
        ResolvedType::U128 => "u128".into(),
        ResolvedType::U256 => "u256".into(),
        ResolvedType::I8 => "i8".into(),
        ResolvedType::I16 => "i16".into(),
        ResolvedType::I32 => "i32".into(),
        ResolvedType::I64 => "i64".into(),
        ResolvedType::I128 => "i128".into(),
        ResolvedType::I256 => "i256".into(),
        ResolvedType::AddressTy => "Address".into(),
        ResolvedType::StringTy => "string".into(),
        ResolvedType::Bytes => "bytes".into(),
        ResolvedType::HashTy => "Hash".into(),
        // For compound types, use display_name (deterministic)
        other => other.display_name(),
    }
}

/// Derive the 32-byte storage key for a state field.
///
/// Key = blake3(field_name).as_bytes() (full 32 bytes).
/// Deterministic, consistent across validators (AGENTS §7.1).
pub(crate) fn storage_key(field_name: &str) -> [u8; 32] {
    let hash = blake3::hash(field_name.as_bytes());
    *hash.as_bytes()
}

/// Byte width of a resolved type in storage encoding.
///
/// Returns the number of bytes needed to store a value of this type in
/// linear memory for storage read/write operations.
pub(super) fn storage_byte_width(ty: &ResolvedType) -> Result<u32, LangError> {
    match ty {
        ResolvedType::Bool => Ok(1),
        ResolvedType::U8 | ResolvedType::I8 => Err(LangError::Codegen {
            message: "sub-word types (u8/i8) in storage not yet implemented (M1)".into(),
        }),
        ResolvedType::U16 | ResolvedType::I16 => Err(LangError::Codegen {
            message: "sub-word types (u16/i16) in storage not yet implemented (M1)".into(),
        }),
        ResolvedType::U32 | ResolvedType::I32 => Ok(4),
        ResolvedType::U64 | ResolvedType::I64 => Ok(8),
        ResolvedType::U128 => Ok(16),
        ResolvedType::AddressTy => Ok(ADDRESS_BYTE_LEN),
        _ => Err(LangError::Codegen {
            message: format!(
                "storage encoding for type {} not yet implemented",
                ty.display_name()
            ),
        }),
    }
}

// ─── Modifier inlining helpers (P3·Step 6f) ──────────────────────────────────

/// Split a modifier body at the `Stmt::Placeholder` position.
///
/// Returns `(pre, post)` where `pre` is everything before `_` and `post` is
/// everything after `_`. Returns `Err` if no `_` is found (defensive; WF-006
/// should have caught this — AGENTS §7.2, no panics in codegen).
pub(super) fn split_at_placeholder(stmts: &[Stmt]) -> Result<(&[Stmt], &[Stmt]), LangError> {
    for (i, stmt) in stmts.iter().enumerate() {
        if matches!(stmt, Stmt::Placeholder(_)) {
            return Ok((&stmts[..i], &stmts[i + 1..]));
        }
    }
    Err(LangError::Codegen {
        message: "modifier body has no `_` placeholder (WF-006 should have caught this)".into(),
    })
}

/// Look up a modifier definition by name from the contract's modifiers.
///
/// Returns `Err` if the modifier is not found — this indicates an annotation
/// referencing a non-existent modifier (should have been caught by the type
/// checker, but codegen handles it defensively).
pub(super) fn find_modifier<'a>(
    contract: &'a TypedContract<'a>,
    name: &str,
) -> Result<&'a ModifierDef, LangError> {
    contract
        .modifiers()
        .into_iter()
        .find(|m| m.name == name)
        .ok_or_else(|| LangError::Codegen {
            message: format!("modifier '{name}' not found in contract"),
        })
}

/// Resolved param info for a contract function: (name, ResolvedType) pairs.
///
/// Used by calldata decoding to know the Lem-level type of each param
/// (needed to distinguish u128 i64-pair from plain i64, and Address pointer
/// from plain i32).
pub(super) fn get_fn_resolved_params(
    func: &ContractFunction<'_>,
    contract: &TypedContract<'_>,
) -> Vec<(String, ResolvedType)> {
    if let Some(sym_id) = func.symbol_id {
        if let Some(SymbolSig::Function(fn_sig)) = contract.sig(sym_id) {
            return fn_sig
                .params
                .iter()
                .map(|(name, ty, _)| (name.clone(), ty.clone()))
                .collect();
        }
    }
    Vec::new()
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Extract the `Expr` from a `CallArg`, returning an error for named args.
///
/// Cross-contract call lowering only supports positional arguments. Named
/// arguments (e.g. `rawCall(data: calldata)`) are not yet supported in
/// codegen — the type checker handles them, but lowering is deferred.
///
/// This is a free function (not a method) because it does not need `LowerCtx`
/// state — it is a pure structural extraction (AGENTS §3.1 single responsibility).
pub(super) fn call_arg_expr(arg: &CallArg) -> Result<&Expr, LangError> {
    match arg {
        CallArg::Positional(expr) => Ok(expr),
        CallArg::Named(name, _) => Err(LangError::Codegen {
            message: format!(
                "named argument '{name}' in cross-contract call not yet supported in codegen"
            ),
        }),
        // Forward-compatibility for #[non_exhaustive]
        #[allow(unreachable_patterns)]
        _ => Err(LangError::Codegen {
            message: "unknown CallArg variant in cross-contract call lowering".into(),
        }),
    }
}

/// Return the variant name of an `Expr` for error messages.
///
/// Avoids printing the full debug representation (which includes all inner data).
/// The `#[allow(unreachable_patterns)]` is required because `Expr` is
/// `#[non_exhaustive]` — the wildcard arm is needed for forward compatibility.
// consumer: LowerCtx::emit_expr (P3·Step 6c)
#[allow(dead_code, unreachable_patterns)]
pub(super) fn expr_variant_name(expr: &Expr) -> &'static str {
    match expr {
        Expr::Literal(..) => "Literal",
        Expr::Ident(..) => "Ident",
        Expr::Tuple(..) => "Tuple",
        Expr::Array(..) => "Array",
        Expr::Struct_ { .. } => "Struct",
        Expr::Call { .. } => "Call",
        Expr::Index(..) => "Index",
        Expr::Member(..) => "Member",
        Expr::Unary(..) => "Unary",
        Expr::Binary(..) => "Binary",
        Expr::Ternary { .. } => "Ternary",
        Expr::Nullish(..) => "Nullish",
        Expr::Try_(..) => "Try",
        Expr::Cast { .. } => "Cast",
        Expr::Lambda { .. } => "Lambda",
        Expr::New { .. } => "New",
        Expr::Match_(..) => "Match",
        Expr::If_ { .. } => "If",
        Expr::Template(..) => "Template",
        Expr::Assign_(..) => "Assign",
        // Forward-compatibility for #[non_exhaustive]
        _ => "Unknown",
    }
}

// ─── LoopCtx — break/continue label tracking ─────────────────────────────────

/// Tracks the WASM block nesting for break/continue label resolution.
///
/// Each entry represents a loop construct (`while`/`loop`) with its
/// break and continue targets expressed as *absolute* block depths.
/// At the point of a `break`/`continue`, the relative `br` depth is
/// computed as `current_block_depth - target_depth`.
///
/// This correctly handles nested control flow (if/else inside loops):
/// the `br` depth adjusts for any intervening blocks.
pub(super) struct LoopCtx {
    /// Absolute block depth of the outer `block` (break target).
    pub(super) break_target_depth: u32,
    /// Absolute block depth of the inner `loop` (continue target).
    pub(super) continue_target_depth: u32,
}

// ─── LowerCtx — expression + statement lowering context ──────────────────────

/// Codegen context for lowering a single function body.
///
/// Holds the contract reference (for type lookups), the WASM function body
/// being built, and the local variable table.
///
/// ## Local variable layout
///
/// WASM locals are indexed sequentially: function params first (0..N),
/// then explicit locals. The `locals` map tracks `name → index`.
/// Temp locals (for checked arithmetic) are allocated via `alloc_temp_local`.
///
/// ## Loop tracking (P3·Step 6d)
///
/// `loop_stack` tracks nested loop contexts for break/continue resolution.
/// `block_depth` tracks the current WASM block nesting depth (incremented
/// by `block`/`loop`/`if`, decremented by `end`).
///
/// ## Storage access (P3·Step 6e)
///
/// `state_fields` maps field names to their resolved type and 32-byte storage
/// key (blake3 hash of the field name). `alloc_fn_idx` is the WASM function
/// index of the internal bump allocator.
// consumer: emit_test_expr_module (P3·Step 6c tests); emit_module (P3·Step 6d/6e)
pub(crate) struct LowerCtx<'a> {
    /// The contract being compiled (for `type_of` lookups).
    pub(super) contract: &'a TypedContract<'a>,
    /// WASM function body being built.
    pub(super) func: Function,
    /// Local variable name → WASM local index mapping.
    /// BTreeMap for deterministic iteration (AGENTS §7.1).
    pub(super) locals: BTreeMap<String, u32>,
    /// Next available local index.
    pub(super) next_local: u32,
    /// Accumulated local type declarations (count, type) for the function.
    /// Params are not included here — only explicitly declared locals.
    pub(super) local_types: Vec<(u32, ValType)>,
    /// Stack of loop contexts for break/continue resolution.
    /// Pushed on entering while/loop, popped on exit.
    pub(super) loop_stack: Vec<LoopCtx>,
    /// Current WASM block nesting depth (incremented by block/loop/if).
    pub(super) block_depth: u32,
    /// WASM function index of the internal bump allocator.
    /// Set to 0 for test helpers that don't use storage.
    pub(super) alloc_fn_idx: u32,
    /// State field map: field_name → (resolved_type, 32-byte storage key).
    /// BTreeMap for deterministic iteration (AGENTS §7.1).
    pub(super) state_fields: BTreeMap<String, (&'a ResolvedType, [u8; 32])>,
}

impl<'a> LowerCtx<'a> {
    /// Create a new lowering context for a function with the given parameters.
    ///
    /// Parameters are assigned local indices 0..N in declaration order.
    pub(crate) fn new(contract: &'a TypedContract<'a>, params: &[(String, ValType)]) -> Self {
        let mut locals = BTreeMap::new();
        for (i, (name, _vt)) in params.iter().enumerate() {
            locals.insert(name.clone(), i as u32);
        }
        // Function::new takes the *extra* locals (not params).
        // We'll accumulate them in local_types and build the Function at finish().
        Self {
            contract,
            func: Function::new(vec![]),
            locals,
            next_local: params.len() as u32,
            local_types: Vec::new(),
            loop_stack: Vec::new(),
            block_depth: 0,
            alloc_fn_idx: 0,
            state_fields: BTreeMap::new(),
        }
    }

    /// Allocate a temporary local of the given type. Returns its index.
    pub(super) fn alloc_temp_local(&mut self, vt: ValType) -> u32 {
        let idx = self.next_local;
        self.next_local += 1;
        self.local_types.push((1, vt));
        idx
    }

    /// Resolve the type of an expression by its span.
    ///
    /// Returns `Err(LangError::Codegen)` if the type is not found — this
    /// should not happen for well-formed, type-checked ASTs.
    pub(super) fn resolve_type(&self, span: &Span) -> Result<ResolvedType, LangError> {
        self.contract
            .type_of(span)
            .cloned()
            .ok_or_else(|| LangError::Codegen {
                message: format!(
                    "no resolved type for expression at line {} col {}",
                    span.line, span.col
                ),
            })
    }

    /// Resolve the type of an expression, with fallback for `self.field`.
    ///
    /// The type checker may store `Unknown` for `self.field` member access
    /// in contract context (the inference pass handles struct fields but not
    /// contract state fields). This method falls back to the state field map
    /// when the expression is `Expr::Member(self, field_name)`.
    pub(super) fn resolve_expr_type(&self, expr: &Expr) -> Result<ResolvedType, LangError> {
        // Try the type checker's span-based map first
        let span = expr_span(expr);
        if let Some(ty) = self.contract.type_of(&span) {
            // If the type checker resolved it to a concrete type, use it.
            // Unknown means the type checker couldn't resolve it — fall through.
            if *ty != ResolvedType::Unknown {
                return Ok(ty.clone());
            }
        }

        // Fallback: if this is self.field, look up from state_fields
        if let Expr::Member(receiver, field, _) = expr {
            if let Expr::Ident(name, _) = receiver.as_ref() {
                if name == "self" {
                    if let Some((ty, _)) = self.state_fields.get(field.as_str()) {
                        return Ok((*ty).clone());
                    }
                }
            }
        }

        // No type found
        Err(LangError::Codegen {
            message: format!(
                "no resolved type for expression at line {} col {}",
                span.line, span.col
            ),
        })
    }
}
