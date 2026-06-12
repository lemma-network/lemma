//! WASM binary emitter — wasm-encoder backend.
//!
//! Emits a valid WASM module from a type-checked Lem contract. Expression
//! lowering (literals, checked arithmetic, comparison, local variable read)
//! was added in P3·Step 6c. Statement/control-flow lowering is 6d; function
//! dispatch + storage host calls are 6e.
//!
//! ## Backend choice
//!
//! Uses `wasm-encoder = "=0.251.0"` (bytecodealliance, decisions-log DB-A52).
//! Chosen for determinism: identical input → identical output bytes, no global
//! state, no RNG, no hash-map iteration in the emit path (AGENTS §7.1).
//!
//! ## Section ordering
//!
//! Canonical WASM section order (per WebAssembly spec §5.5.2):
//! Type → Import → Function → Table → Memory → Global → Export →
//! Start → Element → DataCount → Code → Data → Custom
//!
//! This module emits: Type → Import → Function → Memory → Global → Export → Code.
//!
//! ## Determinism guarantee (AGENTS §7.1)
//!
//! - No `HashMap`/`HashSet` — `BTreeMap`/`BTreeSet` only.
//! - No `SystemTime`, `rand`, or floating-point in the emit path.
//! - Section/function/export ordering is fully deterministic (fixed constants).
//! - `wasm-encoder` itself is a purely syntactic byte emitter with no internal
//!   non-determinism.

use std::collections::BTreeMap;

use wasm_encoder::{
    CodeSection, ConstExpr, EntityType, ExportKind, ExportSection, Function, FunctionSection,
    GlobalSection, GlobalType, ImportSection, Instruction, MemorySection, MemoryType, Module,
    TypeSection, ValType,
};

use crate::codegen::abi::{self, HOST_IMPORT_COUNT, IMPORT_MODULE, IMPORT_ORDER};
use crate::codegen::types::{is_i64, is_signed, is_sub_word};
use crate::error::LangError;
use crate::lexer::token::Span;
#[cfg(test)]
use crate::parser::expr_span;
use crate::parser::{BinaryOp, Expr, Literal, UnaryOp};
use crate::type_checker::typed_contract::TypedContract;
use crate::type_checker::types::ResolvedType;

// ─── Constants ────────────────────────────────────────────────────────────────

/// Initial linear memory size in pages (1 page = 64 KiB).
const INITIAL_MEMORY_PAGES: u64 = 1;

/// Bump-heap base address — first byte past the static data segment.
///
/// Set to page 1 start (65536 = 64 KiB). The guest bump allocator starts
/// here and grows upward. See 08-EXECUTION_SPEC §4.5.
const HEAP_BASE_ADDR: i32 = 65536;

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
];

// ─── Public API ───────────────────────────────────────────────────────────────

/// Emit a valid WASM module for the given contract.
///
/// Builds the full section layout: Type → Import → Function → Memory →
/// Global → Export → Code. Expression lowering (P3·Step 6c) handles
/// literals, checked arithmetic, comparisons, and local variable reads.
///
/// # Returns
///
/// `Ok(Vec<u8>)` — a valid WebAssembly binary, or
/// `Err(LangError::Codegen)` if expression lowering or section assembly fails.
///
/// # Determinism
///
/// Calling this function twice with the same input produces byte-identical
/// output. See module-level doc for the determinism guarantee.
// consumer: codegen::compile orchestrator (P3·Step 6a+); lib.rs pipeline (P3·Step 6j)
#[allow(dead_code)]
pub(crate) fn emit_module(_contract: &TypedContract<'_>) -> Result<Vec<u8>, LangError> {
    let mut module = Module::new();

    // ── 1. Type section ───────────────────────────────────────────────────
    // First: one type per host function signature (indices 0..HOST_IMPORT_COUNT-1).
    // Then: the `call` entry point type (index HOST_IMPORT_COUNT).
    let mut types = TypeSection::new();
    for (params, results) in HOST_SIGS {
        types
            .ty()
            .function(params.iter().copied(), results.iter().copied());
    }
    // call entry point: [] -> []
    types.ty().function([], []);
    module.section(&types);

    // ── 2. Import section ─────────────────────────────────────────────────
    // Import each host function in IMPORT_ORDER. Each import references its
    // type index (position in HOST_SIGS = position in IMPORT_ORDER).
    let mut imports = ImportSection::new();
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        imports.import(IMPORT_MODULE, name, EntityType::Function(i as u32));
    }
    module.section(&imports);

    // ── 3. Function section ───────────────────────────────────────────────
    // Declare the `call` entry point. Its type index is HOST_IMPORT_COUNT
    // (the type we added after all host function types).
    let call_type_index = HOST_IMPORT_COUNT;
    let mut functions = FunctionSection::new();
    functions.function(call_type_index);
    module.section(&functions);

    // ── 4. Memory section ─────────────────────────────────────────────────
    // One page of linear memory (64 KiB). Exported as "memory" for host access.
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: INITIAL_MEMORY_PAGES,
        maximum: None,
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    // ── 5. Global section ─────────────────────────────────────────────────
    // __heap_base: mutable i32 global = HEAP_BASE_ADDR (page 1 start).
    // Exported so the guest bump allocator knows where to start.
    let mut globals = GlobalSection::new();
    globals.global(
        GlobalType {
            val_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        &ConstExpr::i32_const(HEAP_BASE_ADDR),
    );
    module.section(&globals);

    // ── 6. Export section ─────────────────────────────────────────────────
    // Export "call" (entry point), "memory", and "__heap_base".
    let call_func_index = HOST_IMPORT_COUNT; // first defined function
    let mut exports = ExportSection::new();
    exports.export(abi::ENTRY_POINT, ExportKind::Func, call_func_index);
    exports.export(abi::MEMORY_EXPORT, ExportKind::Memory, 0);
    exports.export(abi::HEAP_BASE_GLOBAL, ExportKind::Global, 0);
    module.section(&exports);

    // ── 7. Code section ───────────────────────────────────────────────────
    // Build the `call` function body. For 6c, the entry point body is empty
    // (dispatch logic is 6e). Expression lowering is tested via dedicated
    // test helpers that compile individual expressions.
    let mut codes = CodeSection::new();
    let mut call_fn = Function::new(vec![]);
    call_fn.instruction(&Instruction::End);
    codes.function(&call_fn);
    module.section(&codes);

    Ok(module.finish())
}

// ─── LowerCtx — expression lowering context ──────────────────────────────────

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
/// ## Dead-code note
///
/// `LowerCtx` is consumed by `emit_test_expr_module` (test-only in 6c).
/// Production wiring (emit_module → LowerCtx) lands in 6d/6e.
// consumer: emit_test_expr_module (P3·Step 6c tests); emit_module (P3·Step 6d/6e)
#[allow(dead_code)]
struct LowerCtx<'a> {
    /// The contract being compiled (for `type_of` lookups).
    contract: &'a TypedContract<'a>,
    /// WASM function body being built.
    func: Function,
    /// Local variable name → WASM local index mapping.
    /// BTreeMap for deterministic iteration (AGENTS §7.1).
    locals: BTreeMap<String, u32>,
    /// Next available local index.
    next_local: u32,
    /// Accumulated local type declarations (count, type) for the function.
    /// Params are not included here — only explicitly declared locals.
    local_types: Vec<(u32, ValType)>,
}

#[allow(dead_code)]
impl<'a> LowerCtx<'a> {
    /// Create a new lowering context for a function with the given parameters.
    ///
    /// Parameters are assigned local indices 0..N in declaration order.
    fn new(contract: &'a TypedContract<'a>, params: &[(String, ValType)]) -> Self {
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
        }
    }

    /// Allocate a temporary local of the given type. Returns its index.
    fn alloc_temp_local(&mut self, vt: ValType) -> u32 {
        let idx = self.next_local;
        self.next_local += 1;
        self.local_types.push((1, vt));
        idx
    }

    /// Resolve the type of an expression by its span.
    ///
    /// Returns `Err(LangError::Codegen)` if the type is not found — this
    /// should not happen for well-formed, type-checked ASTs.
    fn resolve_type(&self, span: &Span) -> Result<ResolvedType, LangError> {
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

    /// Emit WASM instructions for an expression.
    ///
    /// Recursively visits the expression tree and emits the corresponding
    /// WASM instructions. The result value is left on the WASM value stack.
    ///
    /// ## Supported expressions (P3·Step 6c)
    ///
    /// - Literals: Int, IntTyped, Hex, Bool
    /// - Binary arithmetic: Add, Sub, Mul, Div, Rem (all checked)
    /// - Comparisons: Eq, NotEq, Lt, Gt, LtEq, GtEq
    /// - Logical: And, Or, Not
    /// - Unary: Neg
    /// - Local variable read (Ident)
    ///
    /// ## Deferred expressions
    ///
    /// All other expression variants return `Err(LangError::Codegen)` with
    /// an honest deferral message.
    fn emit_expr(&mut self, expr: &Expr) -> Result<(), LangError> {
        match expr {
            Expr::Literal(lit, span) => self.emit_literal(lit, span),

            Expr::Ident(name, span) => self.emit_ident(name, span),

            Expr::Binary(op, lhs, rhs, span) => self.emit_binary(op, lhs, rhs, span),

            Expr::Unary(op, inner, span) => self.emit_unary(op, inner, span),

            _ => Err(LangError::Codegen {
                message: format!(
                    "expression lowering not yet implemented for {}",
                    expr_variant_name(expr)
                ),
            }),
        }
    }

    // ── Literal emission ──────────────────────────────────────────────────

    fn emit_literal(&mut self, lit: &Literal, span: &Span) -> Result<(), LangError> {
        match lit {
            Literal::Int(n) => {
                let ty = self.resolve_type(span)?;
                if is_i64(&ty) {
                    // Range check: literal must fit in i64 (M2 — catch oversized IntLiteral)
                    if *n > i64::MAX as u128 {
                        return Err(LangError::Codegen {
                            message: format!(
                                "integer literal {n} exceeds i64 range; u128/u256 codegen not yet implemented"
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::I64Const(*n as i64));
                } else {
                    if *n > u32::MAX as u128 {
                        return Err(LangError::Codegen {
                            message: format!(
                                "integer literal {n} exceeds i32 range; larger type needed"
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::I32Const(*n as i32));
                }
                Ok(())
            }

            Literal::IntTyped { value, .. } => {
                let ty = self.resolve_type(span)?;
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Const(*value as i64));
                } else {
                    self.func.instruction(&Instruction::I32Const(*value as i32));
                }
                Ok(())
            }

            Literal::Hex(s) => {
                let hex_str = s
                    .strip_prefix("0x")
                    .or_else(|| s.strip_prefix("0X"))
                    .unwrap_or(s);
                let value = u128::from_str_radix(hex_str, 16).map_err(|e| LangError::Codegen {
                    message: format!("invalid hex literal '{s}': {e}"),
                })?;
                let ty = self.resolve_type(span)?;
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Const(value as i64));
                } else {
                    self.func.instruction(&Instruction::I32Const(value as i32));
                }
                Ok(())
            }

            Literal::Bool(b) => {
                self.func.instruction(&Instruction::I32Const(i32::from(*b)));
                Ok(())
            }

            _ => Err(LangError::Codegen {
                message: format!("literal lowering not yet implemented for {lit:?}"),
            }),
        }
    }

    // ── Identifier (local variable read) ──────────────────────────────────

    fn emit_ident(&mut self, name: &str, _span: &Span) -> Result<(), LangError> {
        let local_idx = self.locals.get(name).ok_or_else(|| LangError::Codegen {
            message: format!("undefined local variable: {name}"),
        })?;
        self.func.instruction(&Instruction::LocalGet(*local_idx));
        Ok(())
    }

    // ── Binary expression emission ────────────────────────────────────────

    fn emit_binary(
        &mut self,
        op: &BinaryOp,
        lhs: &Expr,
        rhs: &Expr,
        _span: &Span,
    ) -> Result<(), LangError> {
        // Resolve the operand type from the LHS. Both sides have the same type
        // after type checking (or IntLiteral which coerces to the other side's type).
        let lhs_span = crate::parser::expr_span(lhs);
        let ty = self.resolve_type(&lhs_span)?;

        // M1 — sub-word types (u8/u16/i8/i16) need range-check masking after
        // arithmetic to detect overflow within the narrower type range. Until
        // that is implemented, reject arithmetic on sub-word types honestly.
        if matches!(
            op,
            BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem
        ) && is_sub_word(&ty)
        {
            return Err(LangError::Codegen {
                message: format!(
                    "sub-word arithmetic ({}) not yet implemented; range-check masking needed",
                    ty.display_name()
                ),
            });
        }

        // M2 (revised) — IntLiteral in arithmetic is common (untyped `10 + 20`).
        // The type checker doesn't always coerce sub-expression types to concrete.
        // Treat IntLiteral as i64 unsigned (WASM native). Checked arithmetic uses
        // i64 overflow bounds, which is safe for values ≤ i64::MAX. Literal values
        // exceeding i64::MAX are caught at emission time (emit_literal range check).
        // This is conservative: i64 overflow detection is stricter than u256.

        match op {
            // ── Checked arithmetic ────────────────────────────────────
            BinaryOp::Add => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_add(&ty)
            }
            BinaryOp::Sub => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_sub(&ty)
            }
            BinaryOp::Mul => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_mul(&ty)
            }
            BinaryOp::Div => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_div(&ty)
            }
            BinaryOp::Rem => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_checked_rem(&ty)
            }

            // ── Comparisons ───────────────────────────────────────────
            BinaryOp::Eq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Eq);
                } else {
                    self.func.instruction(&Instruction::I32Eq);
                }
                Ok(())
            }
            BinaryOp::NotEq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Ne);
                } else {
                    self.func.instruction(&Instruction::I32Ne);
                }
                Ok(())
            }
            BinaryOp::Lt => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_lt(&ty);
                Ok(())
            }
            BinaryOp::Gt => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_gt(&ty);
                Ok(())
            }
            BinaryOp::LtEq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_le(&ty);
                Ok(())
            }
            BinaryOp::GtEq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.emit_ge(&ty);
                Ok(())
            }

            // ── Logical ───────────────────────────────────────────────
            BinaryOp::And => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.func.instruction(&Instruction::I32And);
                Ok(())
            }
            BinaryOp::Or => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                self.func.instruction(&Instruction::I32Or);
                Ok(())
            }

            _ => Err(LangError::Codegen {
                message: format!("binary operator lowering not yet implemented for {op:?}"),
            }),
        }
    }

    // ── Unary expression emission ─────────────────────────────────────────

    fn emit_unary(&mut self, op: &UnaryOp, inner: &Expr, span: &Span) -> Result<(), LangError> {
        match op {
            UnaryOp::Not => {
                self.emit_expr(inner)?;
                self.func.instruction(&Instruction::I32Eqz);
                Ok(())
            }
            UnaryOp::Neg => {
                // C2 — Neg(MIN) must trap for signed types.
                // Route through checked sub: `0 - x`. For signed types, the
                // checked sub pattern `(a ^ b) & (a ^ result) < 0` catches
                // `0 - MIN` (negation overflow). For unsigned types, checked
                // sub catches `0 - x` when `x > 0` (underflow).
                let ty = self.resolve_type(span)?;

                // Sub-word negation needs range-check masking (same as M1).
                if is_sub_word(&ty) {
                    return Err(LangError::Codegen {
                        message: format!(
                            "sub-word negation ({}) not yet implemented; range-check masking needed",
                            ty.display_name()
                        ),
                    });
                }

                // Emit: [0, inner] on stack, then checked sub
                if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Const(0));
                } else {
                    self.func.instruction(&Instruction::I32Const(0));
                }
                self.emit_expr(inner)?;
                self.emit_checked_sub(&ty)
            }
            _ => Err(LangError::Codegen {
                message: format!("unary operator lowering not yet implemented for {op:?}"),
            }),
        }
    }

    // ── Comparison helpers ────────────────────────────────────────────────

    fn emit_lt(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if is_signed(ty) {
                self.func.instruction(&Instruction::I64LtS);
            } else {
                self.func.instruction(&Instruction::I64LtU);
            }
        } else if is_signed(ty) {
            self.func.instruction(&Instruction::I32LtS);
        } else {
            self.func.instruction(&Instruction::I32LtU);
        }
    }

    fn emit_gt(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if is_signed(ty) {
                self.func.instruction(&Instruction::I64GtS);
            } else {
                self.func.instruction(&Instruction::I64GtU);
            }
        } else if is_signed(ty) {
            self.func.instruction(&Instruction::I32GtS);
        } else {
            self.func.instruction(&Instruction::I32GtU);
        }
    }

    fn emit_le(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if is_signed(ty) {
                self.func.instruction(&Instruction::I64LeS);
            } else {
                self.func.instruction(&Instruction::I64LeU);
            }
        } else if is_signed(ty) {
            self.func.instruction(&Instruction::I32LeS);
        } else {
            self.func.instruction(&Instruction::I32LeU);
        }
    }

    fn emit_ge(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if is_signed(ty) {
                self.func.instruction(&Instruction::I64GeS);
            } else {
                self.func.instruction(&Instruction::I64GeU);
            }
        } else if is_signed(ty) {
            self.func.instruction(&Instruction::I32GeS);
        } else {
            self.func.instruction(&Instruction::I32GeU);
        }
    }

    // ── Checked arithmetic (AGENTS §7.4) ──────────────────────────────────
    //
    // Every arithmetic operation traps on overflow/underflow/division-by-zero.
    // The pattern: save operands to temp locals, perform the operation, check
    // the result, and emit `unreachable` (WASM trap) on failure.

    /// Checked addition: traps if `a + b` overflows.
    ///
    /// ## Unsigned overflow detection
    /// `result < a` implies overflow (since `b >= 0` for unsigned).
    ///
    /// ## Signed overflow detection
    ///
    /// Uses the WASM `add` instruction which wraps, then checks:
    /// - If both operands positive and result negative → overflow
    /// - If both operands negative and result positive → overflow
    ///
    /// Simplified: `(a ^ result) & (b ^ result)` has sign bit set on overflow.
    fn emit_checked_add(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        if wide {
            let tmp_a = self.alloc_temp_local(ValType::I64);
            let tmp_b = self.alloc_temp_local(ValType::I64);
            let tmp_result = self.alloc_temp_local(ValType::I64);

            // Stack: [a, b] → save both
            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            // Compute a + b
            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I64Add);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            if signed {
                // Signed overflow: (a ^ result) & (b ^ result) < 0
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I64Xor);
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I64Xor);
                self.func.instruction(&Instruction::I64And);
                self.func.instruction(&Instruction::I64Const(0));
                self.func.instruction(&Instruction::I64LtS);
            } else {
                // Unsigned overflow: result < a
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::I64LtU);
            }

            // If overflow → trap
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);

            // Push result
            self.func.instruction(&Instruction::LocalGet(tmp_result));
        } else {
            let tmp_a = self.alloc_temp_local(ValType::I32);
            let tmp_b = self.alloc_temp_local(ValType::I32);
            let tmp_result = self.alloc_temp_local(ValType::I32);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I32Add);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            if signed {
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I32Xor);
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I32Xor);
                self.func.instruction(&Instruction::I32And);
                self.func.instruction(&Instruction::I32Const(0));
                self.func.instruction(&Instruction::I32LtS);
            } else {
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::I32LtU);
            }

            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        }
        Ok(())
    }

    /// Checked subtraction: traps if `a - b` underflows.
    ///
    /// ## Unsigned underflow detection
    /// `a < b` implies underflow.
    ///
    /// ## Signed overflow detection
    /// `(a ^ b) & (a ^ result)` has sign bit set on overflow.
    fn emit_checked_sub(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        if wide {
            let tmp_a = self.alloc_temp_local(ValType::I64);
            let tmp_b = self.alloc_temp_local(ValType::I64);
            let tmp_result = self.alloc_temp_local(ValType::I64);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I64Sub);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            if signed {
                // Signed sub overflow: (a ^ b) & (a ^ result) < 0
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I64Xor);
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I64Xor);
                self.func.instruction(&Instruction::I64And);
                self.func.instruction(&Instruction::I64Const(0));
                self.func.instruction(&Instruction::I64LtS);
            } else {
                // Unsigned underflow: a < b
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I64LtU);
            }

            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        } else {
            let tmp_a = self.alloc_temp_local(ValType::I32);
            let tmp_b = self.alloc_temp_local(ValType::I32);
            let tmp_result = self.alloc_temp_local(ValType::I32);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I32Sub);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            if signed {
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I32Xor);
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::I32Xor);
                self.func.instruction(&Instruction::I32And);
                self.func.instruction(&Instruction::I32Const(0));
                self.func.instruction(&Instruction::I32LtS);
            } else {
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I32LtU);
            }

            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        }
        Ok(())
    }

    /// Checked multiplication: traps if `a * b` overflows.
    ///
    /// ## Unsigned overflow detection
    /// If `a != 0 && result / a != b` → overflow.
    ///
    /// ## Signed overflow detection
    /// Same check but using signed division, plus special-case for
    /// `a == -1 && b == MIN` (which would overflow signed div).
    fn emit_checked_mul(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        if wide {
            let tmp_a = self.alloc_temp_local(ValType::I64);
            let tmp_b = self.alloc_temp_local(ValType::I64);
            let tmp_result = self.alloc_temp_local(ValType::I64);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I64Mul);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            // Check: if a != 0 && result / a != b → overflow
            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::I64Const(0));
            self.func.instruction(&Instruction::I64Ne);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            {
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                if signed {
                    self.func.instruction(&Instruction::I64DivS);
                } else {
                    self.func.instruction(&Instruction::I64DivU);
                }
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I64Ne);
                self.func
                    .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                self.func.instruction(&Instruction::Unreachable);
                self.func.instruction(&Instruction::End);
            }
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        } else {
            let tmp_a = self.alloc_temp_local(ValType::I32);
            let tmp_b = self.alloc_temp_local(ValType::I32);
            let tmp_result = self.alloc_temp_local(ValType::I32);

            self.func.instruction(&Instruction::LocalSet(tmp_b));
            self.func.instruction(&Instruction::LocalSet(tmp_a));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            self.func.instruction(&Instruction::I32Mul);
            self.func.instruction(&Instruction::LocalSet(tmp_result));

            self.func.instruction(&Instruction::LocalGet(tmp_a));
            self.func.instruction(&Instruction::I32Const(0));
            self.func.instruction(&Instruction::I32Ne);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            {
                self.func.instruction(&Instruction::LocalGet(tmp_result));
                self.func.instruction(&Instruction::LocalGet(tmp_a));
                if signed {
                    self.func.instruction(&Instruction::I32DivS);
                } else {
                    self.func.instruction(&Instruction::I32DivU);
                }
                self.func.instruction(&Instruction::LocalGet(tmp_b));
                self.func.instruction(&Instruction::I32Ne);
                self.func
                    .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                self.func.instruction(&Instruction::Unreachable);
                self.func.instruction(&Instruction::End);
            }
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(tmp_result));
        }
        Ok(())
    }

    /// Checked division: traps if divisor is zero.
    ///
    /// WASM `div_u` / `div_s` already trap on division by zero, but we emit
    /// an explicit check for clarity and to produce a consistent trap pattern.
    /// For signed division, WASM also traps on `INT_MIN / -1` (overflow).
    fn emit_checked_div(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        // Check divisor != 0 (top of stack is divisor, below is dividend)
        if wide {
            let tmp_b = self.alloc_temp_local(ValType::I64);
            self.func.instruction(&Instruction::LocalTee(tmp_b));
            self.func.instruction(&Instruction::I64Eqz);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);
            // Restore divisor and perform division
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            if signed {
                self.func.instruction(&Instruction::I64DivS);
            } else {
                self.func.instruction(&Instruction::I64DivU);
            }
        } else {
            let tmp_b = self.alloc_temp_local(ValType::I32);
            self.func.instruction(&Instruction::LocalTee(tmp_b));
            self.func.instruction(&Instruction::I32Eqz);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            if signed {
                self.func.instruction(&Instruction::I32DivS);
            } else {
                self.func.instruction(&Instruction::I32DivU);
            }
        }
        Ok(())
    }

    /// Checked remainder: traps if divisor is zero.
    ///
    /// Same zero-check pattern as division.
    fn emit_checked_rem(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        let wide = is_i64(ty);
        let signed = is_signed(ty);

        if wide {
            let tmp_b = self.alloc_temp_local(ValType::I64);
            self.func.instruction(&Instruction::LocalTee(tmp_b));
            self.func.instruction(&Instruction::I64Eqz);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            if signed {
                self.func.instruction(&Instruction::I64RemS);
            } else {
                self.func.instruction(&Instruction::I64RemU);
            }
        } else {
            let tmp_b = self.alloc_temp_local(ValType::I32);
            self.func.instruction(&Instruction::LocalTee(tmp_b));
            self.func.instruction(&Instruction::I32Eqz);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.func.instruction(&Instruction::Unreachable);
            self.func.instruction(&Instruction::End);
            self.func.instruction(&Instruction::LocalGet(tmp_b));
            if signed {
                self.func.instruction(&Instruction::I32RemS);
            } else {
                self.func.instruction(&Instruction::I32RemU);
            }
        }
        Ok(())
    }

    /// Seal the function body by appending the `End` instruction.
    ///
    /// Returns the built `Function`. Note: the caller is responsible for
    /// ensuring the function was created with the correct local declarations
    /// (see `emit_test_expr_module` for the two-pass approach).
    fn finish(mut self) -> Function {
        self.func.instruction(&Instruction::End);
        self.func
    }
}

// ─── Test-only helpers ────────────────────────────────────────────────────────

/// Build a complete WASM module containing a single test function that
/// evaluates the given expression and returns the result.
///
/// This is the primary test vehicle for P3·Step 6c expression lowering.
/// The function signature is `() -> [result_type]` so the expression result
/// can be validated.
///
/// Only available in test builds.
#[cfg(test)]
pub(crate) fn emit_test_expr_module(
    contract: &TypedContract<'_>,
    expr: &Expr,
    params: &[(String, ValType)],
) -> Result<Vec<u8>, LangError> {
    use crate::codegen::types::wasm_valtype;

    let expr_span = expr_span(expr);
    let result_ty = contract
        .type_of(&expr_span)
        .ok_or_else(|| LangError::Codegen {
            message: "no resolved type for test expression".into(),
        })?;
    let wasm_result = wasm_valtype(result_ty)?;

    // Phase 1: emit instructions into a LowerCtx to discover temp locals
    let mut ctx = LowerCtx::new(contract, params);
    ctx.emit_expr(expr)?;
    ctx.func.instruction(&Instruction::End);

    // Phase 2: rebuild the function with correct local declarations
    // We need to replay the instructions with the now-known local count.
    // Since wasm-encoder doesn't support replaying, we use a workaround:
    // build a second LowerCtx with pre-allocated locals matching the first pass.
    //
    // Actually, a simpler approach: we know the local_types from ctx.
    // We can use raw_bytes from the first function and patch the locals.
    // But that's fragile.
    //
    // Simplest correct approach: use Function::new with the right locals
    // from the start by doing a two-pass compile. But that's expensive.
    //
    // Best approach for correctness: since we know the number of temp locals
    // after the first pass, we can pre-allocate them in a second pass.
    let temp_local_count = ctx.local_types.len();
    let all_locals: Vec<(u32, ValType)> = ctx.local_types;

    // Second pass: rebuild with correct locals
    let mut ctx2 = LowerCtx {
        contract,
        func: Function::new(all_locals),
        locals: {
            let mut m = BTreeMap::new();
            for (i, (name, _)) in params.iter().enumerate() {
                m.insert(name.clone(), i as u32);
            }
            m
        },
        next_local: params.len() as u32 + temp_local_count as u32,
        local_types: Vec::new(), // won't allocate more temps in second pass
    };

    // We need to re-emit the expression. The temp local indices must match.
    // Since alloc_temp_local increments next_local, and we set it to skip
    // past the pre-allocated temps, new allocations would get wrong indices.
    // Fix: reset next_local to where temps start, so re-allocation matches.
    ctx2.next_local = params.len() as u32;

    ctx2.emit_expr(expr)?;
    ctx2.func.instruction(&Instruction::End);

    // C1 — assert that pass-2 allocated the same number of temp locals as
    // pass-1. If this fires, the two-pass approach has desynced: the
    // instruction stream references local indices that don't match the
    // declared locals, producing a silently miscompiled module.
    assert_eq!(
        ctx2.next_local,
        params.len() as u32 + temp_local_count as u32,
        "BUG: pass-2 allocated {} temp locals but pass-1 allocated {} — instruction/local desync",
        ctx2.next_local - params.len() as u32,
        temp_local_count,
    );

    // Build the module
    let mut module = Module::new();

    // Type section: host function types + test function type
    let mut types = TypeSection::new();
    for (p, r) in HOST_SIGS {
        types.ty().function(p.iter().copied(), r.iter().copied());
    }
    // Test function type: params → [result]
    let param_valtypes: Vec<ValType> = params.iter().map(|(_, vt)| *vt).collect();
    types
        .ty()
        .function(param_valtypes.iter().copied(), [wasm_result]);
    module.section(&types);

    // Import section
    let mut imports = ImportSection::new();
    for (i, name) in IMPORT_ORDER.iter().enumerate() {
        imports.import(IMPORT_MODULE, name, EntityType::Function(i as u32));
    }
    module.section(&imports);

    // Function section
    let test_type_index = HOST_IMPORT_COUNT;
    let mut functions = FunctionSection::new();
    functions.function(test_type_index);
    module.section(&functions);

    // Memory section
    let mut memories = MemorySection::new();
    memories.memory(MemoryType {
        minimum: INITIAL_MEMORY_PAGES,
        maximum: None,
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memories);

    // Global section
    let mut globals = GlobalSection::new();
    globals.global(
        GlobalType {
            val_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        &ConstExpr::i32_const(HEAP_BASE_ADDR),
    );
    module.section(&globals);

    // Export section
    let test_func_index = HOST_IMPORT_COUNT;
    let mut exports = ExportSection::new();
    exports.export("test", ExportKind::Func, test_func_index);
    exports.export(abi::MEMORY_EXPORT, ExportKind::Memory, 0);
    module.section(&exports);

    // Code section
    let mut codes = CodeSection::new();
    codes.function(&ctx2.func);
    module.section(&codes);

    Ok(module.finish())
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Return the variant name of an `Expr` for error messages.
///
/// Avoids printing the full debug representation (which includes all inner data).
/// The `#[allow(unreachable_patterns)]` is required because `Expr` is
/// `#[non_exhaustive]` — the wildcard arm is needed for forward compatibility.
// consumer: LowerCtx::emit_expr (P3·Step 6c)
#[allow(dead_code, unreachable_patterns)]
fn expr_variant_name(expr: &Expr) -> &'static str {
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
