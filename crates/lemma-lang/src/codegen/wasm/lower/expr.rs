//! Expression lowering — `emit_expr`, `emit_literal`, `emit_ident`,
//! `emit_binary`, `emit_unary`, address constants/predicates.
//!
//! Split from `wasm.rs` (P3·Step 6c/6g expression lowering).

use lemma_core::Address;
use wasm_encoder::{Instruction, ValType};

use crate::codegen::abi::{CALL_CONTRACT_INDEX, DELEGATE_CALL_INDEX, STATIC_CALL_INDEX};
use crate::codegen::types::{is_i64, is_sub_word, is_u128};
use crate::codegen::wasm::lower::{
    call_arg_expr, expr_variant_name, unit_multiplier, LowerCtx, ADDR_BURN_OFFSET,
    ADDR_NATIVE_OFFSET, ADDR_ZERO_OFFSET,
};
use crate::error::LangError;
use crate::lexer::token::Span;
use crate::parser::{BinaryOp, Expr, Literal, UnaryOp};
use crate::type_checker::types::ResolvedType;

impl<'a> LowerCtx<'a> {
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
    pub(crate) fn emit_expr(&mut self, expr: &Expr) -> Result<(), LangError> {
        match expr {
            Expr::Literal(lit, span) => self.emit_literal(lit, span),

            Expr::Ident(name, span) => self.emit_ident(name, span),

            Expr::Binary(op, lhs, rhs, span) => self.emit_binary(op, lhs, rhs, span),

            Expr::Unary(op, inner, span) => self.emit_unary(op, inner, span),

            // Member access: self.field → storage read (P3·Step 6e)
            // Address.zero / Address.burn / Address.nativeLem → constant pointer (P3·Step 6g)
            Expr::Member(receiver, field, _span) => {
                if let Expr::Ident(name, _) = receiver.as_ref() {
                    if name == "self" {
                        return self.emit_storage_read(field);
                    }
                    if name == "Address" {
                        return self.emit_address_constant(field);
                    }
                }
                Err(LangError::Codegen {
                    message: format!(
                        "member access on receiver '{receiver:?}' not yet implemented"
                    ),
                })
            }

            // Function calls: addr.isZero() / addr.isBurn() / addr.isContract() (P3·Step 6g)
            // Cross-contract calls: addr.rawCall() / addr.staticCall() / addr.delegateCall() (P3·Step 21)
            Expr::Call { callee, args, .. } => {
                if let Expr::Member(receiver, method, _) = callee.as_ref() {
                    // Address predicate methods: isZero, isBurn, isNativeLem
                    let predicate_offset = match method.as_str() {
                        "isZero" => Some(ADDR_ZERO_OFFSET),
                        "isBurn" => Some(ADDR_BURN_OFFSET),
                        "isNativeLem" => Some(ADDR_NATIVE_OFFSET),
                        _ => None,
                    };
                    if let Some(offset) = predicate_offset {
                        if args.is_empty() {
                            return self.emit_address_predicate(receiver, offset);
                        }
                        return Err(LangError::Codegen {
                            message: format!("address predicate '{method}' takes no arguments"),
                        });
                    }
                    if method == "isContract" {
                        // isContract() requires a host call to check if an address has
                        // code deployed. The current ABI has no has_code host function.
                        // Deferred: P3·Step 6g scope (DB-A37).
                        return Err(LangError::Codegen {
                            message: "addr.isContract() not yet implemented \
                                      (requires has_code host function — deferred)"
                                .into(),
                        });
                    }

                    // ── Cross-contract calls (P3·Step 21) ─────────────────────────
                    //
                    // rawCall(calldata, opts)    → host fn index 14 (call_contract)
                    // staticCall(calldata)       → host fn index 15 (static_call)
                    // delegateCall(calldata)     → host fn index 16 (delegate_call)
                    //
                    // ABI (DB-A53 §4.5):
                    //   call_contract(addr_ptr, addr_len, data_reg, gas, value) -> i32
                    //   static_call  (addr_ptr, addr_len, data_reg, gas)        -> i32
                    //   delegate_call(addr_ptr, addr_len, data_reg, gas)        -> i32
                    //
                    // The address is passed as a (ptr, len) pair into guest memory.
                    // Calldata is written to a scratch register; the register ID is
                    // passed as data_reg. The result register ID is returned as i32.
                    match method.as_str() {
                        "rawCall" => {
                            // rawCall(calldata, opts) — exactly 2 positional args (spec §16).
                            // args[0] = calldata (bytes — lowered as i32 register ID, MVP)
                            // args[1] = opts struct literal { value: u128, gas: u64 }
                            //
                            // The type-checker enforces 2 args (check_address_call in infer.rs).
                            // Codegen accepts the opts struct leniently for MVP: gas and value
                            // default to 0 (the VM applies 63/64 gas forwarding automatically).
                            // Full opts-struct field extraction is deferred (M6 scope).
                            //
                            // TODO(codegen): extract gas/value from opts struct literal when
                            // struct-literal lowering is implemented (M6 / P3·Step 22).
                            if args.is_empty() {
                                return Err(LangError::Codegen {
                                    message: "rawCall requires 2 arguments (calldata, opts)".into(),
                                });
                            }
                            let calldata = call_arg_expr(&args[0])?;
                            // opts (args[1]) is accepted leniently — gas and value default to 0.
                            // The VM caps forwarded gas at 63/64 of remaining (08-EXECUTION_SPEC §2.4).
                            return self.emit_cross_contract_call(
                                receiver,
                                calldata,
                                None,                // gas: default 0 (VM applies 63/64 rule)
                                None,                // value: default 0 (no value transfer)
                                CALL_CONTRACT_INDEX, // call_contract host fn index (abi.rs)
                            );
                        }
                        "staticCall" => {
                            // staticCall(calldata) — exactly 1 positional arg (spec §16).
                            // No value parameter (static calls cannot transfer value).
                            if args.is_empty() {
                                return Err(LangError::Codegen {
                                    message: "staticCall requires 1 argument (calldata)".into(),
                                });
                            }
                            let calldata = call_arg_expr(&args[0])?;
                            return self.emit_cross_contract_call(
                                receiver,
                                calldata,
                                None,              // gas: default 0 (VM applies 63/64 rule)
                                None,              // no value for static calls
                                STATIC_CALL_INDEX, // static_call host fn index (abi.rs)
                            );
                        }
                        "delegateCall" => {
                            // delegateCall(calldata) — exactly 1 positional arg (spec §16).
                            // No value parameter (delegate calls run in caller's context).
                            //
                            // SAFETY: delegateCall is type-valid here. SAFETY-011b
                            // (analyzer/rules/delegate.rs) enforces the #[allowDelegate]
                            // annotation at compile time — a call site reaching codegen has
                            // already passed that gate. At runtime the VM SAFETY-011 contract
                            // (dispatch_call CallMode::Delegate runs callee code in the
                            // caller's context) is enforced.
                            if args.is_empty() {
                                return Err(LangError::Codegen {
                                    message: "delegateCall requires 1 argument (calldata)".into(),
                                });
                            }
                            let calldata = call_arg_expr(&args[0])?;
                            return self.emit_cross_contract_call(
                                receiver,
                                calldata,
                                None,                // gas: default 0 (VM applies 63/64 rule)
                                None,                // no value for delegate calls
                                DELEGATE_CALL_INDEX, // delegate_call host fn index (abi.rs)
                            );
                        }
                        _ => {}
                    }
                }
                Err(LangError::Codegen {
                    message: "general function call lowering not yet implemented".into(),
                })
            }

            _ => Err(LangError::Codegen {
                message: format!(
                    "expression lowering not yet implemented for {}",
                    expr_variant_name(expr)
                ),
            }),
        }
    }

    // ── Literal emission ──────────────────────────────────────────────────

    pub(super) fn emit_literal(&mut self, lit: &Literal, span: &Span) -> Result<(), LangError> {
        match lit {
            Literal::Int(n) => {
                let ty = self.resolve_type(span)?;
                if is_u128(&ty) {
                    // u128 literal: split into lo/hi i64 pair.
                    let lo = (*n & u64::MAX as u128) as i64;
                    let hi = ((*n >> 64) & u64::MAX as u128) as i64;
                    self.func.instruction(&Instruction::I64Const(lo));
                    self.func.instruction(&Instruction::I64Const(hi));
                } else if is_i64(&ty) {
                    // Range check: literal must fit in i64 (M2 — catch oversized IntLiteral)
                    if *n > i64::MAX as u128 {
                        return Err(LangError::Codegen {
                            message: format!(
                                "integer literal {n} exceeds i64 range; use u128 type"
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

            // ── Unit literals (P3·Step 6h) ────────────────────────────
            //
            // `<n>.<unit>` folds to `n × multiplier` at compile time (checked
            // arithmetic — AGENTS §7.4).  Emitted as I64Const for i64-context
            // types (u64/i64), I32Const otherwise.  Overflows that exceed i64
            // range produce an honest deferral error (u256 multi-word codegen
            // is not yet built).  See DB-A55 and 03-LANGUAGE_SPEC §2.
            Literal::Unit(inner, kind) => {
                // The parser only produces Literal::Unit from `<int>.<unit>`,
                // so inner is always Expr::Literal(Literal::Int(n), _).
                let n = match inner.as_ref() {
                    Expr::Literal(Literal::Int(n), _) => *n,
                    _ => {
                        return Err(LangError::Codegen {
                            message: "unit literal inner expression is not a plain integer".into(),
                        });
                    }
                };
                // Fold: n × multiplier, checked at u128 width (AGENTS §7.4).
                let multiplier = unit_multiplier(kind);
                let folded = n
                    .checked_mul(multiplier)
                    .ok_or_else(|| LangError::Codegen {
                        message: format!(
                            "unit literal {n}.{kind:?} overflows u128; \
                         u256 codegen not yet implemented"
                        ),
                    })?;
                // Emit as i64 or i32 based on context type, mirroring Literal::Int.
                let ty = self.resolve_type(span)?;
                if is_i64(&ty) {
                    if folded > i64::MAX as u128 {
                        return Err(LangError::Codegen {
                            message: format!(
                                "unit literal value {folded} exceeds i64 range; \
                                 u256 codegen not yet implemented"
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::I64Const(folded as i64));
                } else {
                    if folded > u32::MAX as u128 {
                        return Err(LangError::Codegen {
                            message: format!(
                                "unit literal value {folded} exceeds i32 range; \
                                 use a u64 or larger integer type in the context"
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::I32Const(folded as i32));
                }
                Ok(())
            }

            _ => Err(LangError::Codegen {
                message: format!("literal lowering not yet implemented for {lit:?}"),
            }),
        }
    }

    // ── Identifier (local variable read) ──────────────────────────────────

    pub(super) fn emit_ident(&mut self, name: &str, _span: &Span) -> Result<(), LangError> {
        // Check if this is a u128 variable (stored as name_lo + name_hi locals).
        let lo_name = format!("{name}_lo");
        if let Some(&lo_idx) = self.locals.get(&lo_name) {
            let hi_name = format!("{name}_hi");
            let hi_idx = *self
                .locals
                .get(&hi_name)
                .ok_or_else(|| LangError::Codegen {
                    message: format!("u128 variable '{name}' has _lo but missing _hi local"),
                })?;
            self.func.instruction(&Instruction::LocalGet(lo_idx));
            self.func.instruction(&Instruction::LocalGet(hi_idx));
            return Ok(());
        }

        // Standard single-local variable
        let local_idx = self.locals.get(name).ok_or_else(|| LangError::Codegen {
            message: format!("undefined local variable: {name}"),
        })?;
        self.func.instruction(&Instruction::LocalGet(*local_idx));
        Ok(())
    }

    // ── Address constants and predicates (P3·Step 6g) ────────────────────

    /// Emit an i32 pointer to a built-in Address constant in linear memory.
    ///
    /// The three constants (`zero`, `burn`, `nativeLem`) are placed in page 0
    /// at fixed offsets by the data section (see `emit_module`). This method
    /// pushes the corresponding offset as an i32 constant onto the WASM stack.
    ///
    /// The caller receives an i32 pointer into linear memory where the 20-byte
    /// address bytes reside.
    pub(super) fn emit_address_constant(&mut self, field: &str) -> Result<(), LangError> {
        let offset = match field {
            "zero" => ADDR_ZERO_OFFSET,
            "burn" => ADDR_BURN_OFFSET,
            "nativeLem" => ADDR_NATIVE_OFFSET,
            other => {
                return Err(LangError::Codegen {
                    message: format!("Address has no constant '{other}'"),
                })
            }
        };
        self.func.instruction(&Instruction::I32Const(offset as i32));
        Ok(())
    }

    /// Emit a byte-comparison predicate for an address value.
    ///
    /// Compares the 20 bytes at the address pointer produced by `addr_expr`
    /// against the 20-byte constant at `constant_offset` in linear memory.
    /// Returns i32: 1 if equal, 0 if not equal.
    ///
    /// ## Comparison strategy
    ///
    /// Unrolled into 2×i64 loads (bytes 0..8, 8..16) + 1×i32 load (bytes 16..20),
    /// compared against compile-time constants derived from `lemma_core::Address`.
    /// This avoids a runtime loop and is deterministic (AGENTS §7.1).
    ///
    /// The constant bytes are embedded as i64/i32 immediates — no runtime memory
    /// access for the reference side.
    pub(super) fn emit_address_predicate(
        &mut self,
        addr_expr: &Expr,
        constant_offset: u32,
    ) -> Result<(), LangError> {
        // Evaluate addr_expr → i32 pointer to the address bytes in memory
        self.emit_expr(addr_expr)?;
        let addr_ptr = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::LocalSet(addr_ptr));

        // Retrieve the 20 constant bytes from lemma-core (single source of truth).
        // AGENTS §2 DRY: bytes come from Address::burn()/native_lem(), not hardcoded.
        let const_bytes: [u8; 20] = match constant_offset {
            ADDR_ZERO_OFFSET => [0u8; 20],
            ADDR_BURN_OFFSET => *Address::burn().as_bytes(),
            ADDR_NATIVE_OFFSET => *Address::native_lem().as_bytes(),
            other => {
                return Err(LangError::Codegen {
                    message: format!("unknown address constant offset {other}"),
                })
            }
        };

        // chunk 0: bytes 0..8 — compare as i64 (little-endian)
        let chunk0 = i64::from_le_bytes([
            const_bytes[0],
            const_bytes[1],
            const_bytes[2],
            const_bytes[3],
            const_bytes[4],
            const_bytes[5],
            const_bytes[6],
            const_bytes[7],
        ]);
        self.func.instruction(&Instruction::LocalGet(addr_ptr));
        self.func
            .instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                offset: 0,
                align: 1,
                memory_index: 0,
            }));
        self.func.instruction(&Instruction::I64Const(chunk0));
        self.func.instruction(&Instruction::I64Eq);

        // chunk 1: bytes 8..16 — compare as i64 (little-endian)
        let chunk1 = i64::from_le_bytes([
            const_bytes[8],
            const_bytes[9],
            const_bytes[10],
            const_bytes[11],
            const_bytes[12],
            const_bytes[13],
            const_bytes[14],
            const_bytes[15],
        ]);
        self.func.instruction(&Instruction::LocalGet(addr_ptr));
        self.func
            .instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                offset: 8,
                align: 1,
                memory_index: 0,
            }));
        self.func.instruction(&Instruction::I64Const(chunk1));
        self.func.instruction(&Instruction::I64Eq);
        // AND the two i64 comparisons (both return i32 0/1 from I64Eq)
        self.func.instruction(&Instruction::I32And);

        // chunk 2: bytes 16..20 — compare as i32 (little-endian)
        let chunk2 = i32::from_le_bytes([
            const_bytes[16],
            const_bytes[17],
            const_bytes[18],
            const_bytes[19],
        ]);
        self.func.instruction(&Instruction::LocalGet(addr_ptr));
        self.func
            .instruction(&Instruction::I32Load(wasm_encoder::MemArg {
                offset: 16,
                align: 1,
                memory_index: 0,
            }));
        self.func.instruction(&Instruction::I32Const(chunk2));
        self.func.instruction(&Instruction::I32Eq);
        // AND with the previous result
        self.func.instruction(&Instruction::I32And);

        Ok(())
    }

    // ── Binary expression emission ────────────────────────────────────────

    pub(super) fn emit_binary(
        &mut self,
        op: &BinaryOp,
        lhs: &Expr,
        rhs: &Expr,
        _span: &Span,
    ) -> Result<(), LangError> {
        // Resolve the operand type from the LHS. Both sides have the same type
        // after type checking (or IntLiteral which coerces to the other side's type).
        // Uses resolve_expr_type for self.field fallback (P3·Step 6e).
        let ty = self.resolve_expr_type(lhs)?;

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
                if is_u128(&ty) {
                    // u128 eq: (a_lo == b_lo) && (a_hi == b_hi)
                    self.emit_u128_eq()?;
                } else if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Eq);
                } else {
                    self.func.instruction(&Instruction::I32Eq);
                }
                Ok(())
            }
            BinaryOp::NotEq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                if is_u128(&ty) {
                    // u128 ne: !(a_lo == b_lo && a_hi == b_hi)
                    self.emit_u128_eq()?;
                    self.func.instruction(&Instruction::I32Eqz);
                } else if is_i64(&ty) {
                    self.func.instruction(&Instruction::I64Ne);
                } else {
                    self.func.instruction(&Instruction::I32Ne);
                }
                Ok(())
            }
            BinaryOp::Lt => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                if is_u128(&ty) {
                    self.emit_u128_lt()?;
                } else {
                    self.emit_lt(&ty);
                }
                Ok(())
            }
            BinaryOp::Gt => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                if is_u128(&ty) {
                    // a > b ≡ b < a: swap operands and use lt
                    self.emit_u128_gt()?;
                } else {
                    self.emit_gt(&ty);
                }
                Ok(())
            }
            BinaryOp::LtEq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                if is_u128(&ty) {
                    // a <= b ≡ !(a > b) ≡ !(b < a)
                    self.emit_u128_gt()?;
                    self.func.instruction(&Instruction::I32Eqz);
                } else {
                    self.emit_le(&ty);
                }
                Ok(())
            }
            BinaryOp::GtEq => {
                self.emit_expr(lhs)?;
                self.emit_expr(rhs)?;
                if is_u128(&ty) {
                    // a >= b ≡ !(a < b)
                    self.emit_u128_lt()?;
                    self.func.instruction(&Instruction::I32Eqz);
                } else {
                    self.emit_ge(&ty);
                }
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

    pub(super) fn emit_unary(
        &mut self,
        op: &UnaryOp,
        inner: &Expr,
        span: &Span,
    ) -> Result<(), LangError> {
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

    pub(super) fn emit_lt(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if crate::codegen::types::is_signed(ty) {
                self.func.instruction(&Instruction::I64LtS);
            } else {
                self.func.instruction(&Instruction::I64LtU);
            }
        } else if crate::codegen::types::is_signed(ty) {
            self.func.instruction(&Instruction::I32LtS);
        } else {
            self.func.instruction(&Instruction::I32LtU);
        }
    }

    pub(super) fn emit_gt(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if crate::codegen::types::is_signed(ty) {
                self.func.instruction(&Instruction::I64GtS);
            } else {
                self.func.instruction(&Instruction::I64GtU);
            }
        } else if crate::codegen::types::is_signed(ty) {
            self.func.instruction(&Instruction::I32GtS);
        } else {
            self.func.instruction(&Instruction::I32GtU);
        }
    }

    pub(super) fn emit_le(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if crate::codegen::types::is_signed(ty) {
                self.func.instruction(&Instruction::I64LeS);
            } else {
                self.func.instruction(&Instruction::I64LeU);
            }
        } else if crate::codegen::types::is_signed(ty) {
            self.func.instruction(&Instruction::I32LeS);
        } else {
            self.func.instruction(&Instruction::I32LeU);
        }
    }

    pub(super) fn emit_ge(&mut self, ty: &ResolvedType) {
        if is_i64(ty) {
            if crate::codegen::types::is_signed(ty) {
                self.func.instruction(&Instruction::I64GeS);
            } else {
                self.func.instruction(&Instruction::I64GeU);
            }
        } else if crate::codegen::types::is_signed(ty) {
            self.func.instruction(&Instruction::I32GeS);
        } else {
            self.func.instruction(&Instruction::I32GeU);
        }
    }
}
