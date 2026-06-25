//! Checked arithmetic + u128 comparison helpers.
//!
//! Split from `wasm.rs` (AGENTS §7.4 checked arithmetic, subtask_08 u128).

use wasm_encoder::{Instruction, ValType};

use crate::codegen::types::{is_i64, is_signed, is_u128};
use crate::codegen::wasm::lower::LowerCtx;
use crate::error::LangError;
use crate::type_checker::types::ResolvedType;

impl<'a> LowerCtx<'a> {
    // ── u128 comparison helpers (subtask_08) ─────────────────────────────
    //
    // Stack layout for all: [a_lo, a_hi, b_lo, b_hi] → [i32 result].

    /// u128 equality: (a_lo == b_lo) && (a_hi == b_hi).
    /// Stack: [a_lo, a_hi, b_lo, b_hi] → [i32: 1 if equal, 0 if not].
    pub(crate) fn emit_u128_eq(&mut self) -> Result<(), LangError> {
        let a_lo = self.alloc_temp_local(ValType::I64);
        let a_hi = self.alloc_temp_local(ValType::I64);
        let b_lo = self.alloc_temp_local(ValType::I64);
        let b_hi = self.alloc_temp_local(ValType::I64);
        self.func.instruction(&Instruction::LocalSet(b_hi));
        self.func.instruction(&Instruction::LocalSet(b_lo));
        self.func.instruction(&Instruction::LocalSet(a_hi));
        self.func.instruction(&Instruction::LocalSet(a_lo));
        // (a_lo == b_lo) && (a_hi == b_hi)
        self.func.instruction(&Instruction::LocalGet(a_lo));
        self.func.instruction(&Instruction::LocalGet(b_lo));
        self.func.instruction(&Instruction::I64Eq);
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::LocalGet(b_hi));
        self.func.instruction(&Instruction::I64Eq);
        self.func.instruction(&Instruction::I32And);
        Ok(())
    }

    /// u128 less-than (unsigned): a < b.
    /// Stack: [a_lo, a_hi, b_lo, b_hi] → [i32: 1 if a < b, 0 otherwise].
    /// Logic: (a_hi < b_hi) || (a_hi == b_hi && a_lo < b_lo)
    pub(crate) fn emit_u128_lt(&mut self) -> Result<(), LangError> {
        let a_lo = self.alloc_temp_local(ValType::I64);
        let a_hi = self.alloc_temp_local(ValType::I64);
        let b_lo = self.alloc_temp_local(ValType::I64);
        let b_hi = self.alloc_temp_local(ValType::I64);
        self.func.instruction(&Instruction::LocalSet(b_hi));
        self.func.instruction(&Instruction::LocalSet(b_lo));
        self.func.instruction(&Instruction::LocalSet(a_hi));
        self.func.instruction(&Instruction::LocalSet(a_lo));
        // (a_hi < b_hi)
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::LocalGet(b_hi));
        self.func.instruction(&Instruction::I64LtU);
        // (a_hi == b_hi && a_lo < b_lo)
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::LocalGet(b_hi));
        self.func.instruction(&Instruction::I64Eq);
        self.func.instruction(&Instruction::LocalGet(a_lo));
        self.func.instruction(&Instruction::LocalGet(b_lo));
        self.func.instruction(&Instruction::I64LtU);
        self.func.instruction(&Instruction::I32And);
        // OR
        self.func.instruction(&Instruction::I32Or);
        Ok(())
    }

    /// u128 greater-than (unsigned): a > b ≡ b < a.
    /// Stack: [a_lo, a_hi, b_lo, b_hi] → [i32: 1 if a > b, 0 otherwise].
    pub(crate) fn emit_u128_gt(&mut self) -> Result<(), LangError> {
        let a_lo = self.alloc_temp_local(ValType::I64);
        let a_hi = self.alloc_temp_local(ValType::I64);
        let b_lo = self.alloc_temp_local(ValType::I64);
        let b_hi = self.alloc_temp_local(ValType::I64);
        self.func.instruction(&Instruction::LocalSet(b_hi));
        self.func.instruction(&Instruction::LocalSet(b_lo));
        self.func.instruction(&Instruction::LocalSet(a_hi));
        self.func.instruction(&Instruction::LocalSet(a_lo));
        // a > b ≡ (b_hi < a_hi) || (b_hi == a_hi && b_lo < a_lo)
        self.func.instruction(&Instruction::LocalGet(b_hi));
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::I64LtU);
        self.func.instruction(&Instruction::LocalGet(b_hi));
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::I64Eq);
        self.func.instruction(&Instruction::LocalGet(b_lo));
        self.func.instruction(&Instruction::LocalGet(a_lo));
        self.func.instruction(&Instruction::I64LtU);
        self.func.instruction(&Instruction::I32And);
        self.func.instruction(&Instruction::I32Or);
        Ok(())
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
    ///
    /// ## u128 (i64-pair) overflow detection (subtask_08)
    ///
    /// Stack: [a_lo, a_hi, b_lo, b_hi]. Add lo halves, detect carry
    /// (result_lo < a_lo unsigned), add hi halves + carry, detect overflow
    /// (result_hi < a_hi unsigned, or result_hi == a_hi && carry).
    pub(crate) fn emit_checked_add(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        if is_u128(ty) {
            return self.emit_checked_add_u128();
        }
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
    ///
    /// ## u128 (i64-pair) underflow detection (subtask_08)
    ///
    /// Stack: [a_lo, a_hi, b_lo, b_hi]. Sub lo halves, detect borrow
    /// (a_lo < b_lo unsigned), sub hi halves - borrow, detect underflow.
    pub(crate) fn emit_checked_sub(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        if is_u128(ty) {
            return self.emit_checked_sub_u128();
        }
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
    ///
    /// ## u128 multiplication — deferred (subtask_08)
    ///
    /// u128 multiplication requires 4-way i64 cross-product with carry
    /// propagation. Token contracts don't multiply u128 values (transfer is
    /// +/-, mint is +). Deferred to P3·Step 23 with an honest codegen error.
    pub(crate) fn emit_checked_mul(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        if is_u128(ty) {
            return Err(LangError::Codegen {
                message: "u128 multiplication not yet implemented (deferred P3·Step 23; \
                          token contracts use add/sub only)"
                    .into(),
            });
        }
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
    pub(crate) fn emit_checked_div(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        if is_u128(ty) {
            return Err(LangError::Codegen {
                message: "u128 division not yet implemented (deferred P3·Step 23)".into(),
            });
        }
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
    pub(crate) fn emit_checked_rem(&mut self, ty: &ResolvedType) -> Result<(), LangError> {
        if is_u128(ty) {
            return Err(LangError::Codegen {
                message: "u128 remainder not yet implemented (deferred P3·Step 23)".into(),
            });
        }
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

    // ── u128 (i64-pair) checked arithmetic (subtask_08) ──────────────────
    //
    // u128 is represented as (lo: i64, hi: i64) in two consecutive locals.
    // Stack layout: [a_lo, a_hi, b_lo, b_hi] (a pushed first, then b).
    // Result: [result_lo, result_hi] on the stack.
    //
    // Overflow detection for unsigned add:
    //   1. result_lo = a_lo + b_lo (wrapping)
    //   2. carry = (result_lo < a_lo) ? 1 : 0  (unsigned)
    //   3. result_hi = a_hi + b_hi + carry (wrapping)
    //   4. overflow if: result_hi < a_hi (unsigned)
    //      OR (result_hi == a_hi AND carry == 1 AND b_hi == 0)
    //      Simplified: overflow if result_hi < a_hi + carry (with carry from step 2)
    //      Actually: overflow iff (result_hi < a_hi) || (result_hi == a_hi && carry)
    //      But that's not quite right either. The correct check:
    //      hi_sum = a_hi + b_hi (wrapping). Then hi_sum + carry.
    //      Overflow if: (hi_sum < a_hi) || (hi_sum + carry < hi_sum)
    //      i.e. overflow in the hi addition OR overflow when adding carry.

    /// Checked u128 addition: traps if `a + b` overflows (AGENTS §7.4).
    ///
    /// Stack: [a_lo, a_hi, b_lo, b_hi] → [result_lo, result_hi].
    fn emit_checked_add_u128(&mut self) -> Result<(), LangError> {
        let a_lo = self.alloc_temp_local(ValType::I64);
        let a_hi = self.alloc_temp_local(ValType::I64);
        let b_lo = self.alloc_temp_local(ValType::I64);
        let b_hi = self.alloc_temp_local(ValType::I64);
        let r_lo = self.alloc_temp_local(ValType::I64);
        let r_hi = self.alloc_temp_local(ValType::I64);
        let carry = self.alloc_temp_local(ValType::I64);

        // Pop operands: stack is [a_lo, a_hi, b_lo, b_hi]
        self.func.instruction(&Instruction::LocalSet(b_hi));
        self.func.instruction(&Instruction::LocalSet(b_lo));
        self.func.instruction(&Instruction::LocalSet(a_hi));
        self.func.instruction(&Instruction::LocalSet(a_lo));

        // r_lo = a_lo + b_lo (wrapping i64 add)
        self.func.instruction(&Instruction::LocalGet(a_lo));
        self.func.instruction(&Instruction::LocalGet(b_lo));
        self.func.instruction(&Instruction::I64Add);
        self.func.instruction(&Instruction::LocalSet(r_lo));

        // carry = (r_lo < a_lo) ? 1 : 0 (unsigned comparison detects wrap)
        self.func.instruction(&Instruction::LocalGet(r_lo));
        self.func.instruction(&Instruction::LocalGet(a_lo));
        self.func.instruction(&Instruction::I64LtU);
        self.func.instruction(&Instruction::I64ExtendI32U);
        self.func.instruction(&Instruction::LocalSet(carry));

        // r_hi = a_hi + b_hi (wrapping)
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::LocalGet(b_hi));
        self.func.instruction(&Instruction::I64Add);
        // Check overflow of hi addition BEFORE adding carry
        self.func.instruction(&Instruction::LocalTee(r_hi));
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::I64LtU);
        // If r_hi < a_hi → overflow in hi addition → trap
        self.func
            .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
        self.func.instruction(&Instruction::Unreachable);
        self.func.instruction(&Instruction::End);

        // r_hi = r_hi + carry
        self.func.instruction(&Instruction::LocalGet(r_hi));
        self.func.instruction(&Instruction::LocalGet(carry));
        self.func.instruction(&Instruction::I64Add);
        self.func.instruction(&Instruction::LocalTee(r_hi));
        // Check overflow from adding carry: if carry was 1 and r_hi wrapped to 0
        // (only possible if r_hi was 0xFFFF...FFFF before adding carry=1)
        // Detect: new_r_hi < old_r_hi is wrong because we already overwrote.
        // Simpler: if carry != 0 && r_hi == 0 → overflow (wrapped from MAX+1)
        // Actually: r_hi_before_carry + carry overflows iff carry==1 && r_hi_before==MAX.
        // After add: r_hi_new = r_hi_before + carry. Overflow iff r_hi_new < carry.
        self.func.instruction(&Instruction::LocalGet(carry));
        self.func.instruction(&Instruction::I64LtU);
        self.func
            .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
        self.func.instruction(&Instruction::Unreachable);
        self.func.instruction(&Instruction::End);

        // Push result: [r_lo, r_hi]
        self.func.instruction(&Instruction::LocalGet(r_lo));
        self.func.instruction(&Instruction::LocalGet(r_hi));
        Ok(())
    }

    /// Checked u128 subtraction: traps if `a - b` underflows (AGENTS §7.4).
    ///
    /// Stack: [a_lo, a_hi, b_lo, b_hi] → [result_lo, result_hi].
    fn emit_checked_sub_u128(&mut self) -> Result<(), LangError> {
        let a_lo = self.alloc_temp_local(ValType::I64);
        let a_hi = self.alloc_temp_local(ValType::I64);
        let b_lo = self.alloc_temp_local(ValType::I64);
        let b_hi = self.alloc_temp_local(ValType::I64);
        let r_lo = self.alloc_temp_local(ValType::I64);
        let r_hi = self.alloc_temp_local(ValType::I64);
        let borrow = self.alloc_temp_local(ValType::I64);

        // Pop operands: stack is [a_lo, a_hi, b_lo, b_hi]
        self.func.instruction(&Instruction::LocalSet(b_hi));
        self.func.instruction(&Instruction::LocalSet(b_lo));
        self.func.instruction(&Instruction::LocalSet(a_hi));
        self.func.instruction(&Instruction::LocalSet(a_lo));

        // borrow = (a_lo < b_lo) ? 1 : 0 (unsigned — will underflow)
        self.func.instruction(&Instruction::LocalGet(a_lo));
        self.func.instruction(&Instruction::LocalGet(b_lo));
        self.func.instruction(&Instruction::I64LtU);
        self.func.instruction(&Instruction::I64ExtendI32U);
        self.func.instruction(&Instruction::LocalSet(borrow));

        // r_lo = a_lo - b_lo (wrapping)
        self.func.instruction(&Instruction::LocalGet(a_lo));
        self.func.instruction(&Instruction::LocalGet(b_lo));
        self.func.instruction(&Instruction::I64Sub);
        self.func.instruction(&Instruction::LocalSet(r_lo));

        // Check underflow of hi subtraction: if a_hi < b_hi → underflow
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::LocalGet(b_hi));
        self.func.instruction(&Instruction::I64LtU);
        self.func
            .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
        self.func.instruction(&Instruction::Unreachable);
        self.func.instruction(&Instruction::End);

        // Check borrow underflow: (a_hi - b_hi) < borrow → underflow
        // (a_hi >= b_hi is guaranteed by the check above, so a_hi - b_hi >= 0.
        // Underflow from borrow only when a_hi - b_hi == 0 && borrow == 1.)
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::LocalGet(b_hi));
        self.func.instruction(&Instruction::I64Sub);
        // Stack: [r_hi_before]. Check r_hi_before < borrow → underflow
        self.func.instruction(&Instruction::LocalGet(borrow));
        self.func.instruction(&Instruction::I64LtU);
        self.func
            .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
        self.func.instruction(&Instruction::Unreachable);
        self.func.instruction(&Instruction::End);

        // Now compute final r_hi = (a_hi - b_hi) - borrow
        self.func.instruction(&Instruction::LocalGet(a_hi));
        self.func.instruction(&Instruction::LocalGet(b_hi));
        self.func.instruction(&Instruction::I64Sub);
        self.func.instruction(&Instruction::LocalGet(borrow));
        self.func.instruction(&Instruction::I64Sub);
        self.func.instruction(&Instruction::LocalSet(r_hi));

        // Push result: [r_lo, r_hi]
        self.func.instruction(&Instruction::LocalGet(r_lo));
        self.func.instruction(&Instruction::LocalGet(r_hi));
        Ok(())
    }
}
