//! Cross-contract call lowering — `rawCall`, `staticCall`, `delegateCall`.
//!
//! Split from `wasm.rs` (P3·Step 21 cross-contract calls).

use wasm_encoder::{Instruction, ValType};

use crate::codegen::abi::CALL_CONTRACT_INDEX;
use crate::codegen::wasm::lower::{LowerCtx, ADDRESS_BYTE_LEN};
use crate::error::LangError;
use crate::parser::Expr;

impl<'a> LowerCtx<'a> {
    // ── Cross-contract call lowering (P3·Step 21) ─────────────────────────

    /// Emit WASM instructions for a cross-contract call.
    ///
    /// Shared helper for `rawCall`, `staticCall`, and `delegateCall` — all three
    /// call types share the same address marshalling and register-channel pattern.
    /// Only the host function index and the presence of a `value` parameter differ.
    ///
    /// ## ABI (DB-A53 §4.5)
    ///
    /// ```text
    /// call_contract (index 14): (addr_ptr, addr_len, data_reg, gas, value) -> i32
    /// static_call   (index 15): (addr_ptr, addr_len, data_reg, gas)        -> i32
    /// delegate_call (index 16): (addr_ptr, addr_len, data_reg, gas)        -> i32
    /// ```
    ///
    /// ## Lowering strategy
    ///
    /// 1. Lower `addr_expr` → i32 pointer to 20-byte address in guest memory.
    ///    The address is already in memory (from `emit_address_constant` or a
    ///    local variable holding a pointer). Push `addr_ptr: i32` + `addr_len: i32`.
    /// 2. Lower `calldata_expr` → i32 register ID. The calldata expression is
    ///    expected to evaluate to an i32 register ID that the host will read.
    ///    Full bytes-type lowering is deferred (M6 scope); for now the caller
    ///    passes a register ID literal (e.g. `0` for REG_CALLDATA).
    /// 3. Push `gas: i64` — from `gas_expr` if provided, else 0 (no-gas default).
    /// 4. For `rawCall` only: push `value: i64` — from `value_expr` if provided,
    ///    else 0 (no-value transfer).
    /// 5. Emit `Instruction::Call(host_fn_index)`.
    /// 6. Result: the host fn returns an i32 register ID on the WASM stack.
    ///
    /// ## Address pointer convention
    ///
    /// `addr_expr` must evaluate to an i32 pointer into guest linear memory
    /// where 20 address bytes reside. This matches the convention established
    /// by `emit_address_constant` (P3·Step 6g) and the address predicate
    /// comparison pattern.
    ///
    /// ## DRY (AGENTS §2)
    ///
    /// All three call types (`rawCall`, `staticCall`, `delegateCall`) use this
    /// single helper. The only differences are:
    /// - `host_fn_index`: 14, 15, or 16
    /// - `value_expr`: `Some(expr)` for `rawCall`, `None` for static/delegate
    pub(crate) fn emit_cross_contract_call(
        &mut self,
        addr_expr: &Expr,
        calldata_expr: &Expr,
        gas_expr: Option<&Expr>,
        value_expr: Option<&Expr>,
        host_fn_index: u32,
    ) -> Result<(), LangError> {
        // ── Step 1: Marshal address into guest memory ──────────────────────
        //
        // addr_expr evaluates to an i32 pointer to 20 address bytes in memory.
        // Save to a temp local so we can push it as addr_ptr.
        self.emit_expr(addr_expr)?;
        let addr_ptr = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::LocalSet(addr_ptr));

        // Push addr_ptr: i32
        self.func.instruction(&Instruction::LocalGet(addr_ptr));
        // Push addr_len: i32 (always 20 bytes for an Address — AGENTS §7.1 no magic numbers)
        self.func
            .instruction(&Instruction::I32Const(ADDRESS_BYTE_LEN as i32));

        // ── Step 2: Calldata register ──────────────────────────────────────
        //
        // The calldata expression is lowered as an i32 register ID.
        // Full bytes-type lowering is deferred (M6 scope). For now, the
        // calldata expression must evaluate to an i32 register ID that the
        // host will read (e.g. `0` for REG_CALLDATA).
        self.emit_expr(calldata_expr)?;
        // data_reg: i32 is now on the WASM stack

        // ── Step 3: Gas parameter ──────────────────────────────────────────
        //
        // gas_expr: i64 forwarded gas budget. Default 0 if not provided.
        // The VM caps forwarded gas at 63/64 of remaining (08-EXECUTION_SPEC §2.4).
        if let Some(gas) = gas_expr {
            self.emit_expr(gas)?;
        } else {
            // Default: forward 0 gas (host uses 63/64 of remaining)
            self.func.instruction(&Instruction::I64Const(0));
        }

        // ── Step 4: Value parameter (rawCall only) ─────────────────────────
        //
        // value_expr: i64 Drop amount to transfer. Only present for rawCall.
        // staticCall and delegateCall have no value parameter (no value push).
        //
        // When value_expr is None for rawCall (CALL_CONTRACT_INDEX), we push
        // i64.const 0 as the default (no value transfer). This is required because
        // call_contract always takes a value parameter — omitting it would produce
        // a WASM type-stack mismatch at validation time.
        if let Some(value) = value_expr {
            self.emit_expr(value)?;
        } else if host_fn_index == CALL_CONTRACT_INDEX {
            // rawCall requires a value parameter — default to 0 (no value transfer).
            // The VM will not transfer any LEM to the callee.
            self.func.instruction(&Instruction::I64Const(0));
        }

        // ── Step 5: Emit the host function call ────────────────────────────
        //
        // Stack at this point:
        //   rawCall:      [addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64, value: i64]
        //   staticCall:   [addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64]
        //   delegateCall: [addr_ptr: i32, addr_len: i32, data_reg: i32, gas: i64]
        self.func.instruction(&Instruction::Call(host_fn_index));

        // ── Step 6: Result ─────────────────────────────────────────────────
        //
        // The host fn returns i32: result register ID on success, or a negative
        // error sentinel on failure. The i32 is left on the WASM stack as the
        // expression result.

        Ok(())
    }
}
