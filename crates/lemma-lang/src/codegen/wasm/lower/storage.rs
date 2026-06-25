//! Storage read/write lowering — `emit_storage_read`, `emit_storage_write`.
//!
//! Split from `wasm.rs` (P3·Step 6e storage access).

use wasm_encoder::{Instruction, ValType};

use crate::codegen::abi;
use crate::codegen::types::{is_address, is_i64, is_u128};
use crate::codegen::wasm::lower::{storage_byte_width, LowerCtx, ADDR_ZERO_OFFSET};
use crate::error::LangError;
use crate::parser::Expr;
use crate::type_checker::types::ResolvedType;

impl<'a> LowerCtx<'a> {
    // ── Storage access (P3·Step 6e) ──────────────────────────────────────

    /// Emit WASM instructions to read a state field from storage.
    ///
    /// Sequence:
    /// 1. Allocate 32 bytes for the storage key, write key bytes to memory
    /// 2. Call `storage_read(key_ptr, 32, REG_SCRATCH)` → status (i32)
    /// 3. If status == STORAGE_NOT_FOUND: push default value (0)
    /// 4. Else: read value from register into memory, load as typed value
    pub(crate) fn emit_storage_read(&mut self, field_name: &str) -> Result<(), LangError> {
        let (ty, key_bytes) =
            self.state_fields
                .get(field_name)
                .ok_or_else(|| LangError::Codegen {
                    message: format!("unknown state field: {field_name}"),
                })?;
        let ty = (*ty).clone();
        let key_bytes = *key_bytes;
        let byte_width = storage_byte_width(&ty)?;

        // Allocate 32 bytes for the key and write key bytes to memory
        let key_ptr = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::I32Const(32));
        self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
        self.func.instruction(&Instruction::LocalSet(key_ptr));

        // Write key bytes to memory (8 i32.store operations = 32 bytes)
        for chunk_idx in 0..8u32 {
            self.func.instruction(&Instruction::LocalGet(key_ptr));
            let start = (chunk_idx * 4) as usize;
            let word = u32::from_le_bytes([
                key_bytes[start],
                key_bytes[start + 1],
                key_bytes[start + 2],
                key_bytes[start + 3],
            ]);
            self.func.instruction(&Instruction::I32Const(word as i32));
            self.func
                .instruction(&Instruction::I32Store(wasm_encoder::MemArg {
                    offset: (chunk_idx * 4) as u64,
                    align: 2,
                    memory_index: 0,
                }));
        }

        // Call storage_read(key_ptr, 32, REG_SCRATCH) → status
        let status = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::LocalGet(key_ptr));
        self.func.instruction(&Instruction::I32Const(32));
        self.func
            .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
        self.func.instruction(&Instruction::Call(8)); // storage_read = index 8
        self.func.instruction(&Instruction::LocalSet(status));

        // Check status: if STORAGE_NOT_FOUND → push default.
        // u128 defaults to (0i64, 0i64) pair; Address defaults to Address::zero pointer.
        // Single-word types default to 0.
        self.func.instruction(&Instruction::LocalGet(status));
        self.func
            .instruction(&Instruction::I32Const(abi::STORAGE_NOT_FOUND));
        self.func.instruction(&Instruction::I32Eq);

        if is_u128(&ty) {
            // u128 not-found default: push two i64 zeros (lo=0, hi=0).
            // WASM if/else must produce a consistent stack shape. For u128 we
            // need 2 values, but WASM block types only support 0 or 1 result.
            // Solution: use void block, write defaults to temp locals, load after.
            let u128_lo = self.alloc_temp_local(ValType::I64);
            let u128_hi = self.alloc_temp_local(ValType::I64);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.block_depth += 1;
            // Not found → default 0
            self.func.instruction(&Instruction::I64Const(0));
            self.func.instruction(&Instruction::LocalSet(u128_lo));
            self.func.instruction(&Instruction::I64Const(0));
            self.func.instruction(&Instruction::LocalSet(u128_hi));
            self.func.instruction(&Instruction::Else);

            // Found → validate register length, read 16 bytes, split into lo/hi.
            let val_len = self.alloc_temp_local(ValType::I32);
            self.func
                .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
            self.func.instruction(&Instruction::Call(6)); // register_len
            self.func.instruction(&Instruction::I32WrapI64);
            self.func.instruction(&Instruction::LocalTee(val_len));
            self.func
                .instruction(&Instruction::I32Const(byte_width as i32));
            self.func.instruction(&Instruction::I32Ne);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.block_depth += 1;
            self.func.instruction(&Instruction::Unreachable);
            self.block_depth -= 1;
            self.func.instruction(&Instruction::End);

            let val_ptr = self.alloc_temp_local(ValType::I32);
            self.func.instruction(&Instruction::LocalGet(val_len));
            self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
            self.func.instruction(&Instruction::LocalSet(val_ptr));

            self.func
                .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
            self.func.instruction(&Instruction::LocalGet(val_ptr));
            self.func.instruction(&Instruction::Call(7)); // read_register

            // Load lo (bytes 0..8) and hi (bytes 8..16)
            self.func.instruction(&Instruction::LocalGet(val_ptr));
            self.func
                .instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                    offset: 0,
                    align: 3,
                    memory_index: 0,
                }));
            self.func.instruction(&Instruction::LocalSet(u128_lo));
            self.func.instruction(&Instruction::LocalGet(val_ptr));
            self.func
                .instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                    offset: 8,
                    align: 3,
                    memory_index: 0,
                }));
            self.func.instruction(&Instruction::LocalSet(u128_hi));

            self.block_depth -= 1;
            self.func.instruction(&Instruction::End); // end if/else

            // Push lo, hi onto stack
            self.func.instruction(&Instruction::LocalGet(u128_lo));
            self.func.instruction(&Instruction::LocalGet(u128_hi));
        } else if is_address(&ty) {
            // Address not-found default: pointer to Address::zero (offset 0 in page 0).
            let addr_ptr = self.alloc_temp_local(ValType::I32);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.block_depth += 1;
            self.func
                .instruction(&Instruction::I32Const(ADDR_ZERO_OFFSET as i32));
            self.func.instruction(&Instruction::LocalSet(addr_ptr));
            self.func.instruction(&Instruction::Else);

            // Found → read 20 bytes into bump-alloc memory, push pointer.
            let val_len = self.alloc_temp_local(ValType::I32);
            self.func
                .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
            self.func.instruction(&Instruction::Call(6));
            self.func.instruction(&Instruction::I32WrapI64);
            self.func.instruction(&Instruction::LocalTee(val_len));
            self.func
                .instruction(&Instruction::I32Const(byte_width as i32));
            self.func.instruction(&Instruction::I32Ne);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.block_depth += 1;
            self.func.instruction(&Instruction::Unreachable);
            self.block_depth -= 1;
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(val_len));
            self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
            self.func.instruction(&Instruction::LocalSet(addr_ptr));

            self.func
                .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
            self.func.instruction(&Instruction::LocalGet(addr_ptr));
            self.func.instruction(&Instruction::Call(7));

            self.block_depth -= 1;
            self.func.instruction(&Instruction::End);

            self.func.instruction(&Instruction::LocalGet(addr_ptr));
        } else if is_i64(&ty) {
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Result(
                    ValType::I64,
                )));
            self.block_depth += 1;
            // Not found → default 0
            self.func.instruction(&Instruction::I64Const(0));
            self.func.instruction(&Instruction::Else);

            // Found → validate register length matches expected byte width.
            let val_len = self.alloc_temp_local(ValType::I32);
            self.func
                .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
            self.func.instruction(&Instruction::Call(6));
            self.func.instruction(&Instruction::I32WrapI64);
            self.func.instruction(&Instruction::LocalTee(val_len));
            self.func
                .instruction(&Instruction::I32Const(byte_width as i32));
            self.func.instruction(&Instruction::I32Ne);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.block_depth += 1;
            self.func.instruction(&Instruction::Unreachable);
            self.block_depth -= 1;
            self.func.instruction(&Instruction::End);

            let val_ptr = self.alloc_temp_local(ValType::I32);
            self.func.instruction(&Instruction::LocalGet(val_len));
            self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
            self.func.instruction(&Instruction::LocalSet(val_ptr));

            self.func
                .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
            self.func.instruction(&Instruction::LocalGet(val_ptr));
            self.func.instruction(&Instruction::Call(7));

            self.func.instruction(&Instruction::LocalGet(val_ptr));
            self.func
                .instruction(&Instruction::I64Load(wasm_encoder::MemArg {
                    offset: 0,
                    align: 3,
                    memory_index: 0,
                }));

            self.block_depth -= 1;
            self.func.instruction(&Instruction::End);
        } else {
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Result(
                    ValType::I32,
                )));
            self.block_depth += 1;
            // Not found → default 0
            self.func.instruction(&Instruction::I32Const(0));
            self.func.instruction(&Instruction::Else);

            // Found → validate register length matches expected byte width.
            let val_len = self.alloc_temp_local(ValType::I32);
            self.func
                .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
            self.func.instruction(&Instruction::Call(6));
            self.func.instruction(&Instruction::I32WrapI64);
            self.func.instruction(&Instruction::LocalTee(val_len));
            self.func
                .instruction(&Instruction::I32Const(byte_width as i32));
            self.func.instruction(&Instruction::I32Ne);
            self.func
                .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
            self.block_depth += 1;
            self.func.instruction(&Instruction::Unreachable);
            self.block_depth -= 1;
            self.func.instruction(&Instruction::End);

            let val_ptr = self.alloc_temp_local(ValType::I32);
            self.func.instruction(&Instruction::LocalGet(val_len));
            self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
            self.func.instruction(&Instruction::LocalSet(val_ptr));

            self.func
                .instruction(&Instruction::I32Const(abi::REG_SCRATCH as i32));
            self.func.instruction(&Instruction::LocalGet(val_ptr));
            self.func.instruction(&Instruction::Call(7));

            self.func.instruction(&Instruction::LocalGet(val_ptr));
            match &ty {
                ResolvedType::Bool => {
                    self.func
                        .instruction(&Instruction::I32Load8U(wasm_encoder::MemArg {
                            offset: 0,
                            align: 0,
                            memory_index: 0,
                        }));
                }
                ResolvedType::U32 | ResolvedType::I32 => {
                    self.func
                        .instruction(&Instruction::I32Load(wasm_encoder::MemArg {
                            offset: 0,
                            align: 2,
                            memory_index: 0,
                        }));
                }
                _ => {
                    return Err(LangError::Codegen {
                        message: format!(
                            "storage read for type {} not yet implemented",
                            ty.display_name()
                        ),
                    });
                }
            }

            self.block_depth -= 1;
            self.func.instruction(&Instruction::End);
        }

        Ok(())
    }

    /// Emit WASM instructions to write a value to a state field in storage.
    ///
    /// Sequence:
    /// 1. Allocate 32 bytes for the storage key, write key bytes to memory
    /// 2. Emit the value expression
    /// 3. Encode value to bytes in memory
    /// 4. Call `storage_write(key_ptr, 32, val_ptr, val_len)`
    pub(crate) fn emit_storage_write(
        &mut self,
        field_name: &str,
        value: &Expr,
    ) -> Result<(), LangError> {
        let (ty, key_bytes) =
            self.state_fields
                .get(field_name)
                .ok_or_else(|| LangError::Codegen {
                    message: format!("unknown state field: {field_name}"),
                })?;
        let ty = (*ty).clone();
        let key_bytes = *key_bytes;
        let byte_width = storage_byte_width(&ty)?;

        // Allocate 32 bytes for the key and write key bytes to memory
        let key_ptr = self.alloc_temp_local(ValType::I32);
        self.func.instruction(&Instruction::I32Const(32));
        self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
        self.func.instruction(&Instruction::LocalSet(key_ptr));

        // Write key bytes to memory
        for chunk_idx in 0..8u32 {
            self.func.instruction(&Instruction::LocalGet(key_ptr));
            let start = (chunk_idx * 4) as usize;
            let word = u32::from_le_bytes([
                key_bytes[start],
                key_bytes[start + 1],
                key_bytes[start + 2],
                key_bytes[start + 3],
            ]);
            self.func.instruction(&Instruction::I32Const(word as i32));
            self.func
                .instruction(&Instruction::I32Store(wasm_encoder::MemArg {
                    offset: (chunk_idx * 4) as u64,
                    align: 2,
                    memory_index: 0,
                }));
        }

        // Emit the value expression — result on stack
        self.emit_expr(value)?;

        // Allocate buffer for value and store it
        let val_ptr = self.alloc_temp_local(ValType::I32);
        self.func
            .instruction(&Instruction::I32Const(byte_width as i32));
        self.func.instruction(&Instruction::Call(self.alloc_fn_idx));
        self.func.instruction(&Instruction::LocalSet(val_ptr));

        // Store value to memory based on type.
        // The value is on the stack from emit_expr; we need to save it to a temp
        // because we need val_ptr on the stack first for the store instruction.
        if is_u128(&ty) {
            // u128: stack has [lo: i64, hi: i64]. Store both halves to memory.
            let tmp_hi = self.alloc_temp_local(ValType::I64);
            let tmp_lo = self.alloc_temp_local(ValType::I64);
            self.func.instruction(&Instruction::LocalSet(tmp_hi));
            self.func.instruction(&Instruction::LocalSet(tmp_lo));
            // Store lo at val_ptr+0
            self.func.instruction(&Instruction::LocalGet(val_ptr));
            self.func.instruction(&Instruction::LocalGet(tmp_lo));
            self.func
                .instruction(&Instruction::I64Store(wasm_encoder::MemArg {
                    offset: 0,
                    align: 3,
                    memory_index: 0,
                }));
            // Store hi at val_ptr+8
            self.func.instruction(&Instruction::LocalGet(val_ptr));
            self.func.instruction(&Instruction::LocalGet(tmp_hi));
            self.func
                .instruction(&Instruction::I64Store(wasm_encoder::MemArg {
                    offset: 8,
                    align: 3,
                    memory_index: 0,
                }));
        } else if is_address(&ty) {
            // Address: stack has [ptr: i32] pointing to 20 bytes in memory.
            // Copy 20 bytes from the source pointer to val_ptr.
            let src_ptr = self.alloc_temp_local(ValType::I32);
            self.func.instruction(&Instruction::LocalSet(src_ptr));
            // Copy 5 × i32 (20 bytes)
            for chunk in 0..5u32 {
                self.func.instruction(&Instruction::LocalGet(val_ptr));
                self.func.instruction(&Instruction::LocalGet(src_ptr));
                self.func
                    .instruction(&Instruction::I32Load(wasm_encoder::MemArg {
                        offset: (chunk * 4) as u64,
                        align: 2,
                        memory_index: 0,
                    }));
                self.func
                    .instruction(&Instruction::I32Store(wasm_encoder::MemArg {
                        offset: (chunk * 4) as u64,
                        align: 2,
                        memory_index: 0,
                    }));
            }
        } else {
            let val_tmp = if is_i64(&ty) {
                self.alloc_temp_local(ValType::I64)
            } else {
                self.alloc_temp_local(ValType::I32)
            };
            self.func.instruction(&Instruction::LocalSet(val_tmp));

            self.func.instruction(&Instruction::LocalGet(val_ptr));
            self.func.instruction(&Instruction::LocalGet(val_tmp));
            match &ty {
                ResolvedType::Bool => {
                    self.func
                        .instruction(&Instruction::I32Store8(wasm_encoder::MemArg {
                            offset: 0,
                            align: 0,
                            memory_index: 0,
                        }));
                }
                ResolvedType::U32 | ResolvedType::I32 => {
                    self.func
                        .instruction(&Instruction::I32Store(wasm_encoder::MemArg {
                            offset: 0,
                            align: 2,
                            memory_index: 0,
                        }));
                }
                ResolvedType::U64 | ResolvedType::I64 => {
                    self.func
                        .instruction(&Instruction::I64Store(wasm_encoder::MemArg {
                            offset: 0,
                            align: 3,
                            memory_index: 0,
                        }));
                }
                _ => {
                    return Err(LangError::Codegen {
                        message: format!(
                            "storage write for type {} not yet implemented",
                            ty.display_name()
                        ),
                    });
                }
            }
        }

        // Call storage_write(key_ptr, 32, val_ptr, val_len)
        self.func.instruction(&Instruction::LocalGet(key_ptr));
        self.func.instruction(&Instruction::I32Const(32));
        self.func.instruction(&Instruction::LocalGet(val_ptr));
        self.func
            .instruction(&Instruction::I32Const(byte_width as i32));
        self.func.instruction(&Instruction::Call(9)); // storage_write = index 9

        Ok(())
    }
}
