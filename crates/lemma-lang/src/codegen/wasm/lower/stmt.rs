//! Statement + control-flow lowering — `emit_stmt`, `emit_block`,
//! `emit_assign`, `emit_with_modifiers`.
//!
//! Split from `wasm.rs` (P3·Step 6d statement lowering, P3·Step 6f modifiers).

use wasm_encoder::Instruction;

use crate::codegen::types::{is_sub_word, local_count, wasm_valtype};
use crate::codegen::wasm::lower::{find_modifier, split_at_placeholder, LoopCtx, LowerCtx};
use crate::error::LangError;
use crate::lexer::token::Span;
use crate::parser::{expr_span, AssignOp, Expr, Pattern, Stmt};
use crate::type_checker::typed_contract::TypedContract;
use crate::type_checker::types::ResolvedType;

impl<'a> LowerCtx<'a> {
    // ── Statement + control flow lowering (P3·Step 6d) ──────────────────

    /// Emit WASM instructions for a block of statements.
    ///
    /// Simply iterates and calls `emit_stmt` on each statement.
    pub(crate) fn emit_block(&mut self, stmts: &[Stmt]) -> Result<(), LangError> {
        for stmt in stmts {
            self.emit_stmt(stmt)?;
        }
        Ok(())
    }

    /// Emit a function body with modifier inlining applied (P3·Step 6f).
    ///
    /// Processes modifiers outermost-first (left-to-right annotation order):
    /// `@a @b fn f()` → `a.pre → b.pre → f.body → b.post → a.post`.
    ///
    /// Each modifier body is split at `Stmt::Placeholder` (`_`) into pre/post
    /// segments. The inner body (remaining modifiers + function body) replaces
    /// the `_` position.
    ///
    /// ## Parameterized modifiers
    ///
    /// Modifiers with parameters are not yet supported in codegen — returns
    /// an honest deferral error (DB-A37 mod.2 scope).
    pub(crate) fn emit_with_modifiers(
        &mut self,
        inner_body: &[Stmt],
        modifiers: &[&str],
        contract: &TypedContract<'_>,
    ) -> Result<(), LangError> {
        if modifiers.is_empty() {
            // Base case: no more modifiers — emit the function body directly.
            return self.emit_block(inner_body);
        }

        let modifier_name = modifiers[0];
        let remaining = &modifiers[1..];

        let modifier_def = find_modifier(contract, modifier_name)?;

        // Reject parameterized modifiers for now (honest deferral).
        if !modifier_def.params.is_empty() {
            return Err(LangError::Codegen {
                message: format!(
                    "parameterized modifier '{modifier_name}' not yet supported in codegen"
                ),
            });
        }

        let (pre, post) = split_at_placeholder(&modifier_def.body)?;

        // Emit: pre → (inner modifiers + body) → post
        self.emit_block(pre)?;
        self.emit_with_modifiers(inner_body, remaining, contract)?;
        self.emit_block(post)?;

        Ok(())
    }

    /// Emit WASM instructions for a single statement.
    ///
    /// ## Supported statements (P3·Step 6d)
    ///
    /// - Let binding, Const binding (local variable allocation + init)
    /// - Assign (simple and compound: +=, -=, *=, /=, %=)
    /// - If/Else
    /// - While loop, Loop (infinite), Break, Continue
    /// - Return
    /// - Assert (trap on false), Revert (unconditional trap)
    /// - Expr (bare expression statement — result dropped)
    ///
    /// ## Deferred statements
    ///
    /// Match, For, Emit, Try, Unchecked, Placeholder → honest codegen error.
    pub(crate) fn emit_stmt(&mut self, stmt: &Stmt) -> Result<(), LangError> {
        match stmt {
            // ── Let binding ───────────────────────────────────────────
            Stmt::Let { pattern, expr, .. } => {
                // Only support Pattern::Ident for now (destructuring deferred)
                let name = match pattern {
                    Pattern::Ident(name, _) => name.clone(),
                    _ => {
                        return Err(LangError::Codegen {
                            message: "let destructuring not yet implemented in codegen".into(),
                        })
                    }
                };
                // Resolve the type from the expression
                let expr_s = expr_span(expr);
                let resolved = self.resolve_type(&expr_s)?;
                let valtype = wasm_valtype(&resolved)?;
                let count = local_count(&resolved);

                if count == 2 {
                    // u128: allocate two named locals (name_lo, name_hi)
                    let lo_idx = self.next_local;
                    self.locals.insert(format!("{name}_lo"), lo_idx);
                    self.local_types.push((1, valtype));
                    self.next_local += 1;
                    let hi_idx = self.next_local;
                    self.locals.insert(format!("{name}_hi"), hi_idx);
                    self.local_types.push((1, valtype));
                    self.next_local += 1;
                    // Emit the initializer — pushes [lo, hi] on stack
                    self.emit_expr(expr)?;
                    self.func.instruction(&Instruction::LocalSet(hi_idx));
                    self.func.instruction(&Instruction::LocalSet(lo_idx));
                } else {
                    // Standard single-local variable
                    let idx = self.next_local;
                    self.locals.insert(name, idx);
                    self.local_types.push((1, valtype));
                    self.next_local += 1;
                    // Emit the initializer and store
                    self.emit_expr(expr)?;
                    self.func.instruction(&Instruction::LocalSet(idx));
                }
                Ok(())
            }

            // ── Const binding (immutability is a semantic check, not codegen) ──
            Stmt::Const(c) => {
                let name = c.name.clone();
                let expr_s = expr_span(&c.value);
                let resolved = self.resolve_type(&expr_s)?;
                let valtype = wasm_valtype(&resolved)?;
                let count = local_count(&resolved);

                if count == 2 {
                    let lo_idx = self.next_local;
                    self.locals.insert(format!("{name}_lo"), lo_idx);
                    self.local_types.push((1, valtype));
                    self.next_local += 1;
                    let hi_idx = self.next_local;
                    self.locals.insert(format!("{name}_hi"), hi_idx);
                    self.local_types.push((1, valtype));
                    self.next_local += 1;
                    self.emit_expr(&c.value)?;
                    self.func.instruction(&Instruction::LocalSet(hi_idx));
                    self.func.instruction(&Instruction::LocalSet(lo_idx));
                } else {
                    let idx = self.next_local;
                    self.locals.insert(name, idx);
                    self.local_types.push((1, valtype));
                    self.next_local += 1;
                    self.emit_expr(&c.value)?;
                    self.func.instruction(&Instruction::LocalSet(idx));
                }
                Ok(())
            }

            // ── Assignment ────────────────────────────────────────────
            Stmt::Assign {
                target,
                op,
                value,
                span,
            } => self.emit_assign(target, op, value, span),

            // ── If/Else ───────────────────────────────────────────────
            Stmt::If {
                cond, then, else_, ..
            } => {
                self.emit_expr(cond)?;
                if let Some(else_stmts) = else_ {
                    self.func
                        .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                    self.block_depth += 1;
                    self.emit_block(then)?;
                    self.func.instruction(&Instruction::Else);
                    self.emit_block(else_stmts)?;
                    self.block_depth -= 1;
                    self.func.instruction(&Instruction::End);
                } else {
                    self.func
                        .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                    self.block_depth += 1;
                    self.emit_block(then)?;
                    self.block_depth -= 1;
                    self.func.instruction(&Instruction::End);
                }
                Ok(())
            }

            // ── While loop ────────────────────────────────────────────
            // WASM pattern:
            //   block $exit        ;; break target
            //     loop $continue   ;; continue target
            //       <cond>
            //       i32.eqz
            //       br_if 1        ;; if cond is false, exit outer block
            //       <body>
            //       br 0           ;; loop back to loop head
            //     end
            //   end
            Stmt::While { cond, body, .. } => {
                self.func
                    .instruction(&Instruction::Block(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                let break_target = self.block_depth; // outer block

                self.func
                    .instruction(&Instruction::Loop(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                let continue_target = self.block_depth; // loop head

                self.loop_stack.push(LoopCtx {
                    break_target_depth: break_target,
                    continue_target_depth: continue_target,
                });

                self.emit_expr(cond)?;
                self.func.instruction(&Instruction::I32Eqz);
                // br depth to exit outer block = current_depth - break_target
                let br_exit = self.block_depth.checked_sub(break_target).ok_or_else(|| {
                    LangError::Codegen {
                        message: "block depth underflow computing while break target".into(),
                    }
                })?;
                self.func.instruction(&Instruction::BrIf(br_exit));

                self.emit_block(body)?;

                // br depth to loop head = current_depth - continue_target
                let br_cont = self
                    .block_depth
                    .checked_sub(continue_target)
                    .ok_or_else(|| LangError::Codegen {
                        message: "block depth underflow computing while continue target".into(),
                    })?;
                self.func.instruction(&Instruction::Br(br_cont));

                self.loop_stack.pop();
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End); // end loop
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End); // end block
                Ok(())
            }

            // ── Loop (infinite) ───────────────────────────────────────
            Stmt::Loop { body, .. } => {
                self.func
                    .instruction(&Instruction::Block(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                let break_target = self.block_depth;

                self.func
                    .instruction(&Instruction::Loop(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                let continue_target = self.block_depth;

                self.loop_stack.push(LoopCtx {
                    break_target_depth: break_target,
                    continue_target_depth: continue_target,
                });

                self.emit_block(body)?;
                // br depth to loop head = current_depth - continue_target
                let br_cont = self
                    .block_depth
                    .checked_sub(continue_target)
                    .ok_or_else(|| LangError::Codegen {
                        message: "block depth underflow computing loop continue target".into(),
                    })?;
                self.func.instruction(&Instruction::Br(br_cont));

                self.loop_stack.pop();
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End); // end loop
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End); // end block
                Ok(())
            }

            // ── Break ─────────────────────────────────────────────────
            Stmt::Break(_) => {
                let ctx = self.loop_stack.last().ok_or_else(|| LangError::Codegen {
                    message: "break outside of loop".into(),
                })?;
                // Relative br depth = current nesting - target nesting
                let depth = self
                    .block_depth
                    .checked_sub(ctx.break_target_depth)
                    .ok_or_else(|| LangError::Codegen {
                        message: "block depth underflow computing break target".into(),
                    })?;
                self.func.instruction(&Instruction::Br(depth));
                Ok(())
            }

            // ── Continue ──────────────────────────────────────────────
            Stmt::Continue(_) => {
                let ctx = self.loop_stack.last().ok_or_else(|| LangError::Codegen {
                    message: "continue outside of loop".into(),
                })?;
                // Relative br depth = current nesting - target nesting
                let depth = self
                    .block_depth
                    .checked_sub(ctx.continue_target_depth)
                    .ok_or_else(|| LangError::Codegen {
                        message: "block depth underflow computing continue target".into(),
                    })?;
                self.func.instruction(&Instruction::Br(depth));
                Ok(())
            }

            // ── Return ────────────────────────────────────────────────
            Stmt::Return(expr, _) => {
                if let Some(e) = expr {
                    self.emit_expr(e)?;
                }
                self.func.instruction(&Instruction::Return);
                Ok(())
            }

            // ── Assert (trap on false) ────────────────────────────────
            Stmt::Assert { cond, .. } => {
                self.emit_expr(cond)?;
                self.func.instruction(&Instruction::I32Eqz);
                self.func
                    .instruction(&Instruction::If(wasm_encoder::BlockType::Empty));
                self.block_depth += 1;
                self.func.instruction(&Instruction::Unreachable);
                self.block_depth -= 1;
                self.func.instruction(&Instruction::End);
                Ok(())
            }

            // ── Revert (unconditional trap) ───────────────────────────
            Stmt::Revert { .. } => {
                self.func.instruction(&Instruction::Unreachable);
                Ok(())
            }

            // ── Bare expression statement ─────────────────────────────
            // Drop the result from the value stack. All expressions from
            // 6c push exactly one value; void expressions (e.g. function
            // calls returning void) will need special handling in 6e.
            Stmt::Expr(expr, _) => {
                self.emit_expr(expr)?;
                self.func.instruction(&Instruction::Drop);
                Ok(())
            }

            // ── Deferred statement variants ───────────────────────────
            Stmt::Match { .. } => Err(LangError::Codegen {
                message: "match lowering not yet implemented".into(),
            }),
            Stmt::For { .. } => Err(LangError::Codegen {
                message: "for loop lowering not yet implemented".into(),
            }),
            Stmt::Emit { .. } => Err(LangError::Codegen {
                message: "emit lowering not yet implemented (6e)".into(),
            }),
            Stmt::Try { .. } => Err(LangError::Codegen {
                message: "try/catch lowering not yet implemented".into(),
            }),
            Stmt::Unchecked(..) => Err(LangError::Codegen {
                message: "unchecked block lowering not yet implemented".into(),
            }),
            Stmt::Placeholder(..) => Err(LangError::Codegen {
                message: "unexpected `_` placeholder in codegen — modifier inlining should \
                          have removed it (did split_at_placeholder miss?)"
                    .into(),
            }),
            // Forward-compatibility for #[non_exhaustive]
            #[allow(unreachable_patterns)]
            _ => Err(LangError::Codegen {
                message: "unknown statement variant in codegen".into(),
            }),
        }
    }

    /// Emit WASM instructions for an assignment statement.
    ///
    /// Handles simple assignment (`=`) and compound assignment (`+=`, `-=`,
    /// `*=`, `/=`, `%=`). Compound assignment uses checked arithmetic from
    /// 6c (AGENTS §7.4).
    pub(super) fn emit_assign(
        &mut self,
        target: &Expr,
        op: &AssignOp,
        value: &Expr,
        _span: &Span,
    ) -> Result<(), LangError> {
        match target {
            Expr::Ident(name, ident_span) => {
                // Check for u128 variable (stored as name_lo + name_hi)
                let lo_name = format!("{name}_lo");
                if let Some(&lo_idx) = self.locals.get(&lo_name) {
                    let hi_name = format!("{name}_hi");
                    let hi_idx = *self
                        .locals
                        .get(&hi_name)
                        .ok_or_else(|| LangError::Codegen {
                            message: format!(
                                "u128 variable '{name}' has _lo but missing _hi local"
                            ),
                        })?;
                    if matches!(op, AssignOp::Assign) {
                        self.emit_expr(value)?;
                        self.func.instruction(&Instruction::LocalSet(hi_idx));
                        self.func.instruction(&Instruction::LocalSet(lo_idx));
                    } else {
                        let ty = ResolvedType::U128;
                        // Load current value (lo, hi)
                        self.func.instruction(&Instruction::LocalGet(lo_idx));
                        self.func.instruction(&Instruction::LocalGet(hi_idx));
                        self.emit_expr(value)?;
                        match op {
                            AssignOp::Add => self.emit_checked_add(&ty)?,
                            AssignOp::Sub => self.emit_checked_sub(&ty)?,
                            _ => {
                                return Err(LangError::Codegen {
                                    message: format!(
                                        "compound assignment operator {op:?} not yet implemented for u128"
                                    ),
                                })
                            }
                        }
                        self.func.instruction(&Instruction::LocalSet(hi_idx));
                        self.func.instruction(&Instruction::LocalSet(lo_idx));
                    }
                    return Ok(());
                }

                let idx = *self.locals.get(name).ok_or_else(|| LangError::Codegen {
                    message: format!("undefined variable in assignment: {name}"),
                })?;
                if matches!(op, AssignOp::Assign) {
                    // Simple assignment: evaluate value, store
                    self.emit_expr(value)?;
                    self.func.instruction(&Instruction::LocalSet(idx));
                } else {
                    // Compound assign: load current, evaluate value, checked op, store.
                    // Resolve type from the target identifier (not the statement span),
                    // because the type checker stores types by expression span.
                    let ty = self.resolve_type(ident_span)?;
                    // Sub-word compound assignment deferred (M1)
                    if is_sub_word(&ty) {
                        return Err(LangError::Codegen {
                            message: format!(
                                "sub-word compound assignment ({}) not yet implemented",
                                ty.display_name()
                            ),
                        });
                    }
                    self.func.instruction(&Instruction::LocalGet(idx));
                    self.emit_expr(value)?;
                    match op {
                        AssignOp::Add => self.emit_checked_add(&ty)?,
                        AssignOp::Sub => self.emit_checked_sub(&ty)?,
                        AssignOp::Mul => self.emit_checked_mul(&ty)?,
                        AssignOp::Div => self.emit_checked_div(&ty)?,
                        AssignOp::Rem => self.emit_checked_rem(&ty)?,
                        // Forward-compatibility for #[non_exhaustive].
                        // AssignOp::Assign is handled above; remaining
                        // future variants get an honest error.
                        #[allow(unreachable_patterns)]
                        _ => {
                            return Err(LangError::Codegen {
                                message: format!(
                                    "compound assignment operator {op:?} not yet implemented"
                                ),
                            })
                        }
                    }
                    self.func.instruction(&Instruction::LocalSet(idx));
                }
                Ok(())
            }
            // self.field assignment → storage write (P3·Step 6e)
            Expr::Member(receiver, field, _) => {
                if let Expr::Ident(name, _) = receiver.as_ref() {
                    if name == "self" {
                        if !matches!(op, AssignOp::Assign) {
                            return Err(LangError::Codegen {
                                message: "compound assignment to self.field not yet implemented"
                                    .into(),
                            });
                        }
                        return self.emit_storage_write(field, value);
                    }
                }
                Err(LangError::Codegen {
                    message: "assignment to non-self member not yet implemented".into(),
                })
            }
            _ => Err(LangError::Codegen {
                message: "non-local assignment (index) not yet implemented in codegen".into(),
            }),
        }
    }
}
