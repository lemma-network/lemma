//! Shared type-lowering helper for the Lem type checker — P3·Step 3f.
//!
//! Extracts the primitive/compound `Type → ResolvedType` mapping that was
//! previously duplicated between `Resolver::lower_type` (resolver.rs) and
//! `Inferer::lower_cast_target` (infer.rs).  Closes **P3-checker-4**.
//!
//! ## Design
//!
//! The two callers differ only in how they resolve `Type::Named` names:
//! - `Resolver::lower_type` uses the live scope stack (`self.lookup_type`).
//! - `Inferer::lower_cast_target` uses the flat `global_types` map.
//!
//! `lower_type_with` accepts two closures that inject the caller's strategy:
//! - `recurse`: how to lower a nested `Type` (enables recursive compound types).
//! - `resolve_named`: how to turn `(name, lowered_args)` into a `ResolvedType`.
//!
//! The 3f generic-instantiation lowering is the third caller that justifies
//! this extraction (AGENTS §2.1 — 3-concrete-cases threshold).

use super::types::ResolvedType;
use crate::parser::ast::Type;

/// Lower a syntactic [`Type`] to a [`ResolvedType`] using caller-supplied
/// name-resolution and recursion strategies.
///
/// # Parameters
///
/// - `ty`            — the syntactic type to lower.
/// - `recurse`       — closure that lowers a nested `Type` (for compound types).
/// - `resolve_named` — closure that resolves `(name, lowered_args)` to a
///   `ResolvedType`.  Returns `Unknown` for unresolvable names.
///
/// # Exhaustiveness
///
/// This function matches every `Type` variant exhaustively (no `_` arm) so
/// the compiler enforces that new `Type` variants added to the parser are
/// handled here.  Previously `lower_cast_target` had a `_ => Unknown` catch-all
/// that silently swallowed new variants — that hole is now closed.
pub(super) fn lower_type_with(
    ty: &Type,
    recurse: &dyn Fn(&Type) -> ResolvedType,
    resolve_named: &dyn Fn(&str, Vec<ResolvedType>) -> ResolvedType,
) -> ResolvedType {
    match ty {
        // ── Unsigned integers ──────────────────────────────────────────────
        Type::U8 => ResolvedType::U8,
        Type::U16 => ResolvedType::U16,
        Type::U32 => ResolvedType::U32,
        Type::U64 => ResolvedType::U64,
        Type::U128 => ResolvedType::U128,
        Type::U256 => ResolvedType::U256,
        // ── Signed integers ────────────────────────────────────────────────
        Type::I8 => ResolvedType::I8,
        Type::I16 => ResolvedType::I16,
        Type::I32 => ResolvedType::I32,
        Type::I64 => ResolvedType::I64,
        Type::I128 => ResolvedType::I128,
        Type::I256 => ResolvedType::I256,
        // ── Primitives ─────────────────────────────────────────────────────
        Type::Bool => ResolvedType::Bool,
        Type::StringTy => ResolvedType::StringTy,
        Type::CharTy => ResolvedType::CharTy,
        Type::AddressTy => ResolvedType::AddressTy,
        Type::HashTy => ResolvedType::HashTy,
        Type::Bytes => ResolvedType::Bytes,
        Type::BytesN(n) => ResolvedType::BytesN(*n),
        Type::Decimal(n) => ResolvedType::Decimal(*n),
        // ── Compound types ─────────────────────────────────────────────────
        Type::Array(inner) => ResolvedType::Array(Box::new(recurse(inner))),
        Type::FixedArray(inner, n) => ResolvedType::FixedArray(Box::new(recurse(inner)), *n),
        Type::Map(k, v) => ResolvedType::Map(Box::new(recurse(k)), Box::new(recurse(v))),
        Type::FastMap(k, v) => ResolvedType::FastMap(Box::new(recurse(k)), Box::new(recurse(v))),
        Type::Set(inner) => ResolvedType::Set(Box::new(recurse(inner))),
        Type::Option_(inner) => ResolvedType::Option_(Box::new(recurse(inner))),
        Type::Result_(ok, err) => {
            ResolvedType::Result_(Box::new(recurse(ok)), Box::new(recurse(err)))
        }
        Type::Tuple(elems) => ResolvedType::Tuple(elems.iter().map(recurse).collect()),
        Type::Fn(params, ret) => {
            ResolvedType::Fn(params.iter().map(recurse).collect(), Box::new(recurse(ret)))
        }
        // ── Named / generic ────────────────────────────────────────────────
        Type::Named(name, args) => {
            // `_` is the parser's inferred-type placeholder for untyped lambda
            // params.  It is NOT a user type — inferred in 3c.
            if name == "_" {
                return ResolvedType::Unknown;
            }
            let lowered_args: Vec<ResolvedType> = args.iter().map(recurse).collect();
            resolve_named(name, lowered_args)
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
