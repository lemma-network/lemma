//! Solidity AST → Lem IR mapper.
//!
//! Maps `solang_parser::pt` types to the Lem IR defined in [`crate::lem_ir`].
//!
//! ## Batch 3 scope
//!
//! Expression and statement mapping (`map_expr`, `map_stmt`, `map_body`).
//! Function bodies are now populated by calling `map_body` from `map_function_sig`.
//!
//! ## DRY note
//!
//! One canonical verb per concept (AGENTS §2.3):
//! - [`map_type`] — Solidity `Expression` type annotation → `LemType`
//! - [`map_sol_type`] — Solidity `pt::Type` enum → `LemType`
//! - [`map_expr`] — Solidity `pt::Expression` → `LemExpr`
//! - [`map_stmt`] — Solidity `pt::Statement` → `LemStmt`
//! - [`map_body`] — `&[pt::Statement]` → `Vec<LemStmt>`
//! - [`map_function_sig`] — `FunctionDefinition` → `LemFunction` (body populated)
//! - [`map_state_var`] — `VariableDefinition` → `Option<LemParam>`
//! - [`map_event`] — `EventDefinition` → `LemEvent`
//! - [`map_struct`] — `StructDefinition` → `LemStruct`
//! - [`map_enum`] — `EnumDefinition` → `LemEnum`
//! - [`map_contract`] — `ContractDefinition` → `LemContract` (entry point)

use std::collections::BTreeMap;

use solang_parser::pt;

use crate::{
    lem_ir::{
        BinOp, LemContract, LemEnum, LemEvent, LemEventField, LemExpr, LemFunction,
        LemFunctionKind, LemMutability, LemParam, LemStmt, LemStruct, LemType, LemVisibility,
        UnaryOp,
    },
    warnings::{TranspileWarning, WarningCollector},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Bit width of Solidity's default `uint` / `int` (no suffix).
const DEFAULT_INT_BITS: u16 = 256;

/// Known interface base names that map to Lem standard traits.
const ITOKEN_BASES: &[&str] = &["IERC20", "IERC20Metadata", "IToken"];
const OWNABLE_BASES: &[&str] = &["Ownable", "Ownable2Step"];
const PAUSABLE_BASES: &[&str] = &["Pausable"];
const ACCESS_CONTROL_BASES: &[&str] = &["AccessControl", "AccessControlEnumerable"];

/// Modifier names that map to Lem's built-in `Ownable` decorator.
const OWNABLE_MODIFIERS: &[&str] = &["onlyOwner"];
/// Modifier names that map to Lem's built-in `Pausable` decorator.
const PAUSABLE_MODIFIERS: &[&str] = &["whenNotPaused", "whenPaused"];
/// Modifier names that map to Lem's built-in `AccessControl` decorator.
const ACCESS_CONTROL_MODIFIERS: &[&str] = &["onlyRole"];

/// Solidity event parameter name that Lem renames to `amount` (IToken convention, spec §13).
const SOLIDITY_VALUE_PARAM: &str = "value";
const LEM_AMOUNT_PARAM: &str = "amount";
/// Events for which `value` → `amount` is applied (IToken spec §13).
/// Only Transfer and Approval carry a token amount named `value` in Solidity's IERC20.
/// Renaming unconditionally would corrupt other events (e.g. `event Bid(..., uint256 value)`).
const ITOKEN_VALUE_EVENTS: &[&str] = &["Transfer", "Approval"];

// ── Type mapping ──────────────────────────────────────────────────────────────

/// Map a Solidity `pt::Type` enum to a [`LemType`].
///
/// This is the single canonical type-mapping function. All other mapping
/// functions that need a type call this one (DRY, AGENTS §2.1).
///
/// ## Signed integer note
///
/// Solidity `int256` has no direct `LemType::I256` equivalent in the MVP IR.
/// Values wider than 128 bits are mapped to `I128` with a `Raw` comment in
/// the codegen. See `TODO` below.
// TODO: int256 → i256 not yet in LemType; tracked for post-MVP IR extension.
pub(crate) fn map_sol_type(ty: &pt::Type) -> LemType {
    match ty {
        // Unsigned integers — map bit width to the nearest Lem unsigned type.
        pt::Type::Uint(bits) => map_uint_bits(*bits),
        // Signed integers — map bit width to the nearest Lem signed type.
        // int256 → I128 for MVP (no I256 in LemType yet).
        pt::Type::Int(bits) => map_int_bits(*bits),
        pt::Type::Bool => LemType::Bool,
        pt::Type::String => LemType::Str,
        // Fixed-size byte arrays: bytes32 → FixedBytes(32).
        pt::Type::Bytes(n) => LemType::FixedBytes(*n as usize),
        // Dynamic byte array: bytes → Bytes.
        pt::Type::DynamicBytes => LemType::Bytes,
        // Both address and address payable map to Address (Lem has no payable distinction).
        pt::Type::Address | pt::Type::AddressPayable => LemType::Address,
        // mapping(K => V) — recursively map key and value types.
        pt::Type::Mapping { key, value, .. } => {
            let key_ty = map_type(key);
            let val_ty = map_type(value);
            LemType::Map(Box::new(key_ty), Box::new(val_ty))
        }
        // Function types and Rational have no clean Lem equivalent — use Named fallback.
        pt::Type::Function { .. } | pt::Type::Rational | pt::Type::Payable => {
            LemType::Named("/* unsupported type */".to_owned())
        }
    }
}

/// Map a Solidity type expression (as it appears in `VariableDefinition.ty`,
/// `EventParameter.ty`, etc.) to a [`LemType`].
///
/// Solidity type annotations are represented as `pt::Expression` nodes, not
/// bare `pt::Type` values. This function unwraps the expression layer.
pub(crate) fn map_type(expr: &pt::Expression) -> LemType {
    match expr {
        // Most common case: a primitive or mapping type.
        pt::Expression::Type(_, ty) => map_sol_type(ty),
        // Dynamic array: T[] — the size expression is None.
        pt::Expression::ArraySubscript(_, inner, None) => LemType::Array(Box::new(map_type(inner))),
        // Fixed array: T[N] — same Lem representation as dynamic for MVP.
        pt::Expression::ArraySubscript(_, inner, Some(_size)) => {
            LemType::Array(Box::new(map_type(inner)))
        }
        // User-defined type reference: struct name, enum name, contract name.
        pt::Expression::Variable(ident) => LemType::Named(ident.name.clone()),
        // Qualified name (e.g. IERC20.Transfer) — use the last segment.
        pt::Expression::MemberAccess(_, _, ident) => LemType::Named(ident.name.clone()),
        // Tuple type: (T, U) — 2-element only; >2 falls to Named fallback.
        pt::Expression::List(_, params) => {
            let types: Vec<LemType> = params
                .iter()
                .filter_map(|(_, param)| param.as_ref().map(|p| map_type(&p.ty)))
                .collect();
            match types.len() {
                2 => LemType::Tuple(Box::new(types[0].clone()), Box::new(types[1].clone())),
                _ => LemType::Named("/* tuple */".to_owned()),
            }
        }
        // Anything else — emit a Named fallback so transpilation continues.
        _ => LemType::Named("/* unknown type */".to_owned()),
    }
}

/// Map a Solidity unsigned integer bit width to the smallest fitting [`LemType`].
fn map_uint_bits(bits: u16) -> LemType {
    // Solidity uint (no suffix) = uint256.
    let effective = if bits == 0 { DEFAULT_INT_BITS } else { bits };
    match effective {
        1..=8 => LemType::U8,
        9..=16 => LemType::U16,
        17..=32 => LemType::U32,
        33..=64 => LemType::U64,
        65..=128 => LemType::U128,
        _ => LemType::U256,
    }
}

/// Map a Solidity signed integer bit width to the smallest fitting [`LemType`].
///
/// Solidity `int256` maps to `I128` for MVP — no `I256` in `LemType` yet.
// TODO: int256 → i256 not yet in LemType; tracked for post-MVP IR extension.
fn map_int_bits(bits: u16) -> LemType {
    let effective = if bits == 0 { DEFAULT_INT_BITS } else { bits };
    match effective {
        1..=8 => LemType::I8,
        9..=16 => LemType::I16,
        17..=32 => LemType::I32,
        33..=64 => LemType::I64,
        _ => LemType::I128,
    }
}

// ── Name helpers ──────────────────────────────────────────────────────────────

/// Strip the leading `_` from a Solidity private field name.
///
/// Lem convention: no `_` prefix on identifiers (AGENTS §10).
/// `_balances` → `balances`, `_totalSupply` → `totalSupply`.
/// Names without a leading `_` are returned unchanged.
fn strip_leading_underscore(name: &str) -> &str {
    name.strip_prefix('_').unwrap_or(name)
}

/// Detect whether a base name refers to an interface (starts with uppercase `I`
/// followed by another uppercase letter — e.g. `IERC20`, `IToken`).
fn is_interface_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some('I'), Some(c)) if c.is_uppercase()
    )
}

// ── Visibility / Mutability mapping ──────────────────────────────────────────

/// Map Solidity function visibility to [`LemVisibility`].
///
/// `public` and `external` → `Public`; `private` and `internal` → `Private`.
/// Missing visibility defaults to `Private` (safe default).
fn map_visibility(attrs: &[pt::FunctionAttribute]) -> LemVisibility {
    attrs
        .iter()
        .find_map(|attr| match attr {
            pt::FunctionAttribute::Visibility(vis) => Some(match vis {
                pt::Visibility::Public(_) | pt::Visibility::External(_) => LemVisibility::Public,
                pt::Visibility::Private(_) | pt::Visibility::Internal(_) => LemVisibility::Private,
            }),
            _ => None,
        })
        .unwrap_or(LemVisibility::Private)
}

/// Map Solidity function mutability to [`LemMutability`].
///
/// Missing mutability defaults to `Mutable` (may read and write state).
fn map_mutability(attrs: &[pt::FunctionAttribute]) -> LemMutability {
    attrs
        .iter()
        .find_map(|attr| match attr {
            pt::FunctionAttribute::Mutability(m) => Some(match m {
                pt::Mutability::View(_) | pt::Mutability::Constant(_) => LemMutability::View,
                pt::Mutability::Pure(_) => LemMutability::Pure,
                pt::Mutability::Payable(_) => LemMutability::Payable,
            }),
            _ => None,
        })
        .unwrap_or(LemMutability::Mutable)
}

// ── State variable mapping ────────────────────────────────────────────────────

/// Map a Solidity state variable definition to a [`LemParam`] for `LemContract.state`.
///
/// Returns `None` for anonymous variables (parse errors) — these are skipped.
/// `constant` and `immutable` variables are included in state (codegen handles them).
pub(crate) fn map_state_var(def: &pt::VariableDefinition) -> Option<LemParam> {
    let raw_name = def.name.as_ref()?.name.as_str();
    let name = strip_leading_underscore(raw_name).to_owned();
    let ty = map_type(&def.ty);
    Some(LemParam { name, ty })
}

// ── Function signature mapping ────────────────────────────────────────────────

/// Map a Solidity function definition to a [`LemFunction`] with a populated body.
///
/// Returns `None` for:
/// - `FunctionTy::Modifier` — Lem has no modifier bodies; decorator names are
///   captured in `LemFunction::decorators` instead.
///
/// ## Overloading (W002)
///
/// Lem enforces one-name-one-fn. When a name is seen more than once, the
/// second occurrence becomes `{name}_2`, the third `{name}_3`, etc.
/// A [`TranspileWarning::function_overloading`] is emitted for each rename.
///
/// `seen_names` must be a [`BTreeMap`] (deterministic iteration, AGENTS §7.1).
pub(crate) fn map_function_sig(
    def: &pt::FunctionDefinition,
    seen_names: &mut BTreeMap<String, usize>,
    warnings: &mut WarningCollector,
) -> Option<LemFunction> {
    // Skip modifier definitions — their bodies have no Lem equivalent.
    if matches!(def.ty, pt::FunctionTy::Modifier) {
        return None;
    }

    // Determine kind and base name.
    let (kind, base_name) = match def.ty {
        pt::FunctionTy::Constructor => (LemFunctionKind::Constructor, "init".to_owned()),
        pt::FunctionTy::Fallback => (LemFunctionKind::Method, "fallback".to_owned()),
        pt::FunctionTy::Receive => (LemFunctionKind::Method, "receive".to_owned()),
        pt::FunctionTy::Function | pt::FunctionTy::Modifier => {
            let raw = def
                .name
                .as_ref()
                .map(|id| id.name.as_str())
                .unwrap_or("unknown");
            let name = strip_leading_underscore(raw).to_owned();
            (LemFunctionKind::Method, name)
        }
    };

    // Apply W002 overload renaming.
    let name = apply_overload_rename(&base_name, &def.loc, seen_names, warnings);

    // Map parameters.
    let params = map_param_list(&def.params);

    // Map return type.
    let returns = map_return_types(&def.returns);

    // Map visibility and mutability.
    let visibility = map_visibility(&def.attributes);
    let mutability = map_mutability(&def.attributes);

    // Collect decorator names from modifier invocations.
    let decorators = collect_decorators(&def.attributes);

    // Map the function body (Batch 3).
    let body = def
        .body
        .as_ref()
        .map(|block| {
            if let pt::Statement::Block { statements, .. } = block {
                map_body(statements, warnings)
            } else {
                vec![map_stmt(block, warnings)]
            }
        })
        .unwrap_or_default();

    Some(LemFunction {
        name,
        params,
        returns,
        visibility,
        mutability,
        decorators,
        body,
        kind,
    })
}

/// Apply W002 overload renaming and return the final Lem function name.
///
/// First occurrence: name unchanged.
/// Second: `{name}_2`, third: `{name}_3`, etc.
fn apply_overload_rename(
    base_name: &str,
    loc: &pt::Loc,
    seen_names: &mut BTreeMap<String, usize>,
    warnings: &mut WarningCollector,
) -> String {
    let count = seen_names.entry(base_name.to_owned()).or_insert(0);
    *count += 1;
    if *count == 1 {
        base_name.to_owned()
    } else {
        let renamed = format!("{}_{}", base_name, count);
        warnings.push(TranspileWarning::function_overloading(
            loc, base_name, &renamed,
        ));
        renamed
    }
}

/// Map a Solidity `ParameterList` to a `Vec<LemParam>`.
///
/// Anonymous parameters get positional names: `param0`, `param1`, etc.
fn map_param_list(params: &pt::ParameterList) -> Vec<LemParam> {
    params
        .iter()
        .enumerate()
        .filter_map(|(i, (_, param))| {
            let p = param.as_ref()?;
            let name = p
                .name
                .as_ref()
                .map(|id| strip_leading_underscore(&id.name).to_owned())
                .unwrap_or_else(|| format!("param{i}"));
            let ty = map_type(&p.ty);
            Some(LemParam { name, ty })
        })
        .collect()
}

/// Map Solidity return types to a single optional [`LemType`].
///
/// - No returns → `None`
/// - Single return → `Some(ty)`
/// - Multiple returns → `Some(LemType::Tuple(...))` for 2-element; `Some(LemType::Named("/* tuple */"))` for >2
fn map_return_types(returns: &pt::ParameterList) -> Option<LemType> {
    let types: Vec<LemType> = returns
        .iter()
        .filter_map(|(_, param)| param.as_ref().map(|p| map_type(&p.ty)))
        .collect();

    match types.len() {
        0 => None,
        1 => Some(types.into_iter().next().expect("len checked above")),
        2 => {
            let mut it = types.into_iter();
            let a = it.next().expect("len checked above");
            let b = it.next().expect("len checked above");
            Some(LemType::Tuple(Box::new(a), Box::new(b)))
        }
        _ => Some(LemType::Named("/* multi-return tuple */".to_owned())),
    }
}

/// Collect decorator names from function attributes.
///
/// Modifier invocations (`BaseOrModifier`) become decorator strings.
/// Known modifiers (`onlyOwner`, `whenNotPaused`, etc.) are included as-is.
/// `onlyRole(X)` → `"onlyRole"` (argument dropped for MVP).
fn collect_decorators(attrs: &[pt::FunctionAttribute]) -> Vec<String> {
    attrs
        .iter()
        .filter_map(|attr| match attr {
            pt::FunctionAttribute::BaseOrModifier(_, base) => {
                // The modifier name is the last segment of the IdentifierPath.
                base.name.identifiers.last().map(|id| id.name.clone())
            }
            _ => None,
        })
        .collect()
}

// ── Event mapping ─────────────────────────────────────────────────────────────

/// Map a Solidity event definition to a [`LemEvent`].
///
/// Anonymous parameters get positional names: `param0`, `param1`, etc.
/// The Solidity parameter name `value` is renamed to `amount` (IToken convention, spec §13).
pub(crate) fn map_event(def: &pt::EventDefinition) -> LemEvent {
    let name = def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_default();

    let fields = def
        .fields
        .iter()
        .enumerate()
        .map(|(i, field)| {
            let raw_name = field.name.as_ref().map(|id| id.name.as_str()).unwrap_or("");
            // Rename `value` → `amount` ONLY for IToken standard events (Transfer/Approval).
            // Other events with a `value` field (e.g. `event Bid(address, uint256 value)`)
            // keep their field name unchanged — DB-A59 scope (see decisions-log).
            let name = if raw_name == SOLIDITY_VALUE_PARAM
                && ITOKEN_VALUE_EVENTS.contains(&name.as_str())
            {
                LEM_AMOUNT_PARAM.to_owned()
            } else if raw_name.is_empty() {
                format!("param{i}")
            } else {
                raw_name.to_owned()
            };
            let ty = map_type(&field.ty);
            LemEventField {
                name,
                ty,
                indexed: field.indexed,
            }
        })
        .collect();

    LemEvent { name, fields }
}

// ── Struct mapping ────────────────────────────────────────────────────────────

/// Map a Solidity struct definition to a [`LemStruct`].
///
/// Struct fields are `pt::VariableDeclaration` (no attrs, no initializer).
pub(crate) fn map_struct(def: &pt::StructDefinition) -> LemStruct {
    let name = def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_default();

    let fields = def
        .fields
        .iter()
        .filter_map(|field| {
            let field_name = field.name.as_ref()?.name.clone();
            let ty = map_type(&field.ty);
            Some(LemParam {
                name: field_name,
                ty,
            })
        })
        .collect();

    LemStruct { name, fields }
}

// ── Enum mapping ──────────────────────────────────────────────────────────────

/// Map a Solidity enum definition to a [`LemEnum`].
///
/// `None` values in `def.values` are parse-error sentinels — they are skipped.
pub(crate) fn map_enum(def: &pt::EnumDefinition) -> LemEnum {
    let name = def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_default();

    let variants = def
        .values
        .iter()
        .filter_map(|v| v.as_ref().map(|id| id.name.clone()))
        .collect();

    LemEnum { name, variants }
}

// ── Inheritance / base mapping ────────────────────────────────────────────────

/// Classify a base name and update the contract's trait flags.
///
/// Mutates `contract` in place — sets `uses_itoken`, `uses_ownable`,
/// `uses_pausable`, `uses_access_control`, and pushes to `extends`/`uses`.
fn apply_base(base: &pt::Base, contract: &mut LemContract) {
    let name = base
        .name
        .identifiers
        .last()
        .map(|id| id.name.as_str())
        .unwrap_or("");

    if ITOKEN_BASES.contains(&name) {
        contract.uses_itoken = true;
    } else if OWNABLE_BASES.contains(&name) {
        contract.uses_ownable = true;
    } else if PAUSABLE_BASES.contains(&name) {
        contract.uses_pausable = true;
    } else if ACCESS_CONTROL_BASES.contains(&name) {
        contract.uses_access_control = true;
    } else if is_interface_name(name) {
        // Unknown interface (starts with uppercase I + uppercase) → uses list.
        contract.uses.push(name.to_owned());
    } else {
        // Concrete base contract → extends list.
        contract.extends.push(name.to_owned());
    }
}

/// Scan function decorators and update contract trait flags.
///
/// If any function uses `onlyOwner`, the contract uses Ownable.
/// If any function uses `whenNotPaused`/`whenPaused`, it uses Pausable.
/// If any function uses `onlyRole`, it uses AccessControl.
fn apply_decorator_flags(decorators: &[String], contract: &mut LemContract) {
    for dec in decorators {
        let name = dec.as_str();
        if OWNABLE_MODIFIERS.contains(&name) {
            contract.uses_ownable = true;
        } else if PAUSABLE_MODIFIERS.contains(&name) {
            contract.uses_pausable = true;
        } else if ACCESS_CONTROL_MODIFIERS.contains(&name) {
            contract.uses_access_control = true;
        }
    }
}

// ── Expression mapping ────────────────────────────────────────────────────────

/// Map a Solidity expression to a [`LemExpr`].
///
/// Unmappable expressions degrade to [`LemExpr::Raw`] — transpilation never
/// aborts on an unsupported expression form (AGENTS §12.2).
pub(crate) fn map_expr(expr: &pt::Expression, warnings: &mut WarningCollector) -> LemExpr {
    match expr {
        // ── Literals ──────────────────────────────────────────────────────────
        pt::Expression::NumberLiteral(_, value_str, _exp_str, _unit) => {
            // Parse the decimal string; fall back to Raw on overflow (e.g. very large hex).
            match value_str.parse::<u128>() {
                Ok(n) => LemExpr::IntLit(n),
                // Value exceeds u128 (e.g. type(uint256).max) — emit Raw.
                Err(_) => LemExpr::Raw(format!("/* {value_str} */")),
            }
        }
        pt::Expression::BoolLiteral(_, b) => LemExpr::BoolLit(*b),
        pt::Expression::StringLiteral(parts) => {
            // Take the first string part (multi-part string literals are rare in ERC-20).
            let s = parts.first().map(|p| p.string.clone()).unwrap_or_default();
            LemExpr::StringLit(s)
        }
        pt::Expression::HexLiteral(parts) => {
            // Decode hex bytes from all parts concatenated.
            let hex_str: String = parts.iter().map(|p| p.hex.as_str()).collect();
            let bytes = decode_hex_literal(&hex_str);
            LemExpr::BytesLit(bytes)
        }

        // ── References ────────────────────────────────────────────────────────
        pt::Expression::Variable(id) => LemExpr::Ident(id.name.clone()),
        pt::Expression::MemberAccess(_, inner, id) => {
            LemExpr::MemberAccess(Box::new(map_expr(inner, warnings)), id.name.clone())
        }
        pt::Expression::ArraySubscript(_, inner, Some(idx)) => LemExpr::IndexAccess(
            Box::new(map_expr(inner, warnings)),
            Box::new(map_expr(idx, warnings)),
        ),
        // Index access with no subscript (e.g. `arr[]`) — degrade to Raw.
        pt::Expression::ArraySubscript(_, inner, None) => {
            LemExpr::Raw(format!("/* {}[] */", expr_to_raw_hint(inner)))
        }

        // ── Function calls ────────────────────────────────────────────────────
        pt::Expression::FunctionCall(_, func, args) => map_function_call_expr(func, args, warnings),
        // Named function call: f({a: x, b: y}) — degrade to Raw for MVP.
        pt::Expression::NamedFunctionCall(_, func, _named_args) => {
            LemExpr::Raw(format!("/* named call: {} */", expr_to_raw_hint(func)))
        }
        // f{value: x}(args) — degrade to Raw for MVP.
        pt::Expression::FunctionCallBlock(_, func, _block) => {
            LemExpr::Raw(format!("/* call-block: {} */", expr_to_raw_hint(func)))
        }

        // ── Arithmetic binary ops ─────────────────────────────────────────────
        pt::Expression::Add(_, l, r) => map_binop(BinOp::Add, l, r, warnings),
        pt::Expression::Subtract(_, l, r) => map_binop(BinOp::Sub, l, r, warnings),
        pt::Expression::Multiply(_, l, r) => map_binop(BinOp::Mul, l, r, warnings),
        pt::Expression::Divide(_, l, r) => map_binop(BinOp::Div, l, r, warnings),
        pt::Expression::Modulo(_, l, r) => map_binop(BinOp::Rem, l, r, warnings),

        // ── Comparison ops ────────────────────────────────────────────────────
        pt::Expression::Equal(_, l, r) => map_binop(BinOp::Eq, l, r, warnings),
        pt::Expression::NotEqual(_, l, r) => map_binop(BinOp::Ne, l, r, warnings),
        pt::Expression::Less(_, l, r) => map_binop(BinOp::Lt, l, r, warnings),
        pt::Expression::LessEqual(_, l, r) => map_binop(BinOp::Le, l, r, warnings),
        pt::Expression::More(_, l, r) => map_binop(BinOp::Gt, l, r, warnings),
        pt::Expression::MoreEqual(_, l, r) => map_binop(BinOp::Ge, l, r, warnings),

        // ── Logical ops ───────────────────────────────────────────────────────
        pt::Expression::And(_, l, r) => map_binop(BinOp::And, l, r, warnings),
        pt::Expression::Or(_, l, r) => map_binop(BinOp::Or, l, r, warnings),
        pt::Expression::Not(_, e) => LemExpr::UnaryOp {
            op: UnaryOp::Not,
            expr: Box::new(map_expr(e, warnings)),
        },
        pt::Expression::Negate(_, e) => LemExpr::UnaryOp {
            op: UnaryOp::Neg,
            expr: Box::new(map_expr(e, warnings)),
        },

        // ── Bitwise ops ───────────────────────────────────────────────────────
        pt::Expression::BitwiseAnd(_, l, r) => map_binop(BinOp::BitAnd, l, r, warnings),
        pt::Expression::BitwiseOr(_, l, r) => map_binop(BinOp::BitOr, l, r, warnings),
        pt::Expression::BitwiseXor(_, l, r) => map_binop(BinOp::BitXor, l, r, warnings),
        pt::Expression::ShiftLeft(_, l, r) => map_binop(BinOp::Shl, l, r, warnings),
        pt::Expression::ShiftRight(_, l, r) => map_binop(BinOp::Shr, l, r, warnings),

        // ── Compound assignment ops — expand to Assign + BinOp ───────────────
        pt::Expression::AssignAdd(_, l, r) => expand_assign_op(BinOp::Add, l, r, warnings),
        pt::Expression::AssignSubtract(_, l, r) => expand_assign_op(BinOp::Sub, l, r, warnings),
        pt::Expression::AssignMultiply(_, l, r) => expand_assign_op(BinOp::Mul, l, r, warnings),
        pt::Expression::AssignDivide(_, l, r) => expand_assign_op(BinOp::Div, l, r, warnings),
        pt::Expression::AssignModulo(_, l, r) => expand_assign_op(BinOp::Rem, l, r, warnings),
        pt::Expression::AssignAnd(_, l, r) => expand_assign_op(BinOp::BitAnd, l, r, warnings),
        pt::Expression::AssignOr(_, l, r) => expand_assign_op(BinOp::BitOr, l, r, warnings),
        pt::Expression::AssignXor(_, l, r) => expand_assign_op(BinOp::BitXor, l, r, warnings),
        pt::Expression::AssignShiftLeft(_, l, r) => expand_assign_op(BinOp::Shl, l, r, warnings),
        pt::Expression::AssignShiftRight(_, l, r) => expand_assign_op(BinOp::Shr, l, r, warnings),

        // ── Increment / decrement — expand to Assign + BinOp(1) ──────────────
        pt::Expression::PreIncrement(_, e) | pt::Expression::PostIncrement(_, e) => {
            // i++ / ++i → i + 1 (as expression; stmt context wraps in Assign)
            LemExpr::BinaryOp {
                op: BinOp::Add,
                left: Box::new(map_expr(e, warnings)),
                right: Box::new(LemExpr::IntLit(1)),
            }
        }
        pt::Expression::PreDecrement(_, e) | pt::Expression::PostDecrement(_, e) => {
            LemExpr::BinaryOp {
                op: BinOp::Sub,
                left: Box::new(map_expr(e, warnings)),
                right: Box::new(LemExpr::IntLit(1)),
            }
        }

        // ── Ternary ───────────────────────────────────────────────────────────
        pt::Expression::ConditionalOperator(_, cond, then_e, else_e) => LemExpr::Ternary {
            cond: Box::new(map_expr(cond, warnings)),
            then_expr: Box::new(map_expr(then_e, warnings)),
            else_expr: Box::new(map_expr(else_e, warnings)),
        },

        // ── Assignment (as expression) ────────────────────────────────────────
        // Solidity allows `a = b` as an expression; in Lem it's a statement.
        // Represent as Raw — the stmt mapper handles the common `Expression(Assign)` case.
        pt::Expression::Assign(_, l, r) => LemExpr::Raw(format!(
            "/* assign: {} = {} */",
            expr_to_raw_hint(l),
            expr_to_raw_hint(r)
        )),

        // ── Parenthesized expression — transparent ────────────────────────────
        pt::Expression::Parenthesis(_, inner) => map_expr(inner, warnings),

        // ── Address literal (0x... checksummed address) ───────────────────────
        pt::Expression::AddressLiteral(_, addr) => LemExpr::AddressLit(addr.clone()),

        // ── `new T(...)` — no Lem equivalent for MVP ─────────────────────────
        pt::Expression::New(_, _) => LemExpr::Raw("/* new — not supported in MVP */".to_owned()),

        // ── Bare type expression (in cast context) ────────────────────────────
        pt::Expression::Type(_, _) => LemExpr::Raw("/* type expr */".to_owned()),

        // ── Anything else — degrade gracefully ───────────────────────────────
        _ => LemExpr::Raw(format!(
            "/* unsupported expr: {:?} */",
            expr_kind_name(expr)
        )),
    }
}

/// Map a binary operation: build `LemExpr::BinaryOp` from two sub-expressions.
fn map_binop(
    op: BinOp,
    left: &pt::Expression,
    right: &pt::Expression,
    warnings: &mut WarningCollector,
) -> LemExpr {
    LemExpr::BinaryOp {
        op,
        left: Box::new(map_expr(left, warnings)),
        right: Box::new(map_expr(right, warnings)),
    }
}

/// Expand a compound assignment (`a += b`) into `a = a + b` as a `LemExpr`.
///
/// This is used when the compound assignment appears in expression position.
/// The statement mapper handles the common `Expression(AssignAdd(...))` case
/// by calling `map_expr` and wrapping in `LemStmt::Assign`.
fn expand_assign_op(
    op: BinOp,
    left: &pt::Expression,
    right: &pt::Expression,
    warnings: &mut WarningCollector,
) -> LemExpr {
    // a op= b → a op b (the Assign wrapper is added by the stmt mapper)
    LemExpr::BinaryOp {
        op,
        left: Box::new(map_expr(left, warnings)),
        right: Box::new(map_expr(right, warnings)),
    }
}

/// Map a Solidity function call expression.
///
/// In solang-parser 0.3.5, type casts (`address(0)`, `uint256(x)`) are
/// represented as `FunctionCall(_, Type(_, ty), args)` — not a separate `Cast`
/// variant. This function handles both casts and regular calls.
///
/// Special cases:
/// - `address(0)` → `AddressLit("Address.zero")`
/// - `address(x)` / `uint256(x)` → `Cast { expr: x, ty: ... }`
/// - `require(cond, "msg")` → `Call { func: Ident("assert"), args: [cond, msg] }`
/// - `revert("msg")` → `Call { func: Ident("revert"), args: [msg] }`
/// - General calls → `Call { func: map_expr(func), args: map_expr(args) }`
fn map_function_call_expr(
    func: &pt::Expression,
    args: &[pt::Expression],
    warnings: &mut WarningCollector,
) -> LemExpr {
    // ── Type cast: FunctionCall(_, Type(_, ty), [inner]) ─────────────────────
    // In solang-parser 0.3.5, `address(0)` and `uint256(x)` parse as FunctionCall
    // with a Type expression as the function (not a separate Cast variant).
    if let pt::Expression::Type(_, ty) = func {
        if let Some(inner) = args.first() {
            // Special case: `address(0)` → AddressLit("Address.zero").
            if matches!(ty, pt::Type::Address | pt::Type::AddressPayable) {
                if let pt::Expression::NumberLiteral(_, val, _, _) = inner {
                    if val == "0" {
                        return LemExpr::AddressLit("Address.zero".to_owned());
                    }
                }
            }
            // General type cast: `uint256(x)` → Cast { expr: x, ty: U256 }.
            let lem_ty = map_sol_type(ty);
            return LemExpr::Cast {
                expr: Box::new(map_expr(inner, warnings)),
                ty: lem_ty,
            };
        }
    }

    // ── Named built-ins ───────────────────────────────────────────────────────
    if let pt::Expression::Variable(id) = func {
        // `require(cond, "msg")` → assert call in Lem.
        if id.name == "require" {
            let cond = args
                .first()
                .map(|a| map_expr(a, warnings))
                .unwrap_or(LemExpr::BoolLit(true));
            let msg = args
                .get(1)
                .and_then(extract_string_literal)
                .unwrap_or_else(|| "require failed".to_owned());
            return LemExpr::Call {
                func: Box::new(LemExpr::Ident("assert".to_owned())),
                args: vec![cond, LemExpr::StringLit(msg)],
            };
        }
        if id.name == "revert" {
            let msg = args
                .first()
                .and_then(extract_string_literal)
                .unwrap_or_else(|| "revert".to_owned());
            return LemExpr::Call {
                func: Box::new(LemExpr::Ident("revert".to_owned())),
                args: vec![LemExpr::StringLit(msg)],
            };
        }
    }

    // ── General call ──────────────────────────────────────────────────────────
    let mapped_func = map_expr(func, warnings);
    let mapped_args: Vec<LemExpr> = args.iter().map(|a| map_expr(a, warnings)).collect();
    LemExpr::Call {
        func: Box::new(mapped_func),
        args: mapped_args,
    }
}

/// Extract a string literal value from an expression, if it is one.
fn extract_string_literal(expr: &pt::Expression) -> Option<String> {
    if let pt::Expression::StringLiteral(parts) = expr {
        parts.first().map(|p| p.string.clone())
    } else {
        None
    }
}

/// Decode a hex literal string (e.g. `"deadbeef"`) into bytes.
///
/// Strips any `0x` prefix and decodes pairs of hex digits.
/// Odd-length or invalid hex falls back to an empty byte vector.
fn decode_hex_literal(hex: &str) -> Vec<u8> {
    let stripped = hex.strip_prefix("0x").unwrap_or(hex);
    // Pad to even length if needed.
    let padded: String = if stripped.len() % 2 != 0 {
        format!("0{stripped}")
    } else {
        stripped.to_owned()
    };
    padded
        .as_bytes()
        .chunks(2)
        .filter_map(|chunk| {
            let s = std::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(s, 16).ok()
        })
        .collect()
}

/// Return a short human-readable hint for an expression (for Raw fallback messages).
///
/// Does not recurse — just names the variant.
fn expr_to_raw_hint(expr: &pt::Expression) -> &'static str {
    expr_kind_name(expr)
}

/// Return the variant name of a `pt::Expression` for diagnostic messages.
fn expr_kind_name(expr: &pt::Expression) -> &'static str {
    match expr {
        pt::Expression::Variable(_) => "Variable",
        pt::Expression::NumberLiteral(..) => "NumberLiteral",
        pt::Expression::BoolLiteral(..) => "BoolLiteral",
        pt::Expression::StringLiteral(_) => "StringLiteral",
        pt::Expression::HexLiteral(_) => "HexLiteral",
        pt::Expression::MemberAccess(..) => "MemberAccess",
        pt::Expression::ArraySubscript(..) => "ArraySubscript",
        pt::Expression::FunctionCall(..) => "FunctionCall",
        pt::Expression::Add(..) => "Add",
        pt::Expression::Subtract(..) => "Subtract",
        pt::Expression::Multiply(..) => "Multiply",
        pt::Expression::Divide(..) => "Divide",
        pt::Expression::Modulo(..) => "Modulo",
        pt::Expression::Equal(..) => "Equal",
        pt::Expression::NotEqual(..) => "NotEqual",
        pt::Expression::Less(..) => "Less",
        pt::Expression::LessEqual(..) => "LessEqual",
        pt::Expression::More(..) => "More",
        pt::Expression::MoreEqual(..) => "MoreEqual",
        pt::Expression::And(..) => "And",
        pt::Expression::Or(..) => "Or",
        pt::Expression::Not(..) => "Not",
        pt::Expression::Negate(..) => "Negate",
        pt::Expression::BitwiseAnd(..) => "BitwiseAnd",
        pt::Expression::BitwiseOr(..) => "BitwiseOr",
        pt::Expression::BitwiseXor(..) => "BitwiseXor",
        pt::Expression::ShiftLeft(..) => "ShiftLeft",
        pt::Expression::ShiftRight(..) => "ShiftRight",
        pt::Expression::Assign(..) => "Assign",
        pt::Expression::AssignAdd(..) => "AssignAdd",
        pt::Expression::AssignSubtract(..) => "AssignSubtract",
        pt::Expression::AssignMultiply(..) => "AssignMultiply",
        pt::Expression::AssignDivide(..) => "AssignDivide",
        pt::Expression::AssignModulo(..) => "AssignModulo",
        pt::Expression::ConditionalOperator(..) => "ConditionalOperator",
        pt::Expression::New(..) => "New",
        pt::Expression::Type(..) => "Type",
        pt::Expression::PreIncrement(..) => "PreIncrement",
        pt::Expression::PostIncrement(..) => "PostIncrement",
        pt::Expression::PreDecrement(..) => "PreDecrement",
        pt::Expression::PostDecrement(..) => "PostDecrement",
        _ => "Unknown",
    }
}

// ── Statement mapping ─────────────────────────────────────────────────────────

/// Map a slice of Solidity statements to a `Vec<LemStmt>`.
///
/// This is the canonical entry point for mapping function bodies.
pub(crate) fn map_body(stmts: &[pt::Statement], warnings: &mut WarningCollector) -> Vec<LemStmt> {
    stmts.iter().map(|s| map_stmt(s, warnings)).collect()
}

/// Map a single Solidity statement to a [`LemStmt`].
///
/// Unmappable statements degrade to [`LemStmt::Raw`] — transpilation never
/// aborts on an unsupported statement form (AGENTS §12.2).
pub(crate) fn map_stmt(stmt: &pt::Statement, warnings: &mut WarningCollector) -> LemStmt {
    match stmt {
        // ── Block ─────────────────────────────────────────────────────────────
        // Normal block: flatten into the parent body.
        // Unchecked block: emit W003 then treat as normal (Lem always checks).
        pt::Statement::Block {
            loc,
            unchecked,
            statements,
        } => {
            if *unchecked {
                // W003: unchecked arithmetic block treated as normal.
                warnings.push(TranspileWarning::unchecked_block(loc));
            }
            // A block with multiple statements is represented as a single Raw
            // only if it's the top-level call; normally map_body flattens.
            // When map_stmt is called on a Block directly (e.g. from map_stmt_to_vec),
            // we wrap the inner statements in a Raw comment if there's more than one,
            // or return the single statement directly.
            let inner = map_body(statements, warnings);
            match inner.len() {
                0 => LemStmt::Raw("/* empty block */".to_owned()),
                1 => inner.into_iter().next().expect("len checked above"),
                _ => {
                    // Multiple statements in a nested block — wrap in a Raw block comment.
                    // The codegen will emit these as a scoped block.
                    LemStmt::Raw(format!("/* block: {} stmts */", statements.len()))
                }
            }
        }

        // ── Return ────────────────────────────────────────────────────────────
        pt::Statement::Return(_, expr_opt) => {
            LemStmt::Return(expr_opt.as_ref().map(|e| map_expr(e, warnings)))
        }

        // ── Variable definition ───────────────────────────────────────────────
        pt::Statement::VariableDefinition(_, decl, init_opt) => {
            let name = decl
                .name
                .as_ref()
                .map(|id| strip_leading_underscore(&id.name).to_owned())
                .unwrap_or_else(|| "unnamed".to_owned());
            let ty = Some(map_type(&decl.ty));
            let value = init_opt
                .as_ref()
                .map(|e| map_expr(e, warnings))
                .unwrap_or(LemExpr::Raw("// uninitialized".to_owned()));
            LemStmt::Let { name, ty, value }
        }

        // ── Expression statement ──────────────────────────────────────────────
        pt::Statement::Expression(_, expr) => map_expr_stmt(expr, warnings),

        // ── If / else ─────────────────────────────────────────────────────────
        pt::Statement::If(_, cond, then_stmt, else_opt) => {
            let cond_ir = map_expr(cond, warnings);
            let then_body = map_stmt_to_vec(then_stmt, warnings);
            let else_body = else_opt.as_ref().map(|e| map_stmt_to_vec(e, warnings));
            LemStmt::If {
                cond: cond_ir,
                then_body,
                else_body,
            }
        }

        // ── While ─────────────────────────────────────────────────────────────
        pt::Statement::While(_, cond, body) => LemStmt::While {
            cond: map_expr(cond, warnings),
            body: map_stmt_to_vec(body, warnings),
        },

        // ── Do-while — map as while (semantics differ on first iteration) ─────
        pt::Statement::DoWhile(_, body, cond) => LemStmt::While {
            cond: map_expr(cond, warnings),
            body: map_stmt_to_vec(body, warnings),
        },

        // ── For ───────────────────────────────────────────────────────────────
        pt::Statement::For(_, init_opt, cond_opt, update_opt, body_opt) => {
            let init = init_opt.as_ref().map(|s| Box::new(map_stmt(s, warnings)));
            let cond = cond_opt.as_ref().map(|e| map_expr(e, warnings));
            // For-loop update is an Expression in solang-parser, not a Statement.
            let update = update_opt
                .as_ref()
                .map(|e| Box::new(LemStmt::Expr(map_expr(e, warnings))));
            let body = body_opt
                .as_ref()
                .map(|s| map_stmt_to_vec(s, warnings))
                .unwrap_or_default();
            LemStmt::For {
                init,
                cond,
                update,
                body,
            }
        }

        // ── Break / Continue ──────────────────────────────────────────────────
        pt::Statement::Break(_) => LemStmt::Break,
        pt::Statement::Continue(_) => LemStmt::Continue,

        // ── Emit ──────────────────────────────────────────────────────────────
        pt::Statement::Emit(_, call_expr) => map_emit_stmt(call_expr, warnings),

        // ── Revert ────────────────────────────────────────────────────────────
        pt::Statement::Revert(_, name_opt, args) => {
            let msg = name_opt
                .as_ref()
                .and_then(|path| path.identifiers.last())
                .map(|id| id.name.clone())
                .unwrap_or_else(|| "revert".to_owned());
            let mapped_args: Vec<LemExpr> = args.iter().map(|a| map_expr(a, warnings)).collect();
            let mut call_args = vec![LemExpr::StringLit(msg)];
            call_args.extend(mapped_args);
            LemStmt::Expr(LemExpr::Call {
                func: Box::new(LemExpr::Ident("revert".to_owned())),
                args: call_args,
            })
        }

        // ── Try/catch — no Lem equivalent; use ? operator pattern ────────────
        pt::Statement::Try(_, _, _, _) => {
            LemStmt::Raw("// try/catch — use Lem's ? operator".to_owned())
        }

        // ── Inline assembly (Yul) — W001 ─────────────────────────────────────
        pt::Statement::Assembly { loc, .. } => {
            warnings.push(TranspileWarning::inline_assembly(loc));
            LemStmt::Raw("// W001: inline assembly — skipped".to_owned())
        }

        // ── Anything else — degrade gracefully ───────────────────────────────
        _ => LemStmt::Raw("// unsupported statement".to_owned()),
    }
}

/// Map a statement that is expected to produce a `Vec<LemStmt>`.
///
/// A `Block` is flattened into its children; any other statement becomes a
/// single-element vec. This is the canonical helper for `if`/`while`/`for` bodies.
fn map_stmt_to_vec(stmt: &pt::Statement, warnings: &mut WarningCollector) -> Vec<LemStmt> {
    match stmt {
        pt::Statement::Block {
            unchecked,
            statements,
            loc,
        } => {
            // W003: unchecked arithmetic block treated as normal (Lem always checks).
            if *unchecked {
                warnings.push(TranspileWarning::unchecked_block(loc));
            }
            map_body(statements, warnings)
        }
        other => vec![map_stmt(other, warnings)],
    }
}

/// Map an expression statement, handling special cases.
///
/// - `require(cond, "msg")` → `LemStmt::Assert`
/// - `emit Event(...)` is handled by `map_emit_stmt` (via `pt::Statement::Emit`)
/// - Assignments (`a = b`, `a += b`) → `LemStmt::Assign`
/// - General expression → `LemStmt::Expr`
fn map_expr_stmt(expr: &pt::Expression, warnings: &mut WarningCollector) -> LemStmt {
    match expr {
        // `require(cond, "msg")` → Assert
        pt::Expression::FunctionCall(_, func, args) if matches!(func.as_ref(), pt::Expression::Variable(id) if id.name == "require") =>
        {
            let cond = args
                .first()
                .map(|a| map_expr(a, warnings))
                .unwrap_or(LemExpr::BoolLit(true));
            let msg = args
                .get(1)
                .and_then(extract_string_literal)
                .unwrap_or_else(|| "require failed".to_owned());
            LemStmt::Assert { cond, msg }
        }

        // `a = b` → Assign
        pt::Expression::Assign(_, l, r) => LemStmt::Assign {
            target: map_expr(l, warnings),
            value: map_expr(r, warnings),
        },

        // `a += b` → Assign { target: a, value: a + b }
        pt::Expression::AssignAdd(_, l, r) => LemStmt::Assign {
            target: map_expr(l, warnings),
            value: LemExpr::BinaryOp {
                op: BinOp::Add,
                left: Box::new(map_expr(l, warnings)),
                right: Box::new(map_expr(r, warnings)),
            },
        },
        pt::Expression::AssignSubtract(_, l, r) => LemStmt::Assign {
            target: map_expr(l, warnings),
            value: LemExpr::BinaryOp {
                op: BinOp::Sub,
                left: Box::new(map_expr(l, warnings)),
                right: Box::new(map_expr(r, warnings)),
            },
        },
        pt::Expression::AssignMultiply(_, l, r) => LemStmt::Assign {
            target: map_expr(l, warnings),
            value: LemExpr::BinaryOp {
                op: BinOp::Mul,
                left: Box::new(map_expr(l, warnings)),
                right: Box::new(map_expr(r, warnings)),
            },
        },
        pt::Expression::AssignDivide(_, l, r) => LemStmt::Assign {
            target: map_expr(l, warnings),
            value: LemExpr::BinaryOp {
                op: BinOp::Div,
                left: Box::new(map_expr(l, warnings)),
                right: Box::new(map_expr(r, warnings)),
            },
        },
        pt::Expression::AssignModulo(_, l, r) => LemStmt::Assign {
            target: map_expr(l, warnings),
            value: LemExpr::BinaryOp {
                op: BinOp::Rem,
                left: Box::new(map_expr(l, warnings)),
                right: Box::new(map_expr(r, warnings)),
            },
        },

        // `i++` / `++i` as statement → `i = i + 1`
        pt::Expression::PreIncrement(_, e) | pt::Expression::PostIncrement(_, e) => {
            LemStmt::Assign {
                target: map_expr(e, warnings),
                value: LemExpr::BinaryOp {
                    op: BinOp::Add,
                    left: Box::new(map_expr(e, warnings)),
                    right: Box::new(LemExpr::IntLit(1)),
                },
            }
        }
        pt::Expression::PreDecrement(_, e) | pt::Expression::PostDecrement(_, e) => {
            LemStmt::Assign {
                target: map_expr(e, warnings),
                value: LemExpr::BinaryOp {
                    op: BinOp::Sub,
                    left: Box::new(map_expr(e, warnings)),
                    right: Box::new(LemExpr::IntLit(1)),
                },
            }
        }

        // General expression statement.
        other => LemStmt::Expr(map_expr(other, warnings)),
    }
}

/// Map a Solidity `emit Event(args)` statement to [`LemStmt::Emit`].
///
/// The emit call is a `FunctionCall` expression inside `pt::Statement::Emit`.
/// Field names are positional (`param0`, `param1`, …) for MVP — the codegen
/// resolves them against `LemContract.events` when emitting Lem source.
fn map_emit_stmt(call_expr: &pt::Expression, warnings: &mut WarningCollector) -> LemStmt {
    if let pt::Expression::FunctionCall(_, func, args) = call_expr {
        // Extract the event name from the function expression.
        let event_name = match func.as_ref() {
            pt::Expression::Variable(id) => id.name.clone(),
            pt::Expression::MemberAccess(_, _, id) => id.name.clone(),
            _ => "UnknownEvent".to_owned(),
        };
        let fields: Vec<(String, LemExpr)> = args
            .iter()
            .enumerate()
            .map(|(i, arg)| (format!("param{i}"), map_expr(arg, warnings)))
            .collect();
        LemStmt::Emit {
            event: event_name,
            fields,
        }
    } else {
        // Unexpected emit form — degrade to Raw.
        LemStmt::Raw("// emit — unexpected form".to_owned())
    }
}

// ── Contract mapping (entry point) ────────────────────────────────────────────

/// Map a Solidity contract definition to a [`LemContract`].
///
/// This is the top-level entry point called from `crate::transpile()`.
///
/// ## Processing order
///
/// 1. Contract name and inheritance bases.
/// 2. Structs and enums (no cross-references needed).
/// 3. State variables.
/// 4. Events.
/// 5. Function signatures (bodies empty — Batch 3).
pub(crate) fn map_contract(
    def: &pt::ContractDefinition,
    warnings: &mut WarningCollector,
) -> LemContract {
    let name = def
        .name
        .as_ref()
        .map(|id| id.name.clone())
        .unwrap_or_default();

    let mut contract = LemContract {
        name,
        extends: Vec::new(),
        uses: Vec::new(),
        uses_itoken: false,
        structs: Vec::new(),
        enums: Vec::new(),
        state: Vec::new(),
        events: Vec::new(),
        functions: Vec::new(),
        uses_ownable: false,
        uses_pausable: false,
        uses_access_control: false,
    };

    // 1. Process inheritance bases.
    for base in &def.base {
        apply_base(base, &mut contract);
    }

    // 2–5. Walk contract parts in declaration order.
    // BTreeMap for deterministic overload tracking (AGENTS §7.1).
    let mut seen_names: BTreeMap<String, usize> = BTreeMap::new();

    for part in &def.parts {
        match part {
            pt::ContractPart::StructDefinition(s) => {
                contract.structs.push(map_struct(s));
            }
            pt::ContractPart::EnumDefinition(e) => {
                contract.enums.push(map_enum(e));
            }
            pt::ContractPart::VariableDefinition(v) => {
                if let Some(param) = map_state_var(v) {
                    contract.state.push(param);
                }
            }
            pt::ContractPart::EventDefinition(ev) => {
                contract.events.push(map_event(ev));
            }
            pt::ContractPart::FunctionDefinition(f) => {
                if let Some(func) = map_function_sig(f, &mut seen_names, warnings) {
                    // Update contract trait flags from decorator names.
                    apply_decorator_flags(&func.decorators, &mut contract);
                    contract.functions.push(func);
                }
            }
            // Using directives, type definitions, annotations, stray semicolons:
            // no Lem IR equivalent — silently skip.
            _ => {}
        }
    }

    contract
}

#[cfg(test)]
mod tests;
