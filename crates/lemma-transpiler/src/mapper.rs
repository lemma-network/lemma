//! Solidity AST → Lem IR mapper.
//!
//! Maps `solang_parser::pt` types to the Lem IR defined in [`crate::lem_ir`].
//!
//! ## Batch 2 scope
//!
//! Types, declarations (state vars, function signatures, events, structs, enums).
//! Function bodies are `Vec::new()` — mapped in Batch 3 (`map_expr`, `map_stmt`).
//!
//! ## DRY note
//!
//! One canonical verb per concept (AGENTS §2.3):
//! - [`map_type`] — Solidity `Expression` type annotation → `LemType`
//! - [`map_sol_type`] — Solidity `pt::Type` enum → `LemType`
//! - [`map_function_sig`] — `FunctionDefinition` → `LemFunction` (body empty)
//! - [`map_state_var`] — `VariableDefinition` → `Option<LemParam>`
//! - [`map_event`] — `EventDefinition` → `LemEvent`
//! - [`map_struct`] — `StructDefinition` → `LemStruct`
//! - [`map_enum`] — `EnumDefinition` → `LemEnum`
//! - [`map_contract`] — `ContractDefinition` → `LemContract` (entry point)

use std::collections::BTreeMap;

use solang_parser::pt;

use crate::{
    lem_ir::{
        LemContract, LemEnum, LemEvent, LemEventField, LemFunction, LemFunctionKind, LemMutability,
        LemParam, LemStruct, LemType, LemVisibility,
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

/// Map a Solidity function definition to a [`LemFunction`] with an empty body.
///
/// Bodies are populated in Batch 3. Returns `None` for:
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

    Some(LemFunction {
        name,
        params,
        returns,
        visibility,
        mutability,
        decorators,
        body: Vec::new(), // Batch 3 fills this.
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
