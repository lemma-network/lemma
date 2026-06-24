//! Standard library registry for Lem's `@std/*` imports.
//!
//! The `@std` modules are real Lem source files embedded in the compiler binary
//! via [`include_str!`]. When the resolver encounters `import { X } from "@std/module"`,
//! it looks up the module path here, then parses and type-checks the embedded source.
//!
//! ## Module catalog (03-LANGUAGE_SPEC §27)
//!
//! | Module | Contents | Status |
//! |--------|----------|--------|
//! | `@std/token` | Token, TaxToken bases | P3·Step 8 |
//! | `@std/interfaces` | IToken, INFT, IMultiToken, IVault | P3·Step 8 |
//! | `@std/access` | Ownable, Pausable, AccessControl | P3·Step 8 |
//! | `@std/agent` | AgentPolicy, AutoRevoke, KyaTier | P3·Step 12 |
//! | `@std/security` | ReentrancyGuard, PullPayment, RateLimiter | future |
//! | `@std/math` | SafeMath, mulDiv, sqrt, exp, log, FixedPoint | future |
//! | `@std/crypto` | hashing, signatures, merkle, ZK, commitments | future |
//! | `@std/collections` | LinkedList, PriorityQueue, EnumerableSet | future |
//! | `@std/string` | utilities, formatting, parsing | future |
//! | `@std/time` | time/duration helpers | future |
//! | `@std/governance` | voting, proposals, timelock | future |
//! | `@std/dex` | AMM primitives, price oracles, liquidity math | future |

use std::collections::BTreeMap;

use crate::type_checker::types::SymbolKind;

/// Embedded source for `@std/access` — Ownable, Pausable, AccessControl traits.
const ACCESS_SRC: &str = include_str!("access.lem");

/// Embedded source for `@std/agent` — AgentPolicy, AutoRevoke, KyaTier (§2.1, §2.3.5, §7).
const AGENT_SRC: &str = include_str!("agent.lem");

/// Embedded source for `@std/interfaces` — IToken, INFT, IMultiToken, IVault.
const INTERFACES_SRC: &str = include_str!("interfaces.lem");

/// Embedded source for `@std/token` — Token + TaxToken base implementations.
const TOKEN_SRC: &str = include_str!("token.lem");

/// Registry of `@std/*` module paths to their embedded Lem source.
///
/// Key: the module path WITHOUT the `@std/` prefix (e.g. `"token"` for `@std/token`).
/// Value: the embedded Lem source string.
///
/// ## Usage
///
/// ```rust,ignore
/// use lemma_lang::stdlib::StdLibRegistry;
///
/// let registry = StdLibRegistry::new();
/// if let Some(source) = registry.get("token") {
///     // Parse and type-check `source`...
/// }
/// ```
pub struct StdLibRegistry {
    modules: BTreeMap<&'static str, &'static str>,
}

impl StdLibRegistry {
    /// Build the registry with all available `@std` modules.
    pub fn new() -> Self {
        let mut modules = BTreeMap::new();
        modules.insert("access", ACCESS_SRC);
        modules.insert("agent", AGENT_SRC);
        modules.insert("interfaces", INTERFACES_SRC);
        modules.insert("token", TOKEN_SRC);
        Self { modules }
    }

    /// Look up a module by path (without the `@std/` prefix).
    ///
    /// Returns `None` for unknown modules — the caller should produce a
    /// compile error ("unknown @std module").
    pub fn get(&self, module: &str) -> Option<&'static str> {
        self.modules.get(module).copied()
    }

    /// List all available module names (for error messages / suggestions).
    pub fn available_modules(&self) -> Vec<&'static str> {
        self.modules.keys().copied().collect()
    }

    /// Symbol kind for a name exported by an `@std` module.
    ///
    /// Returns the [`SymbolKind`] that should be used when registering the
    /// imported name in the resolver's scope.  Returns `None` if the name is
    /// not exported by the module.
    ///
    /// This is a hardcoded export map — the `.lem` files remain as
    /// documentation; the compiler uses this map for symbol resolution.
    /// Full re-entrant parse+check of `.lem` files is deferred to a future step.
    pub fn symbol_kind(&self, module: &str, name: &str) -> Option<SymbolKind> {
        match (module, name) {
            // @std/token exports
            ("token", "Token") => Some(SymbolKind::Contract),
            ("token", "TaxToken") => Some(SymbolKind::Contract),

            // @std/interfaces exports
            ("interfaces", "IToken") => Some(SymbolKind::Interface),
            ("interfaces", "INFT") => Some(SymbolKind::Interface),
            ("interfaces", "IMultiToken") => Some(SymbolKind::Interface),
            ("interfaces", "IVault") => Some(SymbolKind::Interface),
            ("interfaces", "ApprovalOpts") => Some(SymbolKind::Struct),
            ("interfaces", "Allowance") => Some(SymbolKind::Struct),

            // @std/access exports
            ("access", "Ownable") => Some(SymbolKind::Trait),
            ("access", "Pausable") => Some(SymbolKind::Trait),
            ("access", "AccessControl") => Some(SymbolKind::Trait),

            // @std/agent exports (P3·Step 12)
            // AgentPolicy: bounded-authority grant for a session key (14-AGENT_LAYER §2.1).
            // AutoRevoke: dead-man's switch declaration (§2.3.5).
            // KyaTier: identity-verification tier for A2A interactions (§7).
            ("agent", "AgentPolicy") => Some(SymbolKind::Struct),
            ("agent", "AutoRevoke") => Some(SymbolKind::Struct),
            ("agent", "KyaTier") => Some(SymbolKind::Enum),

            _ => None,
        }
    }

    /// Check if a module path is a known `@std` module.
    pub fn is_std_module(path: &str) -> bool {
        path.starts_with("@std/")
    }

    /// Extract the module name from a full `@std` path.
    ///
    /// `"@std/token"` → `Some("token")`, `"./local"` → `None`.
    pub fn module_name(path: &str) -> Option<&str> {
        path.strip_prefix("@std/")
    }
}

impl Default for StdLibRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Base member definitions ──────────────────────────────────────────────────

/// A state field inherited from a base standard or trait.
///
/// Used by the resolver to inject inherited state fields into the contract
/// scope when `extends Token` or `uses Ownable` is encountered.
#[derive(Debug, Clone, PartialEq)]
pub struct StdField {
    /// Field name (e.g. `"balances"`, `"owner"`).
    pub name: &'static str,
    /// Type name as it would appear in Lem source (e.g. `"Map<Address, u128>"`).
    /// Informational only — the resolver registers the field by name and kind,
    /// not by parsed type (full type resolution is deferred to codegen).
    pub ty: &'static str,
}

/// A function signature inherited from a base standard or trait.
///
/// Used by the resolver to inject inherited function names into the contract
/// scope so user code can reference them and the safety analyzer sees the
/// complete function set.
#[derive(Debug, Clone, PartialEq)]
pub struct StdFunction {
    /// Function name (e.g. `"transfer"`, `"transferOwnership"`).
    pub name: &'static str,
    /// Whether the function is `pub` (visible to external callers).
    pub is_public: bool,
}

/// Members provided by a base standard (`Token`, `TaxToken`) or trait
/// (`Ownable`, `Pausable`, `AccessControl`).
///
/// The resolver calls [`StdLibRegistry::base_members`] to get these when
/// processing `extends` or `uses` clauses, then injects them into the
/// contract's value scope BEFORE user-defined members.  This enables:
/// - User code to reference `self.balances`, `self.owner` (inherited state)
/// - Safety analyzer to see all functions (inherited + user-defined)
/// - Codegen to generate code for the combined contract
#[derive(Debug, Clone, PartialEq)]
pub struct StdBaseMembers {
    /// State fields provided by this base/trait.
    pub state_fields: Vec<StdField>,
    /// Functions provided by this base/trait.
    pub functions: Vec<StdFunction>,
}

impl StdLibRegistry {
    /// Get the members provided by a base standard or trait.
    ///
    /// Called by the resolver to inject inherited members into the contract
    /// scope when `extends Token` or `uses Ownable` is encountered.
    ///
    /// Returns `None` for unknown bases (the user may be extending a
    /// user-defined type — not yet supported, produces a type error elsewhere).
    ///
    /// ## Canonical source: the embedded `.lem` files
    ///
    /// The `@std` base definitions have a SINGLE canonical source — the embedded
    /// Lem source files (`token.lem`, `access.lem`). This map is a *hand-maintained
    /// mirror* used for symbol resolution until full re-entrant parse+check of the
    /// `.lem` files lands (see [`StdLibRegistry::symbol_kind`]). Per AGENTS §2
    /// ("one canonical way"), the two must never diverge: the bidirectional sync
    /// test in `stdlib/tests.rs` (`base_members_match_lem_source`) parses each
    /// `.lem` and asserts every member here exists there and vice-versa, so a drift
    /// fails CI rather than silently changing contract behaviour.
    ///
    /// Member set is dictated by `docs/03-LANGUAGE_SPEC.md` §13 (IToken) + §24
    /// (Token / TaxToken). Note `distributeTaxes` / `isTaxable` are *dev*-implemented
    /// (WF-014), not base members, so they appear in neither.
    pub fn base_members(name: &str) -> Option<StdBaseMembers> {
        match name {
            "Token" => Some(StdBaseMembers {
                state_fields: vec![
                    StdField {
                        name: "balances",
                        ty: "Map<Address, u128>",
                    },
                    StdField {
                        name: "totalSupply",
                        ty: "u128",
                    },
                    StdField {
                        name: "owner",
                        ty: "Address",
                    },
                    StdField {
                        name: "allowances",
                        ty: "Map<Address, Map<Address, Allowance>>",
                    },
                ],
                functions: vec![
                    StdFunction {
                        name: "transfer",
                        is_public: true,
                    },
                    StdFunction {
                        name: "approve",
                        is_public: true,
                    },
                    StdFunction {
                        name: "transferFrom",
                        is_public: true,
                    },
                    StdFunction {
                        name: "balanceOf",
                        is_public: true,
                    },
                    StdFunction {
                        name: "totalSupply",
                        is_public: true,
                    },
                    StdFunction {
                        name: "allowance",
                        is_public: true,
                    },
                    StdFunction {
                        name: "mint",
                        is_public: true,
                    },
                ],
            }),
            "TaxToken" => Some(StdBaseMembers {
                // TaxToken extends Token — includes all Token fields + tax-specific.
                state_fields: vec![
                    // From Token:
                    StdField {
                        name: "balances",
                        ty: "Map<Address, u128>",
                    },
                    StdField {
                        name: "totalSupply",
                        ty: "u128",
                    },
                    StdField {
                        name: "owner",
                        ty: "Address",
                    },
                    StdField {
                        name: "allowances",
                        ty: "Map<Address, Map<Address, Allowance>>",
                    },
                    // TaxToken-specific:
                    StdField {
                        name: "taxPool",
                        ty: "u128",
                    },
                    StdField {
                        name: "pairs",
                        ty: "Set<Address>",
                    },
                    StdField {
                        name: "exempt",
                        ty: "Set<Address>",
                    },
                    StdField {
                        name: "rewardExempt",
                        ty: "Set<Address>",
                    },
                ],
                functions: vec![
                    // From Token:
                    StdFunction {
                        name: "transfer",
                        is_public: true,
                    },
                    StdFunction {
                        name: "approve",
                        is_public: true,
                    },
                    StdFunction {
                        name: "transferFrom",
                        is_public: true,
                    },
                    StdFunction {
                        name: "balanceOf",
                        is_public: true,
                    },
                    StdFunction {
                        name: "totalSupply",
                        is_public: true,
                    },
                    StdFunction {
                        name: "allowance",
                        is_public: true,
                    },
                    StdFunction {
                        name: "mint",
                        is_public: true,
                    },
                    // TaxToken-specific:
                    StdFunction {
                        name: "setPair",
                        is_public: true,
                    },
                    StdFunction {
                        name: "setExempt",
                        is_public: true,
                    },
                    StdFunction {
                        name: "setRewardExempt",
                        is_public: true,
                    },
                    // Internal predicates (§24.5) — private helpers the protocol /
                    // dev `isTaxable` call.  NOT public.  `distributeTaxes` and
                    // `isTaxable` are dev-implemented (WF-014), so they are
                    // intentionally NOT base members.
                    StdFunction {
                        name: "isPair",
                        is_public: false,
                    },
                    StdFunction {
                        name: "isExempt",
                        is_public: false,
                    },
                ],
            }),
            "Ownable" => Some(StdBaseMembers {
                state_fields: vec![StdField {
                    name: "owner",
                    ty: "Address",
                }],
                functions: vec![
                    StdFunction {
                        name: "transferOwnership",
                        is_public: true,
                    },
                    StdFunction {
                        name: "renounceOwnership",
                        is_public: true,
                    },
                    StdFunction {
                        name: "isRenounced",
                        is_public: false,
                    },
                ],
            }),
            "Pausable" => Some(StdBaseMembers {
                state_fields: vec![StdField {
                    name: "paused",
                    ty: "bool",
                }],
                functions: vec![
                    StdFunction {
                        name: "pause",
                        is_public: true,
                    },
                    StdFunction {
                        name: "unpause",
                        is_public: true,
                    },
                ],
            }),
            "AccessControl" => Some(StdBaseMembers {
                state_fields: vec![StdField {
                    name: "roles",
                    ty: "Map<u128, Set<Address>>",
                }],
                functions: vec![
                    StdFunction {
                        name: "hasRole",
                        is_public: false,
                    },
                    StdFunction {
                        name: "grantRole",
                        is_public: true,
                    },
                    StdFunction {
                        name: "revokeRole",
                        is_public: true,
                    },
                ],
            }),
            _ => None,
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
