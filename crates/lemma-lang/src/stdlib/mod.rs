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
//! | `@std/security` | ReentrancyGuard, PullPayment, RateLimiter | future |
//! | `@std/math` | SafeMath, mulDiv, sqrt, exp, log, FixedPoint | future |
//! | `@std/crypto` | hashing, signatures, merkle, ZK, commitments | future |
//! | `@std/collections` | LinkedList, PriorityQueue, EnumerableSet | future |
//! | `@std/string` | utilities, formatting, parsing | future |
//! | `@std/time` | time/duration helpers | future |
//! | `@std/governance` | voting, proposals, timelock | future |
//! | `@std/dex` | AMM primitives, price oracles, liquidity math | future |

use std::collections::BTreeMap;

/// Embedded source for `@std/access` — Ownable, Pausable, AccessControl traits.
const ACCESS_SRC: &str = include_str!("access.lem");

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
}

impl Default for StdLibRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
