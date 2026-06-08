//! Config, metadata, import, and using declaration nodes.

use crate::lexer::token::Span;

use super::super::Type;

// ─── Import / Using ───────────────────────────────────────────────────────────

/// An `import { A, B } from "path"` or `import * as Alias from "path"` statement.
#[derive(Debug, Clone, PartialEq)]
pub struct Import {
    /// What is being imported.
    pub names: ImportNames,
    /// Module path string.
    pub from: String,
    /// Source location.
    pub span: Span,
}

/// The import name list.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum ImportNames {
    /// `{ A, B, C }` — named imports.
    Named(Vec<String>),
    /// `* as Alias` — namespace import.
    Star(String),
}

/// A `using Library for Type` statement.
#[derive(Debug, Clone, PartialEq)]
pub struct Using {
    /// Library name.
    pub library: String,
    /// The type this library is attached to.
    pub for_type: Type,
    /// Source location.
    pub span: Span,
}

// ─── Config / Metadata (token standard) ──────────────────────────────────────

/// A `config { ... }` block inside a token declaration.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Config entries.
    pub entries: Vec<ConfigEntry>,
    /// Source location.
    pub span: Span,
}

/// A `metadata { ... }` block inside a token declaration.
///
/// Uses the same structure as `Config`.
#[derive(Debug, Clone, PartialEq)]
pub struct Metadata {
    /// Metadata entries.
    pub entries: Vec<MetadataEntry>,
    /// Source location.
    pub span: Span,
}

/// A single `key: value` entry in a config or metadata block.
pub type MetadataEntry = ConfigEntry;

/// A single `key: value` entry in a config or metadata block.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigEntry {
    /// Entry key.
    pub key: String,
    /// Entry value.
    pub value: ConfigValue,
    /// Source location.
    pub span: Span,
}

/// A value in a config or metadata entry.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigValue {
    /// A string value: `"text"`
    Str(String),
    /// An integer value: `42`
    Int(u128),
    /// A boolean value: `true` / `false`
    Bool(bool),
    /// A percentage value: `15%` → `Percent(15)`
    Percent(u128),
    /// A unit value: `7.days` → `Unit(7, UnitKind::Days)`
    Unit(u128, UnitKind),
    /// A nested object: `{ key: value, ... }`
    Object(Vec<ConfigEntry>),
    /// An identifier reference: `TokenType`
    Ident(String),
}

/// Time/value unit kinds used in config values and unit literals.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitKind {
    /// `.ether` — 1e18 Drop
    Ether,
    /// `.gwei` — 1e9 Drop
    Gwei,
    /// `.minutes`
    Minutes,
    /// `.hours`
    Hours,
    /// `.days`
    Days,
    /// `.seconds`
    Seconds,
}
