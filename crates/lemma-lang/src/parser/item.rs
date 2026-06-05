//! User-type declaration parsers: struct, enum, event, error, interface, trait, library.
//!
//! Implements `parse_struct_decl`, `parse_enum_decl`, `parse_event_decl`,
//! `parse_error_decl`, `parse_interface`, `parse_trait`, and `parse_library`.
//! These are wired into both `parse_contract_member` (contracts.rs) and
//! `parse_top_level_item` (decl.rs).
//!
//! ## Submodule layout
//!
//! - `item.rs` (this file) — module root; re-exports submodule parsers
//! - `item/struct_enum.rs` — struct and enum parsers
//! - `item/event_error.rs` — event, error, and `is_function_start` helper
//! - `item/advanced.rs` — interface, trait, and library parsers (subtask 2f)
//! - `item/tests.rs` — all tests for this module

mod advanced;
mod event_error;
mod struct_enum;

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
