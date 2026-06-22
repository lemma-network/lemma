//! Tests for the `warnings` module — warning codes, constructors, and collector.

use super::*;
use solang_parser::pt::Loc;

fn file_loc(start: usize) -> Loc {
    Loc::File(0, start, start + 10)
}

#[test]
fn warning_code_display_w001() {
    assert_eq!(WarningCode::InlineAssembly.to_string(), "W001");
}

#[test]
fn warning_code_display_w002() {
    assert_eq!(WarningCode::FunctionOverloading.to_string(), "W002");
}

#[test]
fn warning_code_display_w003() {
    assert_eq!(WarningCode::UncheckedBlock.to_string(), "W003");
}

#[test]
fn inline_assembly_warning_has_w001_code() {
    let w = TranspileWarning::inline_assembly(&file_loc(42));
    assert_eq!(w.code, WarningCode::InlineAssembly);
    assert_eq!(w.offset, 42);
    assert!(w.message.contains("Yul"));
}

#[test]
fn function_overloading_warning_includes_names() {
    let w = TranspileWarning::function_overloading(&file_loc(100), "transfer", "transfer_2");
    assert_eq!(w.code, WarningCode::FunctionOverloading);
    assert!(w.message.contains("transfer"));
    assert!(w.message.contains("transfer_2"));
}

#[test]
fn unchecked_block_warning_has_w003_code() {
    let w = TranspileWarning::unchecked_block(&file_loc(0));
    assert_eq!(w.code, WarningCode::UncheckedBlock);
}

#[test]
fn warning_collector_accumulates_and_drains() {
    let mut col = WarningCollector::new();
    col.push(TranspileWarning::inline_assembly(&file_loc(0)));
    col.push(TranspileWarning::unchecked_block(&file_loc(10)));
    let warnings = col.finish();
    assert_eq!(warnings.len(), 2);
    assert_eq!(warnings[0].code, WarningCode::InlineAssembly);
    assert_eq!(warnings[1].code, WarningCode::UncheckedBlock);
}

#[test]
fn warning_display_includes_code_and_message() {
    let w = TranspileWarning::inline_assembly(&file_loc(5));
    let s = w.to_string();
    assert!(s.contains("W001"));
    assert!(s.contains("5"));
}
