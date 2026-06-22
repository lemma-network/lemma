//! Lem source code generator.
//!
//! Emits valid Lem source text from a [`LemContract`] IR.
//! This is the final stage of the transpilation pipeline:
//!
//! ```text
//! LemContract → emit_lem() → Lem source string
//! ```
//!
//! Output uses 4-space indentation throughout. Every emitted string is valid
//! input to the `lemma-lang` tokenizer and parser.
//!
//! ## DRY note
//!
//! One canonical verb per concept (AGENTS §2.3):
//! - [`emit_lem`]      — top-level entry point: `LemContract` → Lem source string
//! - [`emit_type`]     — `LemType` → type string (pure, no writer)
//! - [`emit_expr`]     — `LemExpr` → expression string (pure, no writer)
//! - [`emit_stmt`]     — `LemStmt` → writes statement line(s) to writer
//! - [`emit_function`] — `LemFunction` → writes function block to writer
//! - [`emit_event`]    — `LemEvent` → writes event line to writer
//! - [`emit_struct`]   — `LemStruct` → writes struct block to writer
//! - [`emit_enum`]     — `LemEnum` → writes enum block to writer
//! - [`emit_state`]    — `Vec<LemParam>` → writes state block to writer
//! - [`emit_contract`] — `LemContract` → writes full contract to writer

use crate::lem_ir::{
    BinOp, LemContract, LemEnum, LemEvent, LemExpr, LemFunction, LemFunctionKind, LemMutability,
    LemParam, LemStmt, LemStruct, LemType, LemVisibility, UnaryOp,
};

// ── CodegenWriter ─────────────────────────────────────────────────────────────

/// Internal string builder with 4-space indentation tracking.
///
/// All `emit_*` functions that produce multi-line output take `&mut CodegenWriter`.
/// Pure single-value emitters (`emit_type`, `emit_expr`) return `String` directly.
pub(crate) struct CodegenWriter {
    buf: String,
    /// Current indentation level (each level = 4 spaces).
    indent: usize,
}

impl CodegenWriter {
    fn new() -> Self {
        Self {
            buf: String::new(),
            indent: 0,
        }
    }

    /// Increase indentation by one level (4 spaces).
    fn indent(&mut self) {
        self.indent += 1;
    }

    /// Decrease indentation by one level (4 spaces). Saturates at zero.
    fn dedent(&mut self) {
        self.indent = self.indent.saturating_sub(1);
    }

    /// Emit a line at the current indentation level.
    ///
    /// An empty `s` emits a blank line (no leading spaces).
    fn line(&mut self, s: &str) {
        if s.is_empty() {
            self.buf.push('\n');
        } else {
            // 4 spaces per indent level.
            for _ in 0..self.indent {
                self.buf.push_str("    ");
            }
            self.buf.push_str(s);
            self.buf.push('\n');
        }
    }

    /// Consume the writer and return the accumulated source string.
    fn finish(self) -> String {
        self.buf
    }
}

// ── Public entry point ────────────────────────────────────────────────────────

/// Emit a complete Lem source file from a [`LemContract`] IR.
///
/// Returns valid Lem source text compilable by `lemma compile`.
///
/// # Example
///
/// ```
/// use lemma_transpiler::lem_ir::{LemContract, LemParam, LemType};
/// use lemma_transpiler::codegen::emit_lem;
///
/// let contract = LemContract {
///     name: "MyToken".to_owned(),
///     extends: vec![],
///     uses: vec![],
///     uses_itoken: false,
///     structs: vec![],
///     enums: vec![],
///     state: vec![LemParam { name: "supply".to_owned(), ty: LemType::U128 }],
///     events: vec![],
///     functions: vec![],
///     uses_ownable: false,
///     uses_pausable: false,
///     uses_access_control: false,
/// };
/// let src = emit_lem(&contract);
/// assert!(src.contains("contract MyToken"));
/// ```
pub fn emit_lem(contract: &LemContract) -> String {
    let mut out = CodegenWriter::new();
    emit_preamble(&mut out);
    emit_contract(&mut out, contract);
    out.finish()
}

// ── Preamble ──────────────────────────────────────────────────────────────────

/// Emit the file-level comment header.
fn emit_preamble(out: &mut CodegenWriter) {
    out.line("// Transpiled from Solidity by lemma-transpiler");
    out.line("// Manual review recommended for Lem-specific features (SAFETY rules, @std library)");
    out.line("");
}

// ── Contract ──────────────────────────────────────────────────────────────────

/// Emit the full contract body.
///
/// Produces:
/// ```text
/// contract Name [implements IFace1, IFace2] [uses Trait1, Trait2] {
///     <structs>
///     <enums>
///     <state block>
///     <events>
///     <functions>
/// }
/// ```
///
/// ## Grammar note
///
/// The Lem `contract` grammar has no `extends` clause (that keyword belongs to
/// `token` declarations only). Concrete Solidity `is ConcreteBase` bases are
/// emitted as a comment and excluded from the header. Interface bases go in
/// `implements`, traits go in `uses`.
fn emit_contract(out: &mut CodegenWriter, contract: &LemContract) {
    // Concrete bases (`contract.extends`) are not expressible in the `contract`
    // header — emit a comment and skip them (MF-1 fix; `extends` is only valid
    // on `token` declarations in Lem grammar).
    if !contract.extends.is_empty() {
        out.line(&format!(
            "// Concrete inheritance from Solidity: {} — manual review:",
            contract.extends.join(", ")
        ));
        out.line(
            "// Lem contracts compose via `uses` (traits) and `implements` (interfaces),",
        );
        out.line("// not class-style `extends`. Extract shared logic into a trait.");
    }

    // `implements` clause: interfaces (IToken, plus any other interface names
    // from `contract.uses` whose names start with 'I' per convention).
    // Traits (`Ownable`, `Pausable`, `AccessControl`) go to `uses` (MF-2 fix).
    let mut implements: Vec<&str> = Vec::new();
    if contract.uses_itoken {
        implements.push("IToken");
    }
    // Items in contract.uses are interface names (collected by apply_base when
    // the base name follows the `I<Upper>...` convention — see mapper.rs).
    let extra_ifaces: Vec<&str> = contract.uses.iter().map(String::as_str).collect();
    implements.extend_from_slice(&extra_ifaces);

    // `uses` clause: traits only.
    let mut uses: Vec<&str> = Vec::new();
    if contract.uses_ownable {
        uses.push("Ownable");
    }
    if contract.uses_pausable {
        uses.push("Pausable");
    }
    if contract.uses_access_control {
        uses.push("AccessControl");
    }

    // Build the contract declaration line.
    let mut decl = format!("contract {}", contract.name);
    if !implements.is_empty() {
        decl.push_str(" implements ");
        decl.push_str(&implements.join(", "));
    }
    if !uses.is_empty() {
        decl.push_str(" uses ");
        decl.push_str(&uses.join(", "));
    }
    decl.push_str(" {");

    out.line(&decl);
    out.indent();

    // Structs.
    for s in &contract.structs {
        emit_struct(out, s);
        out.line("");
    }

    // Enums.
    for e in &contract.enums {
        emit_enum(out, e);
        out.line("");
    }

    // State block (only if there are state variables).
    if !contract.state.is_empty() {
        emit_state(out, &contract.state);
        out.line("");
    }

    // Events.
    for event in &contract.events {
        emit_event(out, event);
    }
    if !contract.events.is_empty() {
        out.line("");
    }

    // Functions.
    for (i, func) in contract.functions.iter().enumerate() {
        emit_function(out, func);
        // Blank line between functions, but not after the last one.
        if i + 1 < contract.functions.len() {
            out.line("");
        }
    }

    out.dedent();
    out.line("}");
}

// ── State block ───────────────────────────────────────────────────────────────

/// Emit the `state { ... }` block.
///
/// Each field is emitted as `name: Type,` (trailing comma, Lem convention).
fn emit_state(out: &mut CodegenWriter, fields: &[LemParam]) {
    out.line("state {");
    out.indent();
    for field in fields {
        out.line(&format!("{}: {},", field.name, emit_type(&field.ty)));
    }
    out.dedent();
    out.line("}");
}

// ── Struct ────────────────────────────────────────────────────────────────────

/// Emit a `struct` definition.
///
/// ```text
/// struct MyStruct {
///     field1: u128,
///     field2: Address,
/// }
/// ```
fn emit_struct(out: &mut CodegenWriter, s: &LemStruct) {
    out.line(&format!("struct {} {{", s.name));
    out.indent();
    for field in &s.fields {
        out.line(&format!("{}: {},", field.name, emit_type(&field.ty)));
    }
    out.dedent();
    out.line("}");
}

// ── Enum ──────────────────────────────────────────────────────────────────────

/// Emit an `enum` definition.
///
/// ```text
/// enum Status {
///     Active,
///     Paused,
/// }
/// ```
fn emit_enum(out: &mut CodegenWriter, e: &LemEnum) {
    out.line(&format!("enum {} {{", e.name));
    out.indent();
    for variant in &e.variants {
        out.line(&format!("{},", variant));
    }
    out.dedent();
    out.line("}");
}

// ── Event ─────────────────────────────────────────────────────────────────────

/// Emit a single event definition on one line.
///
/// ```text
/// event Transfer { @indexed from: Address, @indexed to: Address, amount: u128 }
/// ```
fn emit_event(out: &mut CodegenWriter, event: &LemEvent) {
    let fields: Vec<String> = event
        .fields
        .iter()
        .map(|f| {
            if f.indexed {
                format!("@indexed {}: {}", f.name, emit_type(&f.ty))
            } else {
                format!("{}: {}", f.name, emit_type(&f.ty))
            }
        })
        .collect();

    out.line(&format!("event {} {{ {} }}", event.name, fields.join(", ")));
}

// ── Function ──────────────────────────────────────────────────────────────────

/// Emit a function or constructor definition.
///
/// Decorators are emitted as `@name` lines before the `fn` signature.
/// Constructor (`LemFunctionKind::Constructor`) uses `fn init(...)`.
///
/// ```text
/// @onlyOwner
/// pub fn mint(to: Address, amount: u128) {
///     ...
/// }
/// ```
fn emit_function(out: &mut CodegenWriter, func: &LemFunction) {
    // Decorators — one per line, before the fn signature.
    for dec in &func.decorators {
        out.line(&format!("@{dec}"));
    }

    // Build the signature.
    let vis = match func.visibility {
        LemVisibility::Public => "pub ",
        LemVisibility::Private => "",
    };

    let mutability_kw = match func.mutability {
        LemMutability::Mutable => "",
        LemMutability::View => "view ",
        LemMutability::Pure => "pure ",
        LemMutability::Payable => "payable ",
    };

    // Parameters: `name: Type, ...`
    let params: Vec<String> = func
        .params
        .iter()
        .map(|p| format!("{}: {}", p.name, emit_type(&p.ty)))
        .collect();

    // Constructor → `[payable] init(params)` (keyword form, no `pub`/`fn`).
    // Regular method → `pub [view|pure|payable] fn name(params) [-> RetType]`.
    //
    // Grammar reference (parser/decl/tests.rs:619-636):
    //   `init(owner: Address) { }` — plain constructor
    //   `payable init(val: u128) { }` — payable constructor
    // `init` is a reserved keyword; `pub fn init` is a parse error.
    let sig = match func.kind {
        LemFunctionKind::Constructor => {
            // Only `payable` is valid before `init` (WF-003).
            let payable_prefix = if func.mutability == LemMutability::Payable {
                "payable "
            } else {
                ""
            };
            format!("{payable_prefix}init({}) {{", params.join(", "))
        }
        LemFunctionKind::Method => {
            // Build the function signature line: `pub fn name(params) -> RetType {`
            if let Some(ret_ty) = &func.returns {
                format!(
                    "{vis}{mutability_kw}fn {}({}) -> {} {{",
                    func.name,
                    params.join(", "),
                    emit_type(ret_ty)
                )
            } else {
                format!(
                    "{vis}{mutability_kw}fn {}({}) {{",
                    func.name,
                    params.join(", ")
                )
            }
        }
    };

    out.line(&sig);
    out.indent();

    // Body statements — no semicolons in Lem.
    for stmt in &func.body {
        emit_stmt(stmt, out);
    }

    out.dedent();
    out.line("}");
}

// ── Type emitter (pure) ───────────────────────────────────────────────────────

/// Emit a [`LemType`] as a Lem type string.
///
/// This is a pure function — same input always produces the same output.
pub(crate) fn emit_type(ty: &LemType) -> String {
    match ty {
        LemType::U8 => "u8".to_owned(),
        LemType::U16 => "u16".to_owned(),
        LemType::U32 => "u32".to_owned(),
        LemType::U64 => "u64".to_owned(),
        LemType::U128 => "u128".to_owned(),
        LemType::U256 => "u256".to_owned(),
        LemType::I8 => "i8".to_owned(),
        LemType::I16 => "i16".to_owned(),
        LemType::I32 => "i32".to_owned(),
        LemType::I64 => "i64".to_owned(),
        LemType::I128 => "i128".to_owned(),
        LemType::Bool => "bool".to_owned(),
        LemType::Str => "String".to_owned(),
        LemType::Bytes => "bytes".to_owned(),
        LemType::Address => "Address".to_owned(),
        LemType::FixedBytes(n) => format!("[u8; {n}]"),
        LemType::Array(inner) => format!("Array<{}>", emit_type(inner)),
        LemType::Map(k, v) => format!("Map<{}, {}>", emit_type(k), emit_type(v)),
        LemType::Set(inner) => format!("Set<{}>", emit_type(inner)),
        LemType::Named(name) => name.clone(),
        LemType::Option(inner) => format!("Option<{}>", emit_type(inner)),
        LemType::Tuple(a, b) => format!("({}, {})", emit_type(a), emit_type(b)),
    }
}

// ── Expression emitter (pure) ─────────────────────────────────────────────────

/// Emit a [`LemExpr`] as a Lem expression string.
///
/// This is a pure function — no side effects, no writer mutations.
/// Binary operations are parenthesized for unambiguous precedence.
pub(crate) fn emit_expr(expr: &LemExpr) -> String {
    match expr {
        // ── Literals ──────────────────────────────────────────────────────────
        LemExpr::IntLit(n) => n.to_string(),
        LemExpr::BoolLit(b) => b.to_string(),
        LemExpr::StringLit(s) => format!("\"{}\"", escape_string(s)),
        LemExpr::BytesLit(bytes) => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            format!("0x{hex}")
        }
        LemExpr::AddressLit(s) => s.clone(),

        // ── References ────────────────────────────────────────────────────────
        LemExpr::Ident(name) => name.clone(),
        LemExpr::MemberAccess(expr, field) => format!("{}.{field}", emit_expr(expr)),
        LemExpr::IndexAccess(expr, idx) => format!("{}[{}]", emit_expr(expr), emit_expr(idx)),

        // ── Calls ─────────────────────────────────────────────────────────────
        LemExpr::Call { func, args } => {
            let args_str: Vec<String> = args.iter().map(emit_expr).collect();
            format!("{}({})", emit_expr(func), args_str.join(", "))
        }
        LemExpr::MapGet { map, key } => {
            format!("{}.get({})", emit_expr(map), emit_expr(key))
        }
        LemExpr::MapSet { map, key, value } => {
            format!(
                "{}.set({}, {})",
                emit_expr(map),
                emit_expr(key),
                emit_expr(value)
            )
        }

        // ── Operations ────────────────────────────────────────────────────────
        LemExpr::BinaryOp { op, left, right } => {
            // Parenthesize for unambiguous precedence.
            format!(
                "({} {} {})",
                emit_expr(left),
                emit_binop(*op),
                emit_expr(right)
            )
        }
        LemExpr::UnaryOp { op, expr } => match op {
            UnaryOp::Not => format!("!{}", emit_expr(expr)),
            UnaryOp::Neg => format!("-{}", emit_expr(expr)),
        },

        // ── Compound ──────────────────────────────────────────────────────────
        LemExpr::StructLit { name, fields } => {
            let field_strs: Vec<String> = fields
                .iter()
                .map(|(k, v)| format!("{k}: {}", emit_expr(v)))
                .collect();
            format!("{name} {{ {} }}", field_strs.join(", "))
        }
        LemExpr::Cast { expr, ty } => {
            format!("{} as {}", emit_expr(expr), emit_type(ty))
        }
        // Lem has no ternary operator. When a ternary appears in expression
        // position it cannot be lowered to an if/else (which is a statement
        // in Lem). Emit Raw with a comment so the human reviewer can refactor
        // it to a let + if/else statement.
        LemExpr::Ternary {
            cond,
            then_expr,
            else_expr,
        } => {
            format!(
                "/* ternary: ({}) ? ({}) : ({}) — refactor to if/else statement */",
                emit_expr(cond),
                emit_expr(then_expr),
                emit_expr(else_expr)
            )
        }
        LemExpr::Tuple(elems) => {
            let elem_strs: Vec<String> = elems.iter().map(emit_expr).collect();
            format!("({})", elem_strs.join(", "))
        }

        // ── Raw passthrough ───────────────────────────────────────────────────
        // Raw expressions are emitted verbatim — they were already diagnosed
        // at the mapper layer (W001/W002/etc.) and carry their own comments.
        LemExpr::Raw(s) => s.clone(),
    }
}

/// Emit a [`BinOp`] as its Lem operator symbol.
fn emit_binop(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "+",
        BinOp::Sub => "-",
        BinOp::Mul => "*",
        BinOp::Div => "/",
        BinOp::Rem => "%",
        BinOp::Eq => "==",
        BinOp::Ne => "!=",
        BinOp::Lt => "<",
        BinOp::Le => "<=",
        BinOp::Gt => ">",
        BinOp::Ge => ">=",
        BinOp::And => "&&",
        BinOp::Or => "||",
        BinOp::BitAnd => "&",
        BinOp::BitOr => "|",
        BinOp::BitXor => "^",
        BinOp::Shl => "<<",
        BinOp::Shr => ">>",
    }
}

// ── String escape helper ──────────────────────────────────────────────────────

/// Escape a string literal for inclusion in Lem source.
///
/// Escapes `\` → `\\`, `"` → `\"`, newline → `\n`, carriage return → `\r`,
/// tab → `\t`. Other non-ASCII characters are passed through (Lem source is UTF-8).
fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

// ── Statement emitter ─────────────────────────────────────────────────────────

/// Emit a [`LemStmt`] into the writer.
///
/// Lem uses no semicolons — statements are newline-terminated.
/// Multi-line constructs (`if`, `while`, `for`) open/close their own braces.
pub(crate) fn emit_stmt(stmt: &LemStmt, out: &mut CodegenWriter) {
    match stmt {
        // ── Let ───────────────────────────────────────────────────────────────
        LemStmt::Let { name, ty, value } => {
            let ty_ann = ty
                .as_ref()
                .map(|t| format!(": {}", emit_type(t)))
                .unwrap_or_default();
            out.line(&format!("let {name}{ty_ann} = {}", emit_expr(value)));
        }

        // ── Assign ────────────────────────────────────────────────────────────
        LemStmt::Assign { target, value } => {
            out.line(&format!("{} = {}", emit_expr(target), emit_expr(value)));
        }

        // ── Assert ────────────────────────────────────────────────────────────
        LemStmt::Assert { cond, msg } => {
            out.line(&format!(
                "assert({}, \"{}\")",
                emit_expr(cond),
                escape_string(msg)
            ));
        }

        // ── Emit ──────────────────────────────────────────────────────────────
        LemStmt::Emit { event, fields } => {
            let field_strs: Vec<String> = fields
                .iter()
                .map(|(k, v)| format!("{k}: {}", emit_expr(v)))
                .collect();
            out.line(&format!("emit {event} {{ {} }}", field_strs.join(", ")));
        }

        // ── Return ────────────────────────────────────────────────────────────
        LemStmt::Return(Some(expr)) => {
            out.line(&format!("return {}", emit_expr(expr)));
        }
        LemStmt::Return(None) => {
            out.line("return");
        }

        // ── If / else ─────────────────────────────────────────────────────────
        LemStmt::If {
            cond,
            then_body,
            else_body,
        } => {
            out.line(&format!("if ({}) {{", emit_expr(cond)));
            out.indent();
            for s in then_body {
                emit_stmt(s, out);
            }
            out.dedent();
            if let Some(else_stmts) = else_body {
                out.line("} else {");
                out.indent();
                for s in else_stmts {
                    emit_stmt(s, out);
                }
                out.dedent();
                out.line("}");
            } else {
                out.line("}");
            }
        }

        // ── While ─────────────────────────────────────────────────────────────
        LemStmt::While { cond, body } => {
            out.line(&format!("while ({}) {{", emit_expr(cond)));
            out.indent();
            for s in body {
                emit_stmt(s, out);
            }
            out.dedent();
            out.line("}");
        }

        // ── For ───────────────────────────────────────────────────────────────
        // Lem does not have a C-style `for` loop. Emit as a while loop with
        // the init before and update at the end of the body.
        LemStmt::For {
            init,
            cond,
            update,
            body,
        } => {
            // Emit init statement before the loop (if present).
            if let Some(init_stmt) = init {
                emit_stmt(init_stmt, out);
            }
            let cond_str = cond
                .as_ref()
                .map(emit_expr)
                .unwrap_or_else(|| "true".to_owned());
            out.line(&format!("while ({cond_str}) {{"));
            out.indent();
            for s in body {
                emit_stmt(s, out);
            }
            // Emit update at the end of the loop body (if present).
            if let Some(update_stmt) = update {
                emit_stmt(update_stmt, out);
            }
            out.dedent();
            out.line("}");
        }

        // ── Expr statement ────────────────────────────────────────────────────
        LemStmt::Expr(expr) => {
            out.line(&emit_expr(expr));
        }

        // ── Break / Continue ──────────────────────────────────────────────────
        LemStmt::Break => {
            out.line("break");
        }
        LemStmt::Continue => {
            out.line("continue");
        }

        // ── Raw passthrough ───────────────────────────────────────────────────
        // Raw statements are emitted verbatim — they carry their own comments
        // from the mapper layer and must not be further transformed.
        LemStmt::Raw(s) => {
            out.line(s);
        }
    }
}

#[cfg(test)]
mod tests;
