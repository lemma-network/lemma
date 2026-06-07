//! Token types and source location for the Lem language lexer.
//!
//! [`Token`] is the complete set of lexical tokens produced by the Lem lexer.
//! Every token is paired with a [`Span`] that records its exact source location.
//!
//! ## Design notes
//!
//! - Comments are kept as tokens (not stripped) so the LSP and doc-generator
//!   can consume them without re-parsing.
//! - `Newline` is a token so the parser can implement significant-whitespace
//!   rules (Lem uses newlines as statement terminators, like Go/Python).
//! - Floating-point values are stored as raw strings to preserve determinism
//!   across platforms (no f64 representation).
//! - Address literals are validated as Bech32m at lex time; invalid addresses
//!   produce a `LangError::Lex` rather than a token.

// ─── Span ─────────────────────────────────────────────────────────────────────

/// Source location of a token within a Lem source file.
///
/// All fields are byte-based (not character-based) to match Rust's string
/// indexing model. For ASCII-only source (the common case) byte == char.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Span {
    /// 1-indexed line number.
    pub line: u32,
    /// 1-indexed byte offset on the current line.
    pub col: u32,
    /// Byte offset from the start of the source string.
    pub offset: usize,
    /// Byte length of the token in the source string.
    pub len: usize,
}

impl Span {
    /// Construct a zero-length span at the given position (used for EOF).
    pub fn at(line: u32, col: u32, offset: usize) -> Self {
        Self {
            line,
            col,
            offset,
            len: 0,
        }
    }
}

// ─── TemplateSegment ──────────────────────────────────────────────────────────

/// A segment of a template string literal (`` `...${expr}...` ``).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TemplateSegment {
    /// Plain text between interpolations.
    Literal(String),
    /// Raw expression source between `${` and `}`.
    Interpolation(String),
}

// ─── Token ────────────────────────────────────────────────────────────────────

/// Every lexical token produced by the Lem lexer.
///
/// Variants are grouped by category with section comments for readability.
/// The ordering within each group matches the canonical spec (BUILD_GUIDE §4.1).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Token {
    // ── Keywords ──────────────────────────────────────────────────────────────
    /// `contract`
    Contract,
    /// `token` (Lem token-definition keyword, distinct from the `Token` type)
    Token_,
    /// `state`
    State,
    /// `init`
    Init,
    /// `pub`
    Pub,
    /// `view`
    View,
    /// `pure`
    Pure,
    /// `external`
    External,
    /// `payable`
    Payable,
    /// `fn`
    Fn,
    /// `let`
    Let,
    /// `const`
    Const,
    /// `if`
    If,
    /// `else`
    Else,
    /// `match`
    Match,
    /// `for`
    For,
    /// `while`
    While,
    /// `return`
    Return,
    /// `import`
    Import,
    /// `from`
    From,
    /// `as`
    As,
    /// `emit`
    Emit,
    /// `assert`
    Assert,
    /// `revert`
    Revert,
    /// `self` (keyword, not a type)
    SelfKw,
    /// `trait`
    Trait,
    /// `implements`
    Implements,
    /// `uses`
    Uses,
    /// `modifier`
    Modifier,
    /// `unchecked`
    Unchecked,
    /// `type` (for `type Alias = T`)
    Type,
    /// `struct`
    Struct,
    /// `enum`
    Enum,
    /// `interface`
    Interface,
    /// `library`
    Library,
    /// `loop`
    Loop,
    /// `break`
    Break,
    /// `continue`
    Continue,
    /// `try`
    Try,
    /// `catch`
    Catch,
    /// `mut`
    Mut,
    /// `of` (for-of iteration)
    Of,
    /// `in` (for-in range iteration)
    In,
    /// `using` (for `using Library for Type`)
    Using,
    /// `error` (for `error Foo { ... }`)
    Error,
    /// `extends` (for `token Foo extends Bar`)
    Extends,
    /// `new` (for `new Foo(args)`)
    New,
    /// `receive` (special function)
    Receive,
    /// `fallback` (special function)
    Fallback,
    /// `immutable` (for `immutable NAME: T`)
    Immutable,
    /// `event` (for `event Foo { ... }`)
    Event,

    // ── Type keywords ─────────────────────────────────────────────────────────
    /// `u8`
    U8,
    /// `u16`
    U16,
    /// `u32`
    U32,
    /// `u64`
    U64,
    /// `u128`
    U128,
    /// `u256`
    U256,
    /// `i8`
    I8,
    /// `i16`
    I16,
    /// `i32`
    I32,
    /// `i64`
    I64,
    /// `i128`
    I128,
    /// `i256`
    I256,
    /// `bool`
    Bool,
    /// `string`
    StringTy,
    /// `char`
    CharTy,
    /// `Address`
    AddressTy,
    /// `Hash`
    HashTy,
    /// `bytes`
    Bytes,
    /// `Array`
    ArrayTy,
    /// `Map`
    MapTy,
    /// `FastMap`
    FastMapTy,
    /// `Set`
    SetTy,
    /// `Option`
    OptionTy,
    /// `Result`
    ResultTy,
    /// `decimal` (e.g. `decimal(18)`)
    Decimal,

    // ── Annotations (@decorator syntax) ──────────────────────────────────────
    /// `@onlyOwner`
    OnlyOwner,
    /// `@onlyRole`
    OnlyRole,
    /// `@whenNotPaused`
    WhenNotPaused,
    /// `@whenPaused`
    WhenPaused,
    /// `@nonReentrant`
    NonReentrant,
    /// `@cooldown`
    Cooldown,
    /// `@payable` (annotation form, distinct from `payable` keyword)
    PayableAnn,
    /// `@deadline`
    Deadline,
    /// `@estimateGas`
    EstimateGas,
    /// `@onTransfer`
    OnTransfer,
    /// `@indexed`
    Indexed,
    /// `@private`
    Private,
    /// `@agentCallable` (Phase 3 Warden)
    AgentCallable,
    /// Unknown `@foo` annotation — catch-all for user-defined decorators.
    Annotation(String),

    // ── Literals ──────────────────────────────────────────────────────────────
    /// Decimal integer literal, e.g. `42` or `1_000_000`.
    IntLiteral(u128),
    /// Typed integer literal with suffix, e.g. `42u128`.
    IntLiteralTyped { value: u128, suffix: String },
    /// Hex literal — raw hex digits without `0x` prefix or underscores.
    HexLiteral(String),
    /// Binary literal — raw binary digits without `0b` prefix or underscores.
    BinLiteral(String),
    /// Float literal stored as raw string (no f64 — determinism requirement).
    FloatLiteral(String),
    /// String literal with escape sequences resolved.
    StringLiteral(String),
    /// Byte string literal `b"..."`.
    BytesLiteral(Vec<u8>),
    /// Character literal `'c'`.
    CharLiteral(char),
    /// Boolean literal `true` or `false`.
    BoolLiteral(bool),
    /// Validated Bech32m address literal (full string, e.g. `lem1q...`).
    AddressLiteral(String),
    /// Template string literal `` `text ${expr} text` ``.
    TemplateLiteral(Vec<TemplateSegment>),

    // ── Unit suffixes ─────────────────────────────────────────────────────────
    // Emitted as standalone tokens immediately after the preceding number.
    // e.g. `1.ether` → [IntLiteral(1), UnitEther]
    /// `.ether` — 1e18 Drop
    UnitEther,
    /// `.gwei`
    UnitGwei,
    /// `.minutes`
    UnitMinutes,
    /// `.hours`
    UnitHours,
    /// `.days`
    UnitDays,
    /// `.seconds`
    UnitSeconds,
    /// `.months`
    UnitMonths,
    /// `.tokens` — followed by `(N)` as separate tokens
    UnitTokens,

    // ── Operators ─────────────────────────────────────────────────────────────
    /// `+`
    Plus,
    /// `-`
    Minus,
    /// `*`
    Star,
    /// `/`
    Slash,
    /// `%`
    Percent,
    /// `==`
    Eq,
    /// `!=`
    NotEq,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `<=`
    LtEq,
    /// `>=`
    GtEq,
    /// `&&`
    And,
    /// `||`
    Or,
    /// `!`
    Not,
    /// `&`
    BitAnd,
    /// `|` as a bitwise OR operator — synthesized by the **parser** from `Token::Pipe`
    /// based on context (the lexer always emits `Pipe`; disambiguation happens at parse time).
    BitOr,
    /// `^`
    BitXor,
    /// `~`
    BitNot,
    /// `<<`
    Shl,
    /// `>>`
    Shr,
    /// `=`
    Assign,
    /// `+=`
    PlusAssign,
    /// `-=`
    MinusAssign,
    /// `*=`
    StarAssign,
    /// `/=`
    SlashAssign,
    /// `%=`
    PercentAssign,
    /// `**` (exponentiation)
    StarStar,
    /// `??` (null-coalescing)
    NullCoalesce,

    // ── Punctuation ───────────────────────────────────────────────────────────
    /// `->`
    Arrow,
    /// `=>`
    FatArrow,
    /// `?`
    QuestionMark,
    /// `_` (wildcard in match / modifier placeholder)
    Underscore,
    /// `.`
    Dot,
    /// `..` (range)
    DotDot,
    /// `..=` (inclusive range)
    DotDotEq,
    /// `,`
    Comma,
    /// `:`
    Colon,
    /// `::` (path separator)
    ColonColon,
    /// `;`
    Semicolon,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `{`
    LBrace,
    /// `}`
    RBrace,
    /// `[`
    LBracket,
    /// `]`
    RBracket,
    /// `#`
    Hash_,
    /// `@` (standalone, before annotation names — emitted when `@` is not
    /// followed by an identifier)
    At,
    /// `$` (inside template strings)
    Dollar,
    /// `|` (match arm separator — same as BitOr; context determines meaning)
    Pipe,

    // ── Comments ──────────────────────────────────────────────────────────────
    // Kept as tokens so the LSP and doc-generator can consume them.
    /// `// ...` line comment (content without the `//` prefix).
    LineComment(String),
    /// `/* ... */` block comment (content without delimiters).
    BlockComment(String),
    /// `/// ...` doc comment (content without the `///` prefix).
    DocComment(String),

    // ── Special ───────────────────────────────────────────────────────────────
    /// An identifier that did not match any keyword.
    Identifier(String),
    /// A newline character (`\n`). Used as a statement terminator.
    Newline,
    /// End of file — always the last token in the stream.
    Eof,
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
