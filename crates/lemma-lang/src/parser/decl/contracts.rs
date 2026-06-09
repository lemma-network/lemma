//! Contract, token, and contract-member parsers.
//!
//! Covers:
//! - `contract IDENT implements? uses? { member* }`
//! - `token IDENT extends IDENT { member* }`
//! - All contract member forms: state, const, immutable, fn, modifier,
//!   receive, fallback, config, metadata

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{
    Config, ConfigEntry, ConfigValue, Contract, ContractMember, Fallback_, Immutable, Item,
    Metadata, ModifierDef, Receive, StateBlock, StateField, TokenDecl, UnitKind,
};
use super::super::expr::MergeSpan;
use super::super::Parser;

// Tokens that are valid after a collected annotation set inside a contract body.
// Functions and events both accept leading annotations.
fn is_annotatable_member(tok: &Token) -> bool {
    matches!(
        tok,
        Token::Fn
            | Token::Pub
            | Token::View
            | Token::Pure
            | Token::Payable
            | Token::External
            | Token::Init
            | Token::Event
    )
}

impl Parser {
    // ── Contract ──────────────────────────────────────────────────────────────

    /// Parse `contract IDENT implements? uses? { member* }`.
    pub(crate) fn parse_contract_item(&mut self) -> Result<Item, LangError> {
        let start = self.expect(&Token::Contract, "\"contract\"")?;
        let name = self.expect_identifier("contract name")?;

        // Optional: `implements I1, I2`
        let implements = if self.check(&Token::Implements) {
            self.advance();
            self.parse_identifier_list()?
        } else {
            vec![]
        };

        // Optional: `uses T1, T2`
        let uses = if self.check(&Token::Uses) {
            self.advance();
            self.parse_identifier_list()?
        } else {
            vec![]
        };

        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();
        let mut members = Vec::new();
        while !self.check(&Token::RBrace) && !self.at_end() {
            members.push(self.parse_contract_member()?);
            self.skip_newlines();
        }
        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Item::Contract(Contract {
            name,
            implements,
            uses,
            members,
            span: start.merge_with(end),
        }))
    }

    // ── Token declaration ─────────────────────────────────────────────────────

    /// Parse `token IDENT extends IDENT { member* }`.
    pub(crate) fn parse_token_item(&mut self) -> Result<Item, LangError> {
        let start = self.expect(&Token::Token_, "\"token\"")?;
        let name = self.expect_identifier("token name")?;
        self.expect(&Token::Extends, "\"extends\"")?;
        let extends = self.expect_identifier("base token name")?;

        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();
        let mut members = Vec::new();
        while !self.check(&Token::RBrace) && !self.at_end() {
            // Token members use the same grammar as contract members
            members.push(self.parse_contract_member()?);
            self.skip_newlines();
        }
        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Item::Token_(TokenDecl {
            name,
            extends,
            members,
            span: start.merge_with(end),
        }))
    }

    // ── Contract member dispatcher ────────────────────────────────────────────

    /// Parse a single contract or token body member.
    ///
    /// Collects leading annotations first, then dispatches on the keyword.
    pub(crate) fn parse_contract_member(&mut self) -> Result<ContractMember, LangError> {
        self.skip_newlines();
        let annotations = self.parse_annotations()?;
        self.skip_newlines();

        // Annotations are only valid before function-producing members (fn, init)
        // and event declarations (which accept @anonymous).
        // Error early if annotations were collected but the next token is not annotatable.
        if !annotations.is_empty() && !is_annotatable_member(self.peek()) {
            return Err(self.error(format!(
                "annotations are not permitted before {:?}; \
                 annotations are only valid before function or event declarations",
                self.peek()
            )));
        }

        match self.peek().clone() {
            Token::State => Ok(ContractMember::State(self.parse_state_block()?)),
            Token::Const => Ok(ContractMember::Const(self.parse_const_decl()?)),
            Token::Immutable => Ok(ContractMember::Immutable(self.parse_immutable()?)),
            // `payable init(…) { … }` — the one permitted modifier on init (§9, WF-003).
            // Peek ahead: if `payable` is immediately followed by `init`, route to parse_init.
            // Otherwise fall through to parse_function (e.g. `payable fn receive(…)`).
            Token::Payable if self.peek_nth(1) == &Token::Init => {
                Ok(ContractMember::Function(self.parse_init(annotations)?))
            }
            Token::Init => Ok(ContractMember::Function(self.parse_init(annotations)?)),
            Token::Fn
            | Token::Pub
            | Token::View
            | Token::Pure
            | Token::Payable
            | Token::External => Ok(ContractMember::Function(self.parse_function(annotations)?)),
            Token::Receive => Ok(ContractMember::Receive(self.parse_receive()?)),
            Token::Fallback => Ok(ContractMember::Fallback(self.parse_fallback()?)),
            Token::Modifier => Ok(ContractMember::Modifier(self.parse_modifier_def()?)),
            // User-type declarations inside contract body (subtask 2e)
            Token::Struct => Ok(ContractMember::Struct(self.parse_struct_decl()?)),
            Token::Enum => Ok(ContractMember::Enum(self.parse_enum_decl()?)),
            Token::Event => Ok(ContractMember::Event(self.parse_event_decl(annotations)?)),
            Token::Error => Ok(ContractMember::ErrorDecl(self.parse_error_decl()?)),
            // Token standard blocks (subtask 2g) — `config` and `metadata` are
            // context-sensitive identifiers, not reserved keywords.
            Token::Identifier(ref s) if s == "config" => {
                Ok(ContractMember::Config(self.parse_config_block()?))
            }
            Token::Identifier(ref s) if s == "metadata" => {
                Ok(ContractMember::Metadata(self.parse_metadata_block()?))
            }
            tok => Err(self.error_expected(
                vec!["contract member".into()],
                format!("unexpected contract member token: {tok:?}"),
            )),
        }
    }

    // ── State block ───────────────────────────────────────────────────────────

    /// Parse `state { pub? name: Type (= expr)? ... }`.
    pub(crate) fn parse_state_block(&mut self) -> Result<StateBlock, LangError> {
        let start = self.expect(&Token::State, "\"state\"")?;
        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();
        let mut fields = Vec::new();
        while !self.check(&Token::RBrace) && !self.at_end() {
            let fs = self.peek_span();
            let pub_ = self.advance_if(&Token::Pub);
            let name = self.expect_identifier("state field name")?;
            self.expect(&Token::Colon, "\":\"")?;
            let ty = self.parse_type()?;
            let default = if self.advance_if(&Token::Assign) {
                Some(self.parse_expr()?)
            } else {
                None
            };
            fields.push(StateField {
                pub_,
                name,
                ty,
                default,
                span: fs,
            });
            self.consume_block_sep();
        }
        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(StateBlock {
            fields,
            span: start.merge_with(end),
        })
    }

    // ── Immutable ─────────────────────────────────────────────────────────────

    /// Parse `immutable NAME: Type`.
    pub(crate) fn parse_immutable(&mut self) -> Result<Immutable, LangError> {
        let start = self.expect(&Token::Immutable, "\"immutable\"")?;
        let name = self.expect_identifier("immutable name")?;
        self.expect(&Token::Colon, "\":\"")?;
        let ty = self.parse_type()?;
        let end = self.prev_span();
        self.skip_newlines();
        Ok(Immutable {
            name,
            ty,
            span: start.merge_with(end),
        })
    }

    // ── Init (constructor) ────────────────────────────────────────────────────

    /// Parse `payable? init(params) { body }` — the contract constructor.
    ///
    /// Grammar: `payable? init ( params? ) { body }`
    ///
    /// - Visibility is always `Private` (parser-enforced; WF-003 clause 3a is a
    ///   parse-time guarantee — `pub init` / `external init` are parse errors).
    /// - Return type is always `None` (parser-enforced; WF-003 clause 4 is a
    ///   parse-time guarantee — `init -> T` is a parse error).
    /// - Mutability is `Payable` if the optional `payable` keyword precedes `init`,
    ///   otherwise `Default`. `payable` is the ONE permitted modifier (§9, WF-003).
    ///
    /// See decisions-log.md DB-A46.
    pub(crate) fn parse_init(
        &mut self,
        annotations: Vec<crate::parser::ast::Annotation>,
    ) -> Result<crate::parser::ast::Function, LangError> {
        // Optional `payable` keyword before `init` — the one permitted modifier.
        // Capture the start span from `payable` if present, otherwise from `init`.
        let (mutability, start) = if self.check(&Token::Payable) {
            let payable_span = self.peek_span();
            self.advance(); // consume `payable`
            let init_span = self.expect(&Token::Init, "\"init\"")?;
            // Span starts at `payable` for accurate source location.
            let _ = init_span; // init_span consumed; start from payable
            (crate::parser::ast::Mutability::Payable, payable_span)
        } else {
            let init_span = self.expect(&Token::Init, "\"init\"")?;
            (crate::parser::ast::Mutability::Default, init_span)
        };
        self.expect(&Token::LParen, "\"(\"")?;
        let params = self.parse_param_list()?;
        self.expect(&Token::RParen, "\")\"")?;
        let body = self.parse_block()?;
        let end = self.prev_span();
        Ok(crate::parser::ast::Function {
            name: "init".to_string(),
            annotations,
            visibility: crate::parser::ast::Visibility::Private,
            mutability,
            generic_params: vec![],
            params,
            return_type: None,
            body: Some(body),
            span: start.merge_with(end),
        })
    }

    // ── Receive / Fallback ────────────────────────────────────────────────────

    /// Parse `receive() payable? { body }`.
    pub(crate) fn parse_receive(&mut self) -> Result<Receive, LangError> {
        let start = self.expect(&Token::Receive, "\"receive\"")?;
        self.expect(&Token::LParen, "\"(\"")?;
        self.expect(&Token::RParen, "\")\"")?;
        let payable = self.advance_if(&Token::Payable);
        let body = self.parse_block()?;
        let end = self.prev_span();
        Ok(Receive {
            payable,
            body,
            span: start.merge_with(end),
        })
    }

    /// Parse `fallback() payable? { body }`.
    pub(crate) fn parse_fallback(&mut self) -> Result<Fallback_, LangError> {
        let start = self.expect(&Token::Fallback, "\"fallback\"")?;
        self.expect(&Token::LParen, "\"(\"")?;
        self.expect(&Token::RParen, "\")\"")?;
        let payable = self.advance_if(&Token::Payable);
        let body = self.parse_block()?;
        let end = self.prev_span();
        Ok(Fallback_ {
            payable,
            body,
            span: start.merge_with(end),
        })
    }

    // ── Modifier ──────────────────────────────────────────────────────────────

    /// Parse `modifier NAME(params) { body }`.
    ///
    /// The body may contain `Stmt::Placeholder` for `_`.
    pub(crate) fn parse_modifier_def(&mut self) -> Result<ModifierDef, LangError> {
        let start = self.expect(&Token::Modifier, "\"modifier\"")?;
        let name = self.expect_identifier("modifier name")?;
        self.expect(&Token::LParen, "\"(\"")?;
        let params = self.parse_param_list()?;
        self.expect(&Token::RParen, "\")\"")?;
        let body = self.parse_block()?;
        let end = self.prev_span();
        Ok(ModifierDef {
            name,
            params,
            body,
            span: start.merge_with(end),
        })
    }

    // ── Config block ──────────────────────────────────────────────────────────

    /// Parse `config { key: value ... }` inside a token declaration.
    ///
    /// `config` is a context-sensitive identifier, not a reserved keyword.
    /// The caller has already verified the current token is `Identifier("config")`
    /// via a match guard, so we consume it with `advance()`.
    pub(crate) fn parse_config_block(&mut self) -> Result<Config, LangError> {
        let start = self.peek_span();
        self.advance(); // consume `config` identifier
        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();
        let entries = self.parse_config_entries()?;
        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Config {
            entries,
            span: start.merge_with(end),
        })
    }

    // ── Metadata block ────────────────────────────────────────────────────────

    /// Parse `metadata { key: value ... }` inside a token declaration.
    ///
    /// Same structure as `config { }` — shares `parse_config_entries` to avoid
    /// duplication (DRY: AGENTS §2).
    pub(crate) fn parse_metadata_block(&mut self) -> Result<Metadata, LangError> {
        let start = self.peek_span();
        self.advance(); // consume `metadata` identifier
        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();
        let entries = self.parse_config_entries()?;
        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Metadata {
            entries,
            span: start.merge_with(end),
        })
    }

    // ── Config entries (shared by config, metadata, and nested objects) ───────

    /// Parse a sequence of `key: value` entries until a `}` is reached.
    ///
    /// Entries are separated by a comma, a newline, or both — the §24 spec uses
    /// commas for inline objects (`{ k: v, k: v }`) and newlines for multi-line
    /// blocks. A trailing separator before `}` is permitted.
    ///
    /// This function is called by `parse_config_block`, `parse_metadata_block`,
    /// and recursively by `parse_config_value` for nested objects.
    fn parse_config_entries(&mut self) -> Result<Vec<ConfigEntry>, LangError> {
        let mut entries = Vec::new();
        while !self.check(&Token::RBrace) && !self.at_end() {
            // Capture the start of the entry for span tracking.
            // (Same convention as parse_state_block — start span only.)
            let span = self.peek_span();
            let key = self.expect_identifier("config entry key")?;
            self.expect(&Token::Colon, "\":\"")?;
            let value = self.parse_config_value()?;
            entries.push(ConfigEntry { key, value, span });
            // Pola B (DB-A35): newline-or-comma, trailing OK — same policy as all
            // block declarations; §24 spec uses both comma and newline forms.
            self.consume_block_sep();
        }
        Ok(entries)
    }

    // ── Config value ──────────────────────────────────────────────────────────

    /// Parse a single config value.
    ///
    /// Value forms (all from §24 token standard spec):
    /// - `"text"`          → `ConfigValue::Str`
    /// - `true` / `false`  → `ConfigValue::Bool`
    /// - `42`              → `ConfigValue::Int` (plain integer)
    /// - `15%`             → `ConfigValue::Percent` (integer followed by `%`)
    /// - `24.hours`        → `ConfigValue::Unit`  (integer followed by unit suffix)
    /// - `{ key: val... }` → `ConfigValue::Object` (nested block; recursive)
    /// - `SomeIdent`       → `ConfigValue::Ident`
    fn parse_config_value(&mut self) -> Result<ConfigValue, LangError> {
        match self.peek().clone() {
            Token::StringLiteral(s) => {
                self.advance();
                Ok(ConfigValue::Str(s))
            }
            Token::BoolLiteral(b) => {
                self.advance();
                Ok(ConfigValue::Bool(b))
            }
            Token::IntLiteral(n) => {
                self.advance();
                // Integer followed by `%` → Percent
                if self.advance_if(&Token::Percent) {
                    return Ok(ConfigValue::Percent(n));
                }
                // Integer followed by a unit suffix token → Unit
                let unit = match self.peek() {
                    Token::UnitEther => Some(UnitKind::Ether),
                    Token::UnitGwei => Some(UnitKind::Gwei),
                    Token::UnitMinutes => Some(UnitKind::Minutes),
                    Token::UnitHours => Some(UnitKind::Hours),
                    Token::UnitDays => Some(UnitKind::Days),
                    Token::UnitSeconds => Some(UnitKind::Seconds),
                    _ => None,
                };
                if let Some(kind) = unit {
                    self.advance();
                    return Ok(ConfigValue::Unit(n, kind));
                }
                Ok(ConfigValue::Int(n))
            }
            Token::LBrace => {
                // Nested object — reuse parse_config_entries (recursive)
                self.advance(); // consume `{`
                self.skip_newlines();
                let entries = self.parse_config_entries()?;
                self.expect(&Token::RBrace, "\"}\"")?;
                Ok(ConfigValue::Object(entries))
            }
            Token::Identifier(s) => {
                self.advance();
                Ok(ConfigValue::Ident(s))
            }
            tok => Err(self.error_expected(
                vec!["config value".into()],
                format!("expected config value, found: {tok:?}"),
            )),
        }
    }
}
