//! Contract, token, and contract-member parsers.
//!
//! Covers:
//! - `contract IDENT implements? uses? { member* }`
//! - `token IDENT extends IDENT { member* }`
//! - All contract member forms: state, const, immutable, fn, modifier,
//!   receive, fallback

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{
    Contract, ContractMember, Fallback_, Immutable, Item, ModifierDef, Receive, StateBlock,
    StateField, TokenDecl,
};
use super::super::expr::MergeSpan;
use super::super::Parser;

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

        // Annotations are only valid before function-producing members (fn, init).
        // Error early if annotations were collected but the next token is not a function.
        let next_is_fn = matches!(
            self.peek(),
            Token::Fn
                | Token::Pub
                | Token::View
                | Token::Pure
                | Token::Payable
                | Token::External
                | Token::Init
        );
        if !annotations.is_empty() && !next_is_fn {
            return Err(self.error(format!(
                "annotations are not permitted before {:?}; \
                 annotations are only valid before function declarations",
                self.peek()
            )));
        }

        match self.peek().clone() {
            Token::State => Ok(ContractMember::State(self.parse_state_block()?)),
            Token::Const => Ok(ContractMember::Const(self.parse_const_decl()?)),
            Token::Immutable => Ok(ContractMember::Immutable(self.parse_immutable()?)),
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
            // Struct/Enum/Event/Error inside contract — handled in 2e
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
            self.skip_newlines();
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

    /// Parse `init(params) { body }` — the contract constructor.
    ///
    /// Parsed as a `Function` named `"init"` with `Visibility::Private`.
    pub(crate) fn parse_init(
        &mut self,
        annotations: Vec<crate::parser::ast::Annotation>,
    ) -> Result<crate::parser::ast::Function, LangError> {
        let start = self.expect(&Token::Init, "\"init\"")?;
        self.expect(&Token::LParen, "\"(\"")?;
        let params = self.parse_param_list()?;
        self.expect(&Token::RParen, "\")\"")?;
        let body = self.parse_block()?;
        let end = self.prev_span();
        Ok(crate::parser::ast::Function {
            name: "init".to_string(),
            annotations,
            visibility: crate::parser::ast::Visibility::Private,
            mutability: crate::parser::ast::Mutability::Default,
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
}
