//! Advanced declaration parsers: interface, trait, library.
//!
//! Body-less functions (`Function.body = None`) represent interface/abstract
//! declarations. `parse_function` already handles this correctly — it checks
//! for `Token::LBrace` before parsing a body, returning `body: None` when
//! absent. No separate `FunctionSig` type is needed.

use crate::error::LangError;
use crate::lexer::token::Token;

use super::super::ast::{Interface, InterfaceMember, Library, Trait, TraitMember};
use super::super::expr::MergeSpan;
use super::super::Parser;

impl Parser {
    // ── Interface ─────────────────────────────────────────────────────────────

    /// Parse `interface IDENT { (fn_signature | event_def)* }`.
    ///
    /// Interface members are either body-less function signatures or event
    /// definitions. `parse_function` returns `body: None` when no `{` follows,
    /// which is the correct representation for interface method signatures.
    pub(crate) fn parse_interface(&mut self) -> Result<Interface, LangError> {
        let start = self.expect(&Token::Interface, "\"interface\"")?;
        let name = self.expect_identifier("interface name")?;
        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();

        let mut members = Vec::new();

        while !self.check(&Token::RBrace) && !self.at_end() {
            self.skip_newlines();
            if self.check(&Token::RBrace) || self.at_end() {
                break;
            }

            let annotations = self.parse_annotations()?;
            self.skip_newlines();

            match self.peek().clone() {
                Token::Event => {
                    // Event definitions inside interface
                    let ev = self.parse_event_decl(annotations)?;
                    members.push(InterfaceMember::Event(ev));
                }
                // Function signatures (no body) — visibility/mutability keywords or `fn`
                Token::Fn
                | Token::Pub
                | Token::View
                | Token::Pure
                | Token::External
                | Token::Payable => {
                    // parse_function returns body=None when no `{` follows the signature
                    let func = self.parse_function(annotations)?;
                    members.push(InterfaceMember::Function(func));
                }
                tok => {
                    return Err(self.error_expected(
                        vec!["function signature".into(), "event".into()],
                        format!("expected interface member, got {tok:?}"),
                    ));
                }
            }

            self.skip_newlines();
        }

        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Interface {
            name,
            members,
            span: start.merge_with(end),
        })
    }

    // ── Trait ─────────────────────────────────────────────────────────────────

    /// Parse `trait IDENT { (state_block | function)* }`.
    ///
    /// Trait members are either a `state { ... }` block (declaring required
    /// state) or functions. Functions with a body are default implementations;
    /// functions without a body are required (abstract) methods.
    pub(crate) fn parse_trait(&mut self) -> Result<Trait, LangError> {
        let start = self.expect(&Token::Trait, "\"trait\"")?;
        let name = self.expect_identifier("trait name")?;
        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();

        let mut members = Vec::new();

        while !self.check(&Token::RBrace) && !self.at_end() {
            self.skip_newlines();
            if self.check(&Token::RBrace) || self.at_end() {
                break;
            }

            match self.peek().clone() {
                Token::State => {
                    // Shared state requirement declared by the trait
                    let sb = self.parse_state_block()?;
                    members.push(TraitMember::State(sb));
                }
                _ => {
                    // Function: with body = default impl, without body = required.
                    // parse_function handles both via body: Option<Vec<Stmt>>.
                    let annotations = self.parse_annotations()?;
                    self.skip_newlines();
                    let func = self.parse_function(annotations)?;
                    members.push(TraitMember::Function(func));
                }
            }

            self.skip_newlines();
        }

        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Trait {
            name,
            members,
            span: start.merge_with(end),
        })
    }

    // ── Library ───────────────────────────────────────────────────────────────

    /// Parse `library IDENT { function* }`.
    ///
    /// Libraries are stateless collections of pure functions. Only function
    /// declarations are permitted in a library body — state blocks and other
    /// member types are rejected with a descriptive error.
    pub(crate) fn parse_library(&mut self) -> Result<Library, LangError> {
        let start = self.expect(&Token::Library, "\"library\"")?;
        let name = self.expect_identifier("library name")?;
        self.expect(&Token::LBrace, "\"{\"")?;
        self.skip_newlines();

        let mut functions = Vec::new();

        while !self.check(&Token::RBrace) && !self.at_end() {
            self.skip_newlines();
            if self.check(&Token::RBrace) || self.at_end() {
                break;
            }

            let annotations = self.parse_annotations()?;
            self.skip_newlines();

            match self.peek().clone() {
                Token::Fn
                | Token::Pub
                | Token::View
                | Token::Pure
                | Token::External
                | Token::Payable => {
                    functions.push(self.parse_function(annotations)?);
                }
                tok => {
                    return Err(self.error_expected(
                        vec!["function".into()],
                        format!("libraries can only contain functions, got {tok:?}"),
                    ));
                }
            }

            self.skip_newlines();
        }

        let end = self.expect(&Token::RBrace, "\"}\"")?;
        Ok(Library {
            name,
            functions,
            span: start.merge_with(end),
        })
    }
}
