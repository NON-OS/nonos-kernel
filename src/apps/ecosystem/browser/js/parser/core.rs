// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::ast::*;
use crate::apps::ecosystem::browser::js::lexer::{Lexer, Token, TokenKind};
use alloc::vec::Vec;

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(src: &str) -> Self {
        Self { tokens: Lexer::new(src).tokenize(), pos: 0 }
    }
    pub fn parse(&mut self) -> Program {
        let mut body = Vec::new();
        while !self.at_end() {
            if let Some(s) = self.parse_stmt() {
                body.push(s);
            }
        }
        Program { body }
    }
    pub fn peek(&self) -> &TokenKind {
        self.tokens.get(self.pos).map(|t| &t.kind).unwrap_or(&TokenKind::Eof)
    }
    pub fn peek_n(&self, n: usize) -> &TokenKind {
        self.tokens.get(self.pos + n).map(|t| &t.kind).unwrap_or(&TokenKind::Eof)
    }
    pub fn advance(&mut self) -> TokenKind {
        let k = self.peek().clone();
        if !self.at_end() {
            self.pos += 1;
        }
        k
    }
    pub fn at_end(&self) -> bool {
        matches!(self.peek(), TokenKind::Eof)
    }
    pub fn check(&self, k: &TokenKind) -> bool {
        core::mem::discriminant(self.peek()) == core::mem::discriminant(k)
    }
    pub fn consume(&mut self, k: &TokenKind) -> bool {
        if self.check(k) {
            self.advance();
            true
        } else {
            false
        }
    }
    pub fn expect(&mut self, k: &TokenKind) {
        if !self.consume(k) {
            self.advance();
        }
    }

    pub fn parse_stmt(&mut self) -> Option<Stmt> {
        match self.peek().clone() {
            TokenKind::LBrace => self.parse_block(),
            TokenKind::Var | TokenKind::Let | TokenKind::Const => self.parse_var_decl(),
            TokenKind::If => self.parse_if(),
            TokenKind::While => self.parse_while(),
            TokenKind::Do => self.parse_do_while(),
            TokenKind::For => self.parse_for(),
            TokenKind::Return => {
                self.advance();
                let e = if !self.check(&TokenKind::Semi) && !self.check(&TokenKind::RBrace) {
                    Some(self.parse_expr())
                } else {
                    None
                };
                self.consume(&TokenKind::Semi);
                Some(Stmt::Return(e))
            }
            TokenKind::Break => {
                self.advance();
                self.consume(&TokenKind::Semi);
                Some(Stmt::Break(None))
            }
            TokenKind::Continue => {
                self.advance();
                self.consume(&TokenKind::Semi);
                Some(Stmt::Continue(None))
            }
            TokenKind::Throw => {
                self.advance();
                let e = self.parse_expr();
                self.consume(&TokenKind::Semi);
                Some(Stmt::Throw(e))
            }
            TokenKind::Try => self.parse_try(),
            TokenKind::Function => self.parse_function_decl(),
            TokenKind::Class => self.parse_class_decl(),
            TokenKind::Semi => {
                self.advance();
                Some(Stmt::Empty)
            }
            TokenKind::Debugger => {
                self.advance();
                self.consume(&TokenKind::Semi);
                Some(Stmt::Debugger)
            }
            _ => {
                let e = self.parse_expr();
                self.consume(&TokenKind::Semi);
                Some(Stmt::Expr(e))
            }
        }
    }
}
