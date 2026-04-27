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
use super::core::Parser;
use crate::apps::ecosystem::browser::js::lexer::TokenKind;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

impl Parser {
    pub fn parse_block(&mut self) -> Option<Stmt> {
        self.expect(&TokenKind::LBrace);
        let mut stmts = Vec::new();
        while !self.check(&TokenKind::RBrace) && !self.at_end() {
            if let Some(s) = self.parse_stmt() {
                stmts.push(s);
            }
        }
        self.expect(&TokenKind::RBrace);
        Some(Stmt::Block(stmts))
    }
    pub fn parse_var_decl(&mut self) -> Option<Stmt> {
        let kind = match self.advance() {
            TokenKind::Var => VarKind::Var,
            TokenKind::Let => VarKind::Let,
            TokenKind::Const => VarKind::Const,
            _ => return None,
        };
        let mut decls = Vec::new();
        loop {
            let name = match self.advance() {
                TokenKind::Identifier(s) => s.clone(),
                _ => String::new(),
            };
            let init = if self.consume(&TokenKind::Eq) { Some(self.parse_expr()) } else { None };
            decls.push(VarDecl { name, init });
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        self.consume(&TokenKind::Semi);
        Some(Stmt::Var { kind, decls })
    }
    pub fn parse_if(&mut self) -> Option<Stmt> {
        self.advance();
        self.expect(&TokenKind::LParen);
        let cond = self.parse_expr();
        self.expect(&TokenKind::RParen);
        let then_br = Box::new(self.parse_stmt()?);
        let else_br =
            if self.consume(&TokenKind::Else) { Some(Box::new(self.parse_stmt()?)) } else { None };
        Some(Stmt::If { cond, then_br, else_br })
    }
    pub fn parse_while(&mut self) -> Option<Stmt> {
        self.advance();
        self.expect(&TokenKind::LParen);
        let cond = self.parse_expr();
        self.expect(&TokenKind::RParen);
        Some(Stmt::While { cond, body: Box::new(self.parse_stmt()?) })
    }
    pub fn parse_do_while(&mut self) -> Option<Stmt> {
        self.advance();
        let body = Box::new(self.parse_stmt()?);
        self.expect(&TokenKind::While);
        self.expect(&TokenKind::LParen);
        let cond = self.parse_expr();
        self.expect(&TokenKind::RParen);
        self.consume(&TokenKind::Semi);
        Some(Stmt::DoWhile { body, cond })
    }
    pub fn parse_for(&mut self) -> Option<Stmt> {
        self.advance();
        self.expect(&TokenKind::LParen);
        let init =
            if self.check(&TokenKind::Semi) { None } else { self.parse_stmt().map(Box::new) };
        let cond = if self.check(&TokenKind::Semi) { None } else { Some(self.parse_expr()) };
        self.expect(&TokenKind::Semi);
        let update = if self.check(&TokenKind::RParen) { None } else { Some(self.parse_expr()) };
        self.expect(&TokenKind::RParen);
        Some(Stmt::For { init, cond, update, body: Box::new(self.parse_stmt()?) })
    }
    pub fn parse_try(&mut self) -> Option<Stmt> {
        self.advance();
        let block = Box::new(self.parse_block()?);
        let catch = if self.consume(&TokenKind::Catch) {
            let param = if self.consume(&TokenKind::LParen) {
                let p = match self.advance() {
                    TokenKind::Identifier(s) => Some(s.clone()),
                    _ => None,
                };
                self.expect(&TokenKind::RParen);
                p
            } else {
                None
            };
            Some(CatchClause { param, body: Box::new(self.parse_block()?) })
        } else {
            None
        };
        let finally = if self.consume(&TokenKind::Finally) {
            Some(Box::new(self.parse_block()?))
        } else {
            None
        };
        Some(Stmt::Try { block, catch, finally })
    }
    pub fn parse_function_decl(&mut self) -> Option<Stmt> {
        self.advance();
        let name = match self.advance() {
            TokenKind::Identifier(s) => Some(s.clone()),
            _ => None,
        };
        self.expect(&TokenKind::LParen);
        let params = self.parse_params();
        self.expect(&TokenKind::RParen);
        Some(Stmt::Function { name, params, body: Box::new(self.parse_block()?), is_async: false })
    }
    pub fn parse_class_decl(&mut self) -> Option<Stmt> {
        self.advance();
        let name = match self.advance() {
            TokenKind::Identifier(s) => Some(s.clone()),
            _ => None,
        };
        let super_class =
            if self.consume(&TokenKind::Extends) { Some(self.parse_expr()) } else { None };
        self.expect(&TokenKind::LBrace);
        let body = Vec::new();
        self.expect(&TokenKind::RBrace);
        Some(Stmt::Class { name, super_class, body })
    }
    pub fn parse_params(&mut self) -> Vec<String> {
        let mut params = Vec::new();
        while !self.check(&TokenKind::RParen) {
            if let TokenKind::Identifier(s) = self.advance() {
                params.push(s.clone());
            }
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        params
    }
}
