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
use alloc::vec::Vec;

impl Parser {
    pub fn parse_call(&mut self) -> Expr {
        let mut e = if self.consume(&TokenKind::New) {
            let callee = self.parse_call();
            let args =
                if self.consume(&TokenKind::LParen) { self.parse_args() } else { Vec::new() };
            Expr::New { callee: Box::new(callee), args }
        } else {
            self.parse_primary()
        };
        loop {
            match self.peek() {
                TokenKind::LParen => {
                    self.advance();
                    let args = self.parse_args();
                    e = Expr::Call { callee: Box::new(e), args };
                }
                TokenKind::Dot => {
                    self.advance();
                    let prop = match self.advance() {
                        TokenKind::Identifier(s) => Expr::Literal(Literal::String(s.clone())),
                        _ => Expr::Literal(Literal::Undefined),
                    };
                    e = Expr::Member { obj: Box::new(e), prop: Box::new(prop), computed: false };
                }
                TokenKind::LBracket => {
                    self.advance();
                    let prop = self.parse_expr();
                    self.expect(&TokenKind::RBracket);
                    e = Expr::Member { obj: Box::new(e), prop: Box::new(prop), computed: true };
                }
                _ => break,
            }
        }
        e
    }
    pub fn parse_args(&mut self) -> Vec<Expr> {
        let mut args = Vec::new();
        while !self.check(&TokenKind::RParen) {
            args.push(self.parse_expr());
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RParen);
        args
    }
    pub fn parse_primary(&mut self) -> Expr {
        match self.peek().clone() {
            TokenKind::Null => {
                self.advance();
                Expr::Literal(Literal::Null)
            }
            TokenKind::Undefined => {
                self.advance();
                Expr::Literal(Literal::Undefined)
            }
            TokenKind::Boolean(b) => {
                self.advance();
                Expr::Literal(Literal::Bool(b))
            }
            TokenKind::Number(n) => {
                self.advance();
                Expr::Literal(Literal::Number(n))
            }
            TokenKind::String(s) => {
                self.advance();
                Expr::Literal(Literal::String(s.clone()))
            }
            TokenKind::Identifier(s) => {
                self.advance();
                Expr::Ident(s.clone())
            }
            TokenKind::This => {
                self.advance();
                Expr::This
            }
            TokenKind::Super => {
                self.advance();
                Expr::Super
            }
            TokenKind::LParen => {
                self.advance();
                let e = self.parse_expr();
                self.expect(&TokenKind::RParen);
                e
            }
            TokenKind::LBracket => self.parse_array(),
            TokenKind::LBrace => self.parse_object(),
            TokenKind::Function => self.parse_function_expr(),
            _ => {
                self.advance();
                Expr::Literal(Literal::Undefined)
            }
        }
    }
    fn parse_array(&mut self) -> Expr {
        self.expect(&TokenKind::LBracket);
        let mut elems = Vec::new();
        while !self.check(&TokenKind::RBracket) {
            if self.check(&TokenKind::Comma) {
                elems.push(None);
            } else {
                elems.push(Some(self.parse_expr()));
            }
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RBracket);
        Expr::Array(elems)
    }
    fn parse_object(&mut self) -> Expr {
        self.expect(&TokenKind::LBrace);
        let mut props = Vec::new();
        while !self.check(&TokenKind::RBrace) {
            let key = match self.peek().clone() {
                TokenKind::Identifier(s) => {
                    self.advance();
                    Expr::Literal(Literal::String(s.clone()))
                }
                TokenKind::String(s) => {
                    self.advance();
                    Expr::Literal(Literal::String(s.clone()))
                }
                _ => {
                    self.advance();
                    Expr::Literal(Literal::Undefined)
                }
            };
            let value =
                if self.consume(&TokenKind::Colon) { self.parse_expr() } else { key.clone() };
            props.push(Property {
                key,
                value,
                kind: PropKind::Init,
                shorthand: false,
                computed: false,
            });
            if !self.consume(&TokenKind::Comma) {
                break;
            }
        }
        self.expect(&TokenKind::RBrace);
        Expr::Object(props)
    }
    fn parse_function_expr(&mut self) -> Expr {
        self.advance();
        let name = if let TokenKind::Identifier(s) = self.peek() {
            let n = s.clone();
            self.advance();
            Some(n)
        } else {
            None
        };
        self.expect(&TokenKind::LParen);
        let params = self.parse_params();
        self.expect(&TokenKind::RParen);
        let body = Box::new(self.parse_block().unwrap_or(Stmt::Empty));
        Expr::Function { name, params, body, is_async: false }
    }
}
