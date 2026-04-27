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

impl Parser {
    pub fn parse_shift(&mut self) -> Expr {
        let mut e = self.parse_additive();
        loop {
            match self.peek() {
                TokenKind::LtLt => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Shl,
                        left: Box::new(e),
                        right: Box::new(self.parse_additive()),
                    };
                }
                TokenKind::GtGt => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Shr,
                        left: Box::new(e),
                        right: Box::new(self.parse_additive()),
                    };
                }
                TokenKind::GtGtGt => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Ushr,
                        left: Box::new(e),
                        right: Box::new(self.parse_additive()),
                    };
                }
                _ => break,
            }
        }
        e
    }
    pub fn parse_additive(&mut self) -> Expr {
        let mut e = self.parse_multiplicative();
        loop {
            match self.peek() {
                TokenKind::Plus => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Add,
                        left: Box::new(e),
                        right: Box::new(self.parse_multiplicative()),
                    };
                }
                TokenKind::Minus => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Sub,
                        left: Box::new(e),
                        right: Box::new(self.parse_multiplicative()),
                    };
                }
                _ => break,
            }
        }
        e
    }
    pub fn parse_multiplicative(&mut self) -> Expr {
        let mut e = self.parse_power();
        loop {
            match self.peek() {
                TokenKind::Star => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Mul,
                        left: Box::new(e),
                        right: Box::new(self.parse_power()),
                    };
                }
                TokenKind::Slash => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Div,
                        left: Box::new(e),
                        right: Box::new(self.parse_power()),
                    };
                }
                TokenKind::Percent => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Mod,
                        left: Box::new(e),
                        right: Box::new(self.parse_power()),
                    };
                }
                _ => break,
            }
        }
        e
    }
    pub fn parse_power(&mut self) -> Expr {
        let e = self.parse_unary();
        if self.consume(&TokenKind::StarStar) {
            Expr::Binary {
                op: BinaryOp::Pow,
                left: Box::new(e),
                right: Box::new(self.parse_power()),
            }
        } else {
            e
        }
    }
    pub fn parse_unary(&mut self) -> Expr {
        match self.peek() {
            TokenKind::Bang => {
                self.advance();
                Expr::Unary { op: UnaryOp::Not, arg: Box::new(self.parse_unary()), prefix: true }
            }
            TokenKind::Tilde => {
                self.advance();
                Expr::Unary { op: UnaryOp::BitNot, arg: Box::new(self.parse_unary()), prefix: true }
            }
            TokenKind::Plus => {
                self.advance();
                Expr::Unary { op: UnaryOp::Plus, arg: Box::new(self.parse_unary()), prefix: true }
            }
            TokenKind::Minus => {
                self.advance();
                Expr::Unary { op: UnaryOp::Minus, arg: Box::new(self.parse_unary()), prefix: true }
            }
            TokenKind::PlusPlus => {
                self.advance();
                Expr::Unary {
                    op: UnaryOp::PrefixInc,
                    arg: Box::new(self.parse_unary()),
                    prefix: true,
                }
            }
            TokenKind::MinusMinus => {
                self.advance();
                Expr::Unary {
                    op: UnaryOp::PrefixDec,
                    arg: Box::new(self.parse_unary()),
                    prefix: true,
                }
            }
            TokenKind::Typeof => {
                self.advance();
                Expr::Unary { op: UnaryOp::Typeof, arg: Box::new(self.parse_unary()), prefix: true }
            }
            TokenKind::Void => {
                self.advance();
                Expr::Unary { op: UnaryOp::Void, arg: Box::new(self.parse_unary()), prefix: true }
            }
            TokenKind::Delete => {
                self.advance();
                Expr::Unary { op: UnaryOp::Delete, arg: Box::new(self.parse_unary()), prefix: true }
            }
            TokenKind::Await => {
                self.advance();
                Expr::Await(Box::new(self.parse_unary()))
            }
            _ => self.parse_postfix(),
        }
    }
    pub fn parse_postfix(&mut self) -> Expr {
        let mut e = self.parse_call();
        loop {
            match self.peek() {
                TokenKind::PlusPlus => {
                    self.advance();
                    e = Expr::Unary { op: UnaryOp::PostfixInc, arg: Box::new(e), prefix: false };
                }
                TokenKind::MinusMinus => {
                    self.advance();
                    e = Expr::Unary { op: UnaryOp::PostfixDec, arg: Box::new(e), prefix: false };
                }
                _ => break,
            }
        }
        e
    }
}
