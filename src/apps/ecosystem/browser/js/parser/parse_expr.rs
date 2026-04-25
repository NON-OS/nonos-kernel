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
    pub fn parse_expr(&mut self) -> Expr {
        self.parse_assignment()
    }
    fn parse_assignment(&mut self) -> Expr {
        let left = self.parse_ternary();
        match self.peek() {
            TokenKind::Eq => {
                self.advance();
                Expr::Assign {
                    op: AssignOp::Assign,
                    left: Box::new(left),
                    right: Box::new(self.parse_assignment()),
                }
            }
            TokenKind::PlusEq => {
                self.advance();
                Expr::Assign {
                    op: AssignOp::AddAssign,
                    left: Box::new(left),
                    right: Box::new(self.parse_assignment()),
                }
            }
            TokenKind::MinusEq => {
                self.advance();
                Expr::Assign {
                    op: AssignOp::SubAssign,
                    left: Box::new(left),
                    right: Box::new(self.parse_assignment()),
                }
            }
            TokenKind::StarEq => {
                self.advance();
                Expr::Assign {
                    op: AssignOp::MulAssign,
                    left: Box::new(left),
                    right: Box::new(self.parse_assignment()),
                }
            }
            TokenKind::SlashEq => {
                self.advance();
                Expr::Assign {
                    op: AssignOp::DivAssign,
                    left: Box::new(left),
                    right: Box::new(self.parse_assignment()),
                }
            }
            _ => left,
        }
    }
    fn parse_ternary(&mut self) -> Expr {
        let cond = self.parse_or();
        if self.consume(&TokenKind::Question) {
            let consequent = self.parse_assignment();
            self.expect(&TokenKind::Colon);
            let alternate = self.parse_assignment();
            Expr::Conditional {
                test: Box::new(cond),
                consequent: Box::new(consequent),
                alternate: Box::new(alternate),
            }
        } else {
            cond
        }
    }
    fn parse_or(&mut self) -> Expr {
        let mut e = self.parse_and();
        while self.consume(&TokenKind::PipePipe) {
            e = Expr::Logical {
                op: LogicalOp::Or,
                left: Box::new(e),
                right: Box::new(self.parse_and()),
            };
        }
        e
    }
    fn parse_and(&mut self) -> Expr {
        let mut e = self.parse_bitor();
        while self.consume(&TokenKind::AmpAmp) {
            e = Expr::Logical {
                op: LogicalOp::And,
                left: Box::new(e),
                right: Box::new(self.parse_bitor()),
            };
        }
        e
    }
    fn parse_bitor(&mut self) -> Expr {
        let mut e = self.parse_bitxor();
        while self.consume(&TokenKind::Pipe) {
            e = Expr::Binary {
                op: BinaryOp::BitOr,
                left: Box::new(e),
                right: Box::new(self.parse_bitxor()),
            };
        }
        e
    }
    fn parse_bitxor(&mut self) -> Expr {
        let mut e = self.parse_bitand();
        while self.consume(&TokenKind::Caret) {
            e = Expr::Binary {
                op: BinaryOp::BitXor,
                left: Box::new(e),
                right: Box::new(self.parse_bitand()),
            };
        }
        e
    }
    fn parse_bitand(&mut self) -> Expr {
        let mut e = self.parse_equality();
        while self.consume(&TokenKind::Amp) {
            e = Expr::Binary {
                op: BinaryOp::BitAnd,
                left: Box::new(e),
                right: Box::new(self.parse_equality()),
            };
        }
        e
    }
    fn parse_equality(&mut self) -> Expr {
        let mut e = self.parse_relational();
        loop {
            match self.peek() {
                TokenKind::EqEq => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Eq,
                        left: Box::new(e),
                        right: Box::new(self.parse_relational()),
                    };
                }
                TokenKind::EqEqEq => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::StrictEq,
                        left: Box::new(e),
                        right: Box::new(self.parse_relational()),
                    };
                }
                TokenKind::BangEq => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Ne,
                        left: Box::new(e),
                        right: Box::new(self.parse_relational()),
                    };
                }
                TokenKind::BangEqEq => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::StrictNe,
                        left: Box::new(e),
                        right: Box::new(self.parse_relational()),
                    };
                }
                _ => break,
            }
        }
        e
    }
    fn parse_relational(&mut self) -> Expr {
        let mut e = self.parse_shift();
        loop {
            match self.peek() {
                TokenKind::Lt => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Lt,
                        left: Box::new(e),
                        right: Box::new(self.parse_shift()),
                    };
                }
                TokenKind::Gt => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Gt,
                        left: Box::new(e),
                        right: Box::new(self.parse_shift()),
                    };
                }
                TokenKind::LtEq => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Le,
                        left: Box::new(e),
                        right: Box::new(self.parse_shift()),
                    };
                }
                TokenKind::GtEq => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Ge,
                        left: Box::new(e),
                        right: Box::new(self.parse_shift()),
                    };
                }
                TokenKind::In => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::In,
                        left: Box::new(e),
                        right: Box::new(self.parse_shift()),
                    };
                }
                TokenKind::Instanceof => {
                    self.advance();
                    e = Expr::Binary {
                        op: BinaryOp::Instanceof,
                        left: Box::new(e),
                        right: Box::new(self.parse_shift()),
                    };
                }
                _ => break,
            }
        }
        e
    }
}
